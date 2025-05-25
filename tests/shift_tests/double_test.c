#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5DE1D8AE8B5672B5ULL,
		0x342B6D116EF8614CULL,
		0x2263600E8398ADECULL,
		0x91C09D673D72D8D5ULL,
		0xE03323ACC4E0BA17ULL,
		0x03A718D218617C35ULL,
		0x004B5A8699CCA1B5ULL,
		0x0A583D84FAB85E90ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBBC3B15D16ACE56AULL,
		0x6856DA22DDF0C298ULL,
		0x44C6C01D07315BD8ULL,
		0x23813ACE7AE5B1AAULL,
		0xC066475989C1742FULL,
		0x074E31A430C2F86BULL,
		0x0096B50D3399436AULL,
		0x14B07B09F570BD20ULL
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
		0xC5BC07781169C094ULL,
		0xCA0A8C000892A5FEULL,
		0x69BDC317CB6BF11CULL,
		0x3F8FB4D4986F89F8ULL,
		0x87FDB75E19F80705ULL,
		0x56CA9A7F14C033C5ULL,
		0x678BBF9845082FDCULL,
		0x388384A673E00EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B780EF022D38128ULL,
		0x9415180011254BFDULL,
		0xD37B862F96D7E239ULL,
		0x7F1F69A930DF13F0ULL,
		0x0FFB6EBC33F00E0AULL,
		0xAD9534FE2980678BULL,
		0xCF177F308A105FB8ULL,
		0x7107094CE7C01D62ULL
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
		0xEE340339B49197A9ULL,
		0xD91610317D16C79DULL,
		0x3AB5707CF5A7239FULL,
		0xA6DD56A24142CB81ULL,
		0xD1FB6E963CC3AC84ULL,
		0x0A4AB77C0084E329ULL,
		0x4D84B546B5B29404ULL,
		0x3A63BB153FEAF9F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC68067369232F52ULL,
		0xB22C2062FA2D8F3BULL,
		0x756AE0F9EB4E473FULL,
		0x4DBAAD4482859702ULL,
		0xA3F6DD2C79875909ULL,
		0x14956EF80109C653ULL,
		0x9B096A8D6B652808ULL,
		0x74C7762A7FD5F3E6ULL
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
		0x74B4ADD78F809400ULL,
		0xEC2194644B868B83ULL,
		0x1032A57C939AF48CULL,
		0x99FE1373F3ED8151ULL,
		0x5E54564F67EF352FULL,
		0x8AE7C89DBDB93749ULL,
		0xDE86715E69B48253ULL,
		0x2138C0CE675187A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9695BAF1F012800ULL,
		0xD84328C8970D1706ULL,
		0x20654AF92735E919ULL,
		0x33FC26E7E7DB02A2ULL,
		0xBCA8AC9ECFDE6A5FULL,
		0x15CF913B7B726E92ULL,
		0xBD0CE2BCD36904A7ULL,
		0x4271819CCEA30F47ULL
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
		0x37EC42B2391622C6ULL,
		0xA167B93BFB50B1D8ULL,
		0x5F46B49A3974B56CULL,
		0xBD9BADBD724693B1ULL,
		0xCAEA96CBE3F45F6CULL,
		0xD75BC031FF71F8FCULL,
		0x14952BB2E30C7C99ULL,
		0x2311CC37C44403FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FD88564722C458CULL,
		0x42CF7277F6A163B0ULL,
		0xBE8D693472E96AD9ULL,
		0x7B375B7AE48D2762ULL,
		0x95D52D97C7E8BED9ULL,
		0xAEB78063FEE3F1F9ULL,
		0x292A5765C618F933ULL,
		0x4623986F888807FEULL
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
		0xD53BA514DF2C9E52ULL,
		0xAA93A88B34E53032ULL,
		0xF0AA8B20225BD513ULL,
		0x3A03F042DC32BAD9ULL,
		0x1ECEB1B93BB3C550ULL,
		0x22F42384B4E2A31CULL,
		0x12266965E4503113ULL,
		0x05FC3A06862E6C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA774A29BE593CA4ULL,
		0x5527511669CA6065ULL,
		0xE155164044B7AA27ULL,
		0x7407E085B86575B3ULL,
		0x3D9D637277678AA0ULL,
		0x45E8470969C54638ULL,
		0x244CD2CBC8A06226ULL,
		0x0BF8740D0C5CD894ULL
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
		0x26E38775D1476E58ULL,
		0x2912FDDD004B2E60ULL,
		0x72721D7C9B723DD7ULL,
		0xCE5340A30E95F510ULL,
		0x81821C84056C0B5DULL,
		0xBECEE15F1E56C644ULL,
		0x81853EE2F4E532E8ULL,
		0x04B3C1D81358D04FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC70EEBA28EDCB0ULL,
		0x5225FBBA00965CC0ULL,
		0xE4E43AF936E47BAEULL,
		0x9CA681461D2BEA20ULL,
		0x030439080AD816BBULL,
		0x7D9DC2BE3CAD8C89ULL,
		0x030A7DC5E9CA65D1ULL,
		0x096783B026B1A09FULL
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
		0xC05FBD7B64D47D6DULL,
		0x9E3BE7487027DD04ULL,
		0x0D6BC860312028A2ULL,
		0x232BF1BAB79E672EULL,
		0x28DF54BF0389E944ULL,
		0x942A12B894EF10F7ULL,
		0x92AEBB777C7C5477ULL,
		0x1D7B563EB589B9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BF7AF6C9A8FADAULL,
		0x3C77CE90E04FBA09ULL,
		0x1AD790C062405145ULL,
		0x4657E3756F3CCE5CULL,
		0x51BEA97E0713D288ULL,
		0x2854257129DE21EEULL,
		0x255D76EEF8F8A8EFULL,
		0x3AF6AC7D6B13738FULL
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
		0xE9E3652C2F22D29BULL,
		0xCFEB95A4F8AC139BULL,
		0x71DB5A56FD5650A1ULL,
		0x05D89A062FC68F0FULL,
		0xD81A634FB7717797ULL,
		0xC296D0F0D15AF9C8ULL,
		0x96A72276D1FD12B2ULL,
		0x1831FB4D9854EECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C6CA585E45A536ULL,
		0x9FD72B49F1582737ULL,
		0xE3B6B4ADFAACA143ULL,
		0x0BB1340C5F8D1E1EULL,
		0xB034C69F6EE2EF2EULL,
		0x852DA1E1A2B5F391ULL,
		0x2D4E44EDA3FA2565ULL,
		0x3063F69B30A9DD99ULL
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
		0x057DD9DB2297EF32ULL,
		0x5C1A4F25FC6E370BULL,
		0x3A80C35A388306B3ULL,
		0x8CB521C331FD9885ULL,
		0xE5EE1937A4097847ULL,
		0x4101B6670AF5F7C6ULL,
		0x7D193A9C78E461A6ULL,
		0x3CBE22A3CF40AE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AFBB3B6452FDE64ULL,
		0xB8349E4BF8DC6E16ULL,
		0x750186B471060D66ULL,
		0x196A438663FB310AULL,
		0xCBDC326F4812F08FULL,
		0x82036CCE15EBEF8DULL,
		0xFA327538F1C8C34CULL,
		0x797C45479E815D3AULL
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
		0xC5C8E0F9532CE9CFULL,
		0x4F14E689BD44314BULL,
		0x98157B026AEB8C31ULL,
		0x4D1C95A2DF64FBCFULL,
		0x73330D5F70FBACFEULL,
		0x992064CAB0BEE355ULL,
		0xFADCA6DE16DA184EULL,
		0x1E5C19FEF041C972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B91C1F2A659D39EULL,
		0x9E29CD137A886297ULL,
		0x302AF604D5D71862ULL,
		0x9A392B45BEC9F79FULL,
		0xE6661ABEE1F759FCULL,
		0x3240C995617DC6AAULL,
		0xF5B94DBC2DB4309DULL,
		0x3CB833FDE08392E5ULL
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
		0xF1B22D8B4F032457ULL,
		0x85569A1545C3EAEEULL,
		0x3C4BA1154A39E6A1ULL,
		0x64F0F94F89E53657ULL,
		0xB2814BFD17286353ULL,
		0x5DA13C79226C34E7ULL,
		0xD47423E93D68950DULL,
		0x3294D032A5724CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3645B169E0648AEULL,
		0x0AAD342A8B87D5DDULL,
		0x7897422A9473CD43ULL,
		0xC9E1F29F13CA6CAEULL,
		0x650297FA2E50C6A6ULL,
		0xBB4278F244D869CFULL,
		0xA8E847D27AD12A1AULL,
		0x6529A0654AE49945ULL
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
		0x83A5001E8E68F5B8ULL,
		0x3687EDD09763BD8FULL,
		0x28F8FA765486D0EBULL,
		0x56B3775C5EB0FA8EULL,
		0xEFD9CFE05CB05B18ULL,
		0xFB1CE8B92BEA9FEAULL,
		0xBEF9220C239A2A84ULL,
		0x3C24521C2EB3FFF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074A003D1CD1EB70ULL,
		0x6D0FDBA12EC77B1FULL,
		0x51F1F4ECA90DA1D6ULL,
		0xAD66EEB8BD61F51CULL,
		0xDFB39FC0B960B630ULL,
		0xF639D17257D53FD5ULL,
		0x7DF2441847345509ULL,
		0x7848A4385D67FFEFULL
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
		0xB1DF93BFFBDE37E3ULL,
		0x3E48D39EE2A0F68AULL,
		0x99925FE9FED690B2ULL,
		0x6CAB31B6900D25D6ULL,
		0xE55DB9927FA5181AULL,
		0xBE200E87B019BF67ULL,
		0x1345838CD0685480ULL,
		0x06D81B4F5CD08FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BF277FF7BC6FC6ULL,
		0x7C91A73DC541ED15ULL,
		0x3324BFD3FDAD2164ULL,
		0xD956636D201A4BADULL,
		0xCABB7324FF4A3034ULL,
		0x7C401D0F60337ECFULL,
		0x268B0719A0D0A901ULL,
		0x0DB0369EB9A11FF8ULL
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
		0x95848F06A0673E5AULL,
		0x140A64BF324E46C7ULL,
		0xF082E2AD7327F87DULL,
		0x60F673B7F4149A63ULL,
		0x18E3E692060A31AFULL,
		0x5866CCBB161DFB3FULL,
		0x21636FE60E85FD2AULL,
		0x008850665B1E5A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B091E0D40CE7CB4ULL,
		0x2814C97E649C8D8FULL,
		0xE105C55AE64FF0FAULL,
		0xC1ECE76FE82934C7ULL,
		0x31C7CD240C14635EULL,
		0xB0CD99762C3BF67EULL,
		0x42C6DFCC1D0BFA54ULL,
		0x0110A0CCB63CB47CULL
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
		0x45D6991F39AC1F16ULL,
		0x637C0AEFBDBF8E5DULL,
		0x73A8BFB1D4A16C1CULL,
		0xE1F7B1862334519CULL,
		0xAA379970A20537AFULL,
		0xE8788F59DC74AED9ULL,
		0xDB0F2958897ADB83ULL,
		0x01802BC7BA035E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BAD323E73583E2CULL,
		0xC6F815DF7B7F1CBAULL,
		0xE7517F63A942D838ULL,
		0xC3EF630C4668A338ULL,
		0x546F32E1440A6F5FULL,
		0xD0F11EB3B8E95DB3ULL,
		0xB61E52B112F5B707ULL,
		0x0300578F7406BC43ULL
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
		0x372DD0271389DA94ULL,
		0xC1962F0897714B5CULL,
		0x8DF1D71F82106398ULL,
		0x4C7079DC6321FDD1ULL,
		0xB71991A9A946FCD9ULL,
		0x061B29E0603E89B0ULL,
		0x48DE802B5C1D9087ULL,
		0x3C55871F8CF7513EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E5BA04E2713B528ULL,
		0x832C5E112EE296B8ULL,
		0x1BE3AE3F0420C731ULL,
		0x98E0F3B8C643FBA3ULL,
		0x6E332353528DF9B2ULL,
		0x0C3653C0C07D1361ULL,
		0x91BD0056B83B210EULL,
		0x78AB0E3F19EEA27CULL
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
		0x05F0D5E7A5487E1EULL,
		0xACB9EBD76EF275F6ULL,
		0xBCE46440E73A515DULL,
		0x600B7917AD00F774ULL,
		0xC2E2A066983EC70FULL,
		0x6E50AB975DB9BD5BULL,
		0x0AB7D357BDD72403ULL,
		0x1E5D72B7B9A844A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE1ABCF4A90FC3CULL,
		0x5973D7AEDDE4EBECULL,
		0x79C8C881CE74A2BBULL,
		0xC016F22F5A01EEE9ULL,
		0x85C540CD307D8E1EULL,
		0xDCA1572EBB737AB7ULL,
		0x156FA6AF7BAE4806ULL,
		0x3CBAE56F73508950ULL
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
		0x3434B6E8EFC4CB21ULL,
		0xE445CBEEB11EE6D6ULL,
		0x38B7D3BD5A38A076ULL,
		0x2B1611718E1C109FULL,
		0x9DE4C0EC65094091ULL,
		0x47FF56F66E490BFDULL,
		0x9C0D240AE411C09AULL,
		0x3CF31622C06D2153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68696DD1DF899642ULL,
		0xC88B97DD623DCDACULL,
		0x716FA77AB47140EDULL,
		0x562C22E31C38213EULL,
		0x3BC981D8CA128122ULL,
		0x8FFEADECDC9217FBULL,
		0x381A4815C8238134ULL,
		0x79E62C4580DA42A7ULL
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
		0x87BE63593744BD5EULL,
		0x45CEB1839669EE00ULL,
		0x24AD6DD6FCC698ACULL,
		0x1604B9164631A207ULL,
		0x2260A80EA8EB6E92ULL,
		0x5A1B089C9C3C4450ULL,
		0x1DBB3EA096196EEDULL,
		0x0EB86CF651A04307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7CC6B26E897ABCULL,
		0x8B9D63072CD3DC01ULL,
		0x495ADBADF98D3158ULL,
		0x2C09722C8C63440EULL,
		0x44C1501D51D6DD24ULL,
		0xB4361139387888A0ULL,
		0x3B767D412C32DDDAULL,
		0x1D70D9ECA340860EULL
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
		0x38118A2B87FCEFA7ULL,
		0xB267D668D27B438DULL,
		0x9A64E14E28B47E2BULL,
		0x0F5F623A6A1D1BCFULL,
		0x269E1B9CF4183BCBULL,
		0xAD197589AE64E749ULL,
		0x4DF1DE5064598B55ULL,
		0x05F1E3EF0D20CA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702314570FF9DF4EULL,
		0x64CFACD1A4F6871AULL,
		0x34C9C29C5168FC57ULL,
		0x1EBEC474D43A379FULL,
		0x4D3C3739E8307796ULL,
		0x5A32EB135CC9CE92ULL,
		0x9BE3BCA0C8B316ABULL,
		0x0BE3C7DE1A41950AULL
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
		0x07A951A46FB7679FULL,
		0x7AEC5491A6F63EE3ULL,
		0xD4F36F83E3A31725ULL,
		0x696A56353898888AULL,
		0xBBCA50137D7DCCACULL,
		0x99C072E071C058EEULL,
		0x41A14690F4F0BB14ULL,
		0x24FEE199694F627CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F52A348DF6ECF3EULL,
		0xF5D8A9234DEC7DC6ULL,
		0xA9E6DF07C7462E4AULL,
		0xD2D4AC6A71311115ULL,
		0x7794A026FAFB9958ULL,
		0x3380E5C0E380B1DDULL,
		0x83428D21E9E17629ULL,
		0x49FDC332D29EC4F8ULL
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
		0x3ABCF8CB42918F04ULL,
		0x5BD9AD8D22FF2A97ULL,
		0x34B179C17E0EBE8CULL,
		0xB36FF99CB7FF679BULL,
		0xEE09FFCB3EDDE74BULL,
		0xB40C6AFFF990C3EFULL,
		0x6CA328188CBC19A2ULL,
		0x143B91C23FBDABB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7579F19685231E08ULL,
		0xB7B35B1A45FE552EULL,
		0x6962F382FC1D7D18ULL,
		0x66DFF3396FFECF36ULL,
		0xDC13FF967DBBCE97ULL,
		0x6818D5FFF32187DFULL,
		0xD946503119783345ULL,
		0x287723847F7B5770ULL
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
		0x4AB6E2D6FE9D376AULL,
		0xC9579ADE2BBC65B5ULL,
		0xFE2B95AF1C4FCEB9ULL,
		0xE1163DD883114A37ULL,
		0x02FD01260C11C386ULL,
		0x3D8B59F1E8E7C353ULL,
		0x9B7D1C1240FDBCC1ULL,
		0x04511E123DEF7BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956DC5ADFD3A6ED4ULL,
		0x92AF35BC5778CB6AULL,
		0xFC572B5E389F9D73ULL,
		0xC22C7BB10622946FULL,
		0x05FA024C1823870DULL,
		0x7B16B3E3D1CF86A6ULL,
		0x36FA382481FB7982ULL,
		0x08A23C247BDEF79FULL
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
		0x9885C5C9C9298F75ULL,
		0x32E550A29382E8B7ULL,
		0x0E31C1414F628C61ULL,
		0x6267ABD7E73A5D55ULL,
		0x4FF3C9120FE77B10ULL,
		0x3AD63E424D1A1FD4ULL,
		0x0937196C474C1B82ULL,
		0x3361ED06775EACB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x310B8B9392531EEAULL,
		0x65CAA1452705D16FULL,
		0x1C6382829EC518C2ULL,
		0xC4CF57AFCE74BAAAULL,
		0x9FE792241FCEF620ULL,
		0x75AC7C849A343FA8ULL,
		0x126E32D88E983704ULL,
		0x66C3DA0CEEBD5962ULL
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
		0xCB1925C0E85B4953ULL,
		0xA6C27B5477B9682FULL,
		0xACF5EECFB4F267C3ULL,
		0x8C8948BFCC1EDA4CULL,
		0xF31CCCE600487CC1ULL,
		0x8924D2506CFB6C4CULL,
		0x5B2881C98EFA1F65ULL,
		0x294E279796A82BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96324B81D0B692A6ULL,
		0x4D84F6A8EF72D05FULL,
		0x59EBDD9F69E4CF87ULL,
		0x1912917F983DB499ULL,
		0xE63999CC0090F983ULL,
		0x1249A4A0D9F6D899ULL,
		0xB65103931DF43ECBULL,
		0x529C4F2F2D5057EEULL
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
		0xA93F0138D2A25953ULL,
		0x1BDB0C1511F8390FULL,
		0xB1F5C8E7AE3532D1ULL,
		0xC2FF774CCCA89D05ULL,
		0xA026F8484E6E29EBULL,
		0x064511C512C21807ULL,
		0xA8B10900EA78AD9FULL,
		0x3591D5F926A44337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527E0271A544B2A6ULL,
		0x37B6182A23F0721FULL,
		0x63EB91CF5C6A65A2ULL,
		0x85FEEE9999513A0BULL,
		0x404DF0909CDC53D7ULL,
		0x0C8A238A2584300FULL,
		0x51621201D4F15B3EULL,
		0x6B23ABF24D48866FULL
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
		0x495219E889319A9AULL,
		0x21CEC89D5502474DULL,
		0x08A922E6C724FD90ULL,
		0x86E23F868A1F37FBULL,
		0x596D30DF96CBCFE1ULL,
		0xB7A180F9C3216D6BULL,
		0x05A719FE5C35163AULL,
		0x002E036781F38353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A433D112633534ULL,
		0x439D913AAA048E9AULL,
		0x115245CD8E49FB20ULL,
		0x0DC47F0D143E6FF6ULL,
		0xB2DA61BF2D979FC3ULL,
		0x6F4301F38642DAD6ULL,
		0x0B4E33FCB86A2C75ULL,
		0x005C06CF03E706A6ULL
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
		0xAD387E2645FA08F5ULL,
		0x2C1F60E9763F4566ULL,
		0x0B37FA3A39B0F767ULL,
		0x9207387228190C49ULL,
		0xAA436DE914D3FAF5ULL,
		0x21C595D1C3CBE0BDULL,
		0xCB730A6A500F48E7ULL,
		0x385946C872ABB8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A70FC4C8BF411EAULL,
		0x583EC1D2EC7E8ACDULL,
		0x166FF4747361EECEULL,
		0x240E70E450321892ULL,
		0x5486DBD229A7F5EBULL,
		0x438B2BA38797C17BULL,
		0x96E614D4A01E91CEULL,
		0x70B28D90E55771B5ULL
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
		0xD04668B7E51B24FAULL,
		0x8458F3879F50F33CULL,
		0x625BA2D56D0AE3E6ULL,
		0xF610C6FD56422AD0ULL,
		0xE71F04BD493914B6ULL,
		0x5BD0A7641BA93820ULL,
		0xAC93F1BD67DBE42EULL,
		0x28A4C4EC05D8E4D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08CD16FCA3649F4ULL,
		0x08B1E70F3EA1E679ULL,
		0xC4B745AADA15C7CDULL,
		0xEC218DFAAC8455A0ULL,
		0xCE3E097A9272296DULL,
		0xB7A14EC837527041ULL,
		0x5927E37ACFB7C85CULL,
		0x514989D80BB1C9A9ULL
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
		0xC9A56CD6709318D8ULL,
		0xED8248664B75C3CEULL,
		0x4D07518EFA4CCDAAULL,
		0x17335441256B7799ULL,
		0xF04CCC4908776B79ULL,
		0x98994997434414D2ULL,
		0x855FDCAEB822047EULL,
		0x0AD5F73DC9B30538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934AD9ACE12631B0ULL,
		0xDB0490CC96EB879DULL,
		0x9A0EA31DF4999B55ULL,
		0x2E66A8824AD6EF32ULL,
		0xE099989210EED6F2ULL,
		0x3132932E868829A5ULL,
		0x0ABFB95D704408FDULL,
		0x15ABEE7B93660A71ULL
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
		0x703D98D366CC6C43ULL,
		0x15E6FC7C5E2A13D4ULL,
		0x83EB030036B8B386ULL,
		0xC2FCBC3FAC0F2AF4ULL,
		0xEB4428AB7EABDDC1ULL,
		0x5E566698FB88649EULL,
		0x5D2BDF162A453E78ULL,
		0x0B725F9F32F7C689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07B31A6CD98D886ULL,
		0x2BCDF8F8BC5427A8ULL,
		0x07D606006D71670CULL,
		0x85F9787F581E55E9ULL,
		0xD6885156FD57BB83ULL,
		0xBCACCD31F710C93DULL,
		0xBA57BE2C548A7CF0ULL,
		0x16E4BF3E65EF8D12ULL
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
		0x8A279F6FA07ACE85ULL,
		0x7F30006775B06659ULL,
		0xC0C1F1645AFFE08BULL,
		0x9D662373320967E0ULL,
		0xEC533AB6F2D55C52ULL,
		0x6D1F81940D9E2E11ULL,
		0x9F1E74DE808FDCF6ULL,
		0x17CCB7663DE9BD5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144F3EDF40F59D0AULL,
		0xFE6000CEEB60CCB3ULL,
		0x8183E2C8B5FFC116ULL,
		0x3ACC46E66412CFC1ULL,
		0xD8A6756DE5AAB8A5ULL,
		0xDA3F03281B3C5C23ULL,
		0x3E3CE9BD011FB9ECULL,
		0x2F996ECC7BD37ABDULL
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
		0x1A1D32217DC649EFULL,
		0xDB66CEE97DE068B4ULL,
		0x116BA750CAF5A7DDULL,
		0x483B4A2BEC9724E9ULL,
		0x6B8CBA14F238434DULL,
		0x96FDEBFEA7F4F6A0ULL,
		0x9598CDCC32DF9350ULL,
		0x3AD087ADC4B8A7F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x343A6442FB8C93DEULL,
		0xB6CD9DD2FBC0D168ULL,
		0x22D74EA195EB4FBBULL,
		0x90769457D92E49D2ULL,
		0xD7197429E470869AULL,
		0x2DFBD7FD4FE9ED40ULL,
		0x2B319B9865BF26A1ULL,
		0x75A10F5B89714FE1ULL
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
		0xCE0F3B4ACF6ABBFFULL,
		0x8701822BC13EE30EULL,
		0x0EF1C513CBA6F040ULL,
		0xD8D702EBDE9A6264ULL,
		0x2715CAEDAE91F578ULL,
		0x0A3A189E7DAECBBDULL,
		0xA7543995C48684E0ULL,
		0x267E648D593248CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C1E76959ED577FEULL,
		0x0E030457827DC61DULL,
		0x1DE38A27974DE081ULL,
		0xB1AE05D7BD34C4C8ULL,
		0x4E2B95DB5D23EAF1ULL,
		0x1474313CFB5D977AULL,
		0x4EA8732B890D09C0ULL,
		0x4CFCC91AB264919BULL
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
		0xD0FC8123D647B5E3ULL,
		0x966B1BBEAA2B3EA3ULL,
		0x40AE2DCF2AE9650AULL,
		0x9D8C1F2386C67216ULL,
		0x6F24D4B65AC98062ULL,
		0xDF612B508EEDC305ULL,
		0x0DE1324D3308055FULL,
		0x30127E5DAEFBD536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F90247AC8F6BC6ULL,
		0x2CD6377D54567D47ULL,
		0x815C5B9E55D2CA15ULL,
		0x3B183E470D8CE42CULL,
		0xDE49A96CB59300C5ULL,
		0xBEC256A11DDB860AULL,
		0x1BC2649A66100ABFULL,
		0x6024FCBB5DF7AA6CULL
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
		0x0D44EA62CBD3B2C0ULL,
		0xCCA5A05F37847154ULL,
		0x0B4D016834F584D9ULL,
		0xECC821426F616845ULL,
		0x23DC5B8C7A78A5B6ULL,
		0xE1A5A278A51C5E58ULL,
		0x6CD72BA5F8B316D5ULL,
		0x24AE9E5ED47B2C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A89D4C597A76580ULL,
		0x994B40BE6F08E2A8ULL,
		0x169A02D069EB09B3ULL,
		0xD9904284DEC2D08AULL,
		0x47B8B718F4F14B6DULL,
		0xC34B44F14A38BCB0ULL,
		0xD9AE574BF1662DABULL,
		0x495D3CBDA8F6589AULL
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
		0xA1B6382B5569664BULL,
		0x41F3DCCC1DE538D6ULL,
		0x22BC4E6450B3F401ULL,
		0x50A256FC860222DCULL,
		0x9F903B01E910DE4AULL,
		0x26BC0ED885787688ULL,
		0xD651EBCB2CB69B24ULL,
		0x2F24E2BEB8D7D1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436C7056AAD2CC96ULL,
		0x83E7B9983BCA71ADULL,
		0x45789CC8A167E802ULL,
		0xA144ADF90C0445B8ULL,
		0x3F207603D221BC94ULL,
		0x4D781DB10AF0ED11ULL,
		0xACA3D796596D3648ULL,
		0x5E49C57D71AFA38FULL
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
		0x4699542FDF849FC5ULL,
		0x3F7623D05670F310ULL,
		0xC3CCD6B0A35A5BC9ULL,
		0xC81E7F6D8ECA136AULL,
		0xEB2E7F184931B51DULL,
		0x80DEAA8D985DF7E0ULL,
		0x7454B914A07B4226ULL,
		0x3C7834D4AEAD3F17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D32A85FBF093F8AULL,
		0x7EEC47A0ACE1E620ULL,
		0x8799AD6146B4B792ULL,
		0x903CFEDB1D9426D5ULL,
		0xD65CFE3092636A3BULL,
		0x01BD551B30BBEFC1ULL,
		0xE8A9722940F6844DULL,
		0x78F069A95D5A7E2EULL
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
		0x2FD36E22E61F6584ULL,
		0x3562AD51B4C1EBCDULL,
		0xE407B20DFB586D52ULL,
		0x9E669478A9CA9494ULL,
		0xF6BA95FA2D562B77ULL,
		0x63F7564D8A8CE9E3ULL,
		0x4EFA59535E09BAA0ULL,
		0x2743F21FE56152EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA6DC45CC3ECB08ULL,
		0x6AC55AA36983D79AULL,
		0xC80F641BF6B0DAA4ULL,
		0x3CCD28F153952929ULL,
		0xED752BF45AAC56EFULL,
		0xC7EEAC9B1519D3C7ULL,
		0x9DF4B2A6BC137540ULL,
		0x4E87E43FCAC2A5DAULL
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
		0x5FAAEB93C8344E8CULL,
		0x49DEEFEF1DEFCFA8ULL,
		0x7905AC011E404912ULL,
		0xDD9D5246ECEB8182ULL,
		0x3E7272C04F94E126ULL,
		0x36950D1AC7116091ULL,
		0xB02209DB10071BFDULL,
		0x24292E99C453E505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF55D72790689D18ULL,
		0x93BDDFDE3BDF9F50ULL,
		0xF20B58023C809224ULL,
		0xBB3AA48DD9D70304ULL,
		0x7CE4E5809F29C24DULL,
		0x6D2A1A358E22C122ULL,
		0x604413B6200E37FAULL,
		0x48525D3388A7CA0BULL
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
		0x91A9369881943213ULL,
		0x291D006A7B49729EULL,
		0xC83D59AAEAA14F75ULL,
		0xB5D85DF56230D7E1ULL,
		0xF2651861046961EBULL,
		0xD2270F27E016054CULL,
		0x157C03B8CE41BA8EULL,
		0x345EB0F4A8141486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23526D3103286426ULL,
		0x523A00D4F692E53DULL,
		0x907AB355D5429EEAULL,
		0x6BB0BBEAC461AFC3ULL,
		0xE4CA30C208D2C3D7ULL,
		0xA44E1E4FC02C0A99ULL,
		0x2AF807719C83751DULL,
		0x68BD61E95028290CULL
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
		0x76457FC6933E8DECULL,
		0x57CF7CCDAE147DCBULL,
		0x9E041C74418D49B3ULL,
		0xB46FA23322F6ED9CULL,
		0xF1969FF99E798B04ULL,
		0x1DF16C6B5DC7F790ULL,
		0xD183C39D89F55BBBULL,
		0x2ABE6D6405EBD812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC8AFF8D267D1BD8ULL,
		0xAF9EF99B5C28FB96ULL,
		0x3C0838E8831A9366ULL,
		0x68DF446645EDDB39ULL,
		0xE32D3FF33CF31609ULL,
		0x3BE2D8D6BB8FEF21ULL,
		0xA307873B13EAB776ULL,
		0x557CDAC80BD7B025ULL
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
		0xFF209D3E0510BB5FULL,
		0x3908F76FF2A15AA8ULL,
		0x54D9CE4ECB154F06ULL,
		0xD95B6C33475916EAULL,
		0xF15D7DCE959AF15DULL,
		0x24E3396D51FB997DULL,
		0xFDF221414DA569D1ULL,
		0x12F70ABA77025437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE413A7C0A2176BEULL,
		0x7211EEDFE542B551ULL,
		0xA9B39C9D962A9E0CULL,
		0xB2B6D8668EB22DD4ULL,
		0xE2BAFB9D2B35E2BBULL,
		0x49C672DAA3F732FBULL,
		0xFBE442829B4AD3A2ULL,
		0x25EE1574EE04A86FULL
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
		0x1E6FC9354DEA154EULL,
		0x502DBF75CEBC3526ULL,
		0x607C0FEF981863BCULL,
		0x43126B237349A035ULL,
		0xA8B91AFF6017D406ULL,
		0x11939D8A41C8ED6AULL,
		0x1476A2F7DEF48811ULL,
		0x2A671607DAFD83B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CDF926A9BD42A9CULL,
		0xA05B7EEB9D786A4CULL,
		0xC0F81FDF3030C778ULL,
		0x8624D646E693406AULL,
		0x517235FEC02FA80CULL,
		0x23273B148391DAD5ULL,
		0x28ED45EFBDE91022ULL,
		0x54CE2C0FB5FB076AULL
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
		0x9A509A799AA50D76ULL,
		0xE338F5325642FC3EULL,
		0xD67DC7DB63BCE4C3ULL,
		0xE64D83389C020A5EULL,
		0x622FF89D5299102EULL,
		0xAAF73B7E7A87191EULL,
		0x1BAFE7D2837B686CULL,
		0x082B33E97EC59BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34A134F3354A1AECULL,
		0xC671EA64AC85F87DULL,
		0xACFB8FB6C779C987ULL,
		0xCC9B0671380414BDULL,
		0xC45FF13AA532205DULL,
		0x55EE76FCF50E323CULL,
		0x375FCFA506F6D0D9ULL,
		0x105667D2FD8B37AAULL
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
		0x80DABE8D80A777C3ULL,
		0xD50D2C64528A6505ULL,
		0x9B5ABD8E2E6C1F60ULL,
		0x767076FBE184523BULL,
		0x9CCFA7B73B9B95BFULL,
		0xA1F9352D5110B27EULL,
		0x415BFE329A9B1DEAULL,
		0x2BBE33C0A4C97121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01B57D1B014EEF86ULL,
		0xAA1A58C8A514CA0BULL,
		0x36B57B1C5CD83EC1ULL,
		0xECE0EDF7C308A477ULL,
		0x399F4F6E77372B7EULL,
		0x43F26A5AA22164FDULL,
		0x82B7FC6535363BD5ULL,
		0x577C67814992E242ULL
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
		0xBB89E61E4278B92DULL,
		0x0D5DCA7A93B5FD5CULL,
		0x62DE1084DCFF7DC0ULL,
		0xE598E4AAA0A4C1A1ULL,
		0x8A6AEB50FA71123BULL,
		0x267821320042C816ULL,
		0xF0C893435A3A6056ULL,
		0x03104ABFF3F09CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7713CC3C84F1725AULL,
		0x1ABB94F5276BFAB9ULL,
		0xC5BC2109B9FEFB80ULL,
		0xCB31C95541498342ULL,
		0x14D5D6A1F4E22477ULL,
		0x4CF042640085902DULL,
		0xE1912686B474C0ACULL,
		0x0620957FE7E139EFULL
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
		0x2E019D56BDBADFCFULL,
		0xBA52F37156853517ULL,
		0x159420D9FF092D76ULL,
		0xDB3CF8CDA1BDE63AULL,
		0xB984FDDE941037C4ULL,
		0xAB9C8E340CB11868ULL,
		0x1AA238D11672F590ULL,
		0x2AEF1D796B327705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C033AAD7B75BF9EULL,
		0x74A5E6E2AD0A6A2EULL,
		0x2B2841B3FE125AEDULL,
		0xB679F19B437BCC74ULL,
		0x7309FBBD28206F89ULL,
		0x57391C68196230D1ULL,
		0x354471A22CE5EB21ULL,
		0x55DE3AF2D664EE0AULL
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
		0xD2DE61BB4A77FF91ULL,
		0xD86DA8A548428DFDULL,
		0x47EE6659EEB541F2ULL,
		0x9604A251EDE45F6FULL,
		0x1FF8BA2D0DDBF29BULL,
		0x438521842FEBE732ULL,
		0xE82AADCC73EF72B9ULL,
		0x1A1B33635EE27EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5BCC37694EFFF22ULL,
		0xB0DB514A90851BFBULL,
		0x8FDCCCB3DD6A83E5ULL,
		0x2C0944A3DBC8BEDEULL,
		0x3FF1745A1BB7E537ULL,
		0x870A43085FD7CE64ULL,
		0xD0555B98E7DEE572ULL,
		0x343666C6BDC4FD45ULL
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
		0x0E4AB01C4DD17372ULL,
		0xCF31B5663440C9D6ULL,
		0x99A00C03360DC73AULL,
		0x365DB37FFAB1E123ULL,
		0xEF504B771F9717F9ULL,
		0x412C06C1E906D1F9ULL,
		0x464029F046D374B5ULL,
		0x10DA23BE0109163DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9560389BA2E6E4ULL,
		0x9E636ACC688193ACULL,
		0x334018066C1B8E75ULL,
		0x6CBB66FFF563C247ULL,
		0xDEA096EE3F2E2FF2ULL,
		0x82580D83D20DA3F3ULL,
		0x8C8053E08DA6E96AULL,
		0x21B4477C02122C7AULL
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
		0xFCA20AD93868B331ULL,
		0xAD759F6066CA5D56ULL,
		0xF350E8230E6DAEB0ULL,
		0xD56B2B24D499A1A7ULL,
		0xDFC4EF6C65B27565ULL,
		0xF81DD3B8F159083DULL,
		0xBD5A63245D0534B4ULL,
		0x3975BA3DB466704DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF94415B270D16662ULL,
		0x5AEB3EC0CD94BAADULL,
		0xE6A1D0461CDB5D61ULL,
		0xAAD65649A933434FULL,
		0xBF89DED8CB64EACBULL,
		0xF03BA771E2B2107BULL,
		0x7AB4C648BA0A6969ULL,
		0x72EB747B68CCE09BULL
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
		0x246A4C3055BBB19CULL,
		0x628B538C278CC338ULL,
		0xA35B1BF09E7CCAD9ULL,
		0xE5E4955F15949926ULL,
		0x026954FB80FCC217ULL,
		0x7C61AC8444C8F856ULL,
		0x42B068765CB1E411ULL,
		0x2BE43E8F409A03A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48D49860AB776338ULL,
		0xC516A7184F198670ULL,
		0x46B637E13CF995B2ULL,
		0xCBC92ABE2B29324DULL,
		0x04D2A9F701F9842FULL,
		0xF8C359088991F0ACULL,
		0x8560D0ECB963C822ULL,
		0x57C87D1E8134074CULL
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
		0x3B152A53F8EDF6C9ULL,
		0x6C964D359050B6A2ULL,
		0xADAAE7A46B96C47CULL,
		0x895395CF066C219EULL,
		0xEFCA564837BE5E36ULL,
		0x9FD92D18D8001579ULL,
		0x922A00BF1FEE71F0ULL,
		0x151546206A3C453FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x762A54A7F1DBED92ULL,
		0xD92C9A6B20A16D44ULL,
		0x5B55CF48D72D88F8ULL,
		0x12A72B9E0CD8433DULL,
		0xDF94AC906F7CBC6DULL,
		0x3FB25A31B0002AF3ULL,
		0x2454017E3FDCE3E1ULL,
		0x2A2A8C40D4788A7FULL
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
		0x1452F2B8F3F32AA4ULL,
		0xEFEC73A9C7220EA5ULL,
		0xB07BBC257D9D133AULL,
		0x149658F9D0EB519FULL,
		0xD25D66849E9B1158ULL,
		0x79B6C500D9D87834ULL,
		0xD6A8D4EF1A8C65BBULL,
		0x0E88CDA1EBC24880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A5E571E7E65548ULL,
		0xDFD8E7538E441D4AULL,
		0x60F7784AFB3A2675ULL,
		0x292CB1F3A1D6A33FULL,
		0xA4BACD093D3622B0ULL,
		0xF36D8A01B3B0F069ULL,
		0xAD51A9DE3518CB76ULL,
		0x1D119B43D7849101ULL
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
		0x2C5E9D0F40BFA20AULL,
		0xF3894A1A19F4EEC5ULL,
		0x8B6A0D131339D4CDULL,
		0xA88A14BBE490E320ULL,
		0x66EAD3C815CA8920ULL,
		0x63E80E8289810A19ULL,
		0x69ADBEE33E30B233ULL,
		0x13DACD4A701C1FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58BD3A1E817F4414ULL,
		0xE712943433E9DD8AULL,
		0x16D41A262673A99BULL,
		0x51142977C921C641ULL,
		0xCDD5A7902B951241ULL,
		0xC7D01D0513021432ULL,
		0xD35B7DC67C616466ULL,
		0x27B59A94E0383FFAULL
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
		0x5BBF0FC97C4FA230ULL,
		0x53C25813883229BEULL,
		0x553CF552FFAED109ULL,
		0xB22245D8A1D041C9ULL,
		0x871D3CBC32A84AB0ULL,
		0xFC554BB4193FF1A6ULL,
		0x4671F49C649EFB8FULL,
		0x0BC6CF9A488446FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77E1F92F89F4460ULL,
		0xA784B0271064537CULL,
		0xAA79EAA5FF5DA212ULL,
		0x64448BB143A08392ULL,
		0x0E3A797865509561ULL,
		0xF8AA9768327FE34DULL,
		0x8CE3E938C93DF71FULL,
		0x178D9F3491088DFCULL
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
		0x636575F081050647ULL,
		0xC78F39CDB01182DEULL,
		0x5FA32C64C7F519C3ULL,
		0x6C704BBF9A34BF7AULL,
		0x2F2CBD009FA11F53ULL,
		0x4BD55F8118249FA8ULL,
		0xB352AC3A23DC7DE3ULL,
		0x28B677B0E5CEF2D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CAEBE1020A0C8EULL,
		0x8F1E739B602305BCULL,
		0xBF4658C98FEA3387ULL,
		0xD8E0977F34697EF4ULL,
		0x5E597A013F423EA6ULL,
		0x97AABF0230493F50ULL,
		0x66A5587447B8FBC6ULL,
		0x516CEF61CB9DE5A5ULL
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
		0x32E7114A8357E77AULL,
		0x2793CC17AAAF7ECEULL,
		0x16EC9A374A047311ULL,
		0x99CDE99D39FF2BC3ULL,
		0x738D31223B116CFFULL,
		0xD75924A0124E21B0ULL,
		0xAEC651979297F913ULL,
		0x250F3A63C70EDB15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65CE229506AFCEF4ULL,
		0x4F27982F555EFD9CULL,
		0x2DD9346E9408E622ULL,
		0x339BD33A73FE5786ULL,
		0xE71A62447622D9FFULL,
		0xAEB24940249C4360ULL,
		0x5D8CA32F252FF227ULL,
		0x4A1E74C78E1DB62BULL
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
		0x190C6C00F590A410ULL,
		0x91AE3437E631AACFULL,
		0xC94C0B5992A07B27ULL,
		0x4699FFACAAB1DBAFULL,
		0x6BA9B0957B791C0EULL,
		0x7CCDE25A0625D0CCULL,
		0x6E9BFCF626EC463BULL,
		0x373A421E82381062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3218D801EB214820ULL,
		0x235C686FCC63559EULL,
		0x929816B32540F64FULL,
		0x8D33FF595563B75FULL,
		0xD753612AF6F2381CULL,
		0xF99BC4B40C4BA198ULL,
		0xDD37F9EC4DD88C76ULL,
		0x6E74843D047020C4ULL
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
		0xEFE434FB012A58D4ULL,
		0x7B425AD59C80CD39ULL,
		0xE148F6EAF85C0033ULL,
		0xD311404F97E4F660ULL,
		0xCA015F15550DA92BULL,
		0x68541F11EAB45F82ULL,
		0x90E3C29C89A4E0D8ULL,
		0x22B26F8BE590D17BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFC869F60254B1A8ULL,
		0xF684B5AB39019A73ULL,
		0xC291EDD5F0B80066ULL,
		0xA622809F2FC9ECC1ULL,
		0x9402BE2AAA1B5257ULL,
		0xD0A83E23D568BF05ULL,
		0x21C785391349C1B0ULL,
		0x4564DF17CB21A2F7ULL
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
		0x13A110A6CB3CBE99ULL,
		0x6D1956FBC9FDA2F7ULL,
		0x44D974B5E4E852F0ULL,
		0x2E015D4879034C0EULL,
		0xC8A130ECF06D3305ULL,
		0xDB93D30C2B245CB2ULL,
		0x6076E2B912B718FFULL,
		0x313201E111049C3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2742214D96797D32ULL,
		0xDA32ADF793FB45EEULL,
		0x89B2E96BC9D0A5E0ULL,
		0x5C02BA90F206981CULL,
		0x914261D9E0DA660AULL,
		0xB727A6185648B965ULL,
		0xC0EDC572256E31FFULL,
		0x626403C222093878ULL
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
		0x6DEF0D147DE821BFULL,
		0xB8C8878FE120C521ULL,
		0x28EC567DD8A75CADULL,
		0x43DE17CB387C9474ULL,
		0x3034666D4A5926EFULL,
		0x0DA62F1FC305514AULL,
		0x8BE3AEE6F11963DFULL,
		0x06A4517D2E289555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBDE1A28FBD0437EULL,
		0x71910F1FC2418A42ULL,
		0x51D8ACFBB14EB95BULL,
		0x87BC2F9670F928E8ULL,
		0x6068CCDA94B24DDEULL,
		0x1B4C5E3F860AA294ULL,
		0x17C75DCDE232C7BEULL,
		0x0D48A2FA5C512AABULL
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
		0x3D1C31658A774059ULL,
		0x8B40CC40091702CBULL,
		0xB22385E8DCD7921FULL,
		0xB8F4F056A128EB9AULL,
		0x9E97617A0243768CULL,
		0x48FC07F3F2156BA7ULL,
		0x59322EFEFFF167FFULL,
		0x19D2EFDCB7657609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3862CB14EE80B2ULL,
		0x16819880122E0596ULL,
		0x64470BD1B9AF243FULL,
		0x71E9E0AD4251D735ULL,
		0x3D2EC2F40486ED19ULL,
		0x91F80FE7E42AD74FULL,
		0xB2645DFDFFE2CFFEULL,
		0x33A5DFB96ECAEC12ULL
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
		0x410E93F96DE746BCULL,
		0x4B5F4A6EE7ACFE0FULL,
		0xA1A5E8CAE57414AAULL,
		0xA557C945DFDD949AULL,
		0x528FF95CC1919F16ULL,
		0x9A043C30907C13F2ULL,
		0x6E4DC2451C2389A3ULL,
		0x1C78F183B9DC27F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x821D27F2DBCE8D78ULL,
		0x96BE94DDCF59FC1EULL,
		0x434BD195CAE82954ULL,
		0x4AAF928BBFBB2935ULL,
		0xA51FF2B983233E2DULL,
		0x3408786120F827E4ULL,
		0xDC9B848A38471347ULL,
		0x38F1E30773B84FE8ULL
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
		0x4674B0533400DD1BULL,
		0xBCEA9EF6476F124BULL,
		0x0CE5390A7E14FCB9ULL,
		0x3DD4A366C961AC15ULL,
		0xDA1FA19D86747843ULL,
		0x60BE5FE671DB4A6BULL,
		0xE16C0CFF2495092EULL,
		0x3332BE4BEC7CAF52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE960A66801BA36ULL,
		0x79D53DEC8EDE2496ULL,
		0x19CA7214FC29F973ULL,
		0x7BA946CD92C3582AULL,
		0xB43F433B0CE8F086ULL,
		0xC17CBFCCE3B694D7ULL,
		0xC2D819FE492A125CULL,
		0x66657C97D8F95EA5ULL
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
		0x73F19CA743D3E111ULL,
		0x2907FCDFEDF8B30AULL,
		0x4E060EE40D903261ULL,
		0x2A60F37E773D547EULL,
		0xABE985E1C4D4B051ULL,
		0xF12CE671D50A2BACULL,
		0x3BC85FC1AECA2311ULL,
		0x37ABA224358C212EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E3394E87A7C222ULL,
		0x520FF9BFDBF16614ULL,
		0x9C0C1DC81B2064C2ULL,
		0x54C1E6FCEE7AA8FCULL,
		0x57D30BC389A960A2ULL,
		0xE259CCE3AA145759ULL,
		0x7790BF835D944623ULL,
		0x6F5744486B18425CULL
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
		0xCAA04055EB3C30A1ULL,
		0xDA57E222DC742AB3ULL,
		0x3592F87C42CE00D7ULL,
		0x526565A005E41099ULL,
		0xEA60C37A11071773ULL,
		0xD512F1EFC73CF5CDULL,
		0x63F1F5BDBB1B27EEULL,
		0x377728A825F01B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954080ABD6786142ULL,
		0xB4AFC445B8E85567ULL,
		0x6B25F0F8859C01AFULL,
		0xA4CACB400BC82132ULL,
		0xD4C186F4220E2EE6ULL,
		0xAA25E3DF8E79EB9BULL,
		0xC7E3EB7B76364FDDULL,
		0x6EEE51504BE036CEULL
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
		0x3C9C02E3907DD2B0ULL,
		0xCEF570B7BAFA9B6AULL,
		0x1B81762DCA12FD80ULL,
		0x7CAA794262CA511CULL,
		0x894DE813DCA5B066ULL,
		0xE16F5100D162554CULL,
		0x63744CCEBE1D41D1ULL,
		0x1079C655C120136EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x793805C720FBA560ULL,
		0x9DEAE16F75F536D4ULL,
		0x3702EC5B9425FB01ULL,
		0xF954F284C594A238ULL,
		0x129BD027B94B60CCULL,
		0xC2DEA201A2C4AA99ULL,
		0xC6E8999D7C3A83A3ULL,
		0x20F38CAB824026DCULL
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
		0x6B14E4FC0B9A9475ULL,
		0x95BD829632334C81ULL,
		0x1EB340B546243736ULL,
		0x759120D51BA19996ULL,
		0x9462DDDD0FA795C4ULL,
		0xB68B7C02F56F2D13ULL,
		0x4DD5F5A611DB6CB8ULL,
		0x0E1EBD564D2433E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD629C9F8173528EAULL,
		0x2B7B052C64669902ULL,
		0x3D66816A8C486E6DULL,
		0xEB2241AA3743332CULL,
		0x28C5BBBA1F4F2B88ULL,
		0x6D16F805EADE5A27ULL,
		0x9BABEB4C23B6D971ULL,
		0x1C3D7AAC9A4867D2ULL
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
		0x56CC01E6F731BB63ULL,
		0xD7AE0A9595ACCB11ULL,
		0xA5D8FFFF7DB6EB36ULL,
		0x238CEABD8A31DD66ULL,
		0x3A9C826D404D30FAULL,
		0x993D372837803D76ULL,
		0xC4F32ECF4BA02BF4ULL,
		0x34FA1D2587B08E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9803CDEE6376C6ULL,
		0xAF5C152B2B599622ULL,
		0x4BB1FFFEFB6DD66DULL,
		0x4719D57B1463BACDULL,
		0x753904DA809A61F4ULL,
		0x327A6E506F007AECULL,
		0x89E65D9E974057E9ULL,
		0x69F43A4B0F611D17ULL
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
		0xC95B365373B15E9FULL,
		0x1F5002819E7E806DULL,
		0xE6D0AF1653AF1921ULL,
		0x177151182563DEAAULL,
		0x84A326ADCF7AE003ULL,
		0xA3EE2E233AA652EAULL,
		0x266E9561ECB01562ULL,
		0x2376962BFFAB2275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B66CA6E762BD3EULL,
		0x3EA005033CFD00DBULL,
		0xCDA15E2CA75E3242ULL,
		0x2EE2A2304AC7BD55ULL,
		0x09464D5B9EF5C006ULL,
		0x47DC5C46754CA5D5ULL,
		0x4CDD2AC3D9602AC5ULL,
		0x46ED2C57FF5644EAULL
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
		0xEC1FBA409FB2C198ULL,
		0x61929832C1D4B61BULL,
		0x635FB2543F2D5674ULL,
		0xE8FDE1C7140D45A2ULL,
		0x7DB5F5763467DF2EULL,
		0x08B5F625220EC544ULL,
		0xD1D8BAF3750B6C56ULL,
		0x3781948BB029168FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83F74813F658330ULL,
		0xC325306583A96C37ULL,
		0xC6BF64A87E5AACE8ULL,
		0xD1FBC38E281A8B44ULL,
		0xFB6BEAEC68CFBE5DULL,
		0x116BEC4A441D8A88ULL,
		0xA3B175E6EA16D8ACULL,
		0x6F03291760522D1FULL
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
		0xE4AE1F5428FC3174ULL,
		0xD6D3C5D460F45D88ULL,
		0xDB032AAB33BA5973ULL,
		0x4DEF969A7D38A0FDULL,
		0xA13453EC28FE9AA1ULL,
		0x6AB212DCFA9D0CECULL,
		0xD3911FE81D946073ULL,
		0x3BAF1F77E1492FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC95C3EA851F862E8ULL,
		0xADA78BA8C1E8BB11ULL,
		0xB60655566774B2E7ULL,
		0x9BDF2D34FA7141FBULL,
		0x4268A7D851FD3542ULL,
		0xD56425B9F53A19D9ULL,
		0xA7223FD03B28C0E6ULL,
		0x775E3EEFC2925FBDULL
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
		0xAA226D79C6571C02ULL,
		0xD1EF6274C8579B45ULL,
		0xD4856A62790876B2ULL,
		0x9F2CE6878B19BFAAULL,
		0x8EDF2DF16FB5CF2AULL,
		0xC631192300040F87ULL,
		0x9FDC48D536E495F6ULL,
		0x319FFADFA10B9075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5444DAF38CAE3804ULL,
		0xA3DEC4E990AF368BULL,
		0xA90AD4C4F210ED65ULL,
		0x3E59CD0F16337F55ULL,
		0x1DBE5BE2DF6B9E55ULL,
		0x8C62324600081F0FULL,
		0x3FB891AA6DC92BEDULL,
		0x633FF5BF421720EBULL
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
		0xCAF23CF004B82A9AULL,
		0xC1C2D49D43FE1858ULL,
		0x3DEFB6340AFC0EA5ULL,
		0x63F666A3467B4D1BULL,
		0xAF57F29DBD7B1FA0ULL,
		0xE2056AEA5EE5A839ULL,
		0x00507B4F737EA253ULL,
		0x0483F14647EE5AF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95E479E009705534ULL,
		0x8385A93A87FC30B1ULL,
		0x7BDF6C6815F81D4BULL,
		0xC7ECCD468CF69A36ULL,
		0x5EAFE53B7AF63F40ULL,
		0xC40AD5D4BDCB5073ULL,
		0x00A0F69EE6FD44A7ULL,
		0x0907E28C8FDCB5E0ULL
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
		0x729D52CD3F64ECDEULL,
		0xB48F1FF94B283B6CULL,
		0x0DACAAAC36C1287AULL,
		0xB556345660A370B6ULL,
		0x44ADD52B04909F19ULL,
		0x242D807F0142AC5EULL,
		0x5737227669E47FBFULL,
		0x0A9BF756E06293C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53AA59A7EC9D9BCULL,
		0x691E3FF2965076D8ULL,
		0x1B5955586D8250F5ULL,
		0x6AAC68ACC146E16CULL,
		0x895BAA5609213E33ULL,
		0x485B00FE028558BCULL,
		0xAE6E44ECD3C8FF7EULL,
		0x1537EEADC0C52780ULL
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
		0xD811FA9D8B9F4C7DULL,
		0x7017228EE62E98D7ULL,
		0x49C63E935F926A27ULL,
		0xE0ECEFB06C0A5EEEULL,
		0xEEC498136E40C4D9ULL,
		0x98E8E93A81DA4289ULL,
		0xCBE917CF3D853BFEULL,
		0x170F30739E360DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB023F53B173E98FAULL,
		0xE02E451DCC5D31AFULL,
		0x938C7D26BF24D44EULL,
		0xC1D9DF60D814BDDCULL,
		0xDD893026DC8189B3ULL,
		0x31D1D27503B48513ULL,
		0x97D22F9E7B0A77FDULL,
		0x2E1E60E73C6C1BABULL
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
		0x0E877306783EE1D6ULL,
		0x606A0D1DE442EFF4ULL,
		0xCA0546DFE831E879ULL,
		0xD688D58DDF73BB9CULL,
		0xDA367509E1C86CB2ULL,
		0x7960FA72BE9D91A6ULL,
		0x1FF3C88BA941FB99ULL,
		0x12271DF1D1A3410EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0EE60CF07DC3ACULL,
		0xC0D41A3BC885DFE8ULL,
		0x940A8DBFD063D0F2ULL,
		0xAD11AB1BBEE77739ULL,
		0xB46CEA13C390D965ULL,
		0xF2C1F4E57D3B234DULL,
		0x3FE791175283F732ULL,
		0x244E3BE3A346821CULL
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
		0x6BF5E3D7913EBFE5ULL,
		0xD0DD36A4D41D20F7ULL,
		0x071B264379DE7699ULL,
		0x9E8EAD3E95B39B39ULL,
		0x6C7B8DF033435D4DULL,
		0x71C0B75072FB3D32ULL,
		0x175E9D82F0E2ED0BULL,
		0x3BC48BDDDD18FB61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7EBC7AF227D7FCAULL,
		0xA1BA6D49A83A41EEULL,
		0x0E364C86F3BCED33ULL,
		0x3D1D5A7D2B673672ULL,
		0xD8F71BE06686BA9BULL,
		0xE3816EA0E5F67A64ULL,
		0x2EBD3B05E1C5DA16ULL,
		0x778917BBBA31F6C2ULL
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
		0x17CB36994B5B46C2ULL,
		0x93B63AA6595F701FULL,
		0x62C38E32014BA9D2ULL,
		0xA30760B5D5042E17ULL,
		0x64AC3E7E7700AED9ULL,
		0xD193340FFA803311ULL,
		0xE1F5EC5B12A16449ULL,
		0x32EBC1866450D969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F966D3296B68D84ULL,
		0x276C754CB2BEE03EULL,
		0xC5871C64029753A5ULL,
		0x460EC16BAA085C2EULL,
		0xC9587CFCEE015DB3ULL,
		0xA326681FF5006622ULL,
		0xC3EBD8B62542C893ULL,
		0x65D7830CC8A1B2D3ULL
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
		0xF8D728DF03A7D531ULL,
		0xA1DCFAF15E9E5180ULL,
		0x22A70FD70912E54AULL,
		0xFB3B092EF1CA6751ULL,
		0x42083C1BCD5B27C9ULL,
		0x19010D580D4D7768ULL,
		0x2F737B6A253C5613ULL,
		0x2C7B572772455EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1AE51BE074FAA62ULL,
		0x43B9F5E2BD3CA301ULL,
		0x454E1FAE1225CA95ULL,
		0xF676125DE394CEA2ULL,
		0x841078379AB64F93ULL,
		0x32021AB01A9AEED0ULL,
		0x5EE6F6D44A78AC26ULL,
		0x58F6AE4EE48ABD58ULL
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
		0x40B0B137B6AB7959ULL,
		0x2D12C6833B7B8EDDULL,
		0x90C48A323ECEB3CBULL,
		0x2FA45779534C16E2ULL,
		0x87521B72ED8C7A6BULL,
		0xF5592B457E46D493ULL,
		0xF983F3069FB41ABAULL,
		0x3C3EA24E65019C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8161626F6D56F2B2ULL,
		0x5A258D0676F71DBAULL,
		0x218914647D9D6796ULL,
		0x5F48AEF2A6982DC5ULL,
		0x0EA436E5DB18F4D6ULL,
		0xEAB2568AFC8DA927ULL,
		0xF307E60D3F683575ULL,
		0x787D449CCA033839ULL
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
		0xF45E1D35C7177E48ULL,
		0x1E650A1E74014959ULL,
		0x8CDCA489B61EA446ULL,
		0x26CDE9CDAB503C57ULL,
		0x957380AE58C3DD01ULL,
		0x77596864458399A6ULL,
		0x5EEE48BFFC89EC92ULL,
		0x355E523D4C969231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BC3A6B8E2EFC90ULL,
		0x3CCA143CE80292B3ULL,
		0x19B949136C3D488CULL,
		0x4D9BD39B56A078AFULL,
		0x2AE7015CB187BA02ULL,
		0xEEB2D0C88B07334DULL,
		0xBDDC917FF913D924ULL,
		0x6ABCA47A992D2462ULL
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
		0x2659E128C4F690D8ULL,
		0xE34B1C22A3E9C843ULL,
		0xC3FD48E3C25C19A9ULL,
		0xB95DAD016BC2F01BULL,
		0x879F10120D32204EULL,
		0xAC89565BA788C6D4ULL,
		0x6D5C25BAB378E981ULL,
		0x3661025055FDD397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB3C25189ED21B0ULL,
		0xC696384547D39086ULL,
		0x87FA91C784B83353ULL,
		0x72BB5A02D785E037ULL,
		0x0F3E20241A64409DULL,
		0x5912ACB74F118DA9ULL,
		0xDAB84B7566F1D303ULL,
		0x6CC204A0ABFBA72EULL
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
		0x4404CF75C4506D7AULL,
		0x9674A41A1F3DA2F0ULL,
		0x477D42C9FE50223DULL,
		0x24D4BD13B9BCB200ULL,
		0x8087A84EAB265D29ULL,
		0x9C2BED3806447A75ULL,
		0xD11B358521B5E1DAULL,
		0x18B08BB92B9F5361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88099EEB88A0DAF4ULL,
		0x2CE948343E7B45E0ULL,
		0x8EFA8593FCA0447BULL,
		0x49A97A2773796400ULL,
		0x010F509D564CBA52ULL,
		0x3857DA700C88F4EBULL,
		0xA2366B0A436BC3B5ULL,
		0x31611772573EA6C3ULL
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
		0xEAF852F075AD58EFULL,
		0xAE3A7545D0C01774ULL,
		0xB88CBC897531619BULL,
		0x8D7EE5733B5D9167ULL,
		0x15DF2055E6375222ULL,
		0x204900000D6530BEULL,
		0x828E9DA10C7817B4ULL,
		0x38518E551639C939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5F0A5E0EB5AB1DEULL,
		0x5C74EA8BA1802EE9ULL,
		0x71197912EA62C337ULL,
		0x1AFDCAE676BB22CFULL,
		0x2BBE40ABCC6EA445ULL,
		0x409200001ACA617CULL,
		0x051D3B4218F02F68ULL,
		0x70A31CAA2C739273ULL
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
		0x7C894D35A01A8D21ULL,
		0xFDDA752EFAB46CB2ULL,
		0x2C059CDE68C696D9ULL,
		0x991D9FF357A85742ULL,
		0x6AFCACE761942011ULL,
		0x56E9296B0D65C011ULL,
		0x9129A5EC2AFB5263ULL,
		0x04453535B4A19F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9129A6B40351A42ULL,
		0xFBB4EA5DF568D964ULL,
		0x580B39BCD18D2DB3ULL,
		0x323B3FE6AF50AE84ULL,
		0xD5F959CEC3284023ULL,
		0xADD252D61ACB8022ULL,
		0x22534BD855F6A4C6ULL,
		0x088A6A6B69433E29ULL
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
		0x29EB0B4064F88CFDULL,
		0xA0428D683D427EB6ULL,
		0x4B6F59493235182DULL,
		0xF6EB21B55B66A277ULL,
		0xF0F1B27DFC3F6A65ULL,
		0xD09047426560ECAFULL,
		0x01A37FE3FC8CDE4FULL,
		0x08B2BD0D854A07B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D61680C9F119FAULL,
		0x40851AD07A84FD6CULL,
		0x96DEB292646A305BULL,
		0xEDD6436AB6CD44EEULL,
		0xE1E364FBF87ED4CBULL,
		0xA1208E84CAC1D95FULL,
		0x0346FFC7F919BC9FULL,
		0x11657A1B0A940F6CULL
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
		0xE36AD30E71204B2DULL,
		0x263F1E6E0C28E774ULL,
		0x266A7A73C47012A5ULL,
		0xC5B2B0786361CE08ULL,
		0xDF76728468A846BDULL,
		0x769AFF982D878BB3ULL,
		0xEDA3E75E197DDB27ULL,
		0x0BE9D59E2A14EAF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6D5A61CE240965AULL,
		0x4C7E3CDC1851CEE9ULL,
		0x4CD4F4E788E0254AULL,
		0x8B6560F0C6C39C10ULL,
		0xBEECE508D1508D7BULL,
		0xED35FF305B0F1767ULL,
		0xDB47CEBC32FBB64EULL,
		0x17D3AB3C5429D5EFULL
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
		0x682A4A7308AD3FC8ULL,
		0xBFB7A7F65A882066ULL,
		0xF56CDEFD6BF7F665ULL,
		0x1C9234AA42FDB0DAULL,
		0xCF57F9BE3751CD1DULL,
		0x9B37744A58906171ULL,
		0xF3E6EB5D51DEEACEULL,
		0x2ADC9D2A1B8172DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05494E6115A7F90ULL,
		0x7F6F4FECB51040CCULL,
		0xEAD9BDFAD7EFECCBULL,
		0x3924695485FB61B5ULL,
		0x9EAFF37C6EA39A3AULL,
		0x366EE894B120C2E3ULL,
		0xE7CDD6BAA3BDD59DULL,
		0x55B93A543702E5B9ULL
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
		0xC06D3F27DE45BF76ULL,
		0x26DA400F116EEAC7ULL,
		0x629EC71AC9E2FBBBULL,
		0xE94BEBCC1C8E663BULL,
		0xAB55428B02FABE2CULL,
		0x01A29EB677C176B5ULL,
		0xEFB0E59A0BFAA9B1ULL,
		0x284884592634FA21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DA7E4FBC8B7EECULL,
		0x4DB4801E22DDD58FULL,
		0xC53D8E3593C5F776ULL,
		0xD297D798391CCC76ULL,
		0x56AA851605F57C59ULL,
		0x03453D6CEF82ED6BULL,
		0xDF61CB3417F55362ULL,
		0x509108B24C69F443ULL
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
		0x504B5A91F7817A57ULL,
		0x36FC4C233FEBF630ULL,
		0xF865D9BFD69912E6ULL,
		0x995A898FB39873A5ULL,
		0x6CF02FC9FD99C42CULL,
		0x26F746B86F889273ULL,
		0xEFA5C6306329B15DULL,
		0x2CE8EDD175653AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA096B523EF02F4AEULL,
		0x6DF898467FD7EC60ULL,
		0xF0CBB37FAD3225CCULL,
		0x32B5131F6730E74BULL,
		0xD9E05F93FB338859ULL,
		0x4DEE8D70DF1124E6ULL,
		0xDF4B8C60C65362BAULL,
		0x59D1DBA2EACA75F3ULL
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
		0x96A9363AE853E7B5ULL,
		0xE2EF107FB3347986ULL,
		0xBA4E15B8E63C2478ULL,
		0xD9F12D24733145B1ULL,
		0x720D9577AD718110ULL,
		0x82110495DBFEA894ULL,
		0xBF11FE39CF9971A3ULL,
		0x0966FF535C85F4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D526C75D0A7CF6AULL,
		0xC5DE20FF6668F30DULL,
		0x749C2B71CC7848F1ULL,
		0xB3E25A48E6628B63ULL,
		0xE41B2AEF5AE30221ULL,
		0x0422092BB7FD5128ULL,
		0x7E23FC739F32E347ULL,
		0x12CDFEA6B90BE99FULL
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
		0x36734CAEED423940ULL,
		0x6C30529029654CDCULL,
		0x02BBDFADB0D458FAULL,
		0x5640EEB923CAD8FCULL,
		0x91D2975E5E40F8ABULL,
		0x2CC87E7D3568875BULL,
		0x0665A41C30FD0C67ULL,
		0x2B3ACA308A15789FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE6995DDA847280ULL,
		0xD860A52052CA99B8ULL,
		0x0577BF5B61A8B1F4ULL,
		0xAC81DD724795B1F8ULL,
		0x23A52EBCBC81F156ULL,
		0x5990FCFA6AD10EB7ULL,
		0x0CCB483861FA18CEULL,
		0x56759461142AF13EULL
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
		0xD1B79D49D47EF163ULL,
		0xB8BAB40739B4042EULL,
		0xF6410229B4F3BBD1ULL,
		0x051AC1C531CC6B14ULL,
		0xDFC5CF660C7FF61CULL,
		0x8D0BBBC0E6BE6916ULL,
		0x617A53CAF39777B5ULL,
		0x1A3FF5F8CBEA1FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36F3A93A8FDE2C6ULL,
		0x7175680E7368085DULL,
		0xEC82045369E777A3ULL,
		0x0A35838A6398D629ULL,
		0xBF8B9ECC18FFEC38ULL,
		0x1A177781CD7CD22DULL,
		0xC2F4A795E72EEF6BULL,
		0x347FEBF197D43FF8ULL
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
		0xBC1B8ED6CB5449FEULL,
		0x8C16EE69E97E1264ULL,
		0xB2B968DF91D279A9ULL,
		0x15EFFCD7F1CD046CULL,
		0x95CBF69AD312D162ULL,
		0xEDE0D0B3E2519FBEULL,
		0xF833D89E112A471BULL,
		0x059651E7DEDF1256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78371DAD96A893FCULL,
		0x182DDCD3D2FC24C9ULL,
		0x6572D1BF23A4F353ULL,
		0x2BDFF9AFE39A08D9ULL,
		0x2B97ED35A625A2C4ULL,
		0xDBC1A167C4A33F7DULL,
		0xF067B13C22548E37ULL,
		0x0B2CA3CFBDBE24ADULL
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
		0xD140F7370E161CDAULL,
		0xF3A6F2E50BEF09C7ULL,
		0x86438A17A0ACF386ULL,
		0xC84DF346955F63EEULL,
		0x1BA76A3B7DAF8B3CULL,
		0x374F45B9CBBBD2E2ULL,
		0xE2C3F09D0ECB92D3ULL,
		0x35FC48AFBF451C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA281EE6E1C2C39B4ULL,
		0xE74DE5CA17DE138FULL,
		0x0C87142F4159E70DULL,
		0x909BE68D2ABEC7DDULL,
		0x374ED476FB5F1679ULL,
		0x6E9E8B739777A5C4ULL,
		0xC587E13A1D9725A6ULL,
		0x6BF8915F7E8A3847ULL
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
		0x6F61F6E4042A5BEFULL,
		0x954A3FF99323444EULL,
		0xB24E81227FBDAB54ULL,
		0x33DC90A164EA1F06ULL,
		0xED669D19F45EADF4ULL,
		0x92F195379A8EF648ULL,
		0x0B3219C5006E9646ULL,
		0x3C42BC3477BFAFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC3EDC80854B7DEULL,
		0x2A947FF32646889CULL,
		0x649D0244FF7B56A9ULL,
		0x67B92142C9D43E0DULL,
		0xDACD3A33E8BD5BE8ULL,
		0x25E32A6F351DEC91ULL,
		0x1664338A00DD2C8DULL,
		0x78857868EF7F5F6EULL
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
		0x059B96C22AEC7357ULL,
		0xA67563E1E0AC0449ULL,
		0x1A4C5B695C31576DULL,
		0xA963248CB4841623ULL,
		0x8830307D73DD6922ULL,
		0xEAE02040DB601435ULL,
		0xEEE31193167F57A2ULL,
		0x0CB6D8F8E5CFCD46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B372D8455D8E6AEULL,
		0x4CEAC7C3C1580892ULL,
		0x3498B6D2B862AEDBULL,
		0x52C6491969082C46ULL,
		0x106060FAE7BAD245ULL,
		0xD5C04081B6C0286BULL,
		0xDDC623262CFEAF45ULL,
		0x196DB1F1CB9F9A8DULL
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
		0x0F71B21E538A8E86ULL,
		0xCF2CE6638CEE2BBBULL,
		0xF790A607C8737D1AULL,
		0x3C40B1C8488502C7ULL,
		0xCE1C6E83BA7AD91FULL,
		0xD93D1200B9A8B7FBULL,
		0xCED8712FC3F094C5ULL,
		0x1CE9C198F4DFF6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE3643CA7151D0CULL,
		0x9E59CCC719DC5776ULL,
		0xEF214C0F90E6FA35ULL,
		0x78816390910A058FULL,
		0x9C38DD0774F5B23EULL,
		0xB27A240173516FF7ULL,
		0x9DB0E25F87E1298BULL,
		0x39D38331E9BFEDEFULL
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
		0xD68BFFE12AA8055FULL,
		0xC0EA015F532D0C51ULL,
		0x476FE37820AC659FULL,
		0x1CFE2DAB502FC584ULL,
		0xDE5285399C924882ULL,
		0x01B106DDA5964E23ULL,
		0x3AA9420439E27BAFULL,
		0x3E9879895F722B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD17FFC255500ABEULL,
		0x81D402BEA65A18A3ULL,
		0x8EDFC6F04158CB3FULL,
		0x39FC5B56A05F8B08ULL,
		0xBCA50A7339249104ULL,
		0x03620DBB4B2C9C47ULL,
		0x7552840873C4F75EULL,
		0x7D30F312BEE4565AULL
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
		0x1E4CC121BB726DA2ULL,
		0x8AECF824F5256BD8ULL,
		0xBB459F96E9C762B2ULL,
		0x841E5EE08BC50535ULL,
		0x573C42700AD9FF8BULL,
		0xBE122366BAA44940ULL,
		0x7863E74E079EBF7FULL,
		0x0C3304BF2FAD83DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C99824376E4DB44ULL,
		0x15D9F049EA4AD7B0ULL,
		0x768B3F2DD38EC565ULL,
		0x083CBDC1178A0A6BULL,
		0xAE7884E015B3FF17ULL,
		0x7C2446CD75489280ULL,
		0xF0C7CE9C0F3D7EFFULL,
		0x1866097E5F5B07BAULL
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
		0xA102C11F6D6F9CC4ULL,
		0x27F515A356DB492FULL,
		0x17FF4977F4E83E7FULL,
		0xFF41421945B727CDULL,
		0xF3E17DD7926D2904ULL,
		0xCAE474F2E4096C47ULL,
		0x130BC01128880359ULL,
		0x2A219BB7FB53D9D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4205823EDADF3988ULL,
		0x4FEA2B46ADB6925FULL,
		0x2FFE92EFE9D07CFEULL,
		0xFE8284328B6E4F9AULL,
		0xE7C2FBAF24DA5209ULL,
		0x95C8E9E5C812D88FULL,
		0x26178022511006B3ULL,
		0x5443376FF6A7B3B2ULL
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
		0x2C1F0EBDEAC8C7E3ULL,
		0x4F92129914437166ULL,
		0xDE942A4ECE91074DULL,
		0xEB355A7385B40EF6ULL,
		0xBD9D014C3A87620AULL,
		0x9FD492B0427550B7ULL,
		0x32970096B0D8D50FULL,
		0x1E8E6533BDA51D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x583E1D7BD5918FC6ULL,
		0x9F2425322886E2CCULL,
		0xBD28549D9D220E9AULL,
		0xD66AB4E70B681DEDULL,
		0x7B3A0298750EC415ULL,
		0x3FA9256084EAA16FULL,
		0x652E012D61B1AA1FULL,
		0x3D1CCA677B4A3AC2ULL
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
		0xB6520092116A2713ULL,
		0xC80B166EC9AB679AULL,
		0x3251DFD9CBFD4A31ULL,
		0xEE363EB5FC3EA68CULL,
		0xACF07CD3F18385D9ULL,
		0x5475A71E7A3C7BC5ULL,
		0x2A1446A616FD29B8ULL,
		0x226E103779C4467AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA4012422D44E26ULL,
		0x90162CDD9356CF35ULL,
		0x64A3BFB397FA9463ULL,
		0xDC6C7D6BF87D4D18ULL,
		0x59E0F9A7E3070BB3ULL,
		0xA8EB4E3CF478F78BULL,
		0x54288D4C2DFA5370ULL,
		0x44DC206EF3888CF4ULL
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
		0x97E2644AC9D5C83DULL,
		0xB7F0AE30254B02AFULL,
		0x14218C32733E6CC0ULL,
		0x7DD6FD2CB1C2B930ULL,
		0xC77E0C1D8280163EULL,
		0x3E09ED15B00BE94EULL,
		0x6C24BF55C2B557F1ULL,
		0x23F46B6FD983B386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC4C89593AB907AULL,
		0x6FE15C604A96055FULL,
		0x28431864E67CD981ULL,
		0xFBADFA5963857260ULL,
		0x8EFC183B05002C7CULL,
		0x7C13DA2B6017D29DULL,
		0xD8497EAB856AAFE2ULL,
		0x47E8D6DFB307670CULL
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
		0x0A850AEBCFD0B9CFULL,
		0x46763FF7CA1E9D67ULL,
		0x8C2DEE5EDC588DA0ULL,
		0x5E886D7BC92231B8ULL,
		0x8F8ADA5CF4DAF33DULL,
		0x9CB7FA83F61F33FBULL,
		0x112FC23346FB9683ULL,
		0x172606BA2BA616E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150A15D79FA1739EULL,
		0x8CEC7FEF943D3ACEULL,
		0x185BDCBDB8B11B40ULL,
		0xBD10DAF792446371ULL,
		0x1F15B4B9E9B5E67AULL,
		0x396FF507EC3E67F7ULL,
		0x225F84668DF72D07ULL,
		0x2E4C0D74574C2DCCULL
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
		0x6E82AC41D1BDB6CEULL,
		0x523D08009D415CC4ULL,
		0x704D1DE030315FBBULL,
		0x0929419A57415B9DULL,
		0x7B6283BB5B11A4E5ULL,
		0xBED99023D13ADAFEULL,
		0xB2554B8D9EFBA674ULL,
		0x27093B71AF898787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD055883A37B6D9CULL,
		0xA47A10013A82B988ULL,
		0xE09A3BC06062BF76ULL,
		0x12528334AE82B73AULL,
		0xF6C50776B62349CAULL,
		0x7DB32047A275B5FCULL,
		0x64AA971B3DF74CE9ULL,
		0x4E1276E35F130F0FULL
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
		0xA92ACEA4F616A76AULL,
		0x40D64FED1C649396ULL,
		0x18E68B0FA8D43D5CULL,
		0x6E6AD00AF901C0C6ULL,
		0xCCE6BCDCB4556449ULL,
		0xFF3746091842E2A9ULL,
		0x421D6E4D925A0F38ULL,
		0x2A270A7153716021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52559D49EC2D4ED4ULL,
		0x81AC9FDA38C9272DULL,
		0x31CD161F51A87AB8ULL,
		0xDCD5A015F203818CULL,
		0x99CD79B968AAC892ULL,
		0xFE6E8C123085C553ULL,
		0x843ADC9B24B41E71ULL,
		0x544E14E2A6E2C042ULL
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
		0x23090ABDD746DD07ULL,
		0x1D798A10994A9C67ULL,
		0x850B9E00CF2BF1CBULL,
		0xB36D98E15987406FULL,
		0x365C2B69004986E1ULL,
		0x1F9E31AFC8A4FCE9ULL,
		0x11F4BD11B5BD5933ULL,
		0x03918BBE1DFB8598ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4612157BAE8DBA0EULL,
		0x3AF31421329538CEULL,
		0x0A173C019E57E396ULL,
		0x66DB31C2B30E80DFULL,
		0x6CB856D200930DC3ULL,
		0x3F3C635F9149F9D2ULL,
		0x23E97A236B7AB266ULL,
		0x0723177C3BF70B30ULL
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
		0x1EC3ADAF1F52856CULL,
		0xCA601991287D1DBDULL,
		0x40D1B318EE2D2D6DULL,
		0xB972312A04498BABULL,
		0x1414A1D6E7FF43B5ULL,
		0x79BF77B212273FD8ULL,
		0xF4139443304826C2ULL,
		0x255E030432FD3F43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D875B5E3EA50AD8ULL,
		0x94C0332250FA3B7AULL,
		0x81A36631DC5A5ADBULL,
		0x72E4625408931756ULL,
		0x282943ADCFFE876BULL,
		0xF37EEF64244E7FB0ULL,
		0xE827288660904D84ULL,
		0x4ABC060865FA7E87ULL
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
		0x40959904ECD608AEULL,
		0x7E422AFB06B72397ULL,
		0xEE669D4FCA3A6947ULL,
		0x2D1FD23324A25C7AULL,
		0x276B734A74711074ULL,
		0x81C9C69AB5947C42ULL,
		0x8B1B18EB1232A303ULL,
		0x126A95CFFEB3B11FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812B3209D9AC115CULL,
		0xFC8455F60D6E472EULL,
		0xDCCD3A9F9474D28EULL,
		0x5A3FA4664944B8F5ULL,
		0x4ED6E694E8E220E8ULL,
		0x03938D356B28F884ULL,
		0x163631D624654607ULL,
		0x24D52B9FFD67623FULL
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
		0xE13A0ABEB69F4916ULL,
		0x154E74C75D34511AULL,
		0xB19C52FA959B6DA3ULL,
		0xE0BA83EC97DA5E2CULL,
		0xC0FD6D7E07E0CAA1ULL,
		0xCD4BEE292E8F4DA9ULL,
		0xC61AE2B0EB845781ULL,
		0x2AC700082D821120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC274157D6D3E922CULL,
		0x2A9CE98EBA68A235ULL,
		0x6338A5F52B36DB46ULL,
		0xC17507D92FB4BC59ULL,
		0x81FADAFC0FC19543ULL,
		0x9A97DC525D1E9B53ULL,
		0x8C35C561D708AF03ULL,
		0x558E00105B042241ULL
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
		0x44DBE890D31908CBULL,
		0x47B289053F3CDEE5ULL,
		0xFA6899189EEAEE56ULL,
		0x973BCF37BB00D1C7ULL,
		0xF37A46B1CF8114A7ULL,
		0x30C150BE2B9DF083ULL,
		0x070A085F14E5C419ULL,
		0x3C48E20C0A6177D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B7D121A6321196ULL,
		0x8F65120A7E79BDCAULL,
		0xF4D132313DD5DCACULL,
		0x2E779E6F7601A38FULL,
		0xE6F48D639F02294FULL,
		0x6182A17C573BE107ULL,
		0x0E1410BE29CB8832ULL,
		0x7891C41814C2EFA6ULL
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
		0xEC308D9F105B2C73ULL,
		0x54B8F8BE458B734EULL,
		0x2D9B8233D8892C0BULL,
		0x60DB17DCD604BDECULL,
		0x8865A411B2013C23ULL,
		0x99090A875A5070F3ULL,
		0xCDA6A08A0B256779ULL,
		0x2D70F2DAAD46B681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8611B3E20B658E6ULL,
		0xA971F17C8B16E69DULL,
		0x5B370467B1125816ULL,
		0xC1B62FB9AC097BD8ULL,
		0x10CB482364027846ULL,
		0x3212150EB4A0E1E7ULL,
		0x9B4D4114164ACEF3ULL,
		0x5AE1E5B55A8D6D03ULL
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
		0xC8C00B6F6E286061ULL,
		0x8DDEDB6127179BB6ULL,
		0x9016FC2BC2C20DBAULL,
		0x0E5A91F8F45D19C4ULL,
		0x664AC7A0677791CBULL,
		0x487E70AD6F5043B3ULL,
		0x4CAEA0A7C8DD9A52ULL,
		0x28A01A37A7DBABBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918016DEDC50C0C2ULL,
		0x1BBDB6C24E2F376DULL,
		0x202DF85785841B75ULL,
		0x1CB523F1E8BA3389ULL,
		0xCC958F40CEEF2396ULL,
		0x90FCE15ADEA08766ULL,
		0x995D414F91BB34A4ULL,
		0x5140346F4FB75778ULL
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
		0xC505EB05B6D16571ULL,
		0x79C598DDB0285987ULL,
		0xE4C8B38B505552E5ULL,
		0x5C2C0E2EEF4FAB13ULL,
		0x16CBCC5265D2C077ULL,
		0x434A70A0F21EEE92ULL,
		0x7801A8762F6805C7ULL,
		0x25F14277F15DE524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A0BD60B6DA2CAE2ULL,
		0xF38B31BB6050B30FULL,
		0xC9916716A0AAA5CAULL,
		0xB8581C5DDE9F5627ULL,
		0x2D9798A4CBA580EEULL,
		0x8694E141E43DDD24ULL,
		0xF00350EC5ED00B8EULL,
		0x4BE284EFE2BBCA48ULL
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
		0xD2FEF003CB8B4224ULL,
		0x7D5B3AB93B131AF8ULL,
		0x9B2DB8D7153BD276ULL,
		0xD8123A2A2FC59FCBULL,
		0x5378CA832778E6C2ULL,
		0xA41241F6A8F75713ULL,
		0x399A019FD61AB78EULL,
		0x1B5FE609807E664BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FDE00797168448ULL,
		0xFAB67572762635F1ULL,
		0x365B71AE2A77A4ECULL,
		0xB02474545F8B3F97ULL,
		0xA6F195064EF1CD85ULL,
		0x482483ED51EEAE26ULL,
		0x7334033FAC356F1DULL,
		0x36BFCC1300FCCC96ULL
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
		0x2D054F244EAAFEECULL,
		0x00CA42F2F8308BABULL,
		0xF1F1E4EE05E3C7BFULL,
		0xE3DEA8BCFF8077FFULL,
		0x0EC705E3DF8D570DULL,
		0x3AE31F31B3B04468ULL,
		0xC139087A63E479CCULL,
		0x014D59BB1EC1C603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0A9E489D55FDD8ULL,
		0x019485E5F0611756ULL,
		0xE3E3C9DC0BC78F7EULL,
		0xC7BD5179FF00EFFFULL,
		0x1D8E0BC7BF1AAE1BULL,
		0x75C63E63676088D0ULL,
		0x827210F4C7C8F398ULL,
		0x029AB3763D838C07ULL
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
		0xB9D5A9E41E87F877ULL,
		0x74A5D5664C1F3975ULL,
		0x44FB8ADBEA74A510ULL,
		0x28E120F1864A94E7ULL,
		0x7B281D5797946B9AULL,
		0x159E9C1EE9CFCCEFULL,
		0xC9247B5B4A22BA91ULL,
		0x044735684B59843AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73AB53C83D0FF0EEULL,
		0xE94BAACC983E72EBULL,
		0x89F715B7D4E94A20ULL,
		0x51C241E30C9529CEULL,
		0xF6503AAF2F28D734ULL,
		0x2B3D383DD39F99DEULL,
		0x9248F6B694457522ULL,
		0x088E6AD096B30875ULL
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
		0x92C64196DD9F723FULL,
		0x0519C9418E1C4FA4ULL,
		0x74AC9F932002A2C2ULL,
		0x9C86FD13558A3140ULL,
		0x92FB024FF8E012F7ULL,
		0x5F57B2B5B670F88CULL,
		0xEFBAA23CF22FAF4FULL,
		0x2F9726D95C73F170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258C832DBB3EE47EULL,
		0x0A3392831C389F49ULL,
		0xE9593F2640054584ULL,
		0x390DFA26AB146280ULL,
		0x25F6049FF1C025EFULL,
		0xBEAF656B6CE1F119ULL,
		0xDF754479E45F5E9EULL,
		0x5F2E4DB2B8E7E2E1ULL
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
		0x323D5BA5485F19B7ULL,
		0x0EA740E1F7C1F73FULL,
		0x341EA85B4AB18B12ULL,
		0x03690FFCBDB90B17ULL,
		0x2C53B0BA5A20B902ULL,
		0xFBCEDC434EE98633ULL,
		0x90DCCF0D3486FEC0ULL,
		0x0967951590D0983CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647AB74A90BE336EULL,
		0x1D4E81C3EF83EE7EULL,
		0x683D50B695631624ULL,
		0x06D21FF97B72162EULL,
		0x58A76174B4417204ULL,
		0xF79DB8869DD30C66ULL,
		0x21B99E1A690DFD81ULL,
		0x12CF2A2B21A13079ULL
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
		0x9BFEA3CF45A97AE4ULL,
		0xE877F9ED2F356F7AULL,
		0x3B57F7EFC3CB6D12ULL,
		0x468557C91B8A1858ULL,
		0xEF252A1DAE84632DULL,
		0x00845E128C202A64ULL,
		0xAEBC1462BD63A68BULL,
		0x3E0A4884C168CB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37FD479E8B52F5C8ULL,
		0xD0EFF3DA5E6ADEF5ULL,
		0x76AFEFDF8796DA25ULL,
		0x8D0AAF92371430B0ULL,
		0xDE4A543B5D08C65AULL,
		0x0108BC25184054C9ULL,
		0x5D7828C57AC74D16ULL,
		0x7C14910982D1968FULL
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
		0x480D0CE880BFF996ULL,
		0xC8449C533878D9B4ULL,
		0x8EEFEE79D97D0D62ULL,
		0xC58F65DBACED20AFULL,
		0x9019E3B3CABB701BULL,
		0x0653EB359419ADECULL,
		0x3D880CE1A039DED1ULL,
		0x14B75D983A2A1629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901A19D1017FF32CULL,
		0x908938A670F1B368ULL,
		0x1DDFDCF3B2FA1AC5ULL,
		0x8B1ECBB759DA415FULL,
		0x2033C7679576E037ULL,
		0x0CA7D66B28335BD9ULL,
		0x7B1019C34073BDA2ULL,
		0x296EBB3074542C52ULL
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
		0x7F0D08CE62DB847DULL,
		0xDA22CAD22F3ECC48ULL,
		0xAB5A4BE5AE4A3511ULL,
		0x8C5A1CAEF6F9A9E8ULL,
		0x5D0D888089618E2CULL,
		0x22BB5031FC18A0F9ULL,
		0x20FB0DBD432E7F50ULL,
		0x1D88F650860ADC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1A119CC5B708FAULL,
		0xB44595A45E7D9890ULL,
		0x56B497CB5C946A23ULL,
		0x18B4395DEDF353D1ULL,
		0xBA1B110112C31C59ULL,
		0x4576A063F83141F2ULL,
		0x41F61B7A865CFEA0ULL,
		0x3B11ECA10C15B928ULL
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
		0xA175C227A685D964ULL,
		0x2DB893C8670B01A3ULL,
		0x12DCFA906ED20CBAULL,
		0x8268AF208ED3A705ULL,
		0xF4B70C9233AB3059ULL,
		0xFBBB8AA80545520DULL,
		0x60E99D0361311EC6ULL,
		0x0CA4591072D8635FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42EB844F4D0BB2C8ULL,
		0x5B712790CE160347ULL,
		0x25B9F520DDA41974ULL,
		0x04D15E411DA74E0AULL,
		0xE96E1924675660B3ULL,
		0xF77715500A8AA41BULL,
		0xC1D33A06C2623D8DULL,
		0x1948B220E5B0C6BEULL
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
		0x94FBEAFE92B507D4ULL,
		0x002A13A2D6B8AB0DULL,
		0x78562B950EF4254DULL,
		0xD15C8EA7C4773A07ULL,
		0x29A883C2EE416724ULL,
		0xC997D08A78A3C5D9ULL,
		0xAC9B475E5441621DULL,
		0x0562BBEE81BD8216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F7D5FD256A0FA8ULL,
		0x00542745AD71561BULL,
		0xF0AC572A1DE84A9AULL,
		0xA2B91D4F88EE740EULL,
		0x53510785DC82CE49ULL,
		0x932FA114F1478BB2ULL,
		0x59368EBCA882C43BULL,
		0x0AC577DD037B042DULL
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
		0x7CEB6AC5F8B738B8ULL,
		0x6692AD7C07A3F8BFULL,
		0x52801AE29EC16AEBULL,
		0x535623FB03C69D92ULL,
		0xC880EC873F57FEBBULL,
		0x6A018F7B738B8A84ULL,
		0xEFE3AD25E8C3768DULL,
		0x1613B112C3BCA6A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D6D58BF16E7170ULL,
		0xCD255AF80F47F17EULL,
		0xA50035C53D82D5D6ULL,
		0xA6AC47F6078D3B24ULL,
		0x9101D90E7EAFFD76ULL,
		0xD4031EF6E7171509ULL,
		0xDFC75A4BD186ED1AULL,
		0x2C27622587794D53ULL
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
		0x0D838900100CCCABULL,
		0x04B12E4CAD0E7FF4ULL,
		0x31CC872D2FC7A531ULL,
		0xA0AE176F9B97667BULL,
		0x70DE0FF9BF4DAE3AULL,
		0x83784361AEB18CC5ULL,
		0xC88DE35AC417B5DFULL,
		0x0A912CA4C3672EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B07120020199956ULL,
		0x09625C995A1CFFE8ULL,
		0x63990E5A5F8F4A62ULL,
		0x415C2EDF372ECCF6ULL,
		0xE1BC1FF37E9B5C75ULL,
		0x06F086C35D63198AULL,
		0x911BC6B5882F6BBFULL,
		0x1522594986CE5D4FULL
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
		0xC2E92A6DDE9F6EDAULL,
		0xB30B63089410AB82ULL,
		0xD1CCD28C628FD62BULL,
		0xF2FEAF358ABE57F6ULL,
		0x50212170C6E34839ULL,
		0x2EE67281965CCD16ULL,
		0xAED4B64D307275DCULL,
		0x04D810A974340AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85D254DBBD3EDDB4ULL,
		0x6616C61128215705ULL,
		0xA399A518C51FAC57ULL,
		0xE5FD5E6B157CAFEDULL,
		0xA04242E18DC69073ULL,
		0x5DCCE5032CB99A2CULL,
		0x5DA96C9A60E4EBB8ULL,
		0x09B02152E86815D1ULL
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
		0x7673C6FA777909D3ULL,
		0xBF95A480C9DB37C5ULL,
		0x94AE0FC7C276708AULL,
		0xE074068111EE817BULL,
		0xD71A70C72E02534AULL,
		0xD796A8A4954B2FFCULL,
		0x67943020FE9089A1ULL,
		0x1AB6EC8EEA00FE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE78DF4EEF213A6ULL,
		0x7F2B490193B66F8AULL,
		0x295C1F8F84ECE115ULL,
		0xC0E80D0223DD02F7ULL,
		0xAE34E18E5C04A695ULL,
		0xAF2D51492A965FF9ULL,
		0xCF286041FD211343ULL,
		0x356DD91DD401FC48ULL
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
		0x68184C593FF6810AULL,
		0xBA65D82D9A9E7AA2ULL,
		0x3C8CCAE10A9C6607ULL,
		0xD7A026F66DADE728ULL,
		0x635F2E51983401EBULL,
		0xA02A823D6D91744BULL,
		0x9A63068867ED7218ULL,
		0x32281818A967B0BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD03098B27FED0214ULL,
		0x74CBB05B353CF544ULL,
		0x791995C21538CC0FULL,
		0xAF404DECDB5BCE50ULL,
		0xC6BE5CA3306803D7ULL,
		0x4055047ADB22E896ULL,
		0x34C60D10CFDAE431ULL,
		0x6450303152CF617FULL
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
		0x3B6A3FC5B8E01891ULL,
		0xFE262C21FD48FDE6ULL,
		0xD6B33CC5D9B2FD48ULL,
		0xB83A26DD39578C08ULL,
		0x0891FA32FE6F2355ULL,
		0x216029D3D0FBEF12ULL,
		0x9D73331C5E635701ULL,
		0x0F7C710F79AD0717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76D47F8B71C03122ULL,
		0xFC4C5843FA91FBCCULL,
		0xAD66798BB365FA91ULL,
		0x70744DBA72AF1811ULL,
		0x1123F465FCDE46ABULL,
		0x42C053A7A1F7DE24ULL,
		0x3AE66638BCC6AE02ULL,
		0x1EF8E21EF35A0E2FULL
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
		0x4E41E7C239DE7E98ULL,
		0x77E8E5539BD22402ULL,
		0x31B06C6DACDB7F3BULL,
		0x85A324A4B0F084F2ULL,
		0xB1A1BD0133466EBFULL,
		0x2E56610BFFB6F9E5ULL,
		0xF7F19C63C0ADA635ULL,
		0x1F154DC4DC3E1D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C83CF8473BCFD30ULL,
		0xEFD1CAA737A44804ULL,
		0x6360D8DB59B6FE76ULL,
		0x0B46494961E109E4ULL,
		0x63437A02668CDD7FULL,
		0x5CACC217FF6DF3CBULL,
		0xEFE338C7815B4C6AULL,
		0x3E2A9B89B87C3AB3ULL
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
		0x5EAF6CD399221EFBULL,
		0x29C9348416333E96ULL,
		0x933224692B0924D4ULL,
		0xD9D552AD8EF2AB24ULL,
		0xA55D432985C1323CULL,
		0xF66691F7DA2CC99CULL,
		0x8628EB635EB133DDULL,
		0x363EF7E5D37310F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5ED9A732443DF6ULL,
		0x539269082C667D2CULL,
		0x266448D2561249A8ULL,
		0xB3AAA55B1DE55649ULL,
		0x4ABA86530B826479ULL,
		0xECCD23EFB4599339ULL,
		0x0C51D6C6BD6267BBULL,
		0x6C7DEFCBA6E621F1ULL
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
		0xAA0B04702D738AFDULL,
		0x418DEA1C28AB0D97ULL,
		0x154DB5C998D7E51CULL,
		0x050CB25F83A4F64BULL,
		0x03DDD588FF2B187FULL,
		0x67FD0685151CB6D4ULL,
		0xB6375D7D2506AAF0ULL,
		0x30EFC89DAA663348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x541608E05AE715FAULL,
		0x831BD43851561B2FULL,
		0x2A9B6B9331AFCA38ULL,
		0x0A1964BF0749EC96ULL,
		0x07BBAB11FE5630FEULL,
		0xCFFA0D0A2A396DA8ULL,
		0x6C6EBAFA4A0D55E0ULL,
		0x61DF913B54CC6691ULL
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
		0xEF3FC34D0B535270ULL,
		0x263BB49DEDD163D0ULL,
		0x705AA3F62C5794BDULL,
		0x88B3FA342FF693A6ULL,
		0x181D6808E2DB57E5ULL,
		0x300E3AE15A221DACULL,
		0xB15BE816882E5E1BULL,
		0x086A44413D8F1318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7F869A16A6A4E0ULL,
		0x4C77693BDBA2C7A1ULL,
		0xE0B547EC58AF297AULL,
		0x1167F4685FED274CULL,
		0x303AD011C5B6AFCBULL,
		0x601C75C2B4443B58ULL,
		0x62B7D02D105CBC36ULL,
		0x10D488827B1E2631ULL
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
		0xC9E31A9DE477714BULL,
		0x0A38960EE20C9CA4ULL,
		0xF6E7625BC2D2A96BULL,
		0xE9313B92E9D5F314ULL,
		0x78E3C8D33E7C226CULL,
		0x0501C7AB805E909AULL,
		0x6F5B44660725AEE0ULL,
		0x3E321265C42ECC09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C6353BC8EEE296ULL,
		0x14712C1DC4193949ULL,
		0xEDCEC4B785A552D6ULL,
		0xD2627725D3ABE629ULL,
		0xF1C791A67CF844D9ULL,
		0x0A038F5700BD2134ULL,
		0xDEB688CC0E4B5DC0ULL,
		0x7C6424CB885D9812ULL
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
		0x4078F9B4D8689DF8ULL,
		0xA3395206ADDC9E3DULL,
		0x6C92B8194710C6B1ULL,
		0xB578DD14BE836DDFULL,
		0x27BC407886D8FA4EULL,
		0xB5A5FF411C0A4E14ULL,
		0xC262EFCE15C26AF6ULL,
		0x05F2B96648DAE7EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F1F369B0D13BF0ULL,
		0x4672A40D5BB93C7AULL,
		0xD92570328E218D63ULL,
		0x6AF1BA297D06DBBEULL,
		0x4F7880F10DB1F49DULL,
		0x6B4BFE8238149C28ULL,
		0x84C5DF9C2B84D5EDULL,
		0x0BE572CC91B5CFDBULL
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
		0x7CEA4AE1505CC475ULL,
		0xD8FC9D2064C7BC09ULL,
		0x2BC5BB976785D743ULL,
		0x8B786B8395EF58DEULL,
		0x29C9ECE04EEB68C2ULL,
		0x21308E9D16940507ULL,
		0xAD527A306988A40AULL,
		0x1BF2AD0394D470ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D495C2A0B988EAULL,
		0xB1F93A40C98F7812ULL,
		0x578B772ECF0BAE87ULL,
		0x16F0D7072BDEB1BCULL,
		0x5393D9C09DD6D185ULL,
		0x42611D3A2D280A0EULL,
		0x5AA4F460D3114814ULL,
		0x37E55A0729A8E1D9ULL
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
		0xCD76E3BC388BC4C2ULL,
		0x38AC91F320B80846ULL,
		0x366B71DBFA20582BULL,
		0x1920662F1E41A742ULL,
		0xBB154E6BF3B56F72ULL,
		0x72183B7E51A79068ULL,
		0x9785E2C234662D9AULL,
		0x1E2B0E98621D11C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AEDC77871178984ULL,
		0x715923E64170108DULL,
		0x6CD6E3B7F440B056ULL,
		0x3240CC5E3C834E84ULL,
		0x762A9CD7E76ADEE4ULL,
		0xE43076FCA34F20D1ULL,
		0x2F0BC58468CC5B34ULL,
		0x3C561D30C43A238DULL
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
		0x7866166CCAFD5FA8ULL,
		0x38D27843DB3F47BBULL,
		0xC25FAFD91A21207AULL,
		0x369083F02F0051BCULL,
		0xB35CBF1F4839D51BULL,
		0x054588423A6C2A50ULL,
		0x63831C400DD92B78ULL,
		0x1007A0C608785DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CC2CD995FABF50ULL,
		0x71A4F087B67E8F76ULL,
		0x84BF5FB2344240F4ULL,
		0x6D2107E05E00A379ULL,
		0x66B97E3E9073AA36ULL,
		0x0A8B108474D854A1ULL,
		0xC70638801BB256F0ULL,
		0x200F418C10F0BBA4ULL
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
		0xF5DFD9C33587A0A8ULL,
		0x266443056C8561CEULL,
		0xAA2DF878E5343051ULL,
		0x03E9C5E6C7D95600ULL,
		0x86621CDAE2580C1DULL,
		0x3598491A5C7D03B9ULL,
		0xFA6B00F7E94B8345ULL,
		0x1ECCBEFC8B9141B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBFB3866B0F4150ULL,
		0x4CC8860AD90AC39DULL,
		0x545BF0F1CA6860A2ULL,
		0x07D38BCD8FB2AC01ULL,
		0x0CC439B5C4B0183AULL,
		0x6B309234B8FA0773ULL,
		0xF4D601EFD297068AULL,
		0x3D997DF917228367ULL
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
		0x318911ADAA6FACE1ULL,
		0x549D14F4CBC801C7ULL,
		0xA0527FDAB4E8AF0BULL,
		0x5A579DC820940973ULL,
		0xC1F02700005A4197ULL,
		0xE951215F83BC4AA4ULL,
		0x536325D553692F73ULL,
		0x04EAA40364065D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6312235B54DF59C2ULL,
		0xA93A29E99790038EULL,
		0x40A4FFB569D15E16ULL,
		0xB4AF3B90412812E7ULL,
		0x83E04E0000B4832EULL,
		0xD2A242BF07789549ULL,
		0xA6C64BAAA6D25EE7ULL,
		0x09D54806C80CBA42ULL
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
		0x4836DD5695C9F4D3ULL,
		0x2CB0D3AF65816FF8ULL,
		0x550DDF19A692AF96ULL,
		0xE4DC92A643D2DEFDULL,
		0xB6521B32A97CBB9BULL,
		0xB94D9037B325E6DEULL,
		0xF9CC5AE7E72D3BE4ULL,
		0x2DE449DD32D3B3D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906DBAAD2B93E9A6ULL,
		0x5961A75ECB02DFF0ULL,
		0xAA1BBE334D255F2CULL,
		0xC9B9254C87A5BDFAULL,
		0x6CA4366552F97737ULL,
		0x729B206F664BCDBDULL,
		0xF398B5CFCE5A77C9ULL,
		0x5BC893BA65A767B1ULL
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
		0x3B95E5B115036D69ULL,
		0x661A32E39A2281B0ULL,
		0xB824DABD5629D03FULL,
		0x8C84D50DED8031B1ULL,
		0xE3BA8BDAD38EE07EULL,
		0xCCFCBA0778308A45ULL,
		0x7F995F0E357CC4E5ULL,
		0x178EED5FF455E0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x772BCB622A06DAD2ULL,
		0xCC3465C734450360ULL,
		0x7049B57AAC53A07EULL,
		0x1909AA1BDB006363ULL,
		0xC77517B5A71DC0FDULL,
		0x99F9740EF061148BULL,
		0xFF32BE1C6AF989CBULL,
		0x2F1DDABFE8ABC188ULL
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
		0xA477BE7819AA25CAULL,
		0x4285C2138A422A17ULL,
		0xA474A886D2BF0CC0ULL,
		0x8695CE986809090BULL,
		0x1E44DE94EC6FD14AULL,
		0x9ECA8B194C59814FULL,
		0x460C25DDC530EB9FULL,
		0x108D347A5CBE974AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48EF7CF033544B94ULL,
		0x850B84271484542FULL,
		0x48E9510DA57E1980ULL,
		0x0D2B9D30D0121217ULL,
		0x3C89BD29D8DFA295ULL,
		0x3D95163298B3029EULL,
		0x8C184BBB8A61D73FULL,
		0x211A68F4B97D2E94ULL
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
		0x8F41A462F2B8B650ULL,
		0x91A427729EA3624FULL,
		0xE811E631F6D5C2FCULL,
		0x59EEB3D8CBC41ED9ULL,
		0x5BD2156FFD4841E1ULL,
		0x2C0FC0731893CE0AULL,
		0xFBAC8A94D1C52AFDULL,
		0x21D588DABDB7E94AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E8348C5E5716CA0ULL,
		0x23484EE53D46C49FULL,
		0xD023CC63EDAB85F9ULL,
		0xB3DD67B197883DB3ULL,
		0xB7A42ADFFA9083C2ULL,
		0x581F80E631279C14ULL,
		0xF7591529A38A55FAULL,
		0x43AB11B57B6FD295ULL
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
		0x37BB82AB57B7DDC4ULL,
		0x5280381A488AAD00ULL,
		0xA821BB95835701C5ULL,
		0x5FF6331BD2840983ULL,
		0x22A2D7500E612DC2ULL,
		0x890A9E20529A7B5AULL,
		0x9C0820E6188C69EBULL,
		0x05231303F8082950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F770556AF6FBB88ULL,
		0xA500703491155A00ULL,
		0x5043772B06AE038AULL,
		0xBFEC6637A5081307ULL,
		0x4545AEA01CC25B84ULL,
		0x12153C40A534F6B4ULL,
		0x381041CC3118D3D7ULL,
		0x0A462607F01052A1ULL
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
		0x203DCF7AE929D525ULL,
		0x3B83E8FBBB4667F7ULL,
		0x2881C4818FD540D8ULL,
		0xAAF24430E6FB91FAULL,
		0xEE2104C2C803C433ULL,
		0x1CAED4BFE2F3BF47ULL,
		0x6C574C781C277715ULL,
		0x01458AAC61CDB7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407B9EF5D253AA4AULL,
		0x7707D1F7768CCFEEULL,
		0x510389031FAA81B0ULL,
		0x55E48861CDF723F4ULL,
		0xDC42098590078867ULL,
		0x395DA97FC5E77E8FULL,
		0xD8AE98F0384EEE2AULL,
		0x028B1558C39B6F4CULL
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
		0xA5F1AD30B04FF033ULL,
		0xB86BD653094672BEULL,
		0xC35C165A9FD9B99FULL,
		0xEC657A05F69CE447ULL,
		0x7AE212F982DED356ULL,
		0xD60348D419571539ULL,
		0x4E2A067E9703FF99ULL,
		0x0737714FA8066BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE35A61609FE066ULL,
		0x70D7ACA6128CE57DULL,
		0x86B82CB53FB3733FULL,
		0xD8CAF40BED39C88FULL,
		0xF5C425F305BDA6ADULL,
		0xAC0691A832AE2A72ULL,
		0x9C540CFD2E07FF33ULL,
		0x0E6EE29F500CD790ULL
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
		0xF2CFE36AAFE51F88ULL,
		0x1B9E2EDA50A3508EULL,
		0x25983165608DDF81ULL,
		0xD19B691C8FB79A0CULL,
		0x284A60F6C00C6448ULL,
		0xC333A6C619ED4091ULL,
		0xE7824104EF1BC936ULL,
		0x39AC8A70BE7B308FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE59FC6D55FCA3F10ULL,
		0x373C5DB4A146A11DULL,
		0x4B3062CAC11BBF02ULL,
		0xA336D2391F6F3418ULL,
		0x5094C1ED8018C891ULL,
		0x86674D8C33DA8122ULL,
		0xCF048209DE37926DULL,
		0x735914E17CF6611FULL
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
		0x2DC0D667C8622DB2ULL,
		0x9101471D7D0CE99AULL,
		0x0B37A9C4131CDE2CULL,
		0x3E1EEFD814A54394ULL,
		0x47E962FE6D7369DFULL,
		0x1105A26001ECAABFULL,
		0x3A728DEF2A09D7D2ULL,
		0x2CBACEC18ED03721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B81ACCF90C45B64ULL,
		0x22028E3AFA19D334ULL,
		0x166F53882639BC59ULL,
		0x7C3DDFB0294A8728ULL,
		0x8FD2C5FCDAE6D3BEULL,
		0x220B44C003D9557EULL,
		0x74E51BDE5413AFA4ULL,
		0x59759D831DA06E42ULL
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
		0x338E412E283E8AD0ULL,
		0x3E027AB6D090C684ULL,
		0x40F6C8734798F5D7ULL,
		0xEEED75887EFC9E9CULL,
		0x7A8669F70548A679ULL,
		0xD8C246D92A4011A6ULL,
		0xD23EDB8CB2DADB15ULL,
		0x119C47E2CEBA97BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x671C825C507D15A0ULL,
		0x7C04F56DA1218D08ULL,
		0x81ED90E68F31EBAEULL,
		0xDDDAEB10FDF93D38ULL,
		0xF50CD3EE0A914CF3ULL,
		0xB1848DB25480234CULL,
		0xA47DB71965B5B62BULL,
		0x23388FC59D752F77ULL
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
		0x363C78E683F2CDBEULL,
		0xA320BC2D63DACE81ULL,
		0x61654BD12A116ABBULL,
		0x5F74B0F55AFF0C99ULL,
		0xDA3D56E780B83FF6ULL,
		0xF97F55FBA2F35502ULL,
		0xA73DA9221B4C8BF2ULL,
		0x1C8D624BC4C2DEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C78F1CD07E59B7CULL,
		0x4641785AC7B59D02ULL,
		0xC2CA97A25422D577ULL,
		0xBEE961EAB5FE1932ULL,
		0xB47AADCF01707FECULL,
		0xF2FEABF745E6AA05ULL,
		0x4E7B5244369917E5ULL,
		0x391AC4978985BDFFULL
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
		0x17387709D1A3DA20ULL,
		0x3FF3FD93025FCE8AULL,
		0xA508A0564C045268ULL,
		0x31B5F397B4DF3E92ULL,
		0x7B3DDDB04A2FC47CULL,
		0x35053D53EF7E4C7BULL,
		0xD03355F78931773FULL,
		0x049A9C0F95E433FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E70EE13A347B440ULL,
		0x7FE7FB2604BF9D14ULL,
		0x4A1140AC9808A4D0ULL,
		0x636BE72F69BE7D25ULL,
		0xF67BBB60945F88F8ULL,
		0x6A0A7AA7DEFC98F6ULL,
		0xA066ABEF1262EE7EULL,
		0x0935381F2BC867FBULL
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
		0x167CDD4D1C794CE0ULL,
		0x4AAE18FE65CD9411ULL,
		0x979C4CDCC1F1CB8FULL,
		0x1EB73C3F76318DCEULL,
		0x7A718E7DB721701CULL,
		0xCEFD4630940EE8E6ULL,
		0x6F48EC171A9EB510ULL,
		0x00DC92E803540CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CF9BA9A38F299C0ULL,
		0x955C31FCCB9B2822ULL,
		0x2F3899B983E3971EULL,
		0x3D6E787EEC631B9DULL,
		0xF4E31CFB6E42E038ULL,
		0x9DFA8C61281DD1CCULL,
		0xDE91D82E353D6A21ULL,
		0x01B925D006A819BAULL
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
		0xCFC843B64977620BULL,
		0x8AD08324E1F7CC23ULL,
		0xA64F1B69E6A039E7ULL,
		0x65D8C7F93D827656ULL,
		0x7067080D866A34B4ULL,
		0x1CA51B729E19B116ULL,
		0x8217339ED2F46792ULL,
		0x1E3B6BFEBA343B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F90876C92EEC416ULL,
		0x15A10649C3EF9847ULL,
		0x4C9E36D3CD4073CFULL,
		0xCBB18FF27B04ECADULL,
		0xE0CE101B0CD46968ULL,
		0x394A36E53C33622CULL,
		0x042E673DA5E8CF24ULL,
		0x3C76D7FD7468773DULL
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
		0x7E580746521A774AULL,
		0x07F8DED9B4936C27ULL,
		0x561144E641C04B99ULL,
		0x301F90CA3CE2529FULL,
		0xE9B02A2B5DB499B9ULL,
		0x82DBC13E43A58B84ULL,
		0x59982E071A098564ULL,
		0x2C5DB6371ED28862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB00E8CA434EE94ULL,
		0x0FF1BDB36926D84EULL,
		0xAC2289CC83809732ULL,
		0x603F219479C4A53EULL,
		0xD3605456BB693372ULL,
		0x05B7827C874B1709ULL,
		0xB3305C0E34130AC9ULL,
		0x58BB6C6E3DA510C4ULL
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
		0x6997BBD8DB6E091CULL,
		0xD0D039FC267EC6CDULL,
		0xF82783A0ED486813ULL,
		0x2E3AC99C04309EB9ULL,
		0x2C13FA1489628C9DULL,
		0xAD9F9251EA109351ULL,
		0x2B2FA1FDAFB1A0B1ULL,
		0x12DDB8FFD286DB60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32F77B1B6DC1238ULL,
		0xA1A073F84CFD8D9AULL,
		0xF04F0741DA90D027ULL,
		0x5C75933808613D73ULL,
		0x5827F42912C5193AULL,
		0x5B3F24A3D42126A2ULL,
		0x565F43FB5F634163ULL,
		0x25BB71FFA50DB6C0ULL
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
		0x93EE0D8D54DFB6CAULL,
		0x0EAD815461F84B29ULL,
		0xA91D59F51ED5977EULL,
		0xC3FD3FD5F27A203FULL,
		0xD4E279FC6419F983ULL,
		0x53B4DF0CE0F68A58ULL,
		0xDA13FAD93954EE4DULL,
		0x0363C37DFC8BD151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27DC1B1AA9BF6D94ULL,
		0x1D5B02A8C3F09653ULL,
		0x523AB3EA3DAB2EFCULL,
		0x87FA7FABE4F4407FULL,
		0xA9C4F3F8C833F307ULL,
		0xA769BE19C1ED14B1ULL,
		0xB427F5B272A9DC9AULL,
		0x06C786FBF917A2A3ULL
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
		0xC6590E6806C8EE3DULL,
		0xD268BDDDCF836F7FULL,
		0x479077DEF91C09E8ULL,
		0xE0B4C222A8FE9210ULL,
		0x9D4083875821E29EULL,
		0x4C37FD97CBE29482ULL,
		0x28970F8C073899BAULL,
		0x33A4D63FD20D55BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB21CD00D91DC7AULL,
		0xA4D17BBB9F06DEFFULL,
		0x8F20EFBDF23813D1ULL,
		0xC169844551FD2420ULL,
		0x3A81070EB043C53DULL,
		0x986FFB2F97C52905ULL,
		0x512E1F180E713374ULL,
		0x6749AC7FA41AAB7EULL
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
		0x12C3C1C2BA57D816ULL,
		0x7C89F29C771658D8ULL,
		0x04548BB47499D14BULL,
		0x64B79427CA744D32ULL,
		0x84DAE0E182301F8BULL,
		0x1928C6BF074DD825ULL,
		0xA2F296980E069D78ULL,
		0x294AE6094F8EDE63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2587838574AFB02CULL,
		0xF913E538EE2CB1B0ULL,
		0x08A91768E933A296ULL,
		0xC96F284F94E89A64ULL,
		0x09B5C1C304603F16ULL,
		0x32518D7E0E9BB04BULL,
		0x45E52D301C0D3AF0ULL,
		0x5295CC129F1DBCC7ULL
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
		0xCC460640BD081729ULL,
		0x7BE6FE1757F4E334ULL,
		0xE4C87AF65B5C8DFBULL,
		0x9A428E87AF876B6FULL,
		0x5A2779BB04DA85FFULL,
		0xFEFD6FC8C7CF23B9ULL,
		0x2096619C2623218AULL,
		0x121D22C854E0C100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x988C0C817A102E52ULL,
		0xF7CDFC2EAFE9C669ULL,
		0xC990F5ECB6B91BF6ULL,
		0x34851D0F5F0ED6DFULL,
		0xB44EF37609B50BFFULL,
		0xFDFADF918F9E4772ULL,
		0x412CC3384C464315ULL,
		0x243A4590A9C18200ULL
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
		0x19D21DD17D9BA1B6ULL,
		0x4E7850F0C0917E02ULL,
		0x303467B3986B21CCULL,
		0xA17DF1E625960F38ULL,
		0xE2BCC8A8C3E2C36AULL,
		0xDDA1B2059559AFE9ULL,
		0x56016158FDA29DF5ULL,
		0x2036B0B632AF0905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A43BA2FB37436CULL,
		0x9CF0A1E18122FC04ULL,
		0x6068CF6730D64398ULL,
		0x42FBE3CC4B2C1E70ULL,
		0xC579915187C586D5ULL,
		0xBB43640B2AB35FD3ULL,
		0xAC02C2B1FB453BEBULL,
		0x406D616C655E120AULL
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
		0x6A8FC9B2854A760FULL,
		0xA9AB316355EF63EEULL,
		0xC556B4FEA55C8C4EULL,
		0x3E1D9E36CDB1AF60ULL,
		0xE2E7E5A9455E0580ULL,
		0x852DAFC6F781882DULL,
		0xE59047BBD60E2012ULL,
		0x10395930B3B70E03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51F93650A94EC1EULL,
		0x535662C6ABDEC7DCULL,
		0x8AAD69FD4AB9189DULL,
		0x7C3B3C6D9B635EC1ULL,
		0xC5CFCB528ABC0B00ULL,
		0x0A5B5F8DEF03105BULL,
		0xCB208F77AC1C4025ULL,
		0x2072B261676E1C07ULL
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
		0x084D9469929D6E35ULL,
		0x17DB1D78BEF884F4ULL,
		0x7A820B41F75D2228ULL,
		0x16D9AB237AF4FABEULL,
		0x23819CEED0BB2CFDULL,
		0xC9ADEBF6345A7B74ULL,
		0xA953DA33C70A49A1ULL,
		0x09C3663149011C04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x109B28D3253ADC6AULL,
		0x2FB63AF17DF109E8ULL,
		0xF5041683EEBA4450ULL,
		0x2DB35646F5E9F57CULL,
		0x470339DDA17659FAULL,
		0x935BD7EC68B4F6E8ULL,
		0x52A7B4678E149343ULL,
		0x1386CC6292023809ULL
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
		0x1DA234660D86886BULL,
		0x01D0B282A92E270FULL,
		0xA1298A6C96077863ULL,
		0x4EA1BA643441E3CDULL,
		0xB00BD39C1068A433ULL,
		0x8708A54D6AB3FDC9ULL,
		0x54349C84987B10FDULL,
		0x18048F96A90DF322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4468CC1B0D10D6ULL,
		0x03A16505525C4E1EULL,
		0x425314D92C0EF0C6ULL,
		0x9D4374C86883C79BULL,
		0x6017A73820D14866ULL,
		0x0E114A9AD567FB93ULL,
		0xA869390930F621FBULL,
		0x30091F2D521BE644ULL
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
		0xD1E9F6ACB82D59A3ULL,
		0x3137264BF516E434ULL,
		0x2A9E4775B218E219ULL,
		0x32DA9009BE879201ULL,
		0x8BCB4CD4EE79AEAAULL,
		0x95BCA31E2799DE52ULL,
		0xE1C0177C5CD690E8ULL,
		0x2C7842878705A193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D3ED59705AB346ULL,
		0x626E4C97EA2DC869ULL,
		0x553C8EEB6431C432ULL,
		0x65B520137D0F2402ULL,
		0x179699A9DCF35D54ULL,
		0x2B79463C4F33BCA5ULL,
		0xC3802EF8B9AD21D1ULL,
		0x58F0850F0E0B4327ULL
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
		0x785CEA8835FF39A1ULL,
		0x335DE75407C428A2ULL,
		0xC79F28334CDC4D86ULL,
		0x11E759F5FC692272ULL,
		0x40167A3E82923E39ULL,
		0x41C9698EB4C4EC2BULL,
		0xA2E8C105C2436304ULL,
		0x37814E12CEEBD6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B9D5106BFE7342ULL,
		0x66BBCEA80F885144ULL,
		0x8F3E506699B89B0CULL,
		0x23CEB3EBF8D244E5ULL,
		0x802CF47D05247C72ULL,
		0x8392D31D6989D856ULL,
		0x45D1820B8486C608ULL,
		0x6F029C259DD7AD5DULL
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
		0x8C203ACE01EDAA26ULL,
		0xEA88BE45945D87E9ULL,
		0x8371635F5DED0881ULL,
		0x000D44CA403B5654ULL,
		0x7ABA50BBAFCAF80AULL,
		0x74A5ADCC015D431EULL,
		0x76F1F1E3935BF576ULL,
		0x1D545A2F0F3ABA6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1840759C03DB544CULL,
		0xD5117C8B28BB0FD3ULL,
		0x06E2C6BEBBDA1103ULL,
		0x001A89948076ACA9ULL,
		0xF574A1775F95F014ULL,
		0xE94B5B9802BA863CULL,
		0xEDE3E3C726B7EAECULL,
		0x3AA8B45E1E7574D8ULL
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
		0xEFFD7BADCD28B9C0ULL,
		0xEC8AB2AFF24EC373ULL,
		0xE7E939CACA03BE30ULL,
		0x6EF3715DB5B4491DULL,
		0x7744C07185EF3F43ULL,
		0x40707477E2976366ULL,
		0xB557BF32DAC96DCFULL,
		0x199D6F932B2FA3B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFFAF75B9A517380ULL,
		0xD915655FE49D86E7ULL,
		0xCFD2739594077C61ULL,
		0xDDE6E2BB6B68923BULL,
		0xEE8980E30BDE7E86ULL,
		0x80E0E8EFC52EC6CCULL,
		0x6AAF7E65B592DB9EULL,
		0x333ADF26565F4763ULL
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
		0x7B2837225BDC3E0CULL,
		0xC1FED8F59D03E296ULL,
		0x962FD4268417FCDCULL,
		0x6425BF1E0607F809ULL,
		0xD7810B43D96E0284ULL,
		0x7B8F5EB8464448DAULL,
		0x93E26A77479241E5ULL,
		0x1CFA56B39A7DA71CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6506E44B7B87C18ULL,
		0x83FDB1EB3A07C52CULL,
		0x2C5FA84D082FF9B9ULL,
		0xC84B7E3C0C0FF013ULL,
		0xAF021687B2DC0508ULL,
		0xF71EBD708C8891B5ULL,
		0x27C4D4EE8F2483CAULL,
		0x39F4AD6734FB4E39ULL
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
		0xC392B376BDC623E5ULL,
		0xF93246495A7295ADULL,
		0xDD064D16F6AF9504ULL,
		0xAA3E74212A1E8123ULL,
		0xD349B12C6DD60E63ULL,
		0x5CB1C2D842E29D1DULL,
		0x67BFFE61198A5F0FULL,
		0x3847FBB03D380A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x872566ED7B8C47CAULL,
		0xF2648C92B4E52B5BULL,
		0xBA0C9A2DED5F2A09ULL,
		0x547CE842543D0247ULL,
		0xA6936258DBAC1CC7ULL,
		0xB96385B085C53A3BULL,
		0xCF7FFCC23314BE1EULL,
		0x708FF7607A7014DAULL
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
		0x31762D02ADDC2BB8ULL,
		0xBE1405ACBEDF1E6BULL,
		0x9FF5E232D314E17EULL,
		0x1BE548A8E606A7F0ULL,
		0x87B02044409EF4EAULL,
		0x8B16DFD8894DFE44ULL,
		0x996BCC9736C21045ULL,
		0x2B151297DA0085E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62EC5A055BB85770ULL,
		0x7C280B597DBE3CD6ULL,
		0x3FEBC465A629C2FDULL,
		0x37CA9151CC0D4FE1ULL,
		0x0F604088813DE9D4ULL,
		0x162DBFB1129BFC89ULL,
		0x32D7992E6D84208BULL,
		0x562A252FB4010BCBULL
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
		0xE1D7861DA54639CDULL,
		0x8FEEBEE9F56C8986ULL,
		0x3F19FEFD6371D59BULL,
		0x93200547FC188B04ULL,
		0x9CFB06CA14DDF5CAULL,
		0xB83F35D855D419C2ULL,
		0x9CFB33B931CA8FCCULL,
		0x0EF709CA0C77ED78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3AF0C3B4A8C739AULL,
		0x1FDD7DD3EAD9130DULL,
		0x7E33FDFAC6E3AB37ULL,
		0x26400A8FF8311608ULL,
		0x39F60D9429BBEB95ULL,
		0x707E6BB0ABA83385ULL,
		0x39F6677263951F99ULL,
		0x1DEE139418EFDAF1ULL
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
		0xD4EDFA9D4FC59B6AULL,
		0x37F1E2502508DD12ULL,
		0xD74139746FCDDCB9ULL,
		0x4DC9952609FBCFE6ULL,
		0x7C45ECF19F6A8B87ULL,
		0xAE98AB75E9674CE6ULL,
		0xE3370A73FC4EE855ULL,
		0x2F7DD26F1F6D95FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DBF53A9F8B36D4ULL,
		0x6FE3C4A04A11BA25ULL,
		0xAE8272E8DF9BB972ULL,
		0x9B932A4C13F79FCDULL,
		0xF88BD9E33ED5170EULL,
		0x5D3156EBD2CE99CCULL,
		0xC66E14E7F89DD0ABULL,
		0x5EFBA4DE3EDB2BF9ULL
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
		0x179F170B4013673CULL,
		0xDA3ACD56749D212EULL,
		0x2BE7B5866925C68FULL,
		0x1AA15931DABD6BADULL,
		0x6EC2EF7C29F6FDFBULL,
		0x49471592D4A07C2BULL,
		0x2AE1E39652E141A1ULL,
		0x3FFAAC804A3FFF85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F3E2E168026CE78ULL,
		0xB4759AACE93A425CULL,
		0x57CF6B0CD24B8D1FULL,
		0x3542B263B57AD75AULL,
		0xDD85DEF853EDFBF6ULL,
		0x928E2B25A940F856ULL,
		0x55C3C72CA5C28342ULL,
		0x7FF55900947FFF0AULL
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
		0xA0B0B7C1DF88F53FULL,
		0x481B630727EA75C2ULL,
		0x74DDA483C7CE7E2CULL,
		0x9B80C08ADD54F09CULL,
		0x0333FB09BC9C9350ULL,
		0x8F9B42092BE18469ULL,
		0xDD98163C26135D78ULL,
		0x0A1B5D7D7644674BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41616F83BF11EA7EULL,
		0x9036C60E4FD4EB85ULL,
		0xE9BB49078F9CFC58ULL,
		0x37018115BAA9E138ULL,
		0x0667F613793926A1ULL,
		0x1F36841257C308D2ULL,
		0xBB302C784C26BAF1ULL,
		0x1436BAFAEC88CE97ULL
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
		0x6BFB076453BDC54EULL,
		0xF22A50462392D1E4ULL,
		0x9C9BB55A4EA79B91ULL,
		0xF8FB772889EDE5C8ULL,
		0x5E4DBC962C2AC23FULL,
		0x6812CB1B8EBA08AAULL,
		0x28954B0824DA8A3EULL,
		0x38680AFE81BC594EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F60EC8A77B8A9CULL,
		0xE454A08C4725A3C8ULL,
		0x39376AB49D4F3723ULL,
		0xF1F6EE5113DBCB91ULL,
		0xBC9B792C5855847FULL,
		0xD02596371D741154ULL,
		0x512A961049B5147CULL,
		0x70D015FD0378B29CULL
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
		0x6FBDDCBB7FAB8D06ULL,
		0x716E2C799A415491ULL,
		0x09F84C4354891D7FULL,
		0x59FB5A023D2B90A7ULL,
		0xDF3504228B3C0ECAULL,
		0x08148F51989AFDB3ULL,
		0xB2DAD17B7A67F58EULL,
		0x04B50BCECF0FE6D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF7BB976FF571A0CULL,
		0xE2DC58F33482A922ULL,
		0x13F09886A9123AFEULL,
		0xB3F6B4047A57214EULL,
		0xBE6A084516781D94ULL,
		0x10291EA33135FB67ULL,
		0x65B5A2F6F4CFEB1CULL,
		0x096A179D9E1FCDA1ULL
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
		0x04AF7E910C312C31ULL,
		0x6684066C9D876362ULL,
		0x3CAFCC1485E0E7CFULL,
		0x10D4961B5F86D7D0ULL,
		0x5D0E5A4D55DAF971ULL,
		0xA5ADE5404B78842CULL,
		0xA3A1DEAF653295EDULL,
		0x3A4DC196C76C8A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095EFD2218625862ULL,
		0xCD080CD93B0EC6C4ULL,
		0x795F98290BC1CF9EULL,
		0x21A92C36BF0DAFA0ULL,
		0xBA1CB49AABB5F2E2ULL,
		0x4B5BCA8096F10858ULL,
		0x4743BD5ECA652BDBULL,
		0x749B832D8ED91497ULL
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
		0xF4FC9084CE0CB064ULL,
		0xF06526E93730FFB8ULL,
		0x4A119EDE7A218639ULL,
		0xFA1A45D05D3458ECULL,
		0x281BB2438FFCEDDAULL,
		0x2DEF4BDBCEBF971CULL,
		0x0602FC241DEB909AULL,
		0x27AD756A3C6F2F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9F921099C1960C8ULL,
		0xE0CA4DD26E61FF71ULL,
		0x94233DBCF4430C73ULL,
		0xF4348BA0BA68B1D8ULL,
		0x503764871FF9DBB5ULL,
		0x5BDE97B79D7F2E38ULL,
		0x0C05F8483BD72134ULL,
		0x4F5AEAD478DE5EA2ULL
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
		0x8676EBCABA3512ECULL,
		0xA65A52D11E749832ULL,
		0x1818BD58B53BFD35ULL,
		0xF57B5A0D6D35E146ULL,
		0xB394F14694470E16ULL,
		0x4BC271F31B6A9D64ULL,
		0x9D0E60EF25DD7406ULL,
		0x049032D477B03051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CEDD795746A25D8ULL,
		0x4CB4A5A23CE93065ULL,
		0x30317AB16A77FA6BULL,
		0xEAF6B41ADA6BC28CULL,
		0x6729E28D288E1C2DULL,
		0x9784E3E636D53AC9ULL,
		0x3A1CC1DE4BBAE80CULL,
		0x092065A8EF6060A3ULL
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
		0x6A5EE01F778281BCULL,
		0x88E427FE0893611EULL,
		0x4324765661A883BFULL,
		0x32B77C59B0F3DACDULL,
		0x4D8CFA141A09519BULL,
		0x3CA501C5155D4902ULL,
		0xC361C93932C90F9AULL,
		0x27685694097C7F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BDC03EEF050378ULL,
		0x11C84FFC1126C23CULL,
		0x8648ECACC351077FULL,
		0x656EF8B361E7B59AULL,
		0x9B19F4283412A336ULL,
		0x794A038A2ABA9204ULL,
		0x86C3927265921F34ULL,
		0x4ED0AD2812F8FE07ULL
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
		0xCBF88EDFD97B68F3ULL,
		0x23AC279629C86F08ULL,
		0x1DC5C41C251C9851ULL,
		0xC20DA81212EF17E8ULL,
		0x8CA4BA353077D4A6ULL,
		0x54BEA7F7ED5C0F23ULL,
		0x7BE6E901960FF78CULL,
		0x2F70833CA4948174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F11DBFB2F6D1E6ULL,
		0x47584F2C5390DE11ULL,
		0x3B8B88384A3930A2ULL,
		0x841B502425DE2FD0ULL,
		0x1949746A60EFA94DULL,
		0xA97D4FEFDAB81E47ULL,
		0xF7CDD2032C1FEF18ULL,
		0x5EE10679492902E8ULL
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
		0x4A8F40EA92AB1994ULL,
		0xBD0B5D14B66C3A4EULL,
		0xE3E3E33A5807FCB3ULL,
		0x23C5E6B13E562847ULL,
		0xE22AF9DC26B56844ULL,
		0x0C284CDA3203C666ULL,
		0x35E14BA9D0BDB83AULL,
		0x1EFAE0ABF8995223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951E81D525563328ULL,
		0x7A16BA296CD8749CULL,
		0xC7C7C674B00FF967ULL,
		0x478BCD627CAC508FULL,
		0xC455F3B84D6AD088ULL,
		0x185099B464078CCDULL,
		0x6BC29753A17B7074ULL,
		0x3DF5C157F132A446ULL
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
		0x2B4D4908A38CD08EULL,
		0x3976030846D76D5EULL,
		0xE1ED3812228F06BFULL,
		0xE7D912F4913077BAULL,
		0x21F4C92762D1711FULL,
		0x82BA725C17C6C8A7ULL,
		0x90AAF6A65FEB3DBFULL,
		0x065D7451E7FCA1DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x569A92114719A11CULL,
		0x72EC06108DAEDABCULL,
		0xC3DA7024451E0D7EULL,
		0xCFB225E92260EF75ULL,
		0x43E9924EC5A2E23FULL,
		0x0574E4B82F8D914EULL,
		0x2155ED4CBFD67B7FULL,
		0x0CBAE8A3CFF943BBULL
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
		0xC24058A0B61381B9ULL,
		0xC037E814D9A5E269ULL,
		0x5E09E37C58BB0D28ULL,
		0x576EC2F04D51FA72ULL,
		0x8024F40C3030D3AFULL,
		0x56104C47CCA8A4F8ULL,
		0xD9A468D41912D51AULL,
		0x1B17F83C43A57007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8480B1416C270372ULL,
		0x806FD029B34BC4D3ULL,
		0xBC13C6F8B1761A51ULL,
		0xAEDD85E09AA3F4E4ULL,
		0x0049E8186061A75EULL,
		0xAC20988F995149F1ULL,
		0xB348D1A83225AA34ULL,
		0x362FF078874AE00FULL
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
		0x30C54BAA682DF6A9ULL,
		0x4E072120CE5C4BF0ULL,
		0x6428B927B4C75416ULL,
		0xEB11037AE55E9482ULL,
		0x32A5BD54256D1B49ULL,
		0x43F2396D732103A4ULL,
		0xE967464A3DC48C36ULL,
		0x1D4B0E230AF62D27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x618A9754D05BED52ULL,
		0x9C0E42419CB897E0ULL,
		0xC851724F698EA82CULL,
		0xD62206F5CABD2904ULL,
		0x654B7AA84ADA3693ULL,
		0x87E472DAE6420748ULL,
		0xD2CE8C947B89186CULL,
		0x3A961C4615EC5A4FULL
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
		0x1858B6E91A02A9ABULL,
		0x205CDE94F98C2EE2ULL,
		0xECC6BE98CB73C1BBULL,
		0x2D1403A39D7DEF87ULL,
		0x996D70366858CF89ULL,
		0x52FCA8D3EFB0763DULL,
		0xFB5B76E88E27D51BULL,
		0x10869D77EA8F5ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B16DD234055356ULL,
		0x40B9BD29F3185DC4ULL,
		0xD98D7D3196E78376ULL,
		0x5A2807473AFBDF0FULL,
		0x32DAE06CD0B19F12ULL,
		0xA5F951A7DF60EC7BULL,
		0xF6B6EDD11C4FAA36ULL,
		0x210D3AEFD51EBD9DULL
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
		0xA3F7D5F66E2FF737ULL,
		0x7C50C8D0BCE5585FULL,
		0x3EF29DAB7BBEB9C7ULL,
		0x7BF3AEF2EF4750AFULL,
		0xA2CFC49A9E9DB513ULL,
		0xF953A633638C6963ULL,
		0xAD7AB81E0B07CB74ULL,
		0x068CC18ECF0827D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47EFABECDC5FEE6EULL,
		0xF8A191A179CAB0BFULL,
		0x7DE53B56F77D738EULL,
		0xF7E75DE5DE8EA15EULL,
		0x459F89353D3B6A26ULL,
		0xF2A74C66C718D2C7ULL,
		0x5AF5703C160F96E9ULL,
		0x0D19831D9E104FADULL
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
		0xD4E05C2BE20A7343ULL,
		0x18F74FF1DE36CD6CULL,
		0xADE47F10CF30D186ULL,
		0x3C1A7B8CC3B41F7CULL,
		0xBB3BA91C7C4BC88DULL,
		0xE1B66242DCCE2424ULL,
		0xBA960237D0C6D8B5ULL,
		0x318410D63FA4EC0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C0B857C414E686ULL,
		0x31EE9FE3BC6D9AD9ULL,
		0x5BC8FE219E61A30CULL,
		0x7834F71987683EF9ULL,
		0x76775238F897911AULL,
		0xC36CC485B99C4849ULL,
		0x752C046FA18DB16BULL,
		0x630821AC7F49D819ULL
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
		0x4B4C3EF24A11A463ULL,
		0xA167B16EA1F404A2ULL,
		0x9C267A9A2D61DF06ULL,
		0xF4CDCEE71D2FA55AULL,
		0x18ECC79E659D232FULL,
		0xEF21096446785113ULL,
		0x1C000A2355DA6745ULL,
		0x3889A27B20005B8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96987DE4942348C6ULL,
		0x42CF62DD43E80944ULL,
		0x384CF5345AC3BE0DULL,
		0xE99B9DCE3A5F4AB5ULL,
		0x31D98F3CCB3A465FULL,
		0xDE4212C88CF0A226ULL,
		0x38001446ABB4CE8BULL,
		0x711344F64000B71EULL
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
		0x7BAB70CC63707152ULL,
		0xDD36281C3FB8DC8AULL,
		0x5918719C26811A37ULL,
		0x7843E0F6CEFA80E1ULL,
		0x3135C172B4942A2EULL,
		0x8B7F0DEA4E3DC37AULL,
		0xD551C48352D0CB66ULL,
		0x1C28FE821F8899E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF756E198C6E0E2A4ULL,
		0xBA6C50387F71B914ULL,
		0xB230E3384D02346FULL,
		0xF087C1ED9DF501C2ULL,
		0x626B82E56928545CULL,
		0x16FE1BD49C7B86F4ULL,
		0xAAA38906A5A196CDULL,
		0x3851FD043F1133C9ULL
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
		0x018B4B40993D5622ULL,
		0x1F9F89E3BB1C3523ULL,
		0x68F7869FB02F0BECULL,
		0x335F118A5121F2CCULL,
		0x47853B2B3708CB84ULL,
		0xA558D14A7144A031ULL,
		0x1BD096026424ABECULL,
		0x3FB0F2FCB20C6D1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03169681327AAC44ULL,
		0x3F3F13C776386A46ULL,
		0xD1EF0D3F605E17D8ULL,
		0x66BE2314A243E598ULL,
		0x8F0A76566E119708ULL,
		0x4AB1A294E2894062ULL,
		0x37A12C04C84957D9ULL,
		0x7F61E5F96418DA3EULL
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
		0x89FDA3097EC3159CULL,
		0x4E9274ED0643094FULL,
		0xECB16D0AA327208FULL,
		0xF04232FF92DA50C1ULL,
		0xBEBB5A0E1D30D155ULL,
		0xC2C7BEC37D1EDEFCULL,
		0x086E1DA8F35BBC97ULL,
		0x0A76020E30C1E4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13FB4612FD862B38ULL,
		0x9D24E9DA0C86129FULL,
		0xD962DA15464E411EULL,
		0xE08465FF25B4A183ULL,
		0x7D76B41C3A61A2ABULL,
		0x858F7D86FA3DBDF9ULL,
		0x10DC3B51E6B7792FULL,
		0x14EC041C6183C9E2ULL
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
		0x2C793E5C088712A4ULL,
		0xE2EF716E84BD0031ULL,
		0xF1FEC4C355262F2FULL,
		0xC1F6926C9D49567AULL,
		0x65DC578A180651F5ULL,
		0x5B8550DC8B96D572ULL,
		0x81435CCCD842CFC3ULL,
		0x1A204A5CF636F146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F27CB8110E2548ULL,
		0xC5DEE2DD097A0062ULL,
		0xE3FD8986AA4C5E5FULL,
		0x83ED24D93A92ACF5ULL,
		0xCBB8AF14300CA3EBULL,
		0xB70AA1B9172DAAE4ULL,
		0x0286B999B0859F86ULL,
		0x344094B9EC6DE28DULL
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
		0xCC792D8A9140FE62ULL,
		0x2926CFF56885764CULL,
		0x8713952D95509C01ULL,
		0xE09AE5D18F0D438DULL,
		0x4863300AE999E071ULL,
		0x27E6EE0EB2081824ULL,
		0x2213B6380863A63DULL,
		0x202F1EBC70FE0282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F25B152281FCC4ULL,
		0x524D9FEAD10AEC99ULL,
		0x0E272A5B2AA13802ULL,
		0xC135CBA31E1A871BULL,
		0x90C66015D333C0E3ULL,
		0x4FCDDC1D64103048ULL,
		0x44276C7010C74C7AULL,
		0x405E3D78E1FC0504ULL
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
		0x97CD04C47C59AFCCULL,
		0xA2C67BF084B280AAULL,
		0x975746BF0885BE10ULL,
		0xDD0957567710FDACULL,
		0x73256FE854881464ULL,
		0xDC7E4EE1BB525EBCULL,
		0x84F7DEB0BF0265B2ULL,
		0x1ACE3FB186C63123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F9A0988F8B35F98ULL,
		0x458CF7E109650155ULL,
		0x2EAE8D7E110B7C21ULL,
		0xBA12AEACEE21FB59ULL,
		0xE64ADFD0A91028C9ULL,
		0xB8FC9DC376A4BD78ULL,
		0x09EFBD617E04CB65ULL,
		0x359C7F630D8C6247ULL
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
		0x393DD8D84222D046ULL,
		0x904C4B3A151AC6EEULL,
		0x4777A696741B70D2ULL,
		0x86C5C181563A3B1FULL,
		0x34D4B01315914C44ULL,
		0x9291C13E4A182F0BULL,
		0x61102F3C80C12BF2ULL,
		0x3A36663A1DE78945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x727BB1B08445A08CULL,
		0x209896742A358DDCULL,
		0x8EEF4D2CE836E1A5ULL,
		0x0D8B8302AC74763EULL,
		0x69A960262B229889ULL,
		0x2523827C94305E16ULL,
		0xC2205E79018257E5ULL,
		0x746CCC743BCF128AULL
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
		0x0B08FC402EE32619ULL,
		0xC5E316636FE81CF0ULL,
		0x9E962D592B6D0410ULL,
		0x8CC4536ED0506A0DULL,
		0x504603D565C2F97BULL,
		0x04C3EEEE21505E6CULL,
		0x9283EF362D269C01ULL,
		0x00CF439F0D09250FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1611F8805DC64C32ULL,
		0x8BC62CC6DFD039E0ULL,
		0x3D2C5AB256DA0821ULL,
		0x1988A6DDA0A0D41BULL,
		0xA08C07AACB85F2F7ULL,
		0x0987DDDC42A0BCD8ULL,
		0x2507DE6C5A4D3802ULL,
		0x019E873E1A124A1FULL
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
		0x20892E6D87159DA1ULL,
		0xEC9E938CB647B37CULL,
		0xB010AC8A0A053A53ULL,
		0xEFC1A79BE87E4684ULL,
		0x88E187F23153D6FAULL,
		0xD074AA7665555B85ULL,
		0xDB73125BC74E4803ULL,
		0x0C124D09C145688DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41125CDB0E2B3B42ULL,
		0xD93D27196C8F66F8ULL,
		0x60215914140A74A7ULL,
		0xDF834F37D0FC8D09ULL,
		0x11C30FE462A7ADF5ULL,
		0xA0E954ECCAAAB70BULL,
		0xB6E624B78E9C9007ULL,
		0x18249A13828AD11BULL
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
		0xCA2929BEF0EE2614ULL,
		0x88E538F098A570B2ULL,
		0xA895B165C1B82FAAULL,
		0xE9F25E122FA799D4ULL,
		0x2DBD6E25B2880005ULL,
		0x04394712106F531AULL,
		0xA0100976E61ED35FULL,
		0x243B3E64121E6560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9452537DE1DC4C28ULL,
		0x11CA71E1314AE165ULL,
		0x512B62CB83705F55ULL,
		0xD3E4BC245F4F33A9ULL,
		0x5B7ADC4B6510000BULL,
		0x08728E2420DEA634ULL,
		0x402012EDCC3DA6BEULL,
		0x48767CC8243CCAC1ULL
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
		0x452B5593111320D6ULL,
		0xF498A4C1C16BF858ULL,
		0x27E80334E6AC5608ULL,
		0xDCAE0EAECE5E618CULL,
		0x11BC47117D033061ULL,
		0xB4F3B62B861E3A2EULL,
		0xDE0507EE554DBCD8ULL,
		0x01C3DDA6A0EA12ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A56AB26222641ACULL,
		0xE931498382D7F0B0ULL,
		0x4FD00669CD58AC11ULL,
		0xB95C1D5D9CBCC318ULL,
		0x23788E22FA0660C3ULL,
		0x69E76C570C3C745CULL,
		0xBC0A0FDCAA9B79B1ULL,
		0x0387BB4D41D42557ULL
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
		0x479970AE99866CABULL,
		0xBCEE11B877930030ULL,
		0xCCFF16986216B73EULL,
		0x3692E76CBA3B2B40ULL,
		0x492D8FCDAC537284ULL,
		0xAEDABDF342A5DC60ULL,
		0xB4901FCFB28F0179ULL,
		0x04AC47558FFC321AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F32E15D330CD956ULL,
		0x79DC2370EF260060ULL,
		0x99FE2D30C42D6E7DULL,
		0x6D25CED974765681ULL,
		0x925B1F9B58A6E508ULL,
		0x5DB57BE6854BB8C0ULL,
		0x69203F9F651E02F3ULL,
		0x09588EAB1FF86435ULL
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
		0x8F8BB51DCC6AF85DULL,
		0x45EB8CCA988E426EULL,
		0xD6092D4D481DA387ULL,
		0xDA3CAC910BB4EEC7ULL,
		0x3ADB7E9C5B26D8EFULL,
		0x8C01A267A8D71D38ULL,
		0xB262AB7F5EB441B2ULL,
		0x271BF340ECB59225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F176A3B98D5F0BAULL,
		0x8BD71995311C84DDULL,
		0xAC125A9A903B470EULL,
		0xB47959221769DD8FULL,
		0x75B6FD38B64DB1DFULL,
		0x180344CF51AE3A70ULL,
		0x64C556FEBD688365ULL,
		0x4E37E681D96B244BULL
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
		0xFB89CDFF0A27FAF0ULL,
		0x6DDD1A5628D73922ULL,
		0x022D9A84B6E553F1ULL,
		0x14E783B4F8C5E499ULL,
		0x1471F49E9010C704ULL,
		0x5FE4EE568BB87B0BULL,
		0x8A96B681540F8220ULL,
		0x32743BEAE188A03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7139BFE144FF5E0ULL,
		0xDBBA34AC51AE7245ULL,
		0x045B35096DCAA7E2ULL,
		0x29CF0769F18BC932ULL,
		0x28E3E93D20218E08ULL,
		0xBFC9DCAD1770F616ULL,
		0x152D6D02A81F0440ULL,
		0x64E877D5C311407BULL
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
		0x2F2BED65C0EC97DEULL,
		0x91286EDC41D21410ULL,
		0xBB862B31E2D3AF78ULL,
		0xC9F8FEAED8F133E2ULL,
		0x0C734107E4DD4730ULL,
		0x2510C285121FEED6ULL,
		0xFF628DEE5A16E2A5ULL,
		0x0E61B925D947EE80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E57DACB81D92FBCULL,
		0x2250DDB883A42820ULL,
		0x770C5663C5A75EF1ULL,
		0x93F1FD5DB1E267C5ULL,
		0x18E6820FC9BA8E61ULL,
		0x4A21850A243FDDACULL,
		0xFEC51BDCB42DC54AULL,
		0x1CC3724BB28FDD01ULL
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
		0xD3FB4607683296B8ULL,
		0xA0227E51D9A68BFBULL,
		0xC6DD9DFE4ADC6DDDULL,
		0xDE46058A95A9194AULL,
		0x7B8F298340258EE1ULL,
		0x4825549F980CFA6CULL,
		0x49039A7140052C6DULL,
		0x153AB0866A9820CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F68C0ED0652D70ULL,
		0x4044FCA3B34D17F7ULL,
		0x8DBB3BFC95B8DBBBULL,
		0xBC8C0B152B523295ULL,
		0xF71E5306804B1DC3ULL,
		0x904AA93F3019F4D8ULL,
		0x920734E2800A58DAULL,
		0x2A75610CD530419EULL
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
		0x8336B3E85BEDE7EDULL,
		0xCE54D3E1449235A8ULL,
		0xCD8D1584D29AEC81ULL,
		0xB456A64F2A59C0EFULL,
		0x73FC40E05D8692DEULL,
		0xA2C4FB1F573211D6ULL,
		0xF5F8A1B1F9E1BB2BULL,
		0x1774E7E2286ED688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x066D67D0B7DBCFDAULL,
		0x9CA9A7C289246B51ULL,
		0x9B1A2B09A535D903ULL,
		0x68AD4C9E54B381DFULL,
		0xE7F881C0BB0D25BDULL,
		0x4589F63EAE6423ACULL,
		0xEBF14363F3C37657ULL,
		0x2EE9CFC450DDAD11ULL
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
		0x6A12B067C1C04337ULL,
		0xDD8D48032C7A88DDULL,
		0xEC3486D78DFFA7ABULL,
		0x41E3F0F8611F7210ULL,
		0xEBBEC2EB79C3A414ULL,
		0x93D0AE095E6AF42FULL,
		0xDF77950278D6764FULL,
		0x2EA0485C5AB32B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD42560CF8380866EULL,
		0xBB1A900658F511BAULL,
		0xD8690DAF1BFF4F57ULL,
		0x83C7E1F0C23EE421ULL,
		0xD77D85D6F3874828ULL,
		0x27A15C12BCD5E85FULL,
		0xBEEF2A04F1ACEC9FULL,
		0x5D4090B8B5665687ULL
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
		0xEFBBDAFD6CC997AEULL,
		0x894BF0BE4F933DF4ULL,
		0x891962F9F63D2BF0ULL,
		0xE8E1192F7FD2DC9FULL,
		0x89FF4DA305EA0AECULL,
		0xDFD7B8145E5088D0ULL,
		0xB653A62AAFE24EE4ULL,
		0x1B9CDED56C77E3E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF77B5FAD9932F5CULL,
		0x1297E17C9F267BE9ULL,
		0x1232C5F3EC7A57E1ULL,
		0xD1C2325EFFA5B93FULL,
		0x13FE9B460BD415D9ULL,
		0xBFAF7028BCA111A1ULL,
		0x6CA74C555FC49DC9ULL,
		0x3739BDAAD8EFC7C3ULL
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
		0xC924C11A4875C9CEULL,
		0x73878A2610AC63A0ULL,
		0x3D0FDDBD9EF160E5ULL,
		0xEE5BE4815BA50389ULL,
		0xCF46CD3BDD28E9BDULL,
		0x604E4AEFE12D4391ULL,
		0x48F497EE2D0B9C45ULL,
		0x3A47175E549BD9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9249823490EB939CULL,
		0xE70F144C2158C741ULL,
		0x7A1FBB7B3DE2C1CAULL,
		0xDCB7C902B74A0712ULL,
		0x9E8D9A77BA51D37BULL,
		0xC09C95DFC25A8723ULL,
		0x91E92FDC5A17388AULL,
		0x748E2EBCA937B368ULL
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
		0x00EA8ACFE5BE01D6ULL,
		0x246E8BFF9E29C98BULL,
		0xA776B0F461428FD3ULL,
		0x10F7599EE0B50603ULL,
		0x78B73B272FB7515CULL,
		0x6EA97ED51AA2EBFAULL,
		0x741F3BB104DFE2DBULL,
		0x19197495AE108F31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01D5159FCB7C03ACULL,
		0x48DD17FF3C539316ULL,
		0x4EED61E8C2851FA6ULL,
		0x21EEB33DC16A0C07ULL,
		0xF16E764E5F6EA2B8ULL,
		0xDD52FDAA3545D7F4ULL,
		0xE83E776209BFC5B6ULL,
		0x3232E92B5C211E62ULL
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
		0x915FD443C1B25C0EULL,
		0x89EA69B7B7B5C4AFULL,
		0xE10C68CC5D0493D8ULL,
		0xCAF08A5001BD2417ULL,
		0xC4890CEDD5BCBE63ULL,
		0x488B1D4307C42507ULL,
		0x7997A88E41B7663FULL,
		0x0CACDB1EB11FB5F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22BFA8878364B81CULL,
		0x13D4D36F6F6B895FULL,
		0xC218D198BA0927B1ULL,
		0x95E114A0037A482FULL,
		0x891219DBAB797CC7ULL,
		0x91163A860F884A0FULL,
		0xF32F511C836ECC7EULL,
		0x1959B63D623F6BE0ULL
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
		0xBE5DB79EF96A90F3ULL,
		0xB9C44DF64CAE1477ULL,
		0x51D4B1D0FC126E7DULL,
		0xA5370BDC7F6F89B5ULL,
		0xF764050394F8EED6ULL,
		0x7D2F0B29181D9C04ULL,
		0x452730D5B7E23525ULL,
		0x2965C926BBC85FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CBB6F3DF2D521E6ULL,
		0x73889BEC995C28EFULL,
		0xA3A963A1F824DCFBULL,
		0x4A6E17B8FEDF136AULL,
		0xEEC80A0729F1DDADULL,
		0xFA5E1652303B3809ULL,
		0x8A4E61AB6FC46A4AULL,
		0x52CB924D7790BF5AULL
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
		0x1A266C490DB7E415ULL,
		0xEEF653BD125B3129ULL,
		0xF4808D56A6C75616ULL,
		0x9F815BDFD25D45EBULL,
		0x39515F61B008CEA9ULL,
		0x50B37ABC4BC69FA8ULL,
		0x40BC9B8A663538EAULL,
		0x1B36145F2734A967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x344CD8921B6FC82AULL,
		0xDDECA77A24B66252ULL,
		0xE9011AAD4D8EAC2DULL,
		0x3F02B7BFA4BA8BD7ULL,
		0x72A2BEC360119D53ULL,
		0xA166F578978D3F50ULL,
		0x81793714CC6A71D4ULL,
		0x366C28BE4E6952CEULL
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
		0x8AFABA908D843D17ULL,
		0xC9790B99AF5AF119ULL,
		0x8856904702CB9055ULL,
		0xC71E57BEA93252A0ULL,
		0xD817E5D5886A495FULL,
		0x2259F37A27D5E876ULL,
		0xB8CA614B0D605CB9ULL,
		0x02E7A394B04FFA0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15F575211B087A2EULL,
		0x92F217335EB5E233ULL,
		0x10AD208E059720ABULL,
		0x8E3CAF7D5264A541ULL,
		0xB02FCBAB10D492BFULL,
		0x44B3E6F44FABD0EDULL,
		0x7194C2961AC0B972ULL,
		0x05CF4729609FF41BULL
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
		0x63CABB2354E693FCULL,
		0x7BD5E5511AEFB438ULL,
		0x2912546FBFFD91A0ULL,
		0xE99BA29F1A8C831EULL,
		0x2F7EF3D2D70CD053ULL,
		0xC1102CD6E22014A3ULL,
		0x2C599CDF64D3AB14ULL,
		0x37203809705C2B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7957646A9CD27F8ULL,
		0xF7ABCAA235DF6870ULL,
		0x5224A8DF7FFB2340ULL,
		0xD337453E3519063CULL,
		0x5EFDE7A5AE19A0A7ULL,
		0x822059ADC4402946ULL,
		0x58B339BEC9A75629ULL,
		0x6E407012E0B856B8ULL
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
		0x6A605CF59B29C77CULL,
		0x2458798364478B07ULL,
		0x5C7EEA4319AEC982ULL,
		0x138437EB277701B3ULL,
		0x66548246F5CA97F3ULL,
		0xC4A26457198052ABULL,
		0x9FE8FC7603FD6F7FULL,
		0x013CD3C4304536BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4C0B9EB36538EF8ULL,
		0x48B0F306C88F160EULL,
		0xB8FDD486335D9304ULL,
		0x27086FD64EEE0366ULL,
		0xCCA9048DEB952FE6ULL,
		0x8944C8AE3300A556ULL,
		0x3FD1F8EC07FADEFFULL,
		0x0279A788608A6D7BULL
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
		0xA110E5766752842EULL,
		0x5EA6FA8154FC9B17ULL,
		0x1AE08F762A70FE65ULL,
		0xCBAFD7B81D98BB25ULL,
		0x4056142453936389ULL,
		0xB47D7DEF97B02B31ULL,
		0xB9D0227D3AFBE8EEULL,
		0x0343CC840B87034CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4221CAECCEA5085CULL,
		0xBD4DF502A9F9362FULL,
		0x35C11EEC54E1FCCAULL,
		0x975FAF703B31764AULL,
		0x80AC2848A726C713ULL,
		0x68FAFBDF2F605662ULL,
		0x73A044FA75F7D1DDULL,
		0x06879908170E0699ULL
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
		0x4BF18CB4FDDD2EF1ULL,
		0xF902981185A1659EULL,
		0x282AD3AB7FDF243EULL,
		0x2EBCBD698B59AF29ULL,
		0x8F04D3093C81F9A8ULL,
		0xA8A2439EC0D9ADA7ULL,
		0x2F776F5B5CCACAB6ULL,
		0x35F9D3EFEFAD3283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E31969FBBA5DE2ULL,
		0xF20530230B42CB3CULL,
		0x5055A756FFBE487DULL,
		0x5D797AD316B35E52ULL,
		0x1E09A6127903F350ULL,
		0x5144873D81B35B4FULL,
		0x5EEEDEB6B995956DULL,
		0x6BF3A7DFDF5A6506ULL
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
		0x24DA2CFA6958206DULL,
		0x197E4708AE0A471DULL,
		0x2DDC849438144A73ULL,
		0x8E43467F844B2778ULL,
		0x2D9F71645674B0AFULL,
		0x16DE8782DF27BBA4ULL,
		0xFBA58928AB2DB91BULL,
		0x3F80E97EBCF3BB76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49B459F4D2B040DAULL,
		0x32FC8E115C148E3AULL,
		0x5BB90928702894E6ULL,
		0x1C868CFF08964EF0ULL,
		0x5B3EE2C8ACE9615FULL,
		0x2DBD0F05BE4F7748ULL,
		0xF74B1251565B7236ULL,
		0x7F01D2FD79E776EDULL
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
		0x23BF89F28D52087CULL,
		0xAE0ED79EA2239556ULL,
		0x3239D56B63F5132EULL,
		0x1D773FE787CBDCC7ULL,
		0xF36524D3946FDF3BULL,
		0x7CFF870EB60A1EFDULL,
		0x074665A3B88375C3ULL,
		0x18BB26EF50D5B6DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477F13E51AA410F8ULL,
		0x5C1DAF3D44472AACULL,
		0x6473AAD6C7EA265DULL,
		0x3AEE7FCF0F97B98EULL,
		0xE6CA49A728DFBE76ULL,
		0xF9FF0E1D6C143DFBULL,
		0x0E8CCB477106EB86ULL,
		0x31764DDEA1AB6DB4ULL
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
		0x26EA5ECA72A0CC4AULL,
		0x2505A3DF55833137ULL,
		0xD4A5D1839EB6C566ULL,
		0x389D6247885DBA57ULL,
		0xF3D58A5125D48184ULL,
		0x51AA4D44EAD989DEULL,
		0x792D6ABC95EDBF1EULL,
		0x1E8CCCE04F0DB71DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD4BD94E5419894ULL,
		0x4A0B47BEAB06626EULL,
		0xA94BA3073D6D8ACCULL,
		0x713AC48F10BB74AFULL,
		0xE7AB14A24BA90308ULL,
		0xA3549A89D5B313BDULL,
		0xF25AD5792BDB7E3CULL,
		0x3D1999C09E1B6E3AULL
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
		0xE82AA1508C32A1B7ULL,
		0x8696FA7EE63290FFULL,
		0x53F1BBDE875578B2ULL,
		0x3D27E52341ED1796ULL,
		0x1EC6F7F10D00A29BULL,
		0x47136B795BCFF554ULL,
		0xFBCCE5263AB4FC7EULL,
		0x2F172C55C986C7C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05542A11865436EULL,
		0x0D2DF4FDCC6521FFULL,
		0xA7E377BD0EAAF165ULL,
		0x7A4FCA4683DA2F2CULL,
		0x3D8DEFE21A014536ULL,
		0x8E26D6F2B79FEAA8ULL,
		0xF799CA4C7569F8FCULL,
		0x5E2E58AB930D8F89ULL
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
		0xD39526191E65B43FULL,
		0xBF74ED44DFCE9F74ULL,
		0xDD77EDC5DDFAD69BULL,
		0x9D2C924ABED0BA26ULL,
		0x3932F10C94A369DDULL,
		0xE854D8CD90B65252ULL,
		0x7C0938661A340F30ULL,
		0x3457DF6064F2EF72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72A4C323CCB687EULL,
		0x7EE9DA89BF9D3EE9ULL,
		0xBAEFDB8BBBF5AD37ULL,
		0x3A5924957DA1744DULL,
		0x7265E2192946D3BBULL,
		0xD0A9B19B216CA4A4ULL,
		0xF81270CC34681E61ULL,
		0x68AFBEC0C9E5DEE4ULL
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
		0x8B693EF2187DB188ULL,
		0x298932C197BFD3C3ULL,
		0x4801FFAB455837BCULL,
		0xDA2FF9C86F99685DULL,
		0xCBB10F3D8C213F9FULL,
		0x8C2C49D91AA00B83ULL,
		0x4AB059FABE55451FULL,
		0x29C93D5C99D1F521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16D27DE430FB6310ULL,
		0x531265832F7FA787ULL,
		0x9003FF568AB06F78ULL,
		0xB45FF390DF32D0BAULL,
		0x97621E7B18427F3FULL,
		0x185893B235401707ULL,
		0x9560B3F57CAA8A3FULL,
		0x53927AB933A3EA42ULL
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
		0xC7FE9D4A07E1B7B8ULL,
		0x44EAFD2B1F847266ULL,
		0x1A92EAC37F2B3003ULL,
		0xA0E256E7451B6778ULL,
		0xA7CCAA6AE3BBFA17ULL,
		0xA1FCA9F370ADE3F1ULL,
		0xDC954DEC3BFB9AAEULL,
		0x1E4BECD1DC525E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFD3A940FC36F70ULL,
		0x89D5FA563F08E4CDULL,
		0x3525D586FE566006ULL,
		0x41C4ADCE8A36CEF0ULL,
		0x4F9954D5C777F42FULL,
		0x43F953E6E15BC7E3ULL,
		0xB92A9BD877F7355DULL,
		0x3C97D9A3B8A4BCB1ULL
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
		0x34A3A3E53919F3A1ULL,
		0x6C15AE38369A7790ULL,
		0xDADAD9D571D1E8B6ULL,
		0x58DE765DA1434719ULL,
		0x59160DA27786B359ULL,
		0xCF7384E77AFA1C95ULL,
		0xB994BB6CA7EEDDC8ULL,
		0x04F0AF311A546A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x694747CA7233E742ULL,
		0xD82B5C706D34EF20ULL,
		0xB5B5B3AAE3A3D16CULL,
		0xB1BCECBB42868E33ULL,
		0xB22C1B44EF0D66B2ULL,
		0x9EE709CEF5F4392AULL,
		0x732976D94FDDBB91ULL,
		0x09E15E6234A8D4CBULL
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
		0x2EDECA91FA8E9A3FULL,
		0xFB57B8086ED816E7ULL,
		0xF3308FB2C4DC4983ULL,
		0xD1A8308B4784B66DULL,
		0x8BE73FCEEB56E883ULL,
		0xBE774F3DBE91574CULL,
		0x7705B82AFAEC5D47ULL,
		0x35DD358232864E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DBD9523F51D347EULL,
		0xF6AF7010DDB02DCEULL,
		0xE6611F6589B89307ULL,
		0xA35061168F096CDBULL,
		0x17CE7F9DD6ADD107ULL,
		0x7CEE9E7B7D22AE99ULL,
		0xEE0B7055F5D8BA8FULL,
		0x6BBA6B04650C9C3EULL
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
		0x74A1BE2DC7975159ULL,
		0x6CD62FA5B40B1358ULL,
		0x96E6DF771E8020CEULL,
		0x8B90EA6E0012B529ULL,
		0x27A885498FA66D60ULL,
		0x6E4B650E132007AEULL,
		0x94A4ACAD354DB0D2ULL,
		0x2F8B3C194C6C1C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9437C5B8F2EA2B2ULL,
		0xD9AC5F4B681626B0ULL,
		0x2DCDBEEE3D00419CULL,
		0x1721D4DC00256A53ULL,
		0x4F510A931F4CDAC1ULL,
		0xDC96CA1C26400F5CULL,
		0x2949595A6A9B61A4ULL,
		0x5F16783298D83899ULL
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
		0xD1A2D2C4225B2C35ULL,
		0x33CB463C499BE53AULL,
		0x8E6FBD7754B524D8ULL,
		0xFB70368F6CA8F334ULL,
		0x348F7DA440E7C54DULL,
		0x3DBD24DF6C2CAC61ULL,
		0x961892674F1493AAULL,
		0x0136F9CA197E14D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA345A58844B6586AULL,
		0x67968C789337CA75ULL,
		0x1CDF7AEEA96A49B0ULL,
		0xF6E06D1ED951E669ULL,
		0x691EFB4881CF8A9BULL,
		0x7B7A49BED85958C2ULL,
		0x2C3124CE9E292754ULL,
		0x026DF39432FC29A9ULL
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
		0x53E1574127D9A667ULL,
		0x36D726306B73DE93ULL,
		0xFA49AB8FA0565DE0ULL,
		0x9C539A5EB8F7700FULL,
		0xCBFF7CA1EEC66308ULL,
		0x16D9EF05CB1778C1ULL,
		0xDE34F3C165E9F752ULL,
		0x2B85F2043D2390D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7C2AE824FB34CCEULL,
		0x6DAE4C60D6E7BD26ULL,
		0xF493571F40ACBBC0ULL,
		0x38A734BD71EEE01FULL,
		0x97FEF943DD8CC611ULL,
		0x2DB3DE0B962EF183ULL,
		0xBC69E782CBD3EEA4ULL,
		0x570BE4087A4721ADULL
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
		0xFD8B94619AE4B547ULL,
		0x449DCC3728ADD2AAULL,
		0x5D549E8687114E65ULL,
		0x4B5B7C2AAC6CD884ULL,
		0xC1CBA02C118A8A35ULL,
		0x308E8B2E362A3360ULL,
		0xDAC2DC4D60875F09ULL,
		0x0B4659057BC07EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB1728C335C96A8EULL,
		0x893B986E515BA555ULL,
		0xBAA93D0D0E229CCAULL,
		0x96B6F85558D9B108ULL,
		0x839740582315146AULL,
		0x611D165C6C5466C1ULL,
		0xB585B89AC10EBE12ULL,
		0x168CB20AF780FDCFULL
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
		0xA194FCC7E1332B2DULL,
		0x2D12CB3880C7E0C8ULL,
		0x1E82668B90163E5AULL,
		0x26E6B1C3064DD28AULL,
		0xE74F8A2745F3F2E3ULL,
		0xA17EF6FE6DE4F6A8ULL,
		0xC88F0C5EAD9595AAULL,
		0x15C52A76FCAE9BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4329F98FC266565AULL,
		0x5A259671018FC191ULL,
		0x3D04CD17202C7CB4ULL,
		0x4DCD63860C9BA514ULL,
		0xCE9F144E8BE7E5C6ULL,
		0x42FDEDFCDBC9ED51ULL,
		0x911E18BD5B2B2B55ULL,
		0x2B8A54EDF95D3769ULL
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
		0x8CE4A527F0E327BDULL,
		0x6C58DD8E9D6E878BULL,
		0xFBD5F3CDB6D3CA4CULL,
		0x9FBFAB527E7BB8BBULL,
		0xB9A9CE9A6DB6D44EULL,
		0x88F47C5D56FA8B23ULL,
		0x66F797CE260181DDULL,
		0x259756AA2360670BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C94A4FE1C64F7AULL,
		0xD8B1BB1D3ADD0F17ULL,
		0xF7ABE79B6DA79498ULL,
		0x3F7F56A4FCF77177ULL,
		0x73539D34DB6DA89DULL,
		0x11E8F8BAADF51647ULL,
		0xCDEF2F9C4C0303BBULL,
		0x4B2EAD5446C0CE16ULL
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
		0x7CEC6F7BCB16785FULL,
		0x072ED8BB84E0E2A2ULL,
		0x4E93C64EF05B8177ULL,
		0xE7F8630E1C9F4E30ULL,
		0x216D00134834CF71ULL,
		0x2CA71DF9B8308280ULL,
		0xF09523930E8DA52FULL,
		0x2AB33D7F5653FFA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D8DEF7962CF0BEULL,
		0x0E5DB17709C1C544ULL,
		0x9D278C9DE0B702EEULL,
		0xCFF0C61C393E9C60ULL,
		0x42DA002690699EE3ULL,
		0x594E3BF370610500ULL,
		0xE12A47261D1B4A5EULL,
		0x55667AFEACA7FF43ULL
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
		0x05477F23588D9CDAULL,
		0xAD0A384A7D5F16CFULL,
		0x19A7E47FB3A1D0FDULL,
		0x1DFBDC6C15CC86BCULL,
		0xABED3874F6ACCE12ULL,
		0xB659854FE0061765ULL,
		0x358574172059F90EULL,
		0x1B4D97EE1E544FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8EFE46B11B39B4ULL,
		0x5A147094FABE2D9EULL,
		0x334FC8FF6743A1FBULL,
		0x3BF7B8D82B990D78ULL,
		0x57DA70E9ED599C24ULL,
		0x6CB30A9FC00C2ECBULL,
		0x6B0AE82E40B3F21DULL,
		0x369B2FDC3CA89FB8ULL
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
		0xB52E1FD975E3364EULL,
		0x92E631A72716D384ULL,
		0xB08B5B543EDEAC93ULL,
		0x3C5C06B500B9D61AULL,
		0x6CCEEE8BD46BE0DAULL,
		0x353BB731331EB18BULL,
		0xA4CDBDBBB4405D1BULL,
		0x11E2BC5214B3D4C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A5C3FB2EBC66C9CULL,
		0x25CC634E4E2DA709ULL,
		0x6116B6A87DBD5927ULL,
		0x78B80D6A0173AC35ULL,
		0xD99DDD17A8D7C1B4ULL,
		0x6A776E62663D6316ULL,
		0x499B7B776880BA36ULL,
		0x23C578A42967A993ULL
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
		0xDF26145A524EB8E8ULL,
		0xCF11288BAD463CCFULL,
		0xF00FAE09E0539E66ULL,
		0x2F07FBBA2E79EABBULL,
		0xD356342F7C5767E8ULL,
		0x7F35CE9992FB3303ULL,
		0xD3AC0EB3E2F58137ULL,
		0x32C1F2B82D3F780CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE4C28B4A49D71D0ULL,
		0x9E2251175A8C799FULL,
		0xE01F5C13C0A73CCDULL,
		0x5E0FF7745CF3D577ULL,
		0xA6AC685EF8AECFD0ULL,
		0xFE6B9D3325F66607ULL,
		0xA7581D67C5EB026EULL,
		0x6583E5705A7EF019ULL
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
		0xACDC72F4C28D0214ULL,
		0x459AD813DE0FE371ULL,
		0xF84EF9280F9E5726ULL,
		0x3FE0E3C82036CE50ULL,
		0x0226B8F2AC8724AFULL,
		0xFEA06253C9265B04ULL,
		0xF25E588FBFF55E15ULL,
		0x14ADC76937404196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B8E5E9851A0428ULL,
		0x8B35B027BC1FC6E3ULL,
		0xF09DF2501F3CAE4CULL,
		0x7FC1C790406D9CA1ULL,
		0x044D71E5590E495EULL,
		0xFD40C4A7924CB608ULL,
		0xE4BCB11F7FEABC2BULL,
		0x295B8ED26E80832DULL
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
		0x3E9E38736191E51EULL,
		0xE65A258EDCBC2BECULL,
		0x7A6F66D124E64422ULL,
		0x6A38CA97EC815FFAULL,
		0xCF21D52BA811BA5CULL,
		0xE65F6F6B75FB1EA3ULL,
		0xAB76CC0F3608FAA5ULL,
		0x2FB6AB80EA28A122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D3C70E6C323CA3CULL,
		0xCCB44B1DB97857D8ULL,
		0xF4DECDA249CC8845ULL,
		0xD471952FD902BFF4ULL,
		0x9E43AA57502374B8ULL,
		0xCCBEDED6EBF63D47ULL,
		0x56ED981E6C11F54BULL,
		0x5F6D5701D4514245ULL
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
		0x9E2CB52D0C41997DULL,
		0x0F4330636BBAA863ULL,
		0xAEE177A001A2A0FFULL,
		0x6CC1F27377D6EDACULL,
		0x779451C1CE1F73A7ULL,
		0x9B376A18130A1ECAULL,
		0xA8BAACFE123E1EDDULL,
		0x0429CC4C869A9368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C596A5A188332FAULL,
		0x1E8660C6D77550C7ULL,
		0x5DC2EF40034541FEULL,
		0xD983E4E6EFADDB59ULL,
		0xEF28A3839C3EE74EULL,
		0x366ED43026143D94ULL,
		0x517559FC247C3DBBULL,
		0x085398990D3526D1ULL
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
		0x7E05A55EE3947B53ULL,
		0x190FCF56EA36F528ULL,
		0xCAEF9436E32EB103ULL,
		0x4523D2266BB901F5ULL,
		0xAD7E76155F12C166ULL,
		0xEED63265874E4908ULL,
		0x1F763EF84280C2EDULL,
		0x2A1462658779457BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC0B4ABDC728F6A6ULL,
		0x321F9EADD46DEA50ULL,
		0x95DF286DC65D6206ULL,
		0x8A47A44CD77203EBULL,
		0x5AFCEC2ABE2582CCULL,
		0xDDAC64CB0E9C9211ULL,
		0x3EEC7DF0850185DBULL,
		0x5428C4CB0EF28AF6ULL
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
		0x1B38B83BCB73DEB0ULL,
		0x9BF7E965948A2E26ULL,
		0x63FC36B874C452F3ULL,
		0x2EB01D421CBB24F1ULL,
		0x946A30CCE29E5A28ULL,
		0x38CE36A2DD31CAD1ULL,
		0xE99340ED6742D661ULL,
		0x23A95074CC338337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3671707796E7BD60ULL,
		0x37EFD2CB29145C4CULL,
		0xC7F86D70E988A5E7ULL,
		0x5D603A84397649E2ULL,
		0x28D46199C53CB450ULL,
		0x719C6D45BA6395A3ULL,
		0xD32681DACE85ACC2ULL,
		0x4752A0E99867066FULL
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
		0x4C93D2088EE850A9ULL,
		0x7CAB816F73D7C3D1ULL,
		0x4E961396C942775DULL,
		0xD0074E7E34AEC0C4ULL,
		0x750934344F9A08C7ULL,
		0xF45C9A737A75F627ULL,
		0xDC1178462B44FB84ULL,
		0x3BA6B424DB76A01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9927A4111DD0A152ULL,
		0xF95702DEE7AF87A2ULL,
		0x9D2C272D9284EEBAULL,
		0xA00E9CFC695D8188ULL,
		0xEA1268689F34118FULL,
		0xE8B934E6F4EBEC4EULL,
		0xB822F08C5689F709ULL,
		0x774D6849B6ED403DULL
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
		0x4D733B9E10C6C3A5ULL,
		0x65EDD1DFB3D900CCULL,
		0x5432921A992A56DEULL,
		0x195E84D641280602ULL,
		0xAB92232120065EACULL,
		0x3150069201BBEEA6ULL,
		0x384161602EC0ADB6ULL,
		0x367F6C05A083344AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AE6773C218D874AULL,
		0xCBDBA3BF67B20198ULL,
		0xA86524353254ADBCULL,
		0x32BD09AC82500C04ULL,
		0x57244642400CBD58ULL,
		0x62A00D240377DD4DULL,
		0x7082C2C05D815B6CULL,
		0x6CFED80B41066894ULL
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
		0x3C4C7682C48900F5ULL,
		0x2042DE3D72974740ULL,
		0x4938C6FACE241239ULL,
		0x5D1777FBE158F46BULL,
		0x0431F41E5D724009ULL,
		0x970E1DFD6A707437ULL,
		0x70CB4851B374E324ULL,
		0x388B8DF0E86F9121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7898ED05891201EAULL,
		0x4085BC7AE52E8E80ULL,
		0x92718DF59C482472ULL,
		0xBA2EEFF7C2B1E8D6ULL,
		0x0863E83CBAE48012ULL,
		0x2E1C3BFAD4E0E86EULL,
		0xE19690A366E9C649ULL,
		0x71171BE1D0DF2242ULL
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
		0x39AAAA15069673A0ULL,
		0x2A51EE9F0B525F7FULL,
		0xA087683366D0E77BULL,
		0xB95CF03A956B3566ULL,
		0x6D7A21940979CB3EULL,
		0xF84EF5316701F984ULL,
		0xCEC9CC1DB0A68E3BULL,
		0x185E642587080C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7355542A0D2CE740ULL,
		0x54A3DD3E16A4BEFEULL,
		0x410ED066CDA1CEF6ULL,
		0x72B9E0752AD66ACDULL,
		0xDAF4432812F3967DULL,
		0xF09DEA62CE03F308ULL,
		0x9D93983B614D1C77ULL,
		0x30BCC84B0E101917ULL
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
		0xEE7ED94179296137ULL,
		0xF93F467C0C306F67ULL,
		0x896F9BFE4F1D3846ULL,
		0x6B46482BE67D0B4CULL,
		0xEA70831BF012E69BULL,
		0xEB4557355ADE05BAULL,
		0x89D9A8DCBCC8B2D4ULL,
		0x1E9B4BFB54AA3EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCFDB282F252C26EULL,
		0xF27E8CF81860DECFULL,
		0x12DF37FC9E3A708DULL,
		0xD68C9057CCFA1699ULL,
		0xD4E10637E025CD36ULL,
		0xD68AAE6AB5BC0B75ULL,
		0x13B351B9799165A9ULL,
		0x3D3697F6A9547D4DULL
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
		0xC14E2C8589967436ULL,
		0xEF6AA6ACB45F8889ULL,
		0x803A3124903955F8ULL,
		0x690700D2A97BAC2CULL,
		0x4F6793A3026D47CDULL,
		0x00D7A243CF727D52ULL,
		0xD3BB5AAB14CCCE1BULL,
		0x16D8DD40263461C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x829C590B132CE86CULL,
		0xDED54D5968BF1113ULL,
		0x007462492072ABF1ULL,
		0xD20E01A552F75859ULL,
		0x9ECF274604DA8F9AULL,
		0x01AF44879EE4FAA4ULL,
		0xA776B55629999C36ULL,
		0x2DB1BA804C68C387ULL
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
		0x426D2DEEBF676855ULL,
		0xF47B69AFF56A9A65ULL,
		0xBAD164F29DD9A899ULL,
		0x1C5B8F52D183C179ULL,
		0x51FC60D04D34235EULL,
		0x804A5B5D677DD8FBULL,
		0x6B036ABEB088553FULL,
		0x2A7348249797CC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84DA5BDD7ECED0AAULL,
		0xE8F6D35FEAD534CAULL,
		0x75A2C9E53BB35133ULL,
		0x38B71EA5A30782F3ULL,
		0xA3F8C1A09A6846BCULL,
		0x0094B6BACEFBB1F6ULL,
		0xD606D57D6110AA7FULL,
		0x54E690492F2F9824ULL
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
		0x4B632BF9C8006335ULL,
		0x89654F631370348FULL,
		0xA5CC7D0E45D90A63ULL,
		0x49B460864D12B665ULL,
		0xC22EC944183B6B16ULL,
		0xE16442307183EA32ULL,
		0xA5C9C06C04CD373EULL,
		0x301DC7C05058FE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96C657F39000C66AULL,
		0x12CA9EC626E0691EULL,
		0x4B98FA1C8BB214C7ULL,
		0x9368C10C9A256CCBULL,
		0x845D92883076D62CULL,
		0xC2C88460E307D465ULL,
		0x4B9380D8099A6E7DULL,
		0x603B8F80A0B1FC95ULL
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
		0x9E69A0D194468894ULL,
		0x2D54269B588E53C1ULL,
		0x368F1DC32652E4DCULL,
		0x6CB275E346269FCEULL,
		0x62051465B45442BBULL,
		0xAB094B115A58745CULL,
		0xA85A70C475EF3D06ULL,
		0x352688C4D0091E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD341A3288D1128ULL,
		0x5AA84D36B11CA783ULL,
		0x6D1E3B864CA5C9B8ULL,
		0xD964EBC68C4D3F9CULL,
		0xC40A28CB68A88576ULL,
		0x56129622B4B0E8B8ULL,
		0x50B4E188EBDE7A0DULL,
		0x6A4D1189A0123C53ULL
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
		0xB3605DCDDE1508BDULL,
		0xA91DEEE3B0EEE018ULL,
		0x69A3FE6D54F90946ULL,
		0x1AC22BE4D01D6EADULL,
		0x04FC20C706EB035BULL,
		0x425B2322581F697FULL,
		0xBE7BEB4F68EC7B9BULL,
		0x037BED5882DE4868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C0BB9BBC2A117AULL,
		0x523BDDC761DDC031ULL,
		0xD347FCDAA9F2128DULL,
		0x358457C9A03ADD5AULL,
		0x09F8418E0DD606B6ULL,
		0x84B64644B03ED2FEULL,
		0x7CF7D69ED1D8F736ULL,
		0x06F7DAB105BC90D1ULL
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
		0xF83E0EEE65C838FDULL,
		0x54AAECAAD368F0F3ULL,
		0x88863B9415CEAA47ULL,
		0xFDCFE3C3ADCEED5EULL,
		0xF8A43FBB417720B6ULL,
		0x579BF20EF780BC46ULL,
		0x11BE3C74075D6981ULL,
		0x0ADB5EA5B50710E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07C1DDCCB9071FAULL,
		0xA955D955A6D1E1E7ULL,
		0x110C77282B9D548EULL,
		0xFB9FC7875B9DDABDULL,
		0xF1487F7682EE416DULL,
		0xAF37E41DEF01788DULL,
		0x237C78E80EBAD302ULL,
		0x15B6BD4B6A0E21CEULL
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
		0x1000936004883711ULL,
		0x3A5FAB5C45A4D147ULL,
		0x90F9992DDE67A2EAULL,
		0xFDBF5C795D9721A3ULL,
		0x089CCCABCA6AE68DULL,
		0xDA4172E99937E5C7ULL,
		0x9F7456B032270E40ULL,
		0x32DE1827C7465786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x200126C009106E22ULL,
		0x74BF56B88B49A28EULL,
		0x21F3325BBCCF45D4ULL,
		0xFB7EB8F2BB2E4347ULL,
		0x1139995794D5CD1BULL,
		0xB482E5D3326FCB8EULL,
		0x3EE8AD60644E1C81ULL,
		0x65BC304F8E8CAF0DULL
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
		0x1BCBADFE128B9804ULL,
		0x7C46B65A6229C5D0ULL,
		0x264E5B81B78DBC92ULL,
		0x5241C858BA85BEB1ULL,
		0xAC090ABC558BAAC6ULL,
		0x9A51F2BF662058D0ULL,
		0xA8C823F628168EC0ULL,
		0x085A0F486E34BC4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37975BFC25173008ULL,
		0xF88D6CB4C4538BA0ULL,
		0x4C9CB7036F1B7924ULL,
		0xA48390B1750B7D62ULL,
		0x58121578AB17558CULL,
		0x34A3E57ECC40B1A1ULL,
		0x519047EC502D1D81ULL,
		0x10B41E90DC697897ULL
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
		0x3C2D24BA441FD772ULL,
		0x73C843EB862F69D6ULL,
		0x5B3C732AC4846FFAULL,
		0xD21B6CFBF553A1ECULL,
		0x37DBE94E1643058FULL,
		0xC5C0619E69AA98FCULL,
		0x2E533F9FA20FCE58ULL,
		0x3F354671270A0873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785A4974883FAEE4ULL,
		0xE79087D70C5ED3ACULL,
		0xB678E6558908DFF4ULL,
		0xA436D9F7EAA743D8ULL,
		0x6FB7D29C2C860B1FULL,
		0x8B80C33CD35531F8ULL,
		0x5CA67F3F441F9CB1ULL,
		0x7E6A8CE24E1410E6ULL
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
		0x3819F48F9241813DULL,
		0xD0AD8A9C4E0FC3D8ULL,
		0xDC347316058B3197ULL,
		0xE29D73A7043B20E1ULL,
		0xF7C47A96358B907CULL,
		0x6AE3DB12EDB11848ULL,
		0x5A3EF7C83B5BB463ULL,
		0x3F484AA2A7FBD730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7033E91F2483027AULL,
		0xA15B15389C1F87B0ULL,
		0xB868E62C0B16632FULL,
		0xC53AE74E087641C3ULL,
		0xEF88F52C6B1720F9ULL,
		0xD5C7B625DB623091ULL,
		0xB47DEF9076B768C6ULL,
		0x7E9095454FF7AE60ULL
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
		0x3E137F816DC537D5ULL,
		0x5199EC498BE09CA6ULL,
		0x12AB666CB3D71B06ULL,
		0x71EBA7BEEBA2CC32ULL,
		0x2500E07E9A373C5AULL,
		0x741B230AC584DFBAULL,
		0xBEBDCE8BE548BB37ULL,
		0x25B8F78AFA2830B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C26FF02DB8A6FAAULL,
		0xA333D89317C1394CULL,
		0x2556CCD967AE360CULL,
		0xE3D74F7DD7459864ULL,
		0x4A01C0FD346E78B4ULL,
		0xE83646158B09BF74ULL,
		0x7D7B9D17CA91766EULL,
		0x4B71EF15F4506171ULL
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
		0xC14D875637BC1218ULL,
		0x5F15F73BD15DE973ULL,
		0xE64224E6F0DC255DULL,
		0x4EA1C7085F90A45DULL,
		0xE51F444CA7C071C1ULL,
		0x525663B8494947FDULL,
		0x7ECC6CE67CD911D4ULL,
		0x3E3CDD1FD1412CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x829B0EAC6F782430ULL,
		0xBE2BEE77A2BBD2E7ULL,
		0xCC8449CDE1B84ABAULL,
		0x9D438E10BF2148BBULL,
		0xCA3E88994F80E382ULL,
		0xA4ACC77092928FFBULL,
		0xFD98D9CCF9B223A8ULL,
		0x7C79BA3FA2825958ULL
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
		0xFEE4E62131BDFAFDULL,
		0x0D1D10E72BF3F578ULL,
		0x575E945C672FB228ULL,
		0x383CA8F8189A9954ULL,
		0xE9B87EAF1474B75DULL,
		0x632BF09119CD6840ULL,
		0x2E4DD97154918855ULL,
		0x18DEFDD4134BCD3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC9CC42637BF5FAULL,
		0x1A3A21CE57E7EAF1ULL,
		0xAEBD28B8CE5F6450ULL,
		0x707951F0313532A8ULL,
		0xD370FD5E28E96EBAULL,
		0xC657E122339AD081ULL,
		0x5C9BB2E2A92310AAULL,
		0x31BDFBA826979A7EULL
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
		0xD5E73049EEAD0860ULL,
		0xAC5F5450B17B48F2ULL,
		0xFA785D0ABCE452F6ULL,
		0x7ED9301ACEC1737FULL,
		0x88D47DBC3B230A04ULL,
		0x2C14BC3338E73994ULL,
		0xD384147EA989AB4FULL,
		0x36AAC6C76D092907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABCE6093DD5A10C0ULL,
		0x58BEA8A162F691E5ULL,
		0xF4F0BA1579C8A5EDULL,
		0xFDB260359D82E6FFULL,
		0x11A8FB7876461408ULL,
		0x5829786671CE7329ULL,
		0xA70828FD5313569EULL,
		0x6D558D8EDA12520FULL
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
		0xB58E536C40B1FBB1ULL,
		0x296DA0F30D5C8266ULL,
		0xCB63B90FC4EC31E8ULL,
		0xA94835D7F25B4E69ULL,
		0x8D7276985586FEA2ULL,
		0xC0CFEBB24F214C37ULL,
		0xC065C179556A5F92ULL,
		0x334A2CC8EE089DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1CA6D88163F762ULL,
		0x52DB41E61AB904CDULL,
		0x96C7721F89D863D0ULL,
		0x52906BAFE4B69CD3ULL,
		0x1AE4ED30AB0DFD45ULL,
		0x819FD7649E42986FULL,
		0x80CB82F2AAD4BF25ULL,
		0x66945991DC113BADULL
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
		0x375A978EC00DD852ULL,
		0x18B36A55EE5A1997ULL,
		0x6FDA49D472A84A83ULL,
		0x3031DD216786DA31ULL,
		0xBE89B4EE50B0418BULL,
		0x71EB6CE51A238F25ULL,
		0x87B87C20F56CEC96ULL,
		0x06F3D8612E51C78EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB52F1D801BB0A4ULL,
		0x3166D4ABDCB4332EULL,
		0xDFB493A8E5509506ULL,
		0x6063BA42CF0DB462ULL,
		0x7D1369DCA1608316ULL,
		0xE3D6D9CA34471E4BULL,
		0x0F70F841EAD9D92CULL,
		0x0DE7B0C25CA38F1DULL
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
		0x332C9E3F027B2BFAULL,
		0xBFA06C30788993C3ULL,
		0xE828BCC651C162A2ULL,
		0x3F98E9CF4DE354EDULL,
		0xD2021ACCA8B9AE96ULL,
		0x61F57E04FF536CF9ULL,
		0x3F319C3811C985D0ULL,
		0x216159458CC71B97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66593C7E04F657F4ULL,
		0x7F40D860F1132786ULL,
		0xD051798CA382C545ULL,
		0x7F31D39E9BC6A9DBULL,
		0xA404359951735D2CULL,
		0xC3EAFC09FEA6D9F3ULL,
		0x7E63387023930BA0ULL,
		0x42C2B28B198E372EULL
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
		0x2C55049BD58CCF12ULL,
		0x7EE678DD22DF453FULL,
		0x963272C3EC71666FULL,
		0xC00FA6173B74DEEFULL,
		0x6E8BBC309C78B604ULL,
		0x6A4F23E4B0FFF5ADULL,
		0xBDCB92896660EAF1ULL,
		0x3BA8AE74394F3E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58AA0937AB199E24ULL,
		0xFDCCF1BA45BE8A7EULL,
		0x2C64E587D8E2CCDEULL,
		0x801F4C2E76E9BDDFULL,
		0xDD17786138F16C09ULL,
		0xD49E47C961FFEB5AULL,
		0x7B972512CCC1D5E2ULL,
		0x77515CE8729E7D35ULL
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
		0x20E485B3A05B8E9EULL,
		0x9EC3DC9B5D230219ULL,
		0xD1AA1FC6AD955E4FULL,
		0x1238B11459E1C8ECULL,
		0x4F77CD03A410FB13ULL,
		0x4DB05D735E59A292ULL,
		0x3F26A9270D3EA882ULL,
		0x1F454DBC1EE430E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41C90B6740B71D3CULL,
		0x3D87B936BA460432ULL,
		0xA3543F8D5B2ABC9FULL,
		0x24716228B3C391D9ULL,
		0x9EEF9A074821F626ULL,
		0x9B60BAE6BCB34524ULL,
		0x7E4D524E1A7D5104ULL,
		0x3E8A9B783DC861CEULL
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
		0x608A2E19D28595FBULL,
		0x89C949CA363085DEULL,
		0x804F02A59E118ECBULL,
		0x6D384637D120890DULL,
		0xCA1FAC99748F9F4EULL,
		0xB3DB829D2ADA9901ULL,
		0x1776235942E534E9ULL,
		0x1801CFE31D4103C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1145C33A50B2BF6ULL,
		0x139293946C610BBCULL,
		0x009E054B3C231D97ULL,
		0xDA708C6FA241121BULL,
		0x943F5932E91F3E9CULL,
		0x67B7053A55B53203ULL,
		0x2EEC46B285CA69D3ULL,
		0x30039FC63A82078CULL
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
		0x22779B954C79A41AULL,
		0x9DF7D4F456FC245DULL,
		0x551871AEA23B9CD1ULL,
		0xEB3ECD4F262E49E0ULL,
		0x8DE9168983472441ULL,
		0x590E6EEADD5FAD99ULL,
		0xEFF724BB3598C05AULL,
		0x1333609C55C987C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44EF372A98F34834ULL,
		0x3BEFA9E8ADF848BAULL,
		0xAA30E35D447739A3ULL,
		0xD67D9A9E4C5C93C0ULL,
		0x1BD22D13068E4883ULL,
		0xB21CDDD5BABF5B33ULL,
		0xDFEE49766B3180B4ULL,
		0x2666C138AB930F89ULL
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
		0xFF168A75FD2776F1ULL,
		0x4F823DB538B888ECULL,
		0x7C8C61E095DA21B4ULL,
		0xD35085B9048D264DULL,
		0xB10ACD194A66F224ULL,
		0xAF4D6B63867304CDULL,
		0x8C6EC80C5F2A4552ULL,
		0x12CC689DD800A329ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE2D14EBFA4EEDE2ULL,
		0x9F047B6A717111D9ULL,
		0xF918C3C12BB44368ULL,
		0xA6A10B72091A4C9AULL,
		0x62159A3294CDE449ULL,
		0x5E9AD6C70CE6099BULL,
		0x18DD9018BE548AA5ULL,
		0x2598D13BB0014653ULL
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
		0x84E7BFB63DF7B3F8ULL,
		0x9232C8204F875959ULL,
		0x94D3842F3CC934AAULL,
		0x01BE2C5FBE5D2FB9ULL,
		0x3CB4B460DAA35BABULL,
		0x1090EFAF92728B6EULL,
		0x5E0780DCCA2DBE0DULL,
		0x30247C91D88D50ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09CF7F6C7BEF67F0ULL,
		0x246590409F0EB2B3ULL,
		0x29A7085E79926955ULL,
		0x037C58BF7CBA5F73ULL,
		0x796968C1B546B756ULL,
		0x2121DF5F24E516DCULL,
		0xBC0F01B9945B7C1AULL,
		0x6048F923B11AA15AULL
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
		0x0162289C0146A3C2ULL,
		0xD795A8A7B7E97636ULL,
		0xEB056756F20F4B16ULL,
		0xE238693DD038CA04ULL,
		0x84DF22704E06F360ULL,
		0x8A95A455A0B8043EULL,
		0x0B2B7661561CF09EULL,
		0x19205BC58C5E99F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C45138028D4784ULL,
		0xAF2B514F6FD2EC6CULL,
		0xD60ACEADE41E962DULL,
		0xC470D27BA0719409ULL,
		0x09BE44E09C0DE6C1ULL,
		0x152B48AB4170087DULL,
		0x1656ECC2AC39E13DULL,
		0x3240B78B18BD33E6ULL
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
		0x68D08092F0BE4EAEULL,
		0xC72892921A09540FULL,
		0x8C6C279762C7C228ULL,
		0xF3EE0459F35EDAAFULL,
		0x82589C42F6E4464EULL,
		0xC300DB79BD8BA396ULL,
		0xA342A5223012CB8AULL,
		0x30C96CD86CAD22B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A10125E17C9D5CULL,
		0x8E5125243412A81EULL,
		0x18D84F2EC58F8451ULL,
		0xE7DC08B3E6BDB55FULL,
		0x04B13885EDC88C9DULL,
		0x8601B6F37B17472DULL,
		0x46854A4460259715ULL,
		0x6192D9B0D95A4561ULL
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
		0xCB1C39B87F44039CULL,
		0x82B44CE357550BB6ULL,
		0xABDD3698B15BDC6FULL,
		0x5566EAC44F583719ULL,
		0x5B93D21BE9FEB32DULL,
		0xC4084E3CFBD98077ULL,
		0x51584CEAEF2AA49AULL,
		0x2D418BF5148CB9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96387370FE880738ULL,
		0x056899C6AEAA176DULL,
		0x57BA6D3162B7B8DFULL,
		0xAACDD5889EB06E33ULL,
		0xB727A437D3FD665AULL,
		0x88109C79F7B300EEULL,
		0xA2B099D5DE554935ULL,
		0x5A8317EA29197342ULL
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
		0xF4C710483AB1DE40ULL,
		0xF14211880BFE013AULL,
		0x35C3379AADC20663ULL,
		0xF065A266A41E93AEULL,
		0x348D09AAF856E250ULL,
		0x95FBFEFBE31E5E1CULL,
		0x257AA640BBB25E5FULL,
		0x14EBD460DC0DE062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE98E20907563BC80ULL,
		0xE284231017FC0275ULL,
		0x6B866F355B840CC7ULL,
		0xE0CB44CD483D275CULL,
		0x691A1355F0ADC4A1ULL,
		0x2BF7FDF7C63CBC38ULL,
		0x4AF54C817764BCBFULL,
		0x29D7A8C1B81BC0C4ULL
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
		0x1E6A931715B93F0CULL,
		0xF2FCC2AFE45A4CDFULL,
		0xA512ABF2797FFD54ULL,
		0xEA59DDB92C9CCD78ULL,
		0x4872883CB093596CULL,
		0x6A4B069B60BBD77DULL,
		0x5A2790961EAAB267ULL,
		0x3B73C17AB8C6141AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD5262E2B727E18ULL,
		0xE5F9855FC8B499BEULL,
		0x4A2557E4F2FFFAA9ULL,
		0xD4B3BB7259399AF1ULL,
		0x90E510796126B2D9ULL,
		0xD4960D36C177AEFAULL,
		0xB44F212C3D5564CEULL,
		0x76E782F5718C2834ULL
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
		0xDF576BDF83F3556AULL,
		0x9EEBD6D7D770E40EULL,
		0x764905714D69A4D0ULL,
		0xED789AB3929D9FBBULL,
		0x2014692DAE3C9CA5ULL,
		0x35398F81AFE789D6ULL,
		0x12E9476DDD35BEECULL,
		0x0A507500B9A62139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAED7BF07E6AAD4ULL,
		0x3DD7ADAFAEE1C81DULL,
		0xEC920AE29AD349A1ULL,
		0xDAF13567253B3F76ULL,
		0x4028D25B5C79394BULL,
		0x6A731F035FCF13ACULL,
		0x25D28EDBBA6B7DD8ULL,
		0x14A0EA01734C4272ULL
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
		0xB25C8973EA71B7DDULL,
		0x0A7AD0EF9042BD80ULL,
		0xDA7397BA29919F61ULL,
		0xD51885284A7D04FEULL,
		0x36968B9329373892ULL,
		0xFB62AB8BDB8840BBULL,
		0x88D09C3AB5A55560ULL,
		0x3353657AC7E5502AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B912E7D4E36FBAULL,
		0x14F5A1DF20857B01ULL,
		0xB4E72F7453233EC2ULL,
		0xAA310A5094FA09FDULL,
		0x6D2D1726526E7125ULL,
		0xF6C55717B7108176ULL,
		0x11A138756B4AAAC1ULL,
		0x66A6CAF58FCAA055ULL
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
		0x26FA0E4C51D5F218ULL,
		0xC9518E34FE6C52E3ULL,
		0x7332C2890BC93CA3ULL,
		0x0CEDA9C5E70FE31EULL,
		0xE4247F7B89E04F05ULL,
		0xB74B6E7010127453ULL,
		0x7C5569EC54757CB8ULL,
		0x1D536F732282B60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF41C98A3ABE430ULL,
		0x92A31C69FCD8A5C6ULL,
		0xE665851217927947ULL,
		0x19DB538BCE1FC63CULL,
		0xC848FEF713C09E0AULL,
		0x6E96DCE02024E8A7ULL,
		0xF8AAD3D8A8EAF971ULL,
		0x3AA6DEE645056C14ULL
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
		0x649B798699E10016ULL,
		0xCB989D1C125F40B0ULL,
		0x199807823F3BAA4CULL,
		0xDEEEC2D8D3730290ULL,
		0xC8EC3A4481748D49ULL,
		0x253E54B539B4FE1AULL,
		0x98F4420198DD2384ULL,
		0x2316125BF4172FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC936F30D33C2002CULL,
		0x97313A3824BE8160ULL,
		0x33300F047E775499ULL,
		0xBDDD85B1A6E60520ULL,
		0x91D8748902E91A93ULL,
		0x4A7CA96A7369FC35ULL,
		0x31E8840331BA4708ULL,
		0x462C24B7E82E5FEFULL
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
		0x9058EF042919AA5BULL,
		0xAE56B9F992822710ULL,
		0xCAA9CEB6F18DB6A6ULL,
		0xB84BCDA083A363F4ULL,
		0x0BB8FCD7AEC77E38ULL,
		0x60E64701B57A3D65ULL,
		0x3B43D58F06C87FF7ULL,
		0x0B8F13DD3588F2BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B1DE08523354B6ULL,
		0x5CAD73F325044E21ULL,
		0x95539D6DE31B6D4DULL,
		0x70979B410746C7E9ULL,
		0x1771F9AF5D8EFC71ULL,
		0xC1CC8E036AF47ACAULL,
		0x7687AB1E0D90FFEEULL,
		0x171E27BA6B11E57AULL
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
		0x8DBD85FA192237D5ULL,
		0xEE1218F679F7614FULL,
		0x0D884F1F7DB8DAFFULL,
		0x25A790A1FD77B35BULL,
		0x2D38D8CC248754FCULL,
		0xB2B8855BFFF97A8FULL,
		0x7DA8AD498AFBD4EDULL,
		0x2AF554FB20D50BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7B0BF432446FAAULL,
		0xDC2431ECF3EEC29FULL,
		0x1B109E3EFB71B5FFULL,
		0x4B4F2143FAEF66B6ULL,
		0x5A71B198490EA9F8ULL,
		0x65710AB7FFF2F51EULL,
		0xFB515A9315F7A9DBULL,
		0x55EAA9F641AA17C6ULL
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
		0x0019A20242869FB3ULL,
		0xC959C694D3E9ED16ULL,
		0x5BE7CD65FA775405ULL,
		0xE264E916E6334AFAULL,
		0x78CD53CC3644750BULL,
		0xF3C0358A5AAE3ED0ULL,
		0xC1BB2448A02C3F90ULL,
		0x229DBA5AD1EC5408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00334404850D3F66ULL,
		0x92B38D29A7D3DA2CULL,
		0xB7CF9ACBF4EEA80BULL,
		0xC4C9D22DCC6695F4ULL,
		0xF19AA7986C88EA17ULL,
		0xE7806B14B55C7DA0ULL,
		0x8376489140587F21ULL,
		0x453B74B5A3D8A811ULL
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
		0x526B1CB1B6234366ULL,
		0x418091DB14AF8C71ULL,
		0xD524A8AF73E2AF43ULL,
		0x4168368E3A32B490ULL,
		0x46DAF1BC6A79E4B6ULL,
		0x7FF0788BB8147EC2ULL,
		0x206F6EB6483418EEULL,
		0x22C2EF5CE54C771FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D639636C4686CCULL,
		0x830123B6295F18E2ULL,
		0xAA49515EE7C55E86ULL,
		0x82D06D1C74656921ULL,
		0x8DB5E378D4F3C96CULL,
		0xFFE0F1177028FD84ULL,
		0x40DEDD6C906831DCULL,
		0x4585DEB9CA98EE3EULL
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
		0xF36F8809EC7EA880ULL,
		0x194E1347DAB9C442ULL,
		0x8393F44B1EE10B24ULL,
		0xBAF54BCF4ACBB688ULL,
		0xD51F0AFC6ABF05BDULL,
		0xFA07683E3D69E7BCULL,
		0x59AB20850E192A3AULL,
		0x3B1E1EA48E5DBF79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6DF1013D8FD5100ULL,
		0x329C268FB5738885ULL,
		0x0727E8963DC21648ULL,
		0x75EA979E95976D11ULL,
		0xAA3E15F8D57E0B7BULL,
		0xF40ED07C7AD3CF79ULL,
		0xB356410A1C325475ULL,
		0x763C3D491CBB7EF2ULL
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
		0x2DDE0BEC7BB83305ULL,
		0xE47DF42B98D93691ULL,
		0x564E1E08C6FDBDF2ULL,
		0x9B81EDC57E8701DCULL,
		0xF38123C8A7DD8CCCULL,
		0x9DB992063AED7219ULL,
		0x81266ABD19E8B32AULL,
		0x07A1C8110EACA476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBC17D8F770660AULL,
		0xC8FBE85731B26D22ULL,
		0xAC9C3C118DFB7BE5ULL,
		0x3703DB8AFD0E03B8ULL,
		0xE70247914FBB1999ULL,
		0x3B73240C75DAE433ULL,
		0x024CD57A33D16655ULL,
		0x0F4390221D5948EDULL
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
		0x1C0CB312ACD91B72ULL,
		0xD78547A984D0C7DAULL,
		0x54CC1F5E42EC1F8FULL,
		0xE0865F7EAC6F9DBEULL,
		0x6AA89414921F3D08ULL,
		0x3944979C8AF800A7ULL,
		0xA96DD2693C718B54ULL,
		0x34E28E7331A4F723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3819662559B236E4ULL,
		0xAF0A8F5309A18FB4ULL,
		0xA9983EBC85D83F1FULL,
		0xC10CBEFD58DF3B7CULL,
		0xD5512829243E7A11ULL,
		0x72892F3915F0014EULL,
		0x52DBA4D278E316A8ULL,
		0x69C51CE66349EE47ULL
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
		0x9E5FA943F7855EB1ULL,
		0x69AA1615C977A2CEULL,
		0xE7932D7728C94158ULL,
		0xA3A7FBB2DC4E079DULL,
		0xC695C6E46E1D0E1CULL,
		0xC2A2946EBA7FC8F0ULL,
		0x03074EAE65CD5BEEULL,
		0x200E1F66209A47FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CBF5287EF0ABD62ULL,
		0xD3542C2B92EF459DULL,
		0xCF265AEE519282B0ULL,
		0x474FF765B89C0F3BULL,
		0x8D2B8DC8DC3A1C39ULL,
		0x854528DD74FF91E1ULL,
		0x060E9D5CCB9AB7DDULL,
		0x401C3ECC41348FFAULL
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
		0x95CCA7AE7AE670B6ULL,
		0x181E48DC65186880ULL,
		0xA4046141E4F4A0E7ULL,
		0x3C93CBB7A0C4D0CBULL,
		0x080EC471B9DBF242ULL,
		0x5A1D930C6A141DD4ULL,
		0xF695270CD6D19482ULL,
		0x35C8357A77B0AE50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B994F5CF5CCE16CULL,
		0x303C91B8CA30D101ULL,
		0x4808C283C9E941CEULL,
		0x7927976F4189A197ULL,
		0x101D88E373B7E484ULL,
		0xB43B2618D4283BA8ULL,
		0xED2A4E19ADA32904ULL,
		0x6B906AF4EF615CA1ULL
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
		0x05E9FAF287CEAF74ULL,
		0x7EDD1856FA4381E7ULL,
		0x56F48FED048182D3ULL,
		0xF36BF814D25EEB32ULL,
		0x00A929DCDF414D08ULL,
		0xAAECE5B5257E3E4DULL,
		0xC8A89D57F6E11697ULL,
		0x3F00A7534B3029C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD3F5E50F9D5EE8ULL,
		0xFDBA30ADF48703CEULL,
		0xADE91FDA090305A6ULL,
		0xE6D7F029A4BDD664ULL,
		0x015253B9BE829A11ULL,
		0x55D9CB6A4AFC7C9AULL,
		0x91513AAFEDC22D2FULL,
		0x7E014EA696605387ULL
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
		0x07F6B4EE6E632EE2ULL,
		0x34685E2860819497ULL,
		0xF8989917CF98FFDCULL,
		0xD6BF093B96DE2734ULL,
		0x28D1B0CDDD7090CDULL,
		0x865E3BC3588053E4ULL,
		0x8BB93D145540B8D8ULL,
		0x19EBA5A7DFB9B3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FED69DCDCC65DC4ULL,
		0x68D0BC50C103292EULL,
		0xF131322F9F31FFB8ULL,
		0xAD7E12772DBC4E69ULL,
		0x51A3619BBAE1219BULL,
		0x0CBC7786B100A7C8ULL,
		0x17727A28AA8171B1ULL,
		0x33D74B4FBF736775ULL
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
		0x1FAC9323635406C8ULL,
		0x1803197D8659E1DEULL,
		0xFB26228CE4BB9AC1ULL,
		0x9CDBFE4A709C8DFCULL,
		0xE9731AC8BA39E354ULL,
		0x206962155C805394ULL,
		0x0B1855300BA0A7BFULL,
		0x34AFF23A1DE698EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F592646C6A80D90ULL,
		0x300632FB0CB3C3BCULL,
		0xF64C4519C9773582ULL,
		0x39B7FC94E1391BF9ULL,
		0xD2E635917473C6A9ULL,
		0x40D2C42AB900A729ULL,
		0x1630AA6017414F7EULL,
		0x695FE4743BCD31DCULL
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
		0xEB71115B2367B6E7ULL,
		0xA195D4924A9AA8DFULL,
		0x2C2A2C24EE81A881ULL,
		0x15056EEC19AFAD1AULL,
		0x540933C5C2835FE5ULL,
		0xCE19FF507837EA4EULL,
		0xF262BB9C232D7674ULL,
		0x193EA4825C7328D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E222B646CF6DCEULL,
		0x432BA924953551BFULL,
		0x58545849DD035103ULL,
		0x2A0ADDD8335F5A34ULL,
		0xA812678B8506BFCAULL,
		0x9C33FEA0F06FD49CULL,
		0xE4C57738465AECE9ULL,
		0x327D4904B8E651A3ULL
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
		0xD229E3B798754354ULL,
		0x4D2E835C743DEAFEULL,
		0x15F23EF12D0604E1ULL,
		0x1CE3ED71C89269D5ULL,
		0xC5B7532D5ADD5115ULL,
		0xC4CF0D03FAC255AFULL,
		0x59DAE0EAA35F615EULL,
		0x2192F0FC3605BC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA453C76F30EA86A8ULL,
		0x9A5D06B8E87BD5FDULL,
		0x2BE47DE25A0C09C2ULL,
		0x39C7DAE39124D3AAULL,
		0x8B6EA65AB5BAA22AULL,
		0x899E1A07F584AB5FULL,
		0xB3B5C1D546BEC2BDULL,
		0x4325E1F86C0B7824ULL
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
		0x01E27DEE2FBAFB54ULL,
		0x617CD9F3BD16B412ULL,
		0x4EE4DC013A343D5FULL,
		0x64D3252327EB90BBULL,
		0x4FAF245B9D47F35BULL,
		0x234D0E78F0031D67ULL,
		0xCDAED47A4A784C0CULL,
		0x107F5942C1460995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C4FBDC5F75F6A8ULL,
		0xC2F9B3E77A2D6824ULL,
		0x9DC9B80274687ABEULL,
		0xC9A64A464FD72176ULL,
		0x9F5E48B73A8FE6B6ULL,
		0x469A1CF1E0063ACEULL,
		0x9B5DA8F494F09818ULL,
		0x20FEB285828C132BULL
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
		0xEF185577A5ECFEF5ULL,
		0x4C81CC59CB49E8ACULL,
		0xFB5F76F0051ACC61ULL,
		0xA144480F1B98B4EAULL,
		0x63E8257E89E9B05BULL,
		0xB15496259E2EAFB4ULL,
		0xDAD83F5FE1C95135ULL,
		0x349163074DA61565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE30AAEF4BD9FDEAULL,
		0x990398B39693D159ULL,
		0xF6BEEDE00A3598C2ULL,
		0x4288901E373169D5ULL,
		0xC7D04AFD13D360B7ULL,
		0x62A92C4B3C5D5F68ULL,
		0xB5B07EBFC392A26BULL,
		0x6922C60E9B4C2ACBULL
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
		0xA3A1229A9321BEA6ULL,
		0x14EE0F13215B769DULL,
		0xE41D29DC46D86036ULL,
		0xB8CA1AECB492E92FULL,
		0x3AEAA55ECF44B23EULL,
		0xE26E901BE4DD60EDULL,
		0xE70F0A165CA48EFCULL,
		0x199899063378DF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4742453526437D4CULL,
		0x29DC1E2642B6ED3BULL,
		0xC83A53B88DB0C06CULL,
		0x719435D96925D25FULL,
		0x75D54ABD9E89647DULL,
		0xC4DD2037C9BAC1DAULL,
		0xCE1E142CB9491DF9ULL,
		0x3331320C66F1BE09ULL
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
		0x007B2AC2BAAC7686ULL,
		0xF6B3413278D90017ULL,
		0x5E25047723485553ULL,
		0x1889F87BE271C08CULL,
		0x613114B4C14441E1ULL,
		0xC4ECB76109716FC7ULL,
		0x38D9802120B551B5ULL,
		0x0544A235F3D81781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F655857558ED0CULL,
		0xED668264F1B2002EULL,
		0xBC4A08EE4690AAA7ULL,
		0x3113F0F7C4E38118ULL,
		0xC2622969828883C2ULL,
		0x89D96EC212E2DF8EULL,
		0x71B30042416AA36BULL,
		0x0A89446BE7B02F02ULL
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
		0xEFD9D22839F0D213ULL,
		0xAB52ED7E1A538191ULL,
		0x0E75E4EDBF89C80BULL,
		0x3098D5AB8081222DULL,
		0xE381AA84C8D638DFULL,
		0x233E7D65FF570871ULL,
		0x2569858BC974410CULL,
		0x09C50ABEF16B2ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB3A45073E1A426ULL,
		0x56A5DAFC34A70323ULL,
		0x1CEBC9DB7F139017ULL,
		0x6131AB570102445AULL,
		0xC703550991AC71BEULL,
		0x467CFACBFEAE10E3ULL,
		0x4AD30B1792E88218ULL,
		0x138A157DE2D65598ULL
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
		0x5EB8C0CB6948F138ULL,
		0x867A540D23517DC0ULL,
		0x47E5C72EDA26E35EULL,
		0x25701978EF2EB844ULL,
		0x46B04141ACAA1291ULL,
		0x22A31F6BBAFA2576ULL,
		0xCFDBF2E27FEFD122ULL,
		0x27B596F0D2D737DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD718196D291E270ULL,
		0x0CF4A81A46A2FB80ULL,
		0x8FCB8E5DB44DC6BDULL,
		0x4AE032F1DE5D7088ULL,
		0x8D60828359542522ULL,
		0x45463ED775F44AECULL,
		0x9FB7E5C4FFDFA244ULL,
		0x4F6B2DE1A5AE6FB5ULL
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
		0xCFB00F6764CE4816ULL,
		0xC5D86E1556F42970ULL,
		0x445693151D15E79EULL,
		0xBC53460FBA457746ULL,
		0xA22299F2E3945D0CULL,
		0x9D7D424FD9E1473CULL,
		0xC6FA6E8C5D0F8C72ULL,
		0x032A78A99529B254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F601ECEC99C902CULL,
		0x8BB0DC2AADE852E1ULL,
		0x88AD262A3A2BCF3DULL,
		0x78A68C1F748AEE8CULL,
		0x444533E5C728BA19ULL,
		0x3AFA849FB3C28E79ULL,
		0x8DF4DD18BA1F18E5ULL,
		0x0654F1532A5364A9ULL
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
		0x403EC79D6A61FC6DULL,
		0x6200BA3034B1281FULL,
		0xDF38D6AB14211BF7ULL,
		0x584FAD11182544F4ULL,
		0xEB3E2D371F834891ULL,
		0x2495DC937352620FULL,
		0x095EA21239008CF8ULL,
		0x057961E3AD5ED724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807D8F3AD4C3F8DAULL,
		0xC40174606962503EULL,
		0xBE71AD56284237EEULL,
		0xB09F5A22304A89E9ULL,
		0xD67C5A6E3F069122ULL,
		0x492BB926E6A4C41FULL,
		0x12BD4424720119F0ULL,
		0x0AF2C3C75ABDAE48ULL
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
		0x4D2F6DD0060416C2ULL,
		0xAE2D93999CE7F0D3ULL,
		0xC3C881951A66709CULL,
		0xECD5C1FC4FB809AAULL,
		0xA1C9885769FC1BD0ULL,
		0xC1E300A3E5049514ULL,
		0x7F4AFA0EE3B1A1F9ULL,
		0x199BDD078EF09DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5EDBA00C082D84ULL,
		0x5C5B273339CFE1A6ULL,
		0x8791032A34CCE139ULL,
		0xD9AB83F89F701355ULL,
		0x439310AED3F837A1ULL,
		0x83C60147CA092A29ULL,
		0xFE95F41DC76343F3ULL,
		0x3337BA0F1DE13B88ULL
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
		0x0861FA5D0889B9B8ULL,
		0x3F420EBEDD4357D5ULL,
		0x9090A890947B79B9ULL,
		0x395EB6B1C6A6B855ULL,
		0x08761D6E81E96945ULL,
		0xF7FDEF7603954B57ULL,
		0x917173D49FB36FA9ULL,
		0x330056550BFC8743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C3F4BA11137370ULL,
		0x7E841D7DBA86AFAAULL,
		0x2121512128F6F372ULL,
		0x72BD6D638D4D70ABULL,
		0x10EC3ADD03D2D28AULL,
		0xEFFBDEEC072A96AEULL,
		0x22E2E7A93F66DF53ULL,
		0x6600ACAA17F90E87ULL
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
		0x13622C5A01669C2AULL,
		0x0D82312A1E771A29ULL,
		0x00D03D53C9B90853ULL,
		0x4C57066B97CAB8CAULL,
		0xC2F06F3F8996E754ULL,
		0x0B68A4BFA9D022D2ULL,
		0x7E10072D16F23D78ULL,
		0x12BF531CFCEB78D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C458B402CD3854ULL,
		0x1B0462543CEE3452ULL,
		0x01A07AA7937210A6ULL,
		0x98AE0CD72F957194ULL,
		0x85E0DE7F132DCEA8ULL,
		0x16D1497F53A045A5ULL,
		0xFC200E5A2DE47AF0ULL,
		0x257EA639F9D6F1A6ULL
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
		0x6323B73DC40EDDF5ULL,
		0x8DCECF7BBEBAE0C6ULL,
		0x4131CF074BC2FAEEULL,
		0x9C491D7FD4D4C14CULL,
		0x1D06D8513BCD1D10ULL,
		0x35B21159AC4CF0A0ULL,
		0x1D28D8981EAE9881ULL,
		0x2121801618136059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6476E7B881DBBEAULL,
		0x1B9D9EF77D75C18CULL,
		0x82639E0E9785F5DDULL,
		0x38923AFFA9A98298ULL,
		0x3A0DB0A2779A3A21ULL,
		0x6B6422B35899E140ULL,
		0x3A51B1303D5D3102ULL,
		0x4243002C3026C0B2ULL
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
		0x730F06B4C8168767ULL,
		0x481C095E56E2E56AULL,
		0x013195D7E4ABAE76ULL,
		0x22E8B6A46B0FB4C8ULL,
		0x16907F87B05D14FFULL,
		0x0E6A3FBE668548B0ULL,
		0x30EA5FB212031005ULL,
		0x21E9C427BC7CC4C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61E0D69902D0ECEULL,
		0x903812BCADC5CAD4ULL,
		0x02632BAFC9575CECULL,
		0x45D16D48D61F6990ULL,
		0x2D20FF0F60BA29FEULL,
		0x1CD47F7CCD0A9160ULL,
		0x61D4BF642406200AULL,
		0x43D3884F78F9898EULL
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
		0x947D7AA32F6ED012ULL,
		0x700A43ED6A06FD79ULL,
		0xC57D0B12871229C4ULL,
		0xEF11922C6BA64477ULL,
		0x157177030DF52B80ULL,
		0x88B19B5941491B46ULL,
		0x14738AD8888F9E40ULL,
		0x0F18A3939F91A334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FAF5465EDDA024ULL,
		0xE01487DAD40DFAF3ULL,
		0x8AFA16250E245388ULL,
		0xDE232458D74C88EFULL,
		0x2AE2EE061BEA5701ULL,
		0x116336B28292368CULL,
		0x28E715B1111F3C81ULL,
		0x1E3147273F234668ULL
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
		0x0E9E149C23521DD9ULL,
		0x2BAFC8B0E61DF98DULL,
		0x9B1977A60149872CULL,
		0x390595C43DEDEF21ULL,
		0x964E5A3A1D1219D8ULL,
		0x0FE10FF7E451895BULL,
		0x83ACF611DBE8C448ULL,
		0x2782298463163FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D3C293846A43BB2ULL,
		0x575F9161CC3BF31AULL,
		0x3632EF4C02930E58ULL,
		0x720B2B887BDBDE43ULL,
		0x2C9CB4743A2433B0ULL,
		0x1FC21FEFC8A312B7ULL,
		0x0759EC23B7D18890ULL,
		0x4F045308C62C7FF5ULL
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
		0xE72B895208162B93ULL,
		0x6B29E1C142673AB9ULL,
		0x3EB1890C1A85DC5DULL,
		0xD5892E04F84F2E3BULL,
		0x4DE05F440236644CULL,
		0x3EAC7A493FC18FE2ULL,
		0x0696CE149EC17193ULL,
		0x3D0C6502CB647118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE5712A4102C5726ULL,
		0xD653C38284CE7573ULL,
		0x7D631218350BB8BAULL,
		0xAB125C09F09E5C76ULL,
		0x9BC0BE88046CC899ULL,
		0x7D58F4927F831FC4ULL,
		0x0D2D9C293D82E326ULL,
		0x7A18CA0596C8E230ULL
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
		0x90E62B9A6545E093ULL,
		0x819B44822D7AF8BAULL,
		0x6FAACFEDCCCB0702ULL,
		0x26431020858E4F52ULL,
		0x9357279FDDA3D7D0ULL,
		0x66F95BD45E03096FULL,
		0x5EF6FF5CF48F2452ULL,
		0x2B50E2E174FCF62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21CC5734CA8BC126ULL,
		0x033689045AF5F175ULL,
		0xDF559FDB99960E05ULL,
		0x4C8620410B1C9EA4ULL,
		0x26AE4F3FBB47AFA0ULL,
		0xCDF2B7A8BC0612DFULL,
		0xBDEDFEB9E91E48A4ULL,
		0x56A1C5C2E9F9EC5AULL
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
		0x7B45650DECABB965ULL,
		0x9A5997B7A4DA511AULL,
		0x395DAA0340741987ULL,
		0x6E45262B3B2193CEULL,
		0x272B0AA06689B47FULL,
		0xC61B97382B80186CULL,
		0xFADE5E6863D1FB3CULL,
		0x1EA4EB44A9F1D0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF68ACA1BD95772CAULL,
		0x34B32F6F49B4A234ULL,
		0x72BB540680E8330FULL,
		0xDC8A4C567643279CULL,
		0x4E561540CD1368FEULL,
		0x8C372E70570030D8ULL,
		0xF5BCBCD0C7A3F679ULL,
		0x3D49D68953E3A177ULL
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
		0x7EBF56603200FAE8ULL,
		0xECF1330F3F8C709CULL,
		0x400141EBDBF3BD9CULL,
		0x3798FA26387EF33BULL,
		0xF467E0142A611257ULL,
		0xEE7AFF95D45C4BCCULL,
		0x6D4B5237A19D6E14ULL,
		0x08EC9FE02E507AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7EACC06401F5D0ULL,
		0xD9E2661E7F18E138ULL,
		0x800283D7B7E77B39ULL,
		0x6F31F44C70FDE676ULL,
		0xE8CFC02854C224AEULL,
		0xDCF5FF2BA8B89799ULL,
		0xDA96A46F433ADC29ULL,
		0x11D93FC05CA0F56AULL
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
		0xE5AAAA17900B9766ULL,
		0xFAE072D2C794A57CULL,
		0x544BE05B3A3CA956ULL,
		0x96317A705BA044CDULL,
		0x1A55A2B7CF836733ULL,
		0xBB8723C35E1EAB21ULL,
		0x91436921A8EA68D8ULL,
		0x233BAF46B7A4C01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB55542F20172ECCULL,
		0xF5C0E5A58F294AF9ULL,
		0xA897C0B6747952ADULL,
		0x2C62F4E0B740899AULL,
		0x34AB456F9F06CE67ULL,
		0x770E4786BC3D5642ULL,
		0x2286D24351D4D1B1ULL,
		0x46775E8D6F49803FULL
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
		0x2FD5B7777BF041A7ULL,
		0xB299ECC6AD962C18ULL,
		0xE24087FB337389C5ULL,
		0x72CC16CC1D9DC253ULL,
		0xF7F6F743B1C5EB61ULL,
		0xDD48591DE37B2AC8ULL,
		0xA2C7B96933538E28ULL,
		0x1906D75FA034D611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FAB6EEEF7E0834EULL,
		0x6533D98D5B2C5830ULL,
		0xC4810FF666E7138BULL,
		0xE5982D983B3B84A7ULL,
		0xEFEDEE87638BD6C2ULL,
		0xBA90B23BC6F65591ULL,
		0x458F72D266A71C51ULL,
		0x320DAEBF4069AC23ULL
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
		0x06D58AC26E8BEA15ULL,
		0xA18575D1E4755964ULL,
		0xEC4F53E7F4787E3DULL,
		0x695F17BD0B2A7C85ULL,
		0xD12F8E61F12AA5BBULL,
		0xBD8439C999924DC1ULL,
		0xFF98C7DC24A83FB0ULL,
		0x33E574BD03CCDBE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DAB1584DD17D42AULL,
		0x430AEBA3C8EAB2C8ULL,
		0xD89EA7CFE8F0FC7BULL,
		0xD2BE2F7A1654F90BULL,
		0xA25F1CC3E2554B76ULL,
		0x7B08739333249B83ULL,
		0xFF318FB849507F61ULL,
		0x67CAE97A0799B7CBULL
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
		0xFA7E3F6DB569A6EDULL,
		0x8A624B501C7CD092ULL,
		0xE6C95D2824603BD9ULL,
		0x1E10FD2E07C0F855ULL,
		0xCFE7F3989D66D8A5ULL,
		0x682487E22990CEC4ULL,
		0x8B1DBFF2FFCAC150ULL,
		0x235C9C0F93D61E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4FC7EDB6AD34DDAULL,
		0x14C496A038F9A125ULL,
		0xCD92BA5048C077B3ULL,
		0x3C21FA5C0F81F0ABULL,
		0x9FCFE7313ACDB14AULL,
		0xD0490FC453219D89ULL,
		0x163B7FE5FF9582A0ULL,
		0x46B9381F27AC3CF7ULL
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
		0x92D0F070C2C3AA15ULL,
		0xE0E4FD82D7ED9E4FULL,
		0xDBC47B136E53BDB3ULL,
		0x0A13C09404F43DE5ULL,
		0x20F559637BDEADFAULL,
		0x11E0B0D552136533ULL,
		0x8E0E1FE41EF76ABBULL,
		0x1EA74247FFC9ED3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A1E0E18587542AULL,
		0xC1C9FB05AFDB3C9FULL,
		0xB788F626DCA77B67ULL,
		0x1427812809E87BCBULL,
		0x41EAB2C6F7BD5BF4ULL,
		0x23C161AAA426CA66ULL,
		0x1C1C3FC83DEED576ULL,
		0x3D4E848FFF93DA79ULL
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
		0x431A1EA9D50B2FD3ULL,
		0x5AB4EDD69F9366CEULL,
		0x9AD0646F19008279ULL,
		0xF724147E851D117CULL,
		0xE2EA3530016ED18AULL,
		0x9C0BF963732E5BC8ULL,
		0xB2B844B83C00BAD4ULL,
		0x0C77052DF59D47B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86343D53AA165FA6ULL,
		0xB569DBAD3F26CD9CULL,
		0x35A0C8DE320104F2ULL,
		0xEE4828FD0A3A22F9ULL,
		0xC5D46A6002DDA315ULL,
		0x3817F2C6E65CB791ULL,
		0x65708970780175A9ULL,
		0x18EE0A5BEB3A8F6DULL
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
		0x3B81F19813423D70ULL,
		0xDC54DA887BE8C549ULL,
		0x08F629DB22DF8905ULL,
		0x548EC2F06F276A98ULL,
		0x5FB5C7491CCB8B25ULL,
		0x4735D905CFA46A18ULL,
		0x2A402E4512DF9681ULL,
		0x0BE6B25068D038BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7703E33026847AE0ULL,
		0xB8A9B510F7D18A92ULL,
		0x11EC53B645BF120BULL,
		0xA91D85E0DE4ED530ULL,
		0xBF6B8E923997164AULL,
		0x8E6BB20B9F48D430ULL,
		0x54805C8A25BF2D02ULL,
		0x17CD64A0D1A07178ULL
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
		0x0E3E96CB02FB0966ULL,
		0x16DE965D934B4891ULL,
		0xBCB2187D2FC40AF8ULL,
		0xA1C891C9E15D9FEAULL,
		0x3EFF7F4C8D726ACFULL,
		0x77CCEAF2B6244F64ULL,
		0x9992831ED8ABE891ULL,
		0x0ACE72024C1922A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C7D2D9605F612CCULL,
		0x2DBD2CBB26969122ULL,
		0x796430FA5F8815F0ULL,
		0x43912393C2BB3FD5ULL,
		0x7DFEFE991AE4D59FULL,
		0xEF99D5E56C489EC8ULL,
		0x3325063DB157D122ULL,
		0x159CE4049832454FULL
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
		0x5114BF22FEC7BC3BULL,
		0xF364A315774BE647ULL,
		0xEFC23833B2962E9EULL,
		0xFBC9FB76C9F691DCULL,
		0x4527672A866CE0E9ULL,
		0xAF874C112EBFFA7AULL,
		0x2AFB0D53F765CC15ULL,
		0x345F41B2CFDA47B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2297E45FD8F7876ULL,
		0xE6C9462AEE97CC8EULL,
		0xDF847067652C5D3DULL,
		0xF793F6ED93ED23B9ULL,
		0x8A4ECE550CD9C1D3ULL,
		0x5F0E98225D7FF4F4ULL,
		0x55F61AA7EECB982BULL,
		0x68BE83659FB48F62ULL
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
		0x82B7E119D30BC29AULL,
		0x8BF8F7A72DEE8633ULL,
		0xCD3C7E02585F365FULL,
		0x3E477FFB4B26F6F8ULL,
		0xEE9EE25E4913E6E8ULL,
		0x99FDF01BA6B8FC50ULL,
		0xDDE4B110E05F28E1ULL,
		0x1D634DA5053D5B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056FC233A6178534ULL,
		0x17F1EF4E5BDD0C67ULL,
		0x9A78FC04B0BE6CBFULL,
		0x7C8EFFF6964DEDF1ULL,
		0xDD3DC4BC9227CDD0ULL,
		0x33FBE0374D71F8A1ULL,
		0xBBC96221C0BE51C3ULL,
		0x3AC69B4A0A7AB621ULL
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
		0xF7D40FF579C72662ULL,
		0x7FCE4062DBB52DBEULL,
		0x02712168A73B7AC1ULL,
		0x3783C95CED98FB1DULL,
		0x8D272BDBD747B525ULL,
		0x3F0D92DCEE7F8666ULL,
		0x492BB0E6B2D4E23EULL,
		0x1B7A3589013EC162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA81FEAF38E4CC4ULL,
		0xFF9C80C5B76A5B7DULL,
		0x04E242D14E76F582ULL,
		0x6F0792B9DB31F63AULL,
		0x1A4E57B7AE8F6A4AULL,
		0x7E1B25B9DCFF0CCDULL,
		0x925761CD65A9C47CULL,
		0x36F46B12027D82C4ULL
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
		0xFBF629E62A0214F5ULL,
		0x239FD30AE0383A93ULL,
		0x5DAE56F1DE2F7925ULL,
		0xE159B23BFF70D7EAULL,
		0x3C0D22AA88F7E4E7ULL,
		0xDDEC0C228FB7B8E9ULL,
		0xAD503315DF632CE8ULL,
		0x321D5DC11E538FCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EC53CC540429EAULL,
		0x473FA615C0707527ULL,
		0xBB5CADE3BC5EF24AULL,
		0xC2B36477FEE1AFD4ULL,
		0x781A455511EFC9CFULL,
		0xBBD818451F6F71D2ULL,
		0x5AA0662BBEC659D1ULL,
		0x643ABB823CA71F9BULL
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
		0x65D5B89061535BB4ULL,
		0x7BDAD62310910DD5ULL,
		0x87FB5E8932A79E4AULL,
		0x460F0057A2480A95ULL,
		0xA741819A9A5EE81CULL,
		0x5B0EBC73D9E41665ULL,
		0xBAB7C44D3FE3FC0BULL,
		0x2AC3CB28358A3182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBAB7120C2A6B768ULL,
		0xF7B5AC4621221BAAULL,
		0x0FF6BD12654F3C94ULL,
		0x8C1E00AF4490152BULL,
		0x4E83033534BDD038ULL,
		0xB61D78E7B3C82CCBULL,
		0x756F889A7FC7F816ULL,
		0x558796506B146305ULL
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
		0xF611DE8347F95602ULL,
		0x0E3E08D2C499B96EULL,
		0x1D5A41EE9D92E022ULL,
		0xDE9972CB3B514EC3ULL,
		0x21A83FB9AEF424FFULL,
		0x722D7503B8876F4BULL,
		0x5678CD21AE2F6871ULL,
		0x1BEEA784CD01BC00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC23BD068FF2AC04ULL,
		0x1C7C11A5893372DDULL,
		0x3AB483DD3B25C044ULL,
		0xBD32E59676A29D86ULL,
		0x43507F735DE849FFULL,
		0xE45AEA07710EDE96ULL,
		0xACF19A435C5ED0E2ULL,
		0x37DD4F099A037800ULL
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
		0x4222FD835537DD4FULL,
		0x71B8422ED8DCA7BDULL,
		0x7E2F1EA6512D665FULL,
		0xE76E7D18E275927EULL,
		0xBF21DF4C0BB0881CULL,
		0x26111505897FFFA6ULL,
		0xE44C64224AAAE6D5ULL,
		0x2B718BC44A2767BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8445FB06AA6FBA9EULL,
		0xE370845DB1B94F7AULL,
		0xFC5E3D4CA25ACCBEULL,
		0xCEDCFA31C4EB24FCULL,
		0x7E43BE9817611039ULL,
		0x4C222A0B12FFFF4DULL,
		0xC898C8449555CDAAULL,
		0x56E31788944ECF77ULL
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
		0x43ED8A3F552A10B6ULL,
		0x05F4C31F643F89D7ULL,
		0xF6221C679881C38AULL,
		0x7662C4A4D4E526BEULL,
		0xCE717CE8156B534AULL,
		0x4E71FD9284C90D4AULL,
		0xACB8457FF195DC25ULL,
		0x034E64B1582FCDEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DB147EAA54216CULL,
		0x0BE9863EC87F13AEULL,
		0xEC4438CF31038714ULL,
		0xECC58949A9CA4D7DULL,
		0x9CE2F9D02AD6A694ULL,
		0x9CE3FB2509921A95ULL,
		0x59708AFFE32BB84AULL,
		0x069CC962B05F9BD5ULL
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
		0x3BA4EE2718C0A9A1ULL,
		0xE5AE7708A0E4DC13ULL,
		0x1665B1286A327B6AULL,
		0x8A53A376946DC3E1ULL,
		0xF5D4C591FA219740ULL,
		0x890F583FB4FF38FFULL,
		0x7E6BA315EC8D7274ULL,
		0x1FA2B58F5E63CEC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7749DC4E31815342ULL,
		0xCB5CEE1141C9B826ULL,
		0x2CCB6250D464F6D5ULL,
		0x14A746ED28DB87C2ULL,
		0xEBA98B23F4432E81ULL,
		0x121EB07F69FE71FFULL,
		0xFCD7462BD91AE4E9ULL,
		0x3F456B1EBCC79D86ULL
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
		0x714FE22856C942A5ULL,
		0xF6F53E3D2D0318AFULL,
		0x1E76CC3D89761CCDULL,
		0x513AB4E2E8B8E258ULL,
		0x9332077A9CC5F6E1ULL,
		0x80542DCB7AF8A59AULL,
		0xC3ACFE409C916477ULL,
		0x2D6780561190566CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE29FC450AD92854AULL,
		0xEDEA7C7A5A06315EULL,
		0x3CED987B12EC399BULL,
		0xA27569C5D171C4B0ULL,
		0x26640EF5398BEDC2ULL,
		0x00A85B96F5F14B35ULL,
		0x8759FC813922C8EFULL,
		0x5ACF00AC2320ACD9ULL
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
		0xF62D667997CE6CC5ULL,
		0xEB2CD4F725706CCDULL,
		0x798C1C2F690C9490ULL,
		0x3A916E61FBCAD296ULL,
		0xD1981716E3A9F7ABULL,
		0x1DA8D3B1E05029EFULL,
		0x9E8198B1D7F2B369ULL,
		0x2DB36094EEB57293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC5ACCF32F9CD98AULL,
		0xD659A9EE4AE0D99BULL,
		0xF318385ED2192921ULL,
		0x7522DCC3F795A52CULL,
		0xA3302E2DC753EF56ULL,
		0x3B51A763C0A053DFULL,
		0x3D033163AFE566D2ULL,
		0x5B66C129DD6AE527ULL
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
		0x20CB7D44ACA844DAULL,
		0xB53A580FA5608661ULL,
		0xEEF3DE6727405B39ULL,
		0x05064E292AF8E1E8ULL,
		0xA82C9F366D9BF89DULL,
		0x277B3C8B8DC598DEULL,
		0x9568FE50558A46A6ULL,
		0x362180986109FA5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4196FA89595089B4ULL,
		0x6A74B01F4AC10CC2ULL,
		0xDDE7BCCE4E80B673ULL,
		0x0A0C9C5255F1C3D1ULL,
		0x50593E6CDB37F13AULL,
		0x4EF679171B8B31BDULL,
		0x2AD1FCA0AB148D4CULL,
		0x6C430130C213F4B5ULL
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
		0x83E16242F139DA5AULL,
		0x45BB90EEF16B2D4FULL,
		0xAF3899D497620435ULL,
		0xD4138B7A8975A142ULL,
		0xCF687EB12C0A0275ULL,
		0x94067796FBD7B7FAULL,
		0x332BED90FA512CB1ULL,
		0x1D18215AF809C4B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C2C485E273B4B4ULL,
		0x8B7721DDE2D65A9FULL,
		0x5E7133A92EC4086AULL,
		0xA82716F512EB4285ULL,
		0x9ED0FD62581404EBULL,
		0x280CEF2DF7AF6FF5ULL,
		0x6657DB21F4A25963ULL,
		0x3A3042B5F0138970ULL
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
		0x4103C277E86DF09FULL,
		0xB19D2AECB3F47DA5ULL,
		0xD7AE01AE49C5DFAFULL,
		0x3908EE1B3AB66DA1ULL,
		0x6DB5D50FDAEAAB60ULL,
		0xE44260A9EF4CC350ULL,
		0x547E75F4BBB902A9ULL,
		0x08F3F5EDEF6AE4D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820784EFD0DBE13EULL,
		0x633A55D967E8FB4AULL,
		0xAF5C035C938BBF5FULL,
		0x7211DC36756CDB43ULL,
		0xDB6BAA1FB5D556C0ULL,
		0xC884C153DE9986A0ULL,
		0xA8FCEBE977720553ULL,
		0x11E7EBDBDED5C9A8ULL
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
		0x0C4E9D17FF9BD66CULL,
		0x6583C22AB4CCE2E2ULL,
		0x82754C84397E3995ULL,
		0x05E2CF3D68F4AA1EULL,
		0x3A61A01DE9BBC016ULL,
		0xEAA637383EF36B31ULL,
		0x8C47CFA9C1058A88ULL,
		0x2E4E36B5DD83DB19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189D3A2FFF37ACD8ULL,
		0xCB0784556999C5C4ULL,
		0x04EA990872FC732AULL,
		0x0BC59E7AD1E9543DULL,
		0x74C3403BD377802CULL,
		0xD54C6E707DE6D662ULL,
		0x188F9F53820B1511ULL,
		0x5C9C6D6BBB07B633ULL
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
		0xDA3330D294EE57F1ULL,
		0xF795A53DA2CB81E9ULL,
		0x91E051386D47FBD3ULL,
		0x47D1656455920B51ULL,
		0xB5E03B442192FF55ULL,
		0x3C6733797AC2EC3EULL,
		0x12946C691D12E93FULL,
		0x0394E4775E65163CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46661A529DCAFE2ULL,
		0xEF2B4A7B459703D3ULL,
		0x23C0A270DA8FF7A7ULL,
		0x8FA2CAC8AB2416A3ULL,
		0x6BC076884325FEAAULL,
		0x78CE66F2F585D87DULL,
		0x2528D8D23A25D27EULL,
		0x0729C8EEBCCA2C78ULL
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
		0x78A5E6B464D0CB7BULL,
		0x031B9361D7E41558ULL,
		0xE47357406B455220ULL,
		0xB235973E3D0EA81DULL,
		0xFB820C493F90FE22ULL,
		0xD6F9F8A276635E38ULL,
		0x143F163D129DDE1DULL,
		0x3980B68F0482C0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14BCD68C9A196F6ULL,
		0x063726C3AFC82AB0ULL,
		0xC8E6AE80D68AA440ULL,
		0x646B2E7C7A1D503BULL,
		0xF70418927F21FC45ULL,
		0xADF3F144ECC6BC71ULL,
		0x287E2C7A253BBC3BULL,
		0x73016D1E09058142ULL
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
		0x0214EB6B26C16CA7ULL,
		0x2ACC2BED6EB67DB2ULL,
		0x61661AC3BBCE120AULL,
		0x8A03E97A1FB90858ULL,
		0x7628551177CF6D5FULL,
		0x2A9E3F514AE843F6ULL,
		0x180D657001CA5D18ULL,
		0x23A35E506A9FF7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0429D6D64D82D94EULL,
		0x559857DADD6CFB64ULL,
		0xC2CC3587779C2414ULL,
		0x1407D2F43F7210B0ULL,
		0xEC50AA22EF9EDABFULL,
		0x553C7EA295D087ECULL,
		0x301ACAE00394BA30ULL,
		0x4746BCA0D53FEF9AULL
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
		0xB20AABFD6E75C810ULL,
		0x698DBD2EFB4CF9F1ULL,
		0x71CCECA928C93F9EULL,
		0x615DE00031AAC1BBULL,
		0x92363A61B106570BULL,
		0x14676A4A5B3224D9ULL,
		0xF015921625E2C22BULL,
		0x09147065F20B2735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x641557FADCEB9020ULL,
		0xD31B7A5DF699F3E3ULL,
		0xE399D95251927F3CULL,
		0xC2BBC00063558376ULL,
		0x246C74C3620CAE16ULL,
		0x28CED494B66449B3ULL,
		0xE02B242C4BC58456ULL,
		0x1228E0CBE4164E6BULL
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
		0x391119B403F3301CULL,
		0xAD192B4CB8848050ULL,
		0x44BE255953332B70ULL,
		0x2BDD16499AF3B0E0ULL,
		0x960E4E396AE6FEB4ULL,
		0x59F7A12A1109133DULL,
		0x1451D3CE32B65A1CULL,
		0x1F38BCBA0F45632AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7222336807E66038ULL,
		0x5A325699710900A0ULL,
		0x897C4AB2A66656E1ULL,
		0x57BA2C9335E761C0ULL,
		0x2C1C9C72D5CDFD68ULL,
		0xB3EF42542212267BULL,
		0x28A3A79C656CB438ULL,
		0x3E7179741E8AC654ULL
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
		0xBFB233D9818E9618ULL,
		0x5785C7A14C559B28ULL,
		0x48944AC415BFC917ULL,
		0x7B2DF08154C8A656ULL,
		0xD6C0FC39B2F2D4C3ULL,
		0x5B5F35EDBCEC321CULL,
		0xDC21A9CDB501DA2AULL,
		0x1C2E144795123B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6467B3031D2C30ULL,
		0xAF0B8F4298AB3651ULL,
		0x912895882B7F922EULL,
		0xF65BE102A9914CACULL,
		0xAD81F87365E5A986ULL,
		0xB6BE6BDB79D86439ULL,
		0xB843539B6A03B454ULL,
		0x385C288F2A24769DULL
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
		0xC6A020D1DDC0726AULL,
		0xCCEC9154B331A4D3ULL,
		0xFEF3969A5EB2E632ULL,
		0xC4ADC897A1175A9DULL,
		0x3541D78E32588B49ULL,
		0xC739F2BC2713ECB5ULL,
		0x27220A6E71E198C8ULL,
		0x0451D0E8BB3E402AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D4041A3BB80E4D4ULL,
		0x99D922A9666349A7ULL,
		0xFDE72D34BD65CC65ULL,
		0x895B912F422EB53BULL,
		0x6A83AF1C64B11693ULL,
		0x8E73E5784E27D96AULL,
		0x4E4414DCE3C33191ULL,
		0x08A3A1D1767C8054ULL
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
		0xCB3CDFBD52649B40ULL,
		0xB00333CFC830AA21ULL,
		0x5FA7E15FB0007EF4ULL,
		0xE5CA830583D76CE0ULL,
		0xFD69213A4067CBA9ULL,
		0xC87C63FC5BDEFD67ULL,
		0x09AD3956A06901A3ULL,
		0x0211402F8FCD12A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9679BF7AA4C93680ULL,
		0x6006679F90615443ULL,
		0xBF4FC2BF6000FDE9ULL,
		0xCB95060B07AED9C0ULL,
		0xFAD2427480CF9753ULL,
		0x90F8C7F8B7BDFACFULL,
		0x135A72AD40D20347ULL,
		0x0422805F1F9A2540ULL
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
		0x431B236084E2C244ULL,
		0xB9D708ED33D7B36CULL,
		0xC14565C2EBB55BF3ULL,
		0x816F1AB3945557AAULL,
		0x8EC0DADF9ED412D4ULL,
		0x8EEF2037C87CB1E9ULL,
		0x5BEBFEF936E03567ULL,
		0x275C998F26DB4855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863646C109C58488ULL,
		0x73AE11DA67AF66D8ULL,
		0x828ACB85D76AB7E7ULL,
		0x02DE356728AAAF55ULL,
		0x1D81B5BF3DA825A9ULL,
		0x1DDE406F90F963D3ULL,
		0xB7D7FDF26DC06ACFULL,
		0x4EB9331E4DB690AAULL
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
		0x6A2D046A32F472EDULL,
		0x0E3ED417FA866B70ULL,
		0xDB0DA49743F9C501ULL,
		0xC88FCDCD6037ACBEULL,
		0x871BD423EB862D7CULL,
		0xBC016B4366276E5EULL,
		0x31F7C9233C4565A5ULL,
		0x2E75E551FDFE2E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45A08D465E8E5DAULL,
		0x1C7DA82FF50CD6E0ULL,
		0xB61B492E87F38A02ULL,
		0x911F9B9AC06F597DULL,
		0x0E37A847D70C5AF9ULL,
		0x7802D686CC4EDCBDULL,
		0x63EF9246788ACB4BULL,
		0x5CEBCAA3FBFC5C3CULL
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
		0x81ADB3E05B07BE47ULL,
		0x1034BAB4DAA43A35ULL,
		0xD55C90A16DF91727ULL,
		0xA495F2F270A0C59DULL,
		0xFB5B150A610E7177ULL,
		0x6F261EC3E269D608ULL,
		0x2286902FF119EAD0ULL,
		0x1CEE893B47F71142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x035B67C0B60F7C8EULL,
		0x20697569B548746BULL,
		0xAAB92142DBF22E4EULL,
		0x492BE5E4E1418B3BULL,
		0xF6B62A14C21CE2EFULL,
		0xDE4C3D87C4D3AC11ULL,
		0x450D205FE233D5A0ULL,
		0x39DD12768FEE2284ULL
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
		0x807722808C6C4A05ULL,
		0x706FB1796B222E2CULL,
		0x157E25AE7475AF17ULL,
		0x095C09F455ADCD20ULL,
		0x282460F11FADC265ULL,
		0xDDB26BC2BD27E3B9ULL,
		0x5C1E351E7C6DD0C4ULL,
		0x202B50D1D1899774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00EE450118D8940AULL,
		0xE0DF62F2D6445C59ULL,
		0x2AFC4B5CE8EB5E2EULL,
		0x12B813E8AB5B9A40ULL,
		0x5048C1E23F5B84CAULL,
		0xBB64D7857A4FC772ULL,
		0xB83C6A3CF8DBA189ULL,
		0x4056A1A3A3132EE8ULL
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
		0x83B84744A5B5E132ULL,
		0xEA282070F99E3B53ULL,
		0xA3CC2CF6B2D4C09BULL,
		0x8966CDA7CA8D3552ULL,
		0x09A570A5B141330BULL,
		0x95C23B7BFFA14889ULL,
		0x89517E3E70F72C8EULL,
		0x107399477721F132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07708E894B6BC264ULL,
		0xD45040E1F33C76A7ULL,
		0x479859ED65A98137ULL,
		0x12CD9B4F951A6AA5ULL,
		0x134AE14B62826617ULL,
		0x2B8476F7FF429112ULL,
		0x12A2FC7CE1EE591DULL,
		0x20E7328EEE43E265ULL
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
		0x8B56FD297EE73043ULL,
		0x3BE5A4221D348633ULL,
		0xEC8DEFAA95ED25F5ULL,
		0x24B437F2EF83D53BULL,
		0xA189DBBF09816A15ULL,
		0x3B6204580559A3EFULL,
		0x6CF34EB84380D255ULL,
		0x008DA7FA001D1DF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16ADFA52FDCE6086ULL,
		0x77CB48443A690C67ULL,
		0xD91BDF552BDA4BEAULL,
		0x49686FE5DF07AA77ULL,
		0x4313B77E1302D42AULL,
		0x76C408B00AB347DFULL,
		0xD9E69D708701A4AAULL,
		0x011B4FF4003A3BEAULL
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
		0xC57DE8307A55EF8AULL,
		0x6935DD830E2447C3ULL,
		0xE2AFCBBA6D2F0F76ULL,
		0x1493B341115EBB9BULL,
		0xA9FCC945EFB59798ULL,
		0xA1725E8985967E63ULL,
		0xFD612175A6E5CF63ULL,
		0x0548A201BBEB8681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFBD060F4ABDF14ULL,
		0xD26BBB061C488F87ULL,
		0xC55F9774DA5E1EECULL,
		0x2927668222BD7737ULL,
		0x53F9928BDF6B2F30ULL,
		0x42E4BD130B2CFCC7ULL,
		0xFAC242EB4DCB9EC7ULL,
		0x0A91440377D70D03ULL
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
		0xB4EC6EE178AF5689ULL,
		0x3283435FD7E2DA20ULL,
		0x21681F6975D515DDULL,
		0x3416D853C6487C9CULL,
		0x845EADE4C374040EULL,
		0x0E8DB8D506E8F8CCULL,
		0xCD4320205E332D9EULL,
		0x1E0E5101F2F99395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D8DDC2F15EAD12ULL,
		0x650686BFAFC5B441ULL,
		0x42D03ED2EBAA2BBAULL,
		0x682DB0A78C90F938ULL,
		0x08BD5BC986E8081CULL,
		0x1D1B71AA0DD1F199ULL,
		0x9A864040BC665B3CULL,
		0x3C1CA203E5F3272BULL
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
		0x7344935CB5C8DFF7ULL,
		0x4BD3704FD128E941ULL,
		0xADF8987A0D91626EULL,
		0x54FB976E8BFBD15EULL,
		0x6A6562FCC9BB3F2CULL,
		0xFB5257898F95F347ULL,
		0xF17D6668A9906D4EULL,
		0x2BBAFE3D84CCA6DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE68926B96B91BFEEULL,
		0x97A6E09FA251D282ULL,
		0x5BF130F41B22C4DCULL,
		0xA9F72EDD17F7A2BDULL,
		0xD4CAC5F993767E58ULL,
		0xF6A4AF131F2BE68EULL,
		0xE2FACCD15320DA9DULL,
		0x5775FC7B09994DB9ULL
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
		0x2A5E4C4ABB2A6631ULL,
		0x8070555D0FF9A12CULL,
		0x86BF49170DCF7630ULL,
		0x2D884C0FF52377B3ULL,
		0x684D8E00256F6417ULL,
		0x61329F78B3250730ULL,
		0xEC80A672ABC188F0ULL,
		0x3E9C90353DB6DE83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54BC98957654CC62ULL,
		0x00E0AABA1FF34258ULL,
		0x0D7E922E1B9EEC61ULL,
		0x5B10981FEA46EF67ULL,
		0xD09B1C004ADEC82EULL,
		0xC2653EF1664A0E60ULL,
		0xD9014CE5578311E0ULL,
		0x7D39206A7B6DBD07ULL
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
		0xC035A7C6319FCF46ULL,
		0x59876FD0D6BD3FF7ULL,
		0xADDA8BE0A70E6200ULL,
		0x68B7E0600EDB2880ULL,
		0x07163E421D5433FFULL,
		0x5D5919DF1FB8ED4DULL,
		0x369032D08F23EDA6ULL,
		0x23D17F5E3B86F837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x806B4F8C633F9E8CULL,
		0xB30EDFA1AD7A7FEFULL,
		0x5BB517C14E1CC400ULL,
		0xD16FC0C01DB65101ULL,
		0x0E2C7C843AA867FEULL,
		0xBAB233BE3F71DA9AULL,
		0x6D2065A11E47DB4CULL,
		0x47A2FEBC770DF06EULL
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
		0xCFFDACCB4292BA07ULL,
		0x6B0970D0B7EE5184ULL,
		0x72AEA10491B2AE94ULL,
		0x12141F4AD0CFB3A6ULL,
		0x3C9F235A64CF99A2ULL,
		0xEC4A41F548E23F0EULL,
		0xC463C5B13779678DULL,
		0x157AC980B52E5F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFB59968525740EULL,
		0xD612E1A16FDCA309ULL,
		0xE55D420923655D28ULL,
		0x24283E95A19F674CULL,
		0x793E46B4C99F3344ULL,
		0xD89483EA91C47E1CULL,
		0x88C78B626EF2CF1BULL,
		0x2AF593016A5CBE01ULL
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
		0x2A6479000B40C777ULL,
		0xF01883CF4A09A4E4ULL,
		0xCEE244822BB790ACULL,
		0x9FECEEA39F5960B1ULL,
		0x62EB9F79F84BBF52ULL,
		0x51F064A07BCB6111ULL,
		0x01B63DFB749DE00AULL,
		0x1C977119CA1B36E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C8F20016818EEEULL,
		0xE031079E941349C8ULL,
		0x9DC48904576F2159ULL,
		0x3FD9DD473EB2C163ULL,
		0xC5D73EF3F0977EA5ULL,
		0xA3E0C940F796C222ULL,
		0x036C7BF6E93BC014ULL,
		0x392EE23394366DD2ULL
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
		0xC327B6394E742ECCULL,
		0x65472D9D8F7B6553ULL,
		0x7C7DE6A6E7BF3479ULL,
		0xB1BC977A096991C7ULL,
		0xF31FE6DA32B74917ULL,
		0x94E5042AF065511EULL,
		0xDDB9A09F47F5EB5FULL,
		0x0FBB61E6DCF87A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864F6C729CE85D98ULL,
		0xCA8E5B3B1EF6CAA7ULL,
		0xF8FBCD4DCF7E68F2ULL,
		0x63792EF412D3238EULL,
		0xE63FCDB4656E922FULL,
		0x29CA0855E0CAA23DULL,
		0xBB73413E8FEBD6BFULL,
		0x1F76C3CDB9F0F4F9ULL
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
		0x4367009398CC6BFBULL,
		0xF25973B31D70367EULL,
		0xCB5F94EF9B04AC5DULL,
		0xCEB86432FC4C26A2ULL,
		0xA72EFE85150944CAULL,
		0xBCC90B816BF7F471ULL,
		0xB52C9FF9E35213D8ULL,
		0x286F0D45A73CB758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86CE01273198D7F6ULL,
		0xE4B2E7663AE06CFCULL,
		0x96BF29DF360958BBULL,
		0x9D70C865F8984D45ULL,
		0x4E5DFD0A2A128995ULL,
		0x79921702D7EFE8E3ULL,
		0x6A593FF3C6A427B1ULL,
		0x50DE1A8B4E796EB1ULL
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
		0x122316C37555EEF4ULL,
		0x910E3AD7B8CD5E24ULL,
		0x1AB218AAEA7F9EDFULL,
		0xF2BE8959769CDA22ULL,
		0x791482C02B11E960ULL,
		0x7D923E2D9E49C3BCULL,
		0x7E03B8C7AA36D155ULL,
		0x18FDB4C3A7849D80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24462D86EAABDDE8ULL,
		0x221C75AF719ABC48ULL,
		0x35643155D4FF3DBFULL,
		0xE57D12B2ED39B444ULL,
		0xF22905805623D2C1ULL,
		0xFB247C5B3C938778ULL,
		0xFC07718F546DA2AAULL,
		0x31FB69874F093B00ULL
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
		0x7DC4B69ABB0EC7EEULL,
		0xBC077F1391E974E4ULL,
		0xAF40EB9524331EEFULL,
		0x3B24EBE0DFD10A8FULL,
		0x806A54051898F568ULL,
		0x6CBDFBFDE86DFB7DULL,
		0xC54DD4227D103B67ULL,
		0x12C80ADC88AD9B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB896D35761D8FDCULL,
		0x780EFE2723D2E9C8ULL,
		0x5E81D72A48663DDFULL,
		0x7649D7C1BFA2151FULL,
		0x00D4A80A3131EAD0ULL,
		0xD97BF7FBD0DBF6FBULL,
		0x8A9BA844FA2076CEULL,
		0x259015B9115B36D7ULL
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
		0x6AA20CB37CC7DF2CULL,
		0x8C5C1F645D6231B6ULL,
		0x6982A59599E27303ULL,
		0x63E2ACEDD503EDDEULL,
		0x15231F35F130F948ULL,
		0x267F79EAB00C00DBULL,
		0x20F65C229CEE36B7ULL,
		0x18B3EEBB114BB006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5441966F98FBE58ULL,
		0x18B83EC8BAC4636CULL,
		0xD3054B2B33C4E607ULL,
		0xC7C559DBAA07DBBCULL,
		0x2A463E6BE261F290ULL,
		0x4CFEF3D5601801B6ULL,
		0x41ECB84539DC6D6EULL,
		0x3167DD762297600CULL
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
		0x500D4E7C426BFECAULL,
		0xFD76EA0C09F40A9BULL,
		0x2EA18728E6BDB3FFULL,
		0x50EA056E4AFB1253ULL,
		0x1C34824033A1A824ULL,
		0xFD714782359749D4ULL,
		0x7508B6BC8A367D5EULL,
		0x1B9A465431CED45EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA01A9CF884D7FD94ULL,
		0xFAEDD41813E81536ULL,
		0x5D430E51CD7B67FFULL,
		0xA1D40ADC95F624A6ULL,
		0x3869048067435048ULL,
		0xFAE28F046B2E93A8ULL,
		0xEA116D79146CFABDULL,
		0x37348CA8639DA8BCULL
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
		0xD210DC704076233AULL,
		0x5413B429010514D1ULL,
		0x2BFBF21BBFFA6106ULL,
		0x8F5AF4B569ED999FULL,
		0xB0649B09F53EE21BULL,
		0x11B6AD80C3C3B28AULL,
		0xAE51AC0816AC1F5FULL,
		0x23624E09039B3922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA421B8E080EC4674ULL,
		0xA8276852020A29A3ULL,
		0x57F7E4377FF4C20CULL,
		0x1EB5E96AD3DB333EULL,
		0x60C93613EA7DC437ULL,
		0x236D5B0187876515ULL,
		0x5CA358102D583EBEULL,
		0x46C49C1207367245ULL
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
		0xCBE422FA438F199CULL,
		0x7EC63F1FE64CD7DEULL,
		0x015174DD19D0C829ULL,
		0xB3D25F4C0F10ECA9ULL,
		0x193679C661652FEDULL,
		0x3C07D304678AD6DFULL,
		0x88E95B4CF22D12C1ULL,
		0x0F8D0DEA7D7DF2BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C845F4871E3338ULL,
		0xFD8C7E3FCC99AFBDULL,
		0x02A2E9BA33A19052ULL,
		0x67A4BE981E21D952ULL,
		0x326CF38CC2CA5FDBULL,
		0x780FA608CF15ADBEULL,
		0x11D2B699E45A2582ULL,
		0x1F1A1BD4FAFBE575ULL
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
		0x2D12A25240974B02ULL,
		0x8E975924BFA2D249ULL,
		0xC80F5810EDE577FFULL,
		0x1EE558305E5956D6ULL,
		0x20D3BD0F83D078EEULL,
		0x00183CE1A62A2818ULL,
		0x73D5A76ABF3DC2A3ULL,
		0x06B3435A02DDA47FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2544A4812E9604ULL,
		0x1D2EB2497F45A492ULL,
		0x901EB021DBCAEFFFULL,
		0x3DCAB060BCB2ADADULL,
		0x41A77A1F07A0F1DCULL,
		0x003079C34C545030ULL,
		0xE7AB4ED57E7B8546ULL,
		0x0D6686B405BB48FEULL
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
		0xBEC7A8DF14B8001BULL,
		0x46435F1F6368A8BBULL,
		0x6658092C525DA785ULL,
		0xD1572C275D039213ULL,
		0xF2D27DA806F6BEB2ULL,
		0x439C8F13EE4EE28AULL,
		0x115222EF06DAEE42ULL,
		0x2089F345F6296EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8F51BE29700036ULL,
		0x8C86BE3EC6D15177ULL,
		0xCCB01258A4BB4F0AULL,
		0xA2AE584EBA072426ULL,
		0xE5A4FB500DED7D65ULL,
		0x87391E27DC9DC515ULL,
		0x22A445DE0DB5DC84ULL,
		0x4113E68BEC52DD4EULL
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
		0x92D08A7E22077B9DULL,
		0xA6B52E4A5DF668CBULL,
		0x7C75A085A2AE2741ULL,
		0xBB7921DC1DF653A2ULL,
		0x2149C8954C908126ULL,
		0x0C9D8E4BC6C3805AULL,
		0x8B3F69CFAB17BDBEULL,
		0x0229ECE8AC21D1B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A114FC440EF73AULL,
		0x4D6A5C94BBECD197ULL,
		0xF8EB410B455C4E83ULL,
		0x76F243B83BECA744ULL,
		0x4293912A9921024DULL,
		0x193B1C978D8700B4ULL,
		0x167ED39F562F7B7CULL,
		0x0453D9D15843A363ULL
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
		0x5B2360FA4B841B1DULL,
		0x5CF84825906F45A2ULL,
		0x4AC7D7147E948B3FULL,
		0x2E0CE4A4727EDD5FULL,
		0x3D14DE93F9A40EC4ULL,
		0xD75DD0168330AFF6ULL,
		0xE2F09F3B30E8EC3AULL,
		0x108284293C1CF549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB646C1F49708363AULL,
		0xB9F0904B20DE8B44ULL,
		0x958FAE28FD29167EULL,
		0x5C19C948E4FDBABEULL,
		0x7A29BD27F3481D88ULL,
		0xAEBBA02D06615FECULL,
		0xC5E13E7661D1D875ULL,
		0x210508527839EA93ULL
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
		0x54EE33DAF1461591ULL,
		0xF40879A0150F3A29ULL,
		0xE052E09908D34599ULL,
		0xA2DC3EA7A492EF29ULL,
		0x9690B6A33D551BE8ULL,
		0xEA5CBA26C7DE8C1EULL,
		0x173201FEA68CBF02ULL,
		0x26924976791A5FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DC67B5E28C2B22ULL,
		0xE810F3402A1E7452ULL,
		0xC0A5C13211A68B33ULL,
		0x45B87D4F4925DE53ULL,
		0x2D216D467AAA37D1ULL,
		0xD4B9744D8FBD183DULL,
		0x2E6403FD4D197E05ULL,
		0x4D2492ECF234BFFEULL
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
		0xA33DF945171B2016ULL,
		0x5917550245DD8D58ULL,
		0x365FD4C398AB4595ULL,
		0x614115F1AD6935B1ULL,
		0x3E82C9B3C42A0B88ULL,
		0x6FA009EB5A6CA16EULL,
		0x8751626144952D2EULL,
		0x207BE5AB905B2EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467BF28A2E36402CULL,
		0xB22EAA048BBB1AB1ULL,
		0x6CBFA98731568B2AULL,
		0xC2822BE35AD26B62ULL,
		0x7D05936788541710ULL,
		0xDF4013D6B4D942DCULL,
		0x0EA2C4C2892A5A5CULL,
		0x40F7CB5720B65DE5ULL
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
		0xDA02DC7A0F910C00ULL,
		0x7A7BC7B2E6DF7EEFULL,
		0xFF70597AFD1DCAD3ULL,
		0x72A6BC02A2C9B683ULL,
		0xE6C83E38BAC1359EULL,
		0xCE44FB80949471DAULL,
		0xD9DDAE7CDDD1C06CULL,
		0x08D7011FFF2614FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB405B8F41F221800ULL,
		0xF4F78F65CDBEFDDFULL,
		0xFEE0B2F5FA3B95A6ULL,
		0xE54D780545936D07ULL,
		0xCD907C7175826B3CULL,
		0x9C89F7012928E3B5ULL,
		0xB3BB5CF9BBA380D9ULL,
		0x11AE023FFE4C29F5ULL
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
		0x92D0843C4D250965ULL,
		0x8E4BF2A55037E9A4ULL,
		0xABBFBF82DB9F7B20ULL,
		0xE6DECA50A02870D9ULL,
		0xCACB5B0D3E3E228BULL,
		0x7C30FED681465B46ULL,
		0x5BBD29BECB4F41B0ULL,
		0x3EFC013E23508956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A108789A4A12CAULL,
		0x1C97E54AA06FD349ULL,
		0x577F7F05B73EF641ULL,
		0xCDBD94A14050E1B3ULL,
		0x9596B61A7C7C4517ULL,
		0xF861FDAD028CB68DULL,
		0xB77A537D969E8360ULL,
		0x7DF8027C46A112ACULL
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
		0xAC4D1C6139D7AD55ULL,
		0xD06F819C6B12843BULL,
		0x190706D082F2CCDCULL,
		0xD7437EB42231873DULL,
		0x9D689C5E088536DFULL,
		0xF59679227629C8E0ULL,
		0xC90FF86A3D4C6E2AULL,
		0x2ECE5054BA414472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x589A38C273AF5AAAULL,
		0xA0DF0338D6250877ULL,
		0x320E0DA105E599B9ULL,
		0xAE86FD6844630E7AULL,
		0x3AD138BC110A6DBFULL,
		0xEB2CF244EC5391C1ULL,
		0x921FF0D47A98DC55ULL,
		0x5D9CA0A9748288E5ULL
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
		0x41FC97B6EC8FD266ULL,
		0x8341A2985552B6C9ULL,
		0xB8EB0E758D6FCDB5ULL,
		0x3ECF2C25C9C2E149ULL,
		0x278652D53B7B1899ULL,
		0x9587CE42064E737BULL,
		0xD60A3E982158735CULL,
		0x38E1C54905FA6A28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83F92F6DD91FA4CCULL,
		0x06834530AAA56D92ULL,
		0x71D61CEB1ADF9B6BULL,
		0x7D9E584B9385C293ULL,
		0x4F0CA5AA76F63132ULL,
		0x2B0F9C840C9CE6F6ULL,
		0xAC147D3042B0E6B9ULL,
		0x71C38A920BF4D451ULL
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
		0x57A1D98CE3914B3AULL,
		0xD3AC2437E9FCFBA9ULL,
		0xF03C38BB7AD5B747ULL,
		0x4D1884ACF7989FDDULL,
		0x77A39DB1DEE85B18ULL,
		0xEF5FB52E6D532971ULL,
		0x428020A35D42084BULL,
		0x187BD44480695C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF43B319C7229674ULL,
		0xA758486FD3F9F752ULL,
		0xE0787176F5AB6E8FULL,
		0x9A310959EF313FBBULL,
		0xEF473B63BDD0B630ULL,
		0xDEBF6A5CDAA652E2ULL,
		0x85004146BA841097ULL,
		0x30F7A88900D2B804ULL
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
		0x4B066BCC2B2C7293ULL,
		0xEFF76D95918B062EULL,
		0xF396322CA4A3D179ULL,
		0x61A34E12E0BDA92EULL,
		0x0362C9E50EC89E26ULL,
		0xBBA14BF9DBA18432ULL,
		0xD74651E0F7E77DADULL,
		0x1CC6E517D9228780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x960CD7985658E526ULL,
		0xDFEEDB2B23160C5CULL,
		0xE72C64594947A2F3ULL,
		0xC3469C25C17B525DULL,
		0x06C593CA1D913C4CULL,
		0x774297F3B7430864ULL,
		0xAE8CA3C1EFCEFB5BULL,
		0x398DCA2FB2450F01ULL
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
		0xE6C7221A5349B35BULL,
		0x983F1714F5D5AFDAULL,
		0xBDA6D1A22057C52CULL,
		0x5AB4C9033DD43725ULL,
		0x9F1708CE6E0E16A2ULL,
		0xDB099FA31577600CULL,
		0xFDE1C67E35B9A24EULL,
		0x3B44171FDC9A0B3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD8E4434A69366B6ULL,
		0x307E2E29EBAB5FB5ULL,
		0x7B4DA34440AF8A59ULL,
		0xB56992067BA86E4BULL,
		0x3E2E119CDC1C2D44ULL,
		0xB6133F462AEEC019ULL,
		0xFBC38CFC6B73449DULL,
		0x76882E3FB9341675ULL
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
		0xE1D2FFE8223E6425ULL,
		0x38D2F49D61E97490ULL,
		0x6D9012C8E54665BFULL,
		0x08167434769821AAULL,
		0x5483134E15F94781ULL,
		0x66E5EA2D21B06DF4ULL,
		0x15FFDF10AB42A692ULL,
		0x3DDB2CF8C1BAFD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3A5FFD0447CC84AULL,
		0x71A5E93AC3D2E921ULL,
		0xDB202591CA8CCB7EULL,
		0x102CE868ED304354ULL,
		0xA906269C2BF28F02ULL,
		0xCDCBD45A4360DBE8ULL,
		0x2BFFBE2156854D24ULL,
		0x7BB659F18375FAC4ULL
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
		0xA109AEDFD4C26EF7ULL,
		0x57B1BC156FF0A35DULL,
		0x11E1F2BECE889D0FULL,
		0x94373ACDE0993431ULL,
		0x81174233E8EE0975ULL,
		0x5937694FC7EBC018ULL,
		0x8B635ABEF3BF5639ULL,
		0x006657EFF738D609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42135DBFA984DDEEULL,
		0xAF63782ADFE146BBULL,
		0x23C3E57D9D113A1EULL,
		0x286E759BC1326862ULL,
		0x022E8467D1DC12EBULL,
		0xB26ED29F8FD78031ULL,
		0x16C6B57DE77EAC72ULL,
		0x00CCAFDFEE71AC13ULL
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
		0x0F579B0A6B9B8223ULL,
		0xFF461591EE37C977ULL,
		0x01B265F62C206D1FULL,
		0x735C3B73D23048EFULL,
		0xCFB904A7BD2A1B74ULL,
		0xE90E26797CA30F0EULL,
		0x189205F179565422ULL,
		0x1D7E507332012C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EAF3614D7370446ULL,
		0xFE8C2B23DC6F92EEULL,
		0x0364CBEC5840DA3FULL,
		0xE6B876E7A46091DEULL,
		0x9F72094F7A5436E8ULL,
		0xD21C4CF2F9461E1DULL,
		0x31240BE2F2ACA845ULL,
		0x3AFCA0E664025848ULL
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
		0xE9CE889167899EECULL,
		0x1E0CBC9934208862ULL,
		0x774E3A4052422749ULL,
		0xA858E69A29EC9C42ULL,
		0x004C0F7D4005A23FULL,
		0xB07450472299BA9DULL,
		0x257843CF7ABE6372ULL,
		0x2B4AEBE73D925DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39D1122CF133DD8ULL,
		0x3C197932684110C5ULL,
		0xEE9C7480A4844E92ULL,
		0x50B1CD3453D93884ULL,
		0x00981EFA800B447FULL,
		0x60E8A08E4533753AULL,
		0x4AF0879EF57CC6E5ULL,
		0x5695D7CE7B24BBE0ULL
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
		0x0C0A9CED2240BCE0ULL,
		0x6336D00210DABED0ULL,
		0x6D942CDF85AA54CAULL,
		0x16B6C5A6C575DBF4ULL,
		0x9D802221EF79694BULL,
		0xC3B6D8DC8BD568AAULL,
		0x73827FB3D4DD143FULL,
		0x2B6ECCA6554E58C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x181539DA448179C0ULL,
		0xC66DA00421B57DA0ULL,
		0xDB2859BF0B54A994ULL,
		0x2D6D8B4D8AEBB7E8ULL,
		0x3B004443DEF2D296ULL,
		0x876DB1B917AAD155ULL,
		0xE704FF67A9BA287FULL,
		0x56DD994CAA9CB188ULL
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
		0x887143DEC71BB35BULL,
		0xFAC9E27D1055B37CULL,
		0x7BC7404D7FA70248ULL,
		0x72A139F5C99A06F9ULL,
		0x2BF1F08A79C616C2ULL,
		0x664A0480071AF710ULL,
		0x12DC94264E188109ULL,
		0x3FFA209CB0AA01E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E287BD8E3766B6ULL,
		0xF593C4FA20AB66F9ULL,
		0xF78E809AFF4E0491ULL,
		0xE54273EB93340DF2ULL,
		0x57E3E114F38C2D84ULL,
		0xCC9409000E35EE20ULL,
		0x25B9284C9C310212ULL,
		0x7FF44139615403C6ULL
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
		0xEDED046AC69977EDULL,
		0x312D4BEDC145E99CULL,
		0x6E025136859E2CC7ULL,
		0xDDCD1A429E93E294ULL,
		0xBB8FDE23134B7E34ULL,
		0xFCB848BF59965C6CULL,
		0xDF0BF0C77613B9F1ULL,
		0x3D717D2E33627A4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBDA08D58D32EFDAULL,
		0x625A97DB828BD339ULL,
		0xDC04A26D0B3C598EULL,
		0xBB9A34853D27C528ULL,
		0x771FBC462696FC69ULL,
		0xF970917EB32CB8D9ULL,
		0xBE17E18EEC2773E3ULL,
		0x7AE2FA5C66C4F495ULL
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
		0x2E3E2225F7C7F741ULL,
		0x5BE47E38EC640B99ULL,
		0xC70F8248D3F9F17FULL,
		0x099A5B213AF9BAF0ULL,
		0x302C94BA98FD753EULL,
		0x3A970E09A1FDCAD1ULL,
		0x8D1D2F6E20506259ULL,
		0x1CAE26AE00C401E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7C444BEF8FEE82ULL,
		0xB7C8FC71D8C81732ULL,
		0x8E1F0491A7F3E2FEULL,
		0x1334B64275F375E1ULL,
		0x6059297531FAEA7CULL,
		0x752E1C1343FB95A2ULL,
		0x1A3A5EDC40A0C4B2ULL,
		0x395C4D5C018803D1ULL
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
		0x6099C52E61DCD13BULL,
		0xD3E022182B89887BULL,
		0x238329ACE15441ACULL,
		0xCC9728ECAE87B787ULL,
		0xB635AF26FA83A2B1ULL,
		0x7D57807E4CE4E709ULL,
		0x45E7FE65D6C7BC0BULL,
		0x00BCA88CCC373AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1338A5CC3B9A276ULL,
		0xA7C04430571310F6ULL,
		0x47065359C2A88359ULL,
		0x992E51D95D0F6F0EULL,
		0x6C6B5E4DF5074563ULL,
		0xFAAF00FC99C9CE13ULL,
		0x8BCFFCCBAD8F7816ULL,
		0x01795119986E75C0ULL
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
		0xFC12F11C8D969228ULL,
		0xAFC6F74652921F5EULL,
		0x71705D1B2AB21E9CULL,
		0xD89BF462DF845D50ULL,
		0x977EBCD7216B55E4ULL,
		0x0185754F31E7BD91ULL,
		0x4DFF0CE8519A19D7ULL,
		0x1655924677B01ADCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF825E2391B2D2450ULL,
		0x5F8DEE8CA5243EBDULL,
		0xE2E0BA3655643D39ULL,
		0xB137E8C5BF08BAA0ULL,
		0x2EFD79AE42D6ABC9ULL,
		0x030AEA9E63CF7B23ULL,
		0x9BFE19D0A33433AEULL,
		0x2CAB248CEF6035B8ULL
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
		0x5CB660F04DB41EF3ULL,
		0x60005082618DB653ULL,
		0x5AD283CDB7AA4027ULL,
		0x58A871BE3AEB5314ULL,
		0x3AF5D5D10B328E2DULL,
		0x5EAE6DF69C5BF489ULL,
		0xBA36AE1CA35EB821ULL,
		0x0C05FA90F86FE34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96CC1E09B683DE6ULL,
		0xC000A104C31B6CA6ULL,
		0xB5A5079B6F54804EULL,
		0xB150E37C75D6A628ULL,
		0x75EBABA216651C5AULL,
		0xBD5CDBED38B7E912ULL,
		0x746D5C3946BD7042ULL,
		0x180BF521F0DFC697ULL
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
		0x1AB85F5DE5407274ULL,
		0xEF043A0841CB7A9AULL,
		0xBE5F15EEE3CDBC16ULL,
		0x893060C4E3CB1F15ULL,
		0xF91727343021E0E8ULL,
		0xDFD69CBA738B706BULL,
		0x9CC728A0A397DBA3ULL,
		0x387FEAED4935ABD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3570BEBBCA80E4E8ULL,
		0xDE0874108396F534ULL,
		0x7CBE2BDDC79B782DULL,
		0x1260C189C7963E2BULL,
		0xF22E4E686043C1D1ULL,
		0xBFAD3974E716E0D7ULL,
		0x398E5141472FB747ULL,
		0x70FFD5DA926B57A7ULL
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
		0xE781935D60927D4AULL,
		0xA8632B5DEACE5CAEULL,
		0x10FC4174EFE625ADULL,
		0x7AE23D094C097A41ULL,
		0xC2BE8095FF7F6BAFULL,
		0xD688E4F6BC1D2C0FULL,
		0x2030D0CA65D0D0B8ULL,
		0x22E373FF6D300610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0326BAC124FA94ULL,
		0x50C656BBD59CB95DULL,
		0x21F882E9DFCC4B5BULL,
		0xF5C47A129812F482ULL,
		0x857D012BFEFED75EULL,
		0xAD11C9ED783A581FULL,
		0x4061A194CBA1A171ULL,
		0x45C6E7FEDA600C20ULL
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
		0x05DCBEFA4BEF704CULL,
		0x2CD95CBAF599DD2AULL,
		0x8AA821D5B685FBC1ULL,
		0xD5D7FB24D4710466ULL,
		0x05C12CB83208A272ULL,
		0xC99E54537F0D54CAULL,
		0x85C78B5EDD794DC7ULL,
		0x261359319B1AE2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB97DF497DEE098ULL,
		0x59B2B975EB33BA54ULL,
		0x155043AB6D0BF782ULL,
		0xABAFF649A8E208CDULL,
		0x0B825970641144E5ULL,
		0x933CA8A6FE1AA994ULL,
		0x0B8F16BDBAF29B8FULL,
		0x4C26B2633635C593ULL
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
		0x5B3ACF3B4EEC09DAULL,
		0x0511A78F0F202E13ULL,
		0x29190A58ED236488ULL,
		0x5062AF50AD805E76ULL,
		0x20BB28D78ECAC4D7ULL,
		0x26A64F1F9C2A5FA1ULL,
		0xAD3D8AE9313AC540ULL,
		0x3F2CBBFD9946FAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6759E769DD813B4ULL,
		0x0A234F1E1E405C26ULL,
		0x523214B1DA46C910ULL,
		0xA0C55EA15B00BCECULL,
		0x417651AF1D9589AEULL,
		0x4D4C9E3F3854BF42ULL,
		0x5A7B15D262758A80ULL,
		0x7E5977FB328DF5C3ULL
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
		0x9D75AE34CBAD73A1ULL,
		0x5728EE658B86890AULL,
		0x9752456EBF39DC98ULL,
		0x48528E6C3041698FULL,
		0x9C8883ED921E590BULL,
		0x0B131A747CB187E8ULL,
		0x2572631CC3C7C574ULL,
		0x0CEAFBB9F54050CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AEB5C69975AE742ULL,
		0xAE51DCCB170D1215ULL,
		0x2EA48ADD7E73B930ULL,
		0x90A51CD86082D31FULL,
		0x391107DB243CB216ULL,
		0x162634E8F9630FD1ULL,
		0x4AE4C639878F8AE8ULL,
		0x19D5F773EA80A19CULL
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
		0x539F29965CB2EDD0ULL,
		0xBBDCCF4E17DC3EEFULL,
		0xDD4A966BF75C6756ULL,
		0x21547F0377B0BEC2ULL,
		0x0F862499DC6AF9FEULL,
		0x9D4747CF528217B7ULL,
		0x4C63DF920E8713B5ULL,
		0x0D0C2E48C8E03EF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA73E532CB965DBA0ULL,
		0x77B99E9C2FB87DDEULL,
		0xBA952CD7EEB8CEADULL,
		0x42A8FE06EF617D85ULL,
		0x1F0C4933B8D5F3FCULL,
		0x3A8E8F9EA5042F6EULL,
		0x98C7BF241D0E276BULL,
		0x1A185C9191C07DEEULL
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
		0x916CC64C4F03B8D0ULL,
		0x38E0745647609785ULL,
		0x97CD7AEA9BFC3649ULL,
		0x6E586DA6FCC4B487ULL,
		0xA7FB58F6126C6560ULL,
		0x056024B0118DC581ULL,
		0xF0DAE0B3BC605B3DULL,
		0x35C17DEF51449833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D98C989E0771A0ULL,
		0x71C0E8AC8EC12F0BULL,
		0x2F9AF5D537F86C92ULL,
		0xDCB0DB4DF989690FULL,
		0x4FF6B1EC24D8CAC0ULL,
		0x0AC04960231B8B03ULL,
		0xE1B5C16778C0B67AULL,
		0x6B82FBDEA2893067ULL
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
		0xD301111B23E06858ULL,
		0x65604E635D3138FDULL,
		0x4DF4F05C0F2A2CB9ULL,
		0x86824F14D1D7C470ULL,
		0x6F93F34787BCDE1BULL,
		0xEA56689823903CA6ULL,
		0x0AF33EC20B50902DULL,
		0x3743A57948E23619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA602223647C0D0B0ULL,
		0xCAC09CC6BA6271FBULL,
		0x9BE9E0B81E545972ULL,
		0x0D049E29A3AF88E0ULL,
		0xDF27E68F0F79BC37ULL,
		0xD4ACD1304720794CULL,
		0x15E67D8416A1205BULL,
		0x6E874AF291C46C32ULL
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
		0xD929FE85B6660326ULL,
		0xD98ED4B0CB0B30AEULL,
		0x4A55E56489ED49ECULL,
		0xAC9C230BC0277741ULL,
		0x1B7D314F54A971B1ULL,
		0xF4EC610E18366880ULL,
		0x3C5C660392AC7E4DULL,
		0x3CCD72A625459337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB253FD0B6CCC064CULL,
		0xB31DA9619616615DULL,
		0x94ABCAC913DA93D9ULL,
		0x59384617804EEE82ULL,
		0x36FA629EA952E363ULL,
		0xE9D8C21C306CD100ULL,
		0x78B8CC072558FC9BULL,
		0x799AE54C4A8B266EULL
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
		0x2781B9E2EE8AC79FULL,
		0x9E99768425D89EB5ULL,
		0x1D12FC0B5DE0F3A3ULL,
		0x4480511BC7308458ULL,
		0xA651C27ABE1CFF7AULL,
		0x23D67BFFF803A69CULL,
		0xB1FBD14E5EE89050ULL,
		0x248DE74BF5DD735EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F0373C5DD158F3EULL,
		0x3D32ED084BB13D6AULL,
		0x3A25F816BBC1E747ULL,
		0x8900A2378E6108B0ULL,
		0x4CA384F57C39FEF4ULL,
		0x47ACF7FFF0074D39ULL,
		0x63F7A29CBDD120A0ULL,
		0x491BCE97EBBAE6BDULL
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
		0xACFBD063C2ABFB9AULL,
		0xD93E2FCE3E1A6AC7ULL,
		0x0B45056571BF64A7ULL,
		0x2AC4E717C6C996EEULL,
		0x5D29CF7E48FFBE7BULL,
		0x96BA9937C01F78E0ULL,
		0x7F1EA480B5A63B20ULL,
		0x0725AA09A57159ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F7A0C78557F734ULL,
		0xB27C5F9C7C34D58FULL,
		0x168A0ACAE37EC94FULL,
		0x5589CE2F8D932DDCULL,
		0xBA539EFC91FF7CF6ULL,
		0x2D75326F803EF1C0ULL,
		0xFE3D49016B4C7641ULL,
		0x0E4B54134AE2B35AULL
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
		0xA98C014D8307D66CULL,
		0x02E99F8B1A577732ULL,
		0x45C75A2759481CA9ULL,
		0xA9FD7004BAAC4701ULL,
		0x67BFA7A5278598D3ULL,
		0x9445D0C65A25883AULL,
		0x687BF44D628395C4ULL,
		0x0C9119809CCD5CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5318029B060FACD8ULL,
		0x05D33F1634AEEE65ULL,
		0x8B8EB44EB2903952ULL,
		0x53FAE00975588E02ULL,
		0xCF7F4F4A4F0B31A7ULL,
		0x288BA18CB44B1074ULL,
		0xD0F7E89AC5072B89ULL,
		0x19223301399AB9EEULL
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
		0xFC21DE5FF0A643CAULL,
		0xC879873211E5B81DULL,
		0x04D946B3FA5016CCULL,
		0x18E4242607A955BEULL,
		0xC0FBF497E9CC9D9BULL,
		0x7619EE588CD3BDD6ULL,
		0x903405FA5BA5A79EULL,
		0x121C1BFF470E2080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF843BCBFE14C8794ULL,
		0x90F30E6423CB703BULL,
		0x09B28D67F4A02D99ULL,
		0x31C8484C0F52AB7CULL,
		0x81F7E92FD3993B36ULL,
		0xEC33DCB119A77BADULL,
		0x20680BF4B74B4F3CULL,
		0x243837FE8E1C4101ULL
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
		0x58916A1525F05F91ULL,
		0x7670DE37E6790A4CULL,
		0xB86A38D89ED0B55BULL,
		0xCD1DB169C94D69A0ULL,
		0xBC717A4641534FECULL,
		0x585BAA8DD96F8930ULL,
		0x6C2D2576CEC84E10ULL,
		0x0A5198F6B571ABE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB122D42A4BE0BF22ULL,
		0xECE1BC6FCCF21498ULL,
		0x70D471B13DA16AB6ULL,
		0x9A3B62D3929AD341ULL,
		0x78E2F48C82A69FD9ULL,
		0xB0B7551BB2DF1261ULL,
		0xD85A4AED9D909C20ULL,
		0x14A331ED6AE357C6ULL
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
		0xB2FD62C00C94AB75ULL,
		0x1910CA47C585EEF3ULL,
		0xF46059067BB72853ULL,
		0xBC425D2F8D497747ULL,
		0xA2A1059163A188DDULL,
		0xF4EA833641989DACULL,
		0x792EDD70583CEE45ULL,
		0x2CC5C6F472507780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65FAC580192956EAULL,
		0x3221948F8B0BDDE7ULL,
		0xE8C0B20CF76E50A6ULL,
		0x7884BA5F1A92EE8FULL,
		0x45420B22C74311BBULL,
		0xE9D5066C83313B59ULL,
		0xF25DBAE0B079DC8BULL,
		0x598B8DE8E4A0EF00ULL
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
		0x45E94B3D5B3EDD1CULL,
		0xF89409C11691FE27ULL,
		0xD56D76AF1B483DA6ULL,
		0x6E582D4F902BCACBULL,
		0x917FFC1C7F69ECCCULL,
		0xAF45055E971AD48DULL,
		0xFB63DFB4921B0CB3ULL,
		0x2CC197E78807D771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD2967AB67DBA38ULL,
		0xF12813822D23FC4EULL,
		0xAADAED5E36907B4DULL,
		0xDCB05A9F20579597ULL,
		0x22FFF838FED3D998ULL,
		0x5E8A0ABD2E35A91BULL,
		0xF6C7BF6924361967ULL,
		0x59832FCF100FAEE3ULL
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
		0x8ABC5F83FF25A871ULL,
		0x673A3339BC57648DULL,
		0x4B7391B0B384B7B1ULL,
		0x749A20489EBCE09AULL,
		0x7A6FF264AEC39808ULL,
		0xB87D5F5C4C06EFAAULL,
		0x89877CF7BE13C898ULL,
		0x0D39E2CB5D851792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1578BF07FE4B50E2ULL,
		0xCE74667378AEC91BULL,
		0x96E7236167096F62ULL,
		0xE93440913D79C134ULL,
		0xF4DFE4C95D873010ULL,
		0x70FABEB8980DDF54ULL,
		0x130EF9EF7C279131ULL,
		0x1A73C596BB0A2F25ULL
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
		0xF5997E7B7262041BULL,
		0xE6415C84747685FAULL,
		0x63B1DFD13681BAD0ULL,
		0xCD0325012FE76A33ULL,
		0xAB39FFAD5D7B33AAULL,
		0x8F2AA69B8190D1D3ULL,
		0x7AB34252E9212A78ULL,
		0x0A73EEA062F23387ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB32FCF6E4C40836ULL,
		0xCC82B908E8ED0BF5ULL,
		0xC763BFA26D0375A1ULL,
		0x9A064A025FCED466ULL,
		0x5673FF5ABAF66755ULL,
		0x1E554D370321A3A7ULL,
		0xF56684A5D24254F1ULL,
		0x14E7DD40C5E4670EULL
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
		0x9552D0315E7001A3ULL,
		0x5E2CED45CE1F7D58ULL,
		0xC93989453518FAF4ULL,
		0x1BCAE4B2B84DCBEFULL,
		0xEF2080039A028E18ULL,
		0x3ACDD676AE73C00DULL,
		0x495B337CFF265C4CULL,
		0x28505B1F5010F0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA5A062BCE00346ULL,
		0xBC59DA8B9C3EFAB1ULL,
		0x9273128A6A31F5E8ULL,
		0x3795C965709B97DFULL,
		0xDE41000734051C30ULL,
		0x759BACED5CE7801BULL,
		0x92B666F9FE4CB898ULL,
		0x50A0B63EA021E15EULL
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
		0x669A6644B0329835ULL,
		0x15F5C05E77502042ULL,
		0x2EABA7BD752D4D3CULL,
		0x554C1D8547212A30ULL,
		0xB3D5896F4AE44E8AULL,
		0x9C24AAFD2DE9E57DULL,
		0xC9BB5DE580DB09D7ULL,
		0x12C84C5F91FC400CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD34CC896065306AULL,
		0x2BEB80BCEEA04084ULL,
		0x5D574F7AEA5A9A78ULL,
		0xAA983B0A8E425460ULL,
		0x67AB12DE95C89D14ULL,
		0x384955FA5BD3CAFBULL,
		0x9376BBCB01B613AFULL,
		0x259098BF23F88019ULL
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
		0x03EA3EAB032A914CULL,
		0x6CAB4C25DFED86FCULL,
		0xDBBE270720F45380ULL,
		0x241B2471EF628F26ULL,
		0x8A687ADFA0F7E5A4ULL,
		0xFF74E0E3254F83EBULL,
		0xEA8492786EF15367ULL,
		0x1126E6FC7C8521AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D47D5606552298ULL,
		0xD956984BBFDB0DF8ULL,
		0xB77C4E0E41E8A700ULL,
		0x483648E3DEC51E4DULL,
		0x14D0F5BF41EFCB48ULL,
		0xFEE9C1C64A9F07D7ULL,
		0xD50924F0DDE2A6CFULL,
		0x224DCDF8F90A4355ULL
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
		0x3020A28FDD1DA23FULL,
		0xCCFC191C088365CAULL,
		0xE3FC215F72D023BCULL,
		0x2201E3E402FB0F10ULL,
		0xD5E8F2C05DE0971CULL,
		0xFAF7AB8CD919CDF3ULL,
		0x74D5502EE890EB0BULL,
		0x1497B5CC0455A805ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6041451FBA3B447EULL,
		0x99F832381106CB94ULL,
		0xC7F842BEE5A04779ULL,
		0x4403C7C805F61E21ULL,
		0xABD1E580BBC12E38ULL,
		0xF5EF5719B2339BE7ULL,
		0xE9AAA05DD121D617ULL,
		0x292F6B9808AB500AULL
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
		0xB7FC6A038E8B6F98ULL,
		0x0BC50E243ECE284DULL,
		0x6EFEF4331CD0A944ULL,
		0x42EEF9E7E7A72E40ULL,
		0x12D4CEFF91CF2A9DULL,
		0x12CEA1590B57DBDDULL,
		0xE9CE74BF14BDD957ULL,
		0x23DE0D7868D0AF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF8D4071D16DF30ULL,
		0x178A1C487D9C509BULL,
		0xDDFDE86639A15288ULL,
		0x85DDF3CFCF4E5C80ULL,
		0x25A99DFF239E553AULL,
		0x259D42B216AFB7BAULL,
		0xD39CE97E297BB2AEULL,
		0x47BC1AF0D1A15F17ULL
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
		0xB49430B525A9720EULL,
		0x6849881FCC5C8B0BULL,
		0xFB59F7C4FCAE0B21ULL,
		0xF148AA3F5AABBB3AULL,
		0x875C2676AA8DCD6EULL,
		0x82BEBCAE5D1591D4ULL,
		0x8CDEE31317742367ULL,
		0x1783056268E24EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6928616A4B52E41CULL,
		0xD093103F98B91617ULL,
		0xF6B3EF89F95C1642ULL,
		0xE291547EB5577675ULL,
		0x0EB84CED551B9ADDULL,
		0x057D795CBA2B23A9ULL,
		0x19BDC6262EE846CFULL,
		0x2F060AC4D1C49DEBULL
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
		0x0A6E8D75C5920AB9ULL,
		0xEF40EB5EB42090C6ULL,
		0xBD5F4FCAE357626FULL,
		0x30DBCE1D2FA4E623ULL,
		0xD34692F9148EB744ULL,
		0x3401DC41DAE5464EULL,
		0xA7350101AC75676DULL,
		0x16E50662D38A6F18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14DD1AEB8B241572ULL,
		0xDE81D6BD6841218CULL,
		0x7ABE9F95C6AEC4DFULL,
		0x61B79C3A5F49CC47ULL,
		0xA68D25F2291D6E88ULL,
		0x6803B883B5CA8C9DULL,
		0x4E6A020358EACEDAULL,
		0x2DCA0CC5A714DE31ULL
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
		0x68CA7FA8356A9C66ULL,
		0xE4A4B2B491E2635CULL,
		0x5478CC2D3C38DE33ULL,
		0x91C9E51121AA7167ULL,
		0x909CFDDF8B3548BEULL,
		0x87650EEF11D48532ULL,
		0x900F00BC76384E4CULL,
		0x16A719A9B3EFD010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD194FF506AD538CCULL,
		0xC949656923C4C6B8ULL,
		0xA8F1985A7871BC67ULL,
		0x2393CA224354E2CEULL,
		0x2139FBBF166A917DULL,
		0x0ECA1DDE23A90A65ULL,
		0x201E0178EC709C99ULL,
		0x2D4E335367DFA021ULL
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
		0x9389DF00B6739E09ULL,
		0x7359AB5D33B00003ULL,
		0xBE1CEE6AE6D71A8FULL,
		0xA4BCFFF4A77C2B4EULL,
		0x41BA7C9E1F589CC4ULL,
		0xA73DEE4485A700F7ULL,
		0xAD4D481C26D4D344ULL,
		0x29E7B7975F020452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2713BE016CE73C12ULL,
		0xE6B356BA67600007ULL,
		0x7C39DCD5CDAE351EULL,
		0x4979FFE94EF8569DULL,
		0x8374F93C3EB13989ULL,
		0x4E7BDC890B4E01EEULL,
		0x5A9A90384DA9A689ULL,
		0x53CF6F2EBE0408A5ULL
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
		0x433A345382BDC44DULL,
		0xEAE233C0102450EFULL,
		0xEC9500DFBB0FE81EULL,
		0x094DFE6CBA61EB64ULL,
		0xE07AA5051E3BE609ULL,
		0x0832176D45A33FB6ULL,
		0x873250E02DF2E325ULL,
		0x048F59FE6D082DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867468A7057B889AULL,
		0xD5C467802048A1DEULL,
		0xD92A01BF761FD03DULL,
		0x129BFCD974C3D6C9ULL,
		0xC0F54A0A3C77CC12ULL,
		0x10642EDA8B467F6DULL,
		0x0E64A1C05BE5C64AULL,
		0x091EB3FCDA105B9BULL
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
		0xEB70E7DFAF411363ULL,
		0x5D437DBEA9B536F0ULL,
		0x8C5D36CA32062F28ULL,
		0x50A94B62B8082010ULL,
		0xCC22E49811E0FAD1ULL,
		0xAFE2ED6CB63DC37AULL,
		0x6969655F592A3ACDULL,
		0x0369A1C0DC32C29DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E1CFBF5E8226C6ULL,
		0xBA86FB7D536A6DE1ULL,
		0x18BA6D94640C5E50ULL,
		0xA15296C570104021ULL,
		0x9845C93023C1F5A2ULL,
		0x5FC5DAD96C7B86F5ULL,
		0xD2D2CABEB254759BULL,
		0x06D34381B865853AULL
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
		0x88A21D2C3CA70A1CULL,
		0x1AEE4637D65E5F77ULL,
		0x638240A85B588672ULL,
		0xE1619E42CC35FB09ULL,
		0xC5165FF5803BCF41ULL,
		0x8659526BC68E2D32ULL,
		0x35420D71551D68B7ULL,
		0x3132845B41A7E50AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11443A58794E1438ULL,
		0x35DC8C6FACBCBEEFULL,
		0xC7048150B6B10CE4ULL,
		0xC2C33C85986BF612ULL,
		0x8A2CBFEB00779E83ULL,
		0x0CB2A4D78D1C5A65ULL,
		0x6A841AE2AA3AD16FULL,
		0x626508B6834FCA14ULL
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
		0x0747E415350F3580ULL,
		0x0DEF57419C2F5174ULL,
		0x840D6C6A5F1EE9EFULL,
		0x64D495FAB3AD7CCEULL,
		0xE0247EAFF3208109ULL,
		0x24307706FB4CD469ULL,
		0xB1A0BCD8488BAA77ULL,
		0x1BAD9FADA9300C1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E8FC82A6A1E6B00ULL,
		0x1BDEAE83385EA2E8ULL,
		0x081AD8D4BE3DD3DEULL,
		0xC9A92BF5675AF99DULL,
		0xC048FD5FE6410212ULL,
		0x4860EE0DF699A8D3ULL,
		0x634179B0911754EEULL,
		0x375B3F5B5260183DULL
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
		0xE8F520FB3AB831C9ULL,
		0xC070B07A6A1050D7ULL,
		0xB0BCD3949D4DE60EULL,
		0xDCE654D61EF9F0A5ULL,
		0x0D40420E1ADC9FBDULL,
		0xF904A452506F28F7ULL,
		0x616B30EEA8B3DE47ULL,
		0x152CA59B457243A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1EA41F675706392ULL,
		0x80E160F4D420A1AFULL,
		0x6179A7293A9BCC1DULL,
		0xB9CCA9AC3DF3E14BULL,
		0x1A80841C35B93F7BULL,
		0xF20948A4A0DE51EEULL,
		0xC2D661DD5167BC8FULL,
		0x2A594B368AE4874CULL
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
		0xD3D3AE7538EA91BAULL,
		0xCC9AA2802F101BDAULL,
		0xB3BF9F24A77B7EAFULL,
		0xEE06B570BF084080ULL,
		0x0C7FA345D57629FFULL,
		0x70FBB16B66BFA3B7ULL,
		0x742395921EB22C47ULL,
		0x1249AD70EF60E76FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A75CEA71D52374ULL,
		0x993545005E2037B5ULL,
		0x677F3E494EF6FD5FULL,
		0xDC0D6AE17E108101ULL,
		0x18FF468BAAEC53FFULL,
		0xE1F762D6CD7F476EULL,
		0xE8472B243D64588EULL,
		0x24935AE1DEC1CEDEULL
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
		0xAC026C5F3D0BEE09ULL,
		0xC5D49695407EAB94ULL,
		0x8C780107B2490467ULL,
		0xCD286BA4312FFBCFULL,
		0xB8F68E677C2C53A7ULL,
		0x38A11A9CD1A776B6ULL,
		0xF981438AC7280D11ULL,
		0x00921BF78BDAB186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5804D8BE7A17DC12ULL,
		0x8BA92D2A80FD5729ULL,
		0x18F0020F649208CFULL,
		0x9A50D748625FF79FULL,
		0x71ED1CCEF858A74FULL,
		0x71423539A34EED6DULL,
		0xF30287158E501A22ULL,
		0x012437EF17B5630DULL
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
		0x4A4DCB46BFCC6EF9ULL,
		0x315FF301C8410EBFULL,
		0x6410069BF10C0AC9ULL,
		0x402D1A0C02C4782FULL,
		0x5623A4323D6E039AULL,
		0x25DCFEDDF4736FE3ULL,
		0xA01ABD776DD314BAULL,
		0x2FC0DEC202039E13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x949B968D7F98DDF2ULL,
		0x62BFE60390821D7EULL,
		0xC8200D37E2181592ULL,
		0x805A34180588F05EULL,
		0xAC4748647ADC0734ULL,
		0x4BB9FDBBE8E6DFC6ULL,
		0x40357AEEDBA62974ULL,
		0x5F81BD8404073C27ULL
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
		0x018F06A88061F494ULL,
		0x3866ECA8B95380A3ULL,
		0x7E0966862B6F3D59ULL,
		0x5FAEE123F5FA4A3EULL,
		0xCA44E5E8557399ADULL,
		0x775C4C9C576C82A0ULL,
		0x49C06820127C6D71ULL,
		0x1CD37E16BD4909E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x031E0D5100C3E928ULL,
		0x70CDD95172A70146ULL,
		0xFC12CD0C56DE7AB2ULL,
		0xBF5DC247EBF4947CULL,
		0x9489CBD0AAE7335AULL,
		0xEEB89938AED90541ULL,
		0x9380D04024F8DAE2ULL,
		0x39A6FC2D7A9213C2ULL
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
		0x80954C394E34255BULL,
		0xCD171FC3379EFD31ULL,
		0x93F911DA47B497B7ULL,
		0xE42F7D3328BB0E16ULL,
		0xF47689E5E3A41EF0ULL,
		0x25E57A83F720A688ULL,
		0xE870EBEB9B985E22ULL,
		0x229400909E26F225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012A98729C684AB6ULL,
		0x9A2E3F866F3DFA63ULL,
		0x27F223B48F692F6FULL,
		0xC85EFA6651761C2DULL,
		0xE8ED13CBC7483DE1ULL,
		0x4BCAF507EE414D11ULL,
		0xD0E1D7D73730BC44ULL,
		0x452801213C4DE44BULL
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
		0x3967C29B3FEEF772ULL,
		0xB27C51E38E4C5637ULL,
		0x953F7102606554EAULL,
		0xA2630A845EB57582ULL,
		0xE6C034D4C54CF4C5ULL,
		0x0F797BC2CDD3560EULL,
		0x06C1C8B9474CDC79ULL,
		0x00B65150FB01296EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72CF85367FDDEEE4ULL,
		0x64F8A3C71C98AC6EULL,
		0x2A7EE204C0CAA9D5ULL,
		0x44C61508BD6AEB05ULL,
		0xCD8069A98A99E98BULL,
		0x1EF2F7859BA6AC1DULL,
		0x0D8391728E99B8F2ULL,
		0x016CA2A1F60252DCULL
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
		0x289D50BB0630AF06ULL,
		0x026B89A82B660C10ULL,
		0x6121B7989CBB9E3CULL,
		0x87DBF03551A64764ULL,
		0xECCBAFBEC91EE66CULL,
		0xCCFCF4A3CC03F945ULL,
		0x886CE844DDD9D556ULL,
		0x0E718BA4473CD7A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x513AA1760C615E0CULL,
		0x04D7135056CC1820ULL,
		0xC2436F3139773C78ULL,
		0x0FB7E06AA34C8EC8ULL,
		0xD9975F7D923DCCD9ULL,
		0x99F9E9479807F28BULL,
		0x10D9D089BBB3AAADULL,
		0x1CE317488E79AF4BULL
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
		0xD9523593F988B3DEULL,
		0x371A9281D4366AC6ULL,
		0x3A7956C0DCEC2694ULL,
		0xA32237851B835970ULL,
		0x284A1052C26D1950ULL,
		0x2D0FC913B14E1C1EULL,
		0xC8190A0EFC592566ULL,
		0x2D6805671F4A9181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A46B27F31167BCULL,
		0x6E352503A86CD58DULL,
		0x74F2AD81B9D84D28ULL,
		0x46446F0A3706B2E0ULL,
		0x509420A584DA32A1ULL,
		0x5A1F9227629C383CULL,
		0x9032141DF8B24ACCULL,
		0x5AD00ACE3E952303ULL
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
		0xCA0DD826055F28BFULL,
		0x9D0F8EFC363C8C6CULL,
		0x62F6D03375BFB4E8ULL,
		0xEA6B7AD1D81B095CULL,
		0xDF7AF4CB93AFB19BULL,
		0x6B244174F1C5D700ULL,
		0x21A7A710DEE906A9ULL,
		0x09906EAC5B944221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x941BB04C0ABE517EULL,
		0x3A1F1DF86C7918D9ULL,
		0xC5EDA066EB7F69D1ULL,
		0xD4D6F5A3B03612B8ULL,
		0xBEF5E997275F6337ULL,
		0xD64882E9E38BAE01ULL,
		0x434F4E21BDD20D52ULL,
		0x1320DD58B7288442ULL
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
		0xF2FFCE0BC6A84C63ULL,
		0x84CF36E1C4DB0C4AULL,
		0xF7CF7861D7ACB840ULL,
		0xF51590E070301355ULL,
		0x72ED1C83B4D02563ULL,
		0x2EB15327F21FFEA2ULL,
		0xA558910643F5A478ULL,
		0x1B8244F8DD31B647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5FF9C178D5098C6ULL,
		0x099E6DC389B61895ULL,
		0xEF9EF0C3AF597081ULL,
		0xEA2B21C0E06026ABULL,
		0xE5DA390769A04AC7ULL,
		0x5D62A64FE43FFD44ULL,
		0x4AB1220C87EB48F0ULL,
		0x370489F1BA636C8FULL
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
		0xE6619873B9AFBBB4ULL,
		0xB272CBCF81FD80ADULL,
		0xC728525C7EB94722ULL,
		0x11CA2D2983D047BEULL,
		0xC670DE524BAC8B0AULL,
		0x85192FA1BC80ABFAULL,
		0x56876C459D7A9CD4ULL,
		0x20A93F025C67AD20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC330E7735F7768ULL,
		0x64E5979F03FB015BULL,
		0x8E50A4B8FD728E45ULL,
		0x23945A5307A08F7DULL,
		0x8CE1BCA497591614ULL,
		0x0A325F43790157F5ULL,
		0xAD0ED88B3AF539A9ULL,
		0x41527E04B8CF5A40ULL
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
		0x54A438C4A6763F25ULL,
		0x1146AD4FF2F6598AULL,
		0x0F9C4B41DEE71460ULL,
		0x3BFCC19D24691BAAULL,
		0x297E3F393A87154EULL,
		0x64D698B1B7562B97ULL,
		0x78D684A216354E1DULL,
		0x0F72CCBF04758267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA94871894CEC7E4AULL,
		0x228D5A9FE5ECB314ULL,
		0x1F389683BDCE28C0ULL,
		0x77F9833A48D23754ULL,
		0x52FC7E72750E2A9CULL,
		0xC9AD31636EAC572EULL,
		0xF1AD09442C6A9C3AULL,
		0x1EE5997E08EB04CEULL
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
		0xB54F81BCB813CCDDULL,
		0x9A9B336599AFEFE0ULL,
		0xC89E5C4FD65EEC8FULL,
		0x5637609E828FCFFBULL,
		0x86AEC08C234A0A07ULL,
		0x75E62DB2709A0526ULL,
		0xD75FC8CA2C485E38ULL,
		0x2F8EF4C6C98EEA76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9F0379702799BAULL,
		0x353666CB335FDFC1ULL,
		0x913CB89FACBDD91FULL,
		0xAC6EC13D051F9FF7ULL,
		0x0D5D81184694140EULL,
		0xEBCC5B64E1340A4DULL,
		0xAEBF91945890BC70ULL,
		0x5F1DE98D931DD4EDULL
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
		0x15BD5553307BC865ULL,
		0x363B1732B2956D09ULL,
		0x0ABAB5EF3A8A0AE1ULL,
		0x98985E0F45D77342ULL,
		0x85E89B59344EDF65ULL,
		0x4CED99637D661642ULL,
		0xA6AF4BF6A0B60671ULL,
		0x19DAFD78CEB35581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7AAAA660F790CAULL,
		0x6C762E65652ADA12ULL,
		0x15756BDE751415C2ULL,
		0x3130BC1E8BAEE684ULL,
		0x0BD136B2689DBECBULL,
		0x99DB32C6FACC2C85ULL,
		0x4D5E97ED416C0CE2ULL,
		0x33B5FAF19D66AB03ULL
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
		0x2853563F7B87F078ULL,
		0x9CA9D3D3854EE54FULL,
		0x485ADB4A9E09A4D3ULL,
		0x00AA55A1867CAA63ULL,
		0xEC885EC13133965FULL,
		0xA14DB4841DA481DEULL,
		0x1C56875D5BC13515ULL,
		0x1319889B03F5F5BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A6AC7EF70FE0F0ULL,
		0x3953A7A70A9DCA9EULL,
		0x90B5B6953C1349A7ULL,
		0x0154AB430CF954C6ULL,
		0xD910BD8262672CBEULL,
		0x429B69083B4903BDULL,
		0x38AD0EBAB7826A2BULL,
		0x2633113607EBEB74ULL
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
		0x076445586C73B368ULL,
		0xC58A2022E43DFB2DULL,
		0x18FD4E1044AB2484ULL,
		0x55698B22A80E55BCULL,
		0x0A18164DAAFAF76FULL,
		0x7F11479B49C69C8CULL,
		0x5B6E80B74EC7C261ULL,
		0x2B30912DD44ECF0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC88AB0D8E766D0ULL,
		0x8B144045C87BF65AULL,
		0x31FA9C2089564909ULL,
		0xAAD31645501CAB78ULL,
		0x14302C9B55F5EEDEULL,
		0xFE228F36938D3918ULL,
		0xB6DD016E9D8F84C2ULL,
		0x5661225BA89D9E18ULL
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
		0xCFE16EE06421BC63ULL,
		0xF8FFCCD1FB54B189ULL,
		0xA95BFC7A3227D93BULL,
		0xE2177B31BCC409F3ULL,
		0x6E528A44FFE47958ULL,
		0x7F4A28668181862BULL,
		0xF50835A067681AF8ULL,
		0x206BD4DDAA929C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC2DDC0C84378C6ULL,
		0xF1FF99A3F6A96313ULL,
		0x52B7F8F4644FB277ULL,
		0xC42EF663798813E7ULL,
		0xDCA51489FFC8F2B1ULL,
		0xFE9450CD03030C56ULL,
		0xEA106B40CED035F0ULL,
		0x40D7A9BB552538ADULL
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
		0x11110D7E2E57C343ULL,
		0x391456AD9DA9EA69ULL,
		0x958DD873A510C155ULL,
		0x9DBBD7CE69D032DFULL,
		0x2399175C3B3D4398ULL,
		0xBBA74C3530EA75B7ULL,
		0xE977DC575530EE56ULL,
		0x17D9A30815E56373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22221AFC5CAF8686ULL,
		0x7228AD5B3B53D4D2ULL,
		0x2B1BB0E74A2182AAULL,
		0x3B77AF9CD3A065BFULL,
		0x47322EB8767A8731ULL,
		0x774E986A61D4EB6EULL,
		0xD2EFB8AEAA61DCADULL,
		0x2FB346102BCAC6E7ULL
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
		0xB7042F280EDAF0B8ULL,
		0x6CF63456BD90BD7CULL,
		0xC7A29D6BCCA9AF1DULL,
		0xB3122E872E3063BEULL,
		0xAD7839B69F5B081EULL,
		0x03D16C1665CF2729ULL,
		0xB3F2AE173F32AD94ULL,
		0x0E69B1355C36A077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E085E501DB5E170ULL,
		0xD9EC68AD7B217AF9ULL,
		0x8F453AD799535E3AULL,
		0x66245D0E5C60C77DULL,
		0x5AF0736D3EB6103DULL,
		0x07A2D82CCB9E4E53ULL,
		0x67E55C2E7E655B28ULL,
		0x1CD3626AB86D40EFULL
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
		0x82FF32219A9AA773ULL,
		0xD0C8CC976FD27DFCULL,
		0x178DCF6DF7ADC6E2ULL,
		0xF4935A23605B51A5ULL,
		0xAF916B735E457C81ULL,
		0x3174B9F900BD7B15ULL,
		0x311BD4141FBF47B0ULL,
		0x2C86819460BCF30BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05FE644335354EE6ULL,
		0xA191992EDFA4FBF9ULL,
		0x2F1B9EDBEF5B8DC5ULL,
		0xE926B446C0B6A34AULL,
		0x5F22D6E6BC8AF903ULL,
		0x62E973F2017AF62BULL,
		0x6237A8283F7E8F60ULL,
		0x590D0328C179E616ULL
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
		0x6A41E057B5877630ULL,
		0xBA8E05D73026B5A0ULL,
		0x37BEFA1F7C587E6BULL,
		0x702BB38DE48C7886ULL,
		0xF0741D2C68DA9E82ULL,
		0x2B8F5DD0A5302202ULL,
		0x2D69DAC9DFC20102ULL,
		0x09CA9FA225EDBA63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD483C0AF6B0EEC60ULL,
		0x751C0BAE604D6B40ULL,
		0x6F7DF43EF8B0FCD7ULL,
		0xE057671BC918F10CULL,
		0xE0E83A58D1B53D04ULL,
		0x571EBBA14A604405ULL,
		0x5AD3B593BF840204ULL,
		0x13953F444BDB74C6ULL
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
		0x85B86C4DA0C2ADD9ULL,
		0x2439E724A0244E2AULL,
		0x9097F4A452A0F5A9ULL,
		0x519635D926F68225ULL,
		0x851548B0033FA24DULL,
		0x019E904045F45036ULL,
		0xE771791B58A6D47DULL,
		0x00E3FFBCA38EC130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B70D89B41855BB2ULL,
		0x4873CE4940489C55ULL,
		0x212FE948A541EB52ULL,
		0xA32C6BB24DED044BULL,
		0x0A2A9160067F449AULL,
		0x033D20808BE8A06DULL,
		0xCEE2F236B14DA8FAULL,
		0x01C7FF79471D8261ULL
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
		0x01CFFE68993157EEULL,
		0x7DF4762F464C9EDDULL,
		0xC72C82415F9E21B8ULL,
		0x9AE9E67F5390673EULL,
		0x18E1E44E5C3CD629ULL,
		0x1135286774A2CBE4ULL,
		0xC27A7D57FFED8011ULL,
		0x0B7C123E7CFDDDA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x039FFCD13262AFDCULL,
		0xFBE8EC5E8C993DBAULL,
		0x8E590482BF3C4370ULL,
		0x35D3CCFEA720CE7DULL,
		0x31C3C89CB879AC53ULL,
		0x226A50CEE94597C8ULL,
		0x84F4FAAFFFDB0022ULL,
		0x16F8247CF9FBBB49ULL
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
		0x488E5262657514FBULL,
		0x8DD3925C7CA471F8ULL,
		0xC237D66296709AD7ULL,
		0xAF5113A3A2D6AD19ULL,
		0xE57E95DA992F8866ULL,
		0xD46C8BC2CC6B56DEULL,
		0x81B97EF2F2C1B643ULL,
		0x1F4BA9D3E737878DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x911CA4C4CAEA29F6ULL,
		0x1BA724B8F948E3F0ULL,
		0x846FACC52CE135AFULL,
		0x5EA2274745AD5A33ULL,
		0xCAFD2BB5325F10CDULL,
		0xA8D9178598D6ADBDULL,
		0x0372FDE5E5836C87ULL,
		0x3E9753A7CE6F0F1BULL
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
		0xAFC1FF48D0069DD6ULL,
		0x80CB32554DAB39C9ULL,
		0xE2EE580CDC0BCD7EULL,
		0xD2B1C35A60F49147ULL,
		0x6D454900564B313CULL,
		0x793803B7007CCAE5ULL,
		0x0BB82A20F5CE4142ULL,
		0x1847E144506AFE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F83FE91A00D3BACULL,
		0x019664AA9B567393ULL,
		0xC5DCB019B8179AFDULL,
		0xA56386B4C1E9228FULL,
		0xDA8A9200AC966279ULL,
		0xF270076E00F995CAULL,
		0x17705441EB9C8284ULL,
		0x308FC288A0D5FD0AULL
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
		0xC800EFDFF8874437ULL,
		0xEE21EF20E8F1AA79ULL,
		0x9CD5CDFC184296B8ULL,
		0x8D7070C9A08C3554ULL,
		0x0CC6A00970D98CFCULL,
		0xA8A541447E892DE2ULL,
		0x540E69D44E8C2B99ULL,
		0x3FC1F5D1CDF0CCA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9001DFBFF10E886EULL,
		0xDC43DE41D1E354F3ULL,
		0x39AB9BF830852D71ULL,
		0x1AE0E19341186AA9ULL,
		0x198D4012E1B319F9ULL,
		0x514A8288FD125BC4ULL,
		0xA81CD3A89D185733ULL,
		0x7F83EBA39BE1994EULL
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
		0x68353775EC71E6FAULL,
		0xA55F8B3CD05183CBULL,
		0x0C012B77ABE575DDULL,
		0x0BFD0C7782D5D1D4ULL,
		0x658FF5B1BF20F7EDULL,
		0xC285FEC4643257E5ULL,
		0xBB203931761EDEECULL,
		0x19E4EC312C5BE747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06A6EEBD8E3CDF4ULL,
		0x4ABF1679A0A30796ULL,
		0x180256EF57CAEBBBULL,
		0x17FA18EF05ABA3A8ULL,
		0xCB1FEB637E41EFDAULL,
		0x850BFD88C864AFCAULL,
		0x76407262EC3DBDD9ULL,
		0x33C9D86258B7CE8FULL
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
		0xDB095794FBA33DD4ULL,
		0x973681288738C254ULL,
		0xC6F117EFFC4DCA92ULL,
		0x1967A096C7E1C03FULL,
		0x6E7145BEBC12506EULL,
		0xDD48558900555A23ULL,
		0x22D14B639D33080AULL,
		0x19852859C9F0BDC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB612AF29F7467BA8ULL,
		0x2E6D02510E7184A9ULL,
		0x8DE22FDFF89B9525ULL,
		0x32CF412D8FC3807FULL,
		0xDCE28B7D7824A0DCULL,
		0xBA90AB1200AAB446ULL,
		0x45A296C73A661015ULL,
		0x330A50B393E17B8CULL
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
		0x57856DF01D6BE6CDULL,
		0x7CEDAE26E7D03D57ULL,
		0x1E57F8970500ECF2ULL,
		0x94472A3B000D8D01ULL,
		0xF978D071D1E2F279ULL,
		0x0A854CAC8A65D1CAULL,
		0x25A01F57CF3B4129ULL,
		0x0D3154407DA38BECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0ADBE03AD7CD9AULL,
		0xF9DB5C4DCFA07AAEULL,
		0x3CAFF12E0A01D9E4ULL,
		0x288E5476001B1A02ULL,
		0xF2F1A0E3A3C5E4F3ULL,
		0x150A995914CBA395ULL,
		0x4B403EAF9E768252ULL,
		0x1A62A880FB4717D8ULL
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
		0x3E6794A1FD85E1D7ULL,
		0xB735CE81C3A392B6ULL,
		0x634E1965B507AA4FULL,
		0x7F2841DA014A30BCULL,
		0x8E17F0BE9CED1AB1ULL,
		0xC305CA65B8D69A38ULL,
		0xEC7477B61BCBD116ULL,
		0x1567FD53A9F054FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CCF2943FB0BC3AEULL,
		0x6E6B9D038747256CULL,
		0xC69C32CB6A0F549FULL,
		0xFE5083B402946178ULL,
		0x1C2FE17D39DA3562ULL,
		0x860B94CB71AD3471ULL,
		0xD8E8EF6C3797A22DULL,
		0x2ACFFAA753E0A9F9ULL
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
		0x2D47A840F51AC1E2ULL,
		0x16B6BA434DDF94B4ULL,
		0x6B9727711733F8DDULL,
		0xC578464ADF6AB742ULL,
		0x014AE198754A55A7ULL,
		0xF822477427F22408ULL,
		0x94DE6D139713084FULL,
		0x32E66B08D6440321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8F5081EA3583C4ULL,
		0x2D6D74869BBF2968ULL,
		0xD72E4EE22E67F1BAULL,
		0x8AF08C95BED56E84ULL,
		0x0295C330EA94AB4FULL,
		0xF0448EE84FE44810ULL,
		0x29BCDA272E26109FULL,
		0x65CCD611AC880643ULL
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
		0xC6D1A821637BFB02ULL,
		0xF68DA1E1A1461289ULL,
		0xEB31F1AAE9945318ULL,
		0x16395825A499B81BULL,
		0xE94062099819554BULL,
		0xA519DE29430CADCAULL,
		0x35C925826138A292ULL,
		0x312DC6B83D3613E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA35042C6F7F604ULL,
		0xED1B43C3428C2513ULL,
		0xD663E355D328A631ULL,
		0x2C72B04B49337037ULL,
		0xD280C4133032AA96ULL,
		0x4A33BC5286195B95ULL,
		0x6B924B04C2714525ULL,
		0x625B8D707A6C27CCULL
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
		0x0512D895A4FE9978ULL,
		0x1B74254460A45616ULL,
		0x91C6EBAF02C1D749ULL,
		0x597503934872A506ULL,
		0xDBA36FB9E6E285C7ULL,
		0xB2B08F4C48E7CA61ULL,
		0xABE2F2173F9A8291ULL,
		0x0D8679874900B3ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A25B12B49FD32F0ULL,
		0x36E84A88C148AC2CULL,
		0x238DD75E0583AE92ULL,
		0xB2EA072690E54A0DULL,
		0xB746DF73CDC50B8EULL,
		0x65611E9891CF94C3ULL,
		0x57C5E42E7F350523ULL,
		0x1B0CF30E92016757ULL
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
		0x251A74C2197401C7ULL,
		0x6FA2926993DDA007ULL,
		0x07D7B7BCB1E00750ULL,
		0x4B67E0D90CCA843AULL,
		0xE2EA510F30FECCC9ULL,
		0xD7312FE4C155F457ULL,
		0xA15FEB6D1B7E862FULL,
		0x294F9DAA34E87A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A34E98432E8038EULL,
		0xDF4524D327BB400EULL,
		0x0FAF6F7963C00EA0ULL,
		0x96CFC1B219950874ULL,
		0xC5D4A21E61FD9992ULL,
		0xAE625FC982ABE8AFULL,
		0x42BFD6DA36FD0C5FULL,
		0x529F3B5469D0F515ULL
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
		0xDB581B480D23CC14ULL,
		0xE095955AFFE54D90ULL,
		0x901302532F7D1065ULL,
		0xD99CE6194DD03E96ULL,
		0x10AAE7608FEA2B0EULL,
		0x46120015E63531B3ULL,
		0x8ED5327C4E74433AULL,
		0x11C32DEAEB4B74D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B036901A479828ULL,
		0xC12B2AB5FFCA9B21ULL,
		0x202604A65EFA20CBULL,
		0xB339CC329BA07D2DULL,
		0x2155CEC11FD4561DULL,
		0x8C24002BCC6A6366ULL,
		0x1DAA64F89CE88674ULL,
		0x23865BD5D696E9A7ULL
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
		0x9E87CAFE812C2AD0ULL,
		0xC361ECA5A5FF0780ULL,
		0x87F9911D132C430FULL,
		0xC64AA7870AE8C67DULL,
		0x4168A4B16C9D1127ULL,
		0x0AD662FD50EA73CCULL,
		0x43716F1F62357AF3ULL,
		0x167FFBAEF76A02C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0F95FD025855A0ULL,
		0x86C3D94B4BFE0F01ULL,
		0x0FF3223A2658861FULL,
		0x8C954F0E15D18CFBULL,
		0x82D14962D93A224FULL,
		0x15ACC5FAA1D4E798ULL,
		0x86E2DE3EC46AF5E6ULL,
		0x2CFFF75DEED40580ULL
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
		0x6694284FF234F781ULL,
		0xB28C3C53D851C942ULL,
		0x4AFAADBBD40B2274ULL,
		0xA9609A602CB760BBULL,
		0x1CE6ABA2AD018392ULL,
		0x929C2779126FF5A9ULL,
		0xDB06B73594D0EF12ULL,
		0x22C5F1319C0ADBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD28509FE469EF02ULL,
		0x651878A7B0A39284ULL,
		0x95F55B77A81644E9ULL,
		0x52C134C0596EC176ULL,
		0x39CD57455A030725ULL,
		0x25384EF224DFEB52ULL,
		0xB60D6E6B29A1DE25ULL,
		0x458BE2633815B79DULL
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
		0x5CB88603F458F33DULL,
		0x6BD7B50ED1440403ULL,
		0xCCE409F3F382A255ULL,
		0x26756D3FB2F2CA33ULL,
		0xBEA926920FDB3A83ULL,
		0xBED568F29984F4DAULL,
		0x5EB775C0512509DDULL,
		0x0333BBECE76C0406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9710C07E8B1E67AULL,
		0xD7AF6A1DA2880806ULL,
		0x99C813E7E70544AAULL,
		0x4CEADA7F65E59467ULL,
		0x7D524D241FB67506ULL,
		0x7DAAD1E53309E9B5ULL,
		0xBD6EEB80A24A13BBULL,
		0x066777D9CED8080CULL
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
		0x4D71BCF58127177FULL,
		0x3685319879E82A84ULL,
		0x29BBBF80E4560BF9ULL,
		0x6007EE7866D6B6ACULL,
		0x75E7E63CB18CECB2ULL,
		0xA96D1949AE45B5AEULL,
		0xB929F14DA8D01476ULL,
		0x0DAFA2C5414EE903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AE379EB024E2EFEULL,
		0x6D0A6330F3D05508ULL,
		0x53777F01C8AC17F2ULL,
		0xC00FDCF0CDAD6D58ULL,
		0xEBCFCC796319D964ULL,
		0x52DA32935C8B6B5CULL,
		0x7253E29B51A028EDULL,
		0x1B5F458A829DD207ULL
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
		0x02AFE7BB65DBFCB8ULL,
		0x47BEBC018B1C4B88ULL,
		0x7AB83C83E1176CBFULL,
		0x889C4117FB336415ULL,
		0x22E2198AF099C70BULL,
		0xF3F5344BFA251BBFULL,
		0xDA666742E4017AF5ULL,
		0x075D9A92F4FE4557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055FCF76CBB7F970ULL,
		0x8F7D780316389710ULL,
		0xF5707907C22ED97EULL,
		0x1138822FF666C82AULL,
		0x45C43315E1338E17ULL,
		0xE7EA6897F44A377EULL,
		0xB4CCCE85C802F5EBULL,
		0x0EBB3525E9FC8AAFULL
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
		0x4405F3DF4355EF24ULL,
		0xF27A68427EFDDCCAULL,
		0xDBD0CEA0331D14F3ULL,
		0xD0D064464DA8A4F6ULL,
		0xE0F37DF23809B791ULL,
		0x704D1BD2BF0F5358ULL,
		0xE7E4B7E1B92D04ECULL,
		0x0D4FDEDA9F3D7A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x880BE7BE86ABDE48ULL,
		0xE4F4D084FDFBB994ULL,
		0xB7A19D40663A29E7ULL,
		0xA1A0C88C9B5149EDULL,
		0xC1E6FBE470136F23ULL,
		0xE09A37A57E1EA6B1ULL,
		0xCFC96FC3725A09D8ULL,
		0x1A9FBDB53E7AF40BULL
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
		0x40186BC0E4119757ULL,
		0xE5CAD4C2DDC3347BULL,
		0x65AA367663F9E6EEULL,
		0xAC50C8B535730D7AULL,
		0x58B2861D6CAB5C6DULL,
		0x98977A61F1C989E8ULL,
		0x2A0D4E75E8578786ULL,
		0x3282B5A0B3B6019AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8030D781C8232EAEULL,
		0xCB95A985BB8668F6ULL,
		0xCB546CECC7F3CDDDULL,
		0x58A1916A6AE61AF4ULL,
		0xB1650C3AD956B8DBULL,
		0x312EF4C3E39313D0ULL,
		0x541A9CEBD0AF0F0DULL,
		0x65056B41676C0334ULL
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
		0x109641243CFEDF4DULL,
		0xE124229F192C16FAULL,
		0x0322BA82EF0D6B19ULL,
		0x223F3F05292D257BULL,
		0x17CFBF8C5159FCA8ULL,
		0x53204AF703A157A7ULL,
		0xA43A908D988EE124ULL,
		0x21F2EA2D97AC4CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212C824879FDBE9AULL,
		0xC248453E32582DF4ULL,
		0x06457505DE1AD633ULL,
		0x447E7E0A525A4AF6ULL,
		0x2F9F7F18A2B3F950ULL,
		0xA64095EE0742AF4EULL,
		0x4875211B311DC248ULL,
		0x43E5D45B2F589957ULL
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
		0x5B361AEB846A5162ULL,
		0x9033AD178AB5C95FULL,
		0x907A085C37059022ULL,
		0x305E691CD7BE78BFULL,
		0x6B67E2DE1BE16132ULL,
		0xD00A04EA5BB68D80ULL,
		0x69DB78E4BEE51CF0ULL,
		0x0769AB227EDF35F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB66C35D708D4A2C4ULL,
		0x20675A2F156B92BEULL,
		0x20F410B86E0B2045ULL,
		0x60BCD239AF7CF17FULL,
		0xD6CFC5BC37C2C264ULL,
		0xA01409D4B76D1B00ULL,
		0xD3B6F1C97DCA39E1ULL,
		0x0ED35644FDBE6BE2ULL
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
		0x55F7382F529A5BA5ULL,
		0x1D564148E9BEB9FAULL,
		0x825BEACB41CEFD4DULL,
		0x44D0EB6E629DE60EULL,
		0x62C8A35EA3FC4AD9ULL,
		0xDD39A4A78CD3ED2EULL,
		0x51940E8F5C9FA760ULL,
		0x22165E16BDE47CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABEE705EA534B74AULL,
		0x3AAC8291D37D73F4ULL,
		0x04B7D596839DFA9AULL,
		0x89A1D6DCC53BCC1DULL,
		0xC59146BD47F895B2ULL,
		0xBA73494F19A7DA5CULL,
		0xA3281D1EB93F4EC1ULL,
		0x442CBC2D7BC8F9ECULL
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
		0xF5C0CDAD03B7C087ULL,
		0x7C57B189F942288CULL,
		0x018BA735455F2B2AULL,
		0x2164F6B87327EDE3ULL,
		0xDF33729358CD3613ULL,
		0x40524F0040424B75ULL,
		0x38EAC8869E8EFA5CULL,
		0x1BF8E2BE3E02D01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB819B5A076F810EULL,
		0xF8AF6313F2845119ULL,
		0x03174E6A8ABE5654ULL,
		0x42C9ED70E64FDBC6ULL,
		0xBE66E526B19A6C26ULL,
		0x80A49E00808496EBULL,
		0x71D5910D3D1DF4B8ULL,
		0x37F1C57C7C05A03CULL
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
		0x824896558F168E5FULL,
		0xD27E1086B2C1391EULL,
		0x8CC3A6C7527974E0ULL,
		0x849532F9247E5460ULL,
		0x404C8E6F1C61D5E6ULL,
		0x81C00D379646C577ULL,
		0xD9BE91DE0D3A1352ULL,
		0x19862B5381D857E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04912CAB1E2D1CBEULL,
		0xA4FC210D6582723DULL,
		0x19874D8EA4F2E9C1ULL,
		0x092A65F248FCA8C1ULL,
		0x80991CDE38C3ABCDULL,
		0x03801A6F2C8D8AEEULL,
		0xB37D23BC1A7426A5ULL,
		0x330C56A703B0AFCBULL
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
		0xEF5E820D7860EFACULL,
		0xE3FF7F2FBDCE88BEULL,
		0x238992767B35F3C7ULL,
		0x119BB9F6155F1C33ULL,
		0xEA99E11F8CC791B2ULL,
		0xA1DE14C8A35D6F00ULL,
		0x99292C639787E7A8ULL,
		0x38A3C0EF3869A563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBD041AF0C1DF58ULL,
		0xC7FEFE5F7B9D117DULL,
		0x471324ECF66BE78FULL,
		0x233773EC2ABE3866ULL,
		0xD533C23F198F2364ULL,
		0x43BC299146BADE01ULL,
		0x325258C72F0FCF51ULL,
		0x714781DE70D34AC7ULL
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
		0xA6029D8E05AD160BULL,
		0xED202F48CCAD93A5ULL,
		0x69E31BFD115BEF81ULL,
		0x50D5EB2D1E8BE006ULL,
		0x1FE9370385FE5E7DULL,
		0xDB8E305CB221853AULL,
		0x534269E25520BE2AULL,
		0x3A19BD6402835848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C053B1C0B5A2C16ULL,
		0xDA405E91995B274BULL,
		0xD3C637FA22B7DF03ULL,
		0xA1ABD65A3D17C00CULL,
		0x3FD26E070BFCBCFAULL,
		0xB71C60B964430A74ULL,
		0xA684D3C4AA417C55ULL,
		0x74337AC80506B090ULL
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
		0xAEE18150E03274B9ULL,
		0xBA5BA94BBCD98E34ULL,
		0x7FD087676BE976A7ULL,
		0x72679AA4C1C55928ULL,
		0x316B6B39AA1D494AULL,
		0x7065FE152732D423ULL,
		0x1FF0441F8A8853BBULL,
		0x2DEE9A334FC63568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC302A1C064E972ULL,
		0x74B7529779B31C69ULL,
		0xFFA10ECED7D2ED4FULL,
		0xE4CF3549838AB250ULL,
		0x62D6D673543A9294ULL,
		0xE0CBFC2A4E65A846ULL,
		0x3FE0883F1510A776ULL,
		0x5BDD34669F8C6AD0ULL
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
		0xA3DC48B6E09FDD1BULL,
		0x0574DAB42AB3E364ULL,
		0x8E51799A65392577ULL,
		0xCA3C248783000F01ULL,
		0x1443A86E13132DBBULL,
		0x443D7815BA9ABF5CULL,
		0xD6AE8CED2442ED00ULL,
		0x12D14F769A150F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B8916DC13FBA36ULL,
		0x0AE9B5685567C6C9ULL,
		0x1CA2F334CA724AEEULL,
		0x9478490F06001E03ULL,
		0x288750DC26265B77ULL,
		0x887AF02B75357EB8ULL,
		0xAD5D19DA4885DA00ULL,
		0x25A29EED342A1EABULL
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
		0xC990BFE400624E5BULL,
		0xB8C9C8957AB2228FULL,
		0x9B22607F97F24EACULL,
		0x94157AD34797B51EULL,
		0x95AA5A2C88C5D4E1ULL,
		0x40389E2724F1B072ULL,
		0xEBECA10A043646B2ULL,
		0x01BF30B5EA47A69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93217FC800C49CB6ULL,
		0x7193912AF564451FULL,
		0x3644C0FF2FE49D59ULL,
		0x282AF5A68F2F6A3DULL,
		0x2B54B459118BA9C3ULL,
		0x80713C4E49E360E5ULL,
		0xD7D94214086C8D64ULL,
		0x037E616BD48F4D39ULL
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
		0x269028E68474E66EULL,
		0xEC2DEB95876C6D05ULL,
		0x12C6AC94520B4582ULL,
		0x4D13805A64C3315DULL,
		0x512C0E568AA237DEULL,
		0xDCCF20851F572080ULL,
		0x6802CB204CA2B94AULL,
		0x39048840EAA1062EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D2051CD08E9CCDCULL,
		0xD85BD72B0ED8DA0AULL,
		0x258D5928A4168B05ULL,
		0x9A2700B4C98662BAULL,
		0xA2581CAD15446FBCULL,
		0xB99E410A3EAE4100ULL,
		0xD005964099457295ULL,
		0x72091081D5420C5CULL
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
		0x3DCB44651755894EULL,
		0x78749B72FDF65FF9ULL,
		0x5DAA93924A3DC431ULL,
		0x7C70A22F261BCE6DULL,
		0xA0A43C6BEC8C733FULL,
		0x45C7F7A796759D06ULL,
		0x58B6B8784EF687E2ULL,
		0x20E7EA8A58D48E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B9688CA2EAB129CULL,
		0xF0E936E5FBECBFF2ULL,
		0xBB552724947B8862ULL,
		0xF8E1445E4C379CDAULL,
		0x414878D7D918E67EULL,
		0x8B8FEF4F2CEB3A0DULL,
		0xB16D70F09DED0FC4ULL,
		0x41CFD514B1A91CE0ULL
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
		0xD390A51D7673BB0EULL,
		0x206ED1F4D733007AULL,
		0x39926A4737A7B7A9ULL,
		0xD9FE14E300E087D8ULL,
		0xE4CCD491C7BCD31EULL,
		0x22E62DC2B317E558ULL,
		0x6050E9092D72C9EDULL,
		0x25B69C0BDF9746A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7214A3AECE7761CULL,
		0x40DDA3E9AE6600F5ULL,
		0x7324D48E6F4F6F52ULL,
		0xB3FC29C601C10FB0ULL,
		0xC999A9238F79A63DULL,
		0x45CC5B85662FCAB1ULL,
		0xC0A1D2125AE593DAULL,
		0x4B6D3817BF2E8D4CULL
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
		0x5DB8580AE0025C94ULL,
		0xA059D5555B81A030ULL,
		0x42D9305C6D9357FDULL,
		0xF5AC3D22CBFBC6DDULL,
		0x4E54251F3A171D71ULL,
		0x15C8DE6DBF48BAA9ULL,
		0x88C3251A7F44B311ULL,
		0x37C923BE58124346ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB70B015C004B928ULL,
		0x40B3AAAAB7034060ULL,
		0x85B260B8DB26AFFBULL,
		0xEB587A4597F78DBAULL,
		0x9CA84A3E742E3AE3ULL,
		0x2B91BCDB7E917552ULL,
		0x11864A34FE896622ULL,
		0x6F92477CB024868DULL
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
		0x4A08B9B4FC5C66B5ULL,
		0x71509C6E9BA2D69CULL,
		0x63AE14CF1AF12C7CULL,
		0x0EDC80069BEE3934ULL,
		0x4DEB41CC269850B1ULL,
		0xBD282BF003D66658ULL,
		0x7F9C2E649113B8F7ULL,
		0x2223421AED9281EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94117369F8B8CD6AULL,
		0xE2A138DD3745AD38ULL,
		0xC75C299E35E258F8ULL,
		0x1DB9000D37DC7268ULL,
		0x9BD683984D30A162ULL,
		0x7A5057E007ACCCB0ULL,
		0xFF385CC9222771EFULL,
		0x44468435DB2503DCULL
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
		0xC840165C6198B8D1ULL,
		0xE341AB733CF53C44ULL,
		0xBA6C28B95FBA9800ULL,
		0x208DA76D7FFD724CULL,
		0xF29FFA5AC9F62F4BULL,
		0x03DC2211984B18A1ULL,
		0x53418880C7C1450BULL,
		0x03C9494AC95E4AE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90802CB8C33171A2ULL,
		0xC68356E679EA7889ULL,
		0x74D85172BF753001ULL,
		0x411B4EDAFFFAE499ULL,
		0xE53FF4B593EC5E96ULL,
		0x07B8442330963143ULL,
		0xA68311018F828A16ULL,
		0x0792929592BC95C2ULL
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
		0x7E39D385EA51F4C9ULL,
		0x9066F6DEEED1E546ULL,
		0x2E6560151D72EEC9ULL,
		0xC0FA2C8825494845ULL,
		0xE10AE2BFD7E65A2FULL,
		0x8A71001C7173D5D4ULL,
		0xBA29094B5B2C80C7ULL,
		0x2EB491C6AB0C6C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC73A70BD4A3E992ULL,
		0x20CDEDBDDDA3CA8CULL,
		0x5CCAC02A3AE5DD93ULL,
		0x81F459104A92908AULL,
		0xC215C57FAFCCB45FULL,
		0x14E20038E2E7ABA9ULL,
		0x74521296B659018FULL,
		0x5D69238D5618D893ULL
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
		0xA6EABBE877EFEBB2ULL,
		0x9E9EAA33890EE5FEULL,
		0x2A3D75C1F5041F2DULL,
		0xF7A768CE411EFD91ULL,
		0x73636C9C00A5DBA6ULL,
		0xF1D03BAD3FF0E30DULL,
		0xD207272145442D4EULL,
		0x06FC053F5DD8D6CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD577D0EFDFD764ULL,
		0x3D3D5467121DCBFDULL,
		0x547AEB83EA083E5BULL,
		0xEF4ED19C823DFB22ULL,
		0xE6C6D938014BB74DULL,
		0xE3A0775A7FE1C61AULL,
		0xA40E4E428A885A9DULL,
		0x0DF80A7EBBB1AD97ULL
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
		0x4FCF02F58F74AB30ULL,
		0xE0F9502D5F12AC1AULL,
		0x38B3EF074D9B4DA1ULL,
		0xB2A1685E3C9783ABULL,
		0x2ACC07A994E19C3CULL,
		0x6B87BC353D3CA809ULL,
		0x5DC002F6911ADED0ULL,
		0x25D54C34E0263B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9E05EB1EE95660ULL,
		0xC1F2A05ABE255834ULL,
		0x7167DE0E9B369B43ULL,
		0x6542D0BC792F0756ULL,
		0x55980F5329C33879ULL,
		0xD70F786A7A795012ULL,
		0xBB8005ED2235BDA0ULL,
		0x4BAA9869C04C761EULL
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
		0x199D67D32828A33FULL,
		0xEFED31E97EB4CB4EULL,
		0x8FF51C148E0F7655ULL,
		0xA05AEC0F4E05703AULL,
		0x1A1890CD5513B622ULL,
		0x2AFCCA006CD4ED79ULL,
		0x33E07BEB7116B158ULL,
		0x1F7679C9034F7C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x333ACFA65051467EULL,
		0xDFDA63D2FD69969CULL,
		0x1FEA38291C1EECABULL,
		0x40B5D81E9C0AE075ULL,
		0x3431219AAA276C45ULL,
		0x55F99400D9A9DAF2ULL,
		0x67C0F7D6E22D62B0ULL,
		0x3EECF392069EF85EULL
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
		0x3A9253BC9879E91EULL,
		0xC278DDD2A3515614ULL,
		0xBB57A58DC5C86FCBULL,
		0xD077219C17486560ULL,
		0xCA1716C3D1D762F2ULL,
		0x75D0BBCFF9ED8A4FULL,
		0xFD878CBA1D12BDF3ULL,
		0x3C5ED0D753259A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7524A77930F3D23CULL,
		0x84F1BBA546A2AC28ULL,
		0x76AF4B1B8B90DF97ULL,
		0xA0EE43382E90CAC1ULL,
		0x942E2D87A3AEC5E5ULL,
		0xEBA1779FF3DB149FULL,
		0xFB0F19743A257BE6ULL,
		0x78BDA1AEA64B347BULL
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
		0x432300F853A6AF87ULL,
		0x241F70C5B2DA53CDULL,
		0xF5CD844CBEFC6D85ULL,
		0x093DD5C58BD9F619ULL,
		0x602AFDE7407615E6ULL,
		0x22E3AC644C4A12DAULL,
		0x13D0A99462C45A35ULL,
		0x0522C67EEE556273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864601F0A74D5F0EULL,
		0x483EE18B65B4A79AULL,
		0xEB9B08997DF8DB0AULL,
		0x127BAB8B17B3EC33ULL,
		0xC055FBCE80EC2BCCULL,
		0x45C758C8989425B4ULL,
		0x27A15328C588B46AULL,
		0x0A458CFDDCAAC4E6ULL
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
		0xA587F69AA93887CBULL,
		0x6D269E217F354DF2ULL,
		0x52AA8E19BCACAA4EULL,
		0x100DC0DF4D6E7171ULL,
		0x7C4CB9F28E01B15BULL,
		0x478CFD482965D0A7ULL,
		0x2834B0DA422C4317ULL,
		0x346BA4900DB24A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0FED3552710F96ULL,
		0xDA4D3C42FE6A9BE5ULL,
		0xA5551C337959549CULL,
		0x201B81BE9ADCE2E2ULL,
		0xF89973E51C0362B6ULL,
		0x8F19FA9052CBA14EULL,
		0x506961B48458862EULL,
		0x68D749201B64947AULL
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
		0x69EF68CDB92D88F8ULL,
		0xB18384B1891AE4B9ULL,
		0x9EF09B6F4EC737CAULL,
		0xDD411952049A958CULL,
		0xC1A37EEEA92BAE14ULL,
		0x71BD26836B749B79ULL,
		0xC9ED9C14B316043FULL,
		0x261AAB4EE6C4FE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3DED19B725B11F0ULL,
		0x630709631235C972ULL,
		0x3DE136DE9D8E6F95ULL,
		0xBA8232A409352B19ULL,
		0x8346FDDD52575C29ULL,
		0xE37A4D06D6E936F3ULL,
		0x93DB3829662C087EULL,
		0x4C35569DCD89FC83ULL
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
		0xBA08728BB6355357ULL,
		0xBDDD87CD5EE69FE2ULL,
		0x6C5A2BA253BC9244ULL,
		0xC64FD2EFDAC8F1C2ULL,
		0xA6B6A15B24A4069DULL,
		0xDF6F31C7CC5C50EDULL,
		0x216ED11AC0AE0B54ULL,
		0x31177ECD3FD77C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7410E5176C6AA6AEULL,
		0x7BBB0F9ABDCD3FC5ULL,
		0xD8B45744A7792489ULL,
		0x8C9FA5DFB591E384ULL,
		0x4D6D42B649480D3BULL,
		0xBEDE638F98B8A1DBULL,
		0x42DDA235815C16A9ULL,
		0x622EFD9A7FAEF866ULL
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
		0x21BEEB319BCE6F9BULL,
		0xBC93B9E62059ADDFULL,
		0xA1051B8D981AD210ULL,
		0x626C8D65419D5A1DULL,
		0xC64D7B1193EA2B9CULL,
		0x49E0FAD7E8310179ULL,
		0xC0AAB6BA4FBEF43BULL,
		0x1D9CD2C6633CA908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437DD663379CDF36ULL,
		0x792773CC40B35BBEULL,
		0x420A371B3035A421ULL,
		0xC4D91ACA833AB43BULL,
		0x8C9AF62327D45738ULL,
		0x93C1F5AFD06202F3ULL,
		0x81556D749F7DE876ULL,
		0x3B39A58CC6795211ULL
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
		0xFEE06352702333C1ULL,
		0xC8191693EC341164ULL,
		0x906F305A41CAECD0ULL,
		0x2E3C9AC3B6730A32ULL,
		0x823ADC28B6EA198DULL,
		0xF4D84D35F477CBD3ULL,
		0x825223000584C256ULL,
		0x371F28BF6A563272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC0C6A4E0466782ULL,
		0x90322D27D86822C9ULL,
		0x20DE60B48395D9A1ULL,
		0x5C7935876CE61465ULL,
		0x0475B8516DD4331AULL,
		0xE9B09A6BE8EF97A7ULL,
		0x04A446000B0984ADULL,
		0x6E3E517ED4AC64E5ULL
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
		0x6C2F2C208D4F6786ULL,
		0x5235EAD1AC5258F8ULL,
		0x71A8CEF654C4A19FULL,
		0x4C89668112675219ULL,
		0x07224B58B5BC0DE0ULL,
		0x73EB0C4241B5A4D3ULL,
		0xDF5E95F444A00AB0ULL,
		0x3FDD05FC1398D492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85E58411A9ECF0CULL,
		0xA46BD5A358A4B1F0ULL,
		0xE3519DECA989433EULL,
		0x9912CD0224CEA432ULL,
		0x0E4496B16B781BC0ULL,
		0xE7D61884836B49A6ULL,
		0xBEBD2BE889401560ULL,
		0x7FBA0BF82731A925ULL
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
		0x7390B5838AACAC0BULL,
		0x79910E385297A67CULL,
		0xD24CB470BE74EDD1ULL,
		0x5D6B2035A2A99BCCULL,
		0x975A04DDA19FE966ULL,
		0xC41B007FD5AEE1E4ULL,
		0xF63888FFAAAE052CULL,
		0x34A5707D14471044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7216B0715595816ULL,
		0xF3221C70A52F4CF8ULL,
		0xA49968E17CE9DBA2ULL,
		0xBAD6406B45533799ULL,
		0x2EB409BB433FD2CCULL,
		0x883600FFAB5DC3C9ULL,
		0xEC7111FF555C0A59ULL,
		0x694AE0FA288E2089ULL
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
		0xC88782746E1CC7E5ULL,
		0xE17BFA1CD18C9EEFULL,
		0x9BBFDFD281FBC314ULL,
		0xC4A30870A18240A4ULL,
		0x9238B111AA33F446ULL,
		0xFDC4193C715A4FA1ULL,
		0x8F8B15643FB5BCA7ULL,
		0x1A43C27D4A115426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x910F04E8DC398FCAULL,
		0xC2F7F439A3193DDFULL,
		0x377FBFA503F78629ULL,
		0x894610E143048149ULL,
		0x247162235467E88DULL,
		0xFB883278E2B49F43ULL,
		0x1F162AC87F6B794FULL,
		0x348784FA9422A84DULL
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
		0xCFA4B527EC6FF889ULL,
		0xC8A3A1E1B3E9DBD0ULL,
		0x2583015FEB621DB7ULL,
		0x1AC8B2DC00FAFEB0ULL,
		0x7A04685EA4A73B3FULL,
		0xD5CD26DD95FF6994ULL,
		0x972BBB9AEDCE99DAULL,
		0x06677DE3888AA3D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F496A4FD8DFF112ULL,
		0x914743C367D3B7A1ULL,
		0x4B0602BFD6C43B6FULL,
		0x359165B801F5FD60ULL,
		0xF408D0BD494E767EULL,
		0xAB9A4DBB2BFED328ULL,
		0x2E577735DB9D33B5ULL,
		0x0CCEFBC7111547B1ULL
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
		0x14FEC2C1816DA19CULL,
		0x3BB0CCB1EBEFF82BULL,
		0xB60B5107D2A9D55AULL,
		0xC7D9FFA96E25E3A2ULL,
		0xCDDC827791907A0FULL,
		0x8C790C4BA40A30ADULL,
		0x3348B22A24B67484ULL,
		0x2B8AF0D46CB1A249ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FD858302DB4338ULL,
		0x77619963D7DFF056ULL,
		0x6C16A20FA553AAB4ULL,
		0x8FB3FF52DC4BC745ULL,
		0x9BB904EF2320F41FULL,
		0x18F218974814615BULL,
		0x66916454496CE909ULL,
		0x5715E1A8D9634492ULL
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