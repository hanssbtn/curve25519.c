#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F2446AACCA64AC5ULL,
		0x3153FFE65140C750ULL,
		0xDE76496E93C9DC3FULL,
		0x7EC66C65E5D338A0ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x3556653256280000ULL,
		0xFF328A063A807922ULL,
		0x4B749E4EE1F98A9FULL,
		0x632F2E99C506F3B2ULL,
		0x000000000003F633ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int shift = 173;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD44374D9328EE29ULL,
		0x6975005A2DAF6164ULL,
		0xD590182894D5A48CULL,
		0x4CEA3C6A09C8406DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C99477148000000ULL,
		0xD16D7B0B25EA21BAULL,
		0x44A6AD24634BA802ULL,
		0x504E42036EAC80C1ULL,
		0x00000000026751E3ULL
	}};
	shift = 37;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64B7CEC261119A32ULL,
		0x55FC240DF3655D73ULL,
		0x92BE3C12DEABCE65ULL,
		0x4F6755FF18A895C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x6C96F9D84C223346ULL,
		0xAABF8481BE6CABAEULL,
		0x7257C7825BD579CCULL,
		0x09ECEABFE31512B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89E1A4A55B43AB1EULL,
		0xE5F1DB7ECBE17D74ULL,
		0x2786861252F30F99ULL,
		0x45B210805E4D46B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C3494AB687563CULL,
		0xCBE3B6FD97C2FAE9ULL,
		0x4F0D0C24A5E61F33ULL,
		0x8B642100BC9A8D68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FFF8D49F87B5EA7ULL,
		0xE83B2C2ECFF4AEB2ULL,
		0x5381C9A3EB42AEC3ULL,
		0x932AA8E54D2A3BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB5EA700000000000ULL,
		0x4AEB26FFF8D49F87ULL,
		0x2AEC3E83B2C2ECFFULL,
		0xA3BE15381C9A3EB4ULL,
		0x00000932AA8E54D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5573B16106A7FECULL,
		0x2EE0FB0C3E2F1D31ULL,
		0x6707FDD0E5176853ULL,
		0xAD152DC13A5BDF58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE762C20D4FFD800ULL,
		0xC1F6187C5E3A638AULL,
		0x0FFBA1CA2ED0A65DULL,
		0x2A5B8274B7BEB0CEULL,
		0x000000000000015AULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E16BE39DFD080FBULL,
		0x8594CEFEE78ABFC2ULL,
		0x05B1E448B248390DULL,
		0x4FB3B45C40AF93E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x101F600000000000ULL,
		0x57F843C2D7C73BFAULL,
		0x0721B0B299DFDCF1ULL,
		0xF27C60B63C891649ULL,
		0x000009F6768B8815ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF3601E6EB0DF581ULL,
		0x2B80E01E995F2B5AULL,
		0xD32528A136F5DE49ULL,
		0x554404DAE680974CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC37D60400000000ULL,
		0x657CAD6B7CD8079BULL,
		0xDBD77924AE03807AULL,
		0x9A025D334C94A284ULL,
		0x000000015510136BULL
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12E67CE07EF0810BULL,
		0xEC4DD80F88F1CC9CULL,
		0x41682643B6F46CA4ULL,
		0xE6DB99855F0CE32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0FDE102160000000ULL,
		0xF11E3993825CCF9CULL,
		0x76DE8D949D89BB01ULL,
		0xABE19C65882D04C8ULL,
		0x000000001CDB7330ULL
	}};
	shift = 35;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A01BA430A0EFBAFULL,
		0x33DD9ABCE4528F6FULL,
		0x4F6B528528FB60B0ULL,
		0xBC36DE4F8847F828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xE14037486141DF75ULL,
		0x067BB3579C8A51EDULL,
		0x09ED6A50A51F6C16ULL,
		0x1786DBC9F108FF05ULL
	}};
	shift = 3;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE68793D876D2822ULL,
		0xA92C5F3F67778568ULL,
		0x3365504ACBB263F6ULL,
		0xE89B719AB2096E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4400000000000000ULL,
		0xD1BCD0F27B0EDA50ULL,
		0xED5258BE7ECEEF0AULL,
		0x9266CAA0959764C7ULL,
		0x01D136E3356412DCULL
	}};
	shift = 7;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB5B15D615CA713AULL,
		0x8C2811F14C572EA8ULL,
		0x9D34A0D64F8BBB22ULL,
		0x43549C8062FC42BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94E2740000000000ULL,
		0xAE5D51B6B62BAC2BULL,
		0x177645185023E298ULL,
		0xF885773A6941AC9FULL,
		0x00000086A93900C5ULL
	}};
	shift = 23;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA57B5C16BD0EAF50ULL,
		0x6A37CE8E43F4C4D9ULL,
		0x6802ACB83142F750ULL,
		0xD99299E40816B2D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x6695ED705AF43ABDULL,
		0x41A8DF3A390FD313ULL,
		0x55A00AB2E0C50BDDULL,
		0x03664A6790205ACBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x975498A2AE947909ULL,
		0x95899D86AEB974CBULL,
		0x3BDBB4B78C642EB5ULL,
		0x9FEB1332320723DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x931455D28F212000ULL,
		0x33B0D5D72E9972EAULL,
		0x7696F18C85D6B2B1ULL,
		0x62664640E47BE77BULL,
		0x00000000000013FDULL,
		0x0000000000000000ULL
	}};
	shift = 115;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x434F8538E72ED113ULL,
		0xA46187A99F42D60DULL,
		0x8C2609CDF5F59177ULL,
		0x8398C8DFA355FAB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE5DA226000000000ULL,
		0xE85AC1A869F0A71CULL,
		0xBEB22EF48C30F533ULL,
		0x6ABF571184C139BEULL,
		0x0000001073191BF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDCFB8F8C9338E615ULL,
		0xEE25EF4C07C511BBULL,
		0x68750FE6514D34ACULL,
		0xE2BAA88E9DBB2EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF192671CC2A00000ULL,
		0xE980F8A2377B9F71ULL,
		0xFCCA29A6959DC4BDULL,
		0x11D3B765DFAD0EA1ULL,
		0x00000000001C5755ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2154F6837007555AULL,
		0xA3B997EF3FA7A383ULL,
		0xB173518E09643356ULL,
		0x5A8254CDFB3491A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00EAAB400000000ULL,
		0x7F4F470642A9ED06ULL,
		0x12C866AD47732FDEULL,
		0xF669234362E6A31CULL,
		0x00000000B504A99BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD010E27B6FA376CBULL,
		0xE467A9B652205F86ULL,
		0xDAA4BD27B84A97A7ULL,
		0x135536FE2DD92653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDF46ED9600000000ULL,
		0xA440BF0DA021C4F6ULL,
		0x70952F4FC8CF536CULL,
		0x5BB24CA7B5497A4FULL,
		0x0000000026AA6DFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA2E249EF14FA161ULL,
		0xB3033CE6B5A2059EULL,
		0x23CA2C4BA32B0C3AULL,
		0x45D3F90B20CB51D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6100000000000000ULL,
		0x9EFA2E249EF14FA1ULL,
		0x3AB3033CE6B5A205ULL,
		0xD023CA2C4BA32B0CULL,
		0x0045D3F90B20CB51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2F08805766FEB42ULL,
		0x4B0AA1756CBFA316ULL,
		0x0436B14B4D53EEE7ULL,
		0x878802E88B4E93F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDFD684000000000ULL,
		0x97F462DA5E1100AEULL,
		0xAA7DDCE961542EADULL,
		0x69D27E0086D62969ULL,
		0x00000010F1005D11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x514B9DFE1B194EA9ULL,
		0xFCDFD4915A2BD231ULL,
		0x4A8A42E347FB1C6FULL,
		0xF7FD6D8F85C2DF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x94EA900000000000ULL,
		0xBD231514B9DFE1B1ULL,
		0xB1C6FFCDFD4915A2ULL,
		0x2DF014A8A42E347FULL,
		0x00000F7FD6D8F85CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C0F638E7EC4D24FULL,
		0x01BF94B36908F9E5ULL,
		0x90688B4DA826318AULL,
		0x30DFDDD7FEDFF39EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE39FB13493C00000ULL,
		0x2CDA423E794F03D8ULL,
		0xD36A098C62806FE5ULL,
		0x75FFB7FCE7A41A22ULL,
		0x00000000000C37F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x605C3F2BB0E15D75ULL,
		0x56DEA73101A68716ULL,
		0x6BF9ACB931F1273EULL,
		0x6E99D9A4A6528F2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8170FCAEC38575D4ULL,
		0x5B7A9CC4069A1C59ULL,
		0xAFE6B2E4C7C49CF9ULL,
		0xBA676692994A3CB9ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE3AF88DBC1FA4CDULL,
		0x125121329DE157C4ULL,
		0xF3E1A1705605602AULL,
		0xB418A0E1CA1ACDE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8DBC1FA4CD000000ULL,
		0x329DE157C4FE3AF8ULL,
		0x705605602A125121ULL,
		0xE1CA1ACDE2F3E1A1ULL,
		0x0000000000B418A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A448ACCC69B0813ULL,
		0x4F4B7EA9B616CB01ULL,
		0x7196ED82450C127AULL,
		0xC166B42137AA2B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC204C00000000000ULL,
		0xB2C0669122B331A6ULL,
		0x049E93D2DFAA6D85ULL,
		0x8AC41C65BB609143ULL,
		0x00003059AD084DEAULL,
		0x0000000000000000ULL
	}};
	shift = 82;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3CCF10AEBFAF71EULL,
		0x70227AB7A1DA1191ULL,
		0xBCB735B316CF1921ULL,
		0xC171982DF13EC0E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0AEBFAF71E000000ULL,
		0xB7A1DA1191A3CCF1ULL,
		0xB316CF192170227AULL,
		0x2DF13EC0E1BCB735ULL,
		0x0000000000C17198ULL
	}};
	shift = 40;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4366AEC8EDE2A1C1ULL,
		0x985A7ED77DFAB418ULL,
		0x16B08CDC54FC44FFULL,
		0xEFEC23CBF24A1C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3576476F150E08ULL,
		0xC2D3F6BBEFD5A0C2ULL,
		0xB58466E2A7E227FCULL,
		0x7F611E5F9250E3B8ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF12DD5E03BD4D45ULL,
		0xB4FCE9E96D8D2568ULL,
		0xE615DED5881BED69ULL,
		0x9C5B68C7DD16FA6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x6F896EAF01DEA6A2ULL,
		0xDA7E74F4B6C692B4ULL,
		0x730AEF6AC40DF6B4ULL,
		0x4E2DB463EE8B7D37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2532E6CB5B85443ULL,
		0xCCF8D4C4CBAA98FAULL,
		0x66F7BBBE16025761ULL,
		0x6B6609136E52CFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE2532E6CB5B85443ULL,
		0xCCF8D4C4CBAA98FAULL,
		0x66F7BBBE16025761ULL,
		0x6B6609136E52CFF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD645028603E9B48ULL,
		0xE6A6182F771D3B73ULL,
		0xC53476174AB6E203ULL,
		0xA1839A0E6F95166BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x140A180FA6D20000ULL,
		0x860BDDC74EDCF359ULL,
		0x1D85D2ADB880F9A9ULL,
		0xE6839BE5459AF14DULL,
		0x0000000000002860ULL
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72DE21DE93FA9140ULL,
		0xD19E01B80349CC3EULL,
		0x31BE2C783714C728ULL,
		0xECF9CF78D0A9CDA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE72DE21DE93FA914ULL,
		0x8D19E01B80349CC3ULL,
		0x731BE2C783714C72ULL,
		0x0ECF9CF78D0A9CDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BFC3B0CA5FF0995ULL,
		0x5C07540A27D809D3ULL,
		0x722F719881B4DAB3ULL,
		0x3FDC94BBCD57FD38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA80000000000000ULL,
		0xE9CDFE1D8652FF84ULL,
		0x59AE03AA0513EC04ULL,
		0x9C3917B8CC40DA6DULL,
		0x001FEE4A5DE6ABFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA468A663D879EB1ULL,
		0x5820A50E026F5A2BULL,
		0xDD2FC385D3271CF3ULL,
		0xCE89396AC747BA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2998F61E7AC40000ULL,
		0x943809BD68AFA91AULL,
		0x0E174C9C73CD6082ULL,
		0xE5AB1D1EE9FF74BFULL,
		0x0000000000033A24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61E0B297316BB84DULL,
		0x529A3018BD901441ULL,
		0x4EDFC30DE311CA04ULL,
		0xAFD3E3B638307AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x652E62D7709A0000ULL,
		0x60317B202882C3C1ULL,
		0x861BC6239408A534ULL,
		0xC76C7060F56A9DBFULL,
		0x0000000000015FA7ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62BA22518E0614DBULL,
		0x87F743C8CFEABF42ULL,
		0xC19ACBB0745EEF59ULL,
		0xD2EAB8131C68F6F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C00000000000000ULL,
		0x098AE88946381853ULL,
		0x661FDD0F233FAAFDULL,
		0xE7066B2EC1D17BBDULL,
		0x034BAAE04C71A3DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A915CFBAACCB186ULL,
		0xF65B42DAE408C4C0ULL,
		0x5F6E8FB4A6606D2EULL,
		0x351E5808CBEF2DB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x30C0000000000000ULL,
		0x9803522B9F755996ULL,
		0xA5DECB685B5C8118ULL,
		0xB64BEDD1F694CC0DULL,
		0x0006A3CB01197DE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E42098E53DFE028ULL,
		0xEDED5CCE865ABBE6ULL,
		0xDC26943FC9E3CCFCULL,
		0x6EBA3D339E7A18C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x94F7F80A00000000ULL,
		0xA196AEF99B908263ULL,
		0xF278F33F3B7B5733ULL,
		0xE79E86323709A50FULL,
		0x000000001BAE8F4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FBCF631812368D6ULL,
		0xC5A7C0517083C8A6ULL,
		0xA3442BAADE419D36ULL,
		0xB24B668318FD0952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8C6048DA3580000ULL,
		0x0145C20F2299FEF3ULL,
		0xAEAB790674DB169FULL,
		0x9A0C63F4254A8D10ULL,
		0x000000000002C92DULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9CDA15E8ADEAC7C3ULL,
		0xF50CE00B0F2B975FULL,
		0x5AF44C7781A452F5ULL,
		0x014F6C809A941AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADEAC7C300000000ULL,
		0x0F2B975F9CDA15E8ULL,
		0x81A452F5F50CE00BULL,
		0x9A941AB75AF44C77ULL,
		0x00000000014F6C80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9B641CACF91D02AULL,
		0x74015AD78D118614ULL,
		0x6C00881190919FBCULL,
		0x90C3C71B999EFFE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF91D02A0000000ULL,
		0x78D118614B9B641CULL,
		0x190919FBC74015ADULL,
		0xB999EFFE06C00881ULL,
		0x00000000090C3C71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D02EA6059385AEDULL,
		0x21EF1BEA0CBC2200ULL,
		0xD2E2B199BC13005FULL,
		0x2FF90B2696CD88D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5302C9C2D7680000ULL,
		0xDF5065E110006817ULL,
		0x8CCDE09802F90F78ULL,
		0x5934B66C46BE9715ULL,
		0x0000000000017FC8ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0877F5FDF2428C4EULL,
		0x1CF197F97E9198ABULL,
		0x8585BE5DA9C1AF69ULL,
		0xA0E3F02D2DC60615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5189C00000000000ULL,
		0x3315610EFEBFBE48ULL,
		0x35ED239E32FF2FD2ULL,
		0xC0C2B0B0B7CBB538ULL,
		0x0000141C7E05A5B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x405A236B77529438ULL,
		0x4FF96778F974DE35ULL,
		0x4BCF42F06AC1BE5BULL,
		0xE294759BA4F91568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x236B775294380000ULL,
		0x6778F974DE35405AULL,
		0x42F06AC1BE5B4FF9ULL,
		0x759BA4F915684BCFULL,
		0x000000000000E294ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E97A4923EB65220ULL,
		0x4E578F246BBA4404ULL,
		0xD48EF8D37B62E534ULL,
		0x19C127256E0B41D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2491F5B291000000ULL,
		0x79235DD22020F4BDULL,
		0xC69BDB1729A272BCULL,
		0x392B705A0EC6A477ULL,
		0x000000000000CE09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A0B4817E827E09DULL,
		0x08E6D3223DB969CDULL,
		0x184812E0967A84EFULL,
		0x7EE02051C7475186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4817E827E09D00ULL,
		0xE6D3223DB969CD5AULL,
		0x4812E0967A84EF08ULL,
		0xE02051C747518618ULL,
		0x000000000000007EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x69183B18F359231EULL,
		0x592880CDCF15440EULL,
		0xC03A74874582A0FCULL,
		0x4FC0228DCBA26776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8C79AC918F000000ULL,
		0x66E78AA207348C1DULL,
		0x43A2C1507E2C9440ULL,
		0x46E5D133BB601D3AULL,
		0x000000000027E011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AFADBE43CB2B1FEULL,
		0xA9FCBDA1C110E12DULL,
		0x20F7BC6AC72EFE90ULL,
		0xADA6D80CA6F0CBA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x796563FC00000000ULL,
		0x8221C25A75F5B7C8ULL,
		0x8E5DFD2153F97B43ULL,
		0x4DE1975241EF78D5ULL,
		0x000000015B4DB019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23051EA2F03523E2ULL,
		0x8F35015B0D06407CULL,
		0x92C3DB7034685FAFULL,
		0xF146F944D23B98FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60A3D45E06A47C40ULL,
		0xE6A02B61A0C80F84ULL,
		0x587B6E068D0BF5F1ULL,
		0x28DF289A47731FD2ULL,
		0x000000000000001EULL
	}};
	shift = 59;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7DF8EA49161BB693ULL,
		0xA49376C402D2D9C9ULL,
		0x1C1865B6754EDF2FULL,
		0x94D7F13C3E67E594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB498000000000000ULL,
		0xCE4BEFC75248B0DDULL,
		0xF97D249BB6201696ULL,
		0x2CA0E0C32DB3AA76ULL,
		0x0004A6BF89E1F33FULL
	}};
	shift = 13;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE6AE91F49758D465ULL,
		0x9DA17D547E21C8C7ULL,
		0x38D406B3A6ADF34AULL,
		0xEDA612295C920D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5D23E92EB1A8CA0ULL,
		0xB42FAA8FC43918FCULL,
		0x1A80D674D5BE6953ULL,
		0xB4C2452B9241B087ULL,
		0x000000000000001DULL
	}};
	shift = 59;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E1104C40421C9A6ULL,
		0xEDB2825DC3D45758ULL,
		0xBD859CB374628DDAULL,
		0x02419631E5F47BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x04C40421C9A60000ULL,
		0x825DC3D457581E11ULL,
		0x9CB374628DDAEDB2ULL,
		0x9631E5F47BF7BD85ULL,
		0x0000000000000241ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D77ED8577214A9BULL,
		0x0F3C3E56C177FBF1ULL,
		0x48E5969B324E21C7ULL,
		0x8B4F92ABE7C45EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8577214A9B000000ULL,
		0x56C177FBF14D77EDULL,
		0x9B324E21C70F3C3EULL,
		0xABE7C45EA648E596ULL,
		0x00000000008B4F92ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEFA2FD63DBDBB5ACULL,
		0xF74C11CDCCBE5E61ULL,
		0x0F029A720923379DULL,
		0xA41CA1316AEBCC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ED6B00000000000ULL,
		0xF97987BE8BF58F6FULL,
		0x8CDE77DD30473732ULL,
		0xAF31C03C0A69C824ULL,
		0x000002907284C5ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x293B69CC997480C5ULL,
		0x52DC63222DA6F5B7ULL,
		0x73D2B7E1A5629A0AULL,
		0x3E1133BE38CFC89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDA73265D2031400ULL,
		0x718C88B69BD6DCA4ULL,
		0x4ADF86958A68294BULL,
		0x44CEF8E33F2275CFULL,
		0x00000000000000F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64228767F16798DDULL,
		0xF754469319BC31DAULL,
		0xDC0C29E3D438E8A9ULL,
		0x379FFCF14934398FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF31BA0000000000ULL,
		0x7863B4C8450ECFE2ULL,
		0x71D153EEA88D2633ULL,
		0x68731FB81853C7A8ULL,
		0x0000006F3FF9E292ULL
	}};
	shift = 23;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF9B49F8A6F2BB89ULL,
		0x40B73A2E78F58275ULL,
		0x61AB90118FBF4D15ULL,
		0x2EDD1B90320F93E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9B49F8A6F2BB8900ULL,
		0xB73A2E78F58275CFULL,
		0xAB90118FBF4D1540ULL,
		0xDD1B90320F93E961ULL,
		0x000000000000002EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EE02CACC9E14B7AULL,
		0x6F5C3FAFA1446DCEULL,
		0xFAF652994AF2A508ULL,
		0x982D2FA327812486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F0A5BD000000000ULL,
		0x0A236E7077016566ULL,
		0x579528437AE1FD7DULL,
		0x3C092437D7B294CAULL,
		0x00000004C1697D19ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3598A83D0BD23BEULL,
		0x271D0AF5553FD121ULL,
		0xA1291F009FD47037ULL,
		0x35B1A12BF5007D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD23BE00000000000ULL,
		0xFD121A3598A83D0BULL,
		0x47037271D0AF5553ULL,
		0x07D57A1291F009FDULL,
		0x0000035B1A12BF50ULL
	}};
	shift = 20;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x003D923D4DA3F65AULL,
		0x5102A6B043335D03ULL,
		0x2C45C94EC869D021ULL,
		0x0EA3CFF46CB49884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB47ECB4000000000ULL,
		0x666BA06007B247A9ULL,
		0x0D3A042A2054D608ULL,
		0x9693108588B929D9ULL,
		0x00000001D479FE8DULL,
		0x0000000000000000ULL
	}};
	shift = 91;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4863C6446BA40CE4ULL,
		0x668B114CEA12B79AULL,
		0xAD5BF4B715CE9CB8ULL,
		0xE29917F62AFBEB25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA40CE4000000000ULL,
		0xA12B79A4863C6446ULL,
		0x5CE9CB8668B114CEULL,
		0xAFBEB25AD5BF4B71ULL,
		0x0000000E29917F62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C7BA4FD71FC5076ULL,
		0xA33705F4C7365588ULL,
		0x5363E63DEDF10A05ULL,
		0xC041B1C65D5EE866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA0EC000000000000ULL,
		0xAB1138F749FAE3F8ULL,
		0x140B466E0BE98E6CULL,
		0xD0CCA6C7CC7BDBE2ULL,
		0x00018083638CBABDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x552FD3F1CCA47846ULL,
		0xA642C5DFE3570CAFULL,
		0xCD4ED21AFE9D4794ULL,
		0x477FE76A289C9F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1180000000000000ULL,
		0x2BD54BF4FC73291EULL,
		0xE52990B177F8D5C3ULL,
		0xD4F353B486BFA751ULL,
		0x0011DFF9DA8A2727ULL
	}};
	shift = 10;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AD5137571F2BBF9ULL,
		0x425C85A3A7602894ULL,
		0x6C015E2EFEE4DA95ULL,
		0x86FF0B6E5A0C8F74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7571F2BBF9000000ULL,
		0xA3A76028948AD513ULL,
		0x2EFEE4DA95425C85ULL,
		0x6E5A0C8F746C015EULL,
		0x000000000086FF0BULL
	}};
	shift = 40;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC35C946151880EA4ULL,
		0x670FD03004AD6404ULL,
		0x1797A07946DDFB63ULL,
		0xD38E57CB6F46CACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE4A30A8C4075200ULL,
		0x87E8180256B20261ULL,
		0xCBD03CA36EFDB1B3ULL,
		0xC72BE5B7A365650BULL,
		0x0000000000000069ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC789ED768CB3A3DULL,
		0x1956BF7C24A1C36CULL,
		0x9173E2ED05993DB5ULL,
		0xEAEAFBC9A91356FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2CE8F40000000000ULL,
		0x870DB2B1E27B5DA3ULL,
		0x64F6D4655AFDF092ULL,
		0x4D5BEA45CF8BB416ULL,
		0x000003ABABEF26A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89FF2FFEE0431A47ULL,
		0xFB3DA1199E5F0353ULL,
		0x1491EC1C1026EC6AULL,
		0x4C5BFC334C7678DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FCBFFB810C691C0ULL,
		0xCF68466797C0D4E2ULL,
		0x247B070409BB1ABEULL,
		0x16FF0CD31D9E3705ULL,
		0x0000000000000013ULL
	}};
	shift = 58;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2F22A273E1E3939ULL,
		0xCA39023444B60F9CULL,
		0x9CE42F536C9EC6A2ULL,
		0xD2925C091E4C48E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89CF878E4E400000ULL,
		0x8D112D83E734BC8AULL,
		0xD4DB27B1A8B28E40ULL,
		0x024793123A67390BULL,
		0x000000000034A497ULL
	}};
	shift = 42;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9A584B29155EFCAULL,
		0x062D6ED738FE2BD7ULL,
		0xCC4BA9D220657C1DULL,
		0xE16E10A00F909662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x612CA4557BF28000ULL,
		0x5BB5CE3F8AF5EE69ULL,
		0xEA7488195F07418BULL,
		0x842803E42598B312ULL,
		0x000000000000385BULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9F592CEC94F87F86ULL,
		0xE382605B545C4F9EULL,
		0x3A2441956FB94378ULL,
		0xCDACC018B9F94485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1800000000000000ULL,
		0x7A7D64B3B253E1FEULL,
		0xE38E09816D51713EULL,
		0x14E8910655BEE50DULL,
		0x0336B30062E7E512ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE960BF520BA245CULL,
		0x26A62D45ADE1D20BULL,
		0xAB4A9CBE5C891CE0ULL,
		0x77988C50EE6F2A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C00000000000000ULL,
		0x0BDE960BF520BA24ULL,
		0xE026A62D45ADE1D2ULL,
		0x53AB4A9CBE5C891CULL,
		0x0077988C50EE6F2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE19E3936FB294766ULL,
		0x181DF929E479572EULL,
		0x19E51D556656A12FULL,
		0xB5C72C768AEEDF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x726DF6528ECC0000ULL,
		0xF253C8F2AE5DC33CULL,
		0x3AAACCAD425E303BULL,
		0x58ED15DDBF1633CAULL,
		0x0000000000016B8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9CA764077ED932CULL,
		0x63346705935BB2C2ULL,
		0x12A7ED7896C62FE7ULL,
		0xA0B36605B0512E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB64CB00000000000ULL,
		0x6ECB0B2729D901DFULL,
		0x18BF9D8CD19C164DULL,
		0x44B8D04A9FB5E25BULL,
		0x00000282CD9816C1ULL
	}};
	shift = 22;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB40AEF1E4401E2A1ULL,
		0x2CA2258E17E1022BULL,
		0x4A1C7DCA21A2A77CULL,
		0x3BCE0667CE18FEA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1508000000000000ULL,
		0x115DA05778F2200FULL,
		0x3BE165112C70BF08ULL,
		0xF51250E3EE510D15ULL,
		0x0001DE70333E70C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D56498B6771B8AEULL,
		0x54DE83F7F7AB5426ULL,
		0x90BA80367BEFEA29ULL,
		0x8BFF72A1286957C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x498B6771B8AE0000ULL,
		0x83F7F7AB54266D56ULL,
		0x80367BEFEA2954DEULL,
		0x72A1286957C590BAULL,
		0x0000000000008BFFULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF25847D847D4C90ULL,
		0x815F9B1813AA983EULL,
		0x93238B38BD98FE6AULL,
		0x5152253A2AADDD55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9611F611F5324000ULL,
		0x7E6C604EAA60FBFCULL,
		0x8E2CE2F663F9AA05ULL,
		0x4894E8AAB775564CULL,
		0x0000000000000145ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7DD79FDB8A80963AULL,
		0xF40EE72F254AB103ULL,
		0xD2DD4877A574CA7AULL,
		0x16DCB5A8B57D410AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB715012C7400000ULL,
		0xE5E4A956206FBAF3ULL,
		0x0EF4AE994F5E81DCULL,
		0xB516AFA8215A5BA9ULL,
		0x000000000002DB96ULL
	}};
	shift = 43;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A00E7C67594C54CULL,
		0xE884DBC55D79D794ULL,
		0xF69018622D989003ULL,
		0xF7C2AAC0F14C9D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C54C00000000000ULL,
		0x9D7942A00E7C6759ULL,
		0x89003E884DBC55D7ULL,
		0xC9D43F69018622D9ULL,
		0x00000F7C2AAC0F14ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB49261D4E325A63BULL,
		0xAC53AA00DFC0F773ULL,
		0xE1B7F4FA071FD244ULL,
		0xB0F1F2EFA7080A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4930EA7192D31D8ULL,
		0x629D5006FE07BB9DULL,
		0x0DBFA7D038FE9225ULL,
		0x878F977D38405397ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x514BB9362D62B109ULL,
		0xAE5316C932397133ULL,
		0xB56CC2A6D5C09562ULL,
		0xABBD8B0E31328159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16B1588480000000ULL,
		0x991CB899A8A5DC9BULL,
		0x6AE04AB157298B64ULL,
		0x189940ACDAB66153ULL,
		0x0000000055DEC587ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07A4B1425BF285F2ULL,
		0x91D30A50E85131D9ULL,
		0x69F61582A6B82D57ULL,
		0xDB80336F95E0783DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA12DF942F9000000ULL,
		0x28742898EC83D258ULL,
		0xC1535C16ABC8E985ULL,
		0xB7CAF03C1EB4FB0AULL,
		0x00000000006DC019ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06B3340135E43FD1ULL,
		0x28AF0EB645765533ULL,
		0x5346DB1641659862ULL,
		0xB2498FFFB063F0DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9A009AF21FE88000ULL,
		0x875B22BB2A998359ULL,
		0x6D8B20B2CC311457ULL,
		0xC7FFD831F86E29A3ULL,
		0x0000000000005924ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC65F54C1C8E85F9DULL,
		0xACF993624AE9A2F1ULL,
		0x0859AE87573699D7ULL,
		0xABBF36253E6AADF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8391D0BF3A000000ULL,
		0xC495D345E38CBEA9ULL,
		0x0EAE6D33AF59F326ULL,
		0x4A7CD55BF210B35DULL,
		0x0000000001577E6CULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x922F455A71A2CAC5ULL,
		0xCA7C058C67D16E88ULL,
		0x0DA069C9D6A07680ULL,
		0xCD8EC6A5CD13929CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AD38D1656280000ULL,
		0x2C633E8B7444917AULL,
		0x4E4EB503B40653E0ULL,
		0x352E689C94E06D03ULL,
		0x0000000000066C76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF45C42A56545C123ULL,
		0x5DA6011D3701629FULL,
		0xC540F68ED50BEFA4ULL,
		0x618804E4CECA5B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x45C1230000000000ULL,
		0x01629FF45C42A565ULL,
		0x0BEFA45DA6011D37ULL,
		0xCA5B67C540F68ED5ULL,
		0x000000618804E4CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC6A21AAC99EBF5FULL,
		0xD733E94F763CB753ULL,
		0xEAA721EE37FF9C44ULL,
		0x9435C77FB0F25FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55933D7EBE000000ULL,
		0x9EEC796EA7F8D443ULL,
		0xDC6FFF3889AE67D2ULL,
		0xFF61E4BFC7D54E43ULL,
		0x0000000001286B8EULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E3C30D319CC8513ULL,
		0xEF563E9BCDE9DD83ULL,
		0x496DA2F83CBAAA74ULL,
		0xEA5FBD70158FA635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x32144C0000000000ULL,
		0xA7760E38F0C34C67ULL,
		0xEAA9D3BD58FA6F37ULL,
		0x3E98D525B68BE0F2ULL,
		0x000003A97EF5C056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40E94D8379A8946AULL,
		0x68B2796F751B795BULL,
		0x74C77724047FA0BBULL,
		0xB1BC4360EFA11C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x79A8946A00000000ULL,
		0x751B795B40E94D83ULL,
		0x047FA0BB68B2796FULL,
		0xEFA11C5B74C77724ULL,
		0x00000000B1BC4360ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6499C33AF739E985ULL,
		0x20D23CCB24E270ECULL,
		0x4B3112C037687898ULL,
		0xEFEA20329CB4463EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D30A0000000000ULL,
		0xC4E1D8C9338675EEULL,
		0xD0F13041A4799649ULL,
		0x688C7C966225806EULL,
		0x000001DFD4406539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16C761828CC9A63BULL,
		0xEE009B45C99A3926ULL,
		0x6FDC65810D12C22FULL,
		0xA852A3822A96D96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x85B1D860A332698EULL,
		0xFB8026D172668E49ULL,
		0x1BF719604344B08BULL,
		0x2A14A8E08AA5B65BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAE3D429C4599AB0ULL,
		0xEBB26D4ADE7AF985ULL,
		0xB090D99253A2AA3BULL,
		0xBFB94C594C6D5B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x22CCD58000000000ULL,
		0xF3D7CC2FD71EA14EULL,
		0x9D1551DF5D936A56ULL,
		0x636ADCB58486CC92ULL,
		0x00000005FDCA62CAULL,
		0x0000000000000000ULL
	}};
	shift = 93;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x722D57C6E5FADD0EULL,
		0x18D5B2CEFE239645ULL,
		0x9B551F8FFDAEED93ULL,
		0xD79CFA3370C7A28AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xADD0E00000000000ULL,
		0x39645722D57C6E5FULL,
		0xEED9318D5B2CEFE2ULL,
		0x7A28A9B551F8FFDAULL,
		0x00000D79CFA3370CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74FE3B1D1BF2009FULL,
		0x3520E4BF5620AC1DULL,
		0x8FF5F4C5C114A16BULL,
		0x915BA8A751BCEAFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2009F00000000000ULL,
		0x0AC1D74FE3B1D1BFULL,
		0x4A16B3520E4BF562ULL,
		0xCEAFA8FF5F4C5C11ULL,
		0x00000915BA8A751BULL,
		0x0000000000000000ULL
	}};
	shift = 84;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E0EA05083E2F9AULL,
		0x10E9CD6B457C8B61ULL,
		0x5A0C6EC04952D078ULL,
		0xAE9CD2EBCD93EA22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7502841F17CD0000ULL,
		0xE6B5A2BE45B08CF0ULL,
		0x376024A9683C0874ULL,
		0x6975E6C9F5112D06ULL,
		0x000000000000574EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC8A2BFF7B1327D4ULL,
		0x1604073B5E625325ULL,
		0xB4A9A1338D8E174EULL,
		0xACB7B4137D1146BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6264FA800000000ULL,
		0xBCC4A64B991457FEULL,
		0x1B1C2E9C2C080E76ULL,
		0xFA228D7F69534267ULL,
		0x00000001596F6826ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAADF404233F9BA6ULL,
		0x3AADFBBD8F8E9D5CULL,
		0x5B8790C7A80F42A5ULL,
		0x0BBB5EDF9CEBFDFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF374C00000000000ULL,
		0xD3AB9B55BE808467ULL,
		0xE854A755BF77B1F1ULL,
		0x7FBF8B70F218F501ULL,
		0x000001776BDBF39DULL
	}};
	shift = 19;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE829494277F57C9BULL,
		0x9F8EED24EBD96643ULL,
		0xB9FD900862FBA95CULL,
		0x7C2D3781B3DAAB85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A4A13BFABE4D800ULL,
		0x7769275ECB321F41ULL,
		0xEC804317DD4AE4FCULL,
		0x69BC0D9ED55C2DCFULL,
		0x00000000000003E1ULL
	}};
	shift = 53;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB286B5A95F09FDB9ULL,
		0x607CB9CD14079EEDULL,
		0x7DAD9281980961BBULL,
		0xE728F74E78850046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B52BE13FB720000ULL,
		0x739A280F3DDB650DULL,
		0x25033012C376C0F9ULL,
		0xEE9CF10A008CFB5BULL,
		0x000000000001CE51ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF91C3FED17DC9B5CULL,
		0x67DBDA503D4DE55FULL,
		0x2D1D41721439A0C3ULL,
		0xE4936C3657337622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D70000000000000ULL,
		0x957FE470FFB45F72ULL,
		0x830D9F6F6940F537ULL,
		0xD888B47505C850E6ULL,
		0x0003924DB0D95CCDULL
	}};
	shift = 14;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A8B89DFD40BD0A0ULL,
		0xF7F0FBCB60AFAB71ULL,
		0xF82554C799868F6DULL,
		0x50A225F8E651453FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x502F428000000000ULL,
		0x82BEADC62A2E277FULL,
		0x661A3DB7DFC3EF2DULL,
		0x994514FFE095531EULL,
		0x00000001428897E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2677543758BDBC1ULL,
		0x417A8CC7C395D9B5ULL,
		0x14AC74ECE2628842ULL,
		0x2BA8049B544FC983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43758BDBC1000000ULL,
		0xC7C395D9B5B26775ULL,
		0xECE2628842417A8CULL,
		0x9B544FC98314AC74ULL,
		0x00000000002BA804ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64FE610F4F9F8FE7ULL,
		0x5F7A7F0A49BF8399ULL,
		0xF6682C7E5F283C9FULL,
		0xF89A9AE945C02378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F1FCE0000000000ULL,
		0x7F0732C9FCC21E9FULL,
		0x50793EBEF4FE1493ULL,
		0x8046F1ECD058FCBEULL,
		0x000001F13535D28BULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27236DAB504145ACULL,
		0x15C0F7ED7EBEAABEULL,
		0xC481E450C59933DDULL,
		0xA70A2379C924EA72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x828B580000000000ULL,
		0x7D557C4E46DB56A0ULL,
		0x3267BA2B81EFDAFDULL,
		0x49D4E58903C8A18BULL,
		0x0000014E1446F392ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40F2E37037F2049BULL,
		0x41318DE00750D7BAULL,
		0x46D1F7BEA1C7CC05ULL,
		0x37121057CCF9CD69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C0000000000000ULL,
		0xEE903CB8DC0DFC81ULL,
		0x01504C637801D435ULL,
		0x5A51B47DEFA871F3ULL,
		0x000DC48415F33E73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39A1A96B4F7F3EB3ULL,
		0xBA202901B76E0396ULL,
		0x29B19946C98649CAULL,
		0x3552B863529A0D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFACC00000000000ULL,
		0x80E58E686A5AD3DFULL,
		0x9272AE880A406DDBULL,
		0x83638A6C6651B261ULL,
		0x00000D54AE18D4A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8B94713A84630B8ULL,
		0x778BF269A9353CCAULL,
		0xE3108856BF56FC7DULL,
		0x6B18C2B034FA8D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x630B800000000000ULL,
		0x53CCAB8B94713A84ULL,
		0x6FC7D778BF269A93ULL,
		0xA8D6AE3108856BF5ULL,
		0x000006B18C2B034FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECF6CDB7FEE2744DULL,
		0xE328D972ADD8AEFDULL,
		0x8A3F6FE1B3FF691AULL,
		0x43F6EF405E906989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB89D13400000000ULL,
		0xB762BBF7B3DB36DFULL,
		0xCFFDA46B8CA365CAULL,
		0x7A41A62628FDBF86ULL,
		0x000000010FDBBD01ULL
	}};
	shift = 30;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9A25C4ED1AFA8BFULL,
		0x83F18EF1C0E02A52ULL,
		0xCAEA482A33C07957ULL,
		0x9006EC8E6BF625F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA8BF000000000000ULL,
		0x2A52C9A25C4ED1AFULL,
		0x795783F18EF1C0E0ULL,
		0x25F1CAEA482A33C0ULL,
		0x00009006EC8E6BF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1EDF6DD11F1AA5B9ULL,
		0x28476BE2B9026B32ULL,
		0x33A4DC27A0903969ULL,
		0x6AF737034E76AEDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE88F8D52DC800000ULL,
		0xF15C8135990F6FB6ULL,
		0x13D0481CB49423B5ULL,
		0x81A73B576F19D26EULL,
		0x0000000000357B9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF18737D0CF6F961DULL,
		0x1BFD508CB6C5847CULL,
		0xD78B7A2F881B27DAULL,
		0x2EC8991599716B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE800000000000000ULL,
		0xE78C39BE867B7CB0ULL,
		0xD0DFEA8465B62C23ULL,
		0x0EBC5BD17C40D93EULL,
		0x017644C8ACCB8B5CULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B66348909AC9C37ULL,
		0xCF85951F390D813AULL,
		0xEEB642D53AD4917EULL,
		0xE8E9017F2A2FC2D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21359386E0000000ULL,
		0xE721B027416CC691ULL,
		0xA75A922FD9F0B2A3ULL,
		0xE545F85A7DD6C85AULL,
		0x000000001D1D202FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08DFD50260E537E5ULL,
		0xAC7BCB5DC2D48C11ULL,
		0x03F684EC86AA74D7ULL,
		0x88985C444F4D4976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30729BF280000000ULL,
		0xE16A4608846FEA81ULL,
		0x43553A6BD63DE5AEULL,
		0x27A6A4BB01FB4276ULL,
		0x00000000444C2E22ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD7E6D973F494FF7EULL,
		0x98C3E9C70456727DULL,
		0xC79759F991EB534FULL,
		0x4691C3629563933FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73F494FF7E000000ULL,
		0xC70456727DD7E6D9ULL,
		0xF991EB534F98C3E9ULL,
		0x629563933FC79759ULL,
		0x00000000004691C3ULL
	}};
	shift = 40;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D12210D971D0A8CULL,
		0xD6C0B5512944FBACULL,
		0x9D37B4702FBE631BULL,
		0x893C57D6D161719DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12210D971D0A8C0ULL,
		0x6C0B5512944FBAC5ULL,
		0xD37B4702FBE631BDULL,
		0x93C57D6D161719D9ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9CEA5A1DFFDD5AACULL,
		0x8026E653063A080CULL,
		0x6CFF18BA029DB753ULL,
		0x5E7458FBE44D2929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E752D0EFFEEAD56ULL,
		0xC0137329831D0406ULL,
		0xB67F8C5D014EDBA9ULL,
		0x2F3A2C7DF2269494ULL
	}};
	shift = 1;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36BED0B72E535EECULL,
		0x38F4DB539C16C7B5ULL,
		0x659E7758EC3403D4ULL,
		0x91DBF823FECA391EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DAFB42DCB94D7BBULL,
		0x0E3D36D4E705B1EDULL,
		0x99679DD63B0D00F5ULL,
		0x2476FE08FFB28E47ULL
	}};
	shift = 2;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x000AB92AD057C88CULL,
		0x14088E7C8AD7ABD5ULL,
		0xEE56B0822E6300CAULL,
		0x6533F68426532B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4002AE4AB415F223ULL,
		0x8502239F22B5EAF5ULL,
		0xFB95AC208B98C032ULL,
		0x194CFDA10994CADDULL
	}};
	shift = 2;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDED2D8D0F45A2A4EULL,
		0x27199DFFC7E88170ULL,
		0x54474209A85C5C8CULL,
		0x7FF554F4433BE31CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA938000000000000ULL,
		0x05C37B4B6343D168ULL,
		0x72309C6677FF1FA2ULL,
		0x8C71511D0826A171ULL,
		0x0001FFD553D10CEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6CEE608A9174969FULL,
		0x6209B4B3AEA55ECDULL,
		0x5468A2F97A481439ULL,
		0x581D523F842DB237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9DCC11522E92D3EULL,
		0xC41369675D4ABD9AULL,
		0xA8D145F2F4902872ULL,
		0xB03AA47F085B646EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2395E36F232D3AAULL,
		0x36445E72E41BF02CULL,
		0xDAC5B890377624B3ULL,
		0xF757781DB103D88EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E36F232D3AA0000ULL,
		0x5E72E41BF02CD239ULL,
		0xB890377624B33644ULL,
		0x781DB103D88EDAC5ULL,
		0x000000000000F757ULL
	}};
	shift = 48;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30F75026C38E45F4ULL,
		0xFB4C09CAE31F5790ULL,
		0x016B537A5C7E75B5ULL,
		0xF8EE26E8E505610BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61EEA04D871C8BE8ULL,
		0xF6981395C63EAF20ULL,
		0x02D6A6F4B8FCEB6BULL,
		0xF1DC4DD1CA0AC216ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D2F7EDF5EFD6298ULL,
		0x45DAE582D9BF8FA9ULL,
		0xDEFB287550FEC046ULL,
		0x237843B83D9CD50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBDFAC53000000000ULL,
		0xB37F1F523A5EFDBEULL,
		0xA1FD808C8BB5CB05ULL,
		0x7B39AA1DBDF650EAULL,
		0x0000000046F08770ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BFAF2F3A2D3E42EULL,
		0x35D1C243D3755CA5ULL,
		0x2AD8AFA751166BF8ULL,
		0xC71D02EDA1AE0D79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5E5E745A7C85C000ULL,
		0x38487A6EAB94AF7FULL,
		0x15F4EA22CD7F06BAULL,
		0xA05DB435C1AF255BULL,
		0x00000000000018E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82D1F883075CF720ULL,
		0xA8B2AA09DBE3AF61ULL,
		0x9F81D75209C9CDF2ULL,
		0x89D232B6F5A7435CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE400000000000000ULL,
		0xEC305A3F1060EB9EULL,
		0xBE551655413B7C75ULL,
		0x6B93F03AEA413939ULL,
		0x00113A4656DEB4E8ULL
	}};
	shift = 11;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47BC29E90E17C1DAULL,
		0x73BBF44E9153D016ULL,
		0xDB26A8769CC4A0A6ULL,
		0x567FD2793B525F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7A4385F0768000ULL,
		0xFD13A454F40591EFULL,
		0xAA1DA73128299CEEULL,
		0xF49E4ED497CE76C9ULL,
		0x000000000000159FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x58003C884EF473A6ULL,
		0x4D1F98EFA511A203ULL,
		0x2E0251139D4B58E3ULL,
		0xA0586EA1A9A74B8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8E74C0000000000ULL,
		0x234406B00079109DULL,
		0x96B1C69A3F31DF4AULL,
		0x4E97165C04A2273AULL,
		0x00000140B0DD4353ULL
	}};
	shift = 23;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE98F198FA92DEFC7ULL,
		0x91F4CD2B9DF2DBE2ULL,
		0xC26F67C388D7B289ULL,
		0xC2A0569C55438D50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7E38000000000000ULL,
		0xDF174C78CC7D496FULL,
		0x944C8FA6695CEF96ULL,
		0x6A86137B3E1C46BDULL,
		0x00061502B4E2AA1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EFB78497C39782DULL,
		0x749FAC08BA7DD437ULL,
		0x21A5F1A9F45781CAULL,
		0x6FADC64DC4F1A4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CBC168000000000ULL,
		0x3EEA1B877DBC24BEULL,
		0x2BC0E53A4FD6045DULL,
		0x78D27D10D2F8D4FAULL,
		0x00000037D6E326E2ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C6FE4DFC4F6DCCFULL,
		0xEC76A7DE9A386163ULL,
		0x6998A59A57371AB6ULL,
		0x8534EC09F3FA66AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C00000000000000ULL,
		0x8C71BF937F13DB73ULL,
		0xDBB1DA9F7A68E185ULL,
		0xA9A66296695CDC6AULL,
		0x0214D3B027CFE99AULL
	}};
	shift = 6;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB2126BA5D08F5BEULL,
		0x5EE7632E18631928ULL,
		0xB4F69E776E9B4811ULL,
		0xF6859453B1526BE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB2126BA5D08F5BEULL,
		0x5EE7632E18631928ULL,
		0xB4F69E776E9B4811ULL,
		0xF6859453B1526BE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53D4BF06B5A82092ULL,
		0x1AE37FD4571340D8ULL,
		0x3A6CBFB9AB617CE3ULL,
		0xFA5BA0BCCD485217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8209200000000000ULL,
		0x340D853D4BF06B5AULL,
		0x17CE31AE37FD4571ULL,
		0x852173A6CBFB9AB6ULL,
		0x00000FA5BA0BCCD4ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4BE9FFBF372C3364ULL,
		0x1DD5391403482BD6ULL,
		0x3FDDB06C800C4B8BULL,
		0x85072E022D9733DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFBF372C336400000ULL,
		0x91403482BD64BE9FULL,
		0x06C800C4B8B1DD53ULL,
		0xE022D9733DB3FDDBULL,
		0x0000000000085072ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9CB478F50A89F008ULL,
		0x83DEA2F275BFEDD2ULL,
		0xF94D2B717DA15DF3ULL,
		0x1C717BE97E39DD8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C7A8544F8040000ULL,
		0x51793ADFF6E94E5AULL,
		0x95B8BED0AEF9C1EFULL,
		0xBDF4BF1CEEC67CA6ULL,
		0x0000000000000E38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9750462E635BD102ULL,
		0xC9B4225B6AC44D23ULL,
		0x2C12B8A71AA16CCBULL,
		0xFA5969B26E5E4113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x1CBA8231731ADE88ULL,
		0x5E4DA112DB562269ULL,
		0x996095C538D50B66ULL,
		0x07D2CB4D9372F208ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62C0C9A2172094B1ULL,
		0x06ABD0CC01968A7EULL,
		0xC84871BA06B93E4EULL,
		0xD4133AB19DF38AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC58193442E412962ULL,
		0x0D57A198032D14FCULL,
		0x9090E3740D727C9CULL,
		0xA82675633BE715B1ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAD1177F97270764ULL,
		0x58C3787012377374ULL,
		0x69D839CB7F99BC3FULL,
		0x61F5E5FCF042BBECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5A22EFF2E4E0EC8ULL,
		0xB186F0E0246EE6E9ULL,
		0xD3B07396FF33787EULL,
		0xC3EBCBF9E08577D8ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42B10FC67FD6F171ULL,
		0x39833A66393BDB92ULL,
		0x452A626A4838729DULL,
		0x030BB53C4010BE53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2E20000000000000ULL,
		0x72485621F8CFFADEULL,
		0x53A730674CC7277BULL,
		0xCA68A54C4D49070EULL,
		0x00006176A7880217ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37DC18A2EDB9B36DULL,
		0x3A2EFB58350172C2ULL,
		0xED6907B6037A7302ULL,
		0x152DE8DDA2AFF1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7366DA0000000000ULL,
		0x02E5846FB83145DBULL,
		0xF4E604745DF6B06AULL,
		0x5FE3D7DAD20F6C06ULL,
		0x0000002A5BD1BB45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x538587A5FD40855DULL,
		0xC11589AEA18051AAULL,
		0x3F6A515B8F444ED5ULL,
		0xC43E2C019BB275E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x042AE80000000000ULL,
		0x028D529C2C3D2FEAULL,
		0x2276AE08AC4D750CULL,
		0x93AF01FB528ADC7AULL,
		0x00000621F1600CDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65E9F84815AB4703ULL,
		0x0C279AD1BC261D1AULL,
		0x28EC8DAAA8991D32ULL,
		0x2DC9C50B869B891CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x240AD5A381800000ULL,
		0x68DE130E8D32F4FCULL,
		0xD5544C8E990613CDULL,
		0x85C34DC48E147646ULL,
		0x000000000016E4E2ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72DB20DF00560525ULL,
		0x050369D547470EA3ULL,
		0x8BAC0F1F21FB2196ULL,
		0x6B347A59022CCB66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C837C015814940ULL,
		0x40DA7551D1C3A8DCULL,
		0xEB03C7C87EC86581ULL,
		0xCD1E96408B32D9A2ULL,
		0x000000000000001AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1ADF0567F85FEC34ULL,
		0x11D5780B65E3B493ULL,
		0xA872E3416958DFACULL,
		0x5B8DB75283AABC3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC340000000000000ULL,
		0x4931ADF0567F85FEULL,
		0xFAC11D5780B65E3BULL,
		0xC3BA872E3416958DULL,
		0x0005B8DB75283AABULL,
		0x0000000000000000ULL
	}};
	shift = 76;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDCA27558712C9C5ULL,
		0xAA2C030CADA61986ULL,
		0x4C0088D9252549C8ULL,
		0x16E481EB99DDD8EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAAC38964E2800000ULL,
		0x8656D30CC36EE513ULL,
		0x6C9292A4E4551601ULL,
		0xF5CCEEEC76A60044ULL,
		0x00000000000B7240ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2E69B846DDBC524ULL,
		0x1C0BA66E94C5A734ULL,
		0x0EA08AB6B97201A6ULL,
		0x157B80EE7655C050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x59734DC236EDE292ULL,
		0x0E05D3374A62D39AULL,
		0x0750455B5CB900D3ULL,
		0x0ABDC0773B2AE028ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83F5D6B8D73130A8ULL,
		0x948687CAEEB63178ULL,
		0xDEFC0312C486E170ULL,
		0xD5301D58A4334592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAEB5C6B98985400ULL,
		0x4343E5775B18BC41ULL,
		0x7E0189624370B84AULL,
		0x980EAC5219A2C96FULL,
		0x000000000000006AULL
	}};
	shift = 57;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x379AB0D9ABBEFD6DULL,
		0x1E91B607193E8FF1ULL,
		0x8330D14C2C9E7AE7ULL,
		0xBE2AE25870500DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0x89BCD586CD5DF7EBULL,
		0x38F48DB038C9F47FULL,
		0xF419868A6164F3D7ULL,
		0x05F15712C382806DULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC169F9D088B6C000ULL,
		0xFBCD8509F97B960AULL,
		0xEB8122D3D4B5B8C4ULL,
		0x20FD084AFC1B0D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x45B6000000000000ULL,
		0xCBDCB0560B4FCE84ULL,
		0xA5ADC627DE6C284FULL,
		0xE0D869EF5C09169EULL,
		0x0000000107E84257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD29F436C20B5D23EULL,
		0x756CAA710E50C543ULL,
		0x2B01808E88E29B12ULL,
		0x6C4E03E1E825FBEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D8416BA47C0000ULL,
		0x54E21CA18A87A53EULL,
		0x011D11C53624EAD9ULL,
		0x07C3D04BF7DE5603ULL,
		0x000000000000D89CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A4F30AAAE63AC72ULL,
		0x4F54992364B9C478ULL,
		0x5C937BF3514CC55CULL,
		0xD148E6E941BE1BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2798555731D6390ULL,
		0x7AA4C91B25CE23C3ULL,
		0xE49BDF9A8A662AE2ULL,
		0x8A47374A0DF0DD2AULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3718A4308D32103ULL,
		0x45F04D1F65202A7DULL,
		0x6616EC81F9E5B3EEULL,
		0x6D163B392A7386F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9081800000000000ULL,
		0x153EE9B8C5218469ULL,
		0xD9F722F8268FB290ULL,
		0xC37A330B7640FCF2ULL,
		0x0000368B1D9C9539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B344E6D05822BCEULL,
		0x408D91E91ED77C87ULL,
		0x59FAB49F4889BD70ULL,
		0x5D55E0835A659245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x689CDA0B04579C00ULL,
		0x1B23D23DAEF90E96ULL,
		0xF5693E91137AE081ULL,
		0xABC106B4CB248AB3ULL,
		0x00000000000000BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 183;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97A5808E2D816E36ULL,
		0x013BA8AC9A56DDECULL,
		0xE3DB04BAC21A03C8ULL,
		0xF2A7494F5665231CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x960238B605B8D800ULL,
		0xEEA2B2695B77B25EULL,
		0x6C12EB08680F2004ULL,
		0x9D253D59948C738FULL,
		0x00000000000003CAULL
	}};
	shift = 54;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F8CE3236D0A9D02ULL,
		0xE5B8D5B6F4904030ULL,
		0x48C0093D8F4C14C1ULL,
		0x647961704D44D684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE3236D0A9D02000ULL,
		0x8D5B6F49040307F8ULL,
		0x0093D8F4C14C1E5BULL,
		0x961704D44D68448CULL,
		0x0000000000000647ULL
	}};
	shift = 52;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA744562B3C4062DAULL,
		0xFF0B5D9A25C8A4F4ULL,
		0x426A4FBA7AAA2785ULL,
		0x2903951844DB0FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0C5B400000000000ULL,
		0x149E94E88AC56788ULL,
		0x44F0BFE16BB344B9ULL,
		0x61F6484D49F74F55ULL,
		0x0000052072A3089BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF500887309CE69F5ULL,
		0x5FC939DBAE04557FULL,
		0x90DB1069A65A2B52ULL,
		0x4F1BA4D222A26F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80443984E734FA80ULL,
		0xE49CEDD7022ABFFAULL,
		0x6D8834D32D15A92FULL,
		0x8DD269115137C0C8ULL,
		0x0000000000000027ULL
	}};
	shift = 57;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB11F485D10560C3CULL,
		0x5724259FA7C38927ULL,
		0xFB46648F751A8812ULL,
		0xE1549F531A6F34C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x560C3C0000000000ULL,
		0xC38927B11F485D10ULL,
		0x1A88125724259FA7ULL,
		0x6F34C0FB46648F75ULL,
		0x000000E1549F531AULL
	}};
	shift = 24;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC85075473A69E1DULL,
		0xA2B5E25ACC7DD690ULL,
		0xFE01A7534CF93501ULL,
		0x2E5C1C6CF29B6FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A00000000000000ULL,
		0x21990A0EA8E74D3CULL,
		0x03456BC4B598FBADULL,
		0xD9FC034EA699F26AULL,
		0x005CB838D9E536DFULL
	}};
	shift = 7;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE27834D06C9BFB94ULL,
		0x8D873547C7BE9E2BULL,
		0xBBB5BBE3743600D9ULL,
		0xA5218EF58A25F144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27834D06C9BFB940ULL,
		0xD873547C7BE9E2BEULL,
		0xBB5BBE3743600D98ULL,
		0x5218EF58A25F144BULL,
		0x000000000000000AULL
	}};
	shift = 60;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8ECD31AEE1209BDDULL,
		0x0BCF5A84986EA273ULL,
		0x58AD742FB62E74A3ULL,
		0xBE51F21B352F7ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECD31AEE1209BDD0ULL,
		0xBCF5A84986EA2738ULL,
		0x8AD742FB62E74A30ULL,
		0xE51F21B352F7ED85ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL
	}};
	shift = 124;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7356238273CDFCBDULL,
		0x2D56B647EF245DC3ULL,
		0x6E09DBC11072FF6FULL,
		0x31DE9B2DA57A3FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x88E09CF37F2F4000ULL,
		0xAD91FBC91770DCD5ULL,
		0x76F0441CBFDBCB55ULL,
		0xA6CB695E8FFB5B82ULL,
		0x0000000000000C77ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x151FCD0E1ED35A00ULL,
		0x06D5F563F93F853DULL,
		0x5CF9EA13887A7195ULL,
		0xED36EFE8AE4724EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x51FCD0E1ED35A000ULL,
		0x6D5F563F93F853D1ULL,
		0xCF9EA13887A71950ULL,
		0xD36EFE8AE4724EF5ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CF609B39B7F3351ULL,
		0xCACEBAA2254627D5ULL,
		0x16E5A7197E183294ULL,
		0x351E919F3A6D6771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B39B7F33510000ULL,
		0xBAA2254627D52CF6ULL,
		0xA7197E183294CACEULL,
		0x919F3A6D677116E5ULL,
		0x000000000000351EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7033ED88CE5C9DDCULL,
		0x23D6456E4EDD766DULL,
		0xAE8F00918038F331ULL,
		0x9B54ED4D962DBB4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC4672E4EEE000000ULL,
		0xB7276EBB36B819F6ULL,
		0x48C01C799891EB22ULL,
		0xA6CB16DDA6D74780ULL,
		0x00000000004DAA76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50504ADEF3F99B10ULL,
		0xC6AB84C2C9FF6DC1ULL,
		0xEA219A225617F8B3ULL,
		0x0CAFC4EDC98AC9B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7F33620000000000ULL,
		0x3FEDB82A0A095BDEULL,
		0xC2FF1678D5709859ULL,
		0x315936FD4433444AULL,
		0x0000000195F89DB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x464E1E16579DDB2AULL,
		0x665A8783F95E93F8ULL,
		0x4237ED5C331983F1ULL,
		0x7EDCD8612F66066CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA800000000000000ULL,
		0xE1193878595E776CULL,
		0xC5996A1E0FE57A4FULL,
		0xB108DFB570CC660FULL,
		0x01FB736184BD9819ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03BE260F186B595DULL,
		0x39A22DBF7091A97AULL,
		0xACF37BFC68F330D2ULL,
		0x7EFBF84271AE4B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C1E30D6B2BA0000ULL,
		0x5B7EE12352F4077CULL,
		0xF7F8D1E661A47344ULL,
		0xF084E35C965B59E6ULL,
		0x000000000000FDF7ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x559947D12B7E8FD8ULL,
		0x5248CEC3C0C44115ULL,
		0xD1CFD792EC3DB09BULL,
		0x4BE11417C43C9404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3E895BF47EC0000ULL,
		0x6761E062208AAACCULL,
		0xEBC9761ED84DA924ULL,
		0x8A0BE21E4A0268E7ULL,
		0x00000000000025F0ULL
	}};
	shift = 49;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F90AD4F29FE85DEULL,
		0x300ACA2F66E05E6DULL,
		0xC210DA444C4E5F91ULL,
		0xB541B669BBB708E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA17780000000000ULL,
		0x8179B43E42B53CA7ULL,
		0x397E44C02B28BD9BULL,
		0xDC23970843691131ULL,
		0x000002D506D9A6EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BF94C1D6882A853ULL,
		0xEA02BC4E500D7CEEULL,
		0x1F01269AC9223004ULL,
		0xA75B229DCFDC55FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14C0000000000000ULL,
		0x3B9EFE53075A20AAULL,
		0x013A80AF1394035FULL,
		0x7F47C049A6B2488CULL,
		0x0029D6C8A773F715ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FEB32C1A3D8B518ULL,
		0x7F2FAF06348C54FEULL,
		0xFA109B7F350A190BULL,
		0xE89F6C3811680BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62D4600000000000ULL,
		0x3153F93FACCB068FULL,
		0x28642DFCBEBC18D2ULL,
		0xA02ECBE8426DFCD4ULL,
		0x000003A27DB0E045ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8EC427FC87852C6ULL,
		0x0FB6435A95FD9E9CULL,
		0x7C3D3EF293362E3EULL,
		0x6B16CB6EEDF5D8CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0xE6C76213FE43C296ULL,
		0xF07DB21AD4AFECF4ULL,
		0x6BE1E9F79499B171ULL,
		0x0358B65B776FAEC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48C52CC6F561C59EULL,
		0x614783ABB289BA60ULL,
		0x7C040B765ED81D28ULL,
		0xC3D4432B143FBF3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA598DEAC38B3C000ULL,
		0xF0757651374C0918ULL,
		0x816ECBDB03A50C28ULL,
		0x88656287F7E7EF80ULL,
		0x000000000000187AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8F19BBDBDCBCFEFULL,
		0x3AA1F61AD3C57817ULL,
		0xCABDBDE47356951FULL,
		0x115C253A96300A7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFEF0000000000000ULL,
		0x817C8F19BBDBDCBCULL,
		0x51F3AA1F61AD3C57ULL,
		0xA7ACABDBDE473569ULL,
		0x000115C253A96300ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x438F6AE9A8EB67D7ULL,
		0xB7C1AA55595A5CE9ULL,
		0x7CEDE4620433A9C1ULL,
		0xDF36982FA0617052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B574D475B3EB800ULL,
		0x0D52AACAD2E74A1CULL,
		0x6F2310219D4E0DBEULL,
		0xB4C17D030B8293E7ULL,
		0x00000000000006F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5894F0725298281ULL,
		0x7A92C64FCB06629AULL,
		0xC31C906CC983EC5BULL,
		0x54CF11E7D12EB607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A0400000000000ULL,
		0x98A6B96253C1C94AULL,
		0xFB16DEA4B193F2C1ULL,
		0xAD81F0C7241B3260ULL,
		0x00001533C479F44BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57E98CEDD4E6C446ULL,
		0x3E9E00643DABAEFEULL,
		0xF503158EDA1602C0ULL,
		0x262D0842A4B51533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7362230000000000ULL,
		0xD5D77F2BF4C676EAULL,
		0x0B01601F4F00321EULL,
		0x5A8A99FA818AC76DULL,
		0x0000001316842152ULL
	}};
	shift = 25;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x388814F8FA74521AULL,
		0x7DC388E5101CA4E2ULL,
		0xD02F494FE39741C3ULL,
		0xCFD4AC90E0C64968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x388814F8FA74521AULL,
		0x7DC388E5101CA4E2ULL,
		0xD02F494FE39741C3ULL,
		0xCFD4AC90E0C64968ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF22863CA3ADD1257ULL,
		0x5F236101571F88E2ULL,
		0xA22704D88AA18937ULL,
		0x23EC5876E003D7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31E51D6E892B8000ULL,
		0xB080AB8FC4717914ULL,
		0x826C4550C49BAF91ULL,
		0x2C3B7001EBF25113ULL,
		0x00000000000011F6ULL
	}};
	shift = 49;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA242D38419BE34EULL,
		0xB0C366AEB79C590BULL,
		0xA8313495497B864DULL,
		0x78E44C8A2B3280C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE34E000000000000ULL,
		0x590BCA242D38419BULL,
		0x864DB0C366AEB79CULL,
		0x80C8A8313495497BULL,
		0x000078E44C8A2B32ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8093843620E15A8ULL,
		0x6C74A072879FAD89ULL,
		0xC03B5285AABAEF23ULL,
		0x1CB7C6AE0BDD5C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAD40000000000000ULL,
		0x6C4DC049C21B1070ULL,
		0x791B63A503943CFDULL,
		0xE14601DA942D55D7ULL,
		0x0000E5BE35705EEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64301054FDA74731ULL,
		0x7BC35A6E8710B225ULL,
		0x0C5E679F6EBD94D5ULL,
		0x6655876FA37019AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xB218082A7ED3A398ULL,
		0xBDE1AD3743885912ULL,
		0x062F33CFB75ECA6AULL,
		0x332AC3B7D1B80CD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x994B63FD9A384234ULL,
		0x637DA8A9160A08DEULL,
		0xACE52CCA38FB0054ULL,
		0x5B1F0B0FF76EA698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0xBD3296C7FB347084ULL,
		0xA8C6FB51522C1411ULL,
		0x3159CA599471F600ULL,
		0x00B63E161FEEDD4DULL
	}};
	shift = 7;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x628D82B071AD22C6ULL,
		0x176EE346B3FA1FE3ULL,
		0xDB36CCA5B728E6A3ULL,
		0xED9E240174A9B025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48B1800000000000ULL,
		0x87F8D8A360AC1C6BULL,
		0x39A8C5DBB8D1ACFEULL,
		0x6C0976CDB3296DCAULL,
		0x00003B6789005D2AULL
	}};
	shift = 18;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x577321D12768856AULL,
		0x19E4CDFF9F647DB4ULL,
		0xDF6476987A4168C2ULL,
		0x14A8211E9E3F470EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB500000000000000ULL,
		0xDA2BB990E893B442ULL,
		0x610CF266FFCFB23EULL,
		0x876FB23B4C3D20B4ULL,
		0x000A54108F4F1FA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64BFFEA0130F7CBCULL,
		0xB62F0ECD27D7BE08ULL,
		0xAC88D4B311E550FEULL,
		0x12749A7D90B30E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x804C3DF2F0000000ULL,
		0x349F5EF82192FFFAULL,
		0xCC479543FAD8BC3BULL,
		0xF642CC3842B22352ULL,
		0x000000000049D269ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x310BC669DD691799ULL,
		0xD06757C7B147838AULL,
		0x3DC1D89BC4CC6C08ULL,
		0x7B8DFD1BA341FA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC800000000000000ULL,
		0x51885E334EEB48BCULL,
		0x46833ABE3D8A3C1CULL,
		0x49EE0EC4DE266360ULL,
		0x03DC6FE8DD1A0FD2ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E99CED7EB0B2D0AULL,
		0xED76384CD0319CF6ULL,
		0xA5809C4B42A6D410ULL,
		0x6625C1FB2F95AA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFD6165A140000000ULL,
		0x9A06339EC9D339DAULL,
		0x6854DA821DAEC709ULL,
		0x65F2B54814B01389ULL,
		0x000000000CC4B83FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BBC2AB15E9F41A6ULL,
		0xEB767BBB7177D476ULL,
		0x4A4A0FC22B1D94E2ULL,
		0x3E8BD7837F1995BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D30000000000000ULL,
		0xA3B3DDE1558AF4FAULL,
		0xA7175BB3DDDB8BBEULL,
		0xADEA52507E1158ECULL,
		0x0001F45EBC1BF8CCULL,
		0x0000000000000000ULL
	}};
	shift = 77;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB19F77E9F10682FULL,
		0x47C792C2FCDEFF59ULL,
		0x25F28EA9D051D2E9ULL,
		0xFEB5D54D2D5F7EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CFBBF4F8834178ULL,
		0x3E3C9617E6F7FACDULL,
		0x2F94754E828E974AULL,
		0xF5AEAA696AFBF7A9ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x832C97B6D4386BD6ULL,
		0x55A63EB54650F675ULL,
		0x59A61F8E8850EA1DULL,
		0x5151E22319B8EFBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1AF5800000000000ULL,
		0x3D9D60CB25EDB50EULL,
		0x3A8755698FAD5194ULL,
		0x3BEE966987E3A214ULL,
		0x000014547888C66EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E297DE6EE88C446ULL,
		0x54401A53B4D733D1ULL,
		0x1E111EF0ABB5FEF0ULL,
		0x48957C59F64700C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE88C44600000000ULL,
		0xB4D733D14E297DE6ULL,
		0xABB5FEF054401A53ULL,
		0xF64700C11E111EF0ULL,
		0x0000000048957C59ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6768FAD3F89CB01ULL,
		0xBF4029E6814F0CB9ULL,
		0xA09BF09750B2CFD0ULL,
		0x0201B401EC498DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B47D69FC4E58080ULL,
		0xA014F340A7865CE3ULL,
		0x4DF84BA85967E85FULL,
		0x00DA00F624C6F550ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F28C54B063EABBAULL,
		0x58E4C9A75357D92CULL,
		0x2E7C9F4885D9F750ULL,
		0xD96E8A3015F7CBC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD577400000000000ULL,
		0xFB258BE518A960C7ULL,
		0x3EEA0B1C9934EA6AULL,
		0xF97905CF93E910BBULL,
		0x00001B2DD14602BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7AB5FAB469C3CB61ULL,
		0x09B5C46EBEAFE7D6ULL,
		0x7573F4A72AC42E17ULL,
		0xEB9F42DAB7E4230DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF568D38796C20000ULL,
		0x88DD7D5FCFACF56BULL,
		0xE94E55885C2E136BULL,
		0x85B56FC8461AEAE7ULL,
		0x000000000001D73EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x185A55D2E9996417ULL,
		0x1BBE4C4982D196C0ULL,
		0x9B3829696FC4C369ULL,
		0x0D44DD5D5943D39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9996417000000000ULL,
		0x2D196C0185A55D2EULL,
		0xFC4C3691BBE4C498ULL,
		0x943D39A9B3829696ULL,
		0x00000000D44DD5D5ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x627D57B1DB787945ULL,
		0x44319AF2558206FCULL,
		0x61955065C8BAC5EBULL,
		0xCC4313398AC2CD6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC3CA28000000000ULL,
		0xC1037E313EABD8EDULL,
		0x5D62F5A218CD792AULL,
		0x6166B630CAA832E4ULL,
		0x0000006621899CC5ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5D61CCF555A7B72ULL,
		0xE94E514836F9CDA2ULL,
		0xD66385E6044992A6ULL,
		0x66DE035BB14E8E81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1CCF555A7B720000ULL,
		0x514836F9CDA2A5D6ULL,
		0x85E6044992A6E94EULL,
		0x035BB14E8E81D663ULL,
		0x00000000000066DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4AD724A501A862D4ULL,
		0xFE742363342DCF14ULL,
		0xA3F4D095AA3F6507ULL,
		0xF18B89A558B15001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB925280D4316A000ULL,
		0xA11B19A16E78A256ULL,
		0xA684AD51FB283FF3ULL,
		0x5C4D2AC58A800D1FULL,
		0x000000000000078CULL,
		0x0000000000000000ULL
	}};
	shift = 117;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE787B3517934BDB9ULL,
		0x8655867CF1B044C4ULL,
		0x5767F71DF74B22C6ULL,
		0x468E3B1103E1B7B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x73C3D9A8BC9A5EDCULL,
		0x432AC33E78D82262ULL,
		0x2BB3FB8EFBA59163ULL,
		0x23471D8881F0DBDBULL,
		0x0000000000000000ULL
	}};
	shift = 65;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FF76FCC6271058BULL,
		0x6A76BC029AD3F467ULL,
		0xE581A0E53AC40BAAULL,
		0x3A364EA904350FBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4162C00000000000ULL,
		0xFD19D7FDDBF3189CULL,
		0x02EA9A9DAF00A6B4ULL,
		0x43EFB96068394EB1ULL,
		0x00000E8D93AA410DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4C543EEB650AA41ULL,
		0x75C6131F61522EFDULL,
		0x3631CEC1A1CD2BA5ULL,
		0xFE07796AA92FFDBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x6D3150FBAD942A90ULL,
		0x5D7184C7D8548BBFULL,
		0x0D8C73B068734AE9ULL,
		0x3F81DE5AAA4BFF6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x085BB0948DA23BDCULL,
		0x8F9CFFCFF72AA773ULL,
		0x8AD7CC17346C7A2CULL,
		0x46E4D422251B9F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1291B4477B800000ULL,
		0xF9FEE554EE610B76ULL,
		0x82E68D8F4591F39FULL,
		0x8444A373ECD15AF9ULL,
		0x000000000008DC9AULL
	}};
	shift = 43;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C4FD4B293EEF811ULL,
		0x9A0C5230F7E4F979ULL,
		0x49048CDF0A21B7D2ULL,
		0x5EB53A4F0F0BFA98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x527DDF0220000000ULL,
		0x1EFC9F2F2389FA96ULL,
		0xE14436FA53418A46ULL,
		0xE1E17F530920919BULL,
		0x000000000BD6A749ULL
	}};
	shift = 35;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F381743BBE3AA65ULL,
		0x58BFE6889B5A78D8ULL,
		0x74DD0EA606866AB3ULL,
		0x52A34F7A958DE266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x54CA000000000000ULL,
		0xF1B03E702E8777C7ULL,
		0xD566B17FCD1136B4ULL,
		0xC4CCE9BA1D4C0D0CULL,
		0x0000A5469EF52B1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1983F98AE39B97CULL,
		0xE1605A83A4117232ULL,
		0xDADFFE3299D31872ULL,
		0xE44F87F405CAEF0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B8E6E5F00000000ULL,
		0xE9045C8CAC660FE6ULL,
		0xA674C61CB85816A0ULL,
		0x0172BBC3F6B7FF8CULL,
		0x000000003913E1FDULL,
		0x0000000000000000ULL
	}};
	shift = 98;
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
		0x0000000000000000ULL,
		0x7A51F68D5763EA20ULL,
		0xFDBEB1AC59A95EE3ULL,
		0xCA501B2C4DBA45C8ULL,
		0x669D7B787FC5BC74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F68D5763EA20000ULL,
		0xEB1AC59A95EE37A5ULL,
		0x01B2C4DBA45C8FDBULL,
		0xD7B787FC5BC74CA5ULL,
		0x0000000000000669ULL
	}};
	shift = 52;
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
		0x0000000000000000ULL,
		0xDED7B62571C5792FULL,
		0x5BA6ADDAF7F8A02CULL,
		0xC41CEC9ED273DACAULL,
		0x1277F5C3FC742002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5ED895C715E4BC00ULL,
		0x9AB76BDFE280B37BULL,
		0x73B27B49CF6B296EULL,
		0xDFD70FF1D0800B10ULL,
		0x0000000000000049ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED27DC4CFF211BFAULL,
		0xA208091B0294E3E9ULL,
		0x693CADF0A3893181ULL,
		0x3A6272575D7D317CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x211BFA0000000000ULL,
		0x94E3E9ED27DC4CFFULL,
		0x893181A208091B02ULL,
		0x7D317C693CADF0A3ULL,
		0x0000003A6272575DULL,
		0x0000000000000000ULL
	}};
	shift = 88;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCADE62660794BC57ULL,
		0x1FD8929ADB8D4178ULL,
		0x7D6F979978C01FDBULL,
		0x4362561CC68E1D92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE00000000000000ULL,
		0xF195BCC4CC0F2978ULL,
		0xB63FB12535B71A82ULL,
		0x24FADF2F32F1803FULL,
		0x0086C4AC398D1C3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6B97942B216F04BULL,
		0xECCEEE8CB438496EULL,
		0x06DC542CE0FE24E0ULL,
		0x972898EE11E6D979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7942B216F04B0000ULL,
		0xEE8CB438496EC6B9ULL,
		0x542CE0FE24E0ECCEULL,
		0x98EE11E6D97906DCULL,
		0x0000000000009728ULL
	}};
	shift = 48;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53ED41880B3E0CB8ULL,
		0x6B864B8B8869BDD1ULL,
		0xC99DF3547B5F711CULL,
		0x3ED254F7241C799DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F065C0000000000ULL,
		0x34DEE8A9F6A0C405ULL,
		0xAFB88E35C325C5C4ULL,
		0x0E3CCEE4CEF9AA3DULL,
		0x0000001F692A7B92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3011C52D6A7B6E94ULL,
		0x0B7C914750EEE1EAULL,
		0xE1C82521A6951EA4ULL,
		0xB1605B4740BF1EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBA500000000000ULL,
		0xBB87A8C04714B5A9ULL,
		0x547A902DF2451D43ULL,
		0xFC7A9B872094869AULL,
		0x000002C5816D1D02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC515AC255CEF727FULL,
		0x4EE2CFDB99911212ULL,
		0xBE5EEAA09E3DD267ULL,
		0x418AC561EFA5BF5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12AE77B93F800000ULL,
		0xEDCCC88909628AD6ULL,
		0x504F1EE933A77167ULL,
		0xB0F7D2DFAE5F2F75ULL,
		0x000000000020C562ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32DADA34B3A07639ULL,
		0x1B83C389EDEB31C2ULL,
		0x11CEE4744DA71BE3ULL,
		0x29BEAE50BB21070DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7639000000000000ULL,
		0x31C232DADA34B3A0ULL,
		0x1BE31B83C389EDEBULL,
		0x070D11CEE4744DA7ULL,
		0x000029BEAE50BB21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDD2B5F9265DE072ULL,
		0x5AE75D7CF4B6A7E0ULL,
		0x676A230A98FAD745ULL,
		0xBDBC5282AF571F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774AD7E4997781C8ULL,
		0x6B9D75F3D2DA9F83ULL,
		0x9DA88C2A63EB5D15ULL,
		0xF6F14A0ABD5C7D8DULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A2CE92A9B43AEFEULL,
		0xBFF62B0B034C72ACULL,
		0x952262F1EDFAAB93ULL,
		0x66F92D7B74087B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6D0EBBF80000000ULL,
		0xC0D31CAB0E8B3A4AULL,
		0x7B7EAAE4EFFD8AC2ULL,
		0xDD021EC4E54898BCULL,
		0x0000000019BE4B5EULL
	}};
	shift = 34;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7906AC1390EAA7FULL,
		0xD4BE587EF9953876ULL,
		0xAC63682EDE3384D8ULL,
		0x35544D44683A88FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x35609C87553F8000ULL,
		0x2C3F7CCA9C3B5BC8ULL,
		0xB4176F19C26C6A5FULL,
		0x26A2341D447F5631ULL,
		0x0000000000001AAAULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83F29D9DF36DAFCDULL,
		0x4FB8CF878C3F7234ULL,
		0xB4745A6AC62A4B4EULL,
		0x106B5F5ACB76B3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6D7E6800000000ULL,
		0x61FB91A41F94ECEFULL,
		0x31525A727DC67C3CULL,
		0x5BB59F3DA3A2D356ULL,
		0x00000000835AFAD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F160BE197B23DFFULL,
		0x4353A6E76FE6C765ULL,
		0x6F8280FC51D9B167ULL,
		0xF5B56AC7A66DD3F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B05F0CBD91EFF8ULL,
		0x1A9D373B7F363B29ULL,
		0x7C1407E28ECD8B3AULL,
		0xADAB563D336E9FABULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CD86AE5D3A8B92EULL,
		0x35F127D7945FA191ULL,
		0x29AC05547EB6A549ULL,
		0x728E058B6C287225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA751725C0000000ULL,
		0xF28BF432219B0D5CULL,
		0x8FD6D4A926BE24FAULL,
		0x6D850E44A53580AAULL,
		0x000000000E51C0B1ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A07198DCC672F14ULL,
		0x99D66A2ECB776AF2ULL,
		0x903CE83D70C71848ULL,
		0x550B1E1B323BC701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A00000000000000ULL,
		0x791D038CC6E63397ULL,
		0x244CEB351765BBB5ULL,
		0x80C81E741EB8638CULL,
		0x002A858F0D991DE3ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E303D4CDA1D0B40ULL,
		0x12A139C25582C836ULL,
		0xC3EC733654E32782ULL,
		0xA2389BD448C0A153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CDA1D0B40000000ULL,
		0xC25582C8360E303DULL,
		0x3654E3278212A139ULL,
		0xD448C0A153C3EC73ULL,
		0x0000000000A2389BULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E7DD124949CBE48ULL,
		0xC9A71A9545467612ULL,
		0x936C4EE8CDCBA476ULL,
		0xEB76A8AC0554DCAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49CBE48000000000ULL,
		0x54676125E7DD1249ULL,
		0xDCBA476C9A71A954ULL,
		0x554DCAA936C4EE8CULL,
		0x0000000EB76A8AC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7EE144E46B768EC9ULL,
		0x6C51BFAF1A9653A0ULL,
		0x749545D26FBF88E0ULL,
		0xA71C3EEE239C1DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC9000000000000ULL,
		0x53A07EE144E46B76ULL,
		0x88E06C51BFAF1A96ULL,
		0x1DA2749545D26FBFULL,
		0x0000A71C3EEE239CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x776A47F12E5D7FF4ULL,
		0x0028F9A166B77110ULL,
		0x85AB5A1A363EDC0FULL,
		0x4C5D6E708B3219B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E5D7FF400000000ULL,
		0x66B77110776A47F1ULL,
		0x363EDC0F0028F9A1ULL,
		0x8B3219B285AB5A1AULL,
		0x000000004C5D6E70ULL
	}};
	shift = 32;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x426B46CFE57C88F0ULL,
		0x5784305BFD61022BULL,
		0xB2F592510E8CC93EULL,
		0x84EA26CCDB7CF3F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x46CFE57C88F00000ULL,
		0x305BFD61022B426BULL,
		0x92510E8CC93E5784ULL,
		0x26CCDB7CF3F4B2F5ULL,
		0x00000000000084EAULL
	}};
	shift = 48;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E34E021B8A061C7ULL,
		0x203AB708321B0D17ULL,
		0xBC40FED7D3EA82DDULL,
		0x839D9A1D2919D84DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86E281871C000000ULL,
		0x20C86C345E38D380ULL,
		0x5F4FAA0B7480EADCULL,
		0x74A4676136F103FBULL,
		0x00000000020E7668ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DBE5AACC673D83AULL,
		0xAF668DE8C55ADBCFULL,
		0x3FDEB255C10ABE93ULL,
		0x521F3D0B938B8DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xE76F96AB319CF60EULL,
		0xEBD9A37A3156B6F3ULL,
		0xCFF7AC957042AFA4ULL,
		0x1487CF42E4E2E36FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF53B9D387993C8FULL,
		0x3E4A0E76D0A6C543ULL,
		0x68719A058BDCB2BFULL,
		0x9B8A78004D4DB0D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F00000000000000ULL,
		0x43DF53B9D387993CULL,
		0xBF3E4A0E76D0A6C5ULL,
		0xD068719A058BDCB2ULL,
		0x009B8A78004D4DB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA4A8FEAB56DB483AULL,
		0x48A134DC62E83410ULL,
		0x400A682929A54153ULL,
		0x3935E5EDDF5BA83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB69074000000000ULL,
		0x5D068214951FD56AULL,
		0x34A82A6914269B8CULL,
		0xEB750748014D0525ULL,
		0x0000000726BCBDBBULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DE8970A67C03938ULL,
		0xB7F054BE78C254FDULL,
		0x90767589A4E9BA04ULL,
		0xC9D0F14A1C9F5A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5C299F00E4E00000ULL,
		0x52F9E30953F4F7A2ULL,
		0xD62693A6E812DFC1ULL,
		0xC528727D683A41D9ULL,
		0x0000000000032743ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA210FEB97FC330CULL,
		0x4D59F0862AAF8F6BULL,
		0xC859DD0846342F4FULL,
		0x1CD72371D6CF1B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE5FF0CC3000000ULL,
		0x218AABE3DAF28843ULL,
		0x42118D0BD3D3567CULL,
		0xDC75B3C6C1721677ULL,
		0x00000000000735C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14C03B8BDF9D7F2EULL,
		0x9B0EEA2BB1CC9786ULL,
		0x63119A686E7D975EULL,
		0xC0B9CE1C3B26FB5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE5C000000000000ULL,
		0x2F0C29807717BF3AULL,
		0x2EBD361DD4576399ULL,
		0xF6B4C62334D0DCFBULL,
		0x000181739C38764DULL
	}};
	shift = 15;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98CE37F009CF232EULL,
		0xE6BCD8F5B340724AULL,
		0x967010EA5FA14CA6ULL,
		0x876B333277931708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x009CF232E0000000ULL,
		0x5B340724A98CE37FULL,
		0xA5FA14CA6E6BCD8FULL,
		0x277931708967010EULL,
		0x000000000876B333ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC599899CEA8236B2ULL,
		0x1B186ECFF8223A9FULL,
		0x4E3DB4A41A27B504ULL,
		0x26BA859CB2AC2952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5411B59000000000ULL,
		0xC111D4FE2CCC4CE7ULL,
		0xD13DA820D8C3767FULL,
		0x95614A9271EDA520ULL,
		0x0000000135D42CE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D63B39A0EB84F81ULL,
		0xE1B7084A0EDD7C65ULL,
		0x62A146B91B6D96D7ULL,
		0xE6DF298247B1F49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27C0800000000000ULL,
		0xBE32C6B1D9CD075CULL,
		0xCB6BF0DB8425076EULL,
		0xFA4E3150A35C8DB6ULL,
		0x0000736F94C123D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1946BDACA2F70843ULL,
		0x138C642078FE7FD8ULL,
		0xB49395FEE33C9450ULL,
		0x3DAB4E63BD0030F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5945EE1086000000ULL,
		0x40F1FCFFB0328D7BULL,
		0xFDC67928A02718C8ULL,
		0xC77A0061E369272BULL,
		0x00000000007B569CULL
	}};
	shift = 39;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA4205E2988564EF8ULL,
		0x87B01FC4C19A8526ULL,
		0xE0F85B7D6DF7AEC1ULL,
		0xB12B56F6F531898EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A621593BE000000ULL,
		0xF13066A149A90817ULL,
		0xDF5B7DEBB061EC07ULL,
		0xBDBD4C6263B83E16ULL,
		0x00000000002C4AD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF06DBC973E6CBBD2ULL,
		0xC3E28FCCA96461AAULL,
		0x1C24B49525722B05ULL,
		0xD9BC74A96ADE48D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25CF9B2EF4800000ULL,
		0xF32A59186ABC1B6FULL,
		0x25495C8AC170F8A3ULL,
		0x2A5AB7923507092DULL,
		0x0000000000366F1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC8CDDD93B39BDC9ULL,
		0x98A325021EA69028ULL,
		0xDC09BDBB35F757AFULL,
		0x08C9CB017164165DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEE48000000000000ULL,
		0x8146E466EEC9D9CDULL,
		0xBD7CC5192810F534ULL,
		0xB2EEE04DEDD9AFBAULL,
		0x0000464E580B8B20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6382C71A5AEDF974ULL,
		0x287D2343E6BC6775ULL,
		0x2BE11305B3652CA4ULL,
		0x864A077A0EEDDE25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6382C71A5AEDF974ULL,
		0x287D2343E6BC6775ULL,
		0x2BE11305B3652CA4ULL,
		0x864A077A0EEDDE25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4BE15FCB89CA0F1ULL,
		0x98815A0756E39DA3ULL,
		0x791855BC1F250688ULL,
		0x19CE073F1816C77EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41E2000000000000ULL,
		0x3B47A97C2BF97139ULL,
		0x0D113102B40EADC7ULL,
		0x8EFCF230AB783E4AULL,
		0x0000339C0E7E302DULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEEF6E17E3A9189BEULL,
		0xAF2F61FF1B54BD35ULL,
		0xB8FD29454BD37B01ULL,
		0x1602FA84180D7102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89BE000000000000ULL,
		0xBD35EEF6E17E3A91ULL,
		0x7B01AF2F61FF1B54ULL,
		0x7102B8FD29454BD3ULL,
		0x00001602FA84180DULL
	}};
	shift = 16;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95EA83F3FEA30023ULL,
		0x765DF1CD15EEE7FBULL,
		0x81E6912EFBFF6EC7ULL,
		0xEE8B214BD4B27B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F9FF5180118000ULL,
		0xF8E68AF773FDCAF5ULL,
		0x48977DFFB763BB2EULL,
		0x90A5EA593DA340F3ULL,
		0x0000000000007745ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x842F5C98AC0CD22DULL,
		0x3C74ACB5D1DD01F3ULL,
		0x71D7E5F9B9D8DC7AULL,
		0x8E481BCD2D467816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x7085EB9315819A45ULL,
		0x478E9596BA3BA03EULL,
		0xCE3AFCBF373B1B8FULL,
		0x11C90379A5A8CF02ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x20EA0D923929879DULL,
		0xF66409AF0A062BEDULL,
		0x209A11584D1EFDF8ULL,
		0xECC69FF66DFDAC8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA83648E4A61E7400ULL,
		0x9026BC2818AFB483ULL,
		0x684561347BF7E3D9ULL,
		0x1A7FD9B7F6B22C82ULL,
		0x00000000000003B3ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65243C6F1C72DF3AULL,
		0xC58A1D7C18EF2F74ULL,
		0xDFBAE39440BDF39EULL,
		0x082AFB6DE132FE6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE396F9D000000000ULL,
		0xC7797BA32921E378ULL,
		0x05EF9CF62C50EBE0ULL,
		0x0997F37EFDD71CA2ULL,
		0x000000004157DB6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8612311333349FDULL,
		0xAE7E7BE062BB62D0ULL,
		0x04CB69BB5D2DDE3CULL,
		0xF57AA6C8F4838064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4FE8000000000000ULL,
		0x1685C3091889999AULL,
		0xF1E573F3DF0315DBULL,
		0x0320265B4DDAE96EULL,
		0x0007ABD53647A41CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE1FCDBD1834107BAULL,
		0x53131C3A60BEF32BULL,
		0xFBD5288FFB8FBA38ULL,
		0xE58710F221BEA04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x460D041EE8000000ULL,
		0xE982FBCCAF87F36FULL,
		0x3FEE3EE8E14C4C70ULL,
		0xC886FA8133EF54A2ULL,
		0x0000000003961C43ULL
	}};
	shift = 38;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA148B0D87231EFD4ULL,
		0x11573EA3A62A6AB5ULL,
		0x3648F72C06B2DE9EULL,
		0xAAB85A9A361F0D2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0A4586C3918F7EA0ULL,
		0x8AB9F51D315355ADULL,
		0xB247B9603596F4F0ULL,
		0x55C2D4D1B0F86951ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A918FDAAB36D2F5ULL,
		0xB37E29F83A18AAB8ULL,
		0x2DC2B9B981A2EFB6ULL,
		0x8B76FBE4F0C0ACB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36D2F50000000000ULL,
		0x18AAB83A918FDAABULL,
		0xA2EFB6B37E29F83AULL,
		0xC0ACB52DC2B9B981ULL,
		0x0000008B76FBE4F0ULL
	}};
	shift = 24;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA12783D1880E490BULL,
		0xE47815F932561C01ULL,
		0x1828639F5F52190EULL,
		0x3B94813822AF740EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x24F07A3101C92160ULL,
		0x8F02BF264AC38034ULL,
		0x050C73EBEA4321DCULL,
		0x7290270455EE81C3ULL,
		0x0000000000000007ULL
	}};
	shift = 59;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA6D116C9A2D1E83ULL,
		0xE0305B4B331D651FULL,
		0xD69A20FF84674D42ULL,
		0x99559790709A2A39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x88B64D168F418000ULL,
		0x2DA5998EB28FFD36ULL,
		0x107FC233A6A17018ULL,
		0xCBC8384D151CEB4DULL,
		0x0000000000004CAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34899F2E1482E4E3ULL,
		0x296EA4528E72082AULL,
		0x3F3CD887E99B9D21ULL,
		0xB5410A34BA199A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05C9C60000000000ULL,
		0xE4105469133E5C29ULL,
		0x373A4252DD48A51CULL,
		0x3334BA7E79B10FD3ULL,
		0x0000016A82146974ULL
	}};
	shift = 23;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA54A5E0E855BF551ULL,
		0x85DC6AE314F153FCULL,
		0x1E010AA3BD007E2EULL,
		0x0FC8E7496CA5B49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF0742ADFAA880000ULL,
		0x5718A78A9FE52A52ULL,
		0x551DE803F1742EE3ULL,
		0x3A4B652DA4E0F008ULL,
		0x0000000000007E47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB32414D985F1C4BDULL,
		0x7EBBD6469C8C0DB6ULL,
		0x97A3EEAF25183401ULL,
		0x45BA45351D14A53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6CC2F8E25E80000ULL,
		0xB234E4606DB59920ULL,
		0x757928C1A00BF5DEULL,
		0x29A8E8A529D4BD1FULL,
		0x0000000000022DD2ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1288E8AA864079DBULL,
		0x5D703E6758B60A49ULL,
		0x9EB6466F76E270DAULL,
		0xF967EB0CBE2E60A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4079DB0000000000ULL,
		0xB60A491288E8AA86ULL,
		0xE270DA5D703E6758ULL,
		0x2E60A79EB6466F76ULL,
		0x000000F967EB0CBEULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76C266CAC8A66E5CULL,
		0x12463EBF931B9B98ULL,
		0x77D303A3B0CCB290ULL,
		0xD58369EF0B72356DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDCB800000000000ULL,
		0x73730ED84CD95914ULL,
		0x96520248C7D7F263ULL,
		0x46ADAEFA60747619ULL,
		0x00001AB06D3DE16EULL
	}};
	shift = 19;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75DAC3465317081AULL,
		0xB8E6C857BA86072AULL,
		0x78907F58877DEE0DULL,
		0x5F468F7B81E56867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B840D0000000000ULL,
		0x4303953AED61A329ULL,
		0xBEF706DC73642BDDULL,
		0xF2B433BC483FAC43ULL,
		0x0000002FA347BDC0ULL
	}};
	shift = 25;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0002928DE515BD4AULL,
		0x5DD638838C8CEDA4ULL,
		0xF1DD140D5E55D298ULL,
		0x3D5B1D9ECE154F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF528000000000000ULL,
		0xB690000A4A379456ULL,
		0x4A617758E20E3233ULL,
		0x3E7BC77450357957ULL,
		0x0000F56C767B3855ULL
	}};
	shift = 14;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95DE8FA2D31D4FACULL,
		0xC5CF5A49B741D353ULL,
		0xC8D141B97FDF9ACCULL,
		0x28A21EC464ADFD93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3A9F580000000000ULL,
		0x83A6A72BBD1F45A6ULL,
		0xBF35998B9EB4936EULL,
		0x5BFB2791A28372FFULL,
		0x00000051443D88C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B3440E2E289014AULL,
		0xA9467CC34D8BA859ULL,
		0xB604B34D0DA14786ULL,
		0x3D703ED77F136CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A50000000000000ULL,
		0x42C959A207171448ULL,
		0x3C354A33E61A6C5DULL,
		0x6575B0259A686D0AULL,
		0x0001EB81F6BBF89BULL
	}};
	shift = 13;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9749BABFC7ADEC0DULL,
		0x4F0777119A1AEFD8ULL,
		0x9E46057547E3DE50ULL,
		0x2DED0D7DCDA0799DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81A0000000000000ULL,
		0xFB12E93757F8F5BDULL,
		0xCA09E0EEE233435DULL,
		0x33B3C8C0AEA8FC7BULL,
		0x0005BDA1AFB9B40FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C366CC54B6993F0ULL,
		0xF8D7FDAB91571F73ULL,
		0xC973299F26F4B2EFULL,
		0x01D9047967622187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A96D327E0000000ULL,
		0x5722AE3EE6D86CD9ULL,
		0x3E4DE965DFF1AFFBULL,
		0xF2CEC4430F92E653ULL,
		0x000000000003B208ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x496F2738FD7D331FULL,
		0x4785B8A0B1DAC172ULL,
		0x8AA9B7BE507C91F9ULL,
		0x2F6D9CFB9773DD7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7939C7EBE998F80ULL,
		0xC2DC5058ED60B924ULL,
		0x54DBDF283E48FCA3ULL,
		0xB6CE7DCBB9EEBDC5ULL,
		0x0000000000000017ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5204116739407B7ULL,
		0xEAF725F79AAA7C3BULL,
		0x2779E397EF83000DULL,
		0x76F728FCFFDD4C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6739407B70000000ULL,
		0x79AAA7C3BD520411ULL,
		0x7EF83000DEAF725FULL,
		0xCFFDD4C542779E39ULL,
		0x00000000076F728FULL
	}};
	shift = 36;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B7677992C53E98BULL,
		0x0CCE0FC25E06CC6CULL,
		0xC3C463209548ECD5ULL,
		0x473EC674FB7FA373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB000000000000000ULL,
		0xC8B7677992C53E98ULL,
		0x50CCE0FC25E06CC6ULL,
		0x3C3C463209548ECDULL,
		0x0473EC674FB7FA37ULL
	}};
	shift = 4;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8E40BB03194F087ULL,
		0xB4D47214CBE433FDULL,
		0xDF0BE0F210635BBAULL,
		0x849885DC2F74A578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7843800000000000ULL,
		0x19FEEC7205D818CAULL,
		0xADDD5A6A390A65F2ULL,
		0x52BC6F85F0790831ULL,
		0x0000424C42EE17BAULL
	}};
	shift = 17;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x880FF0BFB0FF75DCULL,
		0x368E4BB66EF14306ULL,
		0xB2C7F1D2571BDD7DULL,
		0x5A378C12C6D55D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x880FF0BFB0FF75DCULL,
		0x368E4BB66EF14306ULL,
		0xB2C7F1D2571BDD7DULL,
		0x5A378C12C6D55D60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D03173B6EB6A3A7ULL,
		0x364C2BBCB984E8D8ULL,
		0x6FFB6E4D65F2EDB5ULL,
		0x6FD49615895042B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x0B40C5CEDBADA8E9ULL,
		0x4D930AEF2E613A36ULL,
		0x5BFEDB93597CBB6DULL,
		0x1BF52585625410AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44AF27EB04D55C9AULL,
		0x19F5A1E769D7EF4FULL,
		0xD341F1A887EED337ULL,
		0x612E35D4F92F1652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FAC135572680000ULL,
		0x879DA75FBD3D12BCULL,
		0xC6A21FBB4CDC67D6ULL,
		0xD753E4BC594B4D07ULL,
		0x00000000000184B8ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4098A328126DA86ULL,
		0x42B4FFDE4E991844ULL,
		0x30A790920E0D8AD6ULL,
		0x6777D4FCAA3EE686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5024DB50C0000000ULL,
		0xC9D3230898813146ULL,
		0x41C1B15AC8569FFBULL,
		0x9547DCD0C614F212ULL,
		0x000000000CEEFA9FULL
	}};
	shift = 35;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F91E0FFC2138606ULL,
		0xABDDC59B66044EAFULL,
		0x1DB47FE1198870F7ULL,
		0x9858ACFE9BE0EFF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x783FF084E1818000ULL,
		0x7166D98113ABDFE4ULL,
		0x1FF846621C3DEAF7ULL,
		0x2B3FA6F83BFE076DULL,
		0x0000000000002616ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29CD4837439F75F6ULL,
		0x0A3AF075F84CEE9DULL,
		0x45C8F20551207FD3ULL,
		0xF51607A674C91646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD0E7DD7D800000ULL,
		0x1D7E133BA74A7352ULL,
		0x8154481FF4C28EBCULL,
		0xE99D32459191723CULL,
		0x00000000003D4581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x69DC4A8CF7CCEEADULL,
		0x3E95780560D9DACAULL,
		0xAE83D014224388B9ULL,
		0xAF5DD0CB4232F3ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF7CCEEAD00000000ULL,
		0x60D9DACA69DC4A8CULL,
		0x224388B93E957805ULL,
		0x4232F3ACAE83D014ULL,
		0x00000000AF5DD0CBULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA2ECBB08E5A83A5ULL,
		0xA0627A34FB8A76BBULL,
		0x949A6D9A0AB92253ULL,
		0x2B8DC090EFD85DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA500000000000000ULL,
		0xBBFA2ECBB08E5A83ULL,
		0x53A0627A34FB8A76ULL,
		0xB1949A6D9A0AB922ULL,
		0x002B8DC090EFD85DULL
	}};
	shift = 8;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AEAC95A900F04BDULL,
		0xA31349668696B744ULL,
		0x3790D2F4A59797FBULL,
		0x2F2C65A17FAB8BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4807825E8000000ULL,
		0x3434B5BA2457564AULL,
		0xA52CBCBFDD189A4BULL,
		0x0BFD5C5E29BC8697ULL,
		0x000000000179632DULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E55E18CD9279C4BULL,
		0x9E4F2D5FC28454AAULL,
		0xE918FDE5AA95DC21ULL,
		0xDA9045DBDAA428E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x55E18CD9279C4B00ULL,
		0x4F2D5FC28454AA3EULL,
		0x18FDE5AA95DC219EULL,
		0x9045DBDAA428E4E9ULL,
		0x00000000000000DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x509B348390EB13BEULL,
		0xDE659D780CDB7017ULL,
		0x3A72ED0D9D8ADB2DULL,
		0xB3EF4ED96F220F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA136690721D6277CULL,
		0xBCCB3AF019B6E02EULL,
		0x74E5DA1B3B15B65BULL,
		0x67DE9DB2DE441E34ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00A88B638238A44BULL,
		0x9C01708C421A7138ULL,
		0x37719A5FC41BD992ULL,
		0x8ECF11136A95E752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A22D8E08E2912C0ULL,
		0x005C2310869C4E00ULL,
		0xDC6697F106F664A7ULL,
		0xB3C444DAA579D48DULL,
		0x0000000000000023ULL
	}};
	shift = 58;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21A7FA60D3983FA3ULL,
		0x0859ACF687490B19ULL,
		0x91033429930AB40CULL,
		0x8310454E64F4D46EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0FE8C00000000000ULL,
		0x42C64869FE9834E6ULL,
		0xAD0302166B3DA1D2ULL,
		0x351BA440CD0A64C2ULL,
		0x000020C41153993DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84EA6C5B2687D19AULL,
		0x75ADAE570F3C2EC1ULL,
		0x1F0440362B39769BULL,
		0x3E5CDACBD674D66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D19A00000000000ULL,
		0xC2EC184EA6C5B268ULL,
		0x9769B75ADAE570F3ULL,
		0x4D66A1F0440362B3ULL,
		0x000003E5CDACBD67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3301FA9D1170FECULL,
		0xFFCDB5DD58BD614FULL,
		0xD0076990C9899D2AULL,
		0xB58F34F9C50EAE93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC07EA7445C3FB00ULL,
		0xF36D77562F5853F4ULL,
		0x01DA643262674ABFULL,
		0x63CD3E7143ABA4F4ULL,
		0x000000000000002DULL
	}};
	shift = 58;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7264745E4E61150CULL,
		0x1DDDAC8DF85BA0EFULL,
		0xB52139E16AA7A666ULL,
		0x849E3B53D3B675BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3984543000000000ULL,
		0xE16E83BDC991D179ULL,
		0xAA9E99987776B237ULL,
		0x4ED9D6FAD484E785ULL,
		0x000000021278ED4FULL
	}};
	shift = 30;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF28E4401FCC1C84ULL,
		0xE80634E7F8B9677DULL,
		0x19B163F3081EF17AULL,
		0x1E1E8E71407C83FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8803F98390800000ULL,
		0x9CFF172CEFB9E51CULL,
		0x7E6103DE2F5D00C6ULL,
		0xCE280F907FC3362CULL,
		0x000000000003C3D1ULL
	}};
	shift = 43;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0458E624E3BD8646ULL,
		0xAB764AFD902AF806ULL,
		0x3A840D9923DC33ECULL,
		0xE7AF0666E7B32837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x116398938EF61918ULL,
		0xADD92BF640ABE018ULL,
		0xEA1036648F70CFB2ULL,
		0x9EBC199B9ECCA0DCULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2B7C1267921B9BFULL,
		0x7C8242358630E204ULL,
		0xA0CA4EFF270FB945ULL,
		0x4791BB4029C056DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BF0000000000000ULL,
		0x204B2B7C1267921BULL,
		0x9457C8242358630EULL,
		0x6DDA0CA4EFF270FBULL,
		0x0004791BB4029C05ULL
	}};
	shift = 12;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5B45698E4C6DD9BULL,
		0x100FEDB2C46548C4ULL,
		0x577330F21E7873D6ULL,
		0x213996EC66B1BA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6C00000000000000ULL,
		0x1396D15A63931B76ULL,
		0x58403FB6CB119523ULL,
		0xF55DCCC3C879E1CFULL,
		0x0084E65BB19AC6E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BAEC5235401137EULL,
		0x17C149B780D3BCD0ULL,
		0x807A87913B552763ULL,
		0xEE65ACC00AC416A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5401137E00000000ULL,
		0x80D3BCD01BAEC523ULL,
		0x3B55276317C149B7ULL,
		0x0AC416A9807A8791ULL,
		0x00000000EE65ACC0ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8EE7C3D71CE81C7FULL,
		0xEB600C44487CCE6BULL,
		0x32061B398354406CULL,
		0xD14FEBFA0BB16EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE740E3F800000000ULL,
		0x43E6735C773E1EB8ULL,
		0x1AA203675B006222ULL,
		0x5D8B75A19030D9CCULL,
		0x000000068A7F5FD0ULL
	}};
	shift = 29;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF5D852CCF09ED53ULL,
		0xFC45926D657D6A0DULL,
		0x7B876BAF56874A8DULL,
		0x02105FDBDB111D53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7B54C00000000000ULL,
		0x5A837FD7614B33C2ULL,
		0xD2A37F11649B595FULL,
		0x4754DEE1DAEBD5A1ULL,
		0x0000008417F6F6C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0DB25F2A037C004DULL,
		0x7FABCEA2DE7A6FADULL,
		0xC4A3DF6E3605258DULL,
		0x4AC999C399B7785EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0026800000000000ULL,
		0x37D686D92F9501BEULL,
		0x92C6BFD5E7516F3DULL,
		0xBC2F6251EFB71B02ULL,
		0x00002564CCE1CCDBULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63F7D9567DFF28FEULL,
		0xB109939C378A6477ULL,
		0x2A05AF83B6773B39ULL,
		0x7B44803C7D278CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFBECAB3EFF947F00ULL,
		0x84C9CE1BC5323BB1ULL,
		0x02D7C1DB3B9D9CD8ULL,
		0xA2401E3E93C67A95ULL,
		0x000000000000003DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3363EBE3481D1D41ULL,
		0xF3DCD1EC3E2983EFULL,
		0x0A4F6DB7FAB9132DULL,
		0xF89677C420F7F32FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE3481D1D4100000ULL,
		0x1EC3E2983EF3363EULL,
		0xDB7FAB9132DF3DCDULL,
		0x7C420F7F32F0A4F6ULL,
		0x00000000000F8967ULL
	}};
	shift = 44;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D14CE55198E742DULL,
		0x89856BB81EE4AEC9ULL,
		0x75C72F2CDA6B8055ULL,
		0x8583890D3754F5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x14CE55198E742D00ULL,
		0x856BB81EE4AEC95DULL,
		0xC72F2CDA6B805589ULL,
		0x83890D3754F5E075ULL,
		0x0000000000000085ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7920A81A1D0D11CULL,
		0x244AE48314F19158ULL,
		0x569D58ECBE75E36FULL,
		0x44BBFFB455AC31C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0x631E482A06874344ULL,
		0xBC912B920C53C645ULL,
		0x1D5A7563B2F9D78DULL,
		0x0112EFFED156B0C7ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18D0FC04B67A9776ULL,
		0x81AB5EE02A3EC806ULL,
		0xDAF3F4B33290CA70ULL,
		0xA1FFB8E6F9739ED0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB000000000000000ULL,
		0x30C687E025B3D4BBULL,
		0x840D5AF70151F640ULL,
		0x86D79FA599948653ULL,
		0x050FFDC737CB9CF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DA8EA1560AEBF93ULL,
		0x159339544818C2D9ULL,
		0xBEB6F8C129C37431ULL,
		0xF892FB807F5E988BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51D42AC15D7F2600ULL,
		0x2672A8903185B25BULL,
		0x6DF1825386E8622BULL,
		0x25F700FEBD31177DULL,
		0x00000000000001F1ULL
	}};
	shift = 55;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x659693CB0D778C27ULL,
		0xF2732CBA874DCB39ULL,
		0x147C47E5D16A4E10ULL,
		0x19A4DC6CBEA2EC3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD778C27000000000ULL,
		0x74DCB39659693CB0ULL,
		0x16A4E10F2732CBA8ULL,
		0xEA2EC3D147C47E5DULL,
		0x000000019A4DC6CBULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4C2D7FDB0E3E280ULL,
		0xBDA44F3C14D8E717ULL,
		0x6BD3BFA0BADAFC98ULL,
		0xF0F3D9B109005E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71F1400000000000ULL,
		0x6C738BEA616BFED8ULL,
		0x6D7E4C5ED2279E0AULL,
		0x802F04B5E9DFD05DULL,
		0x0000007879ECD884ULL
	}};
	shift = 25;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E844B2842AF716FULL,
		0x4D351F84CE57092AULL,
		0x910DD1D7357C84AAULL,
		0x2198C5D7DB2B2DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBC00000000000000ULL,
		0xA87A112CA10ABDC5ULL,
		0xA934D47E13395C24ULL,
		0x464437475CD5F212ULL,
		0x008663175F6CACB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78B56E620C3861C0ULL,
		0x4F43D28DC529A36CULL,
		0x4525753A37BFA1CFULL,
		0x967F599A22CF1421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C30E00000000000ULL,
		0x94D1B63C5AB73106ULL,
		0xDFD0E7A7A1E946E2ULL,
		0x678A10A292BA9D1BULL,
		0x0000004B3FACCD11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x119788FE34D3EF74ULL,
		0xB961BE1B79B20A07ULL,
		0x655A0686A5B9CC01ULL,
		0x5AB7D57B962CBAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xE232F11FC69A7DEEULL,
		0x372C37C36F364140ULL,
		0x2CAB40D0D4B73980ULL,
		0x0B56FAAF72C5975CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A72601E4A9B82D6ULL,
		0x9D914BE765973B36ULL,
		0x35EF49E9527B4312ULL,
		0x9D974BDF7C618AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E4A9B82D6000000ULL,
		0xE765973B360A7260ULL,
		0xE9527B43129D914BULL,
		0xDF7C618AA335EF49ULL,
		0x00000000009D974BULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F55074549970E08ULL,
		0xC1DA426E8D0A3D42ULL,
		0x773C130E12CDBAE7ULL,
		0xAE2BF116B9B8A8CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x265C382000000000ULL,
		0x3428F508FD541D15ULL,
		0x4B36EB9F076909BAULL,
		0xE6E2A339DCF04C38ULL,
		0x00000002B8AFC45AULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB196763C8F2C5B1EULL,
		0x40908C69D777A558ULL,
		0x07B11958494870D9ULL,
		0x50F74A5F88AAD890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E47962D8F00000ULL,
		0x634EBBBD2AC58CB3ULL,
		0xCAC24A4386CA0484ULL,
		0x52FC4556C4803D88ULL,
		0x00000000000287BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A8AE22AE2B85496ULL,
		0x6796784F6EB42F07ULL,
		0x296C8695D3F2BF37ULL,
		0xCD45B4E32324BD2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AE22AE2B8549600ULL,
		0x96784F6EB42F074AULL,
		0x6C8695D3F2BF3767ULL,
		0x45B4E32324BD2E29ULL,
		0x00000000000000CDULL
	}};
	shift = 56;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x315428EC7456B720ULL,
		0xD6D7C37FA82957F0ULL,
		0xF9F43B81EFB42079ULL,
		0x56194449F032184EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x818AA14763A2B5B9ULL,
		0xCEB6BE1BFD414ABFULL,
		0x77CFA1DC0F7DA103ULL,
		0x02B0CA224F8190C2ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB068BC41BD5BFC5FULL,
		0x0CD9C7C822D17B98ULL,
		0x1F470F3334143C18ULL,
		0x61591E50C9F29467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2F8000000000000ULL,
		0xDCC58345E20DEADFULL,
		0xE0C066CE3E41168BULL,
		0xA338FA387999A0A1ULL,
		0x00030AC8F2864F94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60609CAFF1B0E075ULL,
		0xFC09CF5835B15115ULL,
		0x97EF47B75825230DULL,
		0x056D00E546B2CB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xB0304E57F8D8703AULL,
		0xFE04E7AC1AD8A88AULL,
		0x4BF7A3DBAC129186ULL,
		0x02B68072A35965C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA20331E889529FE5ULL,
		0x062F5EAA02771365ULL,
		0xA47ACEABCFA4ED5AULL,
		0x65D0533DAAD85081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53FCA00000000000ULL,
		0xE26CB440663D112AULL,
		0x9DAB40C5EBD5404EULL,
		0x0A10348F59D579F4ULL,
		0x00000CBA0A67B55BULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x343AF6444559E39DULL,
		0x46AF93F8DE532B70ULL,
		0x464C3BB73A2C9B57ULL,
		0x48F2FB93129CB7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0EBD91115678E74ULL,
		0x1ABE4FE3794CADC0ULL,
		0x1930EEDCE8B26D5DULL,
		0x23CBEE4C4A72DEB5ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2A949B016463C59ULL,
		0xFB2C7D65BA25507EULL,
		0x0D1B1B476934FF29ULL,
		0x7D79DC1F525BAB85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA526C05918F16400ULL,
		0xB1F596E89541FACAULL,
		0x6C6D1DA4D3FCA7ECULL,
		0xE7707D496EAE1434ULL,
		0x00000000000001F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 246;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x233C97C10393FEE6ULL,
		0xE27B1F7F839E3A80ULL,
		0x3AE55D4CDFEA1A22ULL,
		0x1B82A02281BA9EF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0393FEE600000000ULL,
		0x839E3A80233C97C1ULL,
		0xDFEA1A22E27B1F7FULL,
		0x81BA9EF93AE55D4CULL,
		0x000000001B82A022ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD04709BC3E7F3377ULL,
		0x9C9DB1280731A367ULL,
		0xF8066A590DCCC143ULL,
		0x0CF5FBF3E34B729DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3E7F33770000000ULL,
		0x80731A367D04709BULL,
		0x90DCCC1439C9DB12ULL,
		0x3E34B729DF8066A5ULL,
		0x0000000000CF5FBFULL
	}};
	shift = 36;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A285F7827C33233ULL,
		0x5844B445C78E12AEULL,
		0x5282EFEFC6F1748AULL,
		0xB4F9CE10D472E3A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0xCD450BEF04F86646ULL,
		0x4B089688B8F1C255ULL,
		0x6A505DFDF8DE2E91ULL,
		0x169F39C21A8E5C74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DC67D620EE602E4ULL,
		0x9B503407F585DDD3ULL,
		0x1DD5D5CC114B16C5ULL,
		0xD21E77ED963506C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7719F5883B980B90ULL,
		0x6D40D01FD617774EULL,
		0x77575730452C5B16ULL,
		0x4879DFB658D41B04ULL,
		0x0000000000000003ULL
	}};
	shift = 62;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA790C3F7149FBECULL,
		0x8B86BA146D42FBECULL,
		0x0F4923025886F5ACULL,
		0x414AC1EDD2833D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC0000000000000ULL,
		0xBECFA790C3F7149FULL,
		0x5AC8B86BA146D42FULL,
		0xD110F4923025886FULL,
		0x000414AC1EDD2833ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE6E39A6B689575BULL,
		0x2CF3B6D4A0F09ABCULL,
		0x83DF41332F253855ULL,
		0xDAE95D7ADFE48B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75B0000000000000ULL,
		0xABCDE6E39A6B6895ULL,
		0x8552CF3B6D4A0F09ULL,
		0xB0883DF41332F253ULL,
		0x000DAE95D7ADFE48ULL
	}};
	shift = 12;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75EC363D6D5F2EF3ULL,
		0x03FABF533653BEA2ULL,
		0x741F9D459A7A925CULL,
		0x857309FBDDEDB8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF30000000000000ULL,
		0xEA275EC363D6D5F2ULL,
		0x25C03FABF533653BULL,
		0x8C2741F9D459A7A9ULL,
		0x000857309FBDDEDBULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE3794E76ADC1F3AULL,
		0x9563552099082FB8ULL,
		0xFBA0350A3624E1EBULL,
		0x771C4BC1E3506DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3794E76ADC1F3A00ULL,
		0x63552099082FB8AEULL,
		0xA0350A3624E1EB95ULL,
		0x1C4BC1E3506DC0FBULL,
		0x0000000000000077ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A44689893D1C781ULL,
		0x1B9FDF1F711C349EULL,
		0xC34A9A193C8FF715ULL,
		0x8D2FFC2CAE5A7A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13127A38F0200000ULL,
		0xE3EE238693CD488DULL,
		0x432791FEE2A373FBULL,
		0x8595CB4F4FB86953ULL,
		0x000000000011A5FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x334CCA57007B2DF7ULL,
		0x6B05035427EE5512ULL,
		0xD24171BFA7F5CEA1ULL,
		0x1A76B5954CC732DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7DC000000000000ULL,
		0x5448CD33295C01ECULL,
		0x3A85AC140D509FB9ULL,
		0xCB7F4905C6FE9FD7ULL,
		0x000069DAD655331CULL
	}};
	shift = 14;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50B2B016C42E939FULL,
		0xE854C73197C8DB73ULL,
		0xC06B75471BBAF494ULL,
		0xF686FCB30AE96CA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBA4E7C0000000000ULL,
		0x236DCD42CAC05B10ULL,
		0xEBD253A1531CC65FULL,
		0xA5B28F01ADD51C6EULL,
		0x000003DA1BF2CC2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB603E32ED80AABEULL,
		0x927CBEA93705D80AULL,
		0x6E6BAAFB67B51E55ULL,
		0xF12800537E7BC998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B01F1976C0555F0ULL,
		0x93E5F549B82EC056ULL,
		0x735D57DB3DA8F2ACULL,
		0x8940029BF3DE4CC3ULL,
		0x0000000000000007ULL
	}};
	shift = 61;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB86FEC2D3FAF8AB9ULL,
		0x15BB5DB2B093715FULL,
		0xE96651F2003D1430ULL,
		0x8068B03FEACCC5C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xF70DFD85A7F5F157ULL,
		0x02B76BB656126E2BULL,
		0x3D2CCA3E4007A286ULL,
		0x100D1607FD5998B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8DD35ACB0F29277ULL,
		0xC31181378EF8AD75ULL,
		0x3E323C6F8A6F9A16ULL,
		0x57B892652A7B9B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9AD65879493B800ULL,
		0x8C09BC77C56BAEC6ULL,
		0x91E37C537CD0B618ULL,
		0xC4932953DCD8A1F1ULL,
		0x00000000000002BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91EED148D6A33F68ULL,
		0x2C113D025CDB0906ULL,
		0x04525C5BE9A8A039ULL,
		0x7975AEE4F52561C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23DDA291AD467ED0ULL,
		0x58227A04B9B6120DULL,
		0x08A4B8B7D3514072ULL,
		0xF2EB5DC9EA4AC388ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9005121C06BD098ULL,
		0x06031F275094D938ULL,
		0xEDC9C8C68DC1F4E5ULL,
		0x14AAD065BB16099EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA130000000000000ULL,
		0xB2715200A24380D7ULL,
		0xE9CA0C063E4EA129ULL,
		0x133DDB93918D1B83ULL,
		0x00002955A0CB762CULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6375DDAE4A098728ULL,
		0xB1EF4BF2665DA93DULL,
		0xD2DB6AB214060B24ULL,
		0xF7A01586CF41067EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xEB1BAEED72504C39ULL,
		0x258F7A5F9332ED49ULL,
		0xF696DB5590A03059ULL,
		0x07BD00AC367A0833ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2E26A7C3C78295EULL,
		0x105A481F41679731ULL,
		0x0E999ED92D3DB2A7ULL,
		0x3A86CF7076460406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x78295E0000000000ULL,
		0x679731B2E26A7C3CULL,
		0x3DB2A7105A481F41ULL,
		0x4604060E999ED92DULL,
		0x0000003A86CF7076ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8809FE105536A45ULL,
		0x18A15B72011FA5D8ULL,
		0x06A0BAC628DF10ABULL,
		0xBCA579797579932DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4154DA9140000000ULL,
		0x8047E9763A2027F8ULL,
		0x8A37C42AC62856DCULL,
		0x5D5E64CB41A82EB1ULL,
		0x000000002F295E5EULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF6E559095CCB729ULL,
		0x85A79D8579809EFDULL,
		0x57C4FF9C3BD1DB5AULL,
		0x1764451991751B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DCA400000000000ULL,
		0x27BF7FDB95642573ULL,
		0x76D6A169E7615E60ULL,
		0x46CDD5F13FE70EF4ULL,
		0x000005D91146645DULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x49198AB1B72D653EULL,
		0xAF1A81918BFC9ED3ULL,
		0xC956A7AB60967CE4ULL,
		0x421D1CFE642B2E7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCB594F800000000ULL,
		0x2FF27B4D24662AC6ULL,
		0x8259F392BC6A0646ULL,
		0x90ACB9EB255A9EADULL,
		0x00000001087473F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98F8F9F484A0CEA5ULL,
		0x0B7908E420FABCE7ULL,
		0x2324478618F09061ULL,
		0x48339E1EBEFBD573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3E909419D4A0000ULL,
		0x11C841F579CF31F1ULL,
		0x8F0C31E120C216F2ULL,
		0x3C3D7DF7AAE64648ULL,
		0x0000000000009067ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5034393AAEDB85B9ULL,
		0xA617D8E25E93ACE2ULL,
		0xD2102BBB805E7EF0ULL,
		0x45020716B384C37DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E4000000000000ULL,
		0xB38940D0E4EABB6EULL,
		0xFBC2985F63897A4EULL,
		0x0DF74840AEEE0179ULL,
		0x000114081C5ACE13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 206;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AC9B81CFED64236ULL,
		0x8E88873D7841A118ULL,
		0x81EFE0A4D68773F4ULL,
		0xC8A09995F1D7D964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC0E7F6B211B00000ULL,
		0x39EBC20D08C1D64DULL,
		0x0526B43B9FA47444ULL,
		0xCCAF8EBECB240F7FULL,
		0x0000000000064504ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DF8563ED307A5C1ULL,
		0xD89C3028285FBA97ULL,
		0xEE141941025369E5ULL,
		0x30C6490B404E9F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE970400000000000ULL,
		0xEEA5CF7E158FB4C1ULL,
		0xDA7976270C0A0A17ULL,
		0xA7C13B8506504094ULL,
		0x00000C319242D013ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCF20B259BD1432CULL,
		0x40A6ED87365EF9D3ULL,
		0x38EBEFD352B8C9E6ULL,
		0x9756D66D463F324EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC966F450CB000000ULL,
		0x61CD97BE74EF3C82ULL,
		0xF4D4AE32799029BBULL,
		0x9B518FCC938E3AFBULL,
		0x000000000025D5B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9AEED2CAFB4A02CULL,
		0x4C137FAFB4ED32B2ULL,
		0x4EF4EE790B2CA160ULL,
		0xDEEFD706DFF9BC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA50160000000000ULL,
		0x7699595CD7769657ULL,
		0x9650B02609BFD7DAULL,
		0xFCDE4C277A773C85ULL,
		0x0000006F77EB836FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB901F6BB9CFF1860ULL,
		0x0FF13E41C22DBF7CULL,
		0xCA2600BAFE56F43CULL,
		0x181FB7E2E627FFEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5C80FB5DCE7F8C30ULL,
		0x07F89F20E116DFBEULL,
		0xE513005D7F2B7A1EULL,
		0x0C0FDBF17313FFF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A9488D8BB289C62ULL,
		0x475F6EA797397533ULL,
		0x265D0B9B4B1A2DBDULL,
		0x47E8B2370B1619E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ECA271880000000ULL,
		0xE5CE5D4CE2A52236ULL,
		0xD2C68B6F51D7DBA9ULL,
		0xC2C58678899742E6ULL,
		0x0000000011FA2C8DULL
	}};
	shift = 34;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6150F73E86E76005ULL,
		0xFB510C4670A888E3ULL,
		0xD85AC3893E850AB5ULL,
		0xCCEE66F2CEE6D273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A1EE7D0DCEC00A0ULL,
		0x6A2188CE15111C6CULL,
		0x0B587127D0A156BFULL,
		0x9DCCDE59DCDA4E7BULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD5C10B58771D598ULL,
		0xC33627D516352569ULL,
		0xD5BE25144786F3F1ULL,
		0x7F577D1B1BE91FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8EACC0000000000ULL,
		0x1A92B4FEAE085AC3ULL,
		0xC379F8E19B13EA8BULL,
		0xF48FE3EADF128A23ULL,
		0x0000003FABBE8D8DULL
	}};
	shift = 25;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68015BCE79E904B3ULL,
		0x4EA76AE3D241545EULL,
		0x34DA965E5FA6DD40ULL,
		0xC37793270A4E5D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39E7A412CC000000ULL,
		0x8F49055179A0056FULL,
		0x797E9B75013A9DABULL,
		0x9C29397548D36A59ULL,
		0x00000000030DDE4CULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEFE013F23AF5895BULL,
		0x969C72EFD21C3A29ULL,
		0x09FBB40E7828855BULL,
		0x0A534ECC5C76E8FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x95B0000000000000ULL,
		0xA29EFE013F23AF58ULL,
		0x55B969C72EFD21C3ULL,
		0x8FC09FBB40E78288ULL,
		0x0000A534ECC5C76EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56FAE39ABEAC9396ULL,
		0x61CA27E91F2B097DULL,
		0xC301DA21B44D0D6AULL,
		0xC335AB577E4402F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x71CD5F5649CB0000ULL,
		0x13F48F9584BEAB7DULL,
		0xED10DA2686B530E5ULL,
		0xD5ABBF22017A6180ULL,
		0x000000000000619AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AAB97FA72145444ULL,
		0xBA8D1094F0B27021ULL,
		0x8FFB7C0B0D3C8F1EULL,
		0x97872DFCDDAF704AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAE5FE9C85151100ULL,
		0xA344253C2C9C0862ULL,
		0xFEDF02C34F23C7AEULL,
		0xE1CB7F376BDC12A3ULL,
		0x0000000000000025ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA28C1148B62B844ULL,
		0x2B6304D8A253FC8AULL,
		0x623446BF5D6A4679ULL,
		0xFD5FB682DAC85855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C57088000000000ULL,
		0x4A7F915745182291ULL,
		0xAD48CF256C609B14ULL,
		0x590B0AAC4688D7EBULL,
		0x0000001FABF6D05BULL
	}};
	shift = 27;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F965D91B92E62F8ULL,
		0xE8797A89827C1AB0ULL,
		0x497E9B2205816ABFULL,
		0x60B24B9A6C7713BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF965D91B92E62F80ULL,
		0x8797A89827C1AB02ULL,
		0x97E9B2205816ABFEULL,
		0x0B24B9A6C7713BC4ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC09EAF97719069C2ULL,
		0xB0FCF966A1C9A6B8ULL,
		0x42F1B098D100138CULL,
		0x2D76D2401B9A7417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57CBB8C834E10000ULL,
		0x7CB350E4D35C604FULL,
		0xD84C688009C6587EULL,
		0x69200DCD3A0BA178ULL,
		0x00000000000016BBULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44D2DF1F7B8D38A8ULL,
		0xCA24809F1B2921F5ULL,
		0x9266C6413D601866ULL,
		0x283B95B7CA0B02E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0xF544D2DF1F7B8D38ULL,
		0x66CA24809F1B2921ULL,
		0xE69266C6413D6018ULL,
		0x00283B95B7CA0B02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86CD37A5FCAD9CFBULL,
		0x1E9A44207362D1BFULL,
		0xAC4E12CFBC20F20FULL,
		0x8A5B9B209D37FCF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF4BF95B39F600000ULL,
		0x840E6C5A37F0D9A6ULL,
		0x59F7841E41E3D348ULL,
		0x6413A6FF9E7589C2ULL,
		0x0000000000114B73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x966236DEAAE23EF9ULL,
		0xC984B6041FF54C78ULL,
		0x2C929DECE2713E0EULL,
		0x60CEE65B361C093FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF900000000000000ULL,
		0x78966236DEAAE23EULL,
		0x0EC984B6041FF54CULL,
		0x3F2C929DECE2713EULL,
		0x0060CEE65B361C09ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BF336DD2C7B1A1FULL,
		0xC7D8956080CFE462ULL,
		0x34737189656DDD37ULL,
		0xB3A7C029BBA0485CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7C00000000000000ULL,
		0x89AFCCDB74B1EC68ULL,
		0xDF1F625582033F91ULL,
		0x70D1CDC62595B774ULL,
		0x02CE9F00A6EE8121ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B9E13BEF973B998ULL,
		0x4BA0E31440F24CBCULL,
		0x3BE0A6FD617F2951ULL,
		0x84B5B82DF70CBF33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BEF973B99800000ULL,
		0x31440F24CBC0B9E1ULL,
		0x6FD617F29514BA0EULL,
		0x82DF70CBF333BE0AULL,
		0x0000000000084B5BULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9076378AF1402EC5ULL,
		0x2BBA61704541E7D1ULL,
		0x8AF972D4D88A049EULL,
		0x9AAAD4053FAB2164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1BC578A01762800ULL,
		0xD30B822A0F3E8C83ULL,
		0xCB96A6C45024F15DULL,
		0x56A029FD590B2457ULL,
		0x00000000000004D5ULL
	}};
	shift = 53;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4310A5CE59517839ULL,
		0xFDA33413AD1473E0ULL,
		0xD3D90B15E541B92FULL,
		0x9A564A2A9E27A773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E40000000000000ULL,
		0xF810C4297396545EULL,
		0x4BFF68CD04EB451CULL,
		0xDCF4F642C579506EULL,
		0x002695928AA789E9ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1F88DCBD368F163ULL,
		0x8391D8BD9198EF67ULL,
		0xF56D49B8637CE669ULL,
		0x91801FEA78721D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC46E5E9B478B180ULL,
		0xC8EC5EC8CC77B3D0ULL,
		0xB6A4DC31BE7334C1ULL,
		0xC00FF53C390E927AULL,
		0x0000000000000048ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF61FC05069A8CFE1ULL,
		0x3B30EA961583449CULL,
		0x1201700C70F33796ULL,
		0xDAB7F5F817D803B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB0FE02834D467F08ULL,
		0xD98754B0AC1A24E7ULL,
		0x900B80638799BCB1ULL,
		0xD5BFAFC0BEC01DC0ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05162522BEBE52E6ULL,
		0xEB6BB57160A55059ULL,
		0x3D404A5EA261D715ULL,
		0x4B499CAFF27D45DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x458948AFAF94B980ULL,
		0xDAED5C5829541641ULL,
		0x501297A89875C57AULL,
		0xD2672BFC9F5176CFULL,
		0x0000000000000012ULL
	}};
	shift = 58;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D41335AD3DDAB9DULL,
		0x09342D8B5821991EULL,
		0xD3E883BDBF9595F4ULL,
		0xD7A22A8494B24707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB573A0000000000ULL,
		0x43323C1A8266B5A7ULL,
		0x2B2BE812685B16B0ULL,
		0x648E0FA7D1077B7FULL,
		0x000001AF44550929ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C7D282ADE0A4F3DULL,
		0x310D41567C02E0CCULL,
		0x42B076A1EFC7BF5FULL,
		0x770565F9D35080FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC149E7A000000000ULL,
		0x805C198F8FA5055BULL,
		0xF8F7EBE621A82ACFULL,
		0x6A101FA8560ED43DULL,
		0x0000000EE0ACBF3AULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C30489869CAA824ULL,
		0x6AF9F3FF54BD12B4ULL,
		0x6602F516221B9B79ULL,
		0x09D290F569101E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C12261A72AA090ULL,
		0xABE7CFFD52F44AD2ULL,
		0x980BD458886E6DE5ULL,
		0x274A43D5A4407A61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FB4C5D9B134C491ULL,
		0x4868C17716C70F57ULL,
		0x9A73ADE62C352F2EULL,
		0x174BC24F2E4B6231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED31766C4D31244ULL,
		0x21A305DC5B1C3D5DULL,
		0x69CEB798B0D4BCB9ULL,
		0x5D2F093CB92D88C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDEDAFB0750A5FABULL,
		0x6871C8AD357E82DFULL,
		0x667FF41458302862ULL,
		0x56A4CAFF646687E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6D7D83A852FD580ULL,
		0x38E4569ABF416FF6ULL,
		0x3FFA0A2C18143134ULL,
		0x52657FB23343F233ULL,
		0x000000000000002BULL
	}};
	shift = 57;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C4F7BB17D8C1349ULL,
		0xB7E5BFED8120BCB7ULL,
		0x7AA4432CBCAC2C8EULL,
		0xCBE4AF7FB83A31A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6304D2400000000ULL,
		0x0482F2DDB13DEEC5ULL,
		0xF2B0B23ADF96FFB6ULL,
		0xE0E8C699EA910CB2ULL,
		0x000000032F92BDFEULL
	}};
	shift = 30;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2EE7E3C9FC41F5A5ULL,
		0x6323C5B548387E0AULL,
		0xA297974F216B8386ULL,
		0xEEDB0699D9413CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27F107D694000000ULL,
		0xD520E1F828BB9F8FULL,
		0x3C85AE0E198C8F16ULL,
		0x676504F2AA8A5E5DULL,
		0x0000000003BB6C1AULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBBDE1AFF324758EAULL,
		0xA6115870DD367DC1ULL,
		0xB4D7FAFE39DFD438ULL,
		0x94BD5247DE048C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EA0000000000000ULL,
		0xDC1BBDE1AFF32475ULL,
		0x438A6115870DD367ULL,
		0xC2DB4D7FAFE39DFDULL,
		0x00094BD5247DE048ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBFD8C7B6A08A77A5ULL,
		0xD728E73A3C39EB4CULL,
		0x1BBA0CFC041868F6ULL,
		0x978A4F4DB0F24122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE940000000000000ULL,
		0xD32FF631EDA8229DULL,
		0x3DB5CA39CE8F0E7AULL,
		0x4886EE833F01061AULL,
		0x0025E293D36C3C90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x13810CDF7631E610ULL,
		0x1550FD8CA23ED2B3ULL,
		0x95EB672FB5C852D2ULL,
		0x3AFE735D4588112CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E6100000000000ULL,
		0x3ED2B313810CDF76ULL,
		0xC852D21550FD8CA2ULL,
		0x88112C95EB672FB5ULL,
		0x0000003AFE735D45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D45E0346A933EE8ULL,
		0xCD3B36B37E0B9C3AULL,
		0x51BDB14644559CACULL,
		0x8A6E69A91E67B8ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF740000000000000ULL,
		0xE1D16A2F01A35499ULL,
		0xE56669D9B59BF05CULL,
		0xC7628DED8A3222ACULL,
		0x000453734D48F33DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFA1DA8ED9E2F909ULL,
		0x932C94FF480FD7D6ULL,
		0xA3D3ADA740EB4FA7ULL,
		0x75BEAF4D0B0D84E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE876A3B678BE424ULL,
		0x4CB253FD203F5F5BULL,
		0x8F4EB69D03AD3E9EULL,
		0xD6FABD342C3613A6ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D0E2E32D6F97BA3ULL,
		0x700D66BC2A75B587ULL,
		0x438EAA849D9FD665ULL,
		0x1A78F5A2DEA308E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE8C00000000000ULL,
		0x6D61CF438B8CB5BEULL,
		0xF5995C0359AF0A9DULL,
		0xC23990E3AAA12767ULL,
		0x0000069E3D68B7A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1960E76B18220DB3ULL,
		0x2D6BA620B79CB8CDULL,
		0xA72B88442B98BEEDULL,
		0x9251A36290E9E9EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x960E76B18220DB30ULL,
		0xD6BA620B79CB8CD1ULL,
		0x72B88442B98BEED2ULL,
		0x251A36290E9E9EAAULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x635215FBF6423BD9ULL,
		0xFF8F31F0F23DF9C8ULL,
		0x8F67B85A890BF0CCULL,
		0x021A8EA1B5EC8895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAFDFB211DEC80000ULL,
		0x8F8791EFCE431A90ULL,
		0xC2D4485F8667FC79ULL,
		0x750DAF6444AC7B3DULL,
		0x00000000000010D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54066284AF91047BULL,
		0x70076EC2A54600AFULL,
		0xDB7730D351B50BE5ULL,
		0x6E02760F08EC2D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2208F6000000000ULL,
		0xA8C015EA80CC5095ULL,
		0x36A17CAE00EDD854ULL,
		0x1D85A2DB6EE61A6AULL,
		0x0000000DC04EC1E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E47FA154478A0AAULL,
		0xCE9B7401C8666B76ULL,
		0x98F8EA41DA2379EAULL,
		0x020C7C84FE000B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A8000000000000ULL,
		0xADD9791FE85511E2ULL,
		0xE7AB3A6DD0072199ULL,
		0x2E4A63E3A907688DULL,
		0x00000831F213F800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 206;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC9973C6FC8F0F5EULL,
		0x7A1D95E74B526651ULL,
		0xC2D5F431BFEE7E1BULL,
		0xBF6DFCEA1729270AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE37E4787AF000000ULL,
		0xF3A5A93328EE4CB9ULL,
		0x18DFF73F0DBD0ECAULL,
		0x750B949385616AFAULL,
		0x00000000005FB6FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9F638B3B6DB062C0ULL,
		0x548766F1837234EFULL,
		0xCF304A7EBB715800ULL,
		0x17A89B9912D8689BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C59DB6D8316000ULL,
		0x43B378C1B91A77CFULL,
		0x98253F5DB8AC002AULL,
		0xD44DCC896C344DE7ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CB4053597710A57ULL,
		0xB7740C38C12F7A56ULL,
		0x7479B4E671D764B3ULL,
		0xF3D3FE362597F764ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB8852B80000000ULL,
		0x6097BD2B3E5A029AULL,
		0x38EBB259DBBA061CULL,
		0x12CBFBB23A3CDA73ULL,
		0x0000000079E9FF1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C66718877C410B1ULL,
		0x0A4454E1C9B79A77ULL,
		0x501761115E8DB8FBULL,
		0xCACB577858685687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EF8821620000000ULL,
		0x3936F34EE78CCE31ULL,
		0x2BD1B71F61488A9CULL,
		0x0B0D0AD0EA02EC22ULL,
		0x0000000019596AEFULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9EE5F8D51AA819DULL,
		0x0F5D8250B19B8D86ULL,
		0x70B59C8B9A5748E6ULL,
		0xD1EFFAA23AA9F595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDCBF1AA355033A00ULL,
		0xBB04A163371B0DB3ULL,
		0x6B391734AE91CC1EULL,
		0xDFF5447553EB2AE1ULL,
		0x00000000000001A3ULL
	}};
	shift = 55;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8F225367BCCE685ULL,
		0xCD18F1BC4D800550ULL,
		0x39D99B64675A0659ULL,
		0xFD628D4C68F4C208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A14000000000000ULL,
		0x1543A3C894D9EF33ULL,
		0x19673463C6F13600ULL,
		0x0820E7666D919D68ULL,
		0x0003F58A3531A3D3ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CCEB6FC8FFC62E0ULL,
		0x4D4776D6F50D4E79ULL,
		0x9306214B0419FC9CULL,
		0x804DDCD4D34742CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E0000000000000ULL,
		0x4E792CCEB6FC8FFCULL,
		0xFC9C4D4776D6F50DULL,
		0x42CC9306214B0419ULL,
		0x0000804DDCD4D347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E28C3068821ACCDULL,
		0xC8AB67938116E802ULL,
		0xA661D57CCB8B4833ULL,
		0x74CA0E0E6DE725C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x043599A000000000ULL,
		0x22DD0053C51860D1ULL,
		0x71690679156CF270ULL,
		0xBCE4B874CC3AAF99ULL,
		0x0000000E9941C1CDULL
	}};
	shift = 27;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA65A759966F0B9DBULL,
		0xD10E9011E658AA12ULL,
		0x90B3ACEF34EEC0C1ULL,
		0xD5E60D2899B5E909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB32CDE173B600000ULL,
		0x023CCB154254CB4EULL,
		0x9DE69DD8183A21D2ULL,
		0xA51336BD21321675ULL,
		0x00000000001ABCC1ULL
	}};
	shift = 43;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF23A53D334F3057ULL,
		0x59D9FA59EC879072ULL,
		0xF56899F8B5465CE3ULL,
		0x5970E6089D8E5090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x5BE474A7A669E60AULL,
		0x6B3B3F4B3D90F20EULL,
		0x1EAD133F16A8CB9CULL,
		0x0B2E1CC113B1CA12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE54D723B70EDCD8FULL,
		0x528D3F3EEA69DA20ULL,
		0x270970FB77B7D4E2ULL,
		0x13ED1DB061CD8EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB876E6C780000000ULL,
		0x7534ED1072A6B91DULL,
		0xBBDBEA7129469F9FULL,
		0x30E6C76D1384B87DULL,
		0x0000000009F68ED8ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71FC79BF308D0ED3ULL,
		0x0D2460FF0F05826CULL,
		0x02B41AD9457C76C9ULL,
		0x13556B1F4F6DBE5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0ED3000000000000ULL,
		0x826C71FC79BF308DULL,
		0x76C90D2460FF0F05ULL,
		0xBE5B02B41AD9457CULL,
		0x000013556B1F4F6DULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3F8DBFFDC898FFCULL,
		0xEAF475B037F18CBEULL,
		0xC5E0E58D571D56D3ULL,
		0xE507C5C35F6F96FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBFFDC898FFC0000ULL,
		0x75B037F18CBEA3F8ULL,
		0xE58D571D56D3EAF4ULL,
		0xC5C35F6F96FAC5E0ULL,
		0x000000000000E507ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A6C82A4F6FA2810ULL,
		0x26618E6E258CE5C4ULL,
		0xE55274B154849419ULL,
		0xCC09044D1F5CA16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A6C82A4F6FA2810ULL,
		0x26618E6E258CE5C4ULL,
		0xE55274B154849419ULL,
		0xCC09044D1F5CA16AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D5FC489822D793DULL,
		0x5A52DB1C11E6C0DFULL,
		0x4E970FAFF47FF4E6ULL,
		0x9510DF3CF186C2DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF27A00000000000ULL,
		0xD81BE1ABF8913045ULL,
		0xFE9CCB4A5B63823CULL,
		0xD85B89D2E1F5FE8FULL,
		0x000012A21BE79E30ULL
	}};
	shift = 19;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8CF577A9B724BEDULL,
		0xD07E221CE3529448ULL,
		0xD61F9B0BEB3E5065ULL,
		0xF8E96D2EC7585257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6800000000000000ULL,
		0x45467ABBD4DB925FULL,
		0x2E83F110E71A94A2ULL,
		0xBEB0FCD85F59F283ULL,
		0x07C74B69763AC292ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF914183B97154F0AULL,
		0x339680E28C390544ULL,
		0x22091AA115C4471EULL,
		0x36DCAEB5552DE90AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC280000000000000ULL,
		0x513E45060EE5C553ULL,
		0xC78CE5A038A30E41ULL,
		0x42888246A8457111ULL,
		0x000DB72BAD554B7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6DA5A945311871FBULL,
		0x5BA61EB7599C57F5ULL,
		0x4225BD5B39C731D0ULL,
		0xC31B14B933AFE7B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C461C7EC0000000ULL,
		0xD66715FD5B696A51ULL,
		0xCE71CC7416E987ADULL,
		0x4CEBF9ED90896F56ULL,
		0x0000000030C6C52EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DA3123CC718D53AULL,
		0x1780074A423A1865ULL,
		0x692ECC6A0095B681ULL,
		0xBF5EDA635DA5FA08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x718D53A000000000ULL,
		0x23A18658DA3123CCULL,
		0x095B6811780074A4ULL,
		0xDA5FA08692ECC6A0ULL,
		0x0000000BF5EDA635ULL
	}};
	shift = 28;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6DA7844B1906E3E8ULL,
		0x0A97A34FD47242F9ULL,
		0x792038317AA4DFBDULL,
		0xED0162112C82A1EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC8371F4000000000ULL,
		0xA39217CB6D3C2258ULL,
		0xD526FDE854BD1A7EULL,
		0x64150F6BC901C18BULL,
		0x00000007680B1089ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x801831A563D94FCFULL,
		0xDCC7608C50D31B4EULL,
		0x4349F19F49241D30ULL,
		0xFA15D151C786D5C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1A563D94FCF00000ULL,
		0x08C50D31B4E80183ULL,
		0x19F49241D30DCC76ULL,
		0x151C786D5C84349FULL,
		0x00000000000FA15DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B0A5D4FD55CBBD9ULL,
		0x7FE9348BF7BDA820ULL,
		0xB158FD0D23EBC7EAULL,
		0xDC6761C96A3F5C39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA7EAAE5DEC8000ULL,
		0x9A45FBDED4101D85ULL,
		0x7E8691F5E3F53FF4ULL,
		0xB0E4B51FAE1CD8ACULL,
		0x0000000000006E33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BCE5FDDB457AC5EULL,
		0x73983FA37CF96D2AULL,
		0x7056458EEDF5AC97ULL,
		0xADB67A51A830DBD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8AF58BC000000000ULL,
		0x9F2DA55379CBFBB6ULL,
		0xBEB592EE7307F46FULL,
		0x061B7A2E0AC8B1DDULL,
		0x00000015B6CF4A35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B741773AEA1BAA1ULL,
		0x6D01A3ADAC7DC65BULL,
		0x025EA390ED48ADF3ULL,
		0xC8070E658DFC13AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE75D43754200000ULL,
		0x75B58FB8CB6B6E82ULL,
		0x721DA915BE6DA034ULL,
		0xCCB1BF8275E04BD4ULL,
		0x00000000001900E1ULL
	}};
	shift = 43;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x191BE9E1FBE9857DULL,
		0x340D3A8F7AAEE2BEULL,
		0x1F9FDDB35577BFD0ULL,
		0xDAB8680A0E59FAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57D0000000000000ULL,
		0x2BE191BE9E1FBE98ULL,
		0xFD0340D3A8F7AAEEULL,
		0xAE21F9FDDB35577BULL,
		0x000DAB8680A0E59FULL
	}};
	shift = 12;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x058FE74B590ABC26ULL,
		0x0FD7AAA82A677798ULL,
		0xCB162FE17C1309EBULL,
		0xDBD6FAD0CD758695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC855E1300000000ULL,
		0x1533BBCC02C7F3A5ULL,
		0xBE0984F587EBD554ULL,
		0x66BAC34AE58B17F0ULL,
		0x000000006DEB7D68ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6636542635EA0F5ULL,
		0x78BA2DFCC7788B1CULL,
		0xF31A7ACB444F0D3AULL,
		0x23068802F738B9FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x6331B2A131AF507AULL,
		0x3C5D16FE63BC458EULL,
		0xF98D3D65A227869DULL,
		0x118344017B9C5CFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E4E60A21B8744AFULL,
		0xF16F8BA9CC9F6A9BULL,
		0xFEAD9E2E7FC6E1CAULL,
		0x865FCC31C7B6693FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC144370E895E0000ULL,
		0x1753993ED5361C9CULL,
		0x3C5CFF8DC395E2DFULL,
		0x98638F6CD27FFD5BULL,
		0x0000000000010CBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x508F280BE8027F31ULL,
		0x9F99FA3C1B1B4C90ULL,
		0x2E93718EE4DED119ULL,
		0x3B2D36519228FFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD004FE6200000000ULL,
		0x36369920A11E5017ULL,
		0xC9BDA2333F33F478ULL,
		0x2451FFD45D26E31DULL,
		0x00000000765A6CA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C0355FFF6FC5788ULL,
		0x70DE67596AA4C66BULL,
		0xB54BE85EBCDD2E42ULL,
		0x6E6B2F1687290D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55FFF6FC57880000ULL,
		0x67596AA4C66B2C03ULL,
		0xE85EBCDD2E4270DEULL,
		0x2F1687290D01B54BULL,
		0x0000000000006E6BULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C0F759162291A91ULL,
		0x7901E514F499EE1FULL,
		0x8B05DD9E00BDCC79ULL,
		0x88BE92953CDC6EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xCF03DD64588A46A4ULL,
		0x5E4079453D267B87ULL,
		0x62C17767802F731EULL,
		0x222FA4A54F371BACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56855279B8C00027ULL,
		0x3CD2136938E8D3D7ULL,
		0xCCC86DC6045DAD02ULL,
		0xCB2A64D23FE60C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x855279B8C0002700ULL,
		0xD2136938E8D3D756ULL,
		0xC86DC6045DAD023CULL,
		0x2A64D23FE60C23CCULL,
		0x00000000000000CBULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C0E3C62D1246553ULL,
		0xA1EE4673E5E458AAULL,
		0x5F09D2EE108DC1B5ULL,
		0x75CBC2CC68E1E36DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C78C5A248CAA600ULL,
		0xDC8CE7CBC8B154D8ULL,
		0x13A5DC211B836B43ULL,
		0x978598D1C3C6DABEULL,
		0x00000000000000EBULL
	}};
	shift = 55;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66C559AFB98C2715ULL,
		0x0A971DCF9A82321AULL,
		0x934D0C421EDB1A11ULL,
		0x3BEDAD347DD7168EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E2A000000000000ULL,
		0x6434CD8AB35F7318ULL,
		0x3422152E3B9F3504ULL,
		0x2D1D269A18843DB6ULL,
		0x000077DB5A68FBAEULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C41CA2ADCF04E75ULL,
		0x1FD4A5809BCAC528ULL,
		0xF32E45B16D0D5A59ULL,
		0xCEAB9271A19285BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC41CA2ADCF04E750ULL,
		0xFD4A5809BCAC5282ULL,
		0x32E45B16D0D5A591ULL,
		0xEAB9271A19285BFFULL,
		0x000000000000000CULL
	}};
	shift = 60;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F88286406D55395ULL,
		0x53B0BDE98C2980F5ULL,
		0xB2F0DB52C38FF8D1ULL,
		0x4B437AD274E0C8A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA9CA8000000000ULL,
		0x14C07A97C4143203ULL,
		0xC7FC68A9D85EF4C6ULL,
		0x706454D9786DA961ULL,
		0x00000025A1BD693AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD451A9125301E798ULL,
		0xB84965104CDDCF03ULL,
		0x7627B477F669E575ULL,
		0xDFF0C1A7030E8B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3CF3000000000000ULL,
		0xB9E07A8A35224A60ULL,
		0x3CAEB7092CA2099BULL,
		0xD1656EC4F68EFECDULL,
		0x00001BFE1834E061ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E2F3BAF42385A3AULL,
		0xC7335FFC8B3E417CULL,
		0x022B0522F9D18C53ULL,
		0x690A72C6A2CDB5FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D00000000000000ULL,
		0xBE37179DD7A11C2DULL,
		0x29E399AFFE459F20ULL,
		0xFF811582917CE8C6ULL,
		0x00348539635166DAULL
	}};
	shift = 9;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41F754213E21182EULL,
		0xE2FD847DC0824D3AULL,
		0x07484C2C3DAED62CULL,
		0x499C99877B6FF6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE21182E000000000ULL,
		0x0824D3A41F754213ULL,
		0xDAED62CE2FD847DCULL,
		0xB6FF6C507484C2C3ULL,
		0x0000000499C99877ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5E5E1AB6A8733F4ULL,
		0xC1ECC0F6AB141787ULL,
		0x9C690052F3C58777ULL,
		0x4A14FF5F8E9E5012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99FA000000000000ULL,
		0x0BC3E2F2F0D5B543ULL,
		0xC3BBE0F6607B558AULL,
		0x28094E34802979E2ULL,
		0x0000250A7FAFC74FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBFF1E8B1B537E3AULL,
		0x1F8E9F32A3D050B2ULL,
		0x3BE01F108CEFB227ULL,
		0xFCC0357ABB1FD35AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37E3A00000000000ULL,
		0x050B2EBFF1E8B1B5ULL,
		0xFB2271F8E9F32A3DULL,
		0xFD35A3BE01F108CEULL,
		0x00000FCC0357ABB1ULL
	}};
	shift = 20;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x285D59546D319ED6ULL,
		0xE4CA20E7B9A0E3C5ULL,
		0x83B47978EEEAB787ULL,
		0x4500373A0E7DAF3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA3698CF6B000000ULL,
		0x73DCD071E2942EACULL,
		0xBC77755BC3F26510ULL,
		0x9D073ED79F41DA3CULL,
		0x000000000022801BULL
	}};
	shift = 41;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB05EE00A40B32C7EULL,
		0x862739643D73ABE1ULL,
		0x17ACA06F5EAB38C0ULL,
		0x8E6D45ECD5643784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCB1F800000000000ULL,
		0xEAF86C17B802902CULL,
		0xCE302189CE590F5CULL,
		0x0DE105EB281BD7AAULL,
		0x0000239B517B3559ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x183754F48A900DF5ULL,
		0x43B5980511FEDDB0ULL,
		0x7A06892D8F9E03A2ULL,
		0xF02D71AC75FB8176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE915201BEA000000ULL,
		0x0A23FDBB60306EA9ULL,
		0x5B1F3C0744876B30ULL,
		0x58EBF702ECF40D12ULL,
		0x0000000001E05AE3ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3613FD68C7BF5BF0ULL,
		0xFD51CC36A2F97384ULL,
		0x5B5D97C817FD0692ULL,
		0x02560780DB6A206FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9FEB463DFADF8000ULL,
		0x8E61B517CB9C21B0ULL,
		0xECBE40BFE83497EAULL,
		0xB03C06DB51037ADAULL,
		0x0000000000000012ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03348C63351B3A8CULL,
		0x7C8207DFA14B6666ULL,
		0x69565DC6DF75D0C0ULL,
		0xB5B84686F09B80B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x918C66A367518000ULL,
		0x40FBF4296CCCC066ULL,
		0xCBB8DBEEBA180F90ULL,
		0x08D0DE1370170D2AULL,
		0x00000000000016B7ULL
	}};
	shift = 51;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7EB4704419E0D8F6ULL,
		0xE2F2C4F09BD3AF90ULL,
		0x0EDF192D71C2A3EBULL,
		0x82115EE1B7495859ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8F6000000000000ULL,
		0xAF907EB4704419E0ULL,
		0xA3EBE2F2C4F09BD3ULL,
		0x58590EDF192D71C2ULL,
		0x000082115EE1B749ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x009D45FF78602502ULL,
		0xE93907A84F7CDC07ULL,
		0x462FD6CD34344A89ULL,
		0xC7385CA72720D5BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0940800000000000ULL,
		0x3701C027517FDE18ULL,
		0x12A27A4E41EA13DFULL,
		0x356F518BF5B34D0DULL,
		0x000031CE1729C9C8ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3719F75082A7C997ULL,
		0xB7E0AC95AD39DF86ULL,
		0x00438D5B2210B6E5ULL,
		0xC2377DF95F405191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x1B8CFBA84153E4CBULL,
		0xDBF0564AD69CEFC3ULL,
		0x8021C6AD91085B72ULL,
		0x611BBEFCAFA028C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADA76DBAF3B4F10AULL,
		0x5395B862F8157E10ULL,
		0x4405AC00A5B9DE1CULL,
		0x5C43B14B632797E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4280000000000000ULL,
		0x842B69DB6EBCED3CULL,
		0x8714E56E18BE055FULL,
		0xF991016B00296E77ULL,
		0x001710EC52D8C9E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD362C093B618C80AULL,
		0xE5258F97B7F21CF3ULL,
		0x3EDD2A508C2314E3ULL,
		0x23FED6DB516A2D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B618C80A0000000ULL,
		0x7B7F21CF3D362C09ULL,
		0x08C2314E3E5258F9ULL,
		0xB516A2D0E3EDD2A5ULL,
		0x00000000023FED6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9F4CD87BCC46203ULL,
		0x222DB8D73A205574ULL,
		0x4BE112CC2D473FB2ULL,
		0x57B02CC77D5E8D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCC4620300000000ULL,
		0x3A205574C9F4CD87ULL,
		0x2D473FB2222DB8D7ULL,
		0x7D5E8D454BE112CCULL,
		0x0000000057B02CC7ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5665D8DBED534F9CULL,
		0xDD85C9BDB2421EDBULL,
		0x6B3A8D46F3C3119EULL,
		0xE8111289CAB338EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34F9C00000000000ULL,
		0x21EDB5665D8DBED5ULL,
		0x3119EDD85C9BDB24ULL,
		0x338ED6B3A8D46F3CULL,
		0x00000E8111289CABULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5CE3D0248DF22BAULL,
		0xFF05CA3F4B8DE89CULL,
		0x1468D18037F5D731ULL,
		0x5825072428778563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE80000000000000ULL,
		0x273D738F409237C8ULL,
		0xCC7FC1728FD2E37AULL,
		0x58C51A34600DFD75ULL,
		0x00160941C90A1DE1ULL
	}};
	shift = 10;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE50358FAA91701DCULL,
		0xC6BDCE682CF19028ULL,
		0x311DC0780A79CEA3ULL,
		0xE39CCD5E7757B82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x01DC000000000000ULL,
		0x9028E50358FAA917ULL,
		0xCEA3C6BDCE682CF1ULL,
		0xB82D311DC0780A79ULL,
		0x0000E39CCD5E7757ULL
	}};
	shift = 16;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FEDA707418746CFULL,
		0x05035DD8EE9DC8B3ULL,
		0x0B82730351D96EE7ULL,
		0x1DAE994DFFFDA05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A0C3A367800000ULL,
		0xEC774EE459CFF6D3ULL,
		0x81A8ECB7738281AEULL,
		0xA6FFFED02F85C139ULL,
		0x00000000000ED74CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4A46CA199C04C64ULL,
		0x786AD50DBCB92E12ULL,
		0x9C0C7373DA387D72ULL,
		0xE5DB4FE61559D72CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x50CCE02632000000ULL,
		0x86DE5C97095A5236ULL,
		0xB9ED1C3EB93C356AULL,
		0xF30AACEB964E0639ULL,
		0x000000000072EDA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FC80E072A72B1A8ULL,
		0x43DCA87C4159FBC7ULL,
		0xE08F292783CFE6DAULL,
		0x05F5EDFD64B3B5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3958D40000000000ULL,
		0xACFDE3A7E4070395ULL,
		0xE7F36D21EE543E20ULL,
		0x59DAF6F0479493C1ULL,
		0x00000002FAF6FEB2ULL
	}};
	shift = 25;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECD93518ABF73ED7ULL,
		0xBB90DC72C71E8A3CULL,
		0x05DA9620CEDDDF40ULL,
		0xA9A048279FBCFC48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAE0000000000000ULL,
		0x479D9B26A3157EE7ULL,
		0xE817721B8E58E3D1ULL,
		0x8900BB52C419DBBBULL,
		0x0015340904F3F79FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD09EAEBD863E490EULL,
		0xA31898B7BAE31F4EULL,
		0x34EDD75246570CC1ULL,
		0x3C976EE628BDE4F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF248700000000000ULL,
		0x18FA7684F575EC31ULL,
		0xB8660D18C4C5BDD7ULL,
		0xEF27C1A76EBA9232ULL,
		0x000001E4BB773145ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x441685B371E44EF0ULL,
		0xC3914FCEEEE98EDBULL,
		0x96F9E49B2F0E2AB9ULL,
		0xF9C47E199F5134A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6882D0B66E3C89DEULL,
		0x387229F9DDDD31DBULL,
		0x52DF3C9365E1C557ULL,
		0x1F388FC333EA2694ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D48E64C2B1E45BAULL,
		0xB54EF0971A299005ULL,
		0xF92B12DBA0A3E143ULL,
		0xADB9D1C4693BD908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCC98563C8B740000ULL,
		0xE12E3453200A5A91ULL,
		0x25B74147C2876A9DULL,
		0xA388D277B211F256ULL,
		0x0000000000015B73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A88AEE7F2A8D2AEULL,
		0x0AD301366EBE3754ULL,
		0xAD09F7C156EFB758ULL,
		0xCFA0476C70E02C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCFE551A55C000000ULL,
		0x6CDD7C6EA855115DULL,
		0x82ADDF6EB015A602ULL,
		0xD8E1C0585F5A13EFULL,
		0x00000000019F408EULL
	}};
	shift = 39;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3275185978B5F2D5ULL,
		0x65E4B132A134137FULL,
		0x64C57E6B34BBC9D5ULL,
		0x86CB5027D7A968AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x30B2F16BE5AA0000ULL,
		0x6265426826FE64EAULL,
		0xFCD6697793AACBC9ULL,
		0xA04FAF52D15CC98AULL,
		0x0000000000010D96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE73A3078FB0A8096ULL,
		0x4677944D8D387876ULL,
		0x830C9A423B652236ULL,
		0xB23E59711F3D4B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x85404B0000000000ULL,
		0x9C3C3B739D183C7DULL,
		0xB2911B233BCA26C6ULL,
		0x9EA5BCC1864D211DULL,
		0x000000591F2CB88FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC078FA61D57F28A3ULL,
		0x59436F9ACE2CAC61ULL,
		0xC4C6362855298BC6ULL,
		0xBDC9DB137EC49BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x01E3E98755FCA28CULL,
		0x650DBE6B38B2B187ULL,
		0x1318D8A154A62F19ULL,
		0xF7276C4DFB126EDFULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x87733A761BA1A456ULL,
		0x8FF85B70489A4BCCULL,
		0xD57C3565AE16AB12ULL,
		0xADDA5411E2EF08A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48AC000000000000ULL,
		0x97990EE674EC3743ULL,
		0x56251FF0B6E09134ULL,
		0x114BAAF86ACB5C2DULL,
		0x00015BB4A823C5DEULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC303342C7CAFA97ULL,
		0x62C4F815B215DAEDULL,
		0xE69A39ABD9D96FC6ULL,
		0xED98D30D455EB2F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x57D4B80000000000ULL,
		0xAED76E61819A163EULL,
		0xCB7E331627C0AD90ULL,
		0xF597CF34D1CD5ECEULL,
		0x0000076CC6986A2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BBF23027DD9BCAFULL,
		0x1B395B7E4C796521ULL,
		0x2F8CB96D2CD1E30EULL,
		0x59F2E7D9D156AE81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF00000000000000ULL,
		0x219BBF23027DD9BCULL,
		0x0E1B395B7E4C7965ULL,
		0x812F8CB96D2CD1E3ULL,
		0x0059F2E7D9D156AEULL
	}};
	shift = 8;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA71B331683BBFC69ULL,
		0x7673153DA92EE9B1ULL,
		0x776EF26974DB0E29ULL,
		0x3A72438AA54C1C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6CCC5A0EEFF1A40ULL,
		0x9CC54F6A4BBA6C69ULL,
		0xDBBC9A5D36C38A5DULL,
		0x9C90E2A9530700DDULL,
		0x000000000000000EULL
	}};
	shift = 58;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C41E00AADE4B42FULL,
		0xAF12A37480525B5BULL,
		0xEB5E8D592923CCE6ULL,
		0x26DE36F0C3C2A0B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x685E000000000000ULL,
		0xB6B63883C0155BC9ULL,
		0x99CD5E2546E900A4ULL,
		0x4171D6BD1AB25247ULL,
		0x00004DBC6DE18785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C2D37F9DC9AA7BBULL,
		0xB8089AFD635D38D3ULL,
		0xADA417F9E50CE051ULL,
		0xE9AE22DBE90C100EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB00000000000000ULL,
		0xD35C2D37F9DC9AA7ULL,
		0x51B8089AFD635D38ULL,
		0x0EADA417F9E50CE0ULL,
		0x00E9AE22DBE90C10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x816D5EE048F5B8CDULL,
		0x3F86719ECCC81B63ULL,
		0xCC2357F1D2FA78A5ULL,
		0xE9AC2253CC5BE83EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57B8123D6E334000ULL,
		0x9C67B33206D8E05BULL,
		0xD5FC74BE9E294FE1ULL,
		0x0894F316FA0FB308ULL,
		0x0000000000003A6BULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B15295C1D043389ULL,
		0x32A43F1363A9FFDDULL,
		0x9DE7B33C1B5116ACULL,
		0x0521244B560FF4C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3890000000000000ULL,
		0xFDD6B15295C1D043ULL,
		0x6AC32A43F1363A9FULL,
		0x4C29DE7B33C1B511ULL,
		0x0000521244B560FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3745349F0BA3D082ULL,
		0xFE23FACF76947F0DULL,
		0xD5EF1E7CCE65C202ULL,
		0x98215A46737FF928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3D08200000000000ULL,
		0x47F0D3745349F0BAULL,
		0x5C202FE23FACF769ULL,
		0xFF928D5EF1E7CCE6ULL,
		0x0000098215A46737ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAC442B72451EE08ULL,
		0xD420DBC305DC0570ULL,
		0xBFDEA3182E6B8164ULL,
		0x7DB0CB97EF9BB65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9228F7040000000ULL,
		0x182EE02B85562215ULL,
		0xC1735C0B26A106DEULL,
		0xBF7CDDB2F5FEF518ULL,
		0x0000000003ED865CULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51CCBED8939C7BB5ULL,
		0xB56BD438B0E0683CULL,
		0x6F544418BAEF8BC5ULL,
		0xFE6614B6D5B5853DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA80000000000000ULL,
		0x1E28E65F6C49CE3DULL,
		0xE2DAB5EA1C587034ULL,
		0x9EB7AA220C5D77C5ULL,
		0x007F330A5B6ADAC2ULL
	}};
	shift = 9;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB114D28EF3F5476ULL,
		0xC63F83B876257DC3ULL,
		0x98AB8221A95809FEULL,
		0x933C5C8547BA7A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DE7EA8EC0000000ULL,
		0x0EC4AFB8776229A5ULL,
		0x352B013FD8C7F077ULL,
		0xA8F74F5093157044ULL,
		0x0000000012678B90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F7C53FF76DAC3EEULL,
		0xE9C8D5BA2BE97CAAULL,
		0x589CFF9608217C40ULL,
		0x781A07CDED9C1D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FEEDB587DC00000ULL,
		0xB7457D2F954DEF8AULL,
		0xF2C1042F881D391AULL,
		0xF9BDB383A58B139FULL,
		0x00000000000F0340ULL
	}};
	shift = 43;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC695A19D20848DBDULL,
		0x5AE1ECC0902E63BBULL,
		0x0732EFE0599C0841ULL,
		0x41F533927CEB385FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x848DBD0000000000ULL,
		0x2E63BBC695A19D20ULL,
		0x9C08415AE1ECC090ULL,
		0xEB385F0732EFE059ULL,
		0x00000041F533927CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x188CB9BF1E336B28ULL,
		0x9B1BE4FBE9215137ULL,
		0x3E490020615BBA27ULL,
		0xBBF8A6839BA27C29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B59400000000000ULL,
		0x0A89B8C465CDF8F1ULL,
		0xDDD13CD8DF27DF49ULL,
		0x13E149F24801030AULL,
		0x000005DFC5341CDDULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCAF6C00F289FD7F1ULL,
		0x26306D0360D284D4ULL,
		0x27F88972522D768CULL,
		0x8BBB7A356CCC45E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5ED801E513FAFE20ULL,
		0xC60DA06C1A509A99ULL,
		0xFF112E4A45AED184ULL,
		0x776F46AD9988BCA4ULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA00B6246B08C385FULL,
		0x3B6B0C5BBA02A2BBULL,
		0x287FAC00F40AC194ULL,
		0x654B90E65CBD19C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0xBA00B6246B08C385ULL,
		0x43B6B0C5BBA02A2BULL,
		0x9287FAC00F40AC19ULL,
		0x0654B90E65CBD19CULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8514DF892365C644ULL,
		0x0DF440B22CF2A55BULL,
		0x2EAEF84DE79C8E1CULL,
		0xE2707CEF3A3989CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37E248D971910000ULL,
		0x102C8B3CA956E145ULL,
		0xBE1379E72387037DULL,
		0x1F3BCE8E6272CBABULL,
		0x000000000000389CULL
	}};
	shift = 50;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29E1809A990368D6ULL,
		0xD73463CE3923881EULL,
		0xCBE041DBE8170BB1ULL,
		0x5966CCEE4B8D9D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x01353206D1AC0000ULL,
		0xC79C7247103C53C3ULL,
		0x83B7D02E1763AE68ULL,
		0x99DC971B3ABD97C0ULL,
		0x000000000000B2CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE36B7C2CB42A3A3AULL,
		0x76A1DAD5FBDE10DBULL,
		0x632E64B99D26CC65ULL,
		0x1870D44FC557385CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D1D000000000000ULL,
		0x086DF1B5BE165A15ULL,
		0x6632BB50ED6AFDEFULL,
		0x9C2E3197325CCE93ULL,
		0x00000C386A27E2ABULL
	}};
	shift = 17;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF0786AA6E691F21ULL,
		0x7571F5CF9F32BFC4ULL,
		0xB34AD3997ADA2B97ULL,
		0x4B065BD40173996EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86AA6E691F210000ULL,
		0xF5CF9F32BFC4AF07ULL,
		0xD3997ADA2B977571ULL,
		0x5BD40173996EB34AULL,
		0x0000000000004B06ULL
	}};
	shift = 48;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3926E345E8E3ADDAULL,
		0xA28DD4671C4974BEULL,
		0x9E0716EA02C68436ULL,
		0x5380198DCF02A7A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B8D17A38EB76800ULL,
		0x37519C7125D2F8E4ULL,
		0x1C5BA80B1A10DA8AULL,
		0x0066373C0A9E8E78ULL,
		0x000000000000014EULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C1E657DBE6E0179ULL,
		0xECDB6F26F6929CDBULL,
		0x67DF148CEB810551ULL,
		0xB26714A67125FA2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC02F200000000000ULL,
		0x539B6583CCAFB7CDULL,
		0x20AA3D9B6DE4DED2ULL,
		0xBF454CFBE2919D70ULL,
		0x0000164CE294CE24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7FBA3427D49B73AULL,
		0xB0D279B86BC48626ULL,
		0xA9A00EF0779C7771ULL,
		0xB57A2936F7D66DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFBA3427D49B73A00ULL,
		0xD279B86BC48626B7ULL,
		0xA00EF0779C7771B0ULL,
		0x7A2936F7D66DF6A9ULL,
		0x00000000000000B5ULL
	}};
	shift = 56;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E953DB7E302563FULL,
		0x5EC4584616E4BE89ULL,
		0xA123EE696B8F5345ULL,
		0x0149D73EB58B8605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63F0000000000000ULL,
		0xE894E953DB7E3025ULL,
		0x3455EC4584616E4BULL,
		0x605A123EE696B8F5ULL,
		0x0000149D73EB58B8ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95BA5DE56E73243AULL,
		0x7A67A70B6A9601A9ULL,
		0x6657978575CA0D05ULL,
		0xBCA751CEBCABAD4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x243A000000000000ULL,
		0x01A995BA5DE56E73ULL,
		0x0D057A67A70B6A96ULL,
		0xAD4C6657978575CAULL,
		0x0000BCA751CEBCABULL
	}};
	shift = 16;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BB2661F31F07212ULL,
		0x201B85FD49E2468CULL,
		0x0A84951770AD21B9ULL,
		0xDAC4D404EC9E395BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F8390900000000ULL,
		0xA4F123464DD9330FULL,
		0xB85690DC900DC2FEULL,
		0x764F1CAD85424A8BULL,
		0x000000006D626A02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B3F65F54A15CB76ULL,
		0xC6FEAC79C53BB0A6ULL,
		0xBC7A97129F76FF18ULL,
		0x604CD6C6FAF59996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECBEA942B96EC000ULL,
		0xD58F38A77614C167ULL,
		0x52E253EEDFE318DFULL,
		0x9AD8DF5EB332D78FULL,
		0x0000000000000C09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FAD0477900B887DULL,
		0xB56059E554FD5347ULL,
		0x1B5B8A177608FF30ULL,
		0xDF61CF2A7F08E652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBF5A08EF201710FAULL,
		0x6AC0B3CAA9FAA68EULL,
		0x36B7142EEC11FE61ULL,
		0xBEC39E54FE11CCA4ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B3B2BA7A3085C30ULL,
		0x843DC984194A4615ULL,
		0x8D8EC8CF07F3AA12ULL,
		0x358AFEB92B0C2029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F4610B860000000ULL,
		0x0832948C2A167657ULL,
		0x9E0FE75425087B93ULL,
		0x72561840531B1D91ULL,
		0x00000000006B15FDULL
	}};
	shift = 39;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0E250D4400FD966ULL,
		0x3E0BB7F5C8E26E6FULL,
		0x359FD024157CBB4FULL,
		0x62B30A8F8042F7CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A2007ECB3000000ULL,
		0xFAE4713737D07128ULL,
		0x120ABE5DA79F05DBULL,
		0x47C0217BE61ACFE8ULL,
		0x0000000000315985ULL
	}};
	shift = 41;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F03CA840F9A9248ULL,
		0x4AB2FCCA49850A84ULL,
		0x02FD6ACEADF7F1B1ULL,
		0xBC53755E3527F28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CD4924000000000ULL,
		0x4C285422781E5420ULL,
		0x6FBF8D8A5597E652ULL,
		0xA93F947817EB5675ULL,
		0x00000005E29BAAF1ULL
	}};
	shift = 29;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F28E134AA215AE6ULL,
		0x96B182B268877F09ULL,
		0x9F88772BCE152FE6ULL,
		0xA9A0A7CCE198CED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9800000000000000ULL,
		0x253CA384D2A8856BULL,
		0x9A5AC60AC9A21DFCULL,
		0x527E21DCAF3854BFULL,
		0x02A6829F3386633BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38B025FE4EF8FF59ULL,
		0x88B3DB74D9225DFEULL,
		0xADC06689A854E53BULL,
		0x09805697383A5AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C097F93BE3FD64ULL,
		0x22CF6DD3648977F8ULL,
		0xB7019A26A15394EEULL,
		0x26015A5CE0E96B5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x722EB47ABCF43759ULL,
		0x90DFB6F996E776A1ULL,
		0x1D53D23D44021579ULL,
		0x71864C0F53A3A355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAF3D0DD64000000ULL,
		0xE65B9DDA85C8BAD1ULL,
		0xF5100855E6437EDBULL,
		0x3D4E8E8D54754F48ULL,
		0x0000000001C61930ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FFDB85D47ADA1B4ULL,
		0x60C3A513632A2D92ULL,
		0xF88FE8A63A6ABB1EULL,
		0x286FEEB9632F8BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x94FFEDC2EA3D6D0DULL,
		0xF3061D289B19516CULL,
		0xD7C47F4531D355D8ULL,
		0x01437F75CB197C5DULL
	}};
	shift = 5;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FDF93A87E49510AULL,
		0xEE2B95042E580150ULL,
		0xAAFB36EEC66351F3ULL,
		0x8B0B5C18D00BE559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FEFC9D43F24A885ULL,
		0xF715CA82172C00A8ULL,
		0xD57D9B776331A8F9ULL,
		0x4585AE0C6805F2ACULL
	}};
	shift = 1;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCAB01E23749D91ADULL,
		0xC69660B9A0F901FBULL,
		0x73224374343459A3ULL,
		0x558C5B12B7CA4E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B235A0000000000ULL,
		0xF203F795603C46E9ULL,
		0x68B3478D2CC17341ULL,
		0x949C66E64486E868ULL,
		0x000000AB18B6256FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74797017C5F45A4FULL,
		0xF3CC3DC5E56B0D33ULL,
		0xA0F1D18EE8ACF4F7ULL,
		0x6C9AE6FCC60EAE86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97017C5F45A4F000ULL,
		0xC3DC5E56B0D33747ULL,
		0x1D18EE8ACF4F7F3CULL,
		0xAE6FCC60EAE86A0FULL,
		0x00000000000006C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD25CABE9FAFA9934ULL,
		0x2D9138A5EED82895ULL,
		0x5896456FDF8B4222ULL,
		0xAF4B1B1AD0680D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B957D3F5F532680ULL,
		0xB22714BDDB0512BAULL,
		0x12C8ADFBF1684445ULL,
		0xE963635A0D01A30BULL,
		0x0000000000000015ULL
	}};
	shift = 59;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F13459C0AB1E575ULL,
		0x6E84909B023F3084ULL,
		0xBE667628C0D0DBEDULL,
		0x8AE970FD4B9DF27BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4D16702AC795D400ULL,
		0x12426C08FCC2123CULL,
		0x99D8A303436FB5BAULL,
		0xA5C3F52E77C9EEF9ULL,
		0x000000000000022BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A679708B18E9928ULL,
		0x80D8D183CFAF868BULL,
		0x22F4DA856A1BC940ULL,
		0xD03B08BC42168CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8458C74C94000000ULL,
		0xC1E7D7C345CD33CBULL,
		0x42B50DE4A0406C68ULL,
		0x5E210B4674917A6DULL,
		0x0000000000681D84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09F015EA8A45BDA4ULL,
		0x06B386192D780EE4ULL,
		0x4944919E2AF52491ULL,
		0xDB0DF9A4DD388130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AF54522DED20000ULL,
		0xC30C96BC077204F8ULL,
		0x48CF157A92488359ULL,
		0xFCD26E9C409824A2ULL,
		0x0000000000006D86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAB673D222EBF46EULL,
		0xBC721150882A8BF0ULL,
		0xFC8A45A5AB045A50ULL,
		0x2E3AA43044AFD0A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF488BAFD1B800000ULL,
		0x54220AA2FC2AAD9CULL,
		0x696AC116942F1C84ULL,
		0x0C112BF4293F2291ULL,
		0x00000000000B8EA9ULL
	}};
	shift = 42;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8931DA795BB3E94EULL,
		0x9BCA35E40343D576ULL,
		0xEA5C73055F98BBD2ULL,
		0xD1328653EE5236C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB767D29C00000000ULL,
		0x0687AAED1263B4F2ULL,
		0xBF3177A537946BC8ULL,
		0xDCA46D85D4B8E60AULL,
		0x00000001A2650CA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAC569DE671362DCULL,
		0xAF40A446583B1A17ULL,
		0x26DB487FB0DAC42FULL,
		0x7BCB2E8EDFE138A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58AD3BCCE26C5B80ULL,
		0xE81488CB076342FBULL,
		0xDB690FF61B5885F5ULL,
		0x7965D1DBFC271524ULL,
		0x000000000000000FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E625EF78D0F9122ULL,
		0x59870C87E732DBDBULL,
		0x3D22F53D5152697BULL,
		0xE79249612BCCCD11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF1A1F22440000000ULL,
		0xFCE65B7B73CC4BDEULL,
		0xAA2A4D2F6B30E190ULL,
		0x257999A227A45EA7ULL,
		0x000000001CF2492CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x245AA5D345A0CC4AULL,
		0x8C00331591BB07D1ULL,
		0x52720EDEC2B4CB34ULL,
		0xE904EE205D084003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B54BA68B4198940ULL,
		0x800662B23760FA24ULL,
		0x4E41DBD856996691ULL,
		0x209DC40BA108006AULL,
		0x000000000000001DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFAB691D52381850ULL,
		0x3282AAF61F66342FULL,
		0x93666CD12CAEACDEULL,
		0x32CFCC3EB38D9D33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA47548E06140000ULL,
		0xAABD87D98D0BEBEAULL,
		0x9B344B2BAB378CA0ULL,
		0xF30FACE3674CE4D9ULL,
		0x0000000000000CB3ULL
	}};
	shift = 50;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x405BFB3D8D0E23FFULL,
		0x3EECB9D22472D11BULL,
		0x3ECF4180BB8F5A3EULL,
		0x8E5E22903FB7D120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF67B1A1C47FE0000ULL,
		0x73A448E5A23680B7ULL,
		0x8301771EB47C7DD9ULL,
		0x45207F6FA2407D9EULL,
		0x0000000000011CBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x924F0D64F47BEDC2ULL,
		0xF06A95432CE710EEULL,
		0x8D5E16D7DCE51002ULL,
		0xA4BE88B2E59F24F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F0D64F47BEDC200ULL,
		0x6A95432CE710EE92ULL,
		0x5E16D7DCE51002F0ULL,
		0xBE88B2E59F24F48DULL,
		0x00000000000000A4ULL
	}};
	shift = 56;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2637617B735C3822ULL,
		0xFE8180C269714233ULL,
		0x4281AAFDE93F7601ULL,
		0xC1DC9F1B85C62EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7617B735C3822000ULL,
		0x180C269714233263ULL,
		0x1AAFDE93F7601FE8ULL,
		0xC9F1B85C62EF6428ULL,
		0x0000000000000C1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D14B060EF7BF3A6ULL,
		0xE10CB0F92A98F3E9ULL,
		0xFB2D46BDA088F155ULL,
		0xB275EF4CFA11E49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF3A600000000000ULL,
		0x8F3E94D14B060EF7ULL,
		0x8F155E10CB0F92A9ULL,
		0x1E49CFB2D46BDA08ULL,
		0x00000B275EF4CFA1ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54C1A6E649FDE0EBULL,
		0x931DDB9A50D25B4CULL,
		0xE0A3FB3759AD4E73ULL,
		0x649A4AC217A356FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7580000000000000ULL,
		0xA62A60D37324FEF0ULL,
		0x39C98EEDCD28692DULL,
		0x7FF051FD9BACD6A7ULL,
		0x00324D25610BD1ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x326A69B6250C208CULL,
		0x522034AEDA5457D1ULL,
		0xCCC2E081A7A7AC28ULL,
		0x30B3C5895F7C303BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0460000000000000ULL,
		0xBE8993534DB12861ULL,
		0x61429101A576D2A2ULL,
		0x81DE6617040D3D3DULL,
		0x0001859E2C4AFBE1ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x590244D4E94E1B7FULL,
		0x8E3D4045D47CE4CBULL,
		0xE5B9D0822E4A7729ULL,
		0x4DBF2AF35F188C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DBF800000000000ULL,
		0x7265AC81226A74A7ULL,
		0x3B94C71EA022EA3EULL,
		0x4609F2DCE8411725ULL,
		0x000026DF9579AF8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16246D565E0988FDULL,
		0x3CBFD1AAFBD5EB06ULL,
		0x962E39BBA133C496ULL,
		0x44A452CA62999331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D565E0988FD0000ULL,
		0xD1AAFBD5EB061624ULL,
		0x39BBA133C4963CBFULL,
		0x52CA62999331962EULL,
		0x00000000000044A4ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0004000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000020000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000004000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000004000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0008000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
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
		0x0000000400000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000001000ULL,
		0x0000000000000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000200000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000100000000ULL,
		0x0000000000000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}