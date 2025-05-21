#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x14BF36A63011BFA4ULL,
		0x03CFE841512D93DFULL,
		0x8FDE0E87E97DD6D5ULL,
		0x46CB922648BDAA08ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xAAF3CB2818EE4E10ULL,
		0x5E47A84FFB380278ULL,
		0xC6FAF7A3B13E18F0ULL,
		0x7238E5A0BAD53308ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x69CB6B7E17237181ULL,
		0xA5883FF155F59166ULL,
		0xC8E316E4383FBDE4ULL,
		0x5492AC858DE876FFULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x84E67A3CB5A4DEC6ULL,
		0x435DA4305B6B5EACULL,
		0x6F5734092275CC39ULL,
		0x50E1EFBC3F82FFCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE736AB566F667C86ULL,
		0x44E113810D6DFDDCULL,
		0x3E0DF4EFA947CD10ULL,
		0x1730944A8A971C74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DAFCEE6463E6240ULL,
		0xFE7C90AF4DFD60CFULL,
		0x31493F19792DFF28ULL,
		0x39B15B71B4EBE358ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7C0FE4B655D90D77ULL,
		0xABEE07AD875D17FEULL,
		0x2224B616B8485741ULL,
		0x0E7287658585834EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47468AC3A3A40F8AULL,
		0xFB28C97390214413ULL,
		0x82B2C4470DE2043BULL,
		0x3E63394A9EC4A96BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34C959F2B234FDDAULL,
		0xB0C53E39F73BD3EBULL,
		0x9F71F1CFAA665305ULL,
		0x500F4E1AE6C0D9E2ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB9D4F3AA4E92A3AAULL,
		0x385CF65FD3A4081CULL,
		0xD948BCCCB4BB0E15ULL,
		0x506C13322B53F469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCABA3055ADF5B5FULL,
		0x30145BFC1F919344ULL,
		0xE0410ED927EA1DD5ULL,
		0x49094D61CF84DFD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED2950A4F3B3484BULL,
		0x08489A63B41274D7ULL,
		0xF907ADF38CD0F040ULL,
		0x0762C5D05BCF1491ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8C77DC35150E269FULL,
		0xA6EC42791FB31998ULL,
		0x805304D6144EE8CBULL,
		0x63BBF06D82F32B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECB747ECD7E0BE7ULL,
		0x9F85CE1C097DAB39ULL,
		0x92D6C78CB85ABAABULL,
		0x647A0101F8FA7CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DAC67B647901AA5ULL,
		0x0766745D16356E5FULL,
		0xED7C3D495BF42E20ULL,
		0x7F41EF6B89F8AE0EULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x202EF73084C1C3C8ULL,
		0x52CD6813744D4E76ULL,
		0x94A4FDBAF3C7F118ULL,
		0x6F6FE1121F0CEF12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B887BB0F3F59A2FULL,
		0x997ABC8B4FFBFC4BULL,
		0xAE98A222F13A4F92ULL,
		0x38BFA75DBA8AEF49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84A67B7F90CC2999ULL,
		0xB952AB882451522AULL,
		0xE60C5B98028DA185ULL,
		0x36B039B46481FFC8ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF8F28F0F6DFBCF9FULL,
		0x244E858F758E15A8ULL,
		0xD19CFD592DF5896FULL,
		0x535ED95FE11ABAA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A238EC21FFC2D4ULL,
		0xE7FCBDEFB796B1C0ULL,
		0x78A8C994AF6BA9CFULL,
		0x19255F6C240F226FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x375056234BFC0CCBULL,
		0x3C51C79FBDF763E8ULL,
		0x58F433C47E89DF9FULL,
		0x3A3979F3BD0B9835ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE146224A6F9B37E0ULL,
		0xF2400164D34474C3ULL,
		0xF4C37BF2B5A43295ULL,
		0x555E4D6A24C9E8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7ADFC67A60EBA74ULL,
		0x8404479A5C1AA2EAULL,
		0x9BE331170F75F7DFULL,
		0x5052CC43A96A9C6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x399825E2C98C7D6CULL,
		0x6E3BB9CA7729D1D9ULL,
		0x58E04ADBA62E3AB6ULL,
		0x050B81267B5F4C3BULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xBE68D9228508A1A9ULL,
		0xFD1FADE5DD85B951ULL,
		0x83A46F011E9D0266ULL,
		0x5861CE000A3BE2E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003C8F78C9ECA12EULL,
		0xE614BE4D3D7B3B7FULL,
		0xB359EB5696F297A1ULL,
		0x289A99C55FCA95CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE2C49A9BB1C007BULL,
		0x170AEF98A00A7DD2ULL,
		0xD04A83AA87AA6AC5ULL,
		0x2FC7343AAA714D15ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC5052FE28D1EDB52ULL,
		0x71E1103884708B11ULL,
		0x12358D0C64D5F9EDULL,
		0x49D6C845BBD8B5DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD98DBEDA58230BULL,
		0x6B4F33CEF0BE5AA1ULL,
		0x049E22ACD7FF759EULL,
		0x211F66636270BAE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x682BA223B2C6B847ULL,
		0x0691DC6993B23070ULL,
		0x0D976A5F8CD6844FULL,
		0x28B761E25967FAFCULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6A7282F74DEAEF9EULL,
		0x471B8C5803DC877AULL,
		0x56DE3825D011D65AULL,
		0x27ED0698C60AF986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0FAA3AEFB355CA3ULL,
		0xFE6A2FBFD2BB7709ULL,
		0xEBD9C349ECEC047AULL,
		0x0C2E9A0A78F61565ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8977DF4852B592FBULL,
		0x48B15C9831211070ULL,
		0x6B0474DBE325D1DFULL,
		0x1BBE6C8E4D14E420ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x262BAA55CEE6956CULL,
		0x4234554F61A4559DULL,
		0x52D3B3AF42D0EEE8ULL,
		0x5523DE30DECF935BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5DD36C329437041ULL,
		0xCBA2D8EBEA3ED599ULL,
		0x1BFD8FF6D6FBC24CULL,
		0x000AEB7258314B89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x804E7392A5A3252BULL,
		0x76917C6377658003ULL,
		0x36D623B86BD52C9BULL,
		0x5518F2BE869E47D2ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xEB366C302FB0483BULL,
		0x4C0100133BF4C1A3ULL,
		0xDFBFF024D3ED634FULL,
		0x160833A0F049E385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0132E6A944C22DULL,
		0xE9CB9FC95F98BC09ULL,
		0x285D1E6E31F8BEBCULL,
		0x17D3980C6646D2D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE353949866B85FBULL,
		0x62356049DC5C059AULL,
		0xB762D1B6A1F4A492ULL,
		0x7E349B948A0310AEULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5CFDAB3C64FDB923ULL,
		0x95717647F3D7C93FULL,
		0x8738E6BACB20C1C7ULL,
		0x17BBD109A6FAD2ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF74FF80D874298F5ULL,
		0x25AB217D12B92E6AULL,
		0x20EA112D0933100FULL,
		0x34C92393128184EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65ADB32EDDBB201BULL,
		0x6FC654CAE11E9AD4ULL,
		0x664ED58DC1EDB1B8ULL,
		0x62F2AD7694794DBEULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xDE84DF410EC95EE8ULL,
		0xDA2EB63B6F7EE0FAULL,
		0x22742307FA7C82D0ULL,
		0x26CB7560DCC3C8B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45738221A213ADDULL,
		0x8A4775A70F7292BBULL,
		0x435E71AAB09E0285ULL,
		0x65AA02BDF2ABD286ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA2DA71EF4A823F8ULL,
		0x4FE74094600C4E3EULL,
		0xDF15B15D49DE804BULL,
		0x412172A2EA17F62AULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x071E53C05E65D660ULL,
		0x26B1DC1829A70F15ULL,
		0xC30D1C1F154EF69CULL,
		0x6CE5D8416206E832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527D3B1252684E6CULL,
		0xFF33055533D1A380ULL,
		0x144D33AE1F14676FULL,
		0x4796DFB138B2C106ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4A118AE0BFD87F4ULL,
		0x277ED6C2F5D56B94ULL,
		0xAEBFE870F63A8F2CULL,
		0x254EF8902954272CULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3CFB7107C2D318C7ULL,
		0xEF2E9D10ADA9F273ULL,
		0x0527320EB4465436ULL,
		0x4FE2B3F0B42FC2EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474C32F0A1FDB112ULL,
		0x7A6908795C50400EULL,
		0x9AD55BE6D66886ADULL,
		0x40D47F1370E2D83FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5AF3E1720D567B5ULL,
		0x74C594975159B264ULL,
		0x6A51D627DDDDCD89ULL,
		0x0F0E34DD434CEAAFULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6FC9979A1132FCE3ULL,
		0x0B80FF769DEA4499ULL,
		0x244977BAB23A1A96ULL,
		0x32E07EB443C91BFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD24FAA42223B7D98ULL,
		0x5F664760EFB5510BULL,
		0x25C52EA1CD883FA3ULL,
		0x11EA3950F55BE6D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D79ED57EEF77F4BULL,
		0xAC1AB815AE34F38DULL,
		0xFE844918E4B1DAF2ULL,
		0x20F645634E6D3526ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x347CAC9D7A89EFE1ULL,
		0xDE472B0FAD6005F2ULL,
		0x6C331E8A89DDE548ULL,
		0x0D283954DC5AAE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBAA104D437EEA4EULL,
		0x3865E72A54B6742BULL,
		0x17DD7052842C36FFULL,
		0x257C140DC6D9D9B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48D29C50370B0580ULL,
		0xA5E143E558A991C6ULL,
		0x5455AE3805B1AE49ULL,
		0x67AC25471580D4CDULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF8CDBEAFF833225AULL,
		0x27F0AFFB3B16A6F9ULL,
		0x43F6E557EE67C9ACULL,
		0x18C766B7E5A9386AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B2367D72D4F7D9ULL,
		0x41F8ED43DCF5DF79ULL,
		0x0D02C54A06A5EBCBULL,
		0x0C51AF900BCD3797ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB71B8832855E2A81ULL,
		0xE5F7C2B75E20C780ULL,
		0x36F4200DE7C1DDE0ULL,
		0x0C75B727D9DC00D3ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x29037FBD5C357577ULL,
		0xC6C1C07F344E70A2ULL,
		0x91B4F1F4D025FE1FULL,
		0x076FCE25A8C1C57BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA341EE837D77CA53ULL,
		0x1AA4F8B08C4B761BULL,
		0x5CD03562CA086C8CULL,
		0x6867E26302242A5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C19139DEBDAB11ULL,
		0xAC1CC7CEA802FA86ULL,
		0x34E4BC92061D9193ULL,
		0x1F07EBC2A69D9B1FULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1CDCC0755EDE54C2ULL,
		0x2A1F6B4C36F1ABD3ULL,
		0x4AC1A9D424BD869BULL,
		0x705F43CD59D84A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CE2689311F36998ULL,
		0x009B493714B21AA2ULL,
		0x9155CB9325FD34D4ULL,
		0x1F39945507C405B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FFA57E24CEAEB2AULL,
		0x29842215223F9131ULL,
		0xB96BDE40FEC051C7ULL,
		0x5125AF785214444CULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE89B1382F92C1A1FULL,
		0xE64AFC36566ED1F9ULL,
		0x239EB3D3D8E89AA0ULL,
		0x65DB09987728702BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88071633B617F2BULL,
		0x60F5A2F8F15952D3ULL,
		0x6A203C85A8FA823EULL,
		0x2CFB5A25726D279AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401AA21FBDCA9AF4ULL,
		0x8555593D65157F26ULL,
		0xB97E774E2FEE1862ULL,
		0x38DFAF7304BB4890ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8E319BA6A4E81CAEULL,
		0x6FE0F9C23EF3EB22ULL,
		0xB6F8E8E0B1B73F01ULL,
		0x47A4F37FD49CD190ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2FE74B2BA348A54ULL,
		0x530C3B9D4C9DED09ULL,
		0x075F4F15552CA9ABULL,
		0x091581C85238A0D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB3326F3EAB3925AULL,
		0x1CD4BE24F255FE18ULL,
		0xAF9999CB5C8A9556ULL,
		0x3E8F71B7826430BCULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6BE13BBD8049297AULL,
		0xA27AB090E0C365E0ULL,
		0x93CDDD8836E10F0FULL,
		0x6F250897317952C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2F469CD3C2858FULL,
		0x4BADC20520B8D864ULL,
		0xDA2A845713D011DFULL,
		0x5EA94E58816F8D78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01B1F520AC86A3EBULL,
		0x56CCEE8BC00A8D7CULL,
		0xB9A359312310FD30ULL,
		0x107BBA3EB009C54EULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x88B5A8C0BA644FBDULL,
		0x580AD0488C65A489ULL,
		0xD6A063CF42ECF7F0ULL,
		0x7EC8D88E0CDB4597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34FF1ECE8F15FCD6ULL,
		0xC5252C7DE7813908ULL,
		0xBC8B1BA0BAFC3B63ULL,
		0x1D2EBEA776E05CCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B689F22B4E52E7ULL,
		0x92E5A3CAA4E46B81ULL,
		0x1A15482E87F0BC8CULL,
		0x619A19E695FAE8C8ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0E3CC455C1502D84ULL,
		0x07D0EB0C20BF12CCULL,
		0x772234188A2069FDULL,
		0x0A28B623680D55CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE5BAA3B0E202B67ULL,
		0xC96393710FCAF797ULL,
		0x995492A9D474F2BCULL,
		0x349FE1AC29C81714ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FE11A1AB330020AULL,
		0x3E6D579B10F41B34ULL,
		0xDDCDA16EB5AB7740ULL,
		0x5588D4773E453EB8ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xD675588C7C3A6913ULL,
		0x355F60714B16F13EULL,
		0x27AE090028234606ULL,
		0x4D5584C77454F12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x761E2BB4ACB59A15ULL,
		0xA975115B266BF879ULL,
		0x12304D9F32EB840DULL,
		0x2EE6F93DAF9588FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60572CD7CF84CEFEULL,
		0x8BEA4F1624AAF8C5ULL,
		0x157DBB60F537C1F8ULL,
		0x1E6E8B89C4BF6833ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xFDEB67F63C8B3DC2ULL,
		0x8D9DB9009542202DULL,
		0xA6518ECA442B3DAEULL,
		0x7A9726BAFE1F4289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD5EEBDA1A471C6ULL,
		0x5FAE4EA30EA9833AULL,
		0x950BEA4C65BA64BAULL,
		0x5CF5F4299488C66EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE01579389AE6CBFCULL,
		0x2DEF6A5D86989CF3ULL,
		0x1145A47DDE70D8F4ULL,
		0x1DA1329169967C1BULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4A42ABC865C3BED9ULL,
		0x02C3DB3F6765E87DULL,
		0x730FA2DD88DACD61ULL,
		0x54B9987A26426F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37BB0B3EF47FEB98ULL,
		0x2264DD0955824D79ULL,
		0x3652C9B8E1C74D4FULL,
		0x1F366E3F115DB937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1287A0897143D341ULL,
		0xE05EFE3611E39B04ULL,
		0x3CBCD924A7138011ULL,
		0x35832A3B14E4B65FULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9D36B73BCF805911ULL,
		0x4D5B48F937A44599ULL,
		0xB0F2342513B812C0ULL,
		0x41366C7297FA8246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C786648EE29D732ULL,
		0xBBC958B005231616ULL,
		0x6379DCC104F2C970ULL,
		0x39A277AFD19C7945ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30BE50F2E15681DFULL,
		0x9191F04932812F83ULL,
		0x4D7857640EC5494FULL,
		0x0793F4C2C65E0901ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5858F5FAC6C597E3ULL,
		0x358FA642E9AAC461ULL,
		0xA2157C2C8307F52DULL,
		0x47C3E16C2F63F166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F1EEE2B7C2B8ECULL,
		0xC4A013BB31D00B6CULL,
		0x1579A409FBE5D7C0ULL,
		0x48C3C1497014A4FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x636707180F02DEE4ULL,
		0x70EF9287B7DAB8F4ULL,
		0x8C9BD82287221D6CULL,
		0x7F002022BF4F4C6BULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x728C3021F20733B8ULL,
		0xD0290951CF0C46EEULL,
		0x0F71DA5FE31A8DABULL,
		0x3103572FFB0EC3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40586F5985217A4ULL,
		0xCF08F76ED15E756EULL,
		0xB14C4BDE107F3BE3ULL,
		0x271347BEBE52C028ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E86A92C59B51C14ULL,
		0x012011E2FDADD17FULL,
		0x5E258E81D29B51C8ULL,
		0x09F00F713CBC03BEULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF9A05381C18BDF35ULL,
		0x576A1519494995DEULL,
		0xFFC9AD1654E781D8ULL,
		0x045F0C4A6916A6E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x208AF8273839E725ULL,
		0x588E3527B17D8936ULL,
		0x56F39A2959822861ULL,
		0x61506F144BD83B08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9155B5A8951F7FDULL,
		0xFEDBDFF197CC0CA8ULL,
		0xA8D612ECFB655976ULL,
		0x230E9D361D3E6BDDULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x127F9A0A5584179AULL,
		0x822152EBF9ACF01AULL,
		0x4C40734779E5C44CULL,
		0x621A06D6BD831E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E2FE2D305E7B23ULL,
		0x8C767A27754D0B26ULL,
		0x3AA529E766C0930AULL,
		0x239A90E88AFC5D22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF9C9BDD25259C77ULL,
		0xF5AAD8C4845FE4F3ULL,
		0x119B496013253141ULL,
		0x3E7F75EE3286C0E6ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0CC09973854E842FULL,
		0xA47F23FAF0ACBED1ULL,
		0x55F0501CD12AD9E0ULL,
		0x0313DC7E5AC9651DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA14450B96297539ULL,
		0x0A34FA2717F00D11ULL,
		0xEA06C1A24D8052E6ULL,
		0x433C9603BBF91673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12AC5467EF250EE3ULL,
		0x9A4A29D3D8BCB1BFULL,
		0x6BE98E7A83AA86FAULL,
		0x3FD7467A9ED04EA9ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE3F7EA652C490461ULL,
		0x042C3F1787C69C35ULL,
		0xA61B624CB1DB39D5ULL,
		0x154E1C7C0C692715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102F759948002107ULL,
		0xC133C1953C77F61AULL,
		0xBE599AD8E1415C88ULL,
		0x5BD7E87EDA596753ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C874CBE448E347ULL,
		0x42F87D824B4EA61BULL,
		0xE7C1C773D099DD4CULL,
		0x397633FD320FBFC1ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4B72E9DBE7D005E4ULL,
		0x06E00247DB8EAA4CULL,
		0x5C4BF2FF18EC5122ULL,
		0x7F9C7F0EC14943AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16D154B44E73CA00ULL,
		0x63C610A49BB14778ULL,
		0x533D7045DEB5CD5FULL,
		0x76D686BA21AB50ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34A19527995C3BE4ULL,
		0xA319F1A33FDD62D4ULL,
		0x090E82B93A3683C2ULL,
		0x08C5F8549F9DF2C2ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0C056CF01A710E8FULL,
		0xD3BFBC99AAE8B62BULL,
		0x3CE39D9197F710BEULL,
		0x43F7842733B4894FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D8FB68EB3B2B52ULL,
		0xE9B64406FBEF3C61ULL,
		0x1DB1633F52D5316BULL,
		0x77DDB456A497B42FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A2C71872F35E32AULL,
		0xEA097892AEF979C9ULL,
		0x1F323A524521DF52ULL,
		0x4C19CFD08F1CD520ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6273C63C68DD7181ULL,
		0xEB075869FB1F6AA5ULL,
		0x22487AD179D4DE20ULL,
		0x4AEF54DA97FA577EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8305F767D5CDCFAULL,
		0x0B67CA558AAB9AB0ULL,
		0x19C4C50716275036ULL,
		0x0C7726D670D5F15FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA4366C5EB809487ULL,
		0xDF9F8E147073CFF4ULL,
		0x0883B5CA63AD8DEAULL,
		0x3E782E042724661FULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9482DDEC62ECB5B2ULL,
		0x4363C65A0156AF43ULL,
		0xE2C75344A0B7D850ULL,
		0x437B00FE6A3CB9FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E0BCF510756040ULL,
		0x7F23B4C793EBC806ULL,
		0x60B0B22878F1EE6EULL,
		0x1515BBED023D4DACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DA220F752775572ULL,
		0xC44011926D6AE73DULL,
		0x8216A11C27C5E9E1ULL,
		0x2E65451167FF6C50ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x747EB32D355BDC79ULL,
		0xB9CFC55D11A7ABC9ULL,
		0x7D32D129E4B7DBFAULL,
		0x3913E14C0175E60EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D978ADA30E305EDULL,
		0xD294F6FCD9D5B67BULL,
		0xDCC86075B49771A3ULL,
		0x61C111577EB09B43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6E728530478D679ULL,
		0xE73ACE6037D1F54DULL,
		0xA06A70B430206A56ULL,
		0x5752CFF482C54ACAULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xAEFF5ED2778D6FF2ULL,
		0x379D177E77FA835EULL,
		0xDA7CC1FCAF8FC6E9ULL,
		0x16B2F3355DBBF6DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B505CC339629D98ULL,
		0xE580431848A17D8BULL,
		0x0B832CA2504AA3B7ULL,
		0x5DD42A86C068BE03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53AF020F3E2AD247ULL,
		0x521CD4662F5905D3ULL,
		0xCEF9955A5F452331ULL,
		0x38DEC8AE9D5338DAULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2E49AFADFE8A474BULL,
		0xA4F5592E477662E1ULL,
		0x3D3CC3784A93091DULL,
		0x59443C13CA53D8D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD29FDF92265EAE39ULL,
		0x9748611F04FBD09DULL,
		0xC9918F97527C0F93ULL,
		0x4529613FFC191610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BA9D01BD82B9912ULL,
		0x0DACF80F427A9243ULL,
		0x73AB33E0F816F98AULL,
		0x141ADAD3CE3AC2C2ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC0725D8E1BABD19BULL,
		0x4DF9C6D456ED1F50ULL,
		0x06ABFCBB6DAD36DDULL,
		0x2D16FA82637EBE54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB902FC678F7A957ULL,
		0x4B8E67D1860C2596ULL,
		0x35B622060C2F5B9FULL,
		0x1600CAB5BFEF04C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4E22DC7A2B42844ULL,
		0x026B5F02D0E0F9B9ULL,
		0xD0F5DAB5617DDB3EULL,
		0x17162FCCA38FB98AULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8E2EAF45A5F4D93BULL,
		0x79C4A8E3D485DAE1ULL,
		0xFF686D69797601E7ULL,
		0x3EA0C7D251356CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x301B91EAD77F4434ULL,
		0x70C26D669B8E453EULL,
		0xB8CB30D513770415ULL,
		0x7974B5AE3439FA4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E131D5ACE7594F4ULL,
		0x09023B7D38F795A3ULL,
		0x469D3C9465FEFDD2ULL,
		0x452C12241CFB7292ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x247540234A9B4F75ULL,
		0xD7E24822284B6FD8ULL,
		0xDBA22387100DBB60ULL,
		0x09D0A322059EE82BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C0D2C9802318780ULL,
		0x2A0714F9397D42BDULL,
		0x27D0CA9C4A82A62AULL,
		0x707183C310514C1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8868138B4869C7E2ULL,
		0xADDB3328EECE2D1AULL,
		0xB3D158EAC58B1536ULL,
		0x195F1F5EF54D9C11ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xAA21DB65F77C0D21ULL,
		0xF5E5009934D377D6ULL,
		0xA323B2F8975017C9ULL,
		0x35AE7D733364F416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3B05BE95A88DF5ULL,
		0xAAFDBFED35DAC686ULL,
		0x092DCB7C4B26610CULL,
		0x7424967DFE031DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CE6D5A761D37F19ULL,
		0x4AE740ABFEF8B150ULL,
		0x99F5E77C4C29B6BDULL,
		0x4189E6F53561D661ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2B4482201A8CDBEEULL,
		0x31EACAF044AAD04AULL,
		0x1222CFEC55F0DA20ULL,
		0x351F118C6C7C1864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A2CA8EDCA96F70ULL,
		0x5621FACCD0B52EFAULL,
		0xAFCFA4F1DA458101ULL,
		0x55ABFDE8B6FD0FDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39A1B7913DE36C6BULL,
		0xDBC8D02373F5A14FULL,
		0x62532AFA7BAB591EULL,
		0x5F7313A3B57F0885ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x97848DB3E9F1BCA1ULL,
		0x7E3B5E5D36C83EF3ULL,
		0xFE8D0D1275CE2030ULL,
		0x3EE16AA5794C2E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD765AE65788CA7D5ULL,
		0xAADAC0B3EAB7C745ULL,
		0x900D7D42B3A7E678ULL,
		0x2D6B01ACA899FE4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01EDF4E716514CCULL,
		0xD3609DA94C1077ADULL,
		0x6E7F8FCFC22639B7ULL,
		0x117668F8D0B23042ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
	return 0;
}