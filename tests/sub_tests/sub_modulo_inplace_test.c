#include "../tests.h"

int32_t curve25519_key_sub_modulo_inplace_test(void) {
	printf("Inplace Modular Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x7C78C51B50D4706EULL,
		0xA674256B904D8330ULL,
		0xE80BC93619A43C6CULL,
		0x37304F0A14629CDAULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xC5306CC3F16692E3ULL,
		0x08F9DFB42890BA64ULL,
		0xA7B1AFE741D23FDBULL,
		0x4559570D4004452AULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xB74858575F6DDD78ULL,
		0x9D7A45B767BCC8CBULL,
		0x405A194ED7D1FC91ULL,
		0x71D6F7FCD45E57B0ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
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
		0xC44F7F030277C21BULL,
		0x7C2D865E95266AE2ULL,
		0xBE1A3DD3643030E9ULL,
		0x5B6CE9922BF3806BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975FA6C3CCC00ED4ULL,
		0x2EB2B44154B6E5DCULL,
		0xE517D1B43BC28613ULL,
		0x1391D4203A6C0A54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CEFD83F35B7B347ULL,
		0x4D7AD21D406F8506ULL,
		0xD9026C1F286DAAD6ULL,
		0x47DB1571F1877616ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9A136F9631183542ULL,
		0x83408519759D71F2ULL,
		0x079875F36C21AAD4ULL,
		0x0755ED17CB47AA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2CA998B03E67C8BULL,
		0x296E66183ED9AE89ULL,
		0x902DE550AE3B552BULL,
		0x5297866A23344837ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB748D60B2D31B8A4ULL,
		0x59D21F0136C3C368ULL,
		0x776A90A2BDE655A9ULL,
		0x34BE66ADA8136247ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x461AA67A8E45A392ULL,
		0xE883F95724DA156CULL,
		0xAEAE2E1FE55C1CA1ULL,
		0x564BBF00C73A4A75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3378D8928DF1EE3ULL,
		0x5C12406B80901749ULL,
		0x82DC0F65E643F684ULL,
		0x7DC541EE225ED102ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2E318F16566849CULL,
		0x8C71B8EBA449FE22ULL,
		0x2BD21EB9FF18261DULL,
		0x58867D12A4DB7973ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCD4D1860A227CC9DULL,
		0x8E488474DB7A847BULL,
		0xDBB0B9B55900BD2DULL,
		0x42B6FF698E53E55EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48614F31C9F206D4ULL,
		0xABF0F197016F180BULL,
		0x634CC76B17A748D3ULL,
		0x1C312E2B4818F278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84EBC92ED835C5C9ULL,
		0xE25792DDDA0B6C70ULL,
		0x7863F24A41597459ULL,
		0x2685D13E463AF2E6ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x79BDFA432331DA3DULL,
		0xB558CCF0050B8FFFULL,
		0x368BA547A8A44C40ULL,
		0x6D3571AEA966CA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C41A20D0251D84FULL,
		0x9B71A0AB20DDC0C5ULL,
		0xA76345C1D5DA4A34ULL,
		0x7BFB384D2E00BC7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D7C583620E001DBULL,
		0x19E72C44E42DCF3AULL,
		0x8F285F85D2CA020CULL,
		0x713A39617B660DCDULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7A85B6FC424A821CULL,
		0x6991C5CA0E8FDFB8ULL,
		0xCAB687C4E2064950ULL,
		0x0651DCBC5B10421BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745BEB4E6583A0B6ULL,
		0xCC875D60EFECC793ULL,
		0x67792D0DEFFB5D8DULL,
		0x64D416F61E7E75C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0629CBADDCC6E153ULL,
		0x9D0A68691EA31825ULL,
		0x633D5AB6F20AEBC2ULL,
		0x217DC5C63C91CC53ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7F4C7DC5B86E0169ULL,
		0x59CDAFA060BA1A75ULL,
		0x7E4987D7BF1EF9D1ULL,
		0x2F04828E7A73B054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BE89BC6826BAC51ULL,
		0xC8A1B2425847216EULL,
		0x5BEA1666B340B838ULL,
		0x39710EE1ED2B2A2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0363E1FF36025505ULL,
		0x912BFD5E0872F907ULL,
		0x225F71710BDE4198ULL,
		0x759373AC8D488627ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEC37201B0A53AF8EULL,
		0x13EF028B9619C68DULL,
		0xC42CB97783380058ULL,
		0x41D8C81FF73C9C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB23CD6698BA69FULL,
		0x7B7B1DFFAED0C4E3ULL,
		0x033FCE2A3DC4D61EULL,
		0x2A54D18F978A34ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C84E344A0C808EFULL,
		0x9873E48BE74901AAULL,
		0xC0ECEB4D45732A39ULL,
		0x1783F6905FB26762ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7269012037F533A0ULL,
		0x9FFBCC8503273AF4ULL,
		0x2100ADDC2B4AAAC3ULL,
		0x7EA227E085D0BED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85620523C0F0F0BFULL,
		0x2B722C0B54610116ULL,
		0x922CF4DA5C14E9A6ULL,
		0x14B783895D44D892ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED06FBFC770442E1ULL,
		0x7489A079AEC639DDULL,
		0x8ED3B901CF35C11DULL,
		0x69EAA457288BE641ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3B2D2F2009A937AAULL,
		0x233A304630C4B977ULL,
		0x94B2495E80A17653ULL,
		0x3876A5ECC3B56A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDA318027357674CULL,
		0xFE700CE9756F7839ULL,
		0x1B1F026B479A7369ULL,
		0x1FBBE4908A8365A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D8A171D9651D05EULL,
		0x24CA235CBB55413DULL,
		0x799346F3390702E9ULL,
		0x18BAC15C393204CAULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x01E54319978CCADEULL,
		0x8AD70EAF9A7DA170ULL,
		0x1C14ABA4F796221AULL,
		0x2F40F5237EC58AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A2C07E36281668ULL,
		0x22552A4FC658ACB8ULL,
		0xDA6878643FB99C45ULL,
		0x38D2129082CA9D57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B42829B6164B463ULL,
		0x6881E45FD424F4B7ULL,
		0x41AC3340B7DC85D5ULL,
		0x766EE292FBFAED7AULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x777A050D44E30FCFULL,
		0x7CEFAEE70A99F755ULL,
		0xD734476628998B02ULL,
		0x5289D975C5D0C3F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFDD2AAA0AF55701ULL,
		0x7A0BF0BA155F7F9BULL,
		0x38EB70E5FB514452ULL,
		0x715BB47DE2B9892CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x879CDA6339EDB8BBULL,
		0x02E3BE2CF53A77B9ULL,
		0x9E48D6802D4846B0ULL,
		0x612E24F7E3173AC7ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF52FB98026466783ULL,
		0x0712A74FB6B5F579ULL,
		0xD209B20D15981DE7ULL,
		0x125D81C6A8657D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB927A34A86865BD8ULL,
		0x8251FE608C304BC5ULL,
		0x549C577A701AB1CBULL,
		0x12CFD9B75AF04C7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C0816359FC00B98ULL,
		0x84C0A8EF2A85A9B4ULL,
		0x7D6D5A92A57D6C1BULL,
		0x7F8DA80F4D753117ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1EC40033B03B93B2ULL,
		0x8214430EBCE114A4ULL,
		0x22BBE0DA815F100CULL,
		0x2951F27491FE59EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE591594DEEB24CULL,
		0x9ABDB49DBE7BA0ACULL,
		0xD3F0666C584CF3B1ULL,
		0x0D2C7684EC74B4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52DE6EDA624CE166ULL,
		0xE7568E70FE6573F7ULL,
		0x4ECB7A6E29121C5AULL,
		0x1C257BEFA589A54AULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x72D8FA45087C2F24ULL,
		0x5A5A915FCB2DA812ULL,
		0xE910C90EC75992E7ULL,
		0x7B1AC1B9FED3CC76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5350A14FCC9C520ULL,
		0xABFDDC9E03387B0BULL,
		0x720F0290C830A206ULL,
		0x5EEED0B35F8EF72EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA3F0300BB26A04ULL,
		0xAE5CB4C1C7F52D06ULL,
		0x7701C67DFF28F0E0ULL,
		0x1C2BF1069F44D548ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA5A1EB4A6C0613EDULL,
		0x7E341D9EB2B14E93ULL,
		0x2F25D715E5EC4414ULL,
		0x2891AB3E2839DFD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBE5212D5E5A4FDULL,
		0xE28DF6F4E0F12A85ULL,
		0x81479D09002A1710ULL,
		0x45FFD800431D9A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9E3993796206EDDULL,
		0x9BA626A9D1C0240DULL,
		0xADDE3A0CE5C22D03ULL,
		0x6291D33DE51C45BBULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x01EB8446ED00F819ULL,
		0xC9EA8D60379AA9FEULL,
		0x500A1BF708CB47DDULL,
		0x0702FD790BB654E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA14E0528EAFB3657ULL,
		0x3496C705033E4A5BULL,
		0xB073778FC87E0C0DULL,
		0x6FC18C4F75E3614AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x609D7F1E0205C1AFULL,
		0x9553C65B345C5FA2ULL,
		0x9F96A467404D3BD0ULL,
		0x1741712995D2F39BULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9BA50B0376796387ULL,
		0xF044EEDF3DAF2BAAULL,
		0x6849E0DB4E38334EULL,
		0x0435ECB4C63DD04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70448279B4BF6B9CULL,
		0x4A5877A89238A86CULL,
		0xD018BF355F3D62F1ULL,
		0x5B52C0B8AE1C85CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B608889C1B9F7D8ULL,
		0xA5EC7736AB76833EULL,
		0x983121A5EEFAD05DULL,
		0x28E32BFC18214A80ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x56DE392373A1E234ULL,
		0x8A0CC7B5C99657FEULL,
		0x56D207D50DBAB7EAULL,
		0x6C8A612AABFECE9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B037F74132479EBULL,
		0x14D8B9B1B8206298ULL,
		0x8EACD4FEA0A14C6EULL,
		0x34C91FB6C2D1F364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBDAB9AF607D6849ULL,
		0x75340E041175F565ULL,
		0xC82532D66D196B7CULL,
		0x37C14173E92CDB3AULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x51120FE56C3EAB98ULL,
		0x2BE0B9DE265D7234ULL,
		0xF03FEFBEF237E685ULL,
		0x406BABBAD7B04FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3024B314F633E4E8ULL,
		0xDE00A0F06F5C440BULL,
		0xF91DA319D0BF3A73ULL,
		0x63CC03A7019D852DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20ED5CD0760AC69DULL,
		0x4DE018EDB7012E29ULL,
		0xF7224CA52178AC11ULL,
		0x5C9FA813D612CACCULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA22A281F6085C4AFULL,
		0xA4DCDC41A7633D45ULL,
		0x5B77E07280CAB6B7ULL,
		0x365561FD62FE6F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECB604B5468600D1ULL,
		0x8B5F141691884A5AULL,
		0x21F7DDF56768F26BULL,
		0x4BDD425B4245A1E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB574236A19FFC3CBULL,
		0x197DC82B15DAF2EAULL,
		0x3980027D1961C44CULL,
		0x6A781FA220B8CD91ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x39B26CCCA4E4EDAEULL,
		0xF5091DE2B044B8BDULL,
		0x56BD6F47C5F62B11ULL,
		0x41E47A26BC235F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5750583E41F2D1ULL,
		0xD335CA6FFB719FC8ULL,
		0xA2C27DA013104987ULL,
		0x63937DB9D4A8A8DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE5B1C7466A2FACAULL,
		0x21D35372B4D318F4ULL,
		0xB3FAF1A7B2E5E18AULL,
		0x5E50FC6CE77AB62FULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x62C223FF3D4227F0ULL,
		0x50ABE3A14B5C0BD3ULL,
		0xCBC295C581E7E03EULL,
		0x61EA4F24464AE973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801DB675DBB27D7AULL,
		0xFE218588724C5FB0ULL,
		0x834A9E5C7C1A5EC0ULL,
		0x077F592E1C378314ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2A46D89618FAA76ULL,
		0x528A5E18D90FAC22ULL,
		0x4877F76905CD817DULL,
		0x5A6AF5F62A13665FULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x68CCE6C973F06957ULL,
		0x82E9BEA4B87982B1ULL,
		0x9082046A79309C77ULL,
		0x291813B4018866F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C40A0F105D312BULL,
		0xCA04BA8C2DE3974EULL,
		0x5B175BFFE879B534ULL,
		0x6BA2A104871C92A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5808DCBA63933819ULL,
		0xB8E504188A95EB63ULL,
		0x356AA86A90B6E742ULL,
		0x3D7572AF7A6BD448ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x43C99968C16935D2ULL,
		0xF9AAA17BF1B51096ULL,
		0x8B81258F627E199CULL,
		0x38392DBE90C73FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C42683875E4180ULL,
		0xD6729E28C6767229ULL,
		0xEECAF3B2EBBE2117ULL,
		0x19A269260DE7F5CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x620572E53A0AF452ULL,
		0x233803532B3E9E6CULL,
		0x9CB631DC76BFF885ULL,
		0x1E96C49882DF49F5ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4A78AA2A6020DE4CULL,
		0x2E192F3786B62350ULL,
		0xA75C114CDDDA2C0EULL,
		0x55FB6DF01DD778BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A3C35A57A85141ULL,
		0x05DE75C7709793A7ULL,
		0x344A84D5FFB0AC19ULL,
		0x1755047A879F3FD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D4E6D008788D0BULL,
		0x283AB970161E8FA8ULL,
		0x73118C76DE297FF5ULL,
		0x3EA66975963838E9ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF57C85832E53F4E0ULL,
		0xE40254EF433EE155ULL,
		0x6DCFAAF6A8B68C15ULL,
		0x6B2610C6516BF926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F5F71D1E34CCA9ULL,
		0x8C0B74D56E0A1D5EULL,
		0x4B66C7BE89DCC741ULL,
		0x586418D4FADFCBB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C868E66101F2837ULL,
		0x57F6E019D534C3F7ULL,
		0x2268E3381ED9C4D4ULL,
		0x12C1F7F1568C2D6EULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE7E7CAA711CBEC4DULL,
		0xD44DE07779252E3CULL,
		0x2D18F4CA11AF985FULL,
		0x58CB4758FF54851DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAB52F0BBB8F8EE0ULL,
		0xB71A753D6551CA8CULL,
		0x180D5003AAA0682CULL,
		0x560D4E3B15602C0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D329B9B563C5D6DULL,
		0x1D336B3A13D363B0ULL,
		0x150BA4C6670F3033ULL,
		0x02BDF91DE9F45913ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x28D26D18CC11081DULL,
		0x4E4EB93553FA88B6ULL,
		0x691EB13081B75D57ULL,
		0x4470195A75E16BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62FA32092A042099ULL,
		0x56301D7A3CD62C9CULL,
		0x39B157CABF09CD3FULL,
		0x22B45488D0C3133AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D83B0FA20CE784ULL,
		0xF81E9BBB17245C19ULL,
		0x2F6D5965C2AD9017ULL,
		0x21BBC4D1A51E58B4ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x44AC2C6AD015E68EULL,
		0xF0B6439AD5D53249ULL,
		0xE0A6185B44D6F683ULL,
		0x44C46AB7DCA80650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9BAA6F2B2B2657ULL,
		0x5C4C44BFBBFC9BB3ULL,
		0xD24393C2F5915DD8ULL,
		0x040E678F531A3873ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x251081FBA4EAC037ULL,
		0x9469FEDB19D89696ULL,
		0x0E6284984F4598ABULL,
		0x40B60328898DCDDDULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4242A7E0D36815A2ULL,
		0x3E41BE2E380F9862ULL,
		0x444EC4DE04CA5E22ULL,
		0x255DF0620DCFE0ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x163C665EC0A89240ULL,
		0xCE360F66BA374D27ULL,
		0xE9668B52C24CC9C0ULL,
		0x26479661BD9D2010ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C06418212BF834FULL,
		0x700BAEC77DD84B3BULL,
		0x5AE8398B427D9461ULL,
		0x7F165A005032C09CULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF2049E11B718C61FULL,
		0x1BF4CBA0258ACB84ULL,
		0xF1FCDBC05E9F0162ULL,
		0x412C709667B3BDCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C66926DA22D1D4ULL,
		0x67D095042134D763ULL,
		0x52CE5D6A4EE934ABULL,
		0x52D6948CF264892BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB83E34EADCF5F438ULL,
		0xB424369C0455F421ULL,
		0x9F2E7E560FB5CCB6ULL,
		0x6E55DC09754F34A2ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1F2ED07B6593054CULL,
		0xE8093F69DE1F48ABULL,
		0x343F1A156EEED012ULL,
		0x6DE9B43FA60BCE7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8260767C4B840141ULL,
		0xC3F581AC11C88849ULL,
		0x5798F096BF2A585BULL,
		0x6462B3E1212E4A55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CCE59FF1A0F040BULL,
		0x2413BDBDCC56C061ULL,
		0xDCA6297EAFC477B7ULL,
		0x0987005E84DD8428ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC9596E7BD81AF9B7ULL,
		0x97341E9D8587C8DBULL,
		0xF5444F200394684BULL,
		0x2DB400A1C28667EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7155F00C1B2794ULL,
		0x12E8A631063FE75CULL,
		0xB4285725A478E79BULL,
		0x127370E3DA653A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9E8188BCBFFD223ULL,
		0x844B786C7F47E17FULL,
		0x411BF7FA5F1B80B0ULL,
		0x1B408FBDE8212DD2ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4E72E4E1B0509E3EULL,
		0xD31FB476699C7824ULL,
		0x3E5FC3809DC2729BULL,
		0x496953845C26BDA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD831C50934881752ULL,
		0xCD5A7A5163D5FE2CULL,
		0xD210EE6EFBF336ACULL,
		0x1270B517756B495DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76411FD87BC886ECULL,
		0x05C53A2505C679F7ULL,
		0x6C4ED511A1CF3BEFULL,
		0x36F89E6CE6BB744AULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAA2CCEF08C5D28B0ULL,
		0xDAA53F3D18BC3911ULL,
		0x8BBFC6115B65D17EULL,
		0x58D26B33737FE10EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F25C347B0BE3F1BULL,
		0x4A413562652C17D4ULL,
		0x5EC234458D8E309AULL,
		0x49E9C05A379904C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B070BA8DB9EE995ULL,
		0x906409DAB390213DULL,
		0x2CFD91CBCDD7A0E4ULL,
		0x0EE8AAD93BE6DC48ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x65774503D80154C4ULL,
		0x791CCD1772E8F4FCULL,
		0xF853812A89630B56ULL,
		0x2479DE3795729682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6047E2C73E500763ULL,
		0x4C911BE144533C74ULL,
		0x363E3E9959A84B88ULL,
		0x6F8FE183533D8BC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x052F623C99B14D4EULL,
		0x2C8BB1362E95B888ULL,
		0xC21542912FBABFCEULL,
		0x34E9FCB442350ABEULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2815B19EB95BF44ULL,
		0x04428ECEEA51E342ULL,
		0xF5D1869201B09E41ULL,
		0x4699832D5BA53782ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A84687074238792ULL,
		0x65E58B398B72F381ULL,
		0xC2EA5B9225B5055EULL,
		0x78DD6FE3B3065ED1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97FCF2A97772379FULL,
		0x9E5D03955EDEEFC1ULL,
		0x32E72AFFDBFB98E2ULL,
		0x4DBC1349A89ED8B1ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x764A15AC5E97C3A7ULL,
		0x43A8294DCE7046C2ULL,
		0xEEC1FE634B712FDCULL,
		0x298485F658C45C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2AF637E71F5A16FULL,
		0x4D542D15B698751AULL,
		0xACA3FF804DFB3B00ULL,
		0x038F0A583992323DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB39AB22DECA22238ULL,
		0xF653FC3817D7D1A7ULL,
		0x421DFEE2FD75F4DBULL,
		0x25F57B9E1F322A4DULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDE117B6F8C7B4816ULL,
		0x1F8C595CCD83E5C4ULL,
		0x5480D756657F48C8ULL,
		0x1C945EE5941ACB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41836F7E7C950BDULL,
		0x0183187AC8BE995EULL,
		0x1D5F4E3BDB21FC0BULL,
		0x30A03716F48055BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29F94477A4B1F746ULL,
		0x1E0940E204C54C66ULL,
		0x3721891A8A5D4CBDULL,
		0x6BF427CE9F9A755FULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4BF96A89B00A9085ULL,
		0x17C982218D62F51AULL,
		0x59D1D770922A5655ULL,
		0x33FF94C70D7D7D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317A5C7D6316959CULL,
		0xBC0D874383CCF954ULL,
		0x096BCD3222188482ULL,
		0x1B86031637899292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A7F0E0C4CF3FAE9ULL,
		0x5BBBFADE0995FBC6ULL,
		0x50660A3E7011D1D2ULL,
		0x187991B0D5F3EA86ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB274C33FA7690F0AULL,
		0x441896352E576C6AULL,
		0xCCD9A717799257A9ULL,
		0x74B6C7E34C29E2EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x649214531D2A7B77ULL,
		0xAB192862F594CB31ULL,
		0xC6E9CBE8213ABFC8ULL,
		0x5CCC723FD48FD757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DE2AEEC8A3E9393ULL,
		0x98FF6DD238C2A139ULL,
		0x05EFDB2F585797E0ULL,
		0x17EA55A3779A0B97ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4CCBBF3BFA6A449DULL,
		0x06AA164535705C97ULL,
		0xC91B7DEB6F3C4F0FULL,
		0x54748A704796ADA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD0D54A53B3AC06ULL,
		0x6A960FF6437DD8A5ULL,
		0x8BAF6CFDDCC5CB13ULL,
		0x20851FE4FF7BDA7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CFAE9F1A6B69897ULL,
		0x9C14064EF1F283F1ULL,
		0x3D6C10ED927683FBULL,
		0x33EF6A8B481AD326ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBA5616C81956A4E5ULL,
		0xE8D0367744517462ULL,
		0x0A8A515770FD3905ULL,
		0x2F6BFD713EC108FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681F26CDF3B3A350ULL,
		0x64145AAA5509B03FULL,
		0xE5767FA63833E480ULL,
		0x15650D225DCA1E0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5236EFFA25A30195ULL,
		0x84BBDBCCEF47C423ULL,
		0x2513D1B138C95485ULL,
		0x1A06F04EE0F6EAF0ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x87BBC796E8367C31ULL,
		0xC3D77D08D485F5FAULL,
		0x9CF28EF23D364F80ULL,
		0x7B5618AD5D53007EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790B9BA88348CF8DULL,
		0x3591209AD3946AB0ULL,
		0x32CD63F2DD730F6DULL,
		0x13776E21183E7DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EB02BEE64EDACA4ULL,
		0x8E465C6E00F18B4AULL,
		0x6A252AFF5FC34013ULL,
		0x67DEAA8C451482B9ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBE8BC0712502599CULL,
		0xBF6AAA9BE8EF0DE2ULL,
		0x22B6F8662E8C8118ULL,
		0x20A604F76D0DF379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4D6D0D85BA1C06ULL,
		0xCE92A699AA1CB2EFULL,
		0xC7E7CAED918E667AULL,
		0x2903A2660CDAC791ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x013E53639F483D83ULL,
		0xF0D804023ED25AF3ULL,
		0x5ACF2D789CFE1A9DULL,
		0x77A2629160332BE7ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBC97DE9BBA857A4DULL,
		0x86EDDD11BE3AC5C6ULL,
		0x56896A2E088059E7ULL,
		0x0CF00F6230589840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8930AFA0C225122ULL,
		0x0692D23A60CC5EA6ULL,
		0xF7C4E8ED35F370E3ULL,
		0x0B582A607FA197B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD404D3A1AE63292BULL,
		0x805B0AD75D6E671FULL,
		0x5EC48140D28CE904ULL,
		0x0197E501B0B7008BULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAF22D988F045EE75ULL,
		0x910B9FA8B3E6DA34ULL,
		0xD8E22D1B1C53B9BEULL,
		0x71E8309C1478E723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016809DBA2297419ULL,
		0x54D4936A4477E933ULL,
		0xD4C7E4C323D4D7F8ULL,
		0x15812C5B3DB582FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADBACFAD4E1C7A5CULL,
		0x3C370C3E6F6EF101ULL,
		0x041A4857F87EE1C6ULL,
		0x5C670440D6C36426ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0BF1D01319DEB480ULL,
		0x95DBD5FDDF5C5FECULL,
		0x74E30732EB6A3257ULL,
		0x6F557F8167AA80E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDDEBAAEC8D3E45FULL,
		0xD8B41CB7804C2537ULL,
		0x964420497F9892FCULL,
		0x3790EF693D72FA64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E131564510AD021ULL,
		0xBD27B9465F103AB4ULL,
		0xDE9EE6E96BD19F5AULL,
		0x37C490182A37867EULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2E8B10DB0365F6DDULL,
		0x36E6814548DD1131ULL,
		0x5EA69AE680B34F0EULL,
		0x40897AE392535EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA238D248F2BC0073ULL,
		0x5C2A852B0B84FA0BULL,
		0x03C209DD62E10F80ULL,
		0x241088466504DCA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C523E9210A9F66AULL,
		0xDABBFC1A3D581725ULL,
		0x5AE491091DD23F8DULL,
		0x1C78F29D2D4E8211ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5281BBB96E99210DULL,
		0x6C64F04F55036A8EULL,
		0x70C659BDC69D5C6CULL,
		0x415587B24798A4D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E9E7CBF1A07ECBULL,
		0xE60478CF7955E729ULL,
		0x73C05C98EAC56AC8ULL,
		0x40555E7E5E5926CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D97D3ED7CF8A242ULL,
		0x8660777FDBAD8365ULL,
		0xFD05FD24DBD7F1A3ULL,
		0x01002933E93F7E04ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0468477B5669F429ULL,
		0x4EEC4F2635CE8496ULL,
		0x080B10915CCCB60DULL,
		0x2CF7646B34583420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA718F9C089B03FDEULL,
		0x00324879A2299D32ULL,
		0xC7B728990658BA60ULL,
		0x38B16CDE40313DCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D4F4DBACCB9B438ULL,
		0x4EBA06AC93A4E763ULL,
		0x4053E7F85673FBADULL,
		0x7445F78CF426F651ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFFD66062E8F03255ULL,
		0x8CE45BE5D1AF34BAULL,
		0xC6BFCA724A3726C0ULL,
		0x127B04C5163AD839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01FEDA56023640BULL,
		0xA4938E5465B67363ULL,
		0xE5A56B4B7F7B4143ULL,
		0x080C85692FB35E8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FB672BD88CCCE4AULL,
		0xE850CD916BF8C157ULL,
		0xE11A5F26CABBE57CULL,
		0x0A6E7F5BE68779ADULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7D9D2F5B790C701BULL,
		0x51EBC2AAFBB5D2BBULL,
		0xC42A6ECFDDE952B4ULL,
		0x146DAD051EE64B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E22447F9E99D588ULL,
		0xC4B910F30A4A9822ULL,
		0x25E0C32F0FC9B3CAULL,
		0x7291CB1136DBE361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F7AEADBDA729A80ULL,
		0x8D32B1B7F16B3A99ULL,
		0x9E49ABA0CE1F9EE9ULL,
		0x21DBE1F3E80A6818ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4E02328D59FFB682ULL,
		0x1B202871F671D622ULL,
		0x49A48E09D56C9642ULL,
		0x1FC1DCED6CE508E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BE0E3DFAB3D2A9ULL,
		0x40C7D2659ED66D66ULL,
		0x819BFD254077CA92ULL,
		0x2CE9971D4B8AF694ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD44244F5F4BE3C6ULL,
		0xDA58560C579B68BBULL,
		0xC80890E494F4CBAFULL,
		0x72D845D0215A1252ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA5E8E00620ACDD14ULL,
		0xA46221B6059D1F9DULL,
		0x07DBB8859B414681ULL,
		0x3C8E295A7F982F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8919D3E855373E6BULL,
		0x27D36E5306D86321ULL,
		0x84B365E1C955D62BULL,
		0x76F3D886CD2372BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CCF0C1DCB759E96ULL,
		0x7C8EB362FEC4BC7CULL,
		0x832852A3D1EB7056ULL,
		0x459A50D3B274BCC5ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD9F05628B8493A35ULL,
		0xF5D1B24D3EAF1240ULL,
		0x0BB1060F28F54B10ULL,
		0x4A1D19DD1F316FF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13D8C6432C1B139FULL,
		0xC0707FE9E0922D1FULL,
		0x5709BA5DA4A2EECFULL,
		0x61122E08B8198C2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6178FE58C2E2683ULL,
		0x356132635E1CE521ULL,
		0xB4A74BB184525C41ULL,
		0x690AEBD46717E3CBULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF544AEF956E8BDAFULL,
		0x7D8D13D8DEF61F63ULL,
		0x2E89D1ADC9A73B44ULL,
		0x45696EA8FC90DB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1F73D7A28AC9A04ULL,
		0xF3BA00F16C4CB23BULL,
		0xCE65030C62F3FFD5ULL,
		0x15E1B27FF241C77DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x134D717F2E3C23ABULL,
		0x89D312E772A96D28ULL,
		0x6024CEA166B33B6EULL,
		0x2F87BC290A4F13ACULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF496C14882C2F692ULL,
		0x38007071C663FCB9ULL,
		0x18952B3C5A30556CULL,
		0x41033076F6E710DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B45925CADDFB877ULL,
		0x980F8ECC3E7A1E5EULL,
		0x393AC23E947DEE93ULL,
		0x10B90A483A787BCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9512EEBD4E33E1BULL,
		0x9FF0E1A587E9DE5BULL,
		0xDF5A68FDC5B266D8ULL,
		0x304A262EBC6E9512ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF4BD1CA2B7754796ULL,
		0x5B71D95E1EFBBF30ULL,
		0xA87957A43576C550ULL,
		0x538D265EAF5A10A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4540173F295B8151ULL,
		0x4D1817B6DA36443AULL,
		0x3D0233D4DB3EFE55ULL,
		0x6E3EEB54F15D383CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF7D05638E19C632ULL,
		0x0E59C1A744C57AF6ULL,
		0x6B7723CF5A37C6FBULL,
		0x654E3B09BDFCD867ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x54E1B2C9AF091CE2ULL,
		0xC5FD71D2B520E877ULL,
		0x0435A74E14EB71F0ULL,
		0x4A1D32E9DFCF1EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD52E7C15891C7AEULL,
		0x38E00A5EE920C1C7ULL,
		0x8948A2B5E3F9B3E1ULL,
		0x5A7F8219BA41EFA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x878ECB0856775521ULL,
		0x8D1D6773CC0026AFULL,
		0x7AED049830F1BE0FULL,
		0x6F9DB0D0258D2F55ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2E04CE5F8EE14F9DULL,
		0xF9573DD2CEDD8004ULL,
		0xC759A32BF67EF105ULL,
		0x6FEF351DB0B43CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81E996B1180C8FAULL,
		0x0C5ADBB03B452A7EULL,
		0xB247E7BAF2899EADULL,
		0x2108819303D52692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65E634F47D6086A3ULL,
		0xECFC622293985585ULL,
		0x1511BB7103F55258ULL,
		0x4EE6B38AACDF160FULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x69CA4875CF7075ADULL,
		0xDEA53D27029AC312ULL,
		0xA96380E38278F2D4ULL,
		0x1B1DD50DB429BDF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BC733D69C60AF7ULL,
		0x0C855A5FCB6413CBULL,
		0x1F24F7D3DB149C48ULL,
		0x0992A18555FE0B13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC30DD53865AA6AB6ULL,
		0xD21FE2C73736AF46ULL,
		0x8A3E890FA764568CULL,
		0x118B33885E2BB2E5ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2A59A05AA9615A84ULL,
		0x058297326CFBD27BULL,
		0x6E19C83A7A8D2AE4ULL,
		0x46D97B7FE2598CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C526C61AAD6D54ULL,
		0xFAD57395B8B8897CULL,
		0x2835D13596EFBB7DULL,
		0x4AC077AA5ABF37E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE99479948EB3ED1DULL,
		0x0AAD239CB44348FEULL,
		0x45E3F704E39D6F66ULL,
		0x7C1903D5879A551BULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBEF2F66BD17E9974ULL,
		0xB8FA44DE69380514ULL,
		0x28529A7ECA418504ULL,
		0x6C317C52E0E59BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F0101B3094C05E2ULL,
		0xF07D6A759A1E8738ULL,
		0xC08A9E0D050FFE91ULL,
		0x5E5BC55571504144ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FF1F4B8C8329392ULL,
		0xC87CDA68CF197DDCULL,
		0x67C7FC71C5318672ULL,
		0x0DD5B6FD6F955A9CULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEF95C3B830FEF083ULL,
		0x0E9EBD08AE30FF99ULL,
		0xFBC41CAAE19932CCULL,
		0x64B8995DFAAC46F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE077E20C9E4B9BA4ULL,
		0x1CB4F0D88007B17CULL,
		0xB3A70216EF4AF8A7ULL,
		0x0C077CD32923441BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F1DE1AB92B354DFULL,
		0xF1E9CC302E294E1DULL,
		0x481D1A93F24E3A24ULL,
		0x58B11C8AD18902D6ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x41214DB9AE264BAEULL,
		0x9E1F39BD433134C5ULL,
		0xD3888C1EC5597007ULL,
		0x5B19DB1CF9CE73D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D96473E1203C347ULL,
		0xCBC59BF9BB97CB4AULL,
		0x58403C37290160E2ULL,
		0x716DBB0A22BB7E02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x238B067B9C228854ULL,
		0xD2599DC38799697BULL,
		0x7B484FE79C580F24ULL,
		0x69AC2012D712F5D1ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDAE43DFAE0C2C5E0ULL,
		0xBC966629596F38ABULL,
		0x992854D76FED03BCULL,
		0x04B87023EE98F8D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BAC5337EB05905ULL,
		0x86003F6D260A9867ULL,
		0xE17CA4A3F799AF42ULL,
		0x79B67AEA49E824F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC62978C762126CC8ULL,
		0x369626BC3364A044ULL,
		0xB7ABB0337853547AULL,
		0x0B01F539A4B0D3DFULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x92ABD1AAA7AC8D6FULL,
		0xC2518E32DEAA674DULL,
		0xF96191DBBF950251ULL,
		0x5E0A235C35B6BADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA5D2D8467CCE32ULL,
		0xF3C198DDC3CEAB38ULL,
		0x526B901AA5E4550BULL,
		0x5DD6A8107AFE0BE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1305FED2612FBF3DULL,
		0xCE8FF5551ADBBC15ULL,
		0xA6F601C119B0AD45ULL,
		0x00337B4BBAB8AEFAULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2A2FAE7AC8924A3ULL,
		0x015FBEE0989C2F5FULL,
		0x77BF877AC1C917E1ULL,
		0x4BF3F727E8746620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F411C7EDF9E7A5ULL,
		0x2CE0FD0D70E8E9BFULL,
		0x3641957C4752D83FULL,
		0x749BFC3D68F10B2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BAEE91FBE8F3CEBULL,
		0xD47EC1D327B345A0ULL,
		0x417DF1FE7A763FA1ULL,
		0x5757FAEA7F835AF6ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2DB0C7249C32C3C0ULL,
		0xCEA7BDACAEB90833ULL,
		0x39513CA621C48373ULL,
		0x0ADB95361D72BD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC047AB75F0977EADULL,
		0x377BE28FCA7496F6ULL,
		0xB6FC0EDD0701B3D9ULL,
		0x28769EA7B1AF1FC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D691BAEAB9B4500ULL,
		0x972BDB1CE444713CULL,
		0x82552DC91AC2CF9AULL,
		0x6264F68E6BC39D88ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x561A9475438D6E00ULL,
		0x540D908202D919C6ULL,
		0x14E9765389977EC0ULL,
		0x27C2944482DD5FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC956CBFB790E599ULL,
		0xD98DD9C4D5AFE671ULL,
		0x280687A6F80F15BCULL,
		0x6F34F3F545056462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x798527B58BFC8854ULL,
		0x7A7FB6BD2D293354ULL,
		0xECE2EEAC91886903ULL,
		0x388DA04F3DD7FB44ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1D4C64E316556732ULL,
		0xC86BF9EF44EA3ADCULL,
		0x677E5BD0CD30CA59ULL,
		0x02DCF0D49FE13D6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x302CC6C660A3426EULL,
		0xECF0CE3E7DA8BB90ULL,
		0x936BB218EF1AB79CULL,
		0x1720BA9B9AFB198EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED1F9E1CB5B224B1ULL,
		0xDB7B2BB0C7417F4BULL,
		0xD412A9B7DE1612BCULL,
		0x6BBC363904E623E0ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA761882479AED4F8ULL,
		0x7EFBD2896EB2D9D2ULL,
		0x14FD35E815E23277ULL,
		0x2D25CB0A8EA82947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3633049C80DF1006ULL,
		0x4F2408E6EC7C99A8ULL,
		0x2042F164E00A6B98ULL,
		0x00F5F8AB1DFFDEC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x712E8387F8CFC4F2ULL,
		0x2FD7C9A28236402AULL,
		0xF4BA448335D7C6DFULL,
		0x2C2FD25F70A84A83ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6AD3998980EF871BULL,
		0xCF757B8A35531C45ULL,
		0x3E016017ED6C861CULL,
		0x6D392B1EF4C0E797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A9EE6074EC76D2ULL,
		0xE2F2BC8ACF49DCC5ULL,
		0xAD71C90ABC016266ULL,
		0x354FF367A0BB1811ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2829AB290C031049ULL,
		0xEC82BEFF66093F80ULL,
		0x908F970D316B23B5ULL,
		0x37E937B75405CF85ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8446858B722427C1ULL,
		0xF693849119CDAF5DULL,
		0xA5B9B6B2ACC27CF1ULL,
		0x1AFA2A0F48439243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE517E7791D2A8828ULL,
		0x963EBF64EE137509ULL,
		0x33A9870038CCF954ULL,
		0x06C9E11EDBB8CE31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F2E9E1254F99F99ULL,
		0x6054C52C2BBA3A53ULL,
		0x72102FB273F5839DULL,
		0x143048F06C8AC412ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF12D560E6A332C3BULL,
		0x8B9B02F63769632DULL,
		0x738FE26B08EE2106ULL,
		0x28BF31A820A9DB21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3D9A13B2887A8BULL,
		0xFB42849C0850FDB7ULL,
		0x8F733FC6AF5B0CD0ULL,
		0x5D6C8EC7C3C6A465ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94EFBBFAB7AAB19DULL,
		0x90587E5A2F186576ULL,
		0xE41CA2A459931435ULL,
		0x4B52A2E05CE336BBULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2D0CAF49B2C6D534ULL,
		0xF7D393A869BA19D5ULL,
		0x51E7F4A199FAEFD2ULL,
		0x40DA47E891907574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93A9B7DA0F3072AULL,
		0x6A9FF8E7F2795977ULL,
		0xE0E7B507E98B1B88ULL,
		0x3E4064D25E63166CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73D213CC11D3CE0AULL,
		0x8D339AC07740C05DULL,
		0x71003F99B06FD44AULL,
		0x0299E316332D5F07ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x466827CEB7D89D32ULL,
		0x2AAB9FD63AEE9C77ULL,
		0x051DB95A08C7A75DULL,
		0x1DB350549C921124ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x660C93A3B5E739E2ULL,
		0x571132B092A13E32ULL,
		0x50BF50542C3DE4CAULL,
		0x3A567B8DF0FDFF03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE05B942B01F1633DULL,
		0xD39A6D25A84D5E44ULL,
		0xB45E6905DC89C292ULL,
		0x635CD4C6AB941220ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC78EC21B1EAEFD36ULL,
		0xFE1EEF674764A17AULL,
		0x525A9B29D9D3BAE2ULL,
		0x3FAC37AD46CF6F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9116F0D65B93BF7ULL,
		0xF6FB13F6020BB198ULL,
		0x0C7AD492CC7856BBULL,
		0x78CA5A2F6C92B3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE7D530DB8F5C12CULL,
		0x0723DB714558EFE1ULL,
		0x45DFC6970D5B6427ULL,
		0x46E1DD7DDA3CBB16ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB462583D6A40FE8AULL,
		0x04CBC1CFF2E0997AULL,
		0x7DBB6FDCF57582FCULL,
		0x6B80996FAB8F683EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2391704081EC180ULL,
		0x00D828FB603B88CFULL,
		0x866D280EF9949797ULL,
		0x1BA255427D2D008CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE229413962223D0AULL,
		0x03F398D492A510AAULL,
		0xF74E47CDFBE0EB65ULL,
		0x4FDE442D2E6267B1ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF9ECE5BB9E002EAAULL,
		0x60EB2AEE0DD9F610ULL,
		0x8290943FA045188DULL,
		0x52EEE8091D00BDF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00503BDA8810DF0FULL,
		0xD8A087E7E2B8C283ULL,
		0x9FB1D8D2BF2D9814ULL,
		0x36AEE257AD63EF17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF99CA9E115EF4F9BULL,
		0x884AA3062B21338DULL,
		0xE2DEBB6CE1178078ULL,
		0x1C4005B16F9CCEDBULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB50221BDD35F541FULL,
		0xDF099821AE138CABULL,
		0x789BBCA67B5B9F6CULL,
		0x70DBB35CB0A3B452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8290EDA09C942643ULL,
		0x12EE0F500E797F57ULL,
		0xD7A4F79CAF7D0C1AULL,
		0x056A53361EBACE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3271341D36CB2DDCULL,
		0xCC1B88D19F9A0D54ULL,
		0xA0F6C509CBDE9352ULL,
		0x6B71602691E8E61AULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5EE0F64E82024B3CULL,
		0xFAA3003C058245BBULL,
		0x796A017E72972EC4ULL,
		0x42F0FDB25AEF6279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB1413B887DD7C9ULL,
		0xA641905AA14C06F7ULL,
		0xDD1D8FA7330F2210ULL,
		0x5E63C657066BBA98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x412FB512F9847360ULL,
		0x54616FE164363EC4ULL,
		0x9C4C71D73F880CB4ULL,
		0x648D375B5483A7E0ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC0BD3BDC364DE332ULL,
		0xA2A550B1D596E69EULL,
		0x7DDE113E7E33BB61ULL,
		0x3B04363E4903BFAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C9351851354759ULL,
		0xD24BA61FB4B0483BULL,
		0xA65F33260B0B212CULL,
		0x5A370A199286C32AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86F406C3E5189BC6ULL,
		0xD059AA9220E69E63ULL,
		0xD77EDE1873289A34ULL,
		0x60CD2C24B67CFC7FULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4697926138ED6D4FULL,
		0x1229D0EECED5A493ULL,
		0xBE07BC13917D7B6AULL,
		0x67D898D904328722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D199B15CBC23952ULL,
		0x119E3715FFD15B46ULL,
		0x1ECFD0CEBDDD8E2AULL,
		0x3783232465C10A45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE97DF74B6D2B33FDULL,
		0x008B99D8CF04494CULL,
		0x9F37EB44D39FED40ULL,
		0x305575B49E717CDDULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB4F0E7702D2FEFCCULL,
		0xEA317A9AD16B7917ULL,
		0x85F356C43A78DD36ULL,
		0x180F70500B733393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB021C30804E807C8ULL,
		0x28F58BF4F6CB9B3EULL,
		0xD56C3369A58B77D6ULL,
		0x478E357D866E3CC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04CF24682847E7F1ULL,
		0xC13BEEA5DA9FDDD9ULL,
		0xB087235A94ED6560ULL,
		0x50813AD28504F6CEULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC48CC387715DAF6BULL,
		0xCEB8FC263A829C3FULL,
		0x39DDE0CD4BDA3E8FULL,
		0x7C6BFBE07CD3B060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01109472DA09CDC3ULL,
		0x65EAFE0F9A01F70EULL,
		0x67E6589B57256A35ULL,
		0x68D4B66659FD7D56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC37C2F149753E1A8ULL,
		0x68CDFE16A080A531ULL,
		0xD1F78831F4B4D45AULL,
		0x1397457A22D63309ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7447D1E71B910E6CULL,
		0x01FB8D06AC8E7D82ULL,
		0x0A6E52956C73AF46ULL,
		0x030596E81A942E9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x344893402A5E29E3ULL,
		0xCC0F4A527F039B89ULL,
		0x13DBD1550F444584ULL,
		0x13DD54769C92B333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FFF3EA6F132E476ULL,
		0x35EC42B42D8AE1F9ULL,
		0xF69281405D2F69C1ULL,
		0x6F2842717E017B67ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6CD9E56EAA077B1BULL,
		0xCC873B05650AE75DULL,
		0x1265BBAE0C84E47DULL,
		0x20A19FC80DE7ED36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DE041AACDB5DD2ULL,
		0xE64C22B055A148FEULL,
		0x7223BEE9A978191FULL,
		0x53338AFBCFC9F3A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4FBE153FD2C1D36ULL,
		0xE63B18550F699E5EULL,
		0xA041FCC4630CCB5DULL,
		0x4D6E14CC3E1DF990ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xADDCCE1AFD9DB010ULL,
		0x44AFEFCA7288F700ULL,
		0xD00A0BEE67CCFE3FULL,
		0x43CA81953B37CCF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF63E8D1130729B17ULL,
		0x6A6CB97335212FB5ULL,
		0x99323F8E6BFE9310ULL,
		0x3BA6C0D215E9F786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB79E4109CD2B14F9ULL,
		0xDA4336573D67C74AULL,
		0x36D7CC5FFBCE6B2EULL,
		0x0823C0C3254DD570ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x76BD1D13C06F461DULL,
		0x2FDB8C5CB4A64892ULL,
		0xFDEFCA92535BCD3BULL,
		0x72216BE5A73A337FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x000FB0DD56B7A880ULL,
		0xC9F1B764363FD5E9ULL,
		0x67F67A2E9AB0320EULL,
		0x7E8CE82CC6F1C8C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76AD6C3669B79D8AULL,
		0x65E9D4F87E6672A9ULL,
		0x95F95063B8AB9B2CULL,
		0x739483B8E0486AB6ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0B5935C0162C1DBEULL,
		0xEA4549324C31A726ULL,
		0x57A0440D33599169ULL,
		0x41DF78B2BDFA6B8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26BE8BBE4CF9DD2BULL,
		0xD5B020A2CACAA024ULL,
		0x9C1BDF3705040EC3ULL,
		0x38D8D9848044B1FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE49AAA01C9324093ULL,
		0x1495288F81670701ULL,
		0xBB8464D62E5582A6ULL,
		0x09069F2E3DB5B98DULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x491D9C6D20B0E8EBULL,
		0x082CCD5AD57F8E12ULL,
		0xD9637A94D1E944FBULL,
		0x42EB93F82B4687B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13524BCEE45C7068ULL,
		0x1651CB99EEE5229CULL,
		0x353BD3EFB03EEF27ULL,
		0x56DCA20401630C8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35CB509E3C547870ULL,
		0xF1DB01C0E69A6B76ULL,
		0xA427A6A521AA55D3ULL,
		0x6C0EF1F429E37B2CULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF32A27F9F0B9D22FULL,
		0xE5EC59F4529F8824ULL,
		0x8F6D87AA7CE61F2CULL,
		0x31796335E2870269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E09B09D2CE13FA7ULL,
		0xD256CDE47C0F93D6ULL,
		0x54D98CC719D196D8ULL,
		0x73E136D92CC248A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA520775CC3D89275ULL,
		0x13958C0FD68FF44EULL,
		0x3A93FAE363148854ULL,
		0x3D982C5CB5C4B9C0ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2707157A961FDC84ULL,
		0x6C7BDBE22BEB27C5ULL,
		0x20889090A25469E4ULL,
		0x1A794B475234223DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB00225A767F61435ULL,
		0x7098DB1E4BE994F2ULL,
		0x339D2EDC2D0C77CBULL,
		0x77F90E226BA0A101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7704EFD32E29C83CULL,
		0xFBE300C3E00192D2ULL,
		0xECEB61B47547F218ULL,
		0x22803D24E693813BULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBF701F35C103EEAAULL,
		0x9417A8086591A94CULL,
		0xCD2AE7E2B225ECB3ULL,
		0x57EB20DEF24C8540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA7BB07F9B17FC2ULL,
		0x4E4D9901C3D98453ULL,
		0x074AD9AD521891C1ULL,
		0x5073A5016267A931ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFC8642DC7526EE8ULL,
		0x45CA0F06A1B824F8ULL,
		0xC5E00E35600D5AF2ULL,
		0x07777BDD8FE4DC0FULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x64BE8B2F38448B12ULL,
		0xBFADC8EECE64628DULL,
		0x0C728875F9B42D57ULL,
		0x6F47757996EF86B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D62077A6FCBC9D0ULL,
		0x8FD787D3A7A3D408ULL,
		0xE4F2AD7BE00DD125ULL,
		0x53606AA75DC9E542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x375C83B4C878C142ULL,
		0x2FD6411B26C08E85ULL,
		0x277FDAFA19A65C32ULL,
		0x1BE70AD23925A171ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7F5A8C5A19626F51ULL,
		0x93C25A733C0EACC4ULL,
		0x8D3B45069270287BULL,
		0x63F2ED1B9346C8D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFEDB28A002F34B5ULL,
		0x3D6C1C82F923CD86ULL,
		0x104EDBF1FEF73F9DULL,
		0x4B011EA1A788D7C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF6CD9D019333A9CULL,
		0x56563DF042EADF3DULL,
		0x7CEC69149378E8DEULL,
		0x18F1CE79EBBDF115ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x47EC2C66D2BC74EFULL,
		0x6370F14D16676552ULL,
		0x1EB1450C7B62ABB4ULL,
		0x60E21A013B66430AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x646E767BB2A4058BULL,
		0x34DE73FE9F766808ULL,
		0x43DDF8996B6B1A73ULL,
		0x33FB373A7978C6EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE37DB5EB20186F64ULL,
		0x2E927D4E76F0FD49ULL,
		0xDAD34C730FF79141ULL,
		0x2CE6E2C6C1ED7C1AULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1174573859170331ULL,
		0x79416D5350560F9BULL,
		0xE19F892520C6C30AULL,
		0x34F6BC586FA23044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x222777183EC8A208ULL,
		0x88420111B37ECA16ULL,
		0x207804613077BB01ULL,
		0x30FD9561FBE87AD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF4CE0201A4E6129ULL,
		0xF0FF6C419CD74584ULL,
		0xC12784C3F04F0808ULL,
		0x03F926F673B9B572ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDB39F202E14836B6ULL,
		0x07861E31FDA79F30ULL,
		0xC65D82B818FB2D07ULL,
		0x0403D53ADDE9A4DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBA293AECEDDC5BULL,
		0x101F7E7A7BE9DE76ULL,
		0x6B75DD6592F6CC06ULL,
		0x12B8D63CDFA3C92DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE7FC8C7F45A5A48ULL,
		0xF7669FB781BDC0BAULL,
		0x5AE7A55286046100ULL,
		0x714AFEFDFE45DBB1ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBAB4052FCA4E42F1ULL,
		0x5D116166A2F1FB46ULL,
		0x0A9BB771DCD1AA55ULL,
		0x7CC5B61DB4A50575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AC17BCD3F63714ULL,
		0x93652C07587D6EA6ULL,
		0x4A1AA2E1EDFBD1F9ULL,
		0x18147B4F78ACC43EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD807ED72F6580BDDULL,
		0xC9AC355F4A748C9FULL,
		0xC081148FEED5D85BULL,
		0x64B13ACE3BF84136ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB8D73446B17DC0D7ULL,
		0x2332E79C6095909DULL,
		0x7764462A1F8F7C47ULL,
		0x2C1F8A95C5C2CF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE25CCD94526CEE1ULL,
		0x889ADFAB6858EB0AULL,
		0xC817051B3B6051E2ULL,
		0x4E7B9A7123262F02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAB1676D6C56F1E3ULL,
		0x9A9807F0F83CA592ULL,
		0xAF4D410EE42F2A64ULL,
		0x5DA3F024A29CA078ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB66377CC14C66E3EULL,
		0xDD2B0A05B12831A3ULL,
		0x62170EC3066AC11AULL,
		0x0F84CFA5CE1874D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB1688499A08056FULL,
		0xAD7AA0AFEA8DAD7EULL,
		0x7A76AF89009DEF4FULL,
		0x6731A4AA048979A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B4CEF827ABE68BCULL,
		0x2FB06955C69A8425ULL,
		0xE7A05F3A05CCD1CBULL,
		0x28532AFBC98EFB33ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x83FEB50EA8031433ULL,
		0x8ECF814A0FF89B11ULL,
		0x0274FEBF0B66631BULL,
		0x7683766E22190D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02095AE97771190ULL,
		0x4D5D33466EE9D853ULL,
		0x965CBAEE09EB5B3EULL,
		0x5C4E200F047323ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3DE1F60108C02A3ULL,
		0x41724E03A10EC2BDULL,
		0x6C1843D1017B07DDULL,
		0x1A35565F1DA5E954ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x526F93DF4849D1FCULL,
		0xC71E414D2BCB6DB2ULL,
		0x3B8E72F9C8F83926ULL,
		0x3754C645A78FC6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107E515EB2CFED64ULL,
		0x9FB3DCD1A463A2A2ULL,
		0x59C04B28A5800D46ULL,
		0x0D97737C2C923D69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41F142809579E498ULL,
		0x276A647B8767CB10ULL,
		0xE1CE27D123782BE0ULL,
		0x29BD52C97AFD8965ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x61E0B8252DF649CCULL,
		0xC3452BFFEE34EFA5ULL,
		0xF460914C9CE73E12ULL,
		0x01CC5664824B0565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2363989A9297E2B1ULL,
		0x70F077FA24325118ULL,
		0x6D467C19F8F79367ULL,
		0x55043D30369E3011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E7D1F8A9B5E6708ULL,
		0x5254B405CA029E8DULL,
		0x871A1532A3EFAAABULL,
		0x2CC819344BACD554ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD8B4B70A271452DDULL,
		0x82AECCD9DABC5387ULL,
		0xDB3D7C5BE0ED3E4BULL,
		0x1444DFA9C55632BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7DC31CC359961AULL,
		0x319A04FFED2C227AULL,
		0x46A5853EE7ADBACBULL,
		0x6CDE1DB4EF6083ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C36F3ED63BABCB0ULL,
		0x5114C7D9ED90310DULL,
		0x9497F71CF93F8380ULL,
		0x2766C1F4D5F5AF11ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x06BB96B964A423C8ULL,
		0xF297C0529009C861ULL,
		0x8632A13179DBA734ULL,
		0x60202D748D8E485FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2176541878001200ULL,
		0x57D53038DAF50DC5ULL,
		0xA99E7DFBA4ABBCF5ULL,
		0x4B0644072277A978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE54542A0ECA411C8ULL,
		0x9AC29019B514BA9BULL,
		0xDC942335D52FEA3FULL,
		0x1519E96D6B169EE6ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD7CA5EA3665427AAULL,
		0xBFEC834AEEFFAAE3ULL,
		0x0AE9491A9604D49CULL,
		0x31C2B53412F66F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6F0E45C2062D77ULL,
		0x04CE4DA6A9E17406ULL,
		0xE2848B1CE7F8674AULL,
		0x455225D61E76205AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D5B505DA44DFA20ULL,
		0xBB1E35A4451E36DDULL,
		0x2864BDFDAE0C6D52ULL,
		0x6C708F5DF4804EC8ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9F762F4F36C08817ULL,
		0xE7F3A535CBD11B53ULL,
		0x84FBF8A191C8B6B5ULL,
		0x28A970FA71A3AB9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F829C561E03291ULL,
		0x6E374E4B4DD09294ULL,
		0x13582AAEAC07DCC2ULL,
		0x5F199A27A539A601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD97E0589D4E05573ULL,
		0x79BC56EA7E0088BEULL,
		0x71A3CDF2E5C0D9F3ULL,
		0x498FD6D2CC6A059BULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF36DB254925F1D2EULL,
		0xEC422831B56D0D36ULL,
		0xDDE65DC148DED959ULL,
		0x0F83BB5F6AAF7180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0AA51FE4F3B6047ULL,
		0x2D59A7ECA13399FCULL,
		0x7CCCB86ADC7B8FD5ULL,
		0x7DBF51961BCE19A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22C360564323BCD4ULL,
		0xBEE880451439733AULL,
		0x6119A5566C634984ULL,
		0x11C469C94EE157D8ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x49BD0087D0924718ULL,
		0x2EEEB1D19C636FDBULL,
		0xF9543A0D0D04199EULL,
		0x05A8358D53E87143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F32091D7FAF92AEULL,
		0x6D6018F3FBE9A611ULL,
		0x786931590E3C5D0DULL,
		0x0BEC9ABFEACEA660ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A8AF76A50E2B457ULL,
		0xC18E98DDA079C9CAULL,
		0x80EB08B3FEC7BC90ULL,
		0x79BB9ACD6919CAE3ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8CFD66990F2A9D7CULL,
		0x8F5998642305A2DFULL,
		0xEA8BD5C539BFE7E4ULL,
		0x42ACC9FFFF9A56FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2876042FA34B898ULL,
		0x41CFBC471EBC1636ULL,
		0x226A52B5C3A9F20EULL,
		0x1F8B26659E27CDDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA76065614F5E4E4ULL,
		0x4D89DC1D04498CA8ULL,
		0xC821830F7615F5D6ULL,
		0x2321A39A6172891FULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x732BF259CEEDBBB9ULL,
		0xDFAA45C5FDBC1239ULL,
		0x6204E4D46F7C0057ULL,
		0x744CDC8E95A533F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6093BC9177F3F814ULL,
		0x3B16EEFC6B09A2DEULL,
		0x5B9FB921CBC59668ULL,
		0x710EC97A6F298D30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x129835C856F9C3A5ULL,
		0xA49356C992B26F5BULL,
		0x06652BB2A3B669EFULL,
		0x033E1314267BA6C3ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1C9AB4FEB79BB8DBULL,
		0x0CA7ABFBBFF61F41ULL,
		0xDE2588FB44C3FEDEULL,
		0x776752B3C29118E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x423E072E846D77EFULL,
		0xA85414D59E3A4F82ULL,
		0x9FF1A2BF2738ADC6ULL,
		0x360EAE666D1F76B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA5CADD0332E40ECULL,
		0x6453972621BBCFBEULL,
		0x3E33E63C1D8B5117ULL,
		0x4158A44D5571A231ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE942982341BC7B7EULL,
		0xFD208D3FA0E4E2CDULL,
		0x24549AAD3166EF64ULL,
		0x3B0F0EA31E770F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE440FF3ADFCD1DULL,
		0xCBBC9E83A79266CCULL,
		0x48849AEA3221B46CULL,
		0x013FF232C7B267A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C5E572406DCAE61ULL,
		0x3163EEBBF9527C01ULL,
		0xDBCFFFC2FF453AF8ULL,
		0x39CF1C7056C4A7ACULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7743BFC375C3FAEEULL,
		0x01675DD4446B3DCCULL,
		0x0EB1ADDCF9896E29ULL,
		0x155181587829FBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0F9E362FC9DF785ULL,
		0x7E9A9290E67372FCULL,
		0x8817D03F18A2AE62ULL,
		0x1D7356CE1C9A9B99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9649DC6079260356ULL,
		0x82CCCB435DF7CACFULL,
		0x8699DD9DE0E6BFC6ULL,
		0x77DE2A8A5B8F6015ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5DA14D888CCEC1F5ULL,
		0x3ABBA70D8456B404ULL,
		0x968209618B50F6B5ULL,
		0x28B04BED8246926FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8CFE446E87C18FULL,
		0xDBEB2ACEF0CC52DBULL,
		0x9283EC23B7394DE2ULL,
		0x1E3EC7979FF393F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF144F441E470066ULL,
		0x5ED07C3E938A6128ULL,
		0x03FE1D3DD417A8D2ULL,
		0x0A718455E252FE7EULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDA7162162C3F5CDFULL,
		0x945E5BA26A8E81D5ULL,
		0x809AC3B60A6BDB53ULL,
		0x369A18FB8838D514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF098462342CDE4ULL,
		0x5B1C590A6C45F9A6ULL,
		0x3B3356915F4E25C4ULL,
		0x664C4C51E36BC919ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D80C9D008FC8EE8ULL,
		0x39420297FE48882FULL,
		0x45676D24AB1DB58FULL,
		0x504DCCA9A4CD0BFBULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAEFD72EC21719B73ULL,
		0x7387F20D6DC61110ULL,
		0x8614F05939A28A3CULL,
		0x3DEC4F63C3C2B4EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD145BF82BA8C703CULL,
		0x9C9FF6D861511376ULL,
		0xF1669188AF0B32B3ULL,
		0x5559E0D2C74BBF6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDB7B36966E52B24ULL,
		0xD6E7FB350C74FD99ULL,
		0x94AE5ED08A975788ULL,
		0x68926E90FC76F57FULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7BA315F3727376C2ULL,
		0xE550166235E29F43ULL,
		0x2623E641178AC257ULL,
		0x205449B80FA5D89CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x275CE1277137158EULL,
		0xF4A7CD059BA9A57EULL,
		0xD7F3B1CC20E1384BULL,
		0x5D1FB76857ED610CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x544634CC013C6121ULL,
		0xF0A8495C9A38F9C5ULL,
		0x4E303474F6A98A0BULL,
		0x4334924FB7B8778FULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2F778695A60AB178ULL,
		0x083CF3A55A057D47ULL,
		0x825262829D51526EULL,
		0x645C6CDF4EE52BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1704ECFFE8947FC0ULL,
		0x36EB3C84F21B34B5ULL,
		0x7F6617A432F7D1E0ULL,
		0x615794796A799419ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18729995BD7631B8ULL,
		0xD151B72067EA4892ULL,
		0x02EC4ADE6A59808DULL,
		0x0304D865E46B979FULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0EEBF505C9DB0041ULL,
		0xF072158D9C2382FCULL,
		0x6F0FC008038213B1ULL,
		0x1F0EA2F9FD79BAB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x757AE819A91B930FULL,
		0x68DDA23C5CC1CB4DULL,
		0x6D14A1E109AD804BULL,
		0x3AB6A39A46BCEB58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99710CEC20BF6D1FULL,
		0x879473513F61B7AEULL,
		0x01FB1E26F9D49366ULL,
		0x6457FF5FB6BCCF60ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x62D73DDD74C7DAAAULL,
		0xDCFCB34CE21F898EULL,
		0x79B9DEAEA223F7C6ULL,
		0x2A424F9942A7D6C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415F55E59F4E9C98ULL,
		0xF28A94FEEA4405ACULL,
		0xCBA71D2F8295E2CEULL,
		0x16139390E79A9EA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2177E7F7D5793E12ULL,
		0xEA721E4DF7DB83E2ULL,
		0xAE12C17F1F8E14F7ULL,
		0x142EBC085B0D3819ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x69BDD9AF4488BA41ULL,
		0xDFBBF1629E4F8DB6ULL,
		0x3CA3ADEFCA52B28FULL,
		0x623BB7B085BBFCB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7108B99F030AE3ULL,
		0x83869196DFD381B1ULL,
		0x1A58BFBB321EC42BULL,
		0x45890DED3DD2046EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B4CD0F5A585AF5EULL,
		0x5C355FCBBE7C0C04ULL,
		0x224AEE349833EE64ULL,
		0x1CB2A9C347E9F844ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4A392EC560B7B1C6ULL,
		0x0DD86BAE43E4C4BCULL,
		0x66F99DAB32CCE295ULL,
		0x11318760D5CBB905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B4E444738165207ULL,
		0xB308B7ED9121D847ULL,
		0xCBC210994E986E2FULL,
		0x014467D70F217D2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EEAEA7E28A15FBFULL,
		0x5ACFB3C0B2C2EC75ULL,
		0x9B378D11E4347465ULL,
		0x0FED1F89C6AA3BDAULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x42A4D6B5C833F676ULL,
		0x3B55B6D895BBE571ULL,
		0x5A8AAF12812F02FFULL,
		0x7D7354A5D986EB6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0258E59FF524C4CULL,
		0xDA98D953FD47761DULL,
		0x3535C93F23B96C34ULL,
		0x11A4FF092BA94405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x927F485BC8E1AA2AULL,
		0x60BCDD8498746F53ULL,
		0x2554E5D35D7596CAULL,
		0x6BCE559CADDDA765ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4A29E58C50AD45F2ULL,
		0x0F02893BC5D1228AULL,
		0x4A542757A99DA202ULL,
		0x44B521E048B64171ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E109D2039595A98ULL,
		0xAFCFD32C616AD033ULL,
		0xF0F8405C97F8FD2AULL,
		0x647602CCB72B862EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C19486C1753EB47ULL,
		0x5F32B60F64665257ULL,
		0x595BE6FB11A4A4D7ULL,
		0x603F1F13918ABB42ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5986FE86C863E5DCULL,
		0x60A538A283335EA0ULL,
		0x475AF53BAA62EEBDULL,
		0x1D02664E3621A2E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9EA26CD76609A4CULL,
		0x23D2A9AB1E2C1B24ULL,
		0x64FA2581FCAE98EAULL,
		0x10B3717D77430917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F9CD7B952034B90ULL,
		0x3CD28EF76507437BULL,
		0xE260CFB9ADB455D3ULL,
		0x0C4EF4D0BEDE99CDULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x82679FF39E87A9A0ULL,
		0xFC57D70EC0C3978DULL,
		0x5A723798AAABF96BULL,
		0x12690934C77C368AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C74A768C2000B1ULL,
		0xCC2797E250399A40ULL,
		0x4FE96DA58B4FA54DULL,
		0x5CEB37ED6B9CA1D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8A0557D1267A8DCULL,
		0x30303F2C7089FD4CULL,
		0x0A88C9F31F5C541EULL,
		0x357DD1475BDF94B8ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2629266D17FF97FBULL,
		0xBB98A404B907CFD4ULL,
		0xD1ACF2873DC6EF4DULL,
		0x1A77FAE0E86533FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85DFF449A1C6E50CULL,
		0x1032E53AE0CD8F30ULL,
		0x57AB392A0769E8DFULL,
		0x411796DFC62F7EEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA04932237638B2DCULL,
		0xAB65BEC9D83A40A3ULL,
		0x7A01B95D365D066EULL,
		0x596064012235B50FULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1B808197D05CA787ULL,
		0xE520FEC44F63A684ULL,
		0xA2A710DC0923B6D0ULL,
		0x5019533130D2AFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5182092264455EULL,
		0xA37613A59DAAB31AULL,
		0xEF86E5CC89E66F26ULL,
		0x58F9F769CB9E56CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x412EFF8EADF86216ULL,
		0x41AAEB1EB1B8F369ULL,
		0xB3202B0F7F3D47AAULL,
		0x771F5BC7653458E0ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4E46898AAC79B449ULL,
		0xD0113F2C738E0185ULL,
		0xA63750EA9B6B1289ULL,
		0x6EB561C9AD54B74CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407BF14955E76EB3ULL,
		0xFCEEE44BF9E204B9ULL,
		0x5700278AE5F5EA93ULL,
		0x3705E8230BD5B1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DCA984156924596ULL,
		0xD3225AE079ABFCCCULL,
		0x4F37295FB57527F5ULL,
		0x37AF79A6A17F0576ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9C8B06F51B3C8BEFULL,
		0xEC1744B78DF4D179ULL,
		0xB6AE2FE37577D313ULL,
		0x69026E359C64CF2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B8A7EE5981E902ULL,
		0xC36E886E240B7D9AULL,
		0x78F2A5CAE0903741ULL,
		0x02593BA6C5134D75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05D25F06C1BAA2EDULL,
		0x28A8BC4969E953DFULL,
		0x3DBB8A1894E79BD2ULL,
		0x66A9328ED75181B9ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3FFB39844299F48AULL,
		0x28ED25154B39A0C1ULL,
		0xC064126579B7FDCBULL,
		0x1808D56FB7C648DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FE63FA2750E88CULL,
		0x03DD619B02C96FC5ULL,
		0x47E6B23CCFD4A0E6ULL,
		0x4B8B4FA2E5CF1EE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45FCD58A1B490BEBULL,
		0x250FC37A487030FBULL,
		0x787D6028A9E35CE5ULL,
		0x4C7D85CCD1F729F1ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7E2B6B5E0DC7AF9AULL,
		0x20518F400B0CBD6DULL,
		0x1F551B907E7A31F2ULL,
		0x3B243965FB832930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB224FE7D7051279ULL,
		0x7AF0066D2E59D6BBULL,
		0x047AAB749B7E0DD9ULL,
		0x04B1CC5118718952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3091B7636C29D21ULL,
		0xA56188D2DCB2E6B1ULL,
		0x1ADA701BE2FC2418ULL,
		0x36726D14E3119FDEULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCF25C8A2B3B77F1EULL,
		0x7F54FB1D6FF9875AULL,
		0x3B66D9047D0CB5E5ULL,
		0x52619228559711A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC7DC4533DAABB24ULL,
		0x2391ECF050D39E2AULL,
		0x356BB13F51EF0C8BULL,
		0x376D84DF220C9923ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A8044F760CC3FAULL,
		0x5BC30E2D1F25E930ULL,
		0x05FB27C52B1DA95AULL,
		0x1AF40D49338A7885ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF3F37F0588AFC890ULL,
		0x7BDD05782C5E7F61ULL,
		0x6B75D702B3F081B5ULL,
		0x14A349CCFF3E8A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731F6CC37A8BF0A3ULL,
		0xC547C1C092F31075ULL,
		0x683FDA6FB5AB866EULL,
		0x7D17C6161D932617ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80D412420E23D7DAULL,
		0xB69543B7996B6EECULL,
		0x0335FC92FE44FB46ULL,
		0x178B83B6E1AB6437ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE562AF3D97A50C00ULL,
		0x08FC85C9296EC7A7ULL,
		0x52A21E5F70E26FAFULL,
		0x5B4819B0C2460080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB4E364905E66510ULL,
		0x8BA677577BB331ACULL,
		0x09068F6FBBC79608ULL,
		0x13B8E524FE010677ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A1478F491BEA6F0ULL,
		0x7D560E71ADBB95FBULL,
		0x499B8EEFB51AD9A6ULL,
		0x478F348BC444FA09ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD7E6AB9EFB70F2C3ULL,
		0x0972C80EF75992C8ULL,
		0x242E892939B1BD0CULL,
		0x7782AF388499C468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CB0559BFF0D9A2ULL,
		0x5530BE3EE96BDDD0ULL,
		0x3F50BB91462DE7A5ULL,
		0x33BB726AFECF0FF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF31BA6453B801921ULL,
		0xB44209D00DEDB4F7ULL,
		0xE4DDCD97F383D566ULL,
		0x43C73CCD85CAB477ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6E758D23B3E06A34ULL,
		0x695F0AEA9DF4961AULL,
		0x43275A5A836897FFULL,
		0x7FF8E6002219C18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8000BCC90AC3046ULL,
		0x80BC30AAEF32BAFAULL,
		0x1C3C0D6678EB6265ULL,
		0x7A8EDB775D66759BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76758157233439EEULL,
		0xE8A2DA3FAEC1DB1FULL,
		0x26EB4CF40A7D3599ULL,
		0x056A0A88C4B34BF0ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3780C0F2A79355CFULL,
		0x011811DFDBE222FFULL,
		0x244E984C74EB709FULL,
		0x15B8E5BD6E643309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3FDFD0D79D18ECCULL,
		0x32BA2280FD8E1616ULL,
		0xD08B950264114B63ULL,
		0x082F4906C7AB9B4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7382C3E52DC1C703ULL,
		0xCE5DEF5EDE540CE8ULL,
		0x53C3034A10DA253BULL,
		0x0D899CB6A6B897B9ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFA9CC0F4A61C9627ULL,
		0xFC38A8BE5B0A3566ULL,
		0x2C56A65A50CE8B45ULL,
		0x77485291BB0FCA2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02D2C3246B8C1214ULL,
		0x1B067CB7E2B0CDEAULL,
		0xDCA186FF7165F25BULL,
		0x1D41C8E509EF28E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7C9FDD03A908413ULL,
		0xE1322C067859677CULL,
		0x4FB51F5ADF6898EAULL,
		0x5A0689ACB120A14BULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7EA93D84C8FB497DULL,
		0xCEF5FC30C14B888FULL,
		0x5028D868FAE96E14ULL,
		0x0E0C6833A76C0541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0459803BCD752AULL,
		0x94A11D02E31FA5B7ULL,
		0x7B7E6FBE7D3101E7ULL,
		0x729F4368A0F7D5D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3A4E4048D2DD440ULL,
		0x3A54DF2DDE2BE2D7ULL,
		0xD4AA68AA7DB86C2DULL,
		0x1B6D24CB06742F6DULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4CBECA0EA82C313AULL,
		0x52C9B7B9480AF6C2ULL,
		0x2058F3F14B3E7E02ULL,
		0x27380FF8BC33AB25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5174E1FB246AC21EULL,
		0xEA5B75C6EDF3762BULL,
		0x8375E4852D73688FULL,
		0x67A0BCAA3AA6C7E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB49E81383C16F09ULL,
		0x686E41F25A178096ULL,
		0x9CE30F6C1DCB1572ULL,
		0x3F97534E818CE33DULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD361012A661FC970ULL,
		0xC5B1E87E6C212262ULL,
		0x79B7274D36390AB3ULL,
		0x6F9E6D190E9B403FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665ADAD10DF9F1CAULL,
		0xF492F973A6E59BCBULL,
		0x47BA31AD28467107ULL,
		0x228B7DB32C66E6A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D0626595825D7A6ULL,
		0xD11EEF0AC53B8697ULL,
		0x31FCF5A00DF299ABULL,
		0x4D12EF65E2345996ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16F0AF6070B9B914ULL,
		0x65760A2BD9FAE1DBULL,
		0xF4418DA198DAF133ULL,
		0x58FED1258B0C7E55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3720506DC69082FBULL,
		0xF87FDAFA1BE16A73ULL,
		0xB1C74A4B0C8E79F3ULL,
		0x489DFE4868130EDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFD05EF2AA293619ULL,
		0x6CF62F31BE197767ULL,
		0x427A43568C4C773FULL,
		0x1060D2DD22F96F77ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3898F5E2E7F49F29ULL,
		0xD684700626FDB645ULL,
		0xC5FF467D924A1DDCULL,
		0x124868278B5D40C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C37B38896CA00FULL,
		0x01CD2802BFDA7889ULL,
		0xB44ECEE19DFFB1A1ULL,
		0x6326E9F6A337BAB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1D57AAA5E87FF07ULL,
		0xD4B7480367233DBBULL,
		0x11B0779BF44A6C3BULL,
		0x2F217E30E825860EULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCB9893C4CB287CCFULL,
		0x3CAB6611FB22DBDCULL,
		0x7FEADE464F518CA1ULL,
		0x5404C2243B9FA8A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB367316A2F60A6FULL,
		0x16834FD97A65E3DEULL,
		0x7E2EC69BE65C6F2EULL,
		0x6B55795AE7CC0366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x106220AE2832724DULL,
		0x2628163880BCF7FEULL,
		0x01BC17AA68F51D73ULL,
		0x68AF48C953D3A53BULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6F689536FD135A06ULL,
		0x445B81D7CD320FDCULL,
		0x4799731D77E9A53BULL,
		0x305FDBFF43C09372ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF195D876D3295BDULL,
		0x3DFAE47C9D411F68ULL,
		0x26FF7AB665785B9DULL,
		0x0CAA7CB2B1065AE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC04F37AF8FE0C449ULL,
		0x06609D5B2FF0F073ULL,
		0x2099F8671271499EULL,
		0x23B55F4C92BA388DULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8FB21803840BEF55ULL,
		0xD6CDABA6C02498C1ULL,
		0x83AE179AD3140CCBULL,
		0x2868175E2FE1EC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE621E9F0DDC624CDULL,
		0x3EDEB40DF92E24A7ULL,
		0xEF72EB6BB98CEB07ULL,
		0x3B2784E13E44B6A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9902E12A645CA75ULL,
		0x97EEF798C6F67419ULL,
		0x943B2C2F198721C4ULL,
		0x6D40927CF19D35DBULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC27EA4F9067476BEULL,
		0x8535AA57A308E5D6ULL,
		0x6B5D3EECF35DF15DULL,
		0x7740239AD22BD3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x064CF89EA8538633ULL,
		0xEDC1D84A6AEBAD44ULL,
		0x0F0FF7E15A7EB705ULL,
		0x3975915E74633C8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC31AC5A5E20F08BULL,
		0x9773D20D381D3892ULL,
		0x5C4D470B98DF3A57ULL,
		0x3DCA923C5DC8975CULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF99D897622EBEE2DULL,
		0xBBB6BF89739C002AULL,
		0x4957A52D4047CD1EULL,
		0x389BD74574507A25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x037A3C88FE66EA74ULL,
		0x909742E4E0F0BE4BULL,
		0xAFE4260DB45A97EFULL,
		0x3F20C5A63D1A896DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6234CED248503A6ULL,
		0x2B1F7CA492AB41DFULL,
		0x99737F1F8BED352FULL,
		0x797B119F3735F0B7ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6F4717780E48762CULL,
		0xD14DA301473530EEULL,
		0xD60A3FFA6405D116ULL,
		0x1C61FB92991B1321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB803FE1B291EF16ULL,
		0xA34C8C89DB0D5E32ULL,
		0x8284F95DD343BADAULL,
		0x26775E78F3B68F2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83C6D7965BB68703ULL,
		0x2E0116776C27D2BBULL,
		0x5385469C90C2163CULL,
		0x75EA9D19A56483F4ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x88259F79DB05EF90ULL,
		0x87FE7BF831C9C344ULL,
		0xE5EBE8325E43A4F2ULL,
		0x6ECF05C3755885DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D56DA5123C1492ULL,
		0x98AFD741A5926AE5ULL,
		0x577BAFCC3B97BAC5ULL,
		0x074D33D02E110A36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E5031D4C8C9DAFEULL,
		0xEF4EA4B68C37585FULL,
		0x8E70386622ABEA2CULL,
		0x6781D1F347477BA5ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4433056C7D61E0F8ULL,
		0x38883FD64D861933ULL,
		0x8BEF8D6ECF69E0B9ULL,
		0x0EE7A2CDAC0E3CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32CFD993FE051670ULL,
		0x0FF502DC73850260ULL,
		0x999399C75D022F2FULL,
		0x35B71FE9C8EFD05CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11632BD87F5CCA75ULL,
		0x28933CF9DA0116D3ULL,
		0xF25BF3A77267B18AULL,
		0x593082E3E31E6C78ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB03CA862B771198CULL,
		0xAF94C606162F27DEULL,
		0xDCF470669EE00A82ULL,
		0x4CE9BD92C050D704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D404E47BD451D3ULL,
		0x6901ABA18B32CE95ULL,
		0xF6F033BCB0DEDE6FULL,
		0x3249C83144AD0F51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC768A37E3B9CC7B9ULL,
		0x46931A648AFC5948ULL,
		0xE6043CA9EE012C13ULL,
		0x1A9FF5617BA3C7B2ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6AD0F55EE6F102AEULL,
		0xB55CEAA7CFD9CE59ULL,
		0x3A2389582CF7E992ULL,
		0x3562A72500BA6504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68C28EB2436C465ULL,
		0xCBBF75C0B626C5D6ULL,
		0x5CE5F7214E1AF1A9ULL,
		0x18F898C29EE745F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB444CC73C2BA3E49ULL,
		0xE99D74E719B30882ULL,
		0xDD3D9236DEDCF7E8ULL,
		0x1C6A0E6261D31F11ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF219295178D16275ULL,
		0x7E58538DCCD7828CULL,
		0xFE17BD88DD2E26CDULL,
		0x6B9889EDF2BC6EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD176CC26B46376ULL,
		0x5E792C6201AAB363ULL,
		0x48D0947F4F41E4DEULL,
		0x67131687F8FEEAADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF247B285521CFEFFULL,
		0x1FDF272BCB2CCF28ULL,
		0xB54729098DEC41EFULL,
		0x04857365F9BD8434ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB3AB8079987A031EULL,
		0x4B4FEC932C4FF44AULL,
		0x51DCBDE7DA757182ULL,
		0x14F23E5395355080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDCD01690688A5B3ULL,
		0x4FDD45BACD7C94B7ULL,
		0xA2F1E83C2398D0F0ULL,
		0x1A17FD69207BF0D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5DE7F1091F15D58ULL,
		0xFB72A6D85ED35F92ULL,
		0xAEEAD5ABB6DCA091ULL,
		0x7ADA40EA74B95FA8ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x210F2190E9A38CA2ULL,
		0x6BD29C8FB2429C9DULL,
		0xDE0D892F2F9350FAULL,
		0x32276C01AF78624CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DFC838782342EFULL,
		0x08DBFFDD80D1C778ULL,
		0xAD9E816F2B93BB76ULL,
		0x30B6C226577F2E2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F2F5958718049B3ULL,
		0x62F69CB23170D524ULL,
		0x306F07C003FF9584ULL,
		0x0170A9DB57F93420ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6C08756B15F84092ULL,
		0x343E03455B0A8A25ULL,
		0x7410198DDC52A4BCULL,
		0x667D8C3577EF4641ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518570465BA36A89ULL,
		0x889A569105C36449ULL,
		0x2244EA1C6C5235CEULL,
		0x2FD7EF6F30691F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A830524BA54D609ULL,
		0xABA3ACB4554725DCULL,
		0x51CB2F7170006EEDULL,
		0x36A59CC647862711ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x001FFFFEC932CE56ULL,
		0x1E5D228F122CAB4DULL,
		0xFE4ED4BA07DBA5FDULL,
		0x3219BBD8C80A19FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F35021C68A115E0ULL,
		0xC34B1E8FD379579CULL,
		0xEB00C427AA16913DULL,
		0x21625390512F8038ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0EAFDE26091B876ULL,
		0x5B1203FF3EB353B0ULL,
		0x134E10925DC514BFULL,
		0x10B7684876DA99C5ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8AC7313F9F67BA73ULL,
		0xCBCE337C3D965BE5ULL,
		0x2160AF2621F04633ULL,
		0x17B2637CA136F7DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E90664484B8B107ULL,
		0xF1BEFFDF68F63DE7ULL,
		0x716E656E66918F7AULL,
		0x18761DA2F1CA8DBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C36CAFB1AAF0959ULL,
		0xDA0F339CD4A01DFEULL,
		0xAFF249B7BB5EB6B8ULL,
		0x7F3C45D9AF6C6A1BULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5FDD3A3147B1CC00ULL,
		0x551EA58360F79280ULL,
		0xCFA9B5906CFBC79BULL,
		0x1F3E99307D7C09DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D1A27FA1FAC34E3ULL,
		0x2C27B378179F3CF4ULL,
		0xBFDCB2EAD458CC1AULL,
		0x3CE3E4E24B15EB3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2C312372805970AULL,
		0x28F6F20B4958558BULL,
		0x0FCD02A598A2FB81ULL,
		0x625AB44E32661EA0ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9FE38E485C15A1CFULL,
		0xE3C126D5C32192EFULL,
		0xFC29FC5BD6AD9115ULL,
		0x3150BC120F32616AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51B238C346BEC09ULL,
		0x427CEF1CC384D158ULL,
		0x4DDBCF76C1A237DCULL,
		0x1C145A332FBE182CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAC86ABC27A9B5C6ULL,
		0xA14437B8FF9CC196ULL,
		0xAE4E2CE5150B5939ULL,
		0x153C61DEDF74493EULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF9FEEB9292626AB9ULL,
		0xBE1E34559CA534DEULL,
		0x6B5A7AB5FFCFE283ULL,
		0x7808A8ED0FCD1BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D0E3B8534CC7F9ULL,
		0x500A4DCC78AB0EE6ULL,
		0x4AF63838FC5C25F0ULL,
		0x5260C480060A2EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC32E07DA3F15A2C0ULL,
		0x6E13E68923FA25F8ULL,
		0x2064427D0373BC93ULL,
		0x25A7E46D09C2ECC6ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD287C1F57F63AAE9ULL,
		0x5DD829AF53124E2FULL,
		0xFA1EB152E7E48B2FULL,
		0x7520C3B5AA15DCD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF1D945CD1830A5ULL,
		0xFF4EFFC17E75E678ULL,
		0x54DA332D111A12D8ULL,
		0x1CB26E66250EB6B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD695E8AFB24B7A44ULL,
		0x5E8929EDD49C67B6ULL,
		0xA5447E25D6CA7856ULL,
		0x586E554F85072618ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC4C5C926765D435EULL,
		0xE2C858AE6D254928ULL,
		0xAB629304E302017BULL,
		0x657FF7A1942E4512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B0B10F34C94FCCULL,
		0x3346BA6EDE14C340ULL,
		0xB86B5D4162F934C8ULL,
		0x239D700C48A0B3A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B1518174193F392ULL,
		0xAF819E3F8F1085E8ULL,
		0xF2F735C38008CCB3ULL,
		0x41E287954B8D9171ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x190FB27B0F93A29FULL,
		0xD1A8639D47D37E06ULL,
		0x939FF307DA7BADC1ULL,
		0x0CBA3EFAC08B07E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2510A5D3976AF819ULL,
		0x6C05727B7E0B83EDULL,
		0x92D6114E8AA051E8ULL,
		0x4A5C1B89C7350268ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3FF0CA77828AA73ULL,
		0x65A2F121C9C7FA18ULL,
		0x00C9E1B94FDB5BD9ULL,
		0x425E2370F9560579ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x246CB19BC2B9643FULL,
		0x10E31B6DD8B1F327ULL,
		0xDF14D4D623F82DE9ULL,
		0x33A956F3434AF623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x822191A086466C8DULL,
		0x2A77C38E2ED4E4A1ULL,
		0x08EB207CCEBC4B28ULL,
		0x230295BAA5101DCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA24B1FFB3C72F7B2ULL,
		0xE66B57DFA9DD0E85ULL,
		0xD629B459553BE2C0ULL,
		0x10A6C1389E3AD855ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA936B64D3EB2BD28ULL,
		0x7D908A9F42D4ECCBULL,
		0xB6D26F1E8D0009D9ULL,
		0x4F71E95F2C82BDABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE956F07EFB1D18ULL,
		0xAA8D778BA3ABB32FULL,
		0x4ABC4BA15A4C1A7EULL,
		0x1D391EB80DEA1B6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD4D5F5CBFB7A010ULL,
		0xD30313139F29399BULL,
		0x6C16237D32B3EF5AULL,
		0x3238CAA71E98A23EULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEDB3F46C66453CB5ULL,
		0x8F91A902C01D5DA2ULL,
		0xF415002EA3CE2C00ULL,
		0x3A034D7E26CB979AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55820C2B3B63DDF5ULL,
		0x3DE71B45C6A0F3B9ULL,
		0x38A52F785AE0AAB2ULL,
		0x2A191BA0A25BC2F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9831E8412AE15EC0ULL,
		0x51AA8DBCF97C69E9ULL,
		0xBB6FD0B648ED814EULL,
		0x0FEA31DD846FD4A8ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6A8CE3BF387EDAB3ULL,
		0x75FF75708A26D3DDULL,
		0xD9649355B9035BA4ULL,
		0x547683E74EF53842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8981489F9998E074ULL,
		0xD016BD5D4F923474ULL,
		0x936F747EF528DABBULL,
		0x5B3BF06A2D1D76E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE10B9B1F9EE5FA2CULL,
		0xA5E8B8133A949F68ULL,
		0x45F51ED6C3DA80E8ULL,
		0x793A937D21D7C15FULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDAA6F83725D693E9ULL,
		0x82159854CE8D8BACULL,
		0xC9A0A8C44A215170ULL,
		0x7F70BED178EE2FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0E033354ECA2300ULL,
		0xCB5F3A330679593EULL,
		0xF0824D4B2300B13AULL,
		0x1DBC43C43EAC79BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39C6C501D70C70E9ULL,
		0xB6B65E21C814326EULL,
		0xD91E5B792720A035ULL,
		0x61B47B0D3A41B620ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5D0F1EAB3B6E21A6ULL,
		0xF72504F65F149BAAULL,
		0xA9602599F3B1B962ULL,
		0x39EC2E67591AF754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D61986DCC804859ULL,
		0x0175190DA98048C0ULL,
		0x5D4287F026145F99ULL,
		0x42652BA1E907DB74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FAD863D6EEDD93AULL,
		0xF5AFEBE8B59452EAULL,
		0x4C1D9DA9CD9D59C9ULL,
		0x778702C570131BE0ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1904E799D89EFC72ULL,
		0x1E67083B735A344BULL,
		0xD43B8048CAFA7E68ULL,
		0x653C4A0497AF8F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8444A835A5044D2ULL,
		0xE74877FCF3B982F1ULL,
		0xC3F36A8EE69AC047ULL,
		0x6879985B4526A77DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20C09D167E4EB78DULL,
		0x371E903E7FA0B159ULL,
		0x104815B9E45FBE20ULL,
		0x7CC2B1A95288E804ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x44884BE605008DE8ULL,
		0x65742DA6CE417623ULL,
		0x4121788080E6FE45ULL,
		0x1EA23A25DB286874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FAFC8009A65AA6ULL,
		0xDED567A04A13C602ULL,
		0x9E0E142B676FAA65ULL,
		0x5112DDACE9BD3CF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C8D4F65FB5A332FULL,
		0x869EC606842DB020ULL,
		0xA3136455197753DFULL,
		0x4D8F5C78F16B2B80ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x72093F41F8F9E4B1ULL,
		0x7F41438CD7395FD8ULL,
		0x51C23DEA882A475DULL,
		0x0CE96479CDD42B94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720199465189E1A4ULL,
		0xE6CBF81EAA57681AULL,
		0x7D288EB8B4837EFEULL,
		0x680B016B3C512927ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0007A5FBA77002FAULL,
		0x98754B6E2CE1F7BEULL,
		0xD499AF31D3A6C85EULL,
		0x24DE630E9183026CULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB096F4AF0EB3786EULL,
		0xE398BC8D76768610ULL,
		0xA00E0FE20211DDF4ULL,
		0x1CFFAD8D1AE5DCAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C4E48AE498F6FB0ULL,
		0x304EB3A6202F914FULL,
		0x3CDFEF6F86170E3BULL,
		0x386A56CBE0211528ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1448AC00C52408ABULL,
		0xB34A08E75646F4C1ULL,
		0x632E20727BFACFB9ULL,
		0x649556C13AC4C782ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x54962D259FF20CCFULL,
		0x15ACB4D82BB41B57ULL,
		0xDF3EC1399524CDCBULL,
		0x72B9EDB1BC96405EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x539D655F8A750DCEULL,
		0x03929674970158F1ULL,
		0x3C6A168DB23D5A13ULL,
		0x6F83CF472B9E87EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00F8C7C6157CFF01ULL,
		0x121A1E6394B2C266ULL,
		0xA2D4AAABE2E773B8ULL,
		0x03361E6A90F7B86FULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x69A1989A65D67819ULL,
		0xEFEB9CCF26FF2B36ULL,
		0xF08378F4CFC83488ULL,
		0x76DA6392FBA19219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2934D73BC9F3B861ULL,
		0x39D8FA1490EB2F35ULL,
		0x09A39F8865EC73E9ULL,
		0x52F0EA8884F94BB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x406CC15E9BE2BFB8ULL,
		0xB612A2BA9613FC01ULL,
		0xE6DFD96C69DBC09FULL,
		0x23E9790A76A84663ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0724771C66C7A73DULL,
		0x1840D90E8ED3EC78ULL,
		0x897A97BBCB3C6120ULL,
		0x7658359643E8393EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3981B0E18E2F204ULL,
		0x24AC197CDDF2985EULL,
		0xC53397B7F78FE670ULL,
		0x16F14812916DA98AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x138C5C0E4DE4B539ULL,
		0xF394BF91B0E15419ULL,
		0xC4470003D3AC7AAFULL,
		0x5F66ED83B27A8FB3ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD0BA028F2C9E7CBFULL,
		0xD32867CD3589E4CCULL,
		0xE4E569D6FA70AE97ULL,
		0x2BFD952204715870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE72A082BC264F42AULL,
		0x8DB8CECD1409EB7EULL,
		0x6034640C9401AAF2ULL,
		0x49F468997BB575B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE98FFA636A398882ULL,
		0x456F9900217FF94DULL,
		0x84B105CA666F03A5ULL,
		0x62092C8888BBE2BAULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2BF82827D912E5D9ULL,
		0x80274F0FA7655D87ULL,
		0xFE481F154AAAABF3ULL,
		0x3D01DE0D955EF9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C3F87142D0E3C4ULL,
		0xFABA0BB92D92D3DFULL,
		0xFEF61F3819BB42EEULL,
		0x650E0FDA7B21DC5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2342FB696420202ULL,
		0x856D435679D289A7ULL,
		0xFF51FFDD30EF6904ULL,
		0x57F3CE331A3D1D59ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC5E3F229FF1BA8BAULL,
		0x927E9CD994E33930ULL,
		0xC13DC7FA238D95B2ULL,
		0x4D611167C784465EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79081E4CB2EEDCDDULL,
		0xFA1235575840D2E8ULL,
		0x74C9ED535549178CULL,
		0x5169A64BD7A8B735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CDBD3DD4C2CCBCAULL,
		0x986C67823CA26648ULL,
		0x4C73DAA6CE447E25ULL,
		0x7BF76B1BEFDB8F29ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x855D4F74B3F37923ULL,
		0xDBA35EFC110A56A7ULL,
		0xB63020681803E748ULL,
		0x0D3B30AE1182A59CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10EBCC6D1F4962F4ULL,
		0xFF49121056640B56ULL,
		0x5C96010EFC612B2AULL,
		0x1EB454554406D52BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7471830794AA161CULL,
		0xDC5A4CEBBAA64B51ULL,
		0x599A1F591BA2BC1DULL,
		0x6E86DC58CD7BD071ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA577F4B3B1011500ULL,
		0x1E76B491CA82FBDBULL,
		0x940016F7E6F4CD7FULL,
		0x1147ADCCDC439884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B337B19D39E3EA2ULL,
		0x041D354087B90E68ULL,
		0x3253330E7EBF8891ULL,
		0x7F713A0C6F52A7C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A447999DD62D64BULL,
		0x1A597F5142C9ED73ULL,
		0x61ACE3E9683544EEULL,
		0x11D673C06CF0F0C2ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x523A5362D257CF22ULL,
		0xDF2861490B09E90FULL,
		0x0B359B833A1E6DA4ULL,
		0x276314D3E0B21309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C48AAEA70B3D8BCULL,
		0xDC99E37C0A77B691ULL,
		0x2DC494CADF1FF50EULL,
		0x38E24529AFAC68C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25F1A87861A3F653ULL,
		0x028E7DCD0092327EULL,
		0xDD7106B85AFE7896ULL,
		0x6E80CFAA3105AA45ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4FA40198FD27DF6FULL,
		0xE330DF7F5E726C34ULL,
		0x2980097243DBABAFULL,
		0x3BE7CFA99A124019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E36CAE9014CFBAEULL,
		0xE97F7A8BB1C2E878ULL,
		0x8CC5508A16922E43ULL,
		0x74E4E877E1DB397BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD16D36AFFBDAE3AEULL,
		0xF9B164F3ACAF83BBULL,
		0x9CBAB8E82D497D6BULL,
		0x4702E731B837069DULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF7232A3E9903302DULL,
		0x68ED834F1906493DULL,
		0x2BFE88D436FE52BAULL,
		0x3BB748A17F850FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830F2CD604A97CE3ULL,
		0x5BBB708840370B12ULL,
		0x677C5389603B9E0DULL,
		0x6B673868F31F08E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7413FD689459B337ULL,
		0x0D3212C6D8CF3E2BULL,
		0xC482354AD6C2B4ADULL,
		0x505010388C660704ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1B5C7A8CAE9E1B54ULL,
		0x3C5FD98C5803A5F7ULL,
		0x5C6D0D70AC102335ULL,
		0x3DD337F7CED3833EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7250D8C135367CAULL,
		0x930D3D0593599A7BULL,
		0xEFF951E4C2A85367ULL,
		0x63AC241961A1E183ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64376D009B4AB377ULL,
		0xA9529C86C4AA0B7BULL,
		0x6C73BB8BE967CFCDULL,
		0x5A2713DE6D31A1BAULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9FE00C7C6A07A750ULL,
		0x189C1D63FC479C99ULL,
		0x83FA7CD2AD15C4F3ULL,
		0x0FB91EA919AC41BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF352ACFE8DA1C3ULL,
		0xACC21973B7BCD948ULL,
		0x5E83A986184C922BULL,
		0x7E06ED8176D6FBE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2ECB9CF6B7A057AULL,
		0x6BDA03F0448AC350ULL,
		0x2576D34C94C932C7ULL,
		0x11B23127A2D545D9ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x43C29CD86183DE63ULL,
		0xEBED154111A8C689ULL,
		0xCCD9E5BDD14C8134ULL,
		0x68AC266A0071074FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC9480B6E9C0D08CULL,
		0xD9EC9995E2583211ULL,
		0x39CCAE27A8159C31ULL,
		0x3F3242EBA6B03FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x572E1C2177C30DD7ULL,
		0x12007BAB2F509477ULL,
		0x930D37962936E503ULL,
		0x2979E37E59C0C777ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB6BBC46E164E780EULL,
		0x122EBEBAAE84E3C3ULL,
		0x78D1A4AC39EEA4F1ULL,
		0x6497CC561DEDEE3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE93E48DF7EB6F0ULL,
		0xA42723AD465B2859ULL,
		0xB69F98659C0914E2ULL,
		0x471E3C3AF46FD680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88D2862536CFC11EULL,
		0x6E079B0D6829BB6AULL,
		0xC2320C469DE5900EULL,
		0x1D79901B297E17BAULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1F83FBCB92DA9331ULL,
		0x52E02FC9A08407FEULL,
		0x527CD4D7A997FFFAULL,
		0x2CBAB3C7FB12B3ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x689EF4BA00CF4FE2ULL,
		0xA9BF1817725AE202ULL,
		0x816C6DA04746CBA7ULL,
		0x2BD2996F8233FB36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6E50711920B434FULL,
		0xA92117B22E2925FBULL,
		0xD110673762513452ULL,
		0x00E81A5878DEB8B5ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1946DBCEB4166AD9ULL,
		0x94FAB66CF352DD18ULL,
		0xF356890C1A3E12FBULL,
		0x62C05830ACD1491DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B144AEEBC34C85FULL,
		0x58996F849DD91068ULL,
		0xD6411B5729410CFDULL,
		0x367AAD24D65092F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E3290DFF7E1A27AULL,
		0x3C6146E85579CCAFULL,
		0x1D156DB4F0FD05FEULL,
		0x2C45AB0BD680B629ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}