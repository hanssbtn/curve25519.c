#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x2B6E474728D6256DULL,
		0x9D95C1F2BC110851ULL,
		0x56661486A9206E8AULL,
		0x16E65B609BC73D3DULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x2581FE9F22E200F6ULL,
		0x93EF13240AA82B60ULL,
		0xF07ADACB2732DE34ULL,
		0x442FB1D7267A2CE6ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x05EC48A805F42464ULL,
		0x09A6AECEB168DCF1ULL,
		0x65EB39BB81ED9056ULL,
		0x52B6A989754D1056ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
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
		0xC9F60E4AE8B0FF15ULL,
		0xCD0D70FC92DA48B4ULL,
		0xA08E39FB3B332895ULL,
		0x251AA330481A888AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9EBD588CD74305CULL,
		0xC7D9A08DD17B476DULL,
		0x92139090A2905252ULL,
		0x29B5A16AE09D4B7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE00A38C21B3CCEA6ULL,
		0x0533D06EC15F0146ULL,
		0x0E7AA96A98A2D643ULL,
		0x7B6501C5677D3D0CULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2A003200D0EA0EB5ULL,
		0xDA1F122B4AA444CFULL,
		0x2E8C8C2EBA2192CFULL,
		0x0BF4FDA5B335B504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07479BF98B0FBFB7ULL,
		0xB525386D11D950B3ULL,
		0x6AD13143F321EFEDULL,
		0x3813620E7E0584BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22B8960745DA4EEBULL,
		0x24F9D9BE38CAF41CULL,
		0xC3BB5AEAC6FFA2E2ULL,
		0x53E19B9735303048ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x25055FB2ECC09941ULL,
		0x7A5B126741C85C72ULL,
		0x2E6430B35BA7A66EULL,
		0x01856E9EF25D09EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AFE441B1A06DDFULL,
		0x7409BF5AC15BA146ULL,
		0xA8D2E190CDF4C4E0ULL,
		0x72D11F797E39491DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23557B713B202B4FULL,
		0x0651530C806CBB2CULL,
		0x85914F228DB2E18EULL,
		0x0EB44F257423C0CCULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xCC2167F72DD48258ULL,
		0xA181F73A02985081ULL,
		0x88ED5D55F12DBC43ULL,
		0x782FA489533A2086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E10DA679860270ULL,
		0x543F79569819C4B3ULL,
		0x1A2F8B3365C8AA75ULL,
		0x74928D9F512C90CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89405A50B44E7FE8ULL,
		0x4D427DE36A7E8BCEULL,
		0x6EBDD2228B6511CEULL,
		0x039D16EA020D8FBAULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD3268D029ABF271AULL,
		0x4F4568139D7D3344ULL,
		0x7C21A2546F2702A8ULL,
		0x4C3F0A575544225BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26EB4CA309F9118DULL,
		0x1D130BE79B019A81ULL,
		0xEF35D9917914E961ULL,
		0x4B66591F9BE67D3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC3B405F90C6158DULL,
		0x32325C2C027B98C3ULL,
		0x8CEBC8C2F6121947ULL,
		0x00D8B137B95DA520ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x804B3AEE37495A73ULL,
		0xE5871ED7C2108149ULL,
		0x9CC2F29955A388CFULL,
		0x753C647E8399439CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299205DF613AB85FULL,
		0x4142ED52F074F9D6ULL,
		0xE96A276E9E2D2FB2ULL,
		0x51398561F42C494FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56B9350ED60EA214ULL,
		0xA4443184D19B8773ULL,
		0xB358CB2AB776591DULL,
		0x2402DF1C8F6CFA4CULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF8B32D203FE1DF74ULL,
		0x47C05A0A61BC9E99ULL,
		0x9B04028BE1BE3750ULL,
		0x4CEFBF885A09372EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21822450FE031481ULL,
		0x988D6E6E50990FFAULL,
		0x421AE924E1DF6433ULL,
		0x1091E7CC3E32ECD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD73108CF41DECAF3ULL,
		0xAF32EB9C11238E9FULL,
		0x58E91966FFDED31CULL,
		0x3C5DD7BC1BD64A55ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2A71C79E46A1DB66ULL,
		0xA78DA8CB2317B7A0ULL,
		0xB77DED00D4441E0BULL,
		0x46B314C959F49C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BA7D23FF2B9E23ULL,
		0x141CBF73D1A5CC34ULL,
		0x681DB764045AFE8FULL,
		0x7FDA301887EF0102ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78B74A7A47763D30ULL,
		0x9370E9575171EB6BULL,
		0x4F60359CCFE91F7CULL,
		0x46D8E4B0D2059B31ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE19F940569EA7B7CULL,
		0x714480FF26D02127ULL,
		0xA10C35BD4D9ECEBEULL,
		0x2DB95FD558147CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE23C81C48717B2ULL,
		0x672539EDAA6C874FULL,
		0x7044705263CA40E4ULL,
		0x729801DC9F9BC395ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56BD5783A56363B7ULL,
		0x0A1F47117C6399D8ULL,
		0x30C7C56AE9D48DDAULL,
		0x3B215DF8B878B90DULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6F7D27F6877C12FCULL,
		0x01D013C4E44ABA1CULL,
		0x1AD8F4E59E4A0176ULL,
		0x135648558B561138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DC2EC114812A681ULL,
		0xD9EF5FE9A75D4E91ULL,
		0xBCB456FE49DACCC3ULL,
		0x11B508AF6B06FC8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41BA3BE53F696C7BULL,
		0x27E0B3DB3CED6B8BULL,
		0x5E249DE7546F34B2ULL,
		0x01A13FA6204F14A8ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5C0B5F47ABCBDF73ULL,
		0x9D9515F0F682A46FULL,
		0x2D8E5D087719D65BULL,
		0x72FB9537D32F73ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9D52CDDEE73332ULL,
		0x79F2EA281BCE0923ULL,
		0xDBABD1925692368BULL,
		0x3DFC83C636EFA777ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD6E0C79CCE4AC41ULL,
		0x23A22BC8DAB49B4BULL,
		0x51E28B7620879FD0ULL,
		0x34FF11719C3FCC74ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2B63BA81569519FFULL,
		0xEB3D4B471F99600AULL,
		0x88DB5818809F2827ULL,
		0x5DF4684FFB5B8934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A84D8FD32EBEDAULL,
		0xB78EFD3C7E79E2B6ULL,
		0xF6E486AB59D6FBD6ULL,
		0x64A953064DAEF159ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33BB6CF183665B12ULL,
		0x33AE4E0AA11F7D53ULL,
		0x91F6D16D26C82C51ULL,
		0x794B1549ADAC97DAULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x85A142C0D54D96C4ULL,
		0x06CA2F963874B03BULL,
		0x7A20BAF0A9773845ULL,
		0x6DA0BE0DA901EF94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165E189DC98511FCULL,
		0xFD66986EEFC4A8C3ULL,
		0x589869007155B340ULL,
		0x450009740F18C035ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F432A230BC884C8ULL,
		0x0963972748B00778ULL,
		0x218851F038218504ULL,
		0x28A0B49999E92F5FULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9A52A3C6C4B6F443ULL,
		0xD75544BE2FE43D3FULL,
		0xA0857F3D33646EF0ULL,
		0x490251CB20EEB5ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA38AC79E6DFA983ULL,
		0x6B4E0A7A3D149267ULL,
		0xE5747A566C413F30ULL,
		0x35644798BD2552FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC019F74CDDD74AC0ULL,
		0x6C073A43F2CFAAD7ULL,
		0xBB1104E6C7232FC0ULL,
		0x139E0A3263C962AEULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x69CDA447B1E1B445ULL,
		0x805FDA0473BE85ADULL,
		0x89175DC850C3587FULL,
		0x580ABC279D55F903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDD5897ABC1B61DULL,
		0x835A8FF41093E482ULL,
		0x582D80FB70C3FE12ULL,
		0x2F5355F8FDC1C8A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CF04BB0061FFE28ULL,
		0xFD054A10632AA12BULL,
		0x30E9DCCCDFFF5A6CULL,
		0x28B7662E9F94305BULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x7608B7C5CA9CA895ULL,
		0xBE5D418E9DF6CF6BULL,
		0x9210F1FC54DEE996ULL,
		0x6A189C007825AA4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5C667C9D147F4AULL,
		0xB304C3256F92C177ULL,
		0x2F5D2CB71AFEC0C3ULL,
		0x53023BF8B1AEF128ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BAC51492D88294BULL,
		0x0B587E692E640DF3ULL,
		0x62B3C54539E028D3ULL,
		0x17166007C676B926ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC96F5B25C3BBFA37ULL,
		0xD75100C7E30AADB0ULL,
		0x67D655E095B75A32ULL,
		0x02F65EE9907D17CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58E463A1BD96538ULL,
		0x9FFDF7311A684EB8ULL,
		0x8ED6735C90401815ULL,
		0x286C7EA4B7195BF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03E114EBA7E294ECULL,
		0x37530996C8A25EF8ULL,
		0xD8FFE2840577421DULL,
		0x5A89E044D963BBD4ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8EE0F3B1CBE23F53ULL,
		0x50F11D339960C43AULL,
		0x58E219804FB5D0D0ULL,
		0x2C541436ACEB8E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606A70D812FF6883ULL,
		0x148067800038C987ULL,
		0x36F56EC64E2B024AULL,
		0x1F17BBBAAAB8A8FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E7682D9B8E2D6D0ULL,
		0x3C70B5B39927FAB3ULL,
		0x21ECAABA018ACE86ULL,
		0x0D3C587C0232E590ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x96DEF0D60AB3F264ULL,
		0x97514A2DC9637987ULL,
		0xEC4E1205AFFAF0B7ULL,
		0x2A86132B947F7F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0C276A39BD6E940ULL,
		0xA58FB08A42797582ULL,
		0xFCD4BCD750DD9832ULL,
		0x47D30186F72CC869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA61C7A326EDD0911ULL,
		0xF1C199A386EA0404ULL,
		0xEF79552E5F1D5884ULL,
		0x62B311A49D52B6FCULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3A2685A9DBAF25B8ULL,
		0x5F57FE53FB808956ULL,
		0x73211EC899D0DB5AULL,
		0x0A9CC880013BE8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B2BF82903DF1E2ULL,
		0x4F8C6CD5EAE6FCB0ULL,
		0x33ADD9A8E1A618FDULL,
		0x7D88C1B4003F6763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB273C6274B7133C3ULL,
		0x0FCB917E10998CA5ULL,
		0x3F73451FB82AC25DULL,
		0x0D1406CC00FC8149ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x00CAEE5020EFEF46ULL,
		0xB75946CDEE2D25C2ULL,
		0xDDA0D26FB5EA94C7ULL,
		0x0B5D58DFD39A05AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D066DADBF1FD7D1ULL,
		0x837FF334CC95143BULL,
		0xE3522876369EAFC4ULL,
		0x7A613640C5E454DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C480A261D01762ULL,
		0x33D9539921981186ULL,
		0xFA4EA9F97F4BE503ULL,
		0x10FC229F0DB5B0D0ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x187568F9AA5BC040ULL,
		0x60D0BD2DFBB4B8E7ULL,
		0xBCD70DE71FE04CF1ULL,
		0x04E8603101A7B497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED5AA0AD0ECA213ULL,
		0x45860AC511C6830DULL,
		0x98FB7C8678A7425CULL,
		0x580FAB2E7398A71EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x499FBEEED96F1E1AULL,
		0x1B4AB268E9EE35D9ULL,
		0x23DB9160A7390A95ULL,
		0x2CD8B5028E0F0D79ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC0BF28D8B463E8A2ULL,
		0xE78451DC9D9D9830ULL,
		0xDCEE15543ED7E4BFULL,
		0x655B7E0F889589BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62208DE58775B237ULL,
		0x5EEC35DA8483F921ULL,
		0x415E957C47AD449AULL,
		0x4FB2F95D9A7D1B07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E9E9AF32CEE366BULL,
		0x88981C0219199F0FULL,
		0x9B8F7FD7F72AA025ULL,
		0x15A884B1EE186EB3ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAA88F6774F4C14F1ULL,
		0xB82185D8719AD0D6ULL,
		0xE8521EA6730AB2CBULL,
		0x231CFA8067188D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C1EB86E92B939BULL,
		0x7B409678A1762795ULL,
		0x71696BC1056946E4ULL,
		0x226F6F851266FA8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2C70AF066208156ULL,
		0x3CE0EF5FD024A940ULL,
		0x76E8B2E56DA16BE7ULL,
		0x00AD8AFB54B19272ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x51D7464080456801ULL,
		0x56117DDF88DCC391ULL,
		0x1336BA522339AC97ULL,
		0x4179EE2BC23E0180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DAC378E8B863942ULL,
		0xA3C03E9767E173D8ULL,
		0xBC6AE0E45006DD60ULL,
		0x067D33E9C356C043ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB42B0EB1F4BF2EBFULL,
		0xB2513F4820FB4FB8ULL,
		0x56CBD96DD332CF36ULL,
		0x3AFCBA41FEE7413CULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x16F6432F8BD73749ULL,
		0x2D29E1EEBF3B69A9ULL,
		0x6E2F809EE290EF13ULL,
		0x43A2E84077B67E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46A3B2EFF5EFC964ULL,
		0x9C831DD3406B8ED9ULL,
		0xA8021CF0F86C37FCULL,
		0x5E71BFBA3DF8C698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD052903F95E76DD2ULL,
		0x90A6C41B7ECFDACFULL,
		0xC62D63ADEA24B716ULL,
		0x6531288639BDB79FULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA46314A790A584A4ULL,
		0x73CCD6CDA233224FULL,
		0x7226E83F27C5AE45ULL,
		0x7536693A8749229CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AFA5473A3C042AULL,
		0x9FD7E3330C686A90ULL,
		0x42ACE1E144268AF3ULL,
		0x4C5DAD7805F0736DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CB36F605669807AULL,
		0xD3F4F39A95CAB7BFULL,
		0x2F7A065DE39F2351ULL,
		0x28D8BBC28158AF2FULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xFA21967552EC6603ULL,
		0xB6E6765A0618B663ULL,
		0x167F9111A447F048ULL,
		0x4159945B22B13605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC343DE7B7EA32DE8ULL,
		0xF3CF8FFFD6A3FE63ULL,
		0x764DCE4F97345D49ULL,
		0x20C54AC5EA6E4F68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36DDB7F9D449381BULL,
		0xC316E65A2F74B800ULL,
		0xA031C2C20D1392FEULL,
		0x209449953842E69CULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x749B183202909342ULL,
		0xD3F9FD7E13534CAFULL,
		0xF401BD3DE336976FULL,
		0x03CD15D03252C9F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x569D7A016F8B7681ULL,
		0x45AB43601A10D723ULL,
		0xDC11B46758E9BE2CULL,
		0x15DD36828897D822ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DFD9E3093051CAEULL,
		0x8E4EBA1DF942758CULL,
		0x17F008D68A4CD943ULL,
		0x6DEFDF4DA9BAF1CFULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x45BD9D0A33837451ULL,
		0x418CB0364C062FA4ULL,
		0x902F570424C36127ULL,
		0x3EEC74FBCD7A5652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A9628799CBD740ULL,
		0xD7C859697F39424EULL,
		0xA77F77BF7E84C37FULL,
		0x26CB47D08B4C4AADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0143A8299B79D11ULL,
		0x69C456CCCCCCED55ULL,
		0xE8AFDF44A63E9DA7ULL,
		0x18212D2B422E0BA4ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6EB7A5F6CF78B690ULL,
		0xAB92A3F09D655DF4ULL,
		0x200E5F49D70E551EULL,
		0x3F4BD8EE7723F5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE475526E9BFB7648ULL,
		0x250C5A522772B1BEULL,
		0x6EB95F2846505B5BULL,
		0x45052D4AAD2BA4ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A425388337D4035ULL,
		0x8686499E75F2AC35ULL,
		0xB155002190BDF9C3ULL,
		0x7A46ABA3C9F85140ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD1C03574DDB62845ULL,
		0xC444A6177F2A8E04ULL,
		0xB99A4DAA01D0D26FULL,
		0x5F80F5630BCEE58DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1267898113E12EULL,
		0x8E4E9F747D4B332AULL,
		0x63136B8ABF697816ULL,
		0x4DAC2E52AA77D7DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84ADCDEB5CA24717ULL,
		0x35F606A301DF5ADAULL,
		0x5686E21F42675A59ULL,
		0x11D4C71061570DB3ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x90558856AE979E18ULL,
		0x545BFFEEDCF79894ULL,
		0xF2B5C97B4C90E9C4ULL,
		0x669904204D4279D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20507C2AB36EB12ULL,
		0x6A0E4D2B525B4AC6ULL,
		0xB42A90E4F5824F2AULL,
		0x1D4B3741354D6299ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE5080940360B306ULL,
		0xEA4DB2C38A9C4DCDULL,
		0x3E8B3896570E9A99ULL,
		0x494DCCDF17F51740ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9413D12C5CA6F0CAULL,
		0x7F4A48A9D714D2EBULL,
		0x64FE4920DC592200ULL,
		0x485990F82A1164B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5DFF5F44AC5FB7ULL,
		0x882B5325238F1D2CULL,
		0xB4756A5F203F2D7CULL,
		0x0A29FB8548AE0AB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56B5D1CD17FA9113ULL,
		0xF71EF584B385B5BFULL,
		0xB088DEC1BC19F483ULL,
		0x3E2F9572E16359FCULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE337F422571E590CULL,
		0x574FA1A9F048E073ULL,
		0x643BF4B6767DCCF3ULL,
		0x0FA065747E0410ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2461F58608ED943ULL,
		0xFF03689204DDBA90ULL,
		0x419F36903911EBC5ULL,
		0x46CA2A2C2BAAF10DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30F1D4C9F68F7FB6ULL,
		0x584C3917EB6B25E3ULL,
		0x229CBE263D6BE12DULL,
		0x48D63B4852591FDFULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1BE52CCFE2CBA5DAULL,
		0x1F422B736917282FULL,
		0x066D7B21EA4132D7ULL,
		0x79EBB8AFF53D7A7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5791D664400BD0ULL,
		0x2B254D68A489DE10ULL,
		0xB1A933A994684A50ULL,
		0x7C425AEBD49C719DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF08D9AF97E8B99F7ULL,
		0xF41CDE0AC48D4A1EULL,
		0x54C4477855D8E886ULL,
		0x7DA95DC420A108DCULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x28C37A033F07EA82ULL,
		0xF72EAEFEF422B1A5ULL,
		0xB8249D983DC895BEULL,
		0x5877B535F6301983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A5BF4DE56D0292FULL,
		0xD247731F832EA63EULL,
		0x82BE3433EA4CCA57ULL,
		0x1DBB0F557C5EB231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE678524E837C153ULL,
		0x24E73BDF70F40B66ULL,
		0x35666964537BCB67ULL,
		0x3ABCA5E079D16752ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC47C0670D1464142ULL,
		0x6BFB466AA236D4B1ULL,
		0x1D416ECBAC1F8B73ULL,
		0x536F4A9B79575517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0629C01032290F2ULL,
		0xC9D478FC2B6AD308ULL,
		0x43C063A3900AE057ULL,
		0x5C46EB912957FD69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4196A6FCE23B03DULL,
		0xA226CD6E76CC01A8ULL,
		0xD9810B281C14AB1BULL,
		0x77285F0A4FFF57ADULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD4ECF88EEBEEDBFAULL,
		0xA62AA63263F08969ULL,
		0x901BEC0FC8310576ULL,
		0x1609647FC8D47142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7510482E22A31008ULL,
		0xCD04EA57D4F4D02EULL,
		0x39CFFFA68F938062ULL,
		0x2BE5180D63DD2EB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FDCB060C94BCBDFULL,
		0xD925BBDA8EFBB93BULL,
		0x564BEC69389D8513ULL,
		0x6A244C7264F7428BULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x41E1D66FBCD1066BULL,
		0xEF4D5C35C286EEC8ULL,
		0x8FAD09CA4292FF93ULL,
		0x71328A3B82D457E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C78A7D9383E1D8ULL,
		0xA3C8DC235D3A7B9BULL,
		0xF8B6B84B430F6C8EULL,
		0x58F2235C242A87BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E1A4BF2294D2493ULL,
		0x4B848012654C732CULL,
		0x96F6517EFF839305ULL,
		0x184066DF5EA9D028ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x85FBDA2B26380351ULL,
		0x4AC65DEA5150F26DULL,
		0xBA346DA3452C2E72ULL,
		0x347ACC591300E552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0B6667602F29A9ULL,
		0x8D127C7ACEADA44EULL,
		0x6E93267A57A8697DULL,
		0x667AEF1C2593AE6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58F073C3C608D995ULL,
		0xBDB3E16F82A34E1FULL,
		0x4BA14728ED83C4F4ULL,
		0x4DFFDD3CED6D36E4ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE6066D909B52603AULL,
		0xA4F681F5FADE1AE0ULL,
		0x8B2B72D15451E8FCULL,
		0x60297DC849C43664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2775E10A506CA2ULL,
		0x9ED3FE0EBA714FBDULL,
		0xABCB4EB01E3E30BFULL,
		0x31F05C605519B3A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BDEF7AF9101F398ULL,
		0x062283E7406CCB23ULL,
		0xDF6024213613B83DULL,
		0x2E392167F4AA82BEULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x43F4B1945F2873BCULL,
		0x7C2E4C84F2EC302BULL,
		0xBB466C8E53BEF7CCULL,
		0x22ED514E3F3C2B8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF043056F613E5390ULL,
		0xE11E6D88F85C8958ULL,
		0x21C79A55E814FF7FULL,
		0x22134D08E02E3E9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B1AC24FDEA202CULL,
		0x9B0FDEFBFA8FA6D2ULL,
		0x997ED2386BA9F84CULL,
		0x00DA04455F0DECF2ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x147D51D53CD7553AULL,
		0x2882860EFE82347DULL,
		0x227BBA77A11DFAC5ULL,
		0x2EA97E767282B110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C8AA9E62DEAD87ULL,
		0xD878F5D3591016DCULL,
		0x0C3023AD500E8FC0ULL,
		0x2D87C166B80FD3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CB4A736D9F8A7B3ULL,
		0x5009903BA5721DA0ULL,
		0x164B96CA510F6B04ULL,
		0x0121BD0FBA72DD5EULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xDD455689557A2E1CULL,
		0xEEFDEC46976260A8ULL,
		0x6BF58D6DABD16372ULL,
		0x55B0F4B0A90AF38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49DE1D3EFABEF7B1ULL,
		0x53FBEC69F018F53BULL,
		0x0C7D905F654731B8ULL,
		0x4AA19121107E2310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9367394A5ABB366BULL,
		0x9B01FFDCA7496B6DULL,
		0x5F77FD0E468A31BAULL,
		0x0B0F638F988CD07EULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3C372B5971619058ULL,
		0x4EB666ADE01CA838ULL,
		0xD1808931980225A1ULL,
		0x574B3209ACFD66A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDBD28FF5A42BA20ULL,
		0x396F702648C545D4ULL,
		0x6E68E64103D56069ULL,
		0x2EF850865B91F6BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E7A025A171ED638ULL,
		0x1546F68797576263ULL,
		0x6317A2F0942CC538ULL,
		0x2852E183516B6FE2ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9F477C641351D1AEULL,
		0xFBF3DA517A4A8B3FULL,
		0x6D66E0572D2987EFULL,
		0x7C4EB4D7AB04FE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BF8EC82D7E7226ULL,
		0x9385DEB2962F8D7EULL,
		0xAD9F2C4216799CACULL,
		0x5539C34E838FDC75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA87ED9BE5D35F88ULL,
		0x686DFB9EE41AFDC0ULL,
		0xBFC7B41516AFEB43ULL,
		0x2714F1892775220CULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAD4B54117A90B8C5ULL,
		0xAF6823A1DE2DB506ULL,
		0xCFFA3D0ABDEAA82DULL,
		0x25F6ABE2ACE2DADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A791FE0D86A57EULL,
		0xB69E4AB0B0CA17CEULL,
		0x04390F713FAA2C4AULL,
		0x18D1721663B6EEB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87A3C2136D0A1347ULL,
		0xF8C9D8F12D639D38ULL,
		0xCBC12D997E407BE2ULL,
		0x0D2539CC492BEC28ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB7FDE029664E3DCCULL,
		0x5C8271992CF597EAULL,
		0xEFDD7269683F9B09ULL,
		0x5394873C74D97A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3064341E1472E367ULL,
		0xD1F4977461267BD5ULL,
		0x65AFC06B76FD9316ULL,
		0x12305F4423ABF959ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8799AC0B51DB5A65ULL,
		0x8A8DDA24CBCF1C15ULL,
		0x8A2DB1FDF14207F2ULL,
		0x416427F8512D80ECULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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