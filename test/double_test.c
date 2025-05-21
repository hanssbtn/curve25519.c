#include "tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Double Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA290F18A0D8CF5A9ULL,
		0xFDB2872669BD333CULL,
		0xD337F6ACD77671DFULL,
		0x5944918ABA201223ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4521E3141B19EB65ULL,
		0xFB650E4CD37A6679ULL,
		0xA66FED59AEECE3BFULL,
		0x3289231574402447ULL
	}};
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91C7E6E6D1366BBFULL,
		0x58AFAFA7339BBBFAULL,
		0xC661A6D7B254D1B3ULL,
		0x1BAD998FFB5FF621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238FCDCDA26CD77EULL,
		0xB15F5F4E673777F5ULL,
		0x8CC34DAF64A9A366ULL,
		0x375B331FF6BFEC43ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABC868E9686950B0ULL,
		0x71E6D128417A1C02ULL,
		0x0D52058731FCCDCEULL,
		0x1D563C9A5B40056CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5790D1D2D0D2A160ULL,
		0xE3CDA25082F43805ULL,
		0x1AA40B0E63F99B9CULL,
		0x3AAC7934B6800AD8ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48BF59E7F1A385E8ULL,
		0x13CA96C16987EE5BULL,
		0x3D16A7E0D87C18FAULL,
		0x76A1D1092FE6BDBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917EB3CFE3470BE3ULL,
		0x27952D82D30FDCB6ULL,
		0x7A2D4FC1B0F831F4ULL,
		0x6D43A2125FCD7B7AULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CFF398DC735118FULL,
		0x7AF8DCB7B0AE51F3ULL,
		0x03FB8F13BA53F911ULL,
		0x6CE8948F05746159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FE731B8E6A2331ULL,
		0xF5F1B96F615CA3E6ULL,
		0x07F71E2774A7F222ULL,
		0x59D1291E0AE8C2B2ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB165D04B7DD9C09ULL,
		0x61E300E83891320DULL,
		0xE3328F2F37E778FBULL,
		0x48745DC0094CB530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962CBA096FBB3825ULL,
		0xC3C601D07122641BULL,
		0xC6651E5E6FCEF1F6ULL,
		0x10E8BB8012996A61ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x272F3D0C3DA3C2F1ULL,
		0xA2CDDF668857F9DDULL,
		0x7C679FA9F6F7F5A9ULL,
		0x7B02F0D30812112CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E5E7A187B4785F5ULL,
		0x459BBECD10AFF3BAULL,
		0xF8CF3F53EDEFEB53ULL,
		0x7605E1A610242258ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE735A95C4CEB08AULL,
		0xF7B7D04B0A074425ULL,
		0x2430E6040C40272CULL,
		0x00A588FBBD8B22F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE6B52B899D6114ULL,
		0xEF6FA096140E884BULL,
		0x4861CC0818804E59ULL,
		0x014B11F77B1645E4ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE5828BFFBC9B683ULL,
		0xACBADC8DB03EFC43ULL,
		0xE8796AF15D8D5272ULL,
		0x322DECF2C613B308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB0517FF7936D06ULL,
		0x5975B91B607DF887ULL,
		0xD0F2D5E2BB1AA4E5ULL,
		0x645BD9E58C276611ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x617BE4B318AD55ECULL,
		0xCDE0AA26A4642BD5ULL,
		0x9ADAD7356D17D674ULL,
		0x11FDEB368646051CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F7C966315AABD8ULL,
		0x9BC1544D48C857AAULL,
		0x35B5AE6ADA2FACE9ULL,
		0x23FBD66D0C8C0A39ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2DC44BC7DFFCE83ULL,
		0x8BEE39476F7F8174ULL,
		0x926063391188C843ULL,
		0x403BC19495450148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B88978FBFF9D19ULL,
		0x17DC728EDEFF02E9ULL,
		0x24C0C67223119087ULL,
		0x007783292A8A0291ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C769CAA5885A238ULL,
		0xC66013B3DA99D3F1ULL,
		0x593F0F2294A4D1D2ULL,
		0x45499230156452D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18ED3954B10B4483ULL,
		0x8CC02767B533A7E2ULL,
		0xB27E1E452949A3A5ULL,
		0x0A9324602AC8A5A2ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC80F6CD8443DC6D0ULL,
		0x444E6C8C511F7461ULL,
		0x9E559CC9298B6590ULL,
		0x67C446EDAEB3982EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901ED9B0887B8DB3ULL,
		0x889CD918A23EE8C3ULL,
		0x3CAB39925316CB20ULL,
		0x4F888DDB5D67305DULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD25F1A617E222DFBULL,
		0x5DA8D27D09D459ADULL,
		0x7E8F54A2C2255983ULL,
		0x4DA33FF7B41B0DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4BE34C2FC445C09ULL,
		0xBB51A4FA13A8B35BULL,
		0xFD1EA945844AB306ULL,
		0x1B467FEF68361BB2ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x973B87526E5D18D8ULL,
		0x52A5D697C83C5029ULL,
		0xC3345906499E75B3ULL,
		0x35ECA02ED0849C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E770EA4DCBA31B0ULL,
		0xA54BAD2F9078A053ULL,
		0x8668B20C933CEB66ULL,
		0x6BD9405DA10938F9ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29C526F8D66CB4D7ULL,
		0x9E382F4F2176656CULL,
		0xFA2F5A3D56AF2DF9ULL,
		0x65BF847A82DBD55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538A4DF1ACD969C1ULL,
		0x3C705E9E42ECCAD8ULL,
		0xF45EB47AAD5E5BF3ULL,
		0x4B7F08F505B7AAB7ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9654308B8236C99AULL,
		0xBDD8A96010CDD1DEULL,
		0xC53D12FB3FB79280ULL,
		0x06559128D3EB35ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA86117046D9334ULL,
		0x7BB152C0219BA3BDULL,
		0x8A7A25F67F6F2501ULL,
		0x0CAB2251A7D66BD9ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A424F8F05849D9DULL,
		0x94617E2F36E06EF0ULL,
		0xB392CB14535B8DC4ULL,
		0x29133EDA85050B27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4849F1E0B093B3AULL,
		0x28C2FC5E6DC0DDE0ULL,
		0x67259628A6B71B89ULL,
		0x52267DB50A0A164FULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF207191360F314E8ULL,
		0xFDF6EA51F2B13037ULL,
		0xBB56DAF7B05C9B6FULL,
		0x793291107F9EFFACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE40E3226C1E629E3ULL,
		0xFBEDD4A3E562606FULL,
		0x76ADB5EF60B936DFULL,
		0x72652220FF3DFF59ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CED29AB94F84D31ULL,
		0x2C4B22826427623FULL,
		0xB7B396BDCA0D4129ULL,
		0x37F72A43BF2ED5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DA535729F09A62ULL,
		0x58964504C84EC47EULL,
		0x6F672D7B941A8252ULL,
		0x6FEE54877E5DAB55ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCD4EC8E9F038BCEULL,
		0xF4FEC1AB85B59D78ULL,
		0x19ED87D9A075BCB7ULL,
		0x3C1803A87B6BDF0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A9D91D3E07179CULL,
		0xE9FD83570B6B3AF1ULL,
		0x33DB0FB340EB796FULL,
		0x78300750F6D7BE18ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x589DDAC490A159BAULL,
		0x006DECC0BBAA5D28ULL,
		0x9D5EFB246838590FULL,
		0x0679280B8C8A9095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB13BB5892142B374ULL,
		0x00DBD9817754BA50ULL,
		0x3ABDF648D070B21EULL,
		0x0CF250171915212BULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25C8B59AD5DD2FC2ULL,
		0xA50DF04CEAC167A0ULL,
		0xAAC864DED16C6232ULL,
		0x3B4D778AFC55E4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B916B35ABBA5F84ULL,
		0x4A1BE099D582CF40ULL,
		0x5590C9BDA2D8C465ULL,
		0x769AEF15F8ABC9EFULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC0CB224BB9D802ULL,
		0x555A443DF78BEAADULL,
		0x4929510D9E6D0AA5ULL,
		0x21214D49B81CE59CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8196449773B004ULL,
		0xAAB4887BEF17D55AULL,
		0x9252A21B3CDA154AULL,
		0x42429A937039CB38ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x286227FEE291F8A9ULL,
		0x64117B58174498E5ULL,
		0x2F8B070C7F09E957ULL,
		0x6DFEDD2FE804114CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C44FFDC523F165ULL,
		0xC822F6B02E8931CAULL,
		0x5F160E18FE13D2AEULL,
		0x5BFDBA5FD0082298ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42BD80FAB348B53BULL,
		0x2B3F872155255877ULL,
		0x4F79141A0BB6C4FBULL,
		0x5978A1137317A67FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857B01F566916A89ULL,
		0x567F0E42AA4AB0EEULL,
		0x9EF22834176D89F6ULL,
		0x32F14226E62F4CFEULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x595F9D806F7ADF3EULL,
		0xE415CA3E100AA111ULL,
		0x9DFD65E1D3AA2FEDULL,
		0x183BD985074D8494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2BF3B00DEF5BE7CULL,
		0xC82B947C20154222ULL,
		0x3BFACBC3A7545FDBULL,
		0x3077B30A0E9B0929ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE5CAE5BB5CC60C9ULL,
		0x83D34DFCA47C7098ULL,
		0xB8B082A936779FAAULL,
		0x5E1D0BEC824243C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB95CB76B98C1A5ULL,
		0x07A69BF948F8E131ULL,
		0x716105526CEF3F55ULL,
		0x3C3A17D904848791ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF56B183741FA35E8ULL,
		0xB7C26EF75FDAA6C1ULL,
		0x4FBECD3A3AE181A8ULL,
		0x24EC89332919A0F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAD6306E83F46BD0ULL,
		0x6F84DDEEBFB54D83ULL,
		0x9F7D9A7475C30351ULL,
		0x49D91266523341E8ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD8C2E77982CD871ULL,
		0x6AC017E7E151592AULL,
		0xE28564B56A08D901ULL,
		0x0A79AF662CE8DBDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B185CEF3059B0E2ULL,
		0xD5802FCFC2A2B255ULL,
		0xC50AC96AD411B202ULL,
		0x14F35ECC59D1B7B9ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x594EEF06140EA538ULL,
		0xFF5EF1FE6B399C9CULL,
		0xA39385B9813995BCULL,
		0x4D781715BCD00C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29DDE0C281D4A83ULL,
		0xFEBDE3FCD6733938ULL,
		0x47270B7302732B79ULL,
		0x1AF02E2B79A01805ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4BF98312BD80791ULL,
		0x9E8022D777AD210BULL,
		0x7821BA0BB5BF7FC9ULL,
		0x0FB85D7C4AF4F272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA97F306257B00F22ULL,
		0x3D0045AEEF5A4217ULL,
		0xF04374176B7EFF93ULL,
		0x1F70BAF895E9E4E4ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A16E2BCF26807D7ULL,
		0xC38C39F41F03371AULL,
		0x2E1C3B10990D1EC7ULL,
		0x2BE6EEC0E2D3A827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x542DC579E4D00FAEULL,
		0x871873E83E066E34ULL,
		0x5C387621321A3D8FULL,
		0x57CDDD81C5A7504EULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED5248E6E69DF49EULL,
		0x4726F50267909F92ULL,
		0x65F865ADDA77516DULL,
		0x096EB233428B28BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAA491CDCD3BE93CULL,
		0x8E4DEA04CF213F25ULL,
		0xCBF0CB5BB4EEA2DAULL,
		0x12DD64668516517CULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x861094F49E2D1BA8ULL,
		0x014B054A5151409AULL,
		0x2E45BDC1EB927437ULL,
		0x6F31FF8E7D519967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2129E93C5A3763ULL,
		0x02960A94A2A28135ULL,
		0x5C8B7B83D724E86EULL,
		0x5E63FF1CFAA332CEULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x787AADA919D360FEULL,
		0xE6FE2DD514D7B382ULL,
		0x7AF7C2CFF1077978ULL,
		0x6664EFC22F87C037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F55B5233A6C20FULL,
		0xCDFC5BAA29AF6704ULL,
		0xF5EF859FE20EF2F1ULL,
		0x4CC9DF845F0F806EULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED03D4409FA8726ULL,
		0x0BB21DCFD2BA047AULL,
		0xDD00A80C797D7A69ULL,
		0x055D32951F97329CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA07A8813F50E4CULL,
		0x17643B9FA57408F5ULL,
		0xBA015018F2FAF4D2ULL,
		0x0ABA652A3F2E6539ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE85EEAA7347CF5D9ULL,
		0xDFFE4AC3549B6EACULL,
		0xB1BC1409998A5702ULL,
		0x3AC447868105D3D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0BDD54E68F9EBB2ULL,
		0xBFFC9586A936DD59ULL,
		0x637828133314AE05ULL,
		0x75888F0D020BA7ABULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4129808C14E37DD3ULL,
		0x4909D187780A6BAAULL,
		0xCA6D2E9CACF3CB79ULL,
		0x449B50FB81BAADB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8253011829C6FBB9ULL,
		0x9213A30EF014D754ULL,
		0x94DA5D3959E796F2ULL,
		0x0936A1F703755B6FULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4191041D42736E8ULL,
		0x3BD3749BBE1525D5ULL,
		0xB56C96A30AAC3D0EULL,
		0x15AE1B891A5A5663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8322083A84E6DD0ULL,
		0x77A6E9377C2A4BABULL,
		0x6AD92D4615587A1CULL,
		0x2B5C371234B4ACC7ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BEC932287FE7CEBULL,
		0xD550ABA5DE840FC5ULL,
		0xDDFDE60032781821ULL,
		0x35E0CD0C7D0653DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D926450FFCF9D6ULL,
		0xAAA1574BBD081F8AULL,
		0xBBFBCC0064F03043ULL,
		0x6BC19A18FA0CA7B5ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC229DF9445666F1BULL,
		0xBB7D35E4FD8D1174ULL,
		0x9D1396DBFC75819AULL,
		0x253F83D38182F543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8453BF288ACCDE36ULL,
		0x76FA6BC9FB1A22E9ULL,
		0x3A272DB7F8EB0335ULL,
		0x4A7F07A70305EA87ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14FC1589C818AB13ULL,
		0xD2E20C7F89CB18A3ULL,
		0xF45ACEC1EDEED6DBULL,
		0x7164F36CAE52F544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F82B1390315639ULL,
		0xA5C418FF13963146ULL,
		0xE8B59D83DBDDADB7ULL,
		0x62C9E6D95CA5EA89ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x686EF93DDA06A8CBULL,
		0xC886B116B2479E8CULL,
		0xCEF1B1DBCD2C70A6ULL,
		0x2A1C412E75153414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0DDF27BB40D5196ULL,
		0x910D622D648F3D18ULL,
		0x9DE363B79A58E14DULL,
		0x5438825CEA2A6829ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80B5E37373589388ULL,
		0x85F5F847D2711D8EULL,
		0x95F9B136D28647D2ULL,
		0x383E2D04DB280699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016BC6E6E6B12710ULL,
		0x0BEBF08FA4E23B1DULL,
		0x2BF3626DA50C8FA5ULL,
		0x707C5A09B6500D33ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A0399C02EAA4EB9ULL,
		0x9D17F031A7C161BAULL,
		0x5F5C2F853F0E215BULL,
		0x6DDE4878AB6022B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB40733805D549D85ULL,
		0x3A2FE0634F82C374ULL,
		0xBEB85F0A7E1C42B7ULL,
		0x5BBC90F156C04570ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB483E1D9174DA42AULL,
		0xB3973F09A729D5D9ULL,
		0x15894C21862E9CE1ULL,
		0x10DCD053D1AA1A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6907C3B22E9B4854ULL,
		0x672E7E134E53ABB3ULL,
		0x2B1298430C5D39C3ULL,
		0x21B9A0A7A3543446ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6DEE0106FE9B84DULL,
		0x774DC8A1D5D9A965ULL,
		0x14B4636E38E079D1ULL,
		0x35315F7C67FD6173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBDC020DFD3709AULL,
		0xEE9B9143ABB352CBULL,
		0x2968C6DC71C0F3A2ULL,
		0x6A62BEF8CFFAC2E6ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90EE9636FE544168ULL,
		0xDE6D4B22B90D9007ULL,
		0x9A4972A68B517F76ULL,
		0x2324F84090E5B703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21DD2C6DFCA882D0ULL,
		0xBCDA9645721B200FULL,
		0x3492E54D16A2FEEDULL,
		0x4649F08121CB6E07ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED17B3061933AADEULL,
		0x56D0BAACAC5E08D9ULL,
		0xEA197574517FDCC5ULL,
		0x2E0B7C6D481E7AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA2F660C326755BCULL,
		0xADA1755958BC11B3ULL,
		0xD432EAE8A2FFB98AULL,
		0x5C16F8DA903CF561ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x578207D34019110DULL,
		0x8856CC75E37426C7ULL,
		0x7965E810CA806A04ULL,
		0x164C9B6EE2D6C469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF040FA68032221AULL,
		0x10AD98EBC6E84D8EULL,
		0xF2CBD0219500D409ULL,
		0x2C9936DDC5AD88D2ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B442F2B19B6E947ULL,
		0x9EA980DF87DAAC99ULL,
		0x90FD184249F72975ULL,
		0x06427E0532B73472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96885E56336DD28EULL,
		0x3D5301BF0FB55932ULL,
		0x21FA308493EE52EBULL,
		0x0C84FC0A656E68E5ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51364791F157C8B9ULL,
		0xEFF0A8C1BB009DE6ULL,
		0x8611A04E367868B2ULL,
		0x39F63A1351B35521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26C8F23E2AF9172ULL,
		0xDFE1518376013BCCULL,
		0x0C23409C6CF0D165ULL,
		0x73EC7426A366AA43ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D4E4D9C7F21A647ULL,
		0xFA001A1EA9DD026CULL,
		0x532B2B5AC0A5A54FULL,
		0x4A92C53D6009C249ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA9C9B38FE434CA1ULL,
		0xF400343D53BA04D8ULL,
		0xA65656B5814B4A9FULL,
		0x15258A7AC0138492ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE5A2FE0CA9D854DULL,
		0x639D73239DC6E92FULL,
		0x89D9006155FF8983ULL,
		0x2122D7F0EA3A5414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB45FC1953B0A9AULL,
		0xC73AE6473B8DD25FULL,
		0x13B200C2ABFF1306ULL,
		0x4245AFE1D474A829ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC00E0B4066B4D650ULL,
		0xD74E2F343CDCFDF2ULL,
		0xB5427B2ED2B096C3ULL,
		0x1E7F9732761791D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801C1680CD69ACA0ULL,
		0xAE9C5E6879B9FBE5ULL,
		0x6A84F65DA5612D87ULL,
		0x3CFF2E64EC2F23A7ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78B9B0D2470E8992ULL,
		0xEBCAD131B4EB9325ULL,
		0xD7220009E274764DULL,
		0x6E01E346099C3B8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17361A48E1D1337ULL,
		0xD795A26369D7264AULL,
		0xAE440013C4E8EC9BULL,
		0x5C03C68C13387719ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25CF6E782A8E73B1ULL,
		0xA10856C9B9B18229ULL,
		0x15946AF015C0C5A1ULL,
		0x3E6958E5E9C13FBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B9EDCF0551CE762ULL,
		0x4210AD9373630452ULL,
		0x2B28D5E02B818B43ULL,
		0x7CD2B1CBD3827F7CULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41182AD4B28D648AULL,
		0x0B99F67C5976C1CFULL,
		0xAB117E2DB9DBBCA6ULL,
		0x6B793E11F9318EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x823055A9651AC927ULL,
		0x1733ECF8B2ED839EULL,
		0x5622FC5B73B7794CULL,
		0x56F27C23F2631D7BULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D5DB5375302ADD6ULL,
		0x2B9657EFEC24C5F1ULL,
		0x39CAFFA411E0C1FBULL,
		0x583CC30ADADD6D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ABB6A6EA6055BBFULL,
		0x572CAFDFD8498BE3ULL,
		0x7395FF4823C183F6ULL,
		0x30798615B5BADA22ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F715B1FA236F79BULL,
		0xAED5A970D9972E4FULL,
		0x2410D33E666DF791ULL,
		0x657E95FC625628C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE2B63F446DEF49ULL,
		0x5DAB52E1B32E5C9FULL,
		0x4821A67CCCDBEF23ULL,
		0x4AFD2BF8C4AC5192ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA12E0D66B984A85AULL,
		0x52D4915B90473B12ULL,
		0xF56410B7A7012E66ULL,
		0x4F82332C06940135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425C1ACD730950C7ULL,
		0xA5A922B7208E7625ULL,
		0xEAC8216F4E025CCCULL,
		0x1F0466580D28026BULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x475B764C1AE12FF5ULL,
		0x3B935CBDC17D24D9ULL,
		0xD368BE934F16F2D1ULL,
		0x46124E6B33BE9413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB6EC9835C25FFDULL,
		0x7726B97B82FA49B2ULL,
		0xA6D17D269E2DE5A2ULL,
		0x0C249CD6677D2827ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED91A2BA4493112ULL,
		0xFC214A7425F4ACCBULL,
		0x8191EFF9AE4297E7ULL,
		0x7C7C932E35EB22B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB2345748926237ULL,
		0xF84294E84BE95997ULL,
		0x0323DFF35C852FCFULL,
		0x78F9265C6BD6456DULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5D41ADB2FDA6E4BULL,
		0x8B27CC0D3CFD6256ULL,
		0xCEE0A3EF31CB4FF5ULL,
		0x12A3FCC2F854F640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA835B65FB4DC96ULL,
		0x164F981A79FAC4ADULL,
		0x9DC147DE63969FEBULL,
		0x2547F985F0A9EC81ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172D9E179260DC3BULL,
		0x9572336747D0BED7ULL,
		0x0EAE66896CDD19A3ULL,
		0x689CEA688C2928FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E5B3C2F24C1B889ULL,
		0x2AE466CE8FA17DAEULL,
		0x1D5CCD12D9BA3347ULL,
		0x5139D4D1185251FEULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FDBF5700D4D7D41ULL,
		0xBE420DFF107C8B6CULL,
		0xB8DD0C6832570100ULL,
		0x287448D6E9F36655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB7EAE01A9AFA82ULL,
		0x7C841BFE20F916D8ULL,
		0x71BA18D064AE0201ULL,
		0x50E891ADD3E6CCABULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECB4672161215E2AULL,
		0xD407E9524894AB04ULL,
		0x8E23525228044CE0ULL,
		0x3B7AB47D1732AFAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD968CE42C242BC54ULL,
		0xA80FD2A491295609ULL,
		0x1C46A4A4500899C1ULL,
		0x76F568FA2E655F5FULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D2B32FFF29EFEAAULL,
		0x36CFA2051AF0A8B2ULL,
		0xE4D040EE47568EEEULL,
		0x0DCEA282FA52978DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5665FFE53DFD54ULL,
		0x6D9F440A35E15164ULL,
		0xC9A081DC8EAD1DDCULL,
		0x1B9D4505F4A52F1BULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50E271DE2E35D69AULL,
		0xDA2F4C111EC34ADDULL,
		0xF0FF9B42275E54C5ULL,
		0x3F1CF06BB8C5F072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1C4E3BC5C6BAD34ULL,
		0xB45E98223D8695BAULL,
		0xE1FF36844EBCA98BULL,
		0x7E39E0D7718BE0E5ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9EF26499AC96A05ULL,
		0xADE19A0969550ECDULL,
		0x209499A3A59632E3ULL,
		0x395DA15DCF7B61EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3DE4C933592D40AULL,
		0x5BC33412D2AA1D9BULL,
		0x412933474B2C65C7ULL,
		0x72BB42BB9EF6C3D6ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0CD4A8CACA6027ULL,
		0xA4F632D1069517A4ULL,
		0xC082C93EFD03393EULL,
		0x4EDCFF22866A2821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1819A9519594C061ULL,
		0x49EC65A20D2A2F49ULL,
		0x8105927DFA06727DULL,
		0x1DB9FE450CD45043ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x615F676741BACA01ULL,
		0x216E5A4514C0E39EULL,
		0x85235EBF790FF5DAULL,
		0x7A61BCD5F9D231B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BECECE83759415ULL,
		0x42DCB48A2981C73CULL,
		0x0A46BD7EF21FEBB4ULL,
		0x74C379ABF3A46367ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06709745CC6981BFULL,
		0x785A5122A834CEC5ULL,
		0x14871BF2BC0509DCULL,
		0x36C8755A6E2649A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CE12E8B98D3037EULL,
		0xF0B4A24550699D8AULL,
		0x290E37E5780A13B8ULL,
		0x6D90EAB4DC4C9342ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54FDFCD277AE3389ULL,
		0x4F7043CAF77E4EAAULL,
		0x0BCE06B722F16BB4ULL,
		0x5409967A5000B510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9FBF9A4EF5C6725ULL,
		0x9EE08795EEFC9D54ULL,
		0x179C0D6E45E2D768ULL,
		0x28132CF4A0016A20ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A2C47ACD3EAA96AULL,
		0xF8033D3E05D6F256ULL,
		0x8564F6D0043D20F2ULL,
		0x67830F1E1A4F0F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94588F59A7D552E7ULL,
		0xF0067A7C0BADE4ACULL,
		0x0AC9EDA0087A41E5ULL,
		0x4F061E3C349E1F19ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F28DA0C52808D1AULL,
		0xBDF69238FF9F284FULL,
		0x0A4637F3656F3A7EULL,
		0x3F66C4701A95AF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE51B418A5011A34ULL,
		0x7BED2471FF3E509EULL,
		0x148C6FE6CADE74FDULL,
		0x7ECD88E0352B5E38ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7A5531979F6411CULL,
		0x69BFB1E22A4B9977ULL,
		0xD61979E197000C07ULL,
		0x6D6E4D6D9CB61C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4AA632F3EC824BULL,
		0xD37F63C4549732EFULL,
		0xAC32F3C32E00180EULL,
		0x5ADC9ADB396C38FBULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C9E8FF931B5B3C1ULL,
		0x54E5E20DE8A7F42AULL,
		0x5C99CAE09F2E39C1ULL,
		0x303EF652B42F010FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x393D1FF2636B6782ULL,
		0xA9CBC41BD14FE854ULL,
		0xB93395C13E5C7382ULL,
		0x607DECA5685E021EULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BE477DDCC4F0CDULL,
		0xE8EFE202838023DBULL,
		0x9E2DA6569305A35CULL,
		0x133E475BCBC3C67EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297C8EFBB989E19AULL,
		0xD1DFC405070047B7ULL,
		0x3C5B4CAD260B46B9ULL,
		0x267C8EB797878CFDULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA8D1952005539B8ULL,
		0x2422042AAE889396ULL,
		0xF195EB9DE3ECA9C7ULL,
		0x7533E4A086B8FEB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951A32A400AA7383ULL,
		0x484408555D11272DULL,
		0xE32BD73BC7D9538EULL,
		0x6A67C9410D71FD69ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B8CA9334DE44757ULL,
		0x1734B270E4E7488EULL,
		0x1718B2B6E3D9EA62ULL,
		0x62770D5A7CDD00F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF71952669BC88EC1ULL,
		0x2E6964E1C9CE911CULL,
		0x2E31656DC7B3D4C4ULL,
		0x44EE1AB4F9BA01E0ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FF8975962A898E3ULL,
		0x1BB2CECDF0C6AAECULL,
		0xACFA012B8324BA09ULL,
		0x1729627672EE7DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF12EB2C55131C6ULL,
		0x37659D9BE18D55D8ULL,
		0x59F4025706497412ULL,
		0x2E52C4ECE5DCFBCBULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E60D756F27FAC61ULL,
		0x2808EAB76EF2B905ULL,
		0x8F02F27401573827ULL,
		0x1060D1B2C4434959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC1AEADE4FF58C2ULL,
		0x5011D56EDDE5720AULL,
		0x1E05E4E802AE704EULL,
		0x20C1A365888692B3ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7729D931B334F110ULL,
		0xBEC256060293EBEAULL,
		0x1562FAD3831E6263ULL,
		0x45259B7249ADAA61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE53B2636669E233ULL,
		0x7D84AC0C0527D7D4ULL,
		0x2AC5F5A7063CC4C7ULL,
		0x0A4B36E4935B54C2ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1A15A98EB93D7E1ULL,
		0x8F349088BF196853ULL,
		0x92CA6A3F317A8998ULL,
		0x11E9F523F304A2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE342B531D727AFC2ULL,
		0x1E6921117E32D0A7ULL,
		0x2594D47E62F51331ULL,
		0x23D3EA47E6094547ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED6747B13E35D085ULL,
		0xD7D06EA146EC75D5ULL,
		0x1579E7C350CA4A5EULL,
		0x58F47CCE7634E022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDACE8F627C6BA11DULL,
		0xAFA0DD428DD8EBABULL,
		0x2AF3CF86A19494BDULL,
		0x31E8F99CEC69C044ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x673A9959093FB190ULL,
		0x512F279035EE109BULL,
		0x1D313FFB12777BB5ULL,
		0x0BF64E397ED51012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE7532B2127F6320ULL,
		0xA25E4F206BDC2136ULL,
		0x3A627FF624EEF76AULL,
		0x17EC9C72FDAA2024ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEA8A59951712406ULL,
		0x7FD08EA182E3602AULL,
		0x0D21AD2E0AEEC4A1ULL,
		0x3C84CA2EDB93FD25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD514B32A2E2480CULL,
		0xFFA11D4305C6C055ULL,
		0x1A435A5C15DD8942ULL,
		0x7909945DB727FA4AULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01E06206C4ECE92DULL,
		0x3182ECFB1D1E9231ULL,
		0x28D55EF2A62AF951ULL,
		0x2F4A925BF68FF435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C0C40D89D9D25AULL,
		0x6305D9F63A3D2462ULL,
		0x51AABDE54C55F2A2ULL,
		0x5E9524B7ED1FE86AULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73C2A5F3200A4B1BULL,
		0x69CAF846565A6E55ULL,
		0x526B6C14395EE163ULL,
		0x4C4422B5AD6E138CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7854BE640149649ULL,
		0xD395F08CACB4DCAAULL,
		0xA4D6D82872BDC2C6ULL,
		0x1888456B5ADC2718ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4ED39624627E485ULL,
		0x82961804A634A460ULL,
		0x2A1C2A9EB714CD98ULL,
		0x1EBF9BB8FE880C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69DA72C48C4FC90AULL,
		0x052C30094C6948C1ULL,
		0x5438553D6E299B31ULL,
		0x3D7F3771FD101830ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88A43576AD06C5DBULL,
		0x1027F217C15B70F8ULL,
		0x978029E78BA3B42AULL,
		0x66806F4853791CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11486AED5A0D8BC9ULL,
		0x204FE42F82B6E1F1ULL,
		0x2F0053CF17476854ULL,
		0x4D00DE90A6F23973ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AF64979132802ACULL,
		0x4166B51A7C022603ULL,
		0xCFB3EA309B40F79EULL,
		0x6EA3D870491ABFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75EC92F22650056BULL,
		0x82CD6A34F8044C06ULL,
		0x9F67D4613681EF3CULL,
		0x5D47B0E092357F6FULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04C96C384B56EDB1ULL,
		0x7F25D62D988245ADULL,
		0x77DB82C778E7D52CULL,
		0x6B8A64094DF23144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0992D87096ADDB75ULL,
		0xFE4BAC5B31048B5AULL,
		0xEFB7058EF1CFAA58ULL,
		0x5714C8129BE46288ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA904C2852439661EULL,
		0x3F62C18E7F9C483EULL,
		0x76C2FD6BEB6EBC66ULL,
		0x29552A97A3EC9E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5209850A4872CC3CULL,
		0x7EC5831CFF38907DULL,
		0xED85FAD7D6DD78CCULL,
		0x52AA552F47D93C5CULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC693CC03F24B6E48ULL,
		0xA00B38C7DFA75B95ULL,
		0x8D4818F017E78F94ULL,
		0x4438B2255E667FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D279807E496DCA3ULL,
		0x4016718FBF4EB72BULL,
		0x1A9031E02FCF1F29ULL,
		0x0871644ABCCCFF91ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48099E49BA07396DULL,
		0x1FC4DEE78CC28740ULL,
		0x53F61CE06A85D6AFULL,
		0x6C218CE7A521BD8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90133C93740E72EDULL,
		0x3F89BDCF19850E80ULL,
		0xA7EC39C0D50BAD5EULL,
		0x584319CF4A437B1AULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2201981065656BCULL,
		0x0AABACC8E57368F3ULL,
		0xAC25AAFA80499471ULL,
		0x44A8D0E5AF96A543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE44033020CACAD8BULL,
		0x15575991CAE6D1E7ULL,
		0x584B55F5009328E2ULL,
		0x0951A1CB5F2D4A87ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48D9DC2B3A17B4FBULL,
		0x7241DABFEC3D76A8ULL,
		0x78151C1F30D27C2FULL,
		0x624C72C8CEE5F9DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91B3B856742F6A09ULL,
		0xE483B57FD87AED50ULL,
		0xF02A383E61A4F85EULL,
		0x4498E5919DCBF3BEULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}