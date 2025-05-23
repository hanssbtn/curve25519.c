#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0xB24E20E9A5C1402EULL,
		0xA6DE4BF397CF1264ULL,
		0x28914C6408547D4CULL,
		0x021935595E822CAEULL,
		0x597A55853DC7C255ULL,
		0x84423C4719B7BBA7ULL,
		0x7333577EE20BB011ULL,
		0x6576D69CDF62CA93ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x84B27CEE38039BB2ULL,
		0x7EE33C74FCF5D159ULL,
		0xE7C8A49A593EBD31ULL,
		0x3353A9EA35CBABA1ULL,
		0x4DF2A2D7812D011BULL,
		0x4C41ADE1570044B0ULL,
		0x25E32F1B35F86D23ULL,
		0x7B355B9B872EAB0BULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xE3C029C56CB65293ULL,
		0x781032998214E9B6ULL,
		0xBAAEA69539F1AF77ULL,
		0x147DCDA240732F47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x95BC040F14A6ABC9ULL,
		0x44CA9F0CB21D67C5ULL,
		0x3B0703EAC22C2F56ULL,
		0x0EF3D6971C012BE9ULL,
		0x42716B307D851DC6ULL,
		0x6CEE1BF8E22B8204ULL,
		0x73747D0B2CCF0354ULL,
		0xD29B60615A87722FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC201EB3C352C7BCULL,
		0x5CFF722A3F52D7F0ULL,
		0xA14A09224211F82BULL,
		0x61BC81F5183F62BAULL,
		0x791C844FC8B9571BULL,
		0x7E6E5A1652A52404ULL,
		0xB4ABC842A1DEDF64ULL,
		0xF4799BF6DEC70CC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC362AB62793609EULL,
		0x4EC1F483C0BC83CCULL,
		0xEB87D08D1FBF8CC8ULL,
		0x263A7C706250D706ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x092911FEA9F8A786ULL,
		0x7535E955D5BCFEE9ULL,
		0x33F790EA9A1B40F9ULL,
		0xDDCC4D8C126953AFULL,
		0x19CC3E9686C832F5ULL,
		0x80A762C37F033DABULL,
		0xDCF2A6060C198FC8ULL,
		0x2E155001281F0EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6C966ED70B8EF63ULL,
		0x45522DEC3A56DE71ULL,
		0x678EF1DAF1A46E78ULL,
		0x68444FACDA752FE1ULL,
		0x72091B0ABE0F1107ULL,
		0x492FDF69654C4DB5ULL,
		0x3E5688E759E9E7F8ULL,
		0xF575A6183DAC1A66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF956F1D104BABD16ULL,
		0x6BA13AC96C8DBEEDULL,
		0x5794F19E1B89BB69ULL,
		0x5D3B36720504711FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB6FCBA3C81411F70ULL,
		0xCCC32FF4695BE31AULL,
		0x9F84A76B70DED32FULL,
		0xE2E68778624F6866ULL,
		0xEE579BECC3A1B901ULL,
		0x0B3D6E7644B66C7CULL,
		0x54E5C8B8A9006C69ULL,
		0xE6AC5ADCE9FC89F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE498BD43447006ECULL,
		0xD25AE48443AFCD9BULL,
		0x416602E2D5F728B3ULL,
		0x11B6FB4ABD2CB08EULL,
		0xA806A846A322E5CBULL,
		0x3044CB2A4EF64BBFULL,
		0x60268AF4D51EC9D0ULL,
		0xDD03C239BBBCEBF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x426827A20FA472D4ULL,
		0x7B5088B6A030F197ULL,
		0xB281CF9A0E65CD2CULL,
		0x4036346682942AF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x26B304C61C46DD2BULL,
		0xA834B70E69199392ULL,
		0xBA4D44BCC52518F7ULL,
		0x8B3AE947B941EA75ULL,
		0x8DC94628DEB5AFE3ULL,
		0x2EDBE6F0B1B539E3ULL,
		0xB7B14AF9EF88A216ULL,
		0xDE277A3DAEC546C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61723797B8F4BBDULL,
		0xC7BC001A9BB9230EULL,
		0x10723E7F0145A5A7ULL,
		0x68456ADEA0559B8EULL,
		0x7442CF968EFDA751ULL,
		0x2275E37844507956ULL,
		0x29D84719C227A6FEULL,
		0x4F41D437A90B6633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA917B047608DA38ULL,
		0xB79D3AD40A550574ULL,
		0xB81199848044B8E1ULL,
		0x590C234DF283A4A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEBC27DB8A1CD83FEULL,
		0x6A203BB73EC51D80ULL,
		0x99371256D3CFB294ULL,
		0x8A46C0D8545AB2C0ULL,
		0x991D1993BDBACD6AULL,
		0x363F0DD55E11082BULL,
		0x16A644E454DCB6DEULL,
		0xD3A2104CF596E2C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C9427E3F874F989ULL,
		0x86CD7C95C4AC12FDULL,
		0xFA014CA9D2A2572EULL,
		0xEE33DA356553BD26ULL,
		0xECE284243983CF09ULL,
		0x885871677F321A63ULL,
		0x3227940591D07D48ULL,
		0xE95C8855379C1229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FE0846249824C43ULL,
		0xB38DF7708F305627ULL,
		0x8A0406BDF4FDE79DULL,
		0x626515692241EC4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x004E4F458478B85FULL,
		0xF8683332B3ADB4C6ULL,
		0x2FC8D22DEAF09277ULL,
		0x7A7259B0DF917FEAULL,
		0x40C32416C9637E48ULL,
		0x9F5DBE5E37B1AB33ULL,
		0x71C981334097160AULL,
		0xC2C5366C84389067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x919108E8C109A3D4ULL,
		0x9548051B2AD23D56ULL,
		0x1E74D6BBD3EE8217ULL,
		0x83169583ABC873AEULL,
		0x0DD56C719E040E8DULL,
		0x63DC1B4B7D613C24ULL,
		0x4BC88D5999F20168ULL,
		0xBC271192A196430AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE0688E13399AA60ULL,
		0x385E62DF30CBF3B0ULL,
		0xB5782DC0D3832075ULL,
		0x72D53C84D7E0880FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5C77AAAC10083937ULL,
		0xF1E24B638EEF1BEBULL,
		0xC9073BE04EBD74C2ULL,
		0xC21A0AB5FB5342A4ULL,
		0x82741B313C14BFC6ULL,
		0xF80EF963C8D3A961ULL,
		0x8A129A9114631202ULL,
		0x885A9A035C9584E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C662F090D780F1ULL,
		0x17E2E1508A0C2AB6ULL,
		0xA43C581940144C29ULL,
		0xAC801EF9E2127B47ULL,
		0xCDF629F96AA15597ULL,
		0x43A8ECDD0AFB387AULL,
		0x7DFD36944C971A1EULL,
		0xA43037E27A795523ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED63160496527A95ULL,
		0xA12546133303B373ULL,
		0xEFF7BB4CB6EFF48CULL,
		0x73E47C9DA96FDEC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3B607D25C06C6089ULL,
		0x3B103C21C832180BULL,
		0x53EDAF2A508675E5ULL,
		0x6A6AF6C6454DD52FULL,
		0x87F9EC0D50E35FB0ULL,
		0x0BFC1CB8366C16C2ULL,
		0x714A1DFFEC220AA0ULL,
		0x3AE44ABDB907D0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C4FE8DDDAD0CBFULL,
		0x813BCED7003FABB1ULL,
		0x8959FCDDFDEDCBCDULL,
		0x14B7DA3F2B5D7833ULL,
		0x7705559D9A5FC8B9ULL,
		0x74C4983354E26EDAULL,
		0x9A2D0EECD6175DBFULL,
		0x52A3DE71186DA1FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE9D32CFA47BBEFULL,
		0x2C121904426158CCULL,
		0xB8E3EF21982E536EULL,
		0x4F432FE6F0D34E59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAFFAC9D1BFCE346EULL,
		0x7ACDDE6F0CC8C25CULL,
		0x3EFE1442B7BAF57BULL,
		0xCDDB1365DDE9F112ULL,
		0x5E671F72E6ABE8D7ULL,
		0x73874AB041378191ULL,
		0xF3C8769442BBFD60ULL,
		0xCBBF4BBF076146F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE33BC724ACF39DEULL,
		0xF731B71EAF927162ULL,
		0x9F92A75CAA318FEAULL,
		0xEE7B669CF0A5DAD2ULL,
		0x5635F3940C271D7EULL,
		0x19477E76096D35E4ULL,
		0x01FE8149AFB6BDCAULL,
		0xE6074BEE5686FB8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09139073E4B5291BULL,
		0xE91477F4A53D8CA9ULL,
		0x8365D5F7E050D5E1ULL,
		0x78AFA5C32DAB47F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB1B35C54576FE770ULL,
		0xB4F1BD67095869E4ULL,
		0x8A22C4705CB47EA6ULL,
		0xC221DCE5B7851B17ULL,
		0x3F03CA1B2F9193E9ULL,
		0x7FEAB407D9021360ULL,
		0x7DA5ABE9CED94BA0ULL,
		0x5CD278959BAEB27EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169AFE1333ED17ABULL,
		0x383EC76DA3CC79A8ULL,
		0xC8BAAFF3E94A573BULL,
		0x679E2E132F314353ULL,
		0xA2D73C416538786BULL,
		0x14E9CE4A1429EEFDULL,
		0x4BDC5AB54BBA9FBEULL,
		0x1301D8A1A2432904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9B56C952CBCE61BULL,
		0x5ED510249DA156DFULL,
		0x254A2247E9F7AB07ULL,
		0x4F7B6D098E4A3FE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA24B879F8E08E710ULL,
		0x703E28C57A193E7CULL,
		0xFB8605AA0A5853B1ULL,
		0x6B3CB1856BC3D054ULL,
		0xF432FBF57CC106E4ULL,
		0x81D3DEACD9DEF658ULL,
		0xA241E1C4DE50DBE4ULL,
		0x97656D79A5FABF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C77DA3FF2D3703ULL,
		0x551C678F6D4BA9A6ULL,
		0x2D57A10105A49269ULL,
		0x18FE986101BEBE30ULL,
		0x1F6C73C3BDC1AB96ULL,
		0x7820C8D3C11651B1ULL,
		0x582A5246A9EF6E96ULL,
		0xC2A552EE8C5D7433ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1FC415DE8C33CAAULL,
		0x8BB6FF6FBA9605BFULL,
		0xCDADB164CB29FADDULL,
		0x66C209CA375E3E6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x052D60AF5120A42BULL,
		0x8376A151D62877D9ULL,
		0x355A41BE32CED5B7ULL,
		0x59B4BF875D2B06AEULL,
		0x2414103D58AD2812ULL,
		0x48462812B656419BULL,
		0x51124104F148BA42ULL,
		0x1A4CB773FF881E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x459B154CEC74C81BULL,
		0x9217BB82DAC8BEA6ULL,
		0xAA65BCB57EB2909DULL,
		0xC076401AF411CEB0ULL,
		0xC4CD467DC5EE3728ULL,
		0x0AD7FCEB6A187F42ULL,
		0x4641320CEC6AA00FULL,
		0xE4A5FC062D5B5E42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4143DD22D039A45ULL,
		0x0FB94DA44C8A9250ULL,
		0x25FCBDD96D1428B5ULL,
		0x0FFE51B99BBDBF45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x91AE693BBFF9DAF8ULL,
		0xE80C580D7DA0E5EBULL,
		0xCF09058FFFF04451ULL,
		0xD11461ECEC1BE223ULL,
		0xC00DF0DDD49A4756ULL,
		0xCC05A61F4BEB9E80ULL,
		0xD467F3BB4D632193ULL,
		0x1941E60FB6F67610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45F4813350B975C7ULL,
		0x62BBAE0C7E4831BBULL,
		0x490B90F2DA28CEDFULL,
		0xCC59DC7E3DB5F1F9ULL,
		0xACA1109FE599D825ULL,
		0x84727E6887188E2DULL,
		0xC9B988C7224667AFULL,
		0x87EA3647612ACDFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DE33139E950E404ULL,
		0x25288F2236AD2085ULL,
		0x1BE154DB8C0B0D55ULL,
		0x17BE9D2B6AA0E2B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x97659EFE40960500ULL,
		0x69D9A551752B1A09ULL,
		0xADC593D029891F82ULL,
		0x0B25021059C485E2ULL,
		0x65EF7F6C6F24CD3EULL,
		0x3DB56CCD15AAD5B6ULL,
		0x7A20432A99357C0CULL,
		0x3BBF800FAB0E5F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED26264364DE80B2ULL,
		0x17ECB4330BB24586ULL,
		0x15759FF6408643BAULL,
		0x13AC41CEF6CAA295ULL,
		0xE6BF499813B974BEULL,
		0xAA410C31BDA23674ULL,
		0x61981025024D8F53ULL,
		0xFF2E7C83241C43BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B6776406DA6A2EDULL,
		0x3533482D7AC0783BULL,
		0x3C8786AE4F6FFF2EULL,
		0x74FF471D6AE9FDCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE035A5D0CEAF8A3EULL,
		0xAAC04959974BA68AULL,
		0x5C7A29EE8443ABE0ULL,
		0xD33BC2A0FE7467DCULL,
		0xF5540DF295134692ULL,
		0x9DF13E034B9972C3ULL,
		0x83FD866C167BF142ULL,
		0x247325DD96C27D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA0F89BBE432101CULL,
		0xE789AF48B57E3DECULL,
		0xA9572E1FE87945C6ULL,
		0x3DED2E1A360C5FA7ULL,
		0xA3343063D3D6F99FULL,
		0x021E11D148AF983EULL,
		0x842B98D9BCF2F0C9ULL,
		0xB0773E72B96CA1F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66E0FF459970E329ULL,
		0xE48F297D5083D868ULL,
		0xAC4C3F87E6207826ULL,
		0x4CB2EE63A3269B6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD8C741AFB29EC6A8ULL,
		0x043B188B51363260ULL,
		0xFE6468BC557B1089ULL,
		0x6C80775B2902FD02ULL,
		0x12B85158A5266ECAULL,
		0x2033F82CB33AF57EULL,
		0xF588D926FAA4AD9AULL,
		0x7FF6001750507B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50437FEF29330328ULL,
		0x3B4C79BFEC4C64E0ULL,
		0x5585B362C9007897ULL,
		0xDA30E7706BF91046ULL,
		0x5FE1B26841707C5EULL,
		0xC7EDD920F67CD31AULL,
		0xFAEACA5A98E23205ULL,
		0xA395EA787F655E1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x145F596F566DBEA4ULL,
		0xE3573A896922E84DULL,
		0xDC54E7B00F58EFF6ULL,
		0x4892C57DBFF03B53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF6AA85A0D9102FC6ULL,
		0x8551C587B891E27AULL,
		0xC103DCFCACA6831BULL,
		0x6E1A163F8FA544E7ULL,
		0xEF99C85794418607ULL,
		0x3F00AFF0B46BBBBCULL,
		0x25C13E8606E49DE4ULL,
		0xF4E0C4DE7C4CB185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3E282126C539500ULL,
		0x6E14D7F0E02B3576ULL,
		0x899782C6B421262FULL,
		0xFA28AB1D8972C8EFULL,
		0x849DA0A8F25579BAULL,
		0x5B7D0039292E7ED2ULL,
		0x1555609B57FA3161ULL,
		0xB179FE3C6BFEC040ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF435E77A75C66F8AULL,
		0xDCC902D5837DB7CFULL,
		0xA76F4B0BEF517859ULL,
		0x7532E73071C44C38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x78DA164D947F648FULL,
		0xD642FFC8CE44ABC7ULL,
		0x1D7DED41E2DFDE99ULL,
		0x71248754F3E31A92ULL,
		0x645B1EB47E3436D9ULL,
		0x6B286716E20AA1B2ULL,
		0x234A436151746F7FULL,
		0x6B9EC9A8F7C673D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BA955B298C0C3FULL,
		0xD5A9B58C97323DEAULL,
		0xE477FC37C3BA0A90ULL,
		0x936FCE34D1C11C20ULL,
		0x1354AE76394A14EAULL,
		0xB36D261834EC8E5EULL,
		0x7527B404B4D0444FULL,
		0x60B2114D1284CF22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B142A30A5B461F0ULL,
		0x4664F009E9894C61ULL,
		0x122738C95F843D1EULL,
		0x7CD816C429E070D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE1A02874C7081BCAULL,
		0x3542647F5E1E442DULL,
		0x229EA1DC710D65EDULL,
		0x610B8A41DD6EAE2EULL,
		0xD0017942317A6D4AULL,
		0xB1D1C279C441D15CULL,
		0x3272943E7C7CC925ULL,
		0x01F767427F70065FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61153296D7F37A01ULL,
		0xB3CF4150742D5980ULL,
		0xA5DD282DCDCB8478ULL,
		0x86E2011B247E5937ULL,
		0xCB106F15C5B30724ULL,
		0x1BBA157DC517EF60ULL,
		0x1DDCB99FDCBA8939ULL,
		0x3C20E70D40FED9C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C527875EEADCA17ULL,
		0xC8F6D096CA287616ULL,
		0x8AFFED3A5A175E92ULL,
		0x3800910DFDBCF46DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x551AAE606FFA6603ULL,
		0x4A1E3AF73A6D2B52ULL,
		0xD91EDE249C687CFEULL,
		0x9A62999D72DF34EFULL,
		0x7D87B2FCFEA7CCB8ULL,
		0x4F6B64C474328B9DULL,
		0x52EEEDA184244A26ULL,
		0x15A258D30EC26185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF355008FBB1B0FEULL,
		0x741FF309EDC391B0ULL,
		0x18F57369FFA541F2ULL,
		0x338B7C24C42A05FDULL,
		0x947B274DEE87B88EULL,
		0x11BA8D97CF591956ULL,
		0x182DEF6EE27E4643ULL,
		0x58C08FF3A1C6CCA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DC21A53D90BB1C5ULL,
		0xFE3E388DC4F09028ULL,
		0x78CF263E9B67CEC6ULL,
		0x705AEEA2DC0D4815ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBB309E6BA9581FABULL,
		0x955A18AD0018C071ULL,
		0xF68985FBCBD31022ULL,
		0xCD4F2C202A519DFEULL,
		0x2CBF09AA2AF62A51ULL,
		0x5427DCB7F834881BULL,
		0x72C1F9DF0E0ACF21ULL,
		0x994093A48291A870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2393790774167134ULL,
		0xC481F313D91946AAULL,
		0xE28BB9121EB52425ULL,
		0x7FBB3416E87DAB68ULL,
		0x7004FF9ADBB0A975ULL,
		0x4FE6944E2388017BULL,
		0x08CE709F81B5810EULL,
		0x31A75E06DB60DCBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B3AA3A9F992D16CULL,
		0x7288E54EB89B757DULL,
		0xCE242C5881C782CFULL,
		0x2E51ED7013122F83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA4B632E6CE2C36EEULL,
		0x1DE666ED2DAEAF36ULL,
		0xC17E62B98854E794ULL,
		0x83FF144D1640D4AEULL,
		0xD3B37F5EACD12349ULL,
		0x85A7DAFE79C19346ULL,
		0x8BC9FC58A90CD094ULL,
		0xAFD908BAA7E7592DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D4C5CE4754690EULL,
		0xFDEB35E637364B27ULL,
		0xAB7B4A1ECB0A2476ULL,
		0x893C146A34709416ULL,
		0x64D901FA8AC0CA86ULL,
		0xAAC939C5CDD27D40ULL,
		0x904096C33B54B8FBULL,
		0x70FEB432FC9AB742ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x565009F59544FC28ULL,
		0x9D071F707BF5A903ULL,
		0x6C682CC9069E43CDULL,
		0x4F2B8C064F304979ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9E92CFF700C917DAULL,
		0x8909E2632131A3E3ULL,
		0xCD3CDE89C007974BULL,
		0xF1003FD6B00B23D4ULL,
		0x08A3D9EB5909E4CDULL,
		0xBFE9C6BB90C64717ULL,
		0x5F91E95F38260FC1ULL,
		0x7371EE72C3819375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99C3F8AFF684D299ULL,
		0xB2D6DC8E899E13CCULL,
		0xB6CDB912FEB91DCFULL,
		0x57A657D0E2D4BF14ULL,
		0xBBCD1A450CAA964DULL,
		0x0BA35F10AAAE5C74ULL,
		0x4501147F00A3A63BULL,
		0xDFF0DCEEC8511115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CAF49F66069E9E1ULL,
		0x98A66932BF20642EULL,
		0x07EEBEBEFEAA237AULL,
		0x7E82819D1669BF04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB01E427A9A5E6009ULL,
		0xFCEF89C2F566BA7EULL,
		0x3A688A80D1D67CC7ULL,
		0x63814B25D995AE58ULL,
		0xE8DF7998A9E38E07ULL,
		0x443091A90D33A247ULL,
		0xFF6833046DA962E5ULL,
		0xF901369B1866C953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB43A26C0032F91D0ULL,
		0x5C4D63F41632547CULL,
		0x6ED330A35932C722ULL,
		0xF04547342B9F87F6ULL,
		0xEC8EC2CEB7266780ULL,
		0x06AC9879EDFB3A44ULL,
		0x4DA994A98DD02654ULL,
		0x5CCD3566D68ACD5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FDF3DB49F42899AULL,
		0xC23922CD8193D673ULL,
		0x2DE0DB5AB2E2B334ULL,
		0x22F431B3749D8CB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x46427A0D9EF1BCD8ULL,
		0xAF58EF4C144C3062ULL,
		0x16968603624D54F5ULL,
		0xBF298459CCC745F5ULL,
		0xFF935299D7ABC57AULL,
		0xD4C37DFA1D04C9A4ULL,
		0x00B7E77AEEDBD152ULL,
		0xD4EDA7B0F879CF0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2B9039CBBA0B76ULL,
		0xDCBE75D6E7A0A433ULL,
		0x163E6D677D01B61AULL,
		0xE095A053359E325EULL,
		0x5D5CF9A8E240BB60ULL,
		0x654F7C7579CB7819ULL,
		0xEB574C0D2C15CA0FULL,
		0x9C9E375EE2B57109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D281D98411B326EULL,
		0x5DD2B325672DA6E8ULL,
		0x2CAF2AE6CEB0B2DDULL,
		0x3A5E9035D24F079AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA315803761DC067CULL,
		0xEC6E7365790E3746ULL,
		0x21ED227F757CF919ULL,
		0xA993D305532876C6ULL,
		0xE844BA934C6F4CE2ULL,
		0x3999ECB172D8E26BULL,
		0xE74995E997AF6FBCULL,
		0x5D6FB2BB4CB3B3E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E819A0B36CF0789ULL,
		0xFE3B6FCC54C22D42ULL,
		0x8E1AC53509AB3160ULL,
		0x8481DE8B9B147ABFULL,
		0xC7370C467343BC15ULL,
		0x00D12C38C7552AC6ULL,
		0xAFDB987C07A62572ULL,
		0x51404925BABF913FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9BC59467847D9AULL,
		0x5BFF958299D94C87ULL,
		0xCE25FB8DCD32CEBDULL,
		0x741BA0AD625120B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x43EFF05F19858E89ULL,
		0xA07CA7BDA8599847ULL,
		0x279C5D0FB851E839ULL,
		0x1D7F96E4AD724D80ULL,
		0x0C86525243C10198ULL,
		0x3D3A140226D9E568ULL,
		0x3B3170C32613682CULL,
		0xF7765A3B010041A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67084F34C6F47950ULL,
		0x48C40888180B5B8BULL,
		0x3FC78F4660C5EA5CULL,
		0xDDE959EC059D8C47ULL,
		0xDA9DAEF5245FC67AULL,
		0xDFB1115E10B19F40ULL,
		0xA3DE293C73E08274ULL,
		0x7E97899377466263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x456FE0FCFAFFDE33ULL,
		0x3A0F0390DA48A68DULL,
		0x5E316BC7CB1A1715ULL,
		0x30A935D7196BE58DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDE066B09524AE329ULL,
		0x8EEBC19CEA5C8511ULL,
		0x429F50A26FCE44D1ULL,
		0xCB07EE80156846E1ULL,
		0x0F550487288BD61CULL,
		0xA6BC6497B8DAE60DULL,
		0x2F9CE20A25F2A60AULL,
		0xF24AB8BF8977CF86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9713416EA8D5978DULL,
		0x12CBD4C0B82B4E90ULL,
		0x80427E819543040DULL,
		0x2ED2688B3AB07856ULL,
		0x4EE4EA69825A3D93ULL,
		0x9C2E3FF5616B7983ULL,
		0xC739F28100BBDF06ULL,
		0xAFDEB32BE63083DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7970A0154D1F16EULL,
		0x0D395CF52CBB52F3ULL,
		0x410C607C60ACCB5EULL,
		0x783E59DF174D09FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0F4AE572DF08FD11ULL,
		0x39558003956186DEULL,
		0x91A06F88007CA2C1ULL,
		0x0498765C8B09AD57ULL,
		0x800CF26B4EDF4354ULL,
		0x4464AEFE3D007B68ULL,
		0x0D29D02A5A3E856FULL,
		0x66FCC7B4DCFA9917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B2E4684C8C7995ULL,
		0xBEE3F62FECD5E494ULL,
		0x451E241FB8D6417BULL,
		0xDEF1CC4E4AD0D75EULL,
		0x7679DE041F2ED126ULL,
		0xE2FB6903544E2B88ULL,
		0xD38035DE3B8C3926ULL,
		0xDCAC58ADBB1A4221ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x186D085BA6AD7391ULL,
		0xF011ED1233037D8BULL,
		0xDBAF32B4D61DB403ULL,
		0x2D97251D4785BE5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0330D4C588057501ULL,
		0xAE71A7C92A8C4BD6ULL,
		0xCA49EDFBBEDF0903ULL,
		0xB00507D035E47EEBULL,
		0xA7DF5B5393E27E44ULL,
		0x2BE53F97D04A8E3CULL,
		0x275A8F3AA317C7A7ULL,
		0xC5F9A336EB4B05E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9766FFF88A98BF92ULL,
		0x95E98B11E5013442ULL,
		0x91630CE8C3D2834EULL,
		0xD7793B1C9EBD07F8ULL,
		0x8ED2EDC28548CACFULL,
		0x66BCE6F0FD5E634BULL,
		0x9625CC9C81DAA56AULL,
		0xA4073B7668A41EC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23A21855283D5978ULL,
		0x5C85457A9499775DULL,
		0xC6BBC48BEA1F9ABAULL,
		0x62873346FBEDC4E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFA69F9E1039B5079ULL,
		0xBBAC61F54FC924CDULL,
		0x324EE15BF0129253ULL,
		0xC56F821A6F7FF789ULL,
		0x662C1905C55D5E08ULL,
		0xDF32FDCCD2CD18DBULL,
		0x929BB2761B53765DULL,
		0xBBDEE2C0CABCE7A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A90B80A64039F5ULL,
		0xBAFB9227582B3F17ULL,
		0xB8815B6B4CA2D3DBULL,
		0xFC725D2E43C54863ULL,
		0x3D67B5CFA5489790ULL,
		0xE539E146F423AEA5ULL,
		0x6A134F36BA9FADEAULL,
		0xEA0CD2E9AC929206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5E7A86920708B37ULL,
		0x1BAB0BAD04C3A9C0ULL,
		0x7E0C4158FE1F7F89ULL,
		0x6E2B7EDAA6036407ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAEC192476AA417FFULL,
		0x4016A0B9333D80D9ULL,
		0x3EDE7B5579C662B3ULL,
		0x1D667CD680A2FD71ULL,
		0xA17DC830AA3E9647ULL,
		0x2CBE063CBFB56ED1ULL,
		0x53A3E0CEB386B552ULL,
		0xA3C1AC5E6A6F0C4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x776C4407CA69722CULL,
		0x8C716E127EBABDA2ULL,
		0xE2062088F129E816ULL,
		0xC7D8BD945004346CULL,
		0x8E8DC62740EA7874ULL,
		0xBD86F07DE6F22EC5ULL,
		0xD703373D20AF2D05ULL,
		0x217121E2AE8A8B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06F59BA542B715E4ULL,
		0x35D26CFAE17E4502ULL,
		0xDCB18668549AB5F5ULL,
		0x2D824DA01489EAC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3B14AD7CE953C062ULL,
		0x1BEF519ACD8C0582ULL,
		0x2FDBF8B9AF93BB07ULL,
		0x8B4F93BD2A70ED56ULL,
		0x9E719FEC724D33C5ULL,
		0x749B38C040359BD6ULL,
		0xE2D0E1F3280D8ADCULL,
		0xA8EAD6F6A15E5957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA669AF7B6A1FD7A6ULL,
		0x22AC2528E86FFCE1ULL,
		0xE3FBD8CC706159A3ULL,
		0xB56468E8218DCC0DULL,
		0x24D3DD6935207D30ULL,
		0x61D325D14BE4E1CBULL,
		0x87E5BD73DF454C0BULL,
		0x154A2C4B8594F219ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA215DD7C93D7060BULL,
		0xC2F5FBEA2917A654ULL,
		0xCAC78AD20CEBB46CULL,
		0x3FC4803B28C87489ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x40B6D488401538C3ULL,
		0xDD3AD2ABBAAE5B3AULL,
		0x1E5046DF081F2736ULL,
		0x639172E1E23C29B6ULL,
		0x6DB3E1773799199CULL,
		0x926A575BBCE8F0D8ULL,
		0x8D7633D633106956ULL,
		0x055C2C3C7C3575E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD96326988B312C4ULL,
		0xF7D45929EFB1E0F7ULL,
		0x57AC814BB21C8C40ULL,
		0xF636DEC272A8E4A4ULL,
		0xC2CFF188729B58CBULL,
		0x78E71E3A97D96F56ULL,
		0x876F839928B090BEULL,
		0x14E01E75C82A9298ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0F63F8FF50CC493ULL,
		0xAEE0F46D4B49B381ULL,
		0xABA1EEA2E03CC189ULL,
		0x1FC49F9E29310280ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1282AAC2D875AA4AULL,
		0x6EC7F2AFA09C888DULL,
		0xE64BA60628F21158ULL,
		0xEDDF5A60E5053397ULL,
		0x3580AE910676644FULL,
		0x8965CCDD61CD9919ULL,
		0xBEA91D8904115B36ULL,
		0xE35EC366A256D55AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EA27BEFF1A0864ULL,
		0xD0128BDE7B6B823CULL,
		0xDE527C2F09282432ULL,
		0xA6206BD4F4CDE7BCULL,
		0x46AB6788DFE4EB5AULL,
		0xE6EBD4AFA67BBAB1ULL,
		0xDED3D9FE62118276ULL,
		0xC13EE79CF4B887ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0410E3992F39702ULL,
		0xBCD03D9AF35809BDULL,
		0x41A1306B2BC41997ULL,
		0x58798E7BB5B6CA2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6C60D2779BE70D89ULL,
		0xCA601DA9EEFE149CULL,
		0xD83CE99C166FC5B3ULL,
		0xAD96BF3A81D76E94ULL,
		0x2E24F21E9044D939ULL,
		0x953B52F3B630BA5BULL,
		0x7F9BBA2C6FF98BE6ULL,
		0x01CCFFD257BB4E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605A90D9C0016AACULL,
		0x6CAEFC4D089FEFCCULL,
		0x535E39718AB40537ULL,
		0x0C83D82581DF6635ULL,
		0x923C03B69ECEA773ULL,
		0x3BFC76350D5DA4BDULL,
		0x9CA0BE3146EC345AULL,
		0xDE02C24F9357A552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3099A50BB371016EULL,
		0x9D05E5A9F5B35A35ULL,
		0x36201772A3B6BF51ULL,
		0x7118087E26C31339ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9B1F44D7183CB78DULL,
		0x314EB7007389281EULL,
		0xB3EB1416D8333A94ULL,
		0x65BCF48C21208B16ULL,
		0x6FC7566F7A4640FFULL,
		0x4B6D8AA152CA8D90ULL,
		0x346AD7AB9D1C9684ULL,
		0x5C843C8B83BE3179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9006429B3B766585ULL,
		0x4999A08CE066DB7DULL,
		0xF1A76F9714AF2F85ULL,
		0x60503F4D4C4C95B6ULL,
		0x3081F9A687BEE20EULL,
		0x81A8BEE640C2551CULL,
		0x7EA998ADAC898C4DULL,
		0x9911B576510D2632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F64C80FDCDE6878ULL,
		0xDAEB5438405AADE2ULL,
		0xBCF2FE3179578F30ULL,
		0x086CC2645B1BA1DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1869D2212A5243B2ULL,
		0x5C16926CAC1515C8ULL,
		0x7427AA1E1035BC2AULL,
		0x929E7EE523C8AB5BULL,
		0xC838E6AAF1A68C30ULL,
		0x01E4F21216BB234EULL,
		0x8142FC70790CBB2BULL,
		0x0C4AB3D600F9B6CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79CC5F60634E830DULL,
		0x31ADC959752B5963ULL,
		0xF0B4F18367183E51ULL,
		0x861D41B7B419AD17ULL,
		0x5A437A6DD34C62F0ULL,
		0xA1952473122665B4ULL,
		0x28F9D5929F1B2CC8ULL,
		0xA9D95385490F1414ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF10B83D34865DCA8ULL,
		0x76414EADE4FDE150ULL,
		0x9E4E7D8902F8A073ULL,
		0x29558928BC8325ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x14F41E9AF2683DC8ULL,
		0xCF3670D74B1904BDULL,
		0x19057F0A7AFCA62CULL,
		0x1C9FF0C1F71040A0ULL,
		0x768A06A988FFF93CULL,
		0x4B94D4E626573F13ULL,
		0x5E9A9AACD61E67D5ULL,
		0xF0C4C63CAF8D73B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFEE3AC2EC5A0E6AULL,
		0xC5E9F0773ED7566AULL,
		0x525336B48F0936EFULL,
		0x49418E8D446CB79EULL,
		0x7A9971C3D9DD68B9ULL,
		0xBDB31B75712FBB6FULL,
		0x2D1E0064CC04EE88ULL,
		0xA0861BCF2B3E6287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ABBFDF0052FA485ULL,
		0x18CE071AF01F38A9ULL,
		0x1F312F076BBB709AULL,
		0x3CABAE765660156BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE766A939583D2D19ULL,
		0x8FCF42087A1A14F6ULL,
		0x7F7C2E85A8E4B363ULL,
		0x84BECCD2785C15DCULL,
		0x387189DFB93A68E8ULL,
		0xAE4ADBE3C3834C7BULL,
		0x3D9C365E664C2C11ULL,
		0xE3132AEC73B92529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81A0D9DAA301A014ULL,
		0xC9035B8AC6A98F5BULL,
		0x7EB09F2A5F137949ULL,
		0xA7AB452782422B23ULL,
		0x10F29ED9A60549B1ULL,
		0x0960C9F8BAB0E242ULL,
		0x15B30734BED2709EULL,
		0xB9C04FF20B6E1884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x429CB2458F1E3000ULL,
		0x418A8F6102AC4A17ULL,
		0xED688F8A25E30D44ULL,
		0x7F6008D6713DCB3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD4AEB268B2D4500EULL,
		0x0DE80F3199F117F5ULL,
		0x33E5CC13FDF8824AULL,
		0xEF5EC023D051380DULL,
		0xFD49BBAE4C0E6745ULL,
		0xAAA443EBDB388799ULL,
		0xA8A56D73377DE792ULL,
		0x0388CBCB68EF2C44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C8CDFDDE50AF73ULL,
		0x831EE7E6700264A1ULL,
		0x7D733411B2C83D4DULL,
		0x82FCEC4F7FDFCDF2ULL,
		0x7B2F6DDE5B934B1DULL,
		0x1AD5FF3A26A587A4ULL,
		0x518FD3A96FFEC858ULL,
		0xDA6484A6A2953D49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFCD714886C9C9DEULL,
		0xE36759ABF7C0B1C5ULL,
		0xA3A76BF5E80EE7ADULL,
		0x07C46349C1CAE369ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE3C656DFC0699425ULL,
		0x13DA6BB2D03D5A45ULL,
		0x88C68E9E119F2A65ULL,
		0x20ED6AC49BD728F0ULL,
		0x42733050E283CF1BULL,
		0x7D2AFD46C0E6A555ULL,
		0xA8BC233E87731ACDULL,
		0xEB459317103E4A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2129815A20E5A49ULL,
		0xFBF98A794965F4F1ULL,
		0xDA99582B953720EAULL,
		0xECF5E5C2E07836C6ULL,
		0x69E86DAFCB4E1100ULL,
		0xC5D0487AA0613BEDULL,
		0xBDB628C899AA769CULL,
		0x9AFA5299C6120C46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x564CA2B390557380ULL,
		0x4F57B7865AA50ABEULL,
		0x911063F3C83068B5ULL,
		0x1F23179ABDF02F5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4A97F8720AE5165CULL,
		0x9A3C71C692B1A7A2ULL,
		0x0603F07A8A99FC90ULL,
		0x045427070FA8F4CEULL,
		0x967D45D108A76A61ULL,
		0x647EC6B742E95619ULL,
		0xAA004C97D766F658ULL,
		0x363B9B5951BD52DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF14606F01B93B2ULL,
		0x8693A698C1A8DDBEULL,
		0xE362346DD6952EAEULL,
		0x4FB0DB89375F1213ULL,
		0xD0291744AD573BADULL,
		0xFEF69733F89AAC31ULL,
		0x6C948BEA9B68E745ULL,
		0x9B187A23A78514CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC259B40A8B06F15ULL,
		0x25DFD8AAD8B6024AULL,
		0x40A055C39BBB0A9DULL,
		0x3BDA39751CA3188BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4C75132BF846D36FULL,
		0x0D5C83E21DC28445ULL,
		0x82F8B68AED367C5FULL,
		0xDA222F745FF8AD36ULL,
		0x5A868CAB58A8DE39ULL,
		0x3439CCB9DCBCE2A5ULL,
		0x43873DB4B75BF369ULL,
		0xAB4F0FA2F4160115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x788C694DA9FC8040ULL,
		0xC603E56B5A6C7BFCULL,
		0x55AC7C6DD603AE00ULL,
		0x8B61017715DCF3DDULL,
		0xF24A114CBEE9B7BAULL,
		0xDBCFEC292C446DE4ULL,
		0x6C5C36F879A8B8CEULL,
		0xF3EAE35955099702ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CE2F9E920AA087AULL,
		0x670FF3F0F5375CD8ULL,
		0x1DAF3A0E3FCD8147ULL,
		0x079FC0EAE5F37825ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE004C514EFC2158EULL,
		0xCC232F4A3DF2A172ULL,
		0xDB447BC012D4DCFAULL,
		0xC909B79D1CAC86B0ULL,
		0x1EED2FE749DECFDFULL,
		0x93D434A9B37758C5ULL,
		0x01C2EB426D3F4087ULL,
		0x2627566D39A01D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E5D68B409E24FEULL,
		0xE016153175AA9411ULL,
		0x43AE64C4B331F9DDULL,
		0x3891DA0F94C664F3ULL,
		0x5B62FCE785C68C1EULL,
		0x005CC6DF5A8C9238ULL,
		0xA1FF8966CD067028ULL,
		0x93BAA67DEEB29D4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FA28080CABDFCD6ULL,
		0xCFC76621FB218646ULL,
		0xCE969D952811D14CULL,
		0x4C99FB12A7271EADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB4A02BC68AF97D07ULL,
		0x5B7DCE888E14E2D7ULL,
		0xE35AC959992D4275ULL,
		0x394BA2AADBB317AAULL,
		0xDA7B77FA3FE37DFFULL,
		0x11C0C9FE44FC71DFULL,
		0x859EAC290CB7A163ULL,
		0x85CE8F55B2A46C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED958E5CA2E47CE1ULL,
		0xB753D2FEFE373F98ULL,
		0xFBC36141089FC423ULL,
		0xE9762A8D9105B418ULL,
		0x3DD0BF57114BA742ULL,
		0x5BEB45A981C83540ULL,
		0x5A97C935BD4ADEF0ULL,
		0xB445CDAEF1E14212ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x086205A2D29EDF04ULL,
		0xA1DBA01E899EA2F0ULL,
		0x4A9D18365AB25B58ULL,
		0x6A2236DDE7A5A0A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFD166CC06860D289ULL,
		0xEC76C07D87CA1300ULL,
		0x6261493187DFA9C5ULL,
		0xEDF7E99802CB26CBULL,
		0x66B8539A66C3250AULL,
		0xF846C3B84D85940CULL,
		0xF859C49DBDE92DD5ULL,
		0x0C22D4DE92EC1251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1453D7D9913D1332ULL,
		0x7234F34896081A70ULL,
		0x41F616D8CDF99EC7ULL,
		0x653E41143622BA22ULL,
		0xA256BEB2BCC9ADD4ULL,
		0x451B7B4D797CCD47ULL,
		0xCDD55DB6DCB05536ULL,
		0xFF39077121FCA889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F3EAF4A122B6C03ULL,
		0x12AE8D106B0F79C6ULL,
		0x7012789E285632B3ULL,
		0x736E26C29032205FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x240852D92F454615ULL,
		0xCFE0AAAD46CE51C1ULL,
		0x3D52EC6985398D05ULL,
		0x73D11B4BF74C6DC7ULL,
		0xEBC7070D1E061ACAULL,
		0x84762786BCBEE524ULL,
		0x57D839431B23C71AULL,
		0x6B3054618C43E675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA06B4BD738800E8ULL,
		0x5E33EB84014D19D1ULL,
		0x3A1621E7773298F3ULL,
		0x70C86835740EBD1FULL,
		0xF84FDE02634542A8ULL,
		0xB78B94A2C08DFAE0ULL,
		0xAAF50EAD0783C345ULL,
		0x83DFEB8B965E4694ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DB1B5B3745D59A1ULL,
		0xDC7E8D00B4C3FE05ULL,
		0xACF51CC8F7C785A8ULL,
		0x58F842D903536C01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x64E5AB45635D907FULL,
		0x7DD9DD6E70CA0706ULL,
		0xCA1546BAE3C51873ULL,
		0x5491491031733728ULL,
		0xBA1E3B0F42BE394DULL,
		0x4A64AF801AB25484ULL,
		0x620F77150EF66E6EULL,
		0x3061DC897D1FAB08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84EAE70204939738ULL,
		0xB2DCE02799DDA992ULL,
		0x2EF3B05D4783E7CCULL,
		0xB4F6FD8D6B4ABAB4ULL,
		0xD6B66FE252D7EA6AULL,
		0x92A87D01F7D1F575ULL,
		0x92C511D533DC0154ULL,
		0xC756B7F004937447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA162ECEEFAF9AB8FULL,
		0x10EC7C00043A79A9ULL,
		0x602C9DD8222D6278ULL,
		0x3741BA4AAAF89D13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEF4F15594C3084B0ULL,
		0x04D0208CFEEB7121ULL,
		0x262DFA27710F9B85ULL,
		0x3022E2B0406D25FAULL,
		0xB290F08E0C9D8866ULL,
		0x4778AB5184650D64ULL,
		0xAD9377F7E348C956ULL,
		0x51567A5BC3378ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0C8328FC58C67CULL,
		0x4BEDDFA4642D389AULL,
		0xF2E032C78EC381A7ULL,
		0x2BE306D551943AB9ULL,
		0x0F3B923E7C92E71FULL,
		0x01D97DC38F0C5BEFULL,
		0x933268D5B96F2734ULL,
		0x9459D5FB1B6930C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EEE91FFB16BAD42ULL,
		0x0E8303FB05E88FFDULL,
		0x1DB60672189A2AF4ULL,
		0x11C04233D77AE1CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA30FE4239C3A48B4ULL,
		0x12C395770CEB85D3ULL,
		0x12D1DA0119E21962ULL,
		0xC05FCDAD4526792CULL,
		0x50682E446A03A136ULL,
		0x11C1A9CC061B2137ULL,
		0x998832B033F485E7ULL,
		0x96D97D6B6EDA63FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93780E0C73A8B084ULL,
		0x79626FCF2F468EB7ULL,
		0x26937E2FF403489FULL,
		0x5286E145F34B943EULL,
		0x7E1304B0817B80AFULL,
		0x2F7B468EB9E06F9EULL,
		0x52C6CC2EC36AEE97ULL,
		0x0EF128C30D7E3252ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x483C020BACC66F45ULL,
		0x2FD3E0C12E5B53CBULL,
		0x6CF39307DA4B469EULL,
		0x1A557D65C58A445AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE5F5EB3BD65294DCULL,
		0xC86BE34AD5810DC4ULL,
		0x6976486CD295E5F4ULL,
		0x307AF1F6B6A56F5AULL,
		0xD041C277CD9438FFULL,
		0xF5403BEFD8EA4C22ULL,
		0xB7BA19D2ACC19F52ULL,
		0x5261BFCB958C1929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C46337FA044DEBFULL,
		0x0B97E68D8058AC02ULL,
		0x11DA8E68A4E9626FULL,
		0x3A5819ACADCF5239ULL,
		0x310D09E5DFB083FBULL,
		0x0D8D7BA30CBAE93FULL,
		0x19242F1BBFFE0DEAULL,
		0x48A3DF913A35526AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB831D6585DA94DBULL,
		0x215C8823A4310F8BULL,
		0xE1DC912B52B41918ULL,
		0x685220F397B79D92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC04949090454AE75ULL,
		0xBD224BA54611105FULL,
		0xC6AB0B4F713E3371ULL,
		0x90A964284E64701FULL,
		0xEBA2FBFE789630C4ULL,
		0x1FB869CDE4094268ULL,
		0xBC0B7B5C604462F9ULL,
		0xFCC6389C5D6C7F50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044F3F2B2254EEC9ULL,
		0x37E072310FCA8666ULL,
		0x91A295E84BFDF7A3ULL,
		0x5E17473C9B984D8EULL,
		0xCEA461C815F48301ULL,
		0x9C38071E2A64A6A0ULL,
		0xBCF0B77A071C6C28ULL,
		0xD23CB0101680EDCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09C4EDF085FF8B95ULL,
		0x0A507F89C4B5A9AEULL,
		0x13018900612EDEC2ULL,
		0x02FC61BE39C3BBB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x365FFAB018D59823ULL,
		0x262F80B9198AE1B3ULL,
		0x18729C203B4FEA4FULL,
		0x198CC06EDD1B1908ULL,
		0x669A67C665E2C48CULL,
		0x67C54C8200547231ULL,
		0x4BD3341988707CC0ULL,
		0x333B20C3B6B279AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6465826FCC6D5368ULL,
		0xF8C75DFE90BE42F6ULL,
		0x3EFD80A6FA7693D3ULL,
		0x3D2EE49B6D1621CBULL,
		0x8433DBDA2B3201D1ULL,
		0x5308E2F4C3186B96ULL,
		0x1B8CFADC89C5D0CEULL,
		0xA352ECD60C22589BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D333D5102A529F7ULL,
		0x415FCDB19FB599BAULL,
		0x03E19A870E2EDC6AULL,
		0x38D5911AC169DF7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE905B80DC9996CC7ULL,
		0xE8D578CDE3E62B2BULL,
		0xE9F396893BDF3C31ULL,
		0xFA91F47EC3ED9D80ULL,
		0x5380E4A3C4D76199ULL,
		0xF058D0A4939465D9ULL,
		0x97B882040454DB4CULL,
		0x665611FF8F3D1A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9714121711CF8CCULL,
		0xC29811F1C981D25CULL,
		0x5B1CB075BAD956CAULL,
		0xD62286237A92480AULL,
		0x97539BE3BBCCEDD3ULL,
		0x790A5D7ED3E0B661ULL,
		0x3F7DE5E1CEC5A48CULL,
		0xE3A07E1B09778C8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E4D436DB009A0A0ULL,
		0xDBE27E768F106495ULL,
		0xA78A1327744805F8ULL,
		0x0B63624724AE6723ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x095C1A28901B55B1ULL,
		0xE6E413150479E051ULL,
		0x85625C849B2E3EADULL,
		0xE732692E4C335DD6ULL,
		0xD78DA5E21380DA4AULL,
		0xFE7F898466929C3CULL,
		0x4C4F157190701958ULL,
		0x812FA09006BC9791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F71CDA43214D61BULL,
		0x3A3C3ADF24AF259AULL,
		0x62288340E5338F4BULL,
		0x3773CD479ACF115BULL,
		0x71C5B806D06899FDULL,
		0x6D11EDBA082E0206ULL,
		0xBB6C5E5859152D12ULL,
		0x4DF97F7187980518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5979B1053A00C34ULL,
		0x42ECF83FE2B99EC9ULL,
		0xA4E10701ED79C1DCULL,
		0x49C7866D90D20A60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA986A2F92EBDFC4FULL,
		0x5F943C8E4E5DA10EULL,
		0x235BD91647EE3E47ULL,
		0x1B48B8A483EC66AFULL,
		0x390A857CAAB3970AULL,
		0x8137D43220E588C7ULL,
		0x57684996952A8E6AULL,
		0x51B288FB699C25F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C89EA5760CB827CULL,
		0x7C3113B5AB72AB6FULL,
		0x2656E4D9E275E374ULL,
		0x883B393CA0EF0D8CULL,
		0x74EE4DDE6A6282FCULL,
		0xE034CA826B715704ULL,
		0x0F649C8D4A28E56AULL,
		0xDD88D32B0765150EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x892CFA1F59FB70B6ULL,
		0xC9D698ED922A5888ULL,
		0xAD90A39D87B770C4ULL,
		0x513E7C567729DADFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCAEB5BBB8A982AF6ULL,
		0x13D33D453FF35108ULL,
		0xA8449DF9F81EFDB0ULL,
		0x330C1008CED11E6BULL,
		0x4A27F27B2B4F7F58ULL,
		0x79DAB48E6C45B069ULL,
		0x55DE5664C8885BE3ULL,
		0x0C130B7E30534191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9D25D873994C27ULL,
		0xC498C5C1C79E0C37ULL,
		0x5B4A214FECB0DD9BULL,
		0xEE0916152A7B2C33ULL,
		0xAB9938C93D04158FULL,
		0xB5A8B03298BB4542ULL,
		0x3420D4864D2BDB32ULL,
		0xFE5D732D22A5CCF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x577DC64C76308D27ULL,
		0x6EA71D24DEE12C8CULL,
		0x4F1BC3B05B293A51ULL,
		0x4DF795FBAC15413FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xABE2E2DA13A5B0AAULL,
		0xC850A5C38B2C8872ULL,
		0x4621AE6768CB842DULL,
		0x198F9C9CA0C4224FULL,
		0x239BD087E131A48FULL,
		0xB21BDCD1DDA0A185ULL,
		0x64709269221C93B1ULL,
		0x900F9D232F6DB85AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D98F75DC999762AULL,
		0x8958CCD5DDEDA55CULL,
		0xD714ECF4BF23A6C2ULL,
		0x8202B44F10C01EAFULL,
		0xBA6738175F3DDBB9ULL,
		0xC5EEFF2D29D15936ULL,
		0xFA9ACCDD06D574CFULL,
		0xB161FF273984F7B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C188C2F943C0973ULL,
		0x4DA0BF605E039EBAULL,
		0x24C8143EB63672F4ULL,
		0x25525BB410909C07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB6F0672A36BA34A5ULL,
		0x99F9EA51C8C03BECULL,
		0x22D6407751D7D9E4ULL,
		0xFB28ADEC52DB0234ULL,
		0x99771A2CC7595F01ULL,
		0xC725783D5D8C8FF8ULL,
		0x84FEB7F36EF74F87ULL,
		0x625850E33B3030AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842B44CC033BB2B8ULL,
		0x6187EDA7DEF7D3BCULL,
		0x0B63F04987F5C730ULL,
		0xB82BE0F54E5FB9EDULL,
		0x6EE688F3E01376FAULL,
		0xF7FEAAAC4588F0B3ULL,
		0x8EC6297724AAAC66ULL,
		0x2577310129DE27B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x843AB0D087DEF44DULL,
		0xF83480337A520C74ULL,
		0xA3D776A0D1424992ULL,
		0x4C67888596A89D87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1DAC0E5D0ACFE752ULL,
		0xD2432AF0DC8C6D25ULL,
		0xA7C4066282E2E630ULL,
		0x46A7D2C087C027F3ULL,
		0x4F7ADBD660FF8B80ULL,
		0x1B5B2E782BB571E7ULL,
		0x17B05177DA0A0ECEULL,
		0xB7398CCD148A248EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3611A3235EB1500ULL,
		0x70FF3E845D455DFEULL,
		0x77590804EBC5FE10ULL,
		0x60E3026BC4532B2DULL,
		0x4F53EFA5DA7518E2ULL,
		0xAB8A0D7E5C0A8CD4ULL,
		0x726AB506F07BA600ULL,
		0x62B536BEF866B805ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3012035ECD71D78EULL,
		0xFA4ED18152A50FF8ULL,
		0xB8C037204240769EULL,
		0x7169966CF0AF190EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF290BC63DE0195B7ULL,
		0x30EB9988EC78F1D6ULL,
		0xA57BDCA9B4EDCC38ULL,
		0xC10392E681F89039ULL,
		0x87678D5115A5127FULL,
		0x7E788F80762AAA57ULL,
		0x476F3E86FEF2856DULL,
		0x76988184F7E4C298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70480748EBBB1A6ULL,
		0x5FB0C4B5ADDFADB0ULL,
		0x7464CFB7232B3683ULL,
		0xD58F3C72E569DACDULL,
		0xB5090534E8E4E865ULL,
		0x5F7820372D086A74ULL,
		0x0684D82BE2814515ULL,
		0x0D5F2EB038D293A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4594701DF3CC263AULL,
		0x6B4B59B419AEBFD1ULL,
		0xD3E23E78CA9222C9ULL,
		0x09F6A207F941ADD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0CA48E13AB6114BBULL,
		0x18039AF2C54CF93EULL,
		0x8DFAE99A79420D35ULL,
		0x4331BCD69A17515BULL,
		0x8C1CD45F4E3FAE74ULL,
		0x91F60A91AB0DDAAFULL,
		0x22848F673B86C747ULL,
		0x49AC0410865F75F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE8B5DE05AF5FDBULL,
		0x375BB041FE13270CULL,
		0x31D698E940B74506ULL,
		0x9C09D1CCAD926ECAULL,
		0xEE4ED377B21E2F81ULL,
		0x9F1268BC8F324E4CULL,
		0xC43CFE4332994B3BULL,
		0x2C039DC18F2A3BCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C4FFA96D2AA8D8AULL,
		0xEE71F052E9D0A8D5ULL,
		0x5AC3DC0A8BCB31F4ULL,
		0x0E271AC29E6B84DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF47A83DAB1733EE8ULL,
		0x322656A9E328A670ULL,
		0xDAFBD7F2C79C1935ULL,
		0xCDB0D0D0CFD215C1ULL,
		0x3A6CB3BCC01E57E1ULL,
		0x34E91F8797F6972FULL,
		0x004151CE6A4FDE9AULL,
		0xB20C8D1C4B18C1A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8E52F21B4D4155ULL,
		0xDC5525F5C6FEE6C0ULL,
		0x9560A0E689B25098ULL,
		0x0F8F0B9721F093EAULL,
		0x8F5F6D25782F7269ULL,
		0xF15779D5634BCB87ULL,
		0x9EE4364EDDF95E82ULL,
		0x7CC3E6FCDB8C129EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68E4AB5D439C0EA6ULL,
		0x5D6FC927ED83FA93ULL,
		0xB96D4BFB12C0CC10ULL,
		0x26EA6DE43CC37D3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9346087B7BFDF9FBULL,
		0x5DB344BDBB93447EULL,
		0xC8783C8B4B62BD47ULL,
		0xF799046F20642634ULL,
		0xF3D357A6F78D079DULL,
		0x09D3FB42AD2A64E5ULL,
		0xB3523816A2647CA7ULL,
		0xBDCAA52F60C3F741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC2D4AA7EE689737ULL,
		0x655AF608D55D318FULL,
		0x0E86FF528A7ED42EULL,
		0x798860162034C3DFULL,
		0x1D2D299620791378ULL,
		0x7BB6C484283DF596ULL,
		0xFE5285E9FC22EF49ULL,
		0xEADA19AB6BA4D922ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3C394537A8B9F4BULL,
		0x10AE6EFCA14E98C8ULL,
		0x97E5AFD96E9EE4FCULL,
		0x4DC559EF62CDDAE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x64B4AD715241AE8BULL,
		0x805376550D06F8EEULL,
		0x750D9EDF65BD32D5ULL,
		0x225DD649355FA6E8ULL,
		0xAEFBB29040B9DF10ULL,
		0x45549DC75EBE5039ULL,
		0x65022818AE56783CULL,
		0x4132EB728EFBFB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7C8D677D42FCA7ULL,
		0xD898BAF306869D31ULL,
		0x4B142F9E2307CD27ULL,
		0xBC2BC19458ADDDD3ULL,
		0xA6A45C890DC82710ULL,
		0x7E378E2583BB82B5ULL,
		0x62D768029E11CC8FULL,
		0xD4C173FD91A5211DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x352EE51B64DFFE7AULL,
		0x360B0D6888EADD56ULL,
		0x7C51F287ACE6E153ULL,
		0x7F09D01277962A21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x07FE9B5211BDDB7BULL,
		0xFA409D07D6F71529ULL,
		0x909ECBE7AB35BF00ULL,
		0x83E2159A30A0D8EAULL,
		0xB2C6C2F6260C2392ULL,
		0xF25D67CD036F0638ULL,
		0xCA2FC7EB6FE78029ULL,
		0x7BE9486B5A411BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA914FDD7021B3A2EULL,
		0x83DD7464C2089454ULL,
		0x1CDB1B74F32745D1ULL,
		0x272C91630795EF75ULL,
		0x83E2CF47E7A8FDCCULL,
		0x39D101AA06631DA3ULL,
		0xAD0851618E2DABDBULL,
		0xA3BB566EBECA43BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54BFC958525A3BCDULL,
		0xDB3A51D4A4B306F9ULL,
		0xC79F48EA39A3FCDEULL,
		0x73876FB63CAEF7B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB79D392BEB687E02ULL,
		0xEE3C24782E431881ULL,
		0xEE2634811CF29472ULL,
		0xC2D1B209E6663C3AULL,
		0x5343323B124FFF48ULL,
		0xA1A753C48657BB15ULL,
		0x0F5A299DBB93A5ADULL,
		0xD0213559B10BBC52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5968776C097047B0ULL,
		0x8D718BE776768CDBULL,
		0x72739689B6B149D0ULL,
		0xFA68960AB73F7927ULL,
		0xDC9A0C0B6079B241ULL,
		0x6BF856A88278D548ULL,
		0x5CEBB24252B33A96ULL,
		0x779F49F719311891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB506CD447C7A737ULL,
		0x58C42AB94AE2A7FFULL,
		0xF8185588F7913014ULL,
		0x6BB20CA1B99B11ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD88B2E8C8D343084ULL,
		0xE079683FD54A8C40ULL,
		0xF3A36ADAC063356FULL,
		0xCC5938BAF91CEFADULL,
		0x6F0A4F8515E3EC68ULL,
		0x6829430DD0B227D6ULL,
		0xBA348E68C59B8B15ULL,
		0x55605C1E4E6AE9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6F4BF741AD5DBAULL,
		0xB772D8FE59CCF68DULL,
		0xD456A42B248CF509ULL,
		0x4F57987C0F278BCCULL,
		0x0CD39E9483C14182ULL,
		0xA149E3CCBE787A08ULL,
		0x3FE2600A58A9419CULL,
		0xFEDF6637BA002FEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103A264AFCAC2D38ULL,
		0xAE2EB2EA300D6256ULL,
		0x477FA8B3C7CD2853ULL,
		0x54262078F1CCFC63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x77E054E7F342A5EFULL,
		0x36FDC7177F597417ULL,
		0xBEB9C5AD17146749ULL,
		0xDDED74C3E1FEDE92ULL,
		0x3C1D98864864B94CULL,
		0x91CCB1B67EE24038ULL,
		0xC72B8AE15703E0D4ULL,
		0x5B758426B65C3704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373557D0BB897754ULL,
		0x79980BDB149B5F37ULL,
		0x8A0B3778A297705BULL,
		0xCE61D6E8D42DCF88ULL,
		0xF033E5BA8BADBED8ULL,
		0x5882152B026998C3ULL,
		0x420AA4AEC26133DCULL,
		0x35B9D00D8E49D5C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x855B87553AE25CA4ULL,
		0x3E78F7F0E4A6F023ULL,
		0xF790B9B684A2A3C6ULL,
		0x29685997008B7E9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x19FFD003B6611674ULL,
		0x2687E41A96D81B35ULL,
		0xA0818EA508C347F1ULL,
		0xFF3A0E6D8473AD87ULL,
		0x694B6514FCE2CBA7ULL,
		0x579FF92E739B0DF2ULL,
		0xADD8E062C6D0E51CULL,
		0xCA512370F95911DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8EB580603557CE1ULL,
		0x71BC12488612E9FAULL,
		0x50D87EF058B97A67ULL,
		0xDC0E24BA4C75D240ULL,
		0x8313825EBD216805ULL,
		0x44B06AB68AD5F117ULL,
		0x16500D2D990F7FAFULL,
		0xD59A0E4DD58E04C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D601F0B29C06353ULL,
		0x845AF79E9E0779B8ULL,
		0xCDF869997ABEDBBAULL,
		0x76590CEA8821CD39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8E8F44D43A91DBADULL,
		0x3A11EC23ABB83916ULL,
		0x4CAE95948B4C4EF6ULL,
		0x525011898F44E254ULL,
		0xFB9F41821B183649ULL,
		0x75E7134DB17599B4ULL,
		0xC6DC1CE26398E6D4ULL,
		0x126C5F15B783AB03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA7147543A7092FULL,
		0x87AF021060EAB951ULL,
		0x8F0E7758C24C1844ULL,
		0x5E083B4A3F5E4008ULL,
		0x9EF5DC1389A2FB90ULL,
		0xFFEEF4A02F166A60ULL,
		0xF75E03C29CF5B64FULL,
		0x91A2474E59EB53CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x930D3EC88E518722ULL,
		0x353777D4A4EE864AULL,
		0x8A57D8F345396A5BULL,
		0x12475DD73483946EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0CD4E734A5F3001DULL,
		0x6D1DD3BB87186D7FULL,
		0x0A4741C3686A43CFULL,
		0x89FD82B2ADE4D924ULL,
		0xC3C4345B75C05AD5ULL,
		0x5CD362742045C2C7ULL,
		0x479D1B862BE0CE75ULL,
		0xF653A4B6B807E51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AAD68355CCB678ULL,
		0x38683AA38E5C85F9ULL,
		0x505FDB6972EACADCULL,
		0x10E6076C3CE014E2ULL,
		0x2B092461555CDA75ULL,
		0xEB48D197E08D00C4ULL,
		0xCA33BB547A7334C3ULL,
		0xFF6B582869393CA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11EE6FD21EEB57BFULL,
		0x0F4719C96E28B40EULL,
		0x578BADBA4BC4494AULL,
		0x1F92D86623B1C696ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD9461409AA8ACA2EULL,
		0x5D6DCF6826CC7A10ULL,
		0xFB8722B2D329D8E2ULL,
		0x5833E30F4051B26BULL,
		0x14AD7D08D74012FBULL,
		0x42241B4E761B5E7FULL,
		0x5A1FAC246667A401ULL,
		0x3686E428999BCAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x064E71D8328429E7ULL,
		0x9E0DB5C817AFCE06ULL,
		0x2A17D16718621AB0ULL,
		0xC1E5C83734D3884AULL,
		0x7A4A9D9C5DEC9691ULL,
		0x52335C8F3ED9188EULL,
		0xBD83C30203F1117FULL,
		0x7CFBE5EB55380625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDA4CC4B7A6B1661ULL,
		0x5D1C6A0242F30DC1ULL,
		0x1093EC6658617D7BULL,
		0x20EFD7F0324D60CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x033F91DD6B287F5EULL,
		0xB613C8625C3DD9ADULL,
		0xEC74FF923FD0B1A8ULL,
		0x1AB3693BB8E520DBULL,
		0xB60DB86500EF28A1ULL,
		0xC3186DC38DC9CD51ULL,
		0x36EDB11A0382DE94ULL,
		0x9B6B5888980B6216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505E05606834D4F0ULL,
		0x30BB893816F7EDF3ULL,
		0x1E81050B15E1FAE9ULL,
		0xFF3B1C670C9F6E24ULL,
		0x89758530621AAF9AULL,
		0x5B4AF32F5BA341B5ULL,
		0x414BA31B5DE262ADULL,
		0x4AFE744AB3ABB411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5179264C967DA31AULL,
		0xEDD87129B6FEA4E8ULL,
		0x44020E53BFC11B18ULL,
		0x0BA22E0492798774ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEF576A59FCF8B033ULL,
		0x8BC31EB3698D405BULL,
		0x7A9D444155C530BAULL,
		0x89142801528B7547ULL,
		0x450534A49A349F44ULL,
		0xD9363736430B08D8ULL,
		0xBE9CC6EB1553BCDBULL,
		0x0F52EF1EBA09350BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19D7F47C3969CEF3ULL,
		0xB372CE9ADDF0134FULL,
		0x6BB01971314AC85EULL,
		0x080649782BB1BD75ULL,
		0xD300413A10A34840ULL,
		0x9E618E3363BE81F0ULL,
		0xB4C102EDAF74895BULL,
		0x74279618A6C07CECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC23B97AE2F21C9B1ULL,
		0x93E16685B0F93367ULL,
		0x858C426D439C0D64ULL,
		0x097D157003A50C6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x71E2C446A91C1F06ULL,
		0x7F6A3351AA762C48ULL,
		0x7E547E0601786EE7ULL,
		0xBF86185F29B1D494ULL,
		0x50F7F57565E81702ULL,
		0xF5EF409763A623D6ULL,
		0x0AA217CAC388BDC9ULL,
		0x21D6380096BF2747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48954F853743B772ULL,
		0xE45B4CBB7D325D2FULL,
		0xD594AC5B870F582AULL,
		0xF15F4BE5C7EBEFABULL,
		0x972156F7504B1858ULL,
		0x3244214B8E8D7AE6ULL,
		0xABF355273B189239ULL,
		0x339DB78328D244CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF28FB78A726345EULL,
		0xA6758BD7CEECE2AEULL,
		0xB6B0B5F0BB0F8E39ULL,
		0x2A89DF17B2EF8338ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1B309A725FB4E637ULL,
		0x886C676C55A4ABB9ULL,
		0x30DB7DEAA56874E1ULL,
		0xCD324A6A1273EF65ULL,
		0xBDB74B404C8BC039ULL,
		0xFE5EE67DF557C313ULL,
		0x0233133E91185647ULL,
		0x72EDF7BBC140830DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD56948BBBD38971ULL,
		0x5F58546478ABC4ACULL,
		0x4B37C20CD52F0009ULL,
		0x0DF464DC9E2B2C5BULL,
		0x3BAC9D805EB7A91BULL,
		0x76DF8FA8E9793145ULL,
		0x8EF4BCD6F28B738BULL,
		0xA2DAC27C1C8A3D61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B6FD063F15CCA43ULL,
		0x45FAF6A7A0028BB3ULL,
		0x00E48F3F59231CD4ULL,
		0x2217CCFFE7571A7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6C09CA71FF6FB6F6ULL,
		0xFF7DBB9A0A6C4E31ULL,
		0x23BF139813236367ULL,
		0xC43273DB24D9B036ULL,
		0x4F6BFE37536C38A3ULL,
		0xC0B933D5B85059A2ULL,
		0x49B0AE6F6DA9F4BBULL,
		0x101F8670863ABBC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834B02967054E4C2ULL,
		0x1DD2BC3AA4646809ULL,
		0xC97738F70BB9F81AULL,
		0x34978759D85215FCULL,
		0xF841EC0B6FB43847ULL,
		0x869A8B8A55B5E05FULL,
		0xC9538109141B84CEULL,
		0x198553A83B5A09BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8FD7A5F5C6ADFB6ULL,
		0x8237FA9008F5E600ULL,
		0x681C97D2528E0884ULL,
		0x2A7E763C69E20730ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBB30B93AAD3D0370ULL,
		0x8C8F3D2DF8370301ULL,
		0xF3D1B9F0EB66F699ULL,
		0xD484F60B0148E758ULL,
		0xAB34FC38BD4BA06CULL,
		0xC43C750C4DFE8CDBULL,
		0x6C8E635EB2C3C9B0ULL,
		0x2588B2165BEFEA95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC8D0DF4119B9255ULL,
		0xC135D00246F81FACULL,
		0xDDECB2D4DF269BE9ULL,
		0x9CCFA003DB0C4EC7ULL,
		0x28FF39A97550B62EULL,
		0x024D17DE6B2F7100ULL,
		0x6DEE8F0361A51847ULL,
		0xFC4085F2E033B641ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x129E8C8B4AE0318FULL,
		0x94E141FB5BFD05EAULL,
		0xE19E8CAA16CEB062ULL,
		0x586BE34B842C5D08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x90E8AE43F0F31E11ULL,
		0x7EEFD04EF36713FFULL,
		0x2CE40C8FCC96EF14ULL,
		0x91D3B7EA4E55A706ULL,
		0x15839F74E11F3325ULL,
		0xFD9AD0C2CADC6433ULL,
		0x261AD9383F989342ULL,
		0xFB8DAAE93920B646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B327E737B16F5C5ULL,
		0x439AA5E14A275D59ULL,
		0xC72A93C41AB10495ULL,
		0x73F5CE5E5ACAA963ULL,
		0x384385C01EA9FF45ULL,
		0x231BC004532B7442ULL,
		0x9F96E26496F59114ULL,
		0x450CC9C4D482EEFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D3A00A55341DF8EULL,
		0xAA31A6B36D835467ULL,
		0x5D501C36BA183D73ULL,
		0x34FF54F2E2F692B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x328918234A913A15ULL,
		0xBA27E47914903754ULL,
		0x6C4BB4F2AD4CFA96ULL,
		0x79080979384A0B3CULL,
		0x103C77F68B20BAB5ULL,
		0x240F074AECB0C246ULL,
		0x3067E93152058D22ULL,
		0xBDFF83B3215C9A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD11FF6F6B4E7926ULL,
		0x6804A40E8CB4AF86ULL,
		0xC586C209B1BFB423ULL,
		0x39A7A68CE1D2BAA6ULL,
		0x4F209FFDAAB307ABULL,
		0x991A9C098AE4FA2FULL,
		0x6D832B449BF966B9ULL,
		0x1B93F0694957151CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F9927A52F8B57FBULL,
		0xF26B2C1F0C1B3B2EULL,
		0x94B9240C015AF9F7ULL,
		0x5B583FE2674918CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDA18023926B30BDEULL,
		0x56F48DAC7E94E25BULL,
		0x623ADCA87321220AULL,
		0xEF0B5E0A3A192D6BULL,
		0xBCB8180B23AECA36ULL,
		0x664546D680948494ULL,
		0x7FC2DF20E2BFFEA5ULL,
		0x0F571E0091BFFE34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC35EA4FBAD6C8CULL,
		0x8AD9C2F6B84C3280ULL,
		0xE28C22CA29848C87ULL,
		0x4A3B49B882380B5FULL,
		0x659EC3173262ED1FULL,
		0xA32CA6E72DC8115CULL,
		0x7D4BB67A2A45A204ULL,
		0x51B374A9FB22826CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C173FC9FC486F53ULL,
		0xC1C2883C10A1CA38ULL,
		0xDD5EC29DABC6555FULL,
		0x4B1B372C134181BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xED527877BF8050F5ULL,
		0x15FFE10D13353EACULL,
		0xA54ED2841E07F0E0ULL,
		0x972230890CB563D5ULL,
		0xB2B16EBE5D823843ULL,
		0x43AC0224B285D9DFULL,
		0x32E2CDB08E7742A7ULL,
		0xAFD0C114079224A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8198B3437664E367ULL,
		0x383DA6A2A3B3E531ULL,
		0xC8849B5D698645CBULL,
		0x47113DDBDD224B28ULL,
		0xCB1A57C9CFA34BFFULL,
		0x39BBF0F2DE41F139ULL,
		0x65D51E81007049C2ULL,
		0xC42FF2E28A81AA5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC272D8158327F34ULL,
		0x5764C7CFF195E21BULL,
		0x4CD23835C98A9D14ULL,
		0x49EF8E05C0053FA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8A48DA0166C6B3BCULL,
		0x3D885CE9E5C7A03AULL,
		0x2FF8A447243A2240ULL,
		0x0A178B0D1F20B5CCULL,
		0x13E481C5D5FD13C4ULL,
		0x52A54A9BE9431602ULL,
		0x68D5D556EAB6EBB7ULL,
		0x9ED1793172AEB18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50874622344C518FULL,
		0xF27B624638447E71ULL,
		0x09C340E9AD5AF90FULL,
		0x3D9345702BA646FDULL,
		0x6A0E8250EEA16E7EULL,
		0xC3BB3A85139FD4C6ULL,
		0xBB9EC9FCECA9E4EDULL,
		0x0660B7C3D22643C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F857F398A14EDD5ULL,
		0x81CB5E0763BED0A4ULL,
		0xDC6112B92CCE2B1BULL,
		0x6D40FBE2C7BABB7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCF5F63DCDE712A82ULL,
		0x7FBAD8F92D0E67EAULL,
		0x0D34D61B6CD5A02BULL,
		0x3F18B7912DAF5DE1ULL,
		0xDA6FBF3F4DF57A9AULL,
		0xA006913C35263A03ULL,
		0x998F8E6F1F6A8AE5ULL,
		0xE9D7AA674D7F77CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66FC36BECDCCCB66ULL,
		0xDBC75580FDED7C4EULL,
		0x8CEBED82AD860EC5ULL,
		0xD0A1FF94527438ABULL,
		0xEA9257B46A608398ULL,
		0x8A4E6D98E2E74BE8ULL,
		0x4FD728D62EE67B12ULL,
		0x0BAC367757CDC59EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03408BBBD8C10E28ULL,
		0xDD48CDB66478439CULL,
		0x71A7FD4C72E9EABAULL,
		0x68E9ED9B539B97EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x309CB9EDC20A59DFULL,
		0x57AF1011B1800269ULL,
		0xB5FBC33AEC9F3270ULL,
		0x0CC3A4E3480B6858ULL,
		0x6E308B128EFF9CA4ULL,
		0x8CECA9645C8CF32FULL,
		0x1800AEA2A6F2EA98ULL,
		0xDA5BC5FA5C4BCC51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38521FB251E6022BULL,
		0x9A947DF81066381FULL,
		0x68B48B67D48B9538ULL,
		0xA1D72D785BCFEFEBULL,
		0x64225905893AF91DULL,
		0x04231F961F30A123ULL,
		0xF5069A82831FE3FDULL,
		0x5A3C4D57BEDE195BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7666082A4B54A06AULL,
		0x0B0506B6BCCDF813ULL,
		0x7E6634986966984EULL,
		0x6F985F8E4A8408D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9E7E65B81190384EULL,
		0x7EB692BEB2BE4ED0ULL,
		0xD8CF5E28C0F98F44ULL,
		0x9242CD07305A66E2ULL,
		0xFD2484B1683A696EULL,
		0xFE177A332D78AB6BULL,
		0x60F401DEF6C5FC50ULL,
		0x4322D5C811C945DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC638B1F18A47340ULL,
		0xA7F23D87C9B92634ULL,
		0xE276B271A03FE329ULL,
		0xFFF68D4C7F12935CULL,
		0x73F0031956F9791AULL,
		0xFD922672F2AA234AULL,
		0xF0AD30857658DF74ULL,
		0xA082BB68E4F084DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE6172B888F6F5FULL,
		0xEA8EC3BFA3AD5D96ULL,
		0xA0DBBF0030EBF4C2ULL,
		0x361029DB59747996ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2A219CAC949DA299ULL,
		0x7D32942108D23DEBULL,
		0x97B8F2DCD4D8F1E1ULL,
		0xB26FC42EFA0E79E7ULL,
		0x95136F21B52FF132ULL,
		0x7D86940E63745AE0ULL,
		0x9AF986E304B4ECE4ULL,
		0x67CC7446915D3397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C24DE6D74744FFULL,
		0x92728266C91C8696ULL,
		0x9645164549270BA3ULL,
		0xD9255BA674DE6EE4ULL,
		0x93963CBE2A88724AULL,
		0xBD87BDECE2DF5EB9ULL,
		0x57A4C4F6064738F1ULL,
		0xA752A8C8807B9AA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78F4C98C5233328EULL,
		0x6A93DAB355D3251EULL,
		0x0008A5C54FFA9C46ULL,
		0x6B5E9D3F06ACBEF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9494AB24271EB1ADULL,
		0xF81FAD8A5672A48FULL,
		0xA24FFDA5D8762196ULL,
		0x3689D1B9AF67C839ULL,
		0x1B84082979EC5B06ULL,
		0x8408E634D805E7C5ULL,
		0xBB5AB185921440B6ULL,
		0x6323EF7D83FBE9C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B1F0364517F2E2ULL,
		0x79EB6BF40F5D7156ULL,
		0xFCBBE130D38A9EB4ULL,
		0x30BF200FCBAC82BAULL,
		0x1D78E10577F2E9B6ULL,
		0x440AB2D158F17E67ULL,
		0xFB0EF3E8964DDF69ULL,
		0xA5F032F3EE3D4451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x728A8A462D0D8F2FULL,
		0xFDEFE25B241CD72CULL,
		0x30D241C2645DF459ULL,
		0x1B78AE161E07D51FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDA4B26C03034CE72ULL,
		0x01D6F9042D3E4559ULL,
		0xDF2A9845ECCAA9BBULL,
		0xC701C10E8B54833BULL,
		0xBC9FCE8E418CCB30ULL,
		0x7EA6E57CDD147B49ULL,
		0xDD6567BE79B75463ULL,
		0x1A80381783B34776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11ED818DFCFFE505ULL,
		0x415E24B2BC813D53ULL,
		0x2B9733F3710AC1F8ULL,
		0x396B4877E200F7E3ULL,
		0xDB0F1D5E83C04F7EULL,
		0x598EC8A4E9659C5CULL,
		0x1F481ACAA6FCFA13ULL,
		0xDB508269BB71494EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43D7F2485F8F419EULL,
		0x420D1C5F9CB21F30ULL,
		0xEBECD083C3694FA8ULL,
		0x6EAB7062631F4564ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4F0CB34BE0962236ULL,
		0x0387AB47F1143291ULL,
		0x8797CA810B33D4D2ULL,
		0x8A65192B00B675C2ULL,
		0xA31AE350E756D772ULL,
		0x5A747156A699640AULL,
		0x775BFEDFC84B582DULL,
		0xB54AC5F160A53E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89837011E797A4C6ULL,
		0x7FC63AC763509F2FULL,
		0xEA9306AAC4EF4358ULL,
		0x5B147B47CA1B7831ULL,
		0x1B5C4F616A5972DAULL,
		0x94D7C6ACCBFD4702ULL,
		0x3C3B5FE181DA05D5ULL,
		0xB83FC08DCD70BD26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBD338C6869B6BEDULL,
		0xD902C5B700EFE2A5ULL,
		0x63DC5D94BB16CA80ULL,
		0x3EF36AAB10661F25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFFF6D74A1269F455ULL,
		0x136ABE3E2DE77E77ULL,
		0xE197F8E84C8FF917ULL,
		0xA601BD8F0C5CB0EAULL,
		0x75151B35BF45B05FULL,
		0x5C840B6093084D3EULL,
		0xEE5C736381E81932ULL,
		0x3F3106FC6D576D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFEC6339D3F5F26ULL,
		0x42FDC3F739988BE4ULL,
		0x0CB0ACE6D7E1A010ULL,
		0xBD7671AC37A92193ULL,
		0x46CDC03998F77C54ULL,
		0x4E5AE513734F5605ULL,
		0xE3EC996363C8753AULL,
		0xD6ED06334208BE44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC28F928424C64B67ULL,
		0xEA88A9B9A9C3A510ULL,
		0x6181A805ED60AFD8ULL,
		0x62A369BF426181C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0F1EBA550C3830C8ULL,
		0x741E8747724D04A3ULL,
		0xE89B5E59095522EEULL,
		0xEA310BAEF02ED456ULL,
		0x98FC4EB085A81A60ULL,
		0x93F086AF74183E14ULL,
		0xA7D769C5D99C9D01ULL,
		0xC5DC70D0E10E5A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF21F28157E733B37ULL,
		0xDA296AF6590CBB15ULL,
		0x38F95880A4A68E41ULL,
		0xE395FD7B46AD6DB4ULL,
		0x2ADEF937767CEAEFULL,
		0x2DD377543550479BULL,
		0x87A8200F35569B48ULL,
		0x008D6C6ECE4086A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x755A4237CE2E04A5ULL,
		0xC24563DC6AEEDF93ULL,
		0x76A6F6F4C712D631ULL,
		0x5055B4C2740ECDE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7056CF5EE0FCEA87ULL,
		0xA27EAF3DE284E472ULL,
		0xCE3B87B00256CB27ULL,
		0x9A598762388B5AA5ULL,
		0xDA9957F5EA4CF87EULL,
		0x48E1DBBB36ED1EDBULL,
		0x96FC807E68310810ULL,
		0x441D2369364AB357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE8E065AE5FEE95AULL,
		0x2CB9692B2F86B549ULL,
		0x4445ECF9DB460225ULL,
		0xE4B02BE791E4F169ULL,
		0xA2C6F9EDF7DD7CA9ULL,
		0x7293ED07C12E2BCEULL,
		0xE5133E69A112C74EULL,
		0xC16BCFE5D06EBEA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB02BE31F78A5FF9ULL,
		0x4556B4B62D56431EULL,
		0xF29569CBB58E65C8ULL,
		0x1BFBC0FBC54CBC34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x565496AD36EED851ULL,
		0xB11E1DB6C35D1675ULL,
		0x2406A9526CDCC99DULL,
		0x7C8CB08980BFF2BEULL,
		0x6C2E752067C35DF6ULL,
		0xABCC8649171D7167ULL,
		0x2796E13FED5CB39CULL,
		0x0BBD508FA12B02EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355CD9F4A0F7E9FFULL,
		0x49C55843D2934F94ULL,
		0x17CA625F9303F216ULL,
		0xA1DD2AA10DDB069AULL,
		0xEAD23938A0116E3DULL,
		0x6B364C70EEE644E9ULL,
		0x0FAF09D83E0F45E9ULL,
		0xEAA32350BEF99849ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54A8A1203A607ECFULL,
		0xFDA55B88E8FA6182ULL,
		0x98A64056DF572022ULL,
		0x44923D3E063AC07FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9EB551AE93C4333EULL,
		0xBDB4A6FAD05993D5ULL,
		0x00B6BF1FE3A662BEULL,
		0xEE99BA88FD5C7B83ULL,
		0x90221A0A2C0DDF23ULL,
		0x06B0C227B64A46ADULL,
		0x109BEF5DFA8BDB47ULL,
		0xE71D84D041728691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3937AC13649DE5ABULL,
		0xE3D5B94F4850BADAULL,
		0x32FAD783B879262AULL,
		0xFCB4CD7FD836E3D9ULL,
		0x77F4430F827EB09EULL,
		0x9DE91F39CEC5DEADULL,
		0x8D6467ECD402E34BULL,
		0x1DBABA5F97463382ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC4B8ED05A6739B2ULL,
		0x67811CFBE5B048FEULL,
		0x47FA0267E3820BE5ULL,
		0x568EF9C267B9EBD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD7A386F5F370D598ULL,
		0x7B6B16843C3859D8ULL,
		0xE11272B3B048C460ULL,
		0x9D4E470146834608ULL,
		0x312999A0921B6F35ULL,
		0x8C4B37952E9B17A7ULL,
		0x528B754F78001D95ULL,
		0x0D2431D8879E4B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2978B65829921BB3ULL,
		0x9E9F078AFE0FF256ULL,
		0x97C7AB02ACE55EB4ULL,
		0x4BBAC5682DBA0B20ULL,
		0xC44DA82B3CB1998CULL,
		0xEA9D23C826539284ULL,
		0xA28AF34234AD5877ULL,
		0x0A81B8A7A4EBDE4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6D0A8087794710EULL,
		0xDCA2FF6878C62A9EULL,
		0x695E15A901ACA811ULL,
		0x35B17EDABF457496ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x70C8CA6176FB55CDULL,
		0xA045F278A35A904CULL,
		0x3A85698156DACDA2ULL,
		0x7C066503EEF49D6CULL,
		0x9118E7B0FEDB191FULL,
		0xE85CB11DFB148C28ULL,
		0xFC2BFC5BF60E5AFBULL,
		0x118AD782F88EA34CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49A23E862A010ABBULL,
		0x1A96EDA688519179ULL,
		0x361B6C31FAD53A0FULL,
		0x2CADF35763F414DEULL,
		0xB4E09414701C5633ULL,
		0x251706C010D5BE3FULL,
		0xA1F1BA367C9C57EFULL,
		0x777C0AECD9A30002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD782F5187D4B37E0ULL,
		0x82064EC2E05B8F63ULL,
		0x690FCEDF62F20778ULL,
		0x2D8ACFF521FAC597ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFB42B323D110E800ULL,
		0x49CF69E5F253C6B8ULL,
		0xA6EDB4FE4BD6241CULL,
		0x4249F39BD036D438ULL,
		0xA4A6AAB89E151B43ULL,
		0x09D6146C5B3E7826ULL,
		0x6FAA8470E5D9BC73ULL,
		0xE200B99EDD619BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A2FA2DC4281F461ULL,
		0xADD211457ED1AC3EULL,
		0xAD61A51A28F9A4A9ULL,
		0xF133A1DC6FC964F5ULL,
		0xC3E616C2F9418CD9ULL,
		0x542028336E305BAFULL,
		0x1B23C4D02E924AB8ULL,
		0xD86EBB1A37F431FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DA906BE05F6176EULL,
		0x94FE6913A39A5420ULL,
		0x858C81BF57776129ULL,
		0x3CC2196FEEAB1DA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCDBD4E41741D5249ULL,
		0x7EEB5469614EC5D1ULL,
		0xB8AE3DB3A36AC1CFULL,
		0xFAC52EF4622BB612ULL,
		0x2C84A671E5B339B2ULL,
		0x78452246F07ED9DCULL,
		0x4818DD7032AF46A4ULL,
		0xDB65D0EE8BBA3877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD4A4C1FAEB3E19CULL,
		0x2B5BC296D041ACCFULL,
		0x4A7721951F3769E6ULL,
		0xAB09FCD4BD6EC133ULL,
		0xFA18B3E554DB2634ULL,
		0x15ABA342FA004C7AULL,
		0x4A04C99CE6CAA5EFULL,
		0x0DD32C9A4E205D87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C7902FF457C59E8ULL,
		0xF6586C6927D6156FULL,
		0x25320D7BC82332D5ULL,
		0x537F96A0C993747FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE1CF1698734AD3E2ULL,
		0x4B1FC8107BFC0C75ULL,
		0x58B9BF14A225DA76ULL,
		0x7ED4234416B19A75ULL,
		0xD329FCCF6C9CC443ULL,
		0xE9F969709227E99AULL,
		0x6AD6FA31A0D1D875ULL,
		0x77AC924E0AB9312BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA47972B6295AAFBULL,
		0x8B1C5D0345CE9E1CULL,
		0x43AB66F4AF6A75B0ULL,
		0x4204505B420B652AULL,
		0x4CA298208E9F79D4ULL,
		0x507AB6C583463930ULL,
		0x161FC7EF87A3A4DCULL,
		0x391AA4F659973C6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FA07162044E36CAULL,
		0x88D1F0716BAD9E29ULL,
		0xA83FCDEFAF970D92ULL,
		0x06790DED1FB089B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0E2E83B8696DB45CULL,
		0xC7E24BA8BCA0E5FEULL,
		0x8DF8913DAC089D4EULL,
		0x33A33A089F432373ULL,
		0x4018C60070E0181AULL,
		0x38EE9B3752A6205CULL,
		0x731F1F35AA29D835ULL,
		0x4B93C0E5C3AC3D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A395FFB7FF8C74ULL,
		0xE4CBAE49F829579AULL,
		0x2E7229995524E9C1ULL,
		0xD2189D015653F00FULL,
		0xA2E48A6A9CC6E515ULL,
		0x75617235D86A2C6BULL,
		0xF768F5A26C84ED60ULL,
		0x28EDD7E7114BCAD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB4BC5F62D2BBB51ULL,
		0xEA0AB396E95DC41AULL,
		0xBC90937F7D5E8F21ULL,
		0x062B32D5C340369EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3F28DEDA57C5EA59ULL,
		0x86ED7121912935EDULL,
		0x11CD50C9A54783A5ULL,
		0x5DB8D4F214633F40ULL,
		0x7FF36575A46D1027ULL,
		0x28C55A3778CB4552ULL,
		0x1592622C8BF5E205ULL,
		0xAACC6E598C3F5930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FCF35ECEE1A04AULL,
		0xAED44657D8A9E238ULL,
		0x49E1E2B444CDA8F1ULL,
		0xA27C6A7FD34411AFULL,
		0xBF5978AB71BA1D84ULL,
		0x87D19DF87D279BCBULL,
		0x25AE2EAC536B0010ULL,
		0x279C01AB41B2862DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA305117F0F745113ULL,
		0xBC471C2312CA7DB5ULL,
		0x63CB131DC5176503ULL,
		0x346C8C5152068000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x34E3EE12C8702A21ULL,
		0x6E79AFB600B6F339ULL,
		0xC1E390EDFE61FCC0ULL,
		0xD1EAD62A88A25F35ULL,
		0xA67B6B2F7044DB06ULL,
		0x77833D39B041F1B7ULL,
		0x4F9F914B6A9D4D49ULL,
		0xE77FF145DE074CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623499A971ECF553ULL,
		0xE29FB17FFC8BDEB1ULL,
		0x56AF86F2529F978AULL,
		0x786C86A5826C695DULL,
		0x11E94F11E4FCCF57ULL,
		0xBB64466F3406EB59ULL,
		0x9D492B083DB6961AULL,
		0x62FBC1E1F1053CEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE05F80CC0334F3C0ULL,
		0x7872A04474EE0691ULL,
		0xE40737F456019625ULL,
		0x051D585A3484555AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3D1834E915797C37ULL,
		0x651EFFAF02EE7744ULL,
		0x1227A788DEACFFEDULL,
		0xD0C8E0A6281A58B1ULL,
		0xBE0B44BB4AC5D250ULL,
		0x4BC7D184207CE011ULL,
		0x9ADB452D70B6FFC3ULL,
		0x638C3E75CD285247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C5CB13CEEA207D5ULL,
		0x3091FD747A3EE65BULL,
		0x8415EE8C90E4EEF5ULL,
		0xBCCB458CC0AC8948ULL,
		0x178B7AC7EAC9E383ULL,
		0x7F4BA83D0D3B5E94ULL,
		0x2D8DF941A7BAEC13ULL,
		0xF33CBEE751146E3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87B37DCC663CE39FULL,
		0x8EFB22C76468C98FULL,
		0xC78AFDFC2332FD10ULL,
		0x3FCA8A3FD261A8A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4B5B3B3FDD21C451ULL,
		0x72B9146747395E13ULL,
		0xB0026EA0A170BD8AULL,
		0xB0A503A9E9B5A23DULL,
		0x4CEFB9B97BEA57B0ULL,
		0xED66AA82D4A77CEFULL,
		0x42E85C25EBE5BA49ULL,
		0xDFCC712A8BE66D0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC645E56A15CBF1EULL,
		0xD69352587BA5BDBEULL,
		0xCFC45D487111F197ULL,
		0xEE74F4BA5F2C1CF1ULL,
		0xA3402A8DA0E58787ULL,
		0xC3A4EF99554A92D0ULL,
		0x97FDAC0ADFFE45F5ULL,
		0x685FCCB681093FF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF061D6BBE7BEDCFULL,
		0xCEE780B7B35E60E1ULL,
		0x3F14355BF4BA1070ULL,
		0x7C507829275E3611ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDC6495B455EB26A1ULL,
		0xAE661D8D1443BEECULL,
		0xCC518CDAC98AE673ULL,
		0xABAA89E4B00BE780ULL,
		0xA4CCF05B287D4F35ULL,
		0x46D7489A5F549BD2ULL,
		0x270CEAB001A102EFULL,
		0xF42B0C1383A4051AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F3C4B799D212A2CULL,
		0x621D70558F47F910ULL,
		0x94DFC75A96EA65EEULL,
		0x5806AA56ECF30A66ULL,
		0x8CD9C1001F7DA8A5ULL,
		0x090CC2ACFE31D5EDULL,
		0x5F969EFFA2514099ULL,
		0xDB2F8EC89872FBAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB4151BE0EBCB66DULL,
		0x78588E73F02525DDULL,
		0xD30101AE58775952ULL,
		0x08F878ACAC604319ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBDAA2F4D8608A4D4ULL,
		0xEA2B01CF853E615CULL,
		0x0CF8A9D4CFD8F1F7ULL,
		0x314BFAD9FE61DF31ULL,
		0xD390CCF35CAC86FCULL,
		0x1B351D19769EE950ULL,
		0x5ED40B3B36091D81ULL,
		0x4A237335B762AE11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D740891E0AEBFEFULL,
		0xD2D918A47B2219EBULL,
		0x21FD0EE0640AD6EAULL,
		0xF9913FF0823E9586ULL,
		0x7F9726E6575B54ACULL,
		0x244E98F03675635CULL,
		0x6144A8AB50667131ULL,
		0x8AF11F9B4F76079CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1744CCAA6F675B36ULL,
		0xBD89874A904629B6ULL,
		0x8E443C5081F3AEEBULL,
		0x193323D4E943FF08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x39964825E814BB49ULL,
		0x3BD83513B80E5FF4ULL,
		0xA0D55BC25C13A8F1ULL,
		0xEA9E33076DA02A61ULL,
		0x0BEA53FD0228F524ULL,
		0x54170593E5620A91ULL,
		0xC2DFCE2D887DFA4CULL,
		0xD0C14F398875FB16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF7BC584FE61758AULL,
		0xFA85036713410360ULL,
		0x9BDA6611C36A7C43ULL,
		0x4F84F6003E9D8472ULL,
		0xD75D2203D8ADACBAULL,
		0x4F59A03CD3432034ULL,
		0xC8C02A45EBB8FCC7ULL,
		0x970D321F5DD1BFCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x070FED9D120006D1ULL,
		0xF5703C9955642643ULL,
		0x25AD4A11DDE6CE6BULL,
		0x2BD58EE983637310ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFFC891C694C35233ULL,
		0x0F8EFE16317C07F8ULL,
		0x9F4B29043CBBD27CULL,
		0xA653006E5BD1CC38ULL,
		0x7DE0D7623B725FA1ULL,
		0x851A18AC433378BAULL,
		0x5B179AEC02513091ULL,
		0x7B68F7EB70FFCE6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA8A72F7169BC7E3ULL,
		0xDA8D4BDE51DCECCEULL,
		0x7C0BA8277D13995EULL,
		0x29BDCD3EBF076633ULL,
		0x642BF3A2B9ABDEEDULL,
		0xA5C7650D01A9F4E6ULL,
		0x7CFAF5A5AB54EC6CULL,
		0xC05A828D04A6C1B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE617ED3CC19EA38CULL,
		0x5B485BDB9A08ACA5ULL,
		0x1B80094DA91A5696ULL,
		0x40BA9F33B202499CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE7C165C5057466ABULL,
		0x69C783BDDF2DB5D5ULL,
		0x18D388F2B5F68499ULL,
		0xCD5E55292B99E88FULL,
		0xA7F6661704BD3DA8ULL,
		0xA6DE61F8DF8AB577ULL,
		0x4A9F94BDB797DEE3ULL,
		0xCC675819655EEE4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBA620AECBBC019ULL,
		0xF783F99B97C65C50ULL,
		0xE4370969166665BBULL,
		0x10F9FC1DC871854AULL,
		0xEDC73B49E1213429ULL,
		0xD4028FCC983480D3ULL,
		0x3BAB97D9C677B6C5ULL,
		0xE4A3242BFB654BBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE075E2D61E20EFAULL,
		0xBEE4BCB4DE3329D2ULL,
		0x6CD4095F6A56134AULL,
		0x23840E491E3684CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE10ECFE40E3F5EB3ULL,
		0x5791DE79112AB1F8ULL,
		0x1B2CDB48CB1A2E0CULL,
		0xE1C2B00B6513CC94ULL,
		0x77CD0AE6C5091A06ULL,
		0xF79C6EAB51EB6FA5ULL,
		0x9223AA6563E9470FULL,
		0x7C4C41D78C811991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2400E815A78A7230ULL,
		0x58F363956BBEB410ULL,
		0x578EAC59714BECCFULL,
		0x40E552B9ADC90A33ULL,
		0xD6E4D9D35718EFC8ULL,
		0xD8F33677674F1684ULL,
		0xD0AEB0C2BF6329ACULL,
		0xEDF4B15C56431E25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F8530B0B85B2F44ULL,
		0x8BBCD29878A138C0ULL,
		0x7AFB3D13C5B69DF3ULL,
		0x41DCCF9BC47E145FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE76295C03DE986D8ULL,
		0xA9DAD2DBF8A0DA77ULL,
		0xFB28EAD84242BFA6ULL,
		0x45ED765C5FA14D27ULL,
		0x6F66B72ED8ED6D5BULL,
		0xB5FC0A7BABD6B365ULL,
		0x09F27CE17712EEF4ULL,
		0xCF9FF60BBE2B3937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x486DF20ED02361F2ULL,
		0x2E2E40D22B236740ULL,
		0xA3192012C6949375ULL,
		0xE6B17900FDA2F56EULL,
		0x45CD1EB0A85B558FULL,
		0x15F826CEBF5E44F1ULL,
		0x0FE4CA5935A1D8DCULL,
		0xAEA818F267E3463FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBC1466CA375ADC6ULL,
		0x3C405DB4E75DD875ULL,
		0x76184AFF327773D9ULL,
		0x4406CF1E30AC6888ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0F586B390416CE4CULL,
		0x3BFD1A5E1A9D950DULL,
		0x071A41FBF1D3CD64ULL,
		0x64A6ED5E875E0E66ULL,
		0x1EA855E38F1874EFULL,
		0xFE9998C0BA333D93ULL,
		0x0A2A32198F43C527ULL,
		0xA01E38F5DEB5DC9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB7AB4FC06953A03ULL,
		0xFD0F73F25D0062E1ULL,
		0x088435E84054F103ULL,
		0x5F45214FE5096EC5ULL,
		0x56C263F3BF02D278ULL,
		0x2291F37BBC293CC9ULL,
		0x4DD8B0CD9CDC85ECULL,
		0x0BEAFA96D7CA442DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FFF9FD5E0B7B537ULL,
		0xE8102EA97319501FULL,
		0xF2AF3D59ACD23F42ULL,
		0x04FD0E29A94D4036ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x743AE46D6CFF25FDULL,
		0x7DD39180BF933E7EULL,
		0x6E62A07D7561B2A0ULL,
		0xB443B50437B88240ULL,
		0x6D849060DC28FD26ULL,
		0xE4E6C012466DC10EULL,
		0x7338BB4BD6996468ULL,
		0x2F1594A854DAFE1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC391E545F0596E10ULL,
		0x09BA9D415829A3F5ULL,
		0x58A10661895EEBCBULL,
		0xE53C14B7C0F49538ULL,
		0x8D4B1B4D9CB1EB7BULL,
		0x4A8FF86B5F913775ULL,
		0x27D2E85A853C9131ULL,
		0x2B23B0A6FDBF15C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9306002E852574FULL,
		0x5CFA9705AC260739ULL,
		0x46DEE9EDFFCA2116ULL,
		0x64EF787F64E869FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5592B18B3B3A7A9BULL,
		0x632F109D1F4F96A9ULL,
		0x83079B953ADB9D61ULL,
		0x4C9CC49250F64271ULL,
		0xA5F5ABFA7BDEABB0ULL,
		0x8D5E58550BA772E1ULL,
		0x331D00E7A6FA82EAULL,
		0x94F6D8CC77743F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x629B0A0FBA2CB996ULL,
		0xE5331BE735B3E7CAULL,
		0x6B370BE07C92088CULL,
		0x170E750ACB69FEFCULL,
		0xE8421F8582890779ULL,
		0x5688CBB977D7A6DEULL,
		0x830A3D5A1FA9F988ULL,
		0xC39CABE550E7BADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B9E80D883C42025ULL,
		0xA1AED3CDDA73F747ULL,
		0x3A9996B6D43DF968ULL,
		0x48F0F9D73E67F6B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF4D6F369811F67B1ULL,
		0x02175949AA4C5150ULL,
		0x6C60011878ED6BB6ULL,
		0x0864E952B00D0EFCULL,
		0x3D565C11C84BBC58ULL,
		0x1F39A91DBC4EF39EULL,
		0xF5EBD3F6472FCC21ULL,
		0xCC754EA88B21E7E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51B4A93ED1FE887ULL,
		0xFA4995DD98FFCF33ULL,
		0x9B3D4C1788D091F1ULL,
		0x7141D41780C3B585ULL,
		0x96842C6524557702ULL,
		0x303893352EF1C9E8ULL,
		0x9615E67E1805AC08ULL,
		0xC5978E48BD15A780ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2EEBC75EA8DCA01ULL,
		0x81F703F10D20B313ULL,
		0x0AE3F4D7F05D9D77ULL,
		0x1C0DA373C51AE7EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB1BF4C048ED0E6D8ULL,
		0x7C6AD631F5FB9AA4ULL,
		0x461268021639A4A0ULL,
		0xE5786DE91031A9B7ULL,
		0x789921CABE88B4F2ULL,
		0x75D93595D5E940CFULL,
		0xB29B2D8612F947B8ULL,
		0x7EB346C1EC3C1419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0CC373D9AF8BA9DULL,
		0xF36F11912CF86D3CULL,
		0x1CE7F68B89681DD5ULL,
		0xCF1FFC0679874BDEULL,
		0xDEC37A9B05E03494ULL,
		0xE5F496DE4486C64EULL,
		0x328A60406CCC3046ULL,
		0xA3274DB1826F9F58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6A9E5DC5CDB395EULL,
		0xE4EB53E05DA15C7EULL,
		0x2BA8E9CD378301A5ULL,
		0x2D1F6A524B03B292ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6B5DD6F5AE435348ULL,
		0x57049A769343DDC2ULL,
		0x3112B2FC6AD43AB3ULL,
		0x4225000E1E9E66F2ULL,
		0x3ADC06FFA603CBDEULL,
		0x61D556BF658CE345ULL,
		0x541370DB29E8F863ULL,
		0xD82B4A915386B424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7273FD257139B0FDULL,
		0xA50FB6123EC7A05CULL,
		0xC2356D3E707C458FULL,
		0xA6F0B9877E80D36BULL,
		0x58B9C007597D7804ULL,
		0x9D8C59AAD20F08A1ULL,
		0x8EA3F0BA33080FDAULL,
		0x47132BE13C24D199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A0062AB98FA17C5ULL,
		0xD4CA7572392AB1B9ULL,
		0xBD6A4AA29FBA7970ULL,
		0x24C8D4AA18A5341FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF624EF93618ADE6DULL,
		0xA9B03C1BF3EB42FBULL,
		0xA7A5A282424EB046ULL,
		0x2E70A8E26A230CAEULL,
		0x5F529DAFAB56C0B6ULL,
		0x0BA0F7AF0290BC97ULL,
		0x1C8598763F4BABEBULL,
		0xA901F2E8AF7137E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AD2E933CFFFE17ULL,
		0xC364819CDA58DE98ULL,
		0xE2E21BD5F0C09171ULL,
		0x307E4D34176A4CBBULL,
		0x025F48D8D9AEFBFDULL,
		0xBE13987D8D8B5E80ULL,
		0xC623822CE92F64CAULL,
		0x0486183A24BAF145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A9658E34372175CULL,
		0x6947DBD6785E5BDBULL,
		0x9752D58F19C0ADA0ULL,
		0x6854D196E9C73BBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4268A4634B8EBC57ULL,
		0x9D71DFA00B0D7F79ULL,
		0x6EAF8F9C7158CA36ULL,
		0xAA5A4A7F6E0CCE86ULL,
		0xAE5750947F7E8F2FULL,
		0xEC64E3AA77C87961ULL,
		0x1B6AA0810917A938ULL,
		0x5B11D3B97982C05EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA2B933F056B516ULL,
		0x15B074ECC6790844ULL,
		0x2EDE21CEFDFEC8BCULL,
		0x10F33AF2CEF10934ULL,
		0xDBF7664038F95374ULL,
		0xE74B30F50D04EB10ULL,
		0xACC95A3DEE2E65F8ULL,
		0x137CE348AB6FCD0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7102B3B1D2FEE6A5ULL,
		0x4991F1A11D9B9734ULL,
		0xABC1DBC371F9FCFBULL,
		0x3982C04B35EBE342ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x82F081AB7CD9FBEFULL,
		0xC96F52DD447B5E0FULL,
		0xD5F947A0BB9AE7C7ULL,
		0x8224322A91036AFEULL,
		0x7C8474BE02CB2BB7ULL,
		0x83DD74F252679732ULL,
		0x67D4DA6B9C0ED43EULL,
		0x7AEE0DE83108BBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE2711B29E98ACABULL,
		0x58F27909FE072C21ULL,
		0x869E1D741F1354B8ULL,
		0x2667119B38F44095ULL,
		0x170B557779EAB337ULL,
		0x4147007A88907316ULL,
		0x4441A15EF61A663DULL,
		0x0C1806010389F0DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4C414712F9334B7ULL,
		0x52D2239B3C638E24ULL,
		0x9735A20D3ECFE73FULL,
		0x4F824CE018E149E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4797D5C448B6D433ULL,
		0xC7913C99F0BC1D79ULL,
		0x3C370401E26B5513ULL,
		0x41612EB3AB393BE8ULL,
		0x8122418C75A670C3ULL,
		0x9F932846D1573CE6ULL,
		0xDB51E8F540C3D094ULL,
		0xEA4265D32F0CB0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E921D603C0B6F7EULL,
		0xD0BFC3D74275EA31ULL,
		0xC96D8333B6703F76ULL,
		0x67D50816F7E5AF33ULL,
		0xA21243B1D0295D76ULL,
		0xE73119293F63FB3DULL,
		0x9791AEB3A58B31E8ULL,
		0x0E6DC16DCA66F906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x556566D89D3C46E3ULL,
		0x555FB7265861F259ULL,
		0x8152268B3662A31AULL,
		0x7B1C8DA9A3ECCFAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC67E2B74D5312146ULL,
		0xF67E07F6CB45193FULL,
		0x2B86F1084FAAB513ULL,
		0x7634DE7D41E9FD20ULL,
		0xFCBA7AFDF2492EAEULL,
		0xB8679128F3261B10ULL,
		0x16A550B3ABB4EB04ULL,
		0x9106E8163E3CED7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003C7650AF934436ULL,
		0x62A56B8344E5F2B1ULL,
		0xC807FF964F2F0897ULL,
		0x883DBCB38420C50DULL,
		0x1F8EE7D1BEBE9CABULL,
		0x8450823DF9076AFCULL,
		0x49F354A7588A3FA2ULL,
		0x69CB93052614753CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AB98DB3CC2F8A53ULL,
		0x4F44D354A6ED49A7ULL,
		0xC5EA5B4658D11D10ULL,
		0x40C5C25353CB113EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x468DD00C03D66B92ULL,
		0xA1366C0EA9EB39FFULL,
		0xB3D7AF5EEC3029AAULL,
		0x7CE4EB868277A420ULL,
		0x3C4A78C43654A2C1ULL,
		0xC6C8955C03830329ULL,
		0x50A29569352FC336ULL,
		0xFFDA3475CC6F52ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D082FB3F794F071ULL,
		0xE2159BCD675201D4ULL,
		0xEE9350C7F0FAE329ULL,
		0xDA477D3B5307CE4BULL,
		0x7F3F9F130AD5D38FULL,
		0xB506F4F5ABF72C58ULL,
		0x3DC2A2A52FC06554ULL,
		0x845231856CB156EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB921F0A481143F26ULL,
		0x61DE9F72415B1B26ULL,
		0x928267AFC9BD360FULL,
		0x78CDDDF965A33E23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2257C67442F9373BULL,
		0xCF0A3C7A175C7B18ULL,
		0xA10C4D055589E25CULL,
		0xAD6664493CC25B9DULL,
		0x12E346AC3BA7843FULL,
		0x3BBB007CE356CEA3ULL,
		0x6FF9F78C5F25863BULL,
		0x5A6EFCE6F8F546AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85A7F41B0EB7EB2DULL,
		0xBDC718C32802BDD8ULL,
		0xC5001BEC8C9FB9B0ULL,
		0x3E85696D1F3B8898ULL,
		0x7BC660B0BF6146DFULL,
		0xCDC4DDA99AC7A694ULL,
		0xE6B14BB702C40EA8ULL,
		0xE80433E2B69A7AEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AF9F5ADA6AE6530ULL,
		0x63CC4F13B499AF6AULL,
		0x3CD5B2C47F61E868ULL,
		0x6ABAD17DF701120BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x651D3AF742CF1333ULL,
		0x5CFD3153F6738750ULL,
		0x8AC945D7F8E22454ULL,
		0x3E96244D41446DCDULL,
		0x8619FAD0D52B97F3ULL,
		0x08EAA856E2AFE262ULL,
		0xC7F85ADDE9E06547ULL,
		0x942A96186ECD1235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B5FC17F8165DC8ULL,
		0xD93386243D8F3B29ULL,
		0x80EFE568FB1CB903ULL,
		0x61DBA81C7C8E80AAULL,
		0x6DF035A692455E37ULL,
		0xF8658E0745D3A8B5ULL,
		0x0525B84610D1B6F5ULL,
		0xD8768F3772B756CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x349A832538E545C4ULL,
		0xF78B93010194DBD8ULL,
		0xF51D82F935F34B58ULL,
		0x397381962FEFBF21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x016C46281B3516C6ULL,
		0x5509A40230AC87B9ULL,
		0x5C3D8538EC64DC26ULL,
		0xCFBECCFBAD1BE339ULL,
		0x61046A647BBE7699ULL,
		0xC7420EFDED229ED9ULL,
		0x8FEB7D09D8A929D6ULL,
		0xD1348E96EED8C11FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0078BB1B1A3993F5ULL,
		0x934FFA2321D689BAULL,
		0x212E9C1C12228E21ULL,
		0xA93C1B9250450941ULL,
		0xE5779F38CBEA51C0ULL,
		0xCC3E63E591926228ULL,
		0x94CB946FDFC169C9ULL,
		0x5248EB685FBE1645ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57D9B3891A78FDC6ULL,
		0x04450F7CA63F0031ULL,
		0x81CB6FF7CCA8CFF2ULL,
		0x7D7CEA529ACC3653ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x86FB29B0918ABCC0ULL,
		0x8DDAE5A39C452FE5ULL,
		0xD9AD3C99A97367B1ULL,
		0x7B5DCBB789B5685BULL,
		0xB413D0C85562996CULL,
		0x9CA0923002D0B362ULL,
		0xB4C877067D6C90F7ULL,
		0xB8AF0657CCF94C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DDD9E8C71FA843ULL,
		0x41ACF406E721DC68ULL,
		0x777B075156E25821ULL,
		0xED2F3DC9D5BA676FULL,
		0x762D2FD1FA1862D8ULL,
		0x66D30DBB961859F1ULL,
		0x3B4B8288F93A80AFULL,
		0x9D6979CA6D4AC6E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D593459576F2EFAULL,
		0x48AF9AE4D8809A4CULL,
		0x6ABE7FE9F1FF7A48ULL,
		0x1A816AE9E7E2D9B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x76799DBFEC8B9A06ULL,
		0x71D31DE79451E3EDULL,
		0x83D9D9D969BCB9D5ULL,
		0xF667A993D0F47BE1ULL,
		0x5C73083582A8F6F2ULL,
		0xCA8FE55CDE15B250ULL,
		0xD19159D9638908ABULL,
		0x3714831ACEEDB4DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44F76EDF9529AD78ULL,
		0xFEFCA7780FAD3407ULL,
		0x780EF89235BF3001ULL,
		0x56DA4D96CE5A3F98ULL,
		0x4CADC5EB9BE31DACULL,
		0x7413CC7B41EEC136ULL,
		0x99E7385943B1BC54ULL,
		0xEA31B25D6D90CE01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88CA05D898C02916ULL,
		0x494227ECB26C79C4ULL,
		0x4F0BDA4BEDF2DECAULL,
		0x09385819766480F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBD3F90404F5DFB12ULL,
		0x2B45F30352D7DDF7ULL,
		0x618768EDF5E4A6A0ULL,
		0xF02824834BF7290CULL,
		0xA53177B0737EBE63ULL,
		0xD54165890AA6AD3FULL,
		0x6FD5FF5F8091C5AEULL,
		0x67ABEED4EDEC6A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0EA2DDFC9FB5577ULL,
		0x16E4548E264EB003ULL,
		0xA07F8036936FA9CCULL,
		0x303706BA7025C297ULL,
		0xDA223AA244FC3262ULL,
		0x727D5D21CFEAD5E0ULL,
		0x1EFE1753B283C7EDULL,
		0x60A968C318CA6E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3098727B6CC36DFAULL,
		0xBD7ADDC7E46B2606ULL,
		0xC1145A77F888A788ULL,
		0x4A51046E7EDCC902ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBE9BCCE91B418088ULL,
		0x9E7964BEC69D9F0DULL,
		0xC91FC1225094E5D7ULL,
		0x2558B23E946CE018ULL,
		0x7790BE7BDFDFDAE9ULL,
		0xCFFFD7D8C94D7609ULL,
		0xCD05F812089D2FC5ULL,
		0xF4168A601C9F1BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59CDE522FDB5EC20ULL,
		0xEF52EC5BF5AC43FEULL,
		0xFC664EF7F6E05BC0ULL,
		0xB6960702ADAA5271ULL,
		0xD8ED11309DEF07A3ULL,
		0x0BE8E658412FDC2AULL,
		0xE54FB9E8A771930EULL,
		0xD6A2583840DF873CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF119A0F1E74AF151ULL,
		0xCA8E51770556321AULL,
		0x31C6AC4EC62DCD5DULL,
		0x4E021D2685329B9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9582BE6294D15DABULL,
		0x0C3894AAEECB7ACFULL,
		0xC2E1FFBD6AEC6530ULL,
		0x7F12137605E452DEULL,
		0xCFB61B536D80A907ULL,
		0xBDEDF73ECDAE01A3ULL,
		0xEB5432801D849CECULL,
		0x648C9F35CBEB71C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7C33D07C2EDECEULL,
		0x2075895CFE2782ADULL,
		0xC10BDC02EB3037A9ULL,
		0x468C1DA9E6EE9CBBULL,
		0x5D60A108EDC3DDF1ULL,
		0x128A5657A1A8C495ULL,
		0xF734D13960377AC5ULL,
		0x79FDE435FAA031C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90B6B1A10EA8A3AFULL,
		0x5C8CED9E796B0846ULL,
		0x3E7E943A992F3F6AULL,
		0x09B5B7C5302136B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x302A29D620E63DB3ULL,
		0x3307EF032AAA7C18ULL,
		0xE48669EE93774CC9ULL,
		0x4DE51BC9FF2AA769ULL,
		0x2338AC736768755EULL,
		0x61962A38F1166ACBULL,
		0x842043A7712E0F49ULL,
		0x21F22DEB8FACECB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6F1E190A0F6DD1ULL,
		0x982F3B739DCBBB53ULL,
		0xD2002E9D140FCC0BULL,
		0xBBA41072D6BD4CCDULL,
		0xF23A9B44D217D416ULL,
		0x2AF77C3500D57143ULL,
		0x870CA596AE6517C1ULL,
		0x163BCA8502DC065FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB7198A740CEC0B8ULL,
		0xB66688253683CAD5ULL,
		0xA36FB1CE693C3EF5ULL,
		0x4F53CC900F6F8AC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6FE6D6A144F50AA2ULL,
		0xD08AF0AE7A5881EBULL,
		0x6DE7A3299CB30C72ULL,
		0xBD531B80D0A9EF96ULL,
		0x1CF75B4ABED0D105ULL,
		0xBD4D029AAD7B112EULL,
		0x4E470B548D24483BULL,
		0x692EDF94A8AF04F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230CB31E72EB09FEULL,
		0x1306D8D892FBDA87ULL,
		0x79A370C81FC3E116ULL,
		0x1A3CA745D41CCD6DULL,
		0x4F0EB6974C02929DULL,
		0x693879DE43415C0CULL,
		0x40FE839D466CECA7ULL,
		0x9A7D8321B4D35F66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD629625DCA7430AULL,
		0x389063CDABED8A68ULL,
		0xED085795FC26C361ULL,
		0x516A2D4B2F27B5D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4AACCFD2B2261CC0ULL,
		0x20EC2604FF3959A1ULL,
		0x7C82F847A96616C8ULL,
		0xDD53BD9486E5CF48ULL,
		0x753B3764F9B6B65CULL,
		0xB35B921A46778F30ULL,
		0xD2EEBDD5472086C8ULL,
		0x28998EB8A39B45B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A508EA0514295FULL,
		0x39CFB938560FE019ULL,
		0x6D42724FA8E7DCA6ULL,
		0x6C2D81379E6B13DBULL,
		0x5E062A86BCD69851ULL,
		0x764DD7B80D6A1338ULL,
		0x1E3724672CCC3A66ULL,
		0x98A2D4607ED6F820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52E7AFE5B6566690ULL,
		0xF72617612129E05BULL,
		0xE2814C4FE90190B6ULL,
		0x4FC5E5725D9E3FCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0A8E6A9F48E6A180ULL,
		0xB07550D22CA12496ULL,
		0x8C22B722FEC13EFDULL,
		0x8D4ECF6B7A8F1F9AULL,
		0x77267376F4A0B1E5ULL,
		0x839803FA0A0DB5D4ULL,
		0xA203AD3EBF258DDDULL,
		0x3547F3E705FF6056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C4047AE31108C5ULL,
		0xB7543CF013545316ULL,
		0x016478E1CC1511A4ULL,
		0x3B42FF5F66A273BDULL,
		0x220C265E36710DFBULL,
		0x0A510C8A295CDEC6ULL,
		0xE1286E4571600208ULL,
		0xE72826EAF7C9397BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AB1D7D0A0E7E988ULL,
		0xF9A9CE7D738CBDA0ULL,
		0x2B499742BDFEEF08ULL,
		0x6AC43D762FF67056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4F232065BD57A43BULL,
		0x6382AE22644457E5ULL,
		0x88E10C654C803876ULL,
		0x9625DDA61CC79C0AULL,
		0x6BC2E63F52BB7F3EULL,
		0x49980D692C980CBEULL,
		0xAF530B633D965F68ULL,
		0x3D81B7CF304EB276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DB3CA155A011CBBULL,
		0x5B4FB51002F128D0ULL,
		0x221321B7F6FD4F06ULL,
		0x579B7C5E6497C191ULL,
		0x260776C5621BA48BULL,
		0x1F2C79DA672851D1ULL,
		0x37A0AAD017DEEEF2ULL,
		0xEFCEDF6EAA0104FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B41E26A1B10FA23ULL,
		0x542AE043AFE8EE4DULL,
		0x2B484084EEBD9AFAULL,
		0x47167F9BA7B79AF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6022FEBCA4CC500AULL,
		0xABC631281C90CC25ULL,
		0x0F180E800760D5C7ULL,
		0x03F3A7AA1E7D2062ULL,
		0x893EA49488FCC747ULL,
		0x2357A04714334409ULL,
		0x53511BC600350E9BULL,
		0x1126BE2561ED480EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167F53616663BF46ULL,
		0xA3886BCC540441D6ULL,
		0x847CDD19A56D677FULL,
		0x1B36F80D3390021DULL,
		0xE794322735A6D033ULL,
		0x59FEC8FBFFB8CB63ULL,
		0x40D15EC8FED8A2D6ULL,
		0xED29E4451B6A262CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48F0A7959D2B38D6ULL,
		0xEB6DBA80D2BA72E5ULL,
		0x49913EF495AB6D7DULL,
		0x404506E7626425D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2380EA6C5908800CULL,
		0xA31CA3F1C021747AULL,
		0x366BC55E5762E62CULL,
		0xA2F4547DB4CFF2C2ULL,
		0x20C39DE6F292B30FULL,
		0xE33AF0E09797AEEBULL,
		0x0919747BAEA9668FULL,
		0x62D4F9625E78A796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA303B9A331FB975EULL,
		0x34256AB542AC828AULL,
		0xC697520A7541234DULL,
		0xD91B4F5B9A7F5AA3ULL,
		0x3FE9493A423DF446ULL,
		0xCCF77D4226E86529ULL,
		0xB10177698129F1F7ULL,
		0x5271875C38B8166CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0E5C26B53A13AD0ULL,
		0xBCFA62C13779E4B6ULL,
		0x83640406A30D1172ULL,
		0x389BF20BB4E62441ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x817D121338B43EBDULL,
		0x955EEEB5A3925F27ULL,
		0x3D7711E2CE4CEA7AULL,
		0x63518EE5431A88AAULL,
		0xAB86F22AA15F08CFULL,
		0x8CB95C5335043DEBULL,
		0xD164E4BC9C155AFFULL,
		0x20C928552BEADBE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3688D479FB2D692FULL,
		0x62607B1A1EACB3FFULL,
		0x15A5139703FEBC92ULL,
		0x1066EC9A0C5D1FFEULL,
		0x63D13DCAB9AA9131ULL,
		0x1E2A268E3F43BA09ULL,
		0x9FDFB90EF79D9E62ULL,
		0x8712395A685C11F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFED03D5A25094C8ULL,
		0x9C406ED7FF793EBEULL,
		0x81967A1234142D46ULL,
		0x24121B843DEF622DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB6F81FCFB9C913FAULL,
		0xF4E9D21B6D525BCCULL,
		0x0B9F478744D8038EULL,
		0xE862E3E9D5737D51ULL,
		0xE6BD860AE6DF24FDULL,
		0x1FBC4D0A09209649ULL,
		0x0B0D38A457215551ULL,
		0x7B8A131F27879222ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75B4769504BB06F2ULL,
		0xBD6CCC9BA6F1179DULL,
		0xE1260763E60B9390ULL,
		0x4EF2AB0FF3D46759ULL,
		0x38517EE7A70CD3C8ULL,
		0x7AE25677E60F7718ULL,
		0x77F475D79D1B900BULL,
		0x4FF443FF494CFBEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x254CB8762E461BF0ULL,
		0xAFD79F30FAEBE58FULL,
		0x00262A86FBA7B854ULL,
		0x11ACF794DE516211ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x76756ED01C04AAC1ULL,
		0x246E08A76C31EC07ULL,
		0x4A938D2EE2ADB02FULL,
		0x8DF2231A00F12B7BULL,
		0x335AD45C940C9ABEULL,
		0x3B812A14B8E22DCAULL,
		0x949B9B84118C9E22ULL,
		0xEEF8263BEF2059FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD5439BBE33B357ULL,
		0xF54D5A75BAAB5A09ULL,
		0xD28D6314E76BDBA4ULL,
		0x7E59B85E554E6AA9ULL,
		0x155476B87BEB01CCULL,
		0x071C8E17F037C0A0ULL,
		0x516168002108DB48ULL,
		0xDCE3C504E429A0CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B92118FF2CDABB5ULL,
		0xF60FD5B77AD2C63EULL,
		0x72A9CFAFAED0C0EDULL,
		0x3E9ED8E74C423EB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x24AC7F7AB6FBD5F2ULL,
		0x7E69A1C455A81637ULL,
		0xC80F9BB676C503CFULL,
		0x48370BC2E17CA6CEULL,
		0x84B1870B9C19CFB5ULL,
		0x6757E1D8F456E8F9ULL,
		0xE8AE6A29B2B420F6ULL,
		0xE692028A361D42A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F3C5F2DE51415ECULL,
		0xFFEFFA60C68308BEULL,
		0xEC75768950786849ULL,
		0x2118284D6DE4A88AULL,
		0x5ACBAD03A9A41CBAULL,
		0xF749E7CB9D7FBD27ULL,
		0xC209DC611C7ACC6AULL,
		0xECA526B3165E4E88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD8E7D7ACF605122ULL,
		0x208CC55E73158EAAULL,
		0x980730F372CF2838ULL,
		0x4047856429F03B2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD7E23D714A1589FBULL,
		0x9C52737832029204ULL,
		0x0E0580B00FA0FD34ULL,
		0x55014F42C7D49F2BULL,
		0xB00AE862D5743B27ULL,
		0x20EFA8B0AA21D37DULL,
		0x37ABDD1196ACDACEULL,
		0x0C5C54D13582CB2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9BAA6420EAD7BDULL,
		0x0DB8BF4AE8BAE95DULL,
		0x33BED2DCAA64A0C3ULL,
		0x35F18F2E6F6ADB91ULL,
		0xA85E415153684CAAULL,
		0x4C4ACE2FDFB8FD9FULL,
		0x032CF0595685805CULL,
		0x1C0738444F2BF0ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10E75FA676F0186DULL,
		0x1F12234B54D7679CULL,
		0xA51DD12CEB13C957ULL,
		0x4BB1FCFE894E296DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x710BC89D4A8703A0ULL,
		0x4ED3774F9AD93572ULL,
		0x8075AC7E9891FCC6ULL,
		0xCB04E6D4CA3A7E78ULL,
		0x80A7EE864AEEC5D4ULL,
		0x241F1A7A4C802253ULL,
		0x72E7271ADDBDF930ULL,
		0x02E2EFEED3A81500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D860ECA0740F9EULL,
		0x0299B24ED5C6D062ULL,
		0xB31EF697F712A1C8ULL,
		0x547C86278B790C04ULL,
		0xB5C20BE4469880C2ULL,
		0x9D8E6D2F0FE0B10EULL,
		0x1032C08B93BDA735ULL,
		0xA662D45EFD0FFCCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68530BBD4EE1311EULL,
		0x45B37E2BC4BD3546ULL,
		0x741DEF2B9D8B862EULL,
		0x318C7807195509EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x416DBA0806CDC512ULL,
		0x210079A540100F3FULL,
		0x757B83E14E1B6763ULL,
		0xB8B49C43BE86B16BULL,
		0x71A44F387C7A217EULL,
		0x026D9359F83C4A09ULL,
		0x34071AFCCD221BD9ULL,
		0x9FF4175472EBC081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72708DDD86EB487EULL,
		0x2FAC8E946C70726BULL,
		0x4AC6596FF6FF9D4EULL,
		0x60D6DADA97D2AD8BULL,
		0xD6625F2CD58B93D6ULL,
		0x565603A278B6C4AFULL,
		0xCB962B62E1E2CD01ULL,
		0x5FD6A57C0FBCD174ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAC6CDE5474B84EDULL,
		0x7CD3404DC1716820ULL,
		0xAB78BB4A42817E18ULL,
		0x5C3CA787DFAB7FB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFA0DE2AFB2999E04ULL,
		0x9DB88FA339C79B80ULL,
		0x33B6A186E080A0CEULL,
		0x7EFA6E0373ED9AB7ULL,
		0xD64A9FD8D875C2D0ULL,
		0x362E7B0671314FC1ULL,
		0xD0BCB999D25E41B2ULL,
		0x430209EB6B4CB39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1360B9F444D24456ULL,
		0x5127BC1B0026830DULL,
		0x34BEC4A90020602AULL,
		0xB8E0D94F8A6126E3ULL,
		0x2D683BD8A92FB353ULL,
		0x1C9843E2B312DACBULL,
		0x58C2A1F1BCA22A0CULL,
		0x20890665FF6D42A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF84800C2722DA6E7ULL,
		0x18DD02D672267510ULL,
		0xCE175FD11A4BC34CULL,
		0x64101A81ECB737D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8B5366AC206E2EEDULL,
		0x24065605097284FDULL,
		0x6D9087F50DA6BD9FULL,
		0x591CEA196B11836DULL,
		0x4B30593AF2C5F47CULL,
		0x775792E68CD25102ULL,
		0xB1DC6F6227F664F5ULL,
		0x0DCDDA783CB91BCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E2CA23DE009EA35ULL,
		0xB4A6C2E11F101B79ULL,
		0x4F33AA4AE4A412CFULL,
		0xB863FB26EA28C686ULL,
		0x67DBD5F041121DF3ULL,
		0xE547AE7747601F54ULL,
		0xC28F314282317EA8ULL,
		0x6E7EB10200B0CF05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBB24184A1161AD4ULL,
		0x1DBB7BA83955C953ULL,
		0xA3D4165CC43CDA2DULL,
		0x4679167F6A242222ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x023CDE889FF25DEEULL,
		0x1F87B85F78C91393ULL,
		0x5DD7E7F943EE14BEULL,
		0x5ADB569848913788ULL,
		0x0CAF318A5B528777ULL,
		0xADC26E9176895DF2ULL,
		0x0894C76C6F234452ULL,
		0x6031676F2B082B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB9FDB827F70918ULL,
		0xA9CFAF04F5837DC5ULL,
		0xF9FE8B649F203FA9ULL,
		0x14419B3027E4B792ULL,
		0x2AC247018A3AE747ULL,
		0x28745227B35AE27BULL,
		0x1542580C7CF6B605ULL,
		0x2E7D0B514D3C2A80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCADB11F817D1D13ULL,
		0x3F50410D7C2BE972ULL,
		0x8215E4D2976AF496ULL,
		0x275F67D70CF49FDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x63076C80DB22C66BULL,
		0x712C9205B0D49B52ULL,
		0x6CFDD2AD57BE4AA3ULL,
		0xE4A643B9880AC18EULL,
		0xB1E2102D9D4B553BULL,
		0x71FB702B076CD54BULL,
		0x77E1FC954177870CULL,
		0x5AA71897503B4C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0809B2F9BA9D2B8BULL,
		0x508DE9BAB3292B3DULL,
		0x6BDD21A8228D21FAULL,
		0x1260CBC09F61E7F7ULL,
		0x3F81DFF7ACF072A7ULL,
		0x1990DEC60B0EF91BULL,
		0xB548F1D842273A51ULL,
		0x221E8E5CD264193BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5544E188CE033E2EULL,
		0x40703D48739A1F46ULL,
		0xE3D849131B1C8C78ULL,
		0x3689FCA7969A6AF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9C288356CDC3527BULL,
		0xCEE652B21242E644ULL,
		0xDE19F14FD9307FB2ULL,
		0xC1EB6ACAA36DB56DULL,
		0xFBE14E56DC23477CULL,
		0xBD0D1D990CBD03FCULL,
		0xFEB66D1DBAFEF30BULL,
		0x40B356C6E418CB45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED6220E8241701B6ULL,
		0x28EEAAB9C2C690ECULL,
		0xA5A64F409057E75CULL,
		0xE2420770E3CFAE0EULL,
		0x27923582CD92D488ULL,
		0x143684B21DB38D15ULL,
		0xA707DAE639748138ULL,
		0x4303B49F7F69846CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x328411E8D31D60EAULL,
		0xB5D25A3FCAE3FBC1ULL,
		0x3C5D564C83657DC1ULL,
		0x07BB7532B1A28BA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA60C887E3AF9F9ABULL,
		0x900C4AF0710593E4ULL,
		0xEC91EF29B8ABC99CULL,
		0x0C77FFB690409327ULL,
		0x262EFB8B8476371FULL,
		0x04CA82700EF4E392ULL,
		0xE54D82DD7F329A19ULL,
		0xA7369DD75D93E9BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB486CE5B61D09170ULL,
		0x67588F5F843E9A71ULL,
		0x4306640A5E6A4767ULL,
		0xA11A7641DAC2F949ULL,
		0xCB8CC3B73D8F8A2DULL,
		0xDBC7EE94DEB55DB2ULL,
		0x8FD7776778AB0029ULL,
		0xD8F38386990DEE4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x659A03A55F6712F7ULL,
		0x3F15AE1A1634D89AULL,
		0x59113EA452625BB5ULL,
		0x09537171E160EC65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1EC7F72504FD7D79ULL,
		0x45E7A4153D6CF568ULL,
		0x278B27A16C729901ULL,
		0x6CCC9B5FDF2388E9ULL,
		0xE32E9673412978D9ULL,
		0x7E4EABDF736F35F1ULL,
		0xB562622A0188F110ULL,
		0x4E3FF311BB923A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6738D5EC4A1E43ULL,
		0x54EA6998CEAF950DULL,
		0xE42BD0A3D42D6C62ULL,
		0xB281FF49F5B01779ULL,
		0x14E10C7F70E51155ULL,
		0x59D00CB0DD5A331DULL,
		0x8690ADC67BE2E96EULL,
		0x1E81FC32CE1C129FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E3388002DABDC5ULL,
		0x5BC8DB66B5DBCBF1ULL,
		0x36801DC36EEA4EB0ULL,
		0x507D412D28FD588EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x70F0C8B25788D182ULL,
		0xEFB943BFC7F3C939ULL,
		0xFE2C1B86CD7E7023ULL,
		0xF504A02198617BF9ULL,
		0x36FDCDD43194A6A4ULL,
		0x5274D3CED8D5C709ULL,
		0x55133E2915ED8E60ULL,
		0x734A94DAD145FD83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B06E836C8CCAD79ULL,
		0x5CC7585BF6B4CB10ULL,
		0x174A6DEE255F6B41ULL,
		0xF84D3669088B8A59ULL,
		0xECD9F95B78769F47ULL,
		0xA89FB8BF1F41CB88ULL,
		0xE9DEFB99BDF402C8ULL,
		0x4FF9D31EA7165F87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF73B6A6709313C95ULL,
		0xC893EFB95D365333ULL,
		0xD0A38EDFB729BD65ULL,
		0x3AB42BA6D2E764F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x843917797F70219CULL,
		0x165F08A74C96B607ULL,
		0x96DF097629AACA14ULL,
		0x1CFB6E3369A0503BULL,
		0x0DF35F2D6848F9C0ULL,
		0x53B6B1CA59CFF2B1ULL,
		0x36B39C598C4454DBULL,
		0x1796A838A8BECC38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x529EFA1CD5939A26ULL,
		0xE6781A4F068C770FULL,
		0xBA540BBD09D5F156ULL,
		0x7C68B693B9B7BBB9ULL,
		0xF6CCBA9D87C877A2ULL,
		0x11A5DDD4D4AAB49AULL,
		0xAD1FFD1FB9909874ULL,
		0xC73602E09FBCB75BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1568AB7FCEFD3FBULL,
		0xFE6664CA0991763FULL,
		0x4874A04E6682D010ULL,
		0x0EEB42B10637AD3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCCFD527E963D14ABULL,
		0xA6D0CAB644CDDA7CULL,
		0x901739EEA33733DFULL,
		0x428FAD150768522AULL,
		0x35B4938023692F31ULL,
		0xBEECA530CDB4F1CCULL,
		0xF4D22A29D3EDD9D4ULL,
		0x4A63D13507C3D6C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF92C142D6A42076ULL,
		0x1867939E39B7CFA6ULL,
		0xF68909130641A0A1ULL,
		0x9FD3EE5DBFB67F4DULL,
		0x3E0B036C9EC4FD0DULL,
		0x38E717FF50DEE450ULL,
		0x83515D424F1116A7ULL,
		0xD1A8348F54684DFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD095F4216FF86282ULL,
		0x733C2C7092DC0B3CULL,
		0x72AC9B3955BA8C00ULL,
		0x0E94FF4FE74820E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1A4FB26AE735EC6DULL,
		0xC6FFA1499E857307ULL,
		0xC01046395BD89AEEULL,
		0x6E08BB88744F4B81ULL,
		0x2FD0E8B5B7FADF87ULL,
		0xC2988344B5364C95ULL,
		0xACBDA14B871E020EULL,
		0x848033E4E41EF715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F51562D75EA7704ULL,
		0x384844F122EA5F28ULL,
		0xA0A534295A512405ULL,
		0x3E58DD3A9D0E89B8ULL,
		0x1F66D37D338E6011ULL,
		0xBE9DD4F7F782D738ULL,
		0xB6FD431D256F1A45ULL,
		0x32CBC085AE376250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ABD82A1196662B5ULL,
		0x25ED3BBCA43E7FAFULL,
		0x99F90CF2817DDEC0ULL,
		0x5078FE6FD7A0D705ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF51B2F4FE29272D1ULL,
		0x9F6EE8C24283FE6CULL,
		0xE93B16EFD265EF46ULL,
		0x408AB6B845FF3F14ULL,
		0x55A8F3DA51A9A7C2ULL,
		0xD86550DDC708F079ULL,
		0xC7F51CD5393931D7ULL,
		0xDF1BB0D5BBFA9263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C545BEF58E8C185ULL,
		0xB92B220389CDB9CBULL,
		0xE03F2BEAD74B2E49ULL,
		0xA14B3147D1214FE3ULL,
		0xB378EB6D1D12DE06ULL,
		0x2BCD22CDB9BBA950ULL,
		0x55301278C48C4E52ULL,
		0x92232E7DEC9E4AFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABE81396580BA4D6ULL,
		0x84DA9D20B22ED4A9ULL,
		0x123B74BE4CC486D4ULL,
		0x0C22DE793C9088D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2390274B24E19F27ULL,
		0xE2D9A0A48BAB8D22ULL,
		0x75AD21D06FB64207ULL,
		0x9BAD2379C20687BCULL,
		0xDE42B22EE9457D3CULL,
		0x25FFBAE31D54B448ULL,
		0xE57D10984AAC257FULL,
		0x84C34DE4C7E20B5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAAABF53CF65D538ULL,
		0xFDEC82CBEFCC47D1ULL,
		0x95871E602DDA6A93ULL,
		0xC271D42D40C461E0ULL,
		0x62AF32CEA788F4C5ULL,
		0xD4EB72099741B929ULL,
		0x28A56D7984B07403ULL,
		0x50830D985BF2676AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0CA504117780CB6ULL,
		0xEDEFEE2282B08BFCULL,
		0xE8283A01A5382FC1ULL,
		0x1AC4DAA486D47B97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x117E837B845A98E0ULL,
		0xAC2EE57211ABE091ULL,
		0xF068501DF0FFAF1DULL,
		0x1651ACE4950EE4AEULL,
		0x9F99C32211B12079ULL,
		0x05E6F9688D58F2B8ULL,
		0x2B637E42614765D5ULL,
		0x0FC9D90DA938B7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9F176C7E0A7588ULL,
		0x8B1222C963FEB2F8ULL,
		0x1A02F029B538EC72ULL,
		0x1A8881EE9B456ACBULL,
		0x898FB77F93E18E8AULL,
		0xDC499E720FFB396CULL,
		0x4ACC5E90573CB87BULL,
		0x3A95DA94A02DBC38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x385D262DB31FCBDBULL,
		0x4E78433F4996AEE4ULL,
		0x2CD41461B95C7DE7ULL,
		0x2180F0ED516AD1FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7AE15DB99964E3C7ULL,
		0x97FCE55F733FE6BDULL,
		0x35AD6431933E721DULL,
		0x07921F5DC3061809ULL,
		0xD00F1F260AEF5746ULL,
		0x2037DD635086BCE6ULL,
		0x7DEA23D38655DD6BULL,
		0xEFFD960448492889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AAAE740828E181ULL,
		0xAF8151E847C8F424ULL,
		0xB900E9D7EC9D6295ULL,
		0xE8C99FF3FE60BC08ULL,
		0xBC06DA03A4BAD89EULL,
		0x3C8AF3188F275180ULL,
		0xCA0B3748B94E1BEFULL,
		0x80B4027C3EC0D2AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD70F260BD06D183ULL,
		0xB4265A8FDFA0E3BFULL,
		0x2FC396F415C7C7EBULL,
		0x23B4659B2EE21B0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x34BBC9FDB4F28A2CULL,
		0x31A70BDFA691C61EULL,
		0xA9401946480AC26EULL,
		0x65901B010E63AD4CULL,
		0x26BF61A396DBBC88ULL,
		0x49BCD8B82763533DULL,
		0x12C95C90E55DCF2AULL,
		0x138A9E0EC8E5B649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95E862CA4D765889ULL,
		0x71B62190BACD49C1ULL,
		0xB03C11ABB2898ECAULL,
		0xF218E27507172A7AULL,
		0x3B1588E708E2088AULL,
		0x91CC40CE3EF7AE3BULL,
		0xC0688AF41743AA7FULL,
		0xEAA747E434B855CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A0993307A8CE484ULL,
		0x0DA777076BBEFAA5ULL,
		0x336324E12D62A4FBULL,
		0x053602DE0608D520ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAAA5B65BACEBFB93ULL,
		0x47D1FE72F6827DC9ULL,
		0xEFEC20C436777A5FULL,
		0x66890D19479B1768ULL,
		0x9471A7D090FCA84CULL,
		0x06EB1EEB0192A1D7ULL,
		0x9DC370D7EB759FC8ULL,
		0x631FB09E3DC06FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D51AA2E9F8134F9ULL,
		0x117B5BEF774C3801ULL,
		0x67956F88E73BAFF9ULL,
		0xF1BD86E39B2ACB85ULL,
		0x3726299AB634630CULL,
		0x27B1D5A2FFF3F399ULL,
		0x97E6A739280AF251ULL,
		0xEABF11CF07A8424FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3688C82B87250AFCULL,
		0x58D78333BCC4230AULL,
		0x671C9ECC51118A0BULL,
		0x532318F7B407092EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x62468045505B4428ULL,
		0x69619E5562C09A0EULL,
		0xE6D83DF5937ED3FFULL,
		0xBF7A93FE7CFC8F29ULL,
		0xC0BD3FC5B2EC3EA5ULL,
		0x62BD7D6856156318ULL,
		0x2E5AD25D5F957D24ULL,
		0x3F5A11966A084782ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814316A05FED6230ULL,
		0x30E8B3B588824B10ULL,
		0x0C184F6F4B8664A0ULL,
		0x11C724973278DC7EULL,
		0x278D1628D9B211B2ULL,
		0x403FAE12BE55DC8EULL,
		0xD1B163880AFF030AULL,
		0x26A29CFE981BFF7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E2996ED2F108EA2ULL,
		0x5725B15460AC4790ULL,
		0x9BE66230D64E8F40ULL,
		0x58EEBDF073966351ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAB30755805CF0FFCULL,
		0x252FD9715E00EF8AULL,
		0xF9D6A61D08B5BC45ULL,
		0x9F08EDAF7BEB0136ULL,
		0x04524B84396714B2ULL,
		0x1ABCD523EB497D27ULL,
		0x9B1E47FADD60B26BULL,
		0xD1D834B60200BC6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA4C0A909AA1BE2ULL,
		0x3D547BD82FAAED4BULL,
		0x4D5CF70AE22EB6EEULL,
		0xBAF43216611854B8ULL,
		0xF4667D311F7E9C9BULL,
		0x5AB20AAF492DB23FULL,
		0xBABFBE0513D615F8ULL,
		0xCAC55D6B5688F8C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A8C5504D4A6C797ULL,
		0x69756AE93E76208BULL,
		0xFA82298E111A3E5FULL,
		0x70E0B0AE8E99B827ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8576CCB2D6380A5AULL,
		0xA28DA7CD911FC484ULL,
		0xA62A2AF40383AA69ULL,
		0x21717AA536FC3853ULL,
		0x7C9FE5DB3DA4FEC1ULL,
		0xBE186E17A35B0B9FULL,
		0x98DEF8A7F3F52109ULL,
		0x332F1F87FA030151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A127BD7B1DF37EFULL,
		0x277E9AC9A683D51BULL,
		0xF28C47EE148BBEAEULL,
		0xA96675D381BB3D09ULL,
		0xDF65AE8EEC4845B6ULL,
		0xE12EB6BED5D7EBC2ULL,
		0xEB42578438AE0F15ULL,
		0x7096EE7295B0060AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD208862F381C4891ULL,
		0x45C044326C12AA28ULL,
		0x78DDCE53BB8495EEULL,
		0x5AA24DFE999247C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7E486E86D936468BULL,
		0xDE1AB6E104690D42ULL,
		0x49CF487529E2881FULL,
		0xBD51E1B3923BEC8CULL,
		0x29F9441DEAAC6E6DULL,
		0xE96155DFACAB4471ULL,
		0x2C3FCDD12BEF30D6ULL,
		0xB68D7EDC1EF1494EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519E17BD59C1099FULL,
		0xAA0E227211CE6547ULL,
		0x18EBFDE043CE9F79ULL,
		0xD141004A4A74AC76ULL,
		0x296EA79352FDBA6DULL,
		0x2980D6962B42F38CULL,
		0xB10170E93064DDCFULL,
		0x4DCAAF54455AE13AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x413D935C0363F726ULL,
		0xAF5F79582816A9F9ULL,
		0x7C2515043C9C3BCCULL,
		0x78FBAF93941AB2FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x831D62A3AA1886B7ULL,
		0x5D4DBEBE0544D284ULL,
		0x2087581CE2ABC6E8ULL,
		0xFCCFF7B392AF965DULL,
		0x9A1AFD4101BB8EB7ULL,
		0x20732EBA7A4F5770ULL,
		0xA6FC8EAC88E0D1ADULL,
		0xC47AF469DE87B2C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9507D14AEC97494FULL,
		0x724ECC7ADFE1285CULL,
		0xE22EF3C296C07B28ULL,
		0x5F6B9B30BDA229BEULL,
		0x5D3020F464F74FBAULL,
		0x37C5370C7E0F15BBULL,
		0xA28E0F60FEFB0D11ULL,
		0x9B835F27F9D8053DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8F244B802A297EDULL,
		0x74D1B61696ED6B0EULL,
		0xE6BF4990C4067AE4ULL,
		0x3224844AC7212E36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x46B865A60F22E889ULL,
		0x72788FFE2BA697C3ULL,
		0x1A865BA736B0F732ULL,
		0xE687DB69EEA5FB0FULL,
		0x435DD0150D9F5AE9ULL,
		0x110685E332F42E45ULL,
		0x0A09C009C4892280ULL,
		0xC01CB6EB14F37E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F68F7E4E55149EULL,
		0xE5A5D9529EE83EB8ULL,
		0x2FDEA90A294F18E3ULL,
		0x3BA42DF5CF431765ULL,
		0x13AD611C83CDE374ULL,
		0x51EDA121B1F5A4ADULL,
		0x8664004363C41725ULL,
		0xEA045EB807CF3A98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4F24F0C35E58E65ULL,
		0xEA84AB64B286C5A1ULL,
		0x75422A0F6AA18DC6ULL,
		0x7280C50812C4E6CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9349A20AD1204A1BULL,
		0x1CB3376997683752ULL,
		0xBE53A62A568BB476ULL,
		0x50790BD160DFC41DULL,
		0x219207061EDE040AULL,
		0xA251058B2F035BAAULL,
		0xFC4535BAA4083042ULL,
		0x245C7C47CB287A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2640C3592FA3437ULL,
		0x1B764CBB28ACF237ULL,
		0x38325DCC694D500DULL,
		0xDBBF05E21EB70C0DULL,
		0xC01849E0070CE679ULL,
		0x6553814607D8C3DEULL,
		0x6708490FB14ED811ULL,
		0x5478B09DB297BE57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68F7A97CC730783AULL,
		0x0EDE8CF23F0DCD4BULL,
		0xAD2C69BDF4C17BB8ULL,
		0x508A412EE7A49B40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB07E0AD4F876084CULL,
		0xF4D8FCEC351056E5ULL,
		0xE135B984908A72EBULL,
		0xACA903B50765376DULL,
		0xFA9B57CC4E4DC52AULL,
		0x6AFAE31B81A49156ULL,
		0xF2613F1794486FE2ULL,
		0xACCCDF38FE5668F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1E305C4F59C7A3ULL,
		0x57EA2B234FB5F35DULL,
		0xFEDF60DC5ABD3E50ULL,
		0xA0E280B12F0142DAULL,
		0x3F6386EF42BF25C6ULL,
		0xD8A6065D13DDE079ULL,
		0x941A1D7142E7667CULL,
		0xCF3C37F8DF40D740ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A8DB486047E8B0ULL,
		0x5587960D30D8A471ULL,
		0xE0E557584A3499AFULL,
		0x6F3F568875979558ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x05740D507B066418ULL,
		0x49D8FC8EEA9931BDULL,
		0xCBFFF149084B7723ULL,
		0xB89B0369E461E7E1ULL,
		0x4BF69DFEEB258F0BULL,
		0x04E0B41284D7EB63ULL,
		0xCA2B45B19655E1CCULL,
		0xDB4D1C435D117295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4712EF49F8AE09ULL,
		0x282E77CDF915687AULL,
		0xE9896B13E9B3424DULL,
		0x315BE7F32984F293ULL,
		0x216D98B0E355A7D4ULL,
		0x2FCEB48E2FE5893DULL,
		0x4605BA7687091AD3ULL,
		0x516763BC4FFF0F7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB83C3F659EA0B44ULL,
		0xC25672658D7E5AECULL,
		0x800930F963FDBDC5ULL,
		0x7F587F82AB97AB63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9291E65D2D28B26FULL,
		0xC724DAE941CDBC31ULL,
		0x64D0C9BDA166AC6BULL,
		0x00FA750152D52A6FULL,
		0x078906EBAB9E09B3ULL,
		0x7C90F0C7383D95DDULL,
		0x6C596CD38A2A538EULL,
		0xC00957C61C1EDFDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A61C06BF3E7A9AEULL,
		0x0762B3B797FDBEDBULL,
		0x57811FEB05829E3CULL,
		0xE2DC13524F49433DULL,
		0xFD7B42EE219AABDEULL,
		0x295F00F7EB38722DULL,
		0x39A495FED377417CULL,
		0xA5AA37718E21E979ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC63B3D93B5C0F6D1ULL,
		0x192BBFF718934951ULL,
		0x94278D65BA78BCE8ULL,
		0x083D2E3C17187A5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x24FF5C47D11C3FA8ULL,
		0x3CD31E307127112BULL,
		0x8AD2D611BB7266D6ULL,
		0x55A2566BBD7A3684ULL,
		0xD7AD0FC5F68ABFD2ULL,
		0xDC713840851DD7A5ULL,
		0x2CF84FC465DF4E63ULL,
		0x075D34DA129DB350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135A503594E99056ULL,
		0x56E977EA0F2C9A2CULL,
		0x7A506E49D85BB3ECULL,
		0x07A68B0A34670567ULL,
		0x755B615CE9038EBBULL,
		0xA2BFCD1869F4C07DULL,
		0x1C6F7DC5C8BA0A5CULL,
		0xC5D0B2CAEB5B30C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9C4EFAA3E43F494ULL,
		0x763F8E3A6A13E6FDULL,
		0x84D19393369ECBFCULL,
		0x08D719A15CF29175ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x36A23ADBAD0FD93EULL,
		0xC7920C84204D24D4ULL,
		0x5E9DAED11EA8CA13ULL,
		0x11C410520D7BBE37ULL,
		0xB4F1665B11178B26ULL,
		0xD55FE486E9958632ULL,
		0xDE13CE7496210163ULL,
		0xACF7093A11E68740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED1DFF09A7824E13ULL,
		0x675577FFC5F51042ULL,
		0x247943425E79E0E9ULL,
		0x5C8B57C62BDE6945ULL,
		0xDC6858DC5B605EEEULL,
		0x5EFD0B268757E8BAULL,
		0x64CD61DED6CC6CC5ULL,
		0x6DCC76F31BF241DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DDC3CA0FEBE1CD1ULL,
		0xF2E8D8D2EF7D745BULL,
		0x3A9889C926BCF8AFULL,
		0x158A6F1463DFA190ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4DD3981AB68454B1ULL,
		0xB03E7B96CAE61534ULL,
		0xCB427AE365D8FB66ULL,
		0xD44A5A9B4F0B2C36ULL,
		0x852BA01F1970E4ADULL,
		0xFED849006A98D044ULL,
		0x7D7CFD9C450DDF83ULL,
		0x2C844F1AE5F3A1ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x244F24B9793DCFB1ULL,
		0x779758E26ABE69B8ULL,
		0xB72BBB0124646C0DULL,
		0x371E5A0B1DC1B7CEULL,
		0x8DEB966A981E851AULL,
		0xB2EAAE99162FD2AFULL,
		0x699324743747615DULL,
		0x1BE62192770B45B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD05E42C6F80B544ULL,
		0x7DEC0E0AE7BD4F98ULL,
		0x08CCFBD44CEB4908ULL,
		0x14A6C2D0A7C724E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA45E5D35EFFAE898ULL,
		0x8EBB15BCEF5A625EULL,
		0x70B69051BF8EF272ULL,
		0xC9A29945149E7534ULL,
		0x1D989A20A069E2F6ULL,
		0xC03B2AF5479672CBULL,
		0x69306EC1D81173FEULL,
		0x4CCE1209064C321EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEEAB520FDC749D7ULL,
		0xC29F980174DABEE3ULL,
		0xA11EAAE735C46284ULL,
		0xC41E1FC4DC78DFFCULL,
		0x9A6701242675D04CULL,
		0x1B21EFB7A6A498C6ULL,
		0x54A28C0EDCE89048ULL,
		0x12F003A850B5FE3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ED05D8F0C6E6540ULL,
		0x4DDA48E15E660026ULL,
		0xDCA78BFBD1DC5D0AULL,
		0x1C7A9BDB2C714854ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2DF0ED1B2AD395CDULL,
		0xB53DD213027F1378ULL,
		0xCB654924BFC0D989ULL,
		0x9F6E987A6D75E604ULL,
		0xB85596BE34427689ULL,
		0x9C0DB242E2088982ULL,
		0xD556E9C4F00E1BF3ULL,
		0x974D81EC00DBB4E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4919E2C3E355B004ULL,
		0x556095580ACE3E31ULL,
		0xBE9C2C80C33171C3ULL,
		0x401EE20ED1D739ACULL,
		0xD99643B1B42B5D3EULL,
		0x6E4B955898803267ULL,
		0xC34134C6EFB677F9ULL,
		0xCCDA7B8AF7FF5BA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53D5E324AEBA5BBULL,
		0x2AAD8781E1EDC343ULL,
		0xBC01FA580991BEE9ULL,
		0x6C62A8D2EC53EAAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE6FCEFBE3CCB21F9ULL,
		0xA3CDEED1A343CB76ULL,
		0x4158A2ACA52DD886ULL,
		0xA8E4585BCA6BF733ULL,
		0xA5CF25B67A3B714AULL,
		0x22AB2B76B022CE1EULL,
		0x15CB926FACB84385ULL,
		0x4B3822A59E1F7271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16108EE8CDAA9B8AULL,
		0x3CF8E71192FC5553ULL,
		0xDF03584967AFE31FULL,
		0x15E11F5AD220C1F6ULL,
		0x9461CC9D9ED360EEULL,
		0xD7CAA078019966C2ULL,
		0x30A455A5E9383468ULL,
		0x5C41CCCD747D52DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67279A860092F3CBULL,
		0x8429A98DF8ACCDCEULL,
		0x662850564280339AULL,
		0x0B93F717265BE530ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1A6CBB9411AA3738ULL,
		0x8489B5992BE88910ULL,
		0x0B310C035600A46DULL,
		0x7DF852F52549F0D4ULL,
		0xA4497B4886BA7EA9ULL,
		0x3E1F17095BF4EF72ULL,
		0x13C8ACB0D83AEA9FULL,
		0xF4DD4B7CCC61CFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE8CFD2F5218B4DULL,
		0x8F0B7C355EF73829ULL,
		0xA3CC97B3DF7ED048ULL,
		0xC2D78D1E2C9A6F1CULL,
		0xCD5EF352531DE21EULL,
		0x4B68A7D40A3E9A5DULL,
		0x8572F032892C49EFULL,
		0xBC3B6BAA7DE79FE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71541A4CC5C7E9BDULL,
		0xFC92BB4DEE01F1FEULL,
		0x881E6F0F32ADAE42ULL,
		0x2327FF0E9ED2A28AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1D88CAF8A9BB52DFULL,
		0x8334EB7B96E753EFULL,
		0xEC0313AA1A2A75F9ULL,
		0xFB34B756142843E7ULL,
		0x12FE4148AF29E56EULL,
		0x0298F508E98EDEB4ULL,
		0xFE03E36FF3C721F3ULL,
		0xBF95BA3021A0F715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x699336CE3A79BCCDULL,
		0xEB55FE8F54EC1B24ULL,
		0xB51583814120CDE9ULL,
		0x63D91C1310AF8B40ULL,
		0xBA6592D5480B0290ULL,
		0xDF80456515B82A6FULL,
		0x2A3DDBFEFB6DE640ULL,
		0x2A31B75D35E99CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA9F794BBDD7465DULL,
		0xCD88FF3DB3D9FAEFULL,
		0xA652AAEDB6488480ULL,
		0x4434069200B02222ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2FF63B9CA4B71C2BULL,
		0x31633711F4332845ULL,
		0x24B628BC548F5582ULL,
		0x61B82947495789C5ULL,
		0xBBD922DC007F72F8ULL,
		0x347D1C6BB988D016ULL,
		0x46244C26AC09D1DBULL,
		0xAD5B3AE093873AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB07CE8D11F3F4EULL,
		0x4B59BE4488C3433DULL,
		0x4F56456455236410ULL,
		0x76E6457E4175F8EAULL,
		0x97DB5A5DA35892ECULL,
		0xD1EFCB875EF779F8ULL,
		0x09DECAFBD8EF6EA7ULL,
		0x828741522AC4F644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBF18175A75D1F89ULL,
		0x87037AB2DD02AD80ULL,
		0xC7B10FB35556AB12ULL,
		0x4648EEEC94B7BE8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x05202003340BF5D2ULL,
		0x3F7B455C54CF9B2BULL,
		0xF5981D8C5487C970ULL,
		0xC46F214255F3BEA3ULL,
		0xC5CE04BCAD9A90F5ULL,
		0xDE9B9DBEA3766DBAULL,
		0x4975B02DC340C0E5ULL,
		0xD26A8A8C15926B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C6C03E7E575175ULL,
		0x65A52E4E4D0DB43EULL,
		0x7932F599097B1D15ULL,
		0x91C098A2B7803EF7ULL,
		0xBEF6210D2A07633FULL,
		0x8D71F028A1319CA3ULL,
		0xA8A646C4E214B1B0ULL,
		0xD256677530CD9130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37652BD23D8D6D61ULL,
		0xE605DB525DF8F057ULL,
		0x5B2ECD84B796EE44ULL,
		0x35ABBE0593ABDAE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x744BE8B22B869389ULL,
		0xA32E25842BD9339AULL,
		0x686613E17A5874C0ULL,
		0xDA35583AC1A1AF89ULL,
		0xA3D8C5A8A485AF31ULL,
		0xB82CFC34660A48E1ULL,
		0xF77DCE8CE7F6A300ULL,
		0x1D1DC43ABF872A31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA1892999871826ULL,
		0x862845518EA5C60EULL,
		0x9F0BAFB84BABC844ULL,
		0xE495C3659530D19CULL,
		0xED76F84CCE066520ULL,
		0xBCB1D8A453DEE7BBULL,
		0x37F7DB65D7F29AD6ULL,
		0x688FD1957DF5C662ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x392EDB2A68E47834ULL,
		0x714D27954FA3D925ULL,
		0x373C7BF58F45E2B7ULL,
		0x42B1995CE805AEC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCFF0A2FEC072B6DAULL,
		0x1777E4D6ACFCC264ULL,
		0x3C94073D0B73A3D5ULL,
		0x4CD4F9EEA92DD382ULL,
		0x8AC612D28951A4F4ULL,
		0xCF38219171E58D19ULL,
		0xB82E917A4D4D9E64ULL,
		0x282D4711309E8F42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8C6694243EFAA9ULL,
		0x448999BE95FFCA3EULL,
		0xB3817394F5C991C8ULL,
		0x4F7C974DAC73DB69ULL,
		0xB7EAC1C78154E30CULL,
		0xD97960D9BF26B948ULL,
		0xEEB0310A3DE0E4ADULL,
		0xAA785A0F9B5570B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50F2440DCBB881BCULL,
		0x4D3EE65C9F506925ULL,
		0x71D4E44A5FCDA335ULL,
		0x263390DD25948066ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x94F764BEB786619EULL,
		0x4E158188D61FA479ULL,
		0x0C4D17C6EAB9A049ULL,
		0x76BD2F793E0353AEULL,
		0x36572AA7AC02F5D8ULL,
		0x04A123F3FC6BC20BULL,
		0x1CB3AD09B3F14393ULL,
		0x3955BA54F192861AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042DC6D1FA6D0145ULL,
		0x83A2F0FB7653C1C5ULL,
		0x76845D85762C3A64ULL,
		0x61072C1F3D0319DCULL,
		0xF0B30A3FFC221A39ULL,
		0xEA281CCF5C22FB29ULL,
		0xAD100350F024D62AULL,
		0xA9BBF27F4E5E872BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7266D50D879F76DULL,
		0xB8699FFD2A996824ULL,
		0x2813EBAE84E5A358ULL,
		0x6689AD103AB81136ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xED90DC755A00EF28ULL,
		0x6900DB1EED7F2DF3ULL,
		0x4B98D6B95A40F7BBULL,
		0x85BFA622CBF2ED83ULL,
		0x945FF53FC28BCDC0ULL,
		0x23C54A9D227716EDULL,
		0xC0777DEDC66C109CULL,
		0x8208864BC7117ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94127410F5713A5ULL,
		0xAF11A7297F70E421ULL,
		0x3CEA111C33B1B0D3ULL,
		0x3DBAEE9CDD7979A0ULL,
		0x6D4F8358F985684BULL,
		0x15EF1A611C17007DULL,
		0xCED531D7A354DF99ULL,
		0x2FB7C1FC87B08B99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0C09D76219CECBCULL,
		0xC7BA5CDE60519E77ULL,
		0xECC610E65C008D5BULL,
		0x0001DB4956DD8F60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4DBBA0682B8ED401ULL,
		0x0862A4AC251BE89FULL,
		0xAC54BEE11335DCB3ULL,
		0x413F1CF6DEC4D7BBULL,
		0x96363F358330AAF3ULL,
		0xA522A232E3F13159ULL,
		0x5BAF4A10F0513AC2ULL,
		0x85FC399D5235D949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F0637E0804FC6F8ULL,
		0x6D66F1C5C21661A9ULL,
		0xDE60251DA894BCC5ULL,
		0x260C19652201D8F7ULL,
		0x89E1806F4FFB6DDBULL,
		0xE6A01D226615E078ULL,
		0xF457E38C383953C7ULL,
		0xE81F01D95D08CAF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB349B9F345261C72ULL,
		0xE25B73591193885DULL,
		0x24EDD176BE2D6925ULL,
		0x0A094AA821731EB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8FD7FE35213EAAFFULL,
		0x31AC9C35FA188AC3ULL,
		0x65A046724003B916ULL,
		0x98AF13C046BC7E68ULL,
		0xA52C97FA8A1DEC2DULL,
		0x6135CD0901BD6A22ULL,
		0x772AD3825A977EE2ULL,
		0x55D7E445E7ECE39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0B3031429CBA64ULL,
		0xB45056BE5F0C7A5EULL,
		0xFF5EB84F8AD110A6ULL,
		0x427EF8100F0E7176ULL,
		0x4B244ACBCECAEF7BULL,
		0x26C93A6123067600ULL,
		0x35447A6AAE9BD998ULL,
		0x2EA58E78DA42728DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD00842F3ACF373EBULL,
		0x297A0A62AA344D7EULL,
		0x2E72C7A63C8D3174ULL,
		0x27A8D8203EFAD4E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5F32477E96D5D66FULL,
		0xC9FA7A0145E74C39ULL,
		0x292E69834D0EBEA1ULL,
		0x87DA37B340A27725ULL,
		0x2DB81CEC72FF7926ULL,
		0x0A5206EF2328D01AULL,
		0x1B7E6308BB732235ULL,
		0xEAEFE5E6A078454EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90B7FABBED354FD1ULL,
		0x3FA27A2CD54A9F29ULL,
		0xC58A2045D95C52BCULL,
		0xC0D61D2B510167A1ULL,
		0xA7B8DAEFCA3AE027ULL,
		0xC19295EB5F2E9E8BULL,
		0x3792EAFB18301DF2ULL,
		0x499D4C28537F9D6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB25E1843B6CF3FF5ULL,
		0x56C2C66387C00837ULL,
		0x38981B43AFA50DBCULL,
		0x3946ECC75C89FABFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x60848C335D4D6C13ULL,
		0xEB28FF547F05470DULL,
		0x3098000E5A71E100ULL,
		0x43084D293BD557BEULL,
		0x160E49A57CB76AC7ULL,
		0x6CD0E24FB1EB47F7ULL,
		0x97AE20C0A802E6A5ULL,
		0x655C7FCFE2781033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E95FF385E4B16CEULL,
		0xF12ED4D415605810ULL,
		0x668B0F399F9B31FCULL,
		0xF7FE98793CB68C91ULL,
		0x9DAC2310B4955757ULL,
		0x8F08A30FE1120558ULL,
		0x9F6A323ECB38F3CBULL,
		0x18E61FA1A7BEBA66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0804710B4113974ULL,
		0xE5B38DF969E4D282ULL,
		0xA422581B80D0BB5AULL,
		0x249BFB8CB6A18799ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEDA5B1E0F51B6A61ULL,
		0x292118DE987BA2CBULL,
		0xFE70963E7DAF8FD8ULL,
		0xF274E71D32415109ULL,
		0xF7CE34589CF52AD9ULL,
		0x61CB671A901B396AULL,
		0x52B10ACE271464D4ULL,
		0xB0EA94DFE8AD1F8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x861A6442787A5C53ULL,
		0x9FFE4F894F1AB605ULL,
		0x037C913A506BFD20ULL,
		0x4583F970E939E58DULL,
		0x8E336A906DC27289ULL,
		0x7CD8A5ED2CF175D6ULL,
		0x7AAFD0464F68C00CULL,
		0x79EE4AC521CB495EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x148541557E286B31ULL,
		0x852B76120193F4CEULL,
		0x0B22B52E30BE0863ULL,
		0x5663EDA5CE8D36BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE280EA5EAF4B0184ULL,
		0xE377BB4578380E68ULL,
		0x105DF1177B6DFA9DULL,
		0xFB7F4CAD1B50D86BULL,
		0x787AABC8F5C12E34ULL,
		0x8696D8A458375CC2ULL,
		0x88FAF35E605DE267ULL,
		0xD88BD03350AA1D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5CA6519CCFAEE3ULL,
		0xA706329AEB2A9200ULL,
		0x7C8F6E56A34A4953ULL,
		0x03CD7A24A7246DD2ULL,
		0x425A10B2AC8E2AD9ULL,
		0xD7C72B033538EBBEULL,
		0xA42943103DA32786ULL,
		0x33EEB027519FC9E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFB495BF00DD5D9ULL,
		0x2F454E95BED24308ULL,
		0x8AEEAE59FFDB6EA4ULL,
		0x670494504FB4C9A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x891C768180D2EFD8ULL,
		0x1DF140A9BC448761ULL,
		0xEA8BB5B17F1200B2ULL,
		0x7D0538D7CA867B07ULL,
		0xB9329C333DE775A3ULL,
		0x9D8F0FF1FB3D0699ULL,
		0xBCD345453710804AULL,
		0x7AD12E84E070562FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955CEDE9836DDF1BULL,
		0x9C8AC887FED40A85ULL,
		0xF5E8B53A7CF75E5EULL,
		0x11C0073E72A3B294ULL,
		0xA9CC8F6637461ACDULL,
		0xA5FDF5E012168C96ULL,
		0xE05012B021C01083ULL,
		0x50618C6D1A4DA94AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CE56F06F9588D78ULL,
		0x40F056CA59269950ULL,
		0xB01C82982C0B39DCULL,
		0x37D74120C108726BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5917416FA22AD94FULL,
		0xA0DF70AE574F6057ULL,
		0x4F18AF46D79036CCULL,
		0x7FDAEE13D411DF8BULL,
		0x8C1B8B324B94143BULL,
		0xC009CB066D679DECULL,
		0xB2479B6C736BA354ULL,
		0xED9A907197792D2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE570735743A5D025ULL,
		0x000046AABB5F59B9ULL,
		0xD02C87DDB5FEDCCEULL,
		0x0AAF2C3A3DF99266ULL,
		0xDA0FBB054EDF6191ULL,
		0xE77F909AC50D377EULL,
		0x6BEDDE071E981159ULL,
		0x127D19609A31D992ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE167B4C5E1579339ULL,
		0xC563D5FE995B3AE5ULL,
		0xF03E4473B8F9053AULL,
		0x7B8B6E5F2EAEB630ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x29055EF93115F9C0ULL,
		0xE28E38D0188A2BF6ULL,
		0x7BA55F730D820505ULL,
		0x9A266E18B81D31F6ULL,
		0x3A1AC3D3E76E2D00ULL,
		0x728A900791227872ULL,
		0x63B6E2D826FCF94FULL,
		0x7D0C927E9A1E98B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7C4573D0421D80ULL,
		0x05525456DC4E59AAULL,
		0x3410A9191268BD9EULL,
		0xFC790433FE3A78F2ULL,
		0x921C2E252666446BULL,
		0xF131EBB14012BC7FULL,
		0xF69ECEA974857E25ULL,
		0x0999628B4CF5B9BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE535176080064D1ULL,
		0x106449494491B850ULL,
		0x7927B54878D58F91ULL,
		0x40C688022DF3D256ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7E358A737878DFA1ULL,
		0xBC00B66097395DCCULL,
		0x840EE5FB60B2F487ULL,
		0xE6222CC247888B75ULL,
		0xCD16A076F6275596ULL,
		0x5078ABF7FA2DA1B1ULL,
		0xAF9BD7F6DC9DF0FFULL,
		0xAA3340D04FB88456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF43955244BEF3DDFULL,
		0xB5F91E9E79D1BECEULL,
		0xB841DBCE823A1EA6ULL,
		0x7BC303979E9F45F3ULL,
		0xCC25586894EAE088ULL,
		0x3F1E67DF9D7F65E8ULL,
		0xDD9E51CCDD85AE68ULL,
		0xE794F23350414E40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADCCE7719B830080ULL,
		0x996DB35FDF447ED3ULL,
		0xF76EF468BC12B84DULL,
		0x4DDED478949B4CBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60757A249B0738DCULL,
		0xB70B428CCD9AF860ULL,
		0x78409470A0040109ULL,
		0x1CF945B8AD1862D5ULL,
		0xC353873543698651ULL,
		0xE364BB7044606E5FULL,
		0xCBD9DF901B7C183BULL,
		0xB48D6623A6850CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D10B3BAE1F87615ULL,
		0xACC483CBCF5D6B97ULL,
		0x3F5A2D434B6593B9ULL,
		0xC12DE0B35A9B0AC1ULL,
		0x7A52E9A3BAC7AF08ULL,
		0x542C86A5E981AE41ULL,
		0x3967317724FCA38AULL,
		0x3877A368D75340A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x297C2A040114BA36ULL,
		0x4C9E94CA7B4E1148ULL,
		0xF5EC3EE1EB89BFABULL,
		0x47064CC013E1A619ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98E9F44500DEDC2CULL,
		0x424387CD706E8D1DULL,
		0x421EB36D94098D46ULL,
		0x238DBA34729B8BA1ULL,
		0xC43B238C09531E74ULL,
		0x17B5D3D37C49EED7ULL,
		0xEAD825F248B75640ULL,
		0xCD0D137BB3F4EB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x140119D1586BE276ULL,
		0x627B5B6567EA6782ULL,
		0x5E6AFA53E17E3E75ULL,
		0x26FDAEC653701AAFULL,
		0xBB90CC20A093D125ULL,
		0xF8D6E88D8F77660AULL,
		0x6710709E10B50990ULL,
		0x8156DC8882F61183ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE31D46534D87512ULL,
		0x74DF18C92FC4740AULL,
		0x7358A39A02E2B0CFULL,
		0x399C338764FFC255ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A9840093569BDA3ULL,
		0x43B6D9F9ED0B488EULL,
		0x31A92291834CFD8DULL,
		0x50FF1F556FD60E78ULL,
		0x0091A672715BA814ULL,
		0x5D7C58C9DD3D8B73ULL,
		0xDAD66C3DA9A57BC1ULL,
		0x47A98ECBA2BD8FB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4935BD02270DBB1ULL,
		0x5B810F00B95EC01DULL,
		0xA807B8FDB1AF21B8ULL,
		0x75D5B2A6D74DFBCCULL,
		0x123E273FF09AE721ULL,
		0x23A7C7125757A91CULL,
		0x17CFE1FDCF1F111DULL,
		0xF2E3F9BF75009C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5669C5B82F958228ULL,
		0x7DC36C3713CC2158ULL,
		0x7C99EF0E4191B035ULL,
		0x707D8C7D62943C16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0211E0DCA12E64BULL,
		0xBBC712C4B6AFB293ULL,
		0x99E1317D838D9247ULL,
		0x337C6A295EAB1E04ULL,
		0x2F4835B4209A4813ULL,
		0xD70FA79458FC09ABULL,
		0x3356796AEF9FC829ULL,
		0x8A8A742F030677B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B665347BEB065ADULL,
		0x6C9A4CF62A650204ULL,
		0x807669AC38A3921EULL,
		0x91AE10F279D1544CULL,
		0xC1C7293EB84E28C6ULL,
		0x99C30D09086C01A6ULL,
		0x190A2C8A913A3305ULL,
		0xAADDD780D3AD0D2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5E2A43386AF253BULL,
		0x688BB67C81ABE137ULL,
		0x00BE311F4DFE238AULL,
		0x556D9B11EC1F992EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77A563F6EE04E26EULL,
		0x7D2F0222C2048F74ULL,
		0xEBAAB6F5579FB09CULL,
		0x5E5A45234557746FULL,
		0x017EB9FBFA0F7516ULL,
		0xCAD3686D5C35B15FULL,
		0xAE1ACE0961E82041ULL,
		0xEEE84C5CE4B62E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB8E0D16B101815ULL,
		0x314016F41B5AFD49ULL,
		0xF761CA993453BAA3ULL,
		0xA2621569B8A3D4EEULL,
		0x0383C68BACB50695ULL,
		0x655A3E2A93DB0E22ULL,
		0x1B07061B150E90B4ULL,
		0x058E5DA5D5A5C6A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E2CA5D0FE61368BULL,
		0x5BEB3118641DCD38ULL,
		0xC93899BB8B9744F6ULL,
		0x5F519EE5C922F92CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x241D8DAE85EFAE60ULL,
		0xB3EDF352B361163DULL,
		0xDD88A3B4C894937EULL,
		0xF166E36395A79ABAULL,
		0xB9C4F2375EFFA834ULL,
		0xB65B109788340B6FULL,
		0xC7A116DA536D23F1ULL,
		0xA402180D2601D4D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDF144FB271B6123ULL,
		0xEC3132370340FA8AULL,
		0xBB0302807966F000ULL,
		0xC7064FCD1AA03C78ULL,
		0x4D68D11EC583B652ULL,
		0xDA1A2B4ACA9D981CULL,
		0x5AF299660EC6847AULL,
		0xBA9DE340FF0DA189ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BD9325A273A3444ULL,
		0x795ECA7FD4753A14ULL,
		0x446C40767FE94F22ULL,
		0x4F4069E44346FB9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4FE28AB9F7429B3ULL,
		0xDB6E33B34BF154BCULL,
		0xE33ADBED85C9B978ULL,
		0x8201EF3B26EFA8B2ULL,
		0x30496B6A5519D476ULL,
		0x273C7EC5E9ED61BCULL,
		0xDF2FF4F706695DE5ULL,
		0x7475A82646F0260EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82376211C494107DULL,
		0x77EE821B8960D841ULL,
		0xF6C2E4E753EAA995ULL,
		0x048AD45AC0CD627EULL,
		0x25DA2EDBA8FAFF11ULL,
		0x3EA4B409A99DDEA6ULL,
		0x1616AA89B48C65BAULL,
		0x5EC44BA264C9466EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF49C3C76773C6B9ULL,
		0xEA07C9894E5DF1C0ULL,
		0xC639034058ABE641ULL,
		0x35CAD673F7E77811ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86832959DB8A92FBULL,
		0x952214C151CF3EEBULL,
		0xD906383D38354BC7ULL,
		0xCA8A0E4695E92CFDULL,
		0x210B0AD1D7853196ULL,
		0xAE869D809AAB1BE6ULL,
		0x3B4C16EBA378B3ECULL,
		0x59701347D2F35E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBC077AACACDEA9DULL,
		0x317843CF2B297CC5ULL,
		0x7E10351ABE84D53CULL,
		0x15E2DF747A70CFC4ULL,
		0xB1977F83672A310FULL,
		0xBFEBB57DD4196053ULL,
		0x2D380A997FB8148BULL,
		0x0422949BD7B65C03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45E95F53BE3EBE56ULL,
		0xCEA8415BA04799E2ULL,
		0x71EFD753C8481EEEULL,
		0x5E27FC596686B541ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB4B4C822DA27662ULL,
		0xCBA9A4C6D3DD0002ULL,
		0x01CDEA72B0B2D741ULL,
		0x78131DD1F6052573ULL,
		0x4728D89DCC0CFA69ULL,
		0x6B235B392A174F79ULL,
		0x1BFB9065A323FE09ULL,
		0xC9BD62D6D0CE2A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F2646C9CA3FAEDULL,
		0xDA23DAB142F805A9ULL,
		0x966B9CD4563F8BF8ULL,
		0xCD5E4605308A2876ULL,
		0xDCCDAA782C62D38CULL,
		0xB8FCA67DC391FAE2ULL,
		0x1EF880A71D92EA11ULL,
		0xB205604DAED2BE28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CE1C1AB444040B5ULL,
		0x63449DE6C8AF88ADULL,
		0xF9D6A3E62DFC420DULL,
		0x30053827D0CD0949ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB512354F3A4BB7BULL,
		0xE6C67A97F242CA32ULL,
		0x234734AB532E74F7ULL,
		0x6BDE643C4138006AULL,
		0x4D59D9672C631C6FULL,
		0x3C5F44BA6DC6DB16ULL,
		0x9FD2F3B20224EA27ULL,
		0x36A80BF3180188DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11AC07DDD4E2F7B3ULL,
		0xCA0AC5598F05C2BAULL,
		0xE4DB72B0D9A47367ULL,
		0xF048591E922F623EULL,
		0xC59E32EAB0A29F88ULL,
		0x82C74D5D35356EEAULL,
		0xD2461FBA08804664ULL,
		0x6577057BD1BC1A2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF7FD1F17D544CF5ULL,
		0xA94A6D14C8D315EEULL,
		0xC15338C987FA5077ULL,
		0x08DD00D21D570C8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE492D9EAAED6F1EBULL,
		0xBDDF5D8165405950ULL,
		0x43558F5F07AFF6A5ULL,
		0x556CE4E44D2FCBC4ULL,
		0xB0215151076CE215ULL,
		0x6A237150E3CBB988ULL,
		0xD636284400FDD555ULL,
		0xDE0B6C5DD0FF4E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A4D97174A0233EULL,
		0x0FC10DB318390D2CULL,
		0x55D7AE82737FE305ULL,
		0x38EF5DD8122D916EULL,
		0xEE0CF5DDB079E3FEULL,
		0x05CE8245DE0DB8B8ULL,
		0x0B2F814FDE778CBFULL,
		0x9CA9A089E2037228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72F3939822488780ULL,
		0x92B9CB71273B6AFBULL,
		0x107AA919B41ED9F3ULL,
		0x5101C881B464DD8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB83B5E3C9CC2A8BULL,
		0xC9BFA340720861A9ULL,
		0x483E99E0AC9672F6ULL,
		0xE868E145C7CB591CULL,
		0x68F9856DA6F55C6AULL,
		0x34B7B22715CD4FA6ULL,
		0x7699BCBAF198D29FULL,
		0xDACE83E5E685F5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8DFC3AA3DF83B61ULL,
		0x794D32F37E4DA4C3ULL,
		0x3C157315E0186754ULL,
		0x4F0F87B16A3C3A49ULL,
		0x2639AB20AF5A629FULL,
		0x3BA6BD657A9F1DABULL,
		0x62F950C2C55E455EULL,
		0xD126EBB9851D499CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB1E59A64CD50398ULL,
		0x48F6C509FC962831ULL,
		0xF5F92DA15D2F0347ULL,
		0x0839F02AD318AE8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3617BA2D793FFF5ULL,
		0x87A6510EC269F2F7ULL,
		0xFBD1E5A1DE9E0714ULL,
		0xAA19EAC9684996B4ULL,
		0x2A0D74B9C8EB6A65ULL,
		0xEC90F4D06866D624ULL,
		0xC305913B6777069DULL,
		0x19D9DCFC8FDE8011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A85599328F6518ULL,
		0xB32EDAE08E44C09AULL,
		0x0B7FF1A9DB209612ULL,
		0x994ADF371958AC11ULL,
		0x78EED06D5A40C00AULL,
		0xAC8E164A2997A15DULL,
		0xB3829B4D5CF86A66ULL,
		0x22F98F92709816A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC74589621259E426ULL,
		0x54E47E1B86E707DBULL,
		0x3DC2754D9248A135ULL,
		0x361A8952F3649088ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BA7F607E3AD403FULL,
		0x5775943E314A6573ULL,
		0xDFA8883D445F8F0EULL,
		0x3342E02A8F4015FBULL,
		0x407E3FD1D9273EDEULL,
		0xFC332AB79A8CB83EULL,
		0xCAB260EF554501DBULL,
		0x70BA574B7066D696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CDF2AE64668C2EBULL,
		0x2B8FEF224E07DF38ULL,
		0xA0763888ACC280B4ULL,
		0xC93CA59B464956FBULL,
		0x9CDC7785A8C7BF73ULL,
		0x8576A6BA52F52671ULL,
		0x1A6DDCC1FB5F5B82ULL,
		0xC3306833615AE6C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28CC8670CB716548ULL,
		0xCBE13CB483C22A9BULL,
		0x695DEE6FEFB3BFA1ULL,
		0x2C7FB82184BC5846ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB584701C812D09ECULL,
		0x1D411B54D7E44051ULL,
		0x72965C5556ABD9A8ULL,
		0xFE6212EE96C23178ULL,
		0xA96C7160D21F0E3CULL,
		0x8A743A81F2A049E1ULL,
		0x114805C1EB501338ULL,
		0x211A13DF029CB159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AE7370FFD6A67BULL,
		0x8A95CC614A5FB240ULL,
		0xF0D628A594410F83ULL,
		0xC0F2C74AF78C0282ULL,
		0xE10F88F5A4F82CCBULL,
		0x133ACD332C03CDCCULL,
		0x231CC9D0E5CD8F6CULL,
		0x63D67631359595E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52A07C94351BD8BBULL,
		0x453188A508BEF927ULL,
		0xDC2B197693CA5A7EULL,
		0x5578B3700E444276ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4F130370060CD85ULL,
		0xFC20E7CB7A7FF261ULL,
		0x6894FD542E166166ULL,
		0xE6966BFC9830188BULL,
		0x9402A7C34AF624E7ULL,
		0xC02E549667997C83ULL,
		0xDC9D0993F7FD906CULL,
		0xA75634ABCFDCCC21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC270FEEC8B6313ULL,
		0x727A462907EF72A1ULL,
		0xC5506910D341F209ULL,
		0x67B5DB3E2543C66BULL,
		0xF5C445C77790151CULL,
		0x87B9DE3D1B67C342ULL,
		0x8070248AF9BDFF15ULL,
		0xD6B18270A107E152ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7714A9974FBC18AULL,
		0xEAF032E3C1F1FF57ULL,
		0x51EE93991844024FULL,
		0x7753058766872CE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10231245798E05ECULL,
		0x221F5764AB448DC6ULL,
		0x792BE7BFEA877F01ULL,
		0xC297CB5EADF8ED36ULL,
		0x0AC5725C0A940915ULL,
		0x37ED0A356E7F8EDBULL,
		0x45E652B24CDD301DULL,
		0xB7A0EEE435CF62EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0F479F838117B3ULL,
		0x182A8D15F179920BULL,
		0xD7C9F5476F3A6638ULL,
		0xD88C908BB9E12D58ULL,
		0x9B867B0717E6422CULL,
		0x1B53DE7A93E8283DULL,
		0xB1EFD76504A75153ULL,
		0xDFC4779ADDF56ADAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x496C8141FBD873D8ULL,
		0x48B1480B2C443719ULL,
		0x97F83FF1334C2AC9ULL,
		0x74C4EFB5FE72929FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10551D285E2BEC2DULL,
		0xB72216471888C498ULL,
		0xCD92F9E8C14E29BFULL,
		0x558687F59AB91219ULL,
		0xD32397501C813FE9ULL,
		0xD14DC1222AFF8BABULL,
		0xAC33C5305FDAB5D1ULL,
		0x776673318E7A9B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D050293BE0F615FULL,
		0x0267D1B41E0FB5ECULL,
		0x028E0D706185C03DULL,
		0x30B33812BAFBD5BCULL,
		0xF6F55F8C3575A540ULL,
		0x360B861AAEB6E215ULL,
		0x5BB4EA8E41788E5AULL,
		0xA37F367C5877BEF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x522C61A8EBD57EEDULL,
		0xC08F07AF6D423AEAULL,
		0xBDD96088E25A4543ULL,
		0x192652C8E429F801ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD79244503A30D5FEULL,
		0xFDDB3A0C064F3978ULL,
		0x36880E3704213C0CULL,
		0xF9DCE894F70F8D73ULL,
		0xE7343BDE914A826CULL,
		0x25AE8C3EFFE55218ULL,
		0xFFF4A1ABAF478C85ULL,
		0xC46627B6B5423B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEDC960E0D49C078ULL,
		0xBDECB0B8577B6171ULL,
		0xB4510B861EC36518ULL,
		0x00C4CEACA5945FE0ULL,
		0xC8D344A643FD9CFFULL,
		0xD7873E0D8139B388ULL,
		0x96C0D42950D599DAULL,
		0xDC229D9306BFC744ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B1A609DA6512342ULL,
		0xD9C424AC7C4D616BULL,
		0x1FE7840AEA47DC3BULL,
		0x731E9B3438D86B92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4A9A92CBE200E28ULL,
		0xA29B20EAADE21578ULL,
		0x5CBB7169FE0CFF96ULL,
		0xE22F06617D0B4D9FULL,
		0x8B9CD793AFC13D55ULL,
		0x8113D4DF529F31ADULL,
		0x095077414C3256A3ULL,
		0x2B63BFD6F51DE2D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607F4AB3BF33136AULL,
		0xF118D430CA18DB62ULL,
		0x0321568335AA1069ULL,
		0x0543BF466B3B6C26ULL,
		0xA2BC19C270C9B9BDULL,
		0x675A2C77F46718A1ULL,
		0xD8D456BBFC715E79ULL,
		0x5ED1A0507A4D1333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25868B8857AA8244ULL,
		0x83114C11E01CF1DBULL,
		0x8C06EEB09F07C56CULL,
		0x3A9BF5114CCEB3D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B2C906B98C82129ULL,
		0x83A015C58F52194CULL,
		0x57DCCB2532302D21ULL,
		0x832FE7078570A18AULL,
		0xC127317B8C6C8A97ULL,
		0x455641D8159A1C82ULL,
		0x13A15C8DA50ED09AULL,
		0xE85BB118EE285082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8727370C4FAB9556ULL,
		0x75D8DE6C282EFF80ULL,
		0xE92C89F8D397FD08ULL,
		0xF9E113EC6904332BULL,
		0x76E3263AE804561CULL,
		0xA882F15D1493746FULL,
		0xB6460D3E50B31A3CULL,
		0xAE4478BBE9F42186ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A1F04F7B0945745ULL,
		0x5525299B8E200CA9ULL,
		0x4A3E06F2E43541FEULL,
		0x28C130E9BC2B67AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9631F82277DC88CCULL,
		0x1FCDF088336E7C50ULL,
		0x59958D7D2C2370D1ULL,
		0xB9407E927803ADF8ULL,
		0x101332AED5C8E0A9ULL,
		0x15FD2113948D4F09ULL,
		0xF381C9FFD225DAD6ULL,
		0x4A7F2A065F4864E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF2F979A95751E59ULL,
		0x1507A7E048E9FD60ULL,
		0xE18206785083318FULL,
		0x429325DF1F28343BULL,
		0x2EA2329EF2F3EE87ULL,
		0x6A9D0ACF24B46959ULL,
		0x1531548D615170EFULL,
		0x95DC93BE17DC6BDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DC862E38E0359DDULL,
		0x7B0996D084B6970BULL,
		0x7804F6019B27F77FULL,
		0x46CFA76DF2E270C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EC8E4918D67B37DULL,
		0x9EC6ED4CB324B6FDULL,
		0x2E29F0F244F83D02ULL,
		0x63B07E4C648442CBULL,
		0x7419EDA5A0A067C8ULL,
		0xC71A7738A00C142EULL,
		0x72356D446F83BFEDULL,
		0xDD2DE17FDDB6D0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFBA9AED799E9491ULL,
		0x0CC37E1A1EB57CC0ULL,
		0x9C49B91FA4239584ULL,
		0x6F16050FBCA97B66ULL,
		0x919554DD41B74E9AULL,
		0x5E0142567950F525ULL,
		0x13BF5344280DD0E3ULL,
		0x77E7D9C3C745E404ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EBCF7622A62DDE7ULL,
		0x2BC148C45435D58EULL,
		0x976813DD3C56230AULL,
		0x7CFF9F27FC9DE96CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB31A64DB132E4512ULL,
		0x58A71B7434CF304EULL,
		0xD7B23BE7E0A646FCULL,
		0xC59AB7A570645DF6ULL,
		0xB57472C2D884E7FAULL,
		0x914681CDC077F753ULL,
		0x739A644090F271B5ULL,
		0xEC13F85034734CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x585DAE7AA77BF0DAULL,
		0xF025706EA6A51C51ULL,
		0x459194653B25381AULL,
		0x0C1D4B321D257D05ULL,
		0x109FC0AE477A31F0ULL,
		0xC1D39235A55336D0ULL,
		0xBDB9903EE7525735ULL,
		0xEF037E929E46BD4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD24F256DF34959B4ULL,
		0x33913B99959EA787ULL,
		0x91801FC1D344FDDAULL,
		0x49EF7E979DDC2C1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E8F6E0BF37B2AB6ULL,
		0x1050BCE1B8C89F42ULL,
		0x431A1E9F49CD80AEULL,
		0x2A2AE9BA45B5685AULL,
		0xAC7C6A8BED24FF79ULL,
		0xAFCB04002E3102EFULL,
		0x5CF3CB063AC3CC8CULL,
		0x924CF0B01B69EC48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E1186D2A3D2EA7ULL,
		0x42A6AF515D8ADE1EULL,
		0xDA85DAAEE7038AB0ULL,
		0xA3386F97592AE47AULL,
		0x263C6BF5541F6777ULL,
		0xDC1C99466C930493ULL,
		0x44914376FD618270ULL,
		0x2DD1ED0BF50C1A54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x892E1FF980128E6FULL,
		0x398DE52318B182DFULL,
		0x073463337F60F61FULL,
		0x713504809E77AE1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DA1E62D9A3F26EFULL,
		0xFFB272BBF131CAB2ULL,
		0x9E293609B1060E9CULL,
		0x0204B29C7B54F0E0ULL,
		0xB3989082249AAFD8ULL,
		0x8476414FAC62821DULL,
		0x77967AE89E0CC3B4ULL,
		0x7BB6A70E2E2CE4A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x663D69DAEA36C911ULL,
		0x1FCF085CEBC6A3A3ULL,
		0x3EB4CBC6793677ECULL,
		0x0673CFAC2225E91EULL,
		0x6D1991E0B5FE3118ULL,
		0x7219D6306F0AAE5AULL,
		0x8835C69211F1DE70ULL,
		0x1093CD6753C1A941ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE3E48491B4330ABULL,
		0x999B51022074960BULL,
		0xE7CF2F1C03CD9ECBULL,
		0x62BD31B4C519D871ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4B667C3EBE99A64ULL,
		0x1FB9D470F7D075D6ULL,
		0x018DA605D8B86E0AULL,
		0x0D90C026996218A8ULL,
		0xACD593C85960FFC0ULL,
		0x0A26E16901670B63ULL,
		0x4AECCD1F17AB3351ULL,
		0x12D4E21F14A82E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDB902CE8200268ULL,
		0xF5DE06FD9E52CA1EULL,
		0x678735067FEC8220ULL,
		0x69A26DD9C7EEFEFFULL,
		0xF872521BC340E312ULL,
		0x9413819265270146ULL,
		0x312B71CF6A1C2BF6ULL,
		0xDE64B36BFCBE6CC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC9697354C8DD536ULL,
		0xB0BC074E8AFF2BFAULL,
		0x6CB9FED31C070356ULL,
		0x6C9540E25E25D000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4807502F6CFFD8D5ULL,
		0x740AB75EF75BE9BAULL,
		0xE5C9EA0FFA53B8FBULL,
		0x6891EBE28BE27BD3ULL,
		0x2FE6818C9869FDF2ULL,
		0x9AABF3D419110D0BULL,
		0x99AA72F92BD65EECULL,
		0x339A5E73738B4266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87417667992EF29ULL,
		0x27518B9E0EA64AB1ULL,
		0x8952672637741B11ULL,
		0x327C2C0E33741B6DULL,
		0xEA351950B7D78F2DULL,
		0x73058BFCE0C4E91DULL,
		0xA0334BFC024521D7ULL,
		0x0FEE6700CC604C79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7E8B1AC49295BBBULL,
		0x2F6C95B34402F440ULL,
		0x64274C7DEE6EAF0EULL,
		0x019C7AD928CEE193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ED56B050F1375A3ULL,
		0x543C72CF1FFB8E88ULL,
		0xABA65D486DEF4BF2ULL,
		0x910AC398E0217413ULL,
		0xF227BEBB7016EC31ULL,
		0x2EAED58AFF5C3BB4ULL,
		0xE2717D786E5B0AF0ULL,
		0x663405D285DC927DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA10E4B741900D9ULL,
		0x26770F8764529CD7ULL,
		0xAA7CC4D7694234BCULL,
		0xFC6FECCFB51AA042ULL,
		0x662A73887A973CACULL,
		0xFCAAB1C66D07C2ACULL,
		0x76EB8F21D52DA297ULL,
		0x6467C56EC64AC3DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BCD864A0BEE8275ULL,
		0x9A62B2757432E8F5ULL,
		0xF70AF94BC16A944DULL,
		0x58EC65979AAB7F54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA521B01405EDD2ULL,
		0xD1E4C75A53058D25ULL,
		0xBD861B4F91D1CA5DULL,
		0x1AAECE0E376461EBULL,
		0xD56F96A27E47A46FULL,
		0xB8F952FCEBEF46E4ULL,
		0x4A88096EDC776FA2ULL,
		0xF11FE0E5656AD837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519106F3BB2ACBADULL,
		0x0EB8237FD2276646ULL,
		0xC36E737833D5DFFAULL,
		0x91D4989E64BF8453ULL,
		0x0C3F1E37305F58F6ULL,
		0x112E3DC03CA1D00EULL,
		0x9CB17D41BBB3D5B9ULL,
		0xA18D3D41616C60EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE645FAA9E95657BDULL,
		0xAB51CADC865DCAC0ULL,
		0xC7F0768A3B04C312ULL,
		0x589E7FC86A6A92D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x508CD9AEF64C8FDDULL,
		0x63C0070DD3CA9260ULL,
		0x86D08F7BFB36F6EBULL,
		0xBB0F1AAF41BF394AULL,
		0x7814F4B7C7549838ULL,
		0x8B55661F4A074D10ULL,
		0xF3DC76EDB9ED046FULL,
		0x03BDB0536F5A355BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77350A4481A1F78FULL,
		0xA3595CB254A2A262ULL,
		0xEF3C5689BB1E5FD4ULL,
		0x67B5155CD0E1B579ULL,
		0xCFF4F99B3004E720ULL,
		0x473F8F94873323B5ULL,
		0xCA37F77106F650BAULL,
		0xA6FB789025C67152ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE1715A8EA7EDE4EULL,
		0xDBA482F46AA61372ULL,
		0xC5FF2574D0B743FEULL,
		0x182E4C4F5CCC9D2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x534E07A6D0493ACCULL,
		0x86B699A5E1081609ULL,
		0x20384DD412040E68ULL,
		0xCA7521EDBA3340C0ULL,
		0xDE738E2DB3C80F35ULL,
		0xC30BEEB673F71242ULL,
		0x975E5950971FDD6DULL,
		0x46A412DDEDD6077FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777C2F3B5D1D3040ULL,
		0x189E36961466F089ULL,
		0x9662D67E3CB17E5AULL,
		0x332EF31DF65486C3ULL,
		0x162969AD6C4A91C9ULL,
		0xD92E9B9BBC7F72BCULL,
		0x8EA5146D097D1911ULL,
		0x31479C2D3E25B944ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96D343760FCCA919ULL,
		0x24F2B9070862D381ULL,
		0xD555B11CDB7BB5B3ULL,
		0x42FFCD09D80A56BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A4620C307168A07ULL,
		0xDA64875D543975EDULL,
		0xD0717348877C91E8ULL,
		0x896A4F4A6E238664ULL,
		0x38AEACCB6AA97982ULL,
		0xA8F8E66C33D9D81FULL,
		0xC71CBD8293D88A04ULL,
		0xA9FD4722DEBC0822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65947FD3621B6335ULL,
		0x6130D5D541DBE4EDULL,
		0xF53697CA4039BF39ULL,
		0xFDDD0214283F9A14ULL,
		0x02F37E6C03E777BCULL,
		0x1924B0EB0F8E0BCEULL,
		0x06EAD0A5A81F6C09ULL,
		0xDEE1F84C37C79BB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE7A8318E5C768F3ULL,
		0xD2B3A2B3759DE50DULL,
		0x62A4044944BD4606ULL,
		0x319B01130E2C049AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FC391146F69E4A4ULL,
		0x6E8C5AB6E2C45352ULL,
		0xFDFCACA95FB78540ULL,
		0x4DA40425FEA50794ULL,
		0xB221BA1E5A87B41EULL,
		0x45423F221E7D0BA7ULL,
		0xD09BB19C2E9D4AF7ULL,
		0x51C92A939B5E21C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477A68116B219692ULL,
		0xAA18212E4B7F7B77ULL,
		0x5A8BC14C60AB6A81ULL,
		0xB192F56BFB284E7BULL,
		0x73214C61ACE893C9ULL,
		0x2A4C61EE399770DAULL,
		0xEEA3D3916E25E6CEULL,
		0x4CBBDA5188AF1A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62597304C9E71AB0ULL,
		0xC4F30F3C9159D252ULL,
		0x2E3BE0F590C4F8D8ULL,
		0x5C0AF888C977CDEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2C37BBE92B21044ULL,
		0x29B9580D5F2D555BULL,
		0xEE8F883F35D06112ULL,
		0x389D02BB48114B2AULL,
		0xEEFD65BB720CEF6CULL,
		0xB0F2091B35041070ULL,
		0xD580D3ECB5927713ULL,
		0x1DF970E901740608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3E478CBE91F5DD8ULL,
		0xD2FC3D0AB84FD56EULL,
		0xA742AB02C38DD329ULL,
		0x385CC23FB20966EDULL,
		0x4A261B821F9B1335ULL,
		0xA46719C8DAD6212AULL,
		0x8BF22CF2DC4CA694ULL,
		0xE58E987D5F69D3D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D40774E6795E22ULL,
		0x335CA13C09AF0469ULL,
		0x3279A652B29F80C4ULL,
		0x601C6075A38B5768ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53DC53F21C1C8B19ULL,
		0xC73865CCA72C6DABULL,
		0xD323E3AAD3667D4BULL,
		0x8A114A71A8BAB847ULL,
		0xA1D1172BB1BC9F5CULL,
		0x36B441A44B178B7FULL,
		0x1D398364B46288E1ULL,
		0x9DE8AF520A7CA719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B038F81DF661D12ULL,
		0x186D045D635626F2ULL,
		0x0301236E5934425DULL,
		0xDC367039DA7D44F1ULL,
		0x011BC3A941B88A59ULL,
		0xDE2619DC49E033CBULL,
		0x3098D2CD06B6CFC3ULL,
		0x4A26BF7592438AFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03C329CCDD518E41ULL,
		0xD3E5491F720D4B89ULL,
		0xEFFCF6C041AFB549ULL,
		0x1CA474F1A6B79FEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x115EC13925717449ULL,
		0x4677BA350885FE19ULL,
		0xC762B4E59DCB2838ULL,
		0x5F005A0A9F2D7AF5ULL,
		0xB1FB57EF9CA64474ULL,
		0xA2C027F3795BC66DULL,
		0xB166B755A667326FULL,
		0xE22E016E195B6261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F57CC44B223D93ULL,
		0x0EA14670EEF26E50ULL,
		0x4316D59173D34A25ULL,
		0x9520AF2A8F71BA0EULL,
		0x3EF2C2032FF428DBULL,
		0xC7431DE21C5E3D04ULL,
		0xFC57A5803C063D6EULL,
		0xAD13427F03A0E35EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FAF858CFCBF5089ULL,
		0xCC65F257E735F56FULL,
		0x64888501F45C3C33ULL,
		0x2BD8025D496A9B4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5605588F964D8797ULL,
		0xA12EB662401784F1ULL,
		0xE345234257BA5F03ULL,
		0x8424CD28B05CA475ULL,
		0x376A2C2330A63FBEULL,
		0xB6CBCA5DD494A085ULL,
		0x1B39606201A4AC2AULL,
		0xA514E7215800D55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B97A0DDCC27F980ULL,
		0x162DD8A7BC0394C8ULL,
		0xCC2EA5505C544416ULL,
		0x92C1DE75FA78EC02ULL,
		0xD92959BBE165A59FULL,
		0xEE9583676240F682ULL,
		0xF088ED0C68698AD7ULL,
		0x9FBD0AB45B725F59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x280CF3078DBC6EC4ULL,
		0x430F664F7C7F2C83ULL,
		0x6D479CA6BA2D0D37ULL,
		0x3C6DA6E033093C9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB1D243A7DC21159ULL,
		0xC080A7AA14474B1EULL,
		0xBCF33B75C31A947AULL,
		0x61D8D49F95C3FF76ULL,
		0xB8612D7E5CBDCD3CULL,
		0xF4E181C85A0DF905ULL,
		0xFC78CA14969075D0ULL,
		0x88A0771BC94368E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4A50A23AD6B9C5EULL,
		0x8DA9946E63FD5BE4ULL,
		0x655E50E9757F7811ULL,
		0x15EF2356BA7BB9DAULL,
		0x71DB75256691CDF8ULL,
		0xEDA2DAA47A7B1FC5ULL,
		0x1F39252B3A8C3D4EULL,
		0x4F17BF580DE9E0E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE51774B5ADE5A56ULL,
		0x4623E28EE0162EC4ULL,
		0x2F07652FF63B7FB6ULL,
		0x5634F856AA927525ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E22B4B7AC339C9EULL,
		0x7819FB85642B3584ULL,
		0x1C9331FAFA09467CULL,
		0x6ECEEDCA05226A07ULL,
		0x3CA46C1919A1F583ULL,
		0xB690877EAEF0C175ULL,
		0x9052CB64C8A5810EULL,
		0x6AE0D30723896642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B34C9452F0D219FULL,
		0x042A232FFFABF428ULL,
		0xCD3EB23FEEA3D3BEULL,
		0x13834B58B0B9A618ULL,
		0x1949E3BB30616A86ULL,
		0x0C6989BA7350DDF8ULL,
		0x381FA6E71620EE2AULL,
		0x66C864AB5BE2245DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x125E29631CBB1CA0ULL,
		0xB5B983763E3B05EFULL,
		0x66EBEA638B1340AFULL,
		0x76EC0410F73C8BF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F00AF811AD04D89ULL,
		0x53AE836A7FE62049ULL,
		0x4F9BE1790619967BULL,
		0x70BA9DCD83DC4761ULL,
		0xBDBB0A7F57E8AE24ULL,
		0xCBC7C60F67421E62ULL,
		0x45E14C7D997C7C17ULL,
		0x250F6E4E4CAF8905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x208EE2F97FC01D1DULL,
		0x2319B8793E4BB60EULL,
		0x3E751680B401080AULL,
		0x0F8C9A2CE8D0297DULL,
		0x12A31CC5F5E58C0BULL,
		0x129D7EBB51F2930CULL,
		0x44F8CFD14D1B09E9ULL,
		0x9A9C076244DDE246ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53FF160C27873D89ULL,
		0xACDB616C6B691918ULL,
		0x33A94C8BA88F8160ULL,
		0x6E4F4AA9C42ADE3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CA588575D821D31ULL,
		0x4112FFBB99B03603ULL,
		0xE4953E0D6013954FULL,
		0x4B4DBB6811BB6539ULL,
		0xCB5E46C3A8861DEFULL,
		0x5AD25DC683D3BC5CULL,
		0x497EC4718E558531ULL,
		0x5817582984839A6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA45EBA1173193852ULL,
		0xD16448D88F0D2C6AULL,
		0xA36786D1BA511A53ULL,
		0x7CFFA3055793D248ULL,
		0xE91C477ED71E4784ULL,
		0xDB7C0403EEAB3C34ULL,
		0xE857FEAC950CC4ECULL,
		0xBA5CC7EB9FC4F13AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E12B27CFFD2B687ULL,
		0x568009C52EA60F84ULL,
		0xACEF1278A68F0526ULL,
		0x37FF8192AE74AFF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x653819BA83DD1AB8ULL,
		0xD496467DCB3D65C4ULL,
		0xE461C65EF35C40DDULL,
		0x83DD0E972B416137ULL,
		0x0BA34C302B529CA3ULL,
		0xEBB85CADB3E34E2FULL,
		0x6F37E8944EFECFF5ULL,
		0xD149E507332C7B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1B94F79433A068ULL,
		0xD515E0ED1A2C7D4DULL,
		0x1F8A95BB80088286ULL,
		0x592A7E77646848FDULL,
		0xE8282F0A6CC45290ULL,
		0x84E604C33A007E7AULL,
		0x687CEE42B335FAF1ULL,
		0xB4B84EC2D29AAE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A62D85D38C879BAULL,
		0x42B9725EC8BBBD34ULL,
		0xC49858C093235CFEULL,
		0x684EDE461C7D7C49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09BA9FB17112F290ULL,
		0x298FF8DF287F3810ULL,
		0x2B9B8FB16939A8A9ULL,
		0xD920F5DC967E076DULL,
		0x90A0429DC9B55554ULL,
		0x7CBD5342AB59867CULL,
		0xFFFFBFEAB29E09D7ULL,
		0xBAC5733A6F95E28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8C8725F016A894ULL,
		0x1F5E21EB2D09739DULL,
		0x7267982E39E664ECULL,
		0xD0750CD461006000ULL,
		0x7333796FE40DB99DULL,
		0x4DBF091EDBAC82B9ULL,
		0x323B321D567D3ABDULL,
		0x2510A13F89054CA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C53F55B97DD6A6AULL,
		0x03F0D844CF245368ULL,
		0x446103FEDC3201A0ULL,
		0x418314466EF3E8B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD45241074080CBDULL,
		0xC76816667FD65532ULL,
		0xB03ECDE3E22CA242ULL,
		0xE829D5DF37211144ULL,
		0xCB6DADEB26073FAFULL,
		0xF634988E28108145ULL,
		0x39D838D4097E9E0FULL,
		0x4533253FE54E1043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD4AE7BF575737D2ULL,
		0xC201FE27E502A44FULL,
		0xF719091D90EB4603ULL,
		0x235BE063A58D5D48ULL,
		0x6B6528CEEC5E3F37ULL,
		0x8F9934B2A9B9214BULL,
		0xC83DC24A24FCE141ULL,
		0x0B685B9019136FFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x113DFE81ABC6E811ULL,
		0x4076EAD35BCBF00DULL,
		0x96135D3E3C8362E2ULL,
		0x58E7E593E2477E24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x527F45336E0C928EULL,
		0x557CB2AFB5B9CE22ULL,
		0x6E08E08614B0946DULL,
		0xFDA9796C02077C13ULL,
		0xE74D08505F2CEF51ULL,
		0xD27E028A1B9B02D4ULL,
		0x58EB6B24F22EC862ULL,
		0xEA399F35054A29C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F96B5FE9C0D38DULL,
		0xE8B37D731AAE0A9EULL,
		0x966590B3E10AD1FBULL,
		0x995E869CB311AAE1ULL,
		0x0B065C98F43BB58EULL,
		0xB0A86FEBC9E3C8ECULL,
		0x5C7967081C39BDC6ULL,
		0xB501CFD4BA8094B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F03570D641A5323ULL,
		0x727CF8BCBC3E5C14ULL,
		0x508FEC19F605559EULL,
		0x4A93BB1A68E1F0ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x449D31B5D81578E4ULL,
		0xBC8B829D22950C34ULL,
		0x61671255E195D9A0ULL,
		0x21E969E522749A86ULL,
		0x306ACA9217F6F1A9ULL,
		0x77245F93408DC4D8ULL,
		0x40997F50331D453CULL,
		0x421A3AD490FEF01CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0A639DA6886E45ULL,
		0x0DD5D3DEEEDD676FULL,
		0x600F42DDF4F57A4BULL,
		0x660AB12968B46422ULL,
		0x54626B49FCE5137AULL,
		0xA50E41916323E04FULL,
		0x4B365DA31360CFB8ULL,
		0xE3DF0FFAD319926CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40D0F2CC363401F6ULL,
		0xDDFE2305116F9115ULL,
		0x6E0ECF2AA299D0E6ULL,
		0x38A7150DE9CC1E82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1B0B30CADEC36AFULL,
		0xCB5B438D12977D50ULL,
		0x0560593099EA214BULL,
		0x5B6664483D2B598AULL,
		0xE918A90F4CA42518ULL,
		0xD91499F1519AE612ULL,
		0x1AEF93B0B7991046ULL,
		0x30A301DAA45B261CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8BD3D3A65A7D234ULL,
		0x2710766456A6E40DULL,
		0xDC1D0C56DCEDAE71ULL,
		0x93B774FDF4C75FAAULL,
		0xCA2E1B334282C424ULL,
		0xC69684AD8E79FD01ULL,
		0xD5E37E449DBAE4F1ULL,
		0xB7EF3932E8D07BC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FC4847BC938C5A8ULL,
		0x6301F537B2D331CDULL,
		0x690E7AE593F6E17BULL,
		0x325EB8301EF94261ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4AB1D338FC075AEULL,
		0x5507E42FE5F44A7CULL,
		0xDE09F5265AA1EAF2ULL,
		0xAB57C39300A8733FULL,
		0xB43C2CA776C5FA51ULL,
		0x029A5CCFE98BEDAFULL,
		0x6557CD9B0D786F8EULL,
		0x789E8D635C995AE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51A3BFEB6AFD100ULL,
		0x0F442D581D8D581EULL,
		0x9CE9120A36548D04ULL,
		0x9C3A66FFE23FFC55ULL,
		0x973CACE595C3D38DULL,
		0xAED2F8680B76E54FULL,
		0xF5B72305F46B3CC5ULL,
		0x42E72F2CE139CC43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D7DD7FC3F6266F6ULL,
		0xB55C9E42BF8630A2ULL,
		0xD2FA353DDC42E7AAULL,
		0x085558A96E97A306ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x782E706710FA4C0CULL,
		0xF8568C1D6924F71DULL,
		0xEE5A2A6A8FE89F56ULL,
		0x4A5409E61D3E32A2ULL,
		0xBAFD3602796FF6C8ULL,
		0xC7242F54883F8523ULL,
		0x65E4BEBFD9F8ECD0ULL,
		0xDB26776D5C3EB35DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD61D3593DAF5372BULL,
		0x85C41CCF4A86914AULL,
		0x1260828C9830F39AULL,
		0xC4A99E188A13741AULL,
		0x1F4A68F46FCED073ULL,
		0xE83DE3A444E0EBE0ULL,
		0x430E763F109030A9ULL,
		0x9FB443E223BA0D03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE9BAAE8A3F0C6AFULL,
		0x88C1AB781EA925DBULL,
		0x07C86AFBDD439981ULL,
		0x589E1277F6DB6FEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F2BB61061C627A8ULL,
		0xADCE4CA79D9A32F1ULL,
		0x3C378DE232E8230FULL,
		0x4B19BDF1B0E481D4ULL,
		0x22EC427C461AE862ULL,
		0x690F343975412529ULL,
		0xCBE75FCB27A925E8ULL,
		0x2C5A49C076866592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD943E8DF6BCDEE1CULL,
		0x9CA97BC608ABD6ECULL,
		0x9A142D35C86B04F8ULL,
		0xB8F4D1C27BF73830ULL,
		0x5D1CE59836D81999ULL,
		0xA0487C5916D81A0CULL,
		0xF285967660674239ULL,
		0xED3D336707E04733ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22AF970B39E2E701ULL,
		0xDEA41C2F9886024AULL,
		0xE6A74341FE44EA08ULL,
		0x70763D75A195CBB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFABA4E850AB41C4CULL,
		0xD805C285F4F3815FULL,
		0x709B5ECA12BD0B9DULL,
		0x5CCFDC57B83803D9ULL,
		0x5BE4EC64666167A7ULL,
		0x9FF2CDF5B420E035ULL,
		0xE1037927C19190FFULL,
		0x362FA4BA0AADA7DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F22A2693FA8E3A8ULL,
		0x4D9C44BB0F101E55ULL,
		0xAA88005B25F8FA70ULL,
		0x1CAF9C86AF2A97E5ULL,
		0x1DE6542F8041A8F2ULL,
		0x5C7BAD8EBA59B48AULL,
		0x815BA0BC82D865C3ULL,
		0x8290EC8A40F711CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F6243F5F3C185CDULL,
		0x8E184D13F973DE75ULL,
		0xF8FD7E5A3C407C1FULL,
		0x69AF96E8FA27B287ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCB57553490D2994ULL,
		0x616F2B0D2771A753ULL,
		0xD9CDECBBCEB8E3C8ULL,
		0x36CA561167578D1DULL,
		0xC05361D00048A537ULL,
		0x9DFA7D63D6FCD521ULL,
		0xA146230803D53C39ULL,
		0x21E55EAFBA965703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65A7436B593A808ULL,
		0x529A3D4D16E53081ULL,
		0x6EEBA6D1A45A635CULL,
		0x548C2005A46034E1ULL,
		0xEF2137F1A1B7A6C5ULL,
		0x5A616AB0EE3190FEULL,
		0x4B1E7B11EA081FCFULL,
		0xD9508B781F66C328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23CD381E9CFF4263ULL,
		0x178DB44E9EB893FDULL,
		0x34C53471FED0B832ULL,
		0x2855904CCC074ACBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C02A484CB372FFCULL,
		0x23B0F79850379B4DULL,
		0x933D1446BC86488DULL,
		0xF6A79CD596A18550ULL,
		0x0BDFF73AD9CF9C6BULL,
		0xD28F4F94A95FD67FULL,
		0xC6044D935F9D0933ULL,
		0x1563BB9E6F9EC0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DBB4146AB64095ULL,
		0xFF335798B611436EULL,
		0x84194D809A4F07CBULL,
		0xEBAA5DAB40AC63CEULL,
		0xD02828DD9762D104ULL,
		0xB9EB12C280AAF3D2ULL,
		0x7C84D1CCCD34CA13ULL,
		0xCF120EAB6B105954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x786F92483CA71C89ULL,
		0xCCDEA731A4FFFD6FULL,
		0xF810263FDDB09F84ULL,
		0x7B1CEB3D03187BE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x500EE71E0107B6FFULL,
		0x90F56DC5A88E54B4ULL,
		0x57D0F0F6C8C5C0B8ULL,
		0x48CB8BAA52470BDEULL,
		0x8A3AEF0841A12C45ULL,
		0x795CF42C72663769ULL,
		0x86C1E40CF82AABC4ULL,
		0x426FBBFDC33E8A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED50E8FD000E3C9ULL,
		0x846D7F46036F27A8ULL,
		0x73DC496E6DDCAB53ULL,
		0x57D86CACD9B035BFULL,
		0xE69AFB60023D04F8ULL,
		0x83A82F9BDDE7612DULL,
		0x2416E4D901D2E359ULL,
		0xB3E3EAC29848DF0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAF8038799E4A61EULL,
		0x855D1BF5AFF2F9E5ULL,
		0x8956893EEBF0D545ULL,
		0x19B42DC5D90E4751ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F3FBDA6D24D1806ULL,
		0x724E64C59A0777A2ULL,
		0x70041AFE60CD0134ULL,
		0xFB02A241CE89AC56ULL,
		0xB6A3D7EDF3554646ULL,
		0x90F26822C2D3FB98ULL,
		0x724804EA9CB58479ULL,
		0x8C50414712167312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x397264C97F9E2557ULL,
		0x82880B2C8AA8D973ULL,
		0x19DB6F5D871600A3ULL,
		0xB0153D330CAE7BC7ULL,
		0xA4E3F8767BA2D250ULL,
		0x9298F7690E97E07CULL,
		0x8D1E5B0EFC2CBAA7ULL,
		0x33246E7BD3F177DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8488499172C2B34ULL,
		0xB10D1529D04AA459ULL,
		0x5A57E23AAE04F5BCULL,
		0x076EAF39FB587AB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFE99C01C4F3DFE8ULL,
		0x4B38309D90041831ULL,
		0x395D8E2366184040ULL,
		0x19CC378543332A3CULL,
		0x7758C4BB81FC1A9CULL,
		0x992A3B67B43BACE4ULL,
		0x1B3568F38451F1A3ULL,
		0x7760C23D696BDC9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x593F902E412285C0ULL,
		0x830CC82A880B04F2ULL,
		0x4AC2CDEA07D9C8EBULL,
		0xF98EB7FE59FC7591ULL,
		0xEFD69AF294E63AD8ULL,
		0xAF6686B81482D56CULL,
		0xA91B10BA65603961ULL,
		0x098606A15E1B6556ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3FC3FA6B510937AULL,
		0x7B383A84BD690EFDULL,
		0xDE83D8B3F61FD11DULL,
		0x6EB558B0972868ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF219BC1E5FC53D6ULL,
		0x68A46CB19D063191ULL,
		0xF3A365310D5F3829ULL,
		0x969E6038B3BDA719ULL,
		0x8EB2FDC8090ABE5CULL,
		0x45B8E4E5EA017956ULL,
		0xED4366ABADD940A6ULL,
		0xB14DFA4C478FDDF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F92A439DD90D33ULL,
		0xAB4A742A41DDACADULL,
		0x05B1392998A242C3ULL,
		0xF05BC33D345F2FCFULL,
		0xB8B29EA286F22776ULL,
		0x238529F4FF05F70FULL,
		0x5B485D7930C711A2ULL,
		0x34E418D2ACCBEC69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B36910F97C9AF73ULL,
		0xD107B84A3C7DDB68ULL,
		0x99358986056FF002ULL,
		0x1DFA150878745202ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x965AA6108C9758F7ULL,
		0x684D329CC3C0A25AULL,
		0x2FF8F876056DED66ULL,
		0xBCC8DF2E4E6B5D48ULL,
		0xB8D9F78C53274305ULL,
		0x4D0E2DCAB500328BULL,
		0x4B994B94005172BBULL,
		0x51C3DEEB1D61EB16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2433A2354E56401ULL,
		0x06C36C0DA07B332EULL,
		0x3D4A56A4EA09C085ULL,
		0x48784025FE572F35ULL,
		0x6C40C21BC9C66510ULL,
		0xB7FDC00795B9DF2EULL,
		0xA6B72CE1347975F0ULL,
		0x6ECE0BA11D5C94D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52D55AA19C12E6BCULL,
		0x81FA1185C7B5CF05ULL,
		0x6C3F305B5D73B2F3ULL,
		0x24CDFC0450DEFB39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10E890A8E8566672ULL,
		0x1F3C18DA328B2D97ULL,
		0x42D5A3E851864AA7ULL,
		0x89ED64D28C08DB88ULL,
		0x875949C19AEE838EULL,
		0xA01A90728B7B4164ULL,
		0x893307894CCEAE87ULL,
		0xD42D94507A07CB19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954CFA64A3F445C4ULL,
		0x0B9A1134F9B2633AULL,
		0xEA6E59E86A4AA3BDULL,
		0x1366B3B5D20F0559ULL,
		0x373D7F6FA235B667ULL,
		0xE41B8A8A67A2EB31ULL,
		0x351AB7EA104512A3ULL,
		0x645EF12548F0699BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FBB9E6F2FD096FEULL,
		0xFB7CE81A8AF595FAULL,
		0xD4031BA2E3A8CAB7ULL,
		0x0F32E98603724EEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1043AC669E9F0F9CULL,
		0x7C77D029D5915DD7ULL,
		0x5F4FE177CCB8BC2DULL,
		0x0B87343DE3A20FF2ULL,
		0x3C6B651316FF8040ULL,
		0x1736FE0B1A61CAA3ULL,
		0xEE1D425773F89F84ULL,
		0xFEC2100CECE801AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50802BBBB1A6150DULL,
		0x324DE0CE2BAA4B5AULL,
		0x749E63EF10994B90ULL,
		0xC262AEEE35DBFD3FULL,
		0x7B405E2854BC93EAULL,
		0x5F51195AEB1524BDULL,
		0x9E96AC318CF18835ULL,
		0xD61AAEDBBCE468DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C268783C2E81011ULL,
		0x9649E182AF47B297ULL,
		0xB8ABC729072CE64CULL,
		0x51FCF29CCE4EC1C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7236085E5D52AD2ULL,
		0x24D9E1627D9A1C09ULL,
		0x5A51379CD817121CULL,
		0x0C152D24B76CB6BEULL,
		0xEE7817D7DE50804AULL,
		0xE3763DE72340BD26ULL,
		0xD943B34C5412E3D7ULL,
		0x5200F8E00745C214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6877BEAA90F709B2ULL,
		0xA4FCC073DCB0F1E6ULL,
		0x61B4D32DBF9EB4FEULL,
		0x6680DF7FD189E50FULL,
		0xEC2B493BBCABE9DFULL,
		0xECB041FE8AD38D46ULL,
		0x6244206B1B329CAFULL,
		0xE56A41C5052193D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6124D08534C71ABULL,
		0x21408575411E4563ULL,
		0xA28C31DD89C2ED0CULL,
		0x43F37BA73741AF66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5359832B1B8B123ULL,
		0xF6C7B42F87F6B05AULL,
		0xA8D5DF6CC5D93B3AULL,
		0x24957CB20054611DULL,
		0xEE7A75DEE0187479ULL,
		0x38F292B1DD8DC59FULL,
		0xCDC67DABC0B08507ULL,
		0x63BBF9D0D518E4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF8C9EE36CDDBADULL,
		0xD943CC532E8568E5ULL,
		0x8263F6B8BADD2600ULL,
		0xA15703A6B682D7ADULL,
		0xEBCF698319BE515EULL,
		0xC561B3589740AB90ULL,
		0x76B88F0B4EA127ACULL,
		0xD5A3FECCFC8802E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFA0A3E3EC4C08DFULL,
		0x45050F1CC8E325AFULL,
		0x12835484F943F0A7ULL,
		0x1ACDBB9D6F531557ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB99D11A6E31EBEA4ULL,
		0xC2BFEE7198998FC3ULL,
		0x0D09C61B6980A749ULL,
		0x7ED476F56420B77FULL,
		0x29817E39AE3C51EAULL,
		0xD688D050F385BC6FULL,
		0xCC5CC8054F348460ULL,
		0x4B3087648BD45725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE73C1FF4F1A5F51ULL,
		0x17A1180DFBE99FC1ULL,
		0x01A889DC9F367D13ULL,
		0x58134D8E6C98842CULL,
		0x60CE4E3D1B525A16ULL,
		0xCEF77674557B7BCBULL,
		0x9AA3A66C7D428D86ULL,
		0xD712A53E75B4C3BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5C26F2562BF25ADULL,
		0xCAB22D2312358851ULL,
		0x6CDC38EDF434CE93ULL,
		0x6330BB0E403814F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE696E0D22B0962FULL,
		0x2205FF7411423B4AULL,
		0xEF1F6A8BA3C90E56ULL,
		0xD067D03EE29EB725ULL,
		0x467A76BA9F4CC2C1ULL,
		0xDC0BE2A33B5795E0ULL,
		0x4A668912C512F30BULL,
		0xF9EC706DA85EA3B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE6A572B72DD809AULL,
		0x4326D72578E7E7DEULL,
		0x8830041FF751FFA2ULL,
		0x7C7A2338C3C7CC8AULL,
		0xBF56839461E82D77ULL,
		0x397D6AA186F1E0DDULL,
		0x3006D4C77A105505ULL,
		0xB430192169D5A57DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF552E8ECCC14020ULL,
		0x0004F88F5F7331CBULL,
		0x51242998CEDA83B0ULL,
		0x2DE2A257672CA787ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE303D4C1EFBCE314ULL,
		0xAC1BBD0101E716B4ULL,
		0xE6E694085B9FD23DULL,
		0xACE2234558BDAB4CULL,
		0x898A61B3F3FDD41BULL,
		0x0D21B9E08EACA217ULL,
		0x207E6E98A22F99F3ULL,
		0x5CFE0FE9671C264DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F0F6D858E3C1B7DULL,
		0x8536F1D70BD68638ULL,
		0x61356EB0C77BA76BULL,
		0x5ED857D251DD598CULL,
		0x164DE38E72F7060FULL,
		0xC1A94A7FADB64CFBULL,
		0xDE2E8F1AC1CCD60AULL,
		0x8F44210C69A92372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEEF20CD88835C42ULL,
		0x5AC5538B5AA132B5ULL,
		0x5D8C5206E2CD3F4DULL,
		0x57A34040A5F2BE26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F83FF4A025AE13CULL,
		0x41EE676EC2E31576ULL,
		0x1D9A38946B0816BFULL,
		0x05312C22CA6CA452ULL,
		0x88D5F27597FD4883ULL,
		0x7864869C1F8C41A3ULL,
		0x01384D686386DB88ULL,
		0x8A9031B3E96C78E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B64EBB24FCB2D87ULL,
		0x99952484D64458A7ULL,
		0x151816399FE6CCFAULL,
		0x7D93445AC50ACAD1ULL,
		0xAA777F7D49459D8FULL,
		0xC2CB588803F38D4AULL,
		0x074D340F8EB2FB49ULL,
		0x5D39911281BC699AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6624247361D314D1ULL,
		0x9D1619E605498200ULL,
		0x2167E58A62949313ULL,
		0x4279BFBD69841F3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30BDB31352CE9F9CULL,
		0xC98B867C5AFCA95DULL,
		0x8F912B93585B5788ULL,
		0x11EF157324386A32ULL,
		0x36C9D02745E69F01ULL,
		0x3DFFAE8F82640CC1ULL,
		0xE8E25F7336058F16ULL,
		0x03DA686A7EFEAB14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51A4E134D4B0187ULL,
		0x36170B05E4B0B7A7ULL,
		0x6F64D3EA811A02C6ULL,
		0x18FBC278C31579BBULL,
		0xAC8761CEA02FEB5EULL,
		0x7DB94E8A59A59E6BULL,
		0x2A73C204D722AED7ULL,
		0xE6EBB16F0ABF1483ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x017FC6289EA2433BULL,
		0x1DE6BC3A82905268ULL,
		0x6497B60AECEE9E13ULL,
		0x44627C4DA2934A19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF25A6D0E6A59961ULL,
		0x836CA23DD892BA7DULL,
		0x7EDE1F7CEBCC606FULL,
		0xFBFC2991C078A4F2ULL,
		0x0D138F680A3AFADAULL,
		0x7317AB7DE6F10B73ULL,
		0xF06A87E363BE76DBULL,
		0xDFB1E9A6AAAAF51AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB771BFBCE584DF5ULL,
		0xA78FA6730E1C63AAULL,
		0x24868C5DB2EFFDF2ULL,
		0x1BF76D6D81176D39ULL,
		0x793F55B479ED5425ULL,
		0xF883694B6EAA0232ULL,
		0xE520D013FB886EB0ULL,
		0x51356B65DC1DD14EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x052F1B7C83D40D8EULL,
		0x0DDECF48A501B669ULL,
		0x0748DBE8B0E198CBULL,
		0x067F79C2E8548803ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AAA9D04484FAFE3ULL,
		0x277A4E913268D213ULL,
		0x3985C440D0B71211ULL,
		0x7E2BC54F856AE694ULL,
		0xC8B5CF00CEA3B8E2ULL,
		0xF7716AA5CD46379AULL,
		0xF5F9943473CF8984ULL,
		0x91FDDAF811F65E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x693084E603182738ULL,
		0xC49EBDA3C0F997EAULL,
		0x11FC688D5A22016FULL,
		0x3E5B02D313B044B4ULL,
		0x24AB86128966C0DAULL,
		0xBFB73B142C897E25ULL,
		0xB6C5B32822E2A1D1ULL,
		0x138906188BA9B401ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B00EB7C8C445CADULL,
		0xA87EA08B4D72C19FULL,
		0x893CC38779BF753BULL,
		0x05285BAA611BF077ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA8301C0CCC24F12ULL,
		0xC5DB14E4D5D469A7ULL,
		0x1F54F95F00A15631ULL,
		0xA5BDB791A99AD687ULL,
		0xF5AD2508E1DA9180ULL,
		0x1A9DD9D2A7B05A49ULL,
		0x17926386F8135FBFULL,
		0xE8DB6FE25F8BAB4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EC841DA54562B9BULL,
		0x9A9D746092ACBF08ULL,
		0x280D3D5A4508AE1EULL,
		0x98D63B7D5575B40AULL,
		0x06A7957D7545ECE9ULL,
		0x64DE9178A1D7F3F2ULL,
		0xF308DDED90197E32ULL,
		0x8B7303E2BB5ED3C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x268E0E98967C93E2ULL,
		0x25A25DE12146DBADULL,
		0x63B190CA2AB022F6ULL,
		0x6A678406B2CD2066ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD8D7E73EBB2B2B8ULL,
		0x27A27A25656E0206ULL,
		0x082C4AC6F79CBC05ULL,
		0x122C0B97A5468F7BULL,
		0xAD956CE936AEF585ULL,
		0x742DA7E3CF5BFBF0ULL,
		0x085F90528B07BD10ULL,
		0xED6CE476B5A74216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73AD43C2B869092EULL,
		0x0FF8EE6040094776ULL,
		0x85D422F665197DDAULL,
		0xCF44CA752BB9A813ULL,
		0xF0F4958996B0DA5DULL,
		0x1DAE48498A9FC386ULL,
		0x335998E4AEFC235BULL,
		0x8B70F2EB34E2F72DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89C032E2F301B37BULL,
		0xEE91BCAB59551A42ULL,
		0x213AE21F3C3C0F15ULL,
		0x4E4D1BD796B005F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6348550E383AAF6ULL,
		0x3743E08E1700A891ULL,
		0xB9F96A0F9813B939ULL,
		0x5CD63CBBE914FF51ULL,
		0x345CEC04D56032B5ULL,
		0xDF7F69948DC89D1BULL,
		0xA614034808E20082ULL,
		0x252A5AEA19AAAB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99325B2FCE79B892ULL,
		0x8449967F448EFE06ULL,
		0x6F05A639CAB1C0EEULL,
		0x363A4A375AC84B96ULL,
		0x0AC8B95DAEDC23A5ULL,
		0xC30690198F58B3E9ULL,
		0x68D27970D78E3C3EULL,
		0x599E044BF25C7D28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7901AEF0CCA42D94ULL,
		0xECEA9250970E47FDULL,
		0x62AE39C71FD11A66ULL,
		0x5D70CDFE63E78E4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74CBABDF503CB346ULL,
		0xC166C016DDD541CBULL,
		0x0184451D86E46AD0ULL,
		0x71345F5E3824EFB5ULL,
		0x9D227134D07EC50FULL,
		0xFA87AFBBEFE57182ULL,
		0x76B7CB6C031B7BF9ULL,
		0x4747F12E7B36E13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4B9E22AD05AFE0ULL,
		0xCB2E20F3015B1EF4ULL,
		0x3E2B4992966323BBULL,
		0xF725619CA1F15718ULL,
		0x62185FA473C608CDULL,
		0x361E6C77B8C4E9BBULL,
		0x853D282D1C12DD3AULL,
		0x0DA2E0291717E1CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AFEA92A66A2F662ULL,
		0x1DD89B440B4E4A69ULL,
		0x9B8D36E13BC8D78CULL,
		0x088F848E72CD83ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77D7BB79B0FC1AB7ULL,
		0x059E0E13EA9FF3DCULL,
		0x0C40E9DBC1F83487ULL,
		0x2C8F200F0039DC3DULL,
		0x3DC9072DC88ABFFFULL,
		0x2EAE9D053B256439ULL,
		0x247F1CC9874DFFA8ULL,
		0x970C345E1B659DFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCA29E9B295A5320ULL,
		0x73E93625FC2A7E3DULL,
		0x3EE333C9917D59B5ULL,
		0x24C69238628B856BULL,
		0x44CFF4DBA3962CB4ULL,
		0x095045ABD255D35CULL,
		0x7D5BE95F09A558BAULL,
		0xF05B96513DD55B78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x702DD51003EFA2B8ULL,
		0x1DB5CF337D44F66BULL,
		0x9C9757E0D783A22BULL,
		0x460003BF81183682ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5362FE11697DE2CDULL,
		0x06EFE840D9DCCAE5ULL,
		0x9D66AE76D59DA962ULL,
		0x16931564782B59F7ULL,
		0xA1A71929F9C952D7ULL,
		0xBAA228639BE109B1ULL,
		0xE948C0CE9E1EA7CFULL,
		0x68D763225D766875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6392D6F1A4DE71EULL,
		0xD03F170FC0EE1ED1ULL,
		0x3C33CE59C66B0CCFULL,
		0xB073F8E40E14E96EULL,
		0x9C4507518B966726ULL,
		0x570F6F4FF5F93138ULL,
		0x009FCADF136520F4ULL,
		0x5216BB5A7A287F53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49B876C2AABEF854ULL,
		0xFE784A1BB958CE0AULL,
		0xEA4761ABA6BCA122ULL,
		0x46B8042C27A70BB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x703380747A98D9C4ULL,
		0xD11BDD312B3ECC9AULL,
		0xAEF7BD439335944EULL,
		0xF26E4D1790A5B7A1ULL,
		0x949A9BCEF39FC785ULL,
		0xA10F9F5525BD2813ULL,
		0x5A784A74CC8F6E70ULL,
		0x5803BE63509DA477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5E9F355A534B9AULL,
		0x3078EBDFD71C0145ULL,
		0xA378377182C893FDULL,
		0x6ADF8396AF24C042ULL,
		0xB2426DEAB189E3EBULL,
		0x543BE32CB1D71B35ULL,
		0x5FA9A1266CFC663AULL,
		0x4182C822E17CE269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CEBB120EF85578BULL,
		0x0810DF528848B444ULL,
		0x462CA77440403861ULL,
		0x5EB35711605DC572ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x968E8CEC9F1E61C0ULL,
		0xC76B674D641DDDC8ULL,
		0x4F47EA6F0F489DD0ULL,
		0x8E20467429836DEEULL,
		0x9B530FD2A6437B94ULL,
		0xDD5754AA25FDB702ULL,
		0xD831D2C46C7B6E68ULL,
		0x1EB6AF7F52184C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF33E2B6BE6E69BAULL,
		0xE350084D539ED4B4ULL,
		0x96E0F8BBF43462A1ULL,
		0xFCA58FDAB55BD7D6ULL,
		0x0F0828F9FAB85CE3ULL,
		0x168391C6196CD15EULL,
		0xEB1406E564A2A88CULL,
		0x2EE8705BDAE15F7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A78EE5F575685DAULL,
		0x678A4CD9EE011F80ULL,
		0xEAD334CE454199F4ULL,
		0x2A1815DD264EC732ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EE52B301E52B66BULL,
		0xC3D56462F0A5E689ULL,
		0x5FF5ACF02450CC36ULL,
		0xBAF7FCAF46DA67A6ULL,
		0x00379E4EE2F9A97FULL,
		0x4066B889844371B9ULL,
		0x9B2B33A2D64FA1B9ULL,
		0x8D787E35EE1958AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E069D4C677CD11ULL,
		0x5E412E4700E5B5DEULL,
		0x0E47082026F2FA7BULL,
		0x53DB4FB065A18AABULL,
		0x55E06AD875A85A6BULL,
		0xA6D730D7647174CBULL,
		0xED8781C500CC6A25ULL,
		0x6C9F9C56A9531452ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEF664EF91ECA710ULL,
		0x30E25A8CA8EBBBF1ULL,
		0x17FB0BBDAED811A4ULL,
		0x474E342316A70297ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F7B47A9E30F7BE3ULL,
		0xD2C246B84ED66BA2ULL,
		0xF26CA8EEF0C7CD95ULL,
		0xD0535CDCB0C61690ULL,
		0x9B598EEED3D8349EULL,
		0x5E3EB7BBA9D56C74ULL,
		0x14CBCF48304A9957ULL,
		0x0873B87B67A63F3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC08BF0CCBBDACD80ULL,
		0x4B57BE98BBAED7D1ULL,
		0x989B960EED149474ULL,
		0x119CBC532BA8C6A0ULL,
		0xAD0969F2052DFCBEULL,
		0xD6D3F5D2DB627D02ULL,
		0x360B85B7DFE844FDULL,
		0x15419C766A4715DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEED4D463D478F96AULL,
		0xA14350AE38371EB9ULL,
		0x6A5BFE4BF24BBE6BULL,
		0x5826C947213D73B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BB2C6C20263ED98ULL,
		0x3B1F63D57F001BCBULL,
		0x0298BE7C0B26BB40ULL,
		0xB7BB34A5BBB88C1AULL,
		0xF83799C4A5087042ULL,
		0x54A384B560782883ULL,
		0x3479E81F64F66F8BULL,
		0x2E0F65E63F35A639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B56661FFA534CEULL,
		0x310DEBE7941424D0ULL,
		0x9E41D889A7FC8142ULL,
		0x1C1E2F4B033EADA7ULL,
		0x52044C9EA59A9C53ULL,
		0x1D1B7CD388C5E530ULL,
		0x78E8BC5B47830405ULL,
		0xFD823259F6B3E725ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x549AD403ED0C29BDULL,
		0x4842A373EF61F565ULL,
		0x3BE3650EC24C2FEAULL,
		0x5092AC2D7BBC3B60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A90600186542225ULL,
		0x8C853C65BCE7E9DEULL,
		0xC3EDBD3F81A8660FULL,
		0x1530FF8FBD8B56B9ULL,
		0x1E19A5855C46BDCBULL,
		0xCCE9CB161BB9242BULL,
		0x6CF9BC43310AF1A9ULL,
		0xB3AACD7742ECBF9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C85F8CE2075F61ULL,
		0xD5BDF83FB12F49D0ULL,
		0x2A8FEE594CEC3C64ULL,
		0xBF3649D808DED7E3ULL,
		0x36D7814B86442AC0ULL,
		0xD429D647FE34EB82ULL,
		0xDEC9F0EBC3551399ULL,
		0x2A296B9FC770CB3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A99610A68AE994BULL,
		0xA3459ABE6D590920ULL,
		0xB475FDE07DBB2009ULL,
		0x3F2F3BB40912C4B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B8EB24C1911C3E5ULL,
		0x72746D94A98788AEULL,
		0x5836B6D92C7CD78FULL,
		0x52511A00F6A21D6AULL,
		0x2AA91A777B82B73EULL,
		0x1490F283DE9C332EULL,
		0x11D745598CFA526CULL,
		0xDCF619CDB3F8A6E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAE3078FB3BDEBBULL,
		0xC2B7E7F4424FB36BULL,
		0xF78179F193067F85ULL,
		0xC37609FA4F4F5473ULL,
		0x9910F82143608AA8ULL,
		0x580D515647E41E31ULL,
		0xC13F72E1D41D2C4EULL,
		0x8B88F00DBD18A257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59759A9F72E88523ULL,
		0xAB467264C68AF2C0ULL,
		0x573E7AAD0A4A0073ULL,
		0x250F42854C93763CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCA8F2AE274602D8ULL,
		0xBCE4F0B41A72ABB8ULL,
		0x478F0DFA83B895CDULL,
		0xBFE154D35FF033CEULL,
		0x23A7296BE4DE5007ULL,
		0x81E3A7F1933272ADULL,
		0x69E69564BFCDB530ULL,
		0x7002DB9B6FCD0D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20F2E361CE3B846FULL,
		0xC78ED6BFEE1C355EULL,
		0x148116E333404554ULL,
		0x5A8546AE93AA18F8ULL,
		0xFAAFA0B35643A5E4ULL,
		0x3476473A624A2323ULL,
		0x7AB4D1F3F0BB7051ULL,
		0x7C3650172C92DF8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0745AB183FFBF62ULL,
		0x739275256ED244B6ULL,
		0xB470F9D60D2E899EULL,
		0x15B8C3C6C6E8E5EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADDC5472F722B11CULL,
		0x125C6B62F40F2AFEULL,
		0x7C87CC5AA255635AULL,
		0x06A5E46D669D58A3ULL,
		0x80D3DF4A3AC94425ULL,
		0x84EEC3F6C0FBDA3DULL,
		0xEE351A74CD9B4783ULL,
		0x2864DA9B70C999D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D50FD3301A3E8EULL,
		0xE5F27CF976DD8AEFULL,
		0x9DB2414E24C6CED3ULL,
		0x235E4F405721C966ULL,
		0x7A8F1CB43A91A60FULL,
		0xCF03D531A2276D2EULL,
		0x5790BDA43A59C267ULL,
		0xF3CAADAFCC9C4BE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x393C26E3CF49E54BULL,
		0x2D495FAC10B9D04AULL,
		0x3B3B5202594856A3ULL,
		0x322A40276E3520CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x691CF5EA88DF6FFDULL,
		0xC3F592511220E6EDULL,
		0x273D2952284290A7ULL,
		0xE54A88E01A37BE61ULL,
		0x457BE44CDCFE5A7CULL,
		0x0433DFB1012C4A13ULL,
		0x240E546F8F3130CEULL,
		0xEEA2B7D7B376452AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE91ABEB1C20D4B5ULL,
		0x7DE4D88B06020221ULL,
		0x974C1E5987DB0563ULL,
		0x8E1B3BFFC00D13AAULL,
		0x7177BCBEBF8A093AULL,
		0xC45CBAABE9E22C3CULL,
		0x43AB70E4DAB0F356ULL,
		0xCC212E2D3D5DAF37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33292917CC02ABD2ULL,
		0xC0003887811F52AFULL,
		0xDE9ED18F6B70AAF7ULL,
		0x7669BC2DE1D0ECC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A265F941E5DB546ULL,
		0x3A818D883F75119CULL,
		0x7D128B13123DF1CEULL,
		0x05AD97E960435F4EULL,
		0x6E775F2E1EFF413AULL,
		0xE78599F2BBE0FEADULL,
		0xB9ABC4983AC24966ULL,
		0x564179CB7D8F6979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD215E06FDF2DBA66ULL,
		0xA6120FBDA75B4C3EULL,
		0x16AF800FCE1C4A92ULL,
		0x9241D09D49BFA3EFULL,
		0x3D9CC10134E0169AULL,
		0x0D6A3A24A8FF3EF3ULL,
		0x904AE814FCB83FFBULL,
		0x0D7F393BF1063820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD883F9CEFFD0501CULL,
		0xF47FB661659C3B00ULL,
		0x8AC3C67E799F0D3DULL,
		0x40415C9AF2E10E9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C28133A29C3131ULL,
		0x22C901BB2565E676ULL,
		0x99420E2D32F94900ULL,
		0xDC03CF2A070C4A3BULL,
		0x6D97A859E5BFEE4BULL,
		0x6E6E6AD49DD93A86ULL,
		0x23A6BA620517B389ULL,
		0x792B5DD1AE516B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC2CCE88940BCD4ULL,
		0x27F3DFDC22E81E2CULL,
		0xFF314D6F1DA59049ULL,
		0xCFC9272C4C2573D3ULL,
		0x8DB8D3E8A0FCCD79ULL,
		0x744D4775259E43BEULL,
		0x7816DADCCAB76B0EULL,
		0x9972E101D22E65F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50133D1B4E5252CBULL,
		0x1BC0620ADB3E69F5ULL,
		0x116BEE84BF9E7AF8ULL,
		0x419D2ED868199BA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5323025EE2059CBAULL,
		0xB783B6B45ED3B945ULL,
		0xBB64C6C9F07E4104ULL,
		0x7409EBC8414F0B96ULL,
		0xBC603E0FEE139A34ULL,
		0xFBD6A886EE2EC774ULL,
		0x1D0033A81EE7A5D7ULL,
		0xCB2CB891A7FEF30EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BCAC2D7F177B777ULL,
		0x02D9F948CFDE800DULL,
		0x485B65EA49289064ULL,
		0xFDC8504199A4C252ULL,
		0x980A343A77F66ED1ULL,
		0xC2568CBFAF829A09ULL,
		0xCA9A3E217A491649ULL,
		0xCB33AAB6C48C2CEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC1DB53678E255CFULL,
		0x3DADDCFEDC83F71FULL,
		0xAE2BD2DC16DEFFBDULL,
		0x7539AA046AB3B210ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87117DCE3A0BAE0EULL,
		0x48E185AA9EFD21E8ULL,
		0x7B4B88313B8965FDULL,
		0x0B887ABAA85D79B5ULL,
		0x22302644D65ACB97ULL,
		0xA6D679D6932EBC63ULL,
		0xC000E73C30CDD7E2ULL,
		0xE3497F1138BF913CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFE37A41501E949BULL,
		0xD4F88F4E96E7FD00ULL,
		0xAB873A60B4D98069ULL,
		0x3EABA8DCCD3E16E9ULL,
		0x34A63A1B870DD123ULL,
		0xD29552C83617A658ULL,
		0x8C752E0B4401E4D4ULL,
		0x8F52D11396C5BD0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9A711AEAF5A4873ULL,
		0xF594C27DD9826A86ULL,
		0x7681CB13ACF5F9A0ULL,
		0x437AA583E634E1A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB893736D7DDCB3A4ULL,
		0xDD72E3B2CFB759A1ULL,
		0xC7BD39A0F02DDB2AULL,
		0xC716103ACF05B2E8ULL,
		0x79C09641E7D60FCFULL,
		0xC7522DB768EAC1BFULL,
		0x9AA4BF49DDD5DAE9ULL,
		0xBB2C306BC700BE1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC728C19223C631AULL,
		0xB6327755C06A9F27ULL,
		0x58C8963755481E60ULL,
		0x497BFB04910854D9ULL,
		0x31F4DDFC98F52271ULL,
		0x51D9EAE37381A99BULL,
		0x8D56D29BE3395EB4ULL,
		0x6C155CA9DB74AF65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x845E419E11038E46ULL,
		0x971A57D37CE64FDCULL,
		0x6885C53CCE202CB9ULL,
		0x3AFD83FF34C78DADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30832E3330680490ULL,
		0x761CD354791A975AULL,
		0xF2D6E77630C1E77DULL,
		0x348CB01DF36A93B4ULL,
		0xE4E535A416753A75ULL,
		0x9B1B846A82377F11ULL,
		0x29BA6D6E338CE04DULL,
		0x78B7A643C73396DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7FB017B2B79333ULL,
		0xDEACA7FD153276E1ULL,
		0x3162BC8AF02DB515ULL,
		0x9BC86EEF5CF5F3B6ULL,
		0x3D6061CBAEF059D7ULL,
		0xFF1CBAB17BB413D6ULL,
		0xBE8AA4538231F3F4ULL,
		0x2B4E42A4C5A14300ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1BAF03ADB69CA73ULL,
		0xBF421CCE5B6A0B53ULL,
		0xAA8C04E19413478EULL,
		0x16690AC8D22D1244ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1270628A6ACBF483ULL,
		0x7BF7BA96C2DF031CULL,
		0x9C5FA2E06D885633ULL,
		0xAB62B0E63B54C3E5ULL,
		0x0CE6DE0A401A34ACULL,
		0xF401D4A468C21AA7ULL,
		0xB4E8DF34AB146A3CULL,
		0xFF88DA4D2E7DD534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F9CED6637D52CCULL,
		0x4EC748B188F0E7A4ULL,
		0x4C82D8169246DB60ULL,
		0xFACFF3E7CCA564DBULL,
		0x80264F1402400D24ULL,
		0x02C8F635D7B4A199ULL,
		0x32B71990C1BC6BACULL,
		0x1F3A082489BD9125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F0BCC4135B084BAULL,
		0xFBA1764EC1EE137AULL,
		0xA340211E7E514456ULL,
		0x7C45EF06E3397957ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8495F3DD56A8FF1CULL,
		0xC3BC29EFED322375ULL,
		0x0A96FA56A0AFCA3AULL,
		0xC7C416E79D1C3F05ULL,
		0x88696601384EF155ULL,
		0xB896DD76C3913FD7ULL,
		0xD654E2CDBE3C6244ULL,
		0xEE8C4731EF6B4F60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7726F3AECED12B00ULL,
		0x8E6265404096F38DULL,
		0x3221ABB9C0678156ULL,
		0xA84195E267413636ULL,
		0xD0030CF86E8BFAA0ULL,
		0xC0BF2D392D5048C7ULL,
		0x9566B507C05E011AULL,
		0x85C2509E30C178C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CA0377C7AC87547ULL,
		0xFF5DEDD3FA3FDC3DULL,
		0x7BD01A008F4AB51EULL,
		0x2D7D1AF38310E498ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03499CA156DFC5A8ULL,
		0xA7D7235F30ECB6F0ULL,
		0x1235A04F00B2EA9EULL,
		0x5239B2117D8FEEE7ULL,
		0xA4A1143D8BA58060ULL,
		0x178CBE275B49458EULL,
		0xC53AA7F85E9A7FDEULL,
		0xD1788B12BB2F6E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26EE7AC1E85D00EULL,
		0xE3BD49290D82E8C6ULL,
		0xF148D47A9A150503ULL,
		0x7C7A372C889D992EULL,
		0xCF5861A10C6AB919ULL,
		0xE15B8D344F7014A7ULL,
		0x22B735E0DD844AE0ULL,
		0x07173CA9967E73FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09A538301B138E85ULL,
		0xCF671E49E5A7106DULL,
		0x406FBB518FE9C330ULL,
		0x60311E8067377962ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D3CA88A72BF990FULL,
		0x4C3889961EED1166ULL,
		0x60140E08CD006575ULL,
		0x1C45082BB03E6127ULL,
		0x20F0845A5ED1AACDULL,
		0x79B80488922D4E07ULL,
		0x360E95D033A9C481ULL,
		0x5FDB8EA91B8D47F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55534C86D12007D5ULL,
		0x63A54B4290462730ULL,
		0x0B0BCDB512643243ULL,
		0xB88ADC74C34790E9ULL,
		0x2D7722D8148C15ABULL,
		0x2F7FA29A42AAE192ULL,
		0xC0E84DFB11CBD5F6ULL,
		0x31BBEBB26DA54BB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBEDD55AA7F3B52AULL,
		0xECF1C7B35C030391ULL,
		0xB8B6E9F6C18D9BDEULL,
		0x3C6C5C54BD664241ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08EDF07DF1C2B52FULL,
		0x4A169A6E9B884871ULL,
		0xDAAAD0B174C6072CULL,
		0x3FC81620B1A3CA63ULL,
		0x39A14323B12913DDULL,
		0x76B869243F6D8412ULL,
		0x27E7F1CA6662087FULL,
		0xD61C39DCE372C157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E86D8E28BCF874ULL,
		0x46D8DEAB6C9E2726ULL,
		0x9150FBE3D91837E9ULL,
		0x9FF6F7E9CC5A13D1ULL,
		0x30601E891FE5C27BULL,
		0xAF72E94E9A6AB89AULL,
		0x8F19845F632938D5ULL,
		0x9EB6D929CB183442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63B0F1E15903D264ULL,
		0x978EB579AD54551CULL,
		0xF7FE12B0161CA276ULL,
		0x58DD78CC82BAA7A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58790F01F7855783ULL,
		0x66EDF3BEC94109D2ULL,
		0xB2074EC42E168DC4ULL,
		0x24E73B37F0642C4EULL,
		0xE69AB24D2A6F7B89ULL,
		0x5381C641C0B6C261ULL,
		0x4A67D834BED764DDULL,
		0xCFAE0E0163146116ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB50745BFAF43959ULL,
		0x68F38EF1F12C5829ULL,
		0x970C60BF7624CF03ULL,
		0x72A35A73142A6713ULL,
		0xF80E3BC516297A6EULL,
		0xDBA525795D415B0BULL,
		0xBD9D638897E926CFULL,
		0x651E753243B86D47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC60232D8FEF54A79ULL,
		0xC8BA428B9B820869ULL,
		0x01083F927F4EF4C0ULL,
		0x03948F8383DFF5E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04D0CEF6AA0F81BBULL,
		0x6B57EF35225A8611ULL,
		0x718A0C5F1306EF4AULL,
		0x028A7D66F6220F78ULL,
		0xB22D60CE9B9B7FBCULL,
		0xDA4439F25F2D7EC4ULL,
		0x4D55D24A8EBDDB60ULL,
		0x379B08D8387FC602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96004E1406CAF149ULL,
		0xB3550299A0D17C17ULL,
		0x85F347C1F87CEE6DULL,
		0xFE5E7BF498B8E755ULL,
		0xCD17548EE6E85174ULL,
		0x0E644A103B7A1BD9ULL,
		0x650CE6D8FDFBA850ULL,
		0xC3BE1AE51441B1DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7016525775DD6BDEULL,
		0xFB40882CCE29B8D7ULL,
		0x6669B778975D955AULL,
		0x36F75389BEA025C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F1790F969919D2BULL,
		0xF477E8F4E5C14328ULL,
		0x73EE8CBC91959267ULL,
		0xF19E07C54589315AULL,
		0xD2947DB17660C07EULL,
		0x47A76D00B06D9ADFULL,
		0x9EAD0412D45C017EULL,
		0x0797F79C0FCA6F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE3A02A9E75D7B07ULL,
		0xE7FBBA20A44EEBFCULL,
		0x39AE72C0D0E3A0FDULL,
		0x4F4755E93DC8A817ULL,
		0x8D2BBCFF00114896ULL,
		0xEFD6209AE11B789CULL,
		0xFC3102823032F1D1ULL,
		0x9C35909D054C79A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE6A28CD11FFEB63ULL,
		0x158D85F107A36D27ULL,
		0x58A855741ECA44FFULL,
		0x12F1FBB79672FECFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3892E8C4EB5362C6ULL,
		0x4E51A03C94226579ULL,
		0xF398FF225D0C8B3EULL,
		0xE048389030AFC544ULL,
		0x385E959536DBFC8AULL,
		0x2326243D1C610DCDULL,
		0x00C5374FA42D0460ULL,
		0x5C2A3719A6C9B03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4566E55DD25D803ULL,
		0x2C93DCAB3852796DULL,
		0x423ACE4242549C59ULL,
		0x930D21287937E07DULL,
		0x38B4A1E909C281C9ULL,
		0xEA4B28EC44065BE5ULL,
		0x8E8B8AA8954AB354ULL,
		0xE86215AC34FF25A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5776A5FDBFF5C04BULL,
		0x923F11917946547BULL,
		0xA5EDD1AC504FF68FULL,
		0x7CF00DA69B8876F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A283D51EDDEDD6ULL,
		0xFB6959E3ADB53D62ULL,
		0x8F0686E02E558C52ULL,
		0x03194ED5595EDFFEULL,
		0x6A6B7590BE16A5F1ULL,
		0x2099BF407593EE54ULL,
		0x536CD7BEA2E18241ULL,
		0xB402EFE8C00A8B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2DAE89D23CF1AEULL,
		0x642A51A4424AF71AULL,
		0xD8BC2821637F67CBULL,
		0x550B17ABF33D3A0AULL,
		0xB1FB9573FB314BCAULL,
		0x565C16F41E631DB9ULL,
		0x3C25BC775FB57945ULL,
		0x882347BA75095611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA1019903AAC5ED6ULL,
		0x9C6603945CA93D3EULL,
		0x2AD86B52C35F79E7ULL,
		0x31412E08884F8BAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5CDCEEBF8044465ULL,
		0x3B30228764776ED4ULL,
		0x88E2FF35DA6FCE5FULL,
		0x73961BE82FCF3171ULL,
		0x4469FE9F71BF5C10ULL,
		0x59C557ECB3D9206FULL,
		0x2D974321BA19FF7EULL,
		0xEB074227732D769AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291F54C04D5184C5ULL,
		0x441BC58376B2AA75ULL,
		0x1D65CFA8B10ADFDCULL,
		0x8E956DE72A805917ULL,
		0xECC15D3199BFCC10ULL,
		0x8720ECE12364AC42ULL,
		0x36345F6454A4CB2BULL,
		0xC05E622370A29260ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFB67079BAA22084ULL,
		0x3B7C40BB5F0E02F4ULL,
		0x242AFDAA38CAB2CEULL,
		0x3A11EE9965ECB8F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF912A8FA08A1AA4EULL,
		0x63DE012326C9C8C0ULL,
		0xE30C999078CD3554ULL,
		0x73D5169B8F8AF787ULL,
		0xAD289CD99EC4DFEFULL,
		0x13BBA086D9AFF623ULL,
		0x28BCE3F2411BBA6BULL,
		0x46647314C1EAF2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D82743E7954A5DULL,
		0x40E516452D056DA0ULL,
		0x68C9C7B13ED02334ULL,
		0x910385645A148F33ULL,
		0x9D52071B37C67079ULL,
		0xFB995856718F7918ULL,
		0x4A163675B75EF3FAULL,
		0x1C0BCB10EC08B151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3114BBF96AD0EC59ULL,
		0xB80FA20D6E96EAC5ULL,
		0x8700925BAC0286C3ULL,
		0x2BFA81C8F50C1D01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30CD4052B9AD8E88ULL,
		0xDA26479AE26970D5ULL,
		0x229AF4F348783090ULL,
		0x178B8A7FFC28664DULL,
		0x8686DAE5F40A2EC5ULL,
		0x2855813FC3F2EDCAULL,
		0x22DBF798F2EF2639ULL,
		0x3BC546B5D1D1DB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B2D544ED651A2BULL,
		0xA9126D3BA445ECADULL,
		0x69AC9B7FF0E3E3B9ULL,
		0xC00E71A1B68A8D36ULL,
		0xB735ABB125D22748ULL,
		0xF3F18A1948BA63A2ULL,
		0xF0051961AB0D8DFAULL,
		0x7AE43912E40B516DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30276CE468998F5CULL,
		0xF7EA8A1588880610ULL,
		0x44D355A80310E612ULL,
		0x78E51F0D91164D8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x321138BD193B6E0FULL,
		0x1BD0EF8FE6A84AA6ULL,
		0x3E74588E189B61E8ULL,
		0x27E0105660CC5DAFULL,
		0xE6C5C42A746610DCULL,
		0x25109B2A39248E1AULL,
		0xEA3C4EF90C29FEC8ULL,
		0xF800DEAE9D4FCFE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x874883E6B4547E8DULL,
		0x84638E4A89F3AED6ULL,
		0xC1BA472B9EEBE68CULL,
		0x1E2DA0B29A4C3657ULL,
		0x8965BE4899AB3B07ULL,
		0x816C1EFEB8774BFEULL,
		0x1B69AC50560CBBB1ULL,
		0x9DF1EA8D9D953948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8709945CDCA2AF0EULL,
		0xE1D7CFBA766C6C05ULL,
		0x2FFE366D820770B7ULL,
		0x67EAAC89BC328252ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF24442A9FED1C793ULL,
		0x3098D2A3A7B4E9F2ULL,
		0x861136559B4ECF74ULL,
		0x1000021A767E1330ULL,
		0xDD4FAC0DCFC4084CULL,
		0x9411EDC8C7EC4B66ULL,
		0x39E957875D4A39C5ULL,
		0xB36D71F95793ED3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC88C158A00062DB9ULL,
		0x4D4C9EDC1E7EC06BULL,
		0x08EE99284893C734ULL,
		0x51852236EF9F99E5ULL,
		0x608598F565C0F145ULL,
		0xAA9C5F1A9CB12873ULL,
		0x1CD13F3CC630F7BCULL,
		0xC916749376BFE3CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFB702BFBB41045FULL,
		0x8ABF61A1F3FD59ABULL,
		0xCEB6383FC07AD592ULL,
		0x07647D02E657E03BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD24562AF98C9C739ULL,
		0x04A9DAA8B5EBACB3ULL,
		0x0AC313658F7A74AFULL,
		0x909C4E30E6C835F5ULL,
		0x1541285A87926EAAULL,
		0xC9E5F21D543DA13EULL,
		0xB36DA7BB4EC1FE1EULL,
		0x63CC1E0C80321A16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2E51BC833E6C33ULL,
		0x30436C5E14D368C4ULL,
		0x745EB6CC43DA3BBEULL,
		0xF35ED98A6D40D273ULL,
		0xB160649EA8579992ULL,
		0x2ECF95F4751A6F54ULL,
		0x0F67380559934E9DULL,
		0x1A131D97BC24B993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99741ED63846FE25ULL,
		0xD9B81C5BC051AC94ULL,
		0xEF58F19BB08E462DULL,
		0x0EB385FB9383B70BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73C411144FCFF3ABULL,
		0xBB208C3E63D66377ULL,
		0xC39CAD7C912A6049ULL,
		0x03A822F2905CCD3EULL,
		0x3B17C7D8028FA09EULL,
		0x4F5C090EFBD02672ULL,
		0x2AAE86FCE2528554ULL,
		0x9EE2A94EB5719FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52291926BC2197A1ULL,
		0xB7B73883702671A8ULL,
		0x250C2F9AB6DFAB0DULL,
		0x7F6FEAC64D67A692ULL,
		0xAD3849DF999E1F0DULL,
		0x9941EAFE0FA811F2ULL,
		0x20CAB95AA2C6B722ULL,
		0x99B8F8C1A7170CCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30C7AACD27879790ULL,
		0x0B49CA3E01A2FCBEULL,
		0x166103F7490B509DULL,
		0x48686D1C6466F8AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DE4A03608F78A96ULL,
		0x68881660F3791854ULL,
		0x0186D9B2D7A64671ULL,
		0xE47ED4E24288B2D2ULL,
		0x39DC6112F975B449ULL,
		0xCD252995724244A2ULL,
		0xBFFCE2F9341C2189ULL,
		0x44B9827F7222E0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF214C20B5C9477ULL,
		0x72F0C5B4587F3D0EULL,
		0x4D9FD923059AEA06ULL,
		0xE2BA09E49775BC67ULL,
		0x6F6664ECCE2C466BULL,
		0x76C5B1498E798E64ULL,
		0x003C63F259894493ULL,
		0xD71A4E07888CC85AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB75F91E6A8141CFULL,
		0xC7C32BF06AC4E871ULL,
		0x2A79DB9443D828FBULL,
		0x476694CA575A9F05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10BF65F0DD218C2AULL,
		0x514BF52D296EB40AULL,
		0x6139E5B1434FE72FULL,
		0x92214980A395911CULL,
		0x6BA9BDBB76714106ULL,
		0xF80469E20026F06DULL,
		0xAD941EB8994A98A6ULL,
		0xE1C263D1B90F95B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63570EDC00BE8972ULL,
		0xA1490A45CBABF687ULL,
		0x605B70C062610A8CULL,
		0xEA4F24AEC95BF27CULL,
		0x7AA84DD21D9459E8ULL,
		0xA34B0A8DFB88B2D9ULL,
		0x7CF3EC4CB71F7E08ULL,
		0x97DA419478B66863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x739EF3B80D2D52BBULL,
		0x438711600D3FE178ULL,
		0x38A5F0F47354D023ULL,
		0x204739E9677658ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F20D90DA0164A38ULL,
		0x9A43D23538389FB7ULL,
		0xEED45436ECA81BA2ULL,
		0x9E4004EB6952BF40ULL,
		0xE0AC0B31A754E609ULL,
		0x4A26B4F2C760A17EULL,
		0xF032400E18D23181ULL,
		0xB6B3393F49AA55F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C1F3231B211A24ULL,
		0x22A77B33D4CE9782ULL,
		0x99D1C9509DC789EBULL,
		0x73812CFD6A441D71ULL,
		0x3A917EF2F7AE6BEFULL,
		0xF8642C19110DD833ULL,
		0x4CDE852EDEA71C1BULL,
		0xE462CAA1656494ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD64FB73897AB4EE6ULL,
		0x9A7CA75273B3E96FULL,
		0x93704808F145BEC1ULL,
		0x62AF435DE1695271ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x577F7B7CF9CBAC86ULL,
		0xE68672587F15D5EEULL,
		0x9109557E9F30EEA7ULL,
		0x4613C8D90A085853ULL,
		0xC03B22A8C1E035A5ULL,
		0x865584380442B774ULL,
		0x199A0F10279CC6EBULL,
		0x6C3ABE179277C986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D40D3BD5CED6378ULL,
		0x83387357C34349B7ULL,
		0x35A0482A7E420854ULL,
		0x263FE69AE25B1486ULL,
		0xDED2CC2940C2E1B8ULL,
		0x1350BAD549156D5CULL,
		0x522EE7B530E47ACDULL,
		0x88C4F810B84C0A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FBB7EACC738BD91ULL,
		0x7603E3A8848B8BC2ULL,
		0xF550E4D4C04A32D8ULL,
		0x634F47428A2B9ECEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDC1E9C07219F8FFULL,
		0xE8136B44056CDBC6ULL,
		0x8DF8D85B79FF0AD6ULL,
		0x92FB7D183979A6EBULL,
		0xE83D84E07CA6A884ULL,
		0xD37A76A52C0F135BULL,
		0x0DA8FF8F75860ED9ULL,
		0xB0C8CF6AE711B07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AA7A7D7DFA449A4ULL,
		0xC999460759E333C6ULL,
		0xF3AFB7946A510A95ULL,
		0xD1413044B9157545ULL,
		0x13B18F0977A97D33ULL,
		0xE2842DE16E500121ULL,
		0x0C97B548685A2950ULL,
		0x292B6E6DF603469BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FE0BFD3500A2046ULL,
		0xE308F24AD5E65CBCULL,
		0xC2DA275304321294ULL,
		0x6316B25F4887E97DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FB5F5DC919EC37DULL,
		0x122DC08A67364331ULL,
		0xDC970B28E6DB139CULL,
		0xAA2AD573E55AFA4DULL,
		0xFC244C33212A0D64ULL,
		0xFDFDDBF8284E377CULL,
		0xEA0C69C96389DA0EULL,
		0x7C998D115172C6C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF64F80FD6765D2ULL,
		0x09249DA617C66A42ULL,
		0xC7C9E7DFC0A29D90ULL,
		0xE01364F9CB27999AULL,
		0x6B7547B83B45FAB9ULL,
		0x29E9650854F9C490ULL,
		0xB74E4F42A4991909ULL,
		0xC82E367C414AE233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDBA5099B4122158ULL,
		0x8412CA7DADF8E80BULL,
		0x9D0513497DF51CE9ULL,
		0x12064A9A801F4EB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4397EFAF26B73F51ULL,
		0x0681CE158FB1D9EAULL,
		0xA4465BC649A685F7ULL,
		0x75CBA47CB598E33BULL,
		0x88BDFF9ABD8C677AULL,
		0x7AEB37455C3345BFULL,
		0xC17E9474AE518C29ULL,
		0x5ADB4F504C935A5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5C5785153EB4F2ULL,
		0x29424FFE1ABC01A5ULL,
		0x8F8848CF58079929ULL,
		0x6BB39314BDB29722ULL,
		0xBDDB0F198596D1D9ULL,
		0xF8D98326F7C40760ULL,
		0x44CB3F2F0ABA65AFULL,
		0x1A6301AFFB19C085ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51EB4B585FECC1AEULL,
		0x2BE03A9A5D791A57ULL,
		0x975CBB4D3A0EA2D7ULL,
		0x1BF397340FF321C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9C22D3B83065FBAULL,
		0x9512E4F8A06C2133ULL,
		0x2D22FB2856139CD0ULL,
		0xA914DB9C5C59A317ULL,
		0x9E1FCAF7E30D3951ULL,
		0x7B23F45AA50B8176ULL,
		0x3B68A1E30354F83CULL,
		0x27135DB2C8F576A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36FE4A49F00D6C0ULL,
		0x2F783B57C77BA384ULL,
		0xBD1039BE0DE74D6CULL,
		0x85E6E359C4DDA5F1ULL,
		0xE19FC9FBB88F2C1BULL,
		0xFADDB6E30B62D282ULL,
		0xE51229DE9DC6B452ULL,
		0x8BC20AF3A6E8E337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11526E0532BB7CC4ULL,
		0x7007C961A7FA75DDULL,
		0x40E892115B4A640DULL,
		0x314040A1A559DF14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2542C99869EF5D01ULL,
		0xDAE41157D27D4131ULL,
		0x00687E4EE52C272AULL,
		0xEF700AD2A7E67F2BULL,
		0xFDECC12658584DC3ULL,
		0x0F98B3A6B050799DULL,
		0xF55F6EEE828BED0DULL,
		0x597CE47E1C045B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE1C78CEC21CCFDULL,
		0x9E704E8D61E1C129ULL,
		0x58912278E090DE3AULL,
		0xEBED058BC5AF5C9EULL,
		0xDD86220CA746D665ULL,
		0xA10E4E2043A0A4EDULL,
		0x18879E1DFE67E9AEULL,
		0x5B39F4F59B4BCB92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089C9FDBC66547E5ULL,
		0xA4FED4BE92B5122CULL,
		0x6FE05AC9A1F3C8F4ULL,
		0x41729389FD9C8391ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE896CEBA1CDCA48DULL,
		0x2FCBC83F5B73F498ULL,
		0xF19F64EAEAFBAB2CULL,
		0x3320FCEE6CA4F57DULL,
		0x043ECF58ACAFA78DULL,
		0x90DFBCB56C485CEDULL,
		0x8E59585687E3FCA6ULL,
		0xBBFC7E649EA4411EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F5CF1639D14DDD9ULL,
		0x9C8BE04F0A8771CFULL,
		0xFD0E01EEC4CFA3C3ULL,
		0xE12B54EAA4922FEFULL,
		0x336BE158381355E3ULL,
		0x0B9876966F7758BDULL,
		0x4917F5AE8BEB8F30ULL,
		0x342DB3D1979C25D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68893167CEFBE8C2ULL,
		0x5BD45089D7F321E2ULL,
		0x3C4607EB8D0C4700ULL,
		0x7AA7B9D6D346D2E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD10D144FF210D7CEULL,
		0xE5ACA5F43E4A4844ULL,
		0x51C0F4A9BAC5A3CEULL,
		0xD8567FB7BF2E1E67ULL,
		0x0DF61808D88410CEULL,
		0xC3F9CBC436B475CEULL,
		0xD6D3A2EA8050CDF5ULL,
		0x17EB627F8BCCEDDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA751AB7FDCCA83CULL,
		0x7F5C18EAA60A3D4FULL,
		0xA2FFCCAF801A2D40ULL,
		0x36057A92F16C4F03ULL,
		0x2344B4EB33C2B1BAULL,
		0xF386231C6313DCABULL,
		0x7A32EC925262FC73ULL,
		0x559311FC0B0E5D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACECAFFE68F84B34ULL,
		0x577B95F30216C623ULL,
		0x6E9C39110BF88FD3ULL,
		0x7B6CF8A9EA0B46BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E15268D69FBB39ULL,
		0x20BF4E797D5C6F71ULL,
		0xDDD6CBB9845FADC1ULL,
		0x660DD5FF99FDAD0AULL,
		0x11D1B0B3E5B1E4ABULL,
		0x58753E7AC48C2973ULL,
		0x45516C093B05F162ULL,
		0x40551B94B463C0F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0DF5761674A546ULL,
		0xDB500FF3A678151AULL,
		0x84D6281F5C0B4DE5ULL,
		0x43628DAA9D5BD0FEULL,
		0x3968E0C228487668ULL,
		0xE2D79150A36CAEFCULL,
		0x2BA63C3F572686DEULL,
		0xCAF3DE638D9ABA1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA623AD4DDD170DAULL,
		0xBAD6F2C6C19087FBULL,
		0x2869BB91FB7E2F5EULL,
		0x0F1A5DA0BE78DFAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28A662F69A614054ULL,
		0xCEB62E3D1FDD6E07ULL,
		0xC589F9BCCC3F0AF0ULL,
		0x211AD96FA1007575ULL,
		0x016EB359464E4511ULL,
		0x01DA9A0C7C54999DULL,
		0x2B8CE6E5445BE613ULL,
		0x75072ED62B97E572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6ED6AD017B1F91ULL,
		0xBA446C31215BBC84ULL,
		0xF2443BAAA7BB821CULL,
		0x582FF305EEE913DAULL,
		0xD2ED1DE49AEE4614ULL,
		0x71D2A9A980534C2EULL,
		0xB9697E9CDBBA0BE0ULL,
		0xDCA25DC69881CCA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2473BB9B0925F7F1ULL,
		0x759F70BD66B32FDDULL,
		0xC48738D1AC89EC55ULL,
		0x67E1EEB9875F108BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F97DE28DDA52E32ULL,
		0xAB68D5202EBAE4DBULL,
		0xBC84B13C553B123CULL,
		0x569E4AC6A306859CULL,
		0x10F149A55E26F61EULL,
		0xFF33CD1D0471B6C6ULL,
		0xD65FE5495F97FB64ULL,
		0x93FD9BB8A1C6F0DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1423CB90BD3392ULL,
		0x639490627F14EA80ULL,
		0xFD4FBE622539AC3CULL,
		0x561AF3014FEBCAE3ULL,
		0x0FDD4B9D27587DF2ULL,
		0xA9A02682A3CE6B3FULL,
		0x8CF0494AB60DF90BULL,
		0x29CB6DE6794D460CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA97B6F956F8DD375ULL,
		0xFBBEFFA807E33065ULL,
		0xA5C61AA75A7DBF42ULL,
		0x43F624F7552A15C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AA34FDB91A7A5E7ULL,
		0x2FCB9780D8837A60ULL,
		0xFB3116BF18FCB375ULL,
		0x4CC511E8B33A74E0ULL,
		0xE8CD95063252DD13ULL,
		0x059E93EA606BA3D2ULL,
		0xDE71EE41903F324EULL,
		0x4EC223E8DA47EBC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D150775519BF066ULL,
		0x3045CDD68953FF22ULL,
		0x402CDF32C18DAF76ULL,
		0x4B0B04F4AEA54CE7ULL,
		0xC2D38769F27FD38EULL,
		0x3F9D7557E6AE769EULL,
		0xB97EAD2B9E096009ULL,
		0x60AF9278EF2C06BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AC4D97B95F1ECDULL,
		0x63B05368614430FCULL,
		0x371FE0CE4B6C3A34ULL,
		0x587BA390EAB926E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4C77462FB5CB170ULL,
		0x6604F17B9C198433ULL,
		0xAB3AFF63B0B1E96EULL,
		0x6B4A1EADE59C8391ULL,
		0x108DDE7ED3DF949DULL,
		0x997D171FE81E1C72ULL,
		0xD69EEDD922E63C54ULL,
		0x1D9C4EA8E61D079BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5649318D1DDC37DBULL,
		0xB91ACE9D4E6D3C8EULL,
		0x21A296F7D1978658ULL,
		0x7200AD3C136CDDD4ULL,
		0x28D6C66012AD8AFAULL,
		0x001871D3340462C6ULL,
		0x939968FB39CD3CA5ULL,
		0xD469AEE1ECD0D1C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3ABD7668AEDE3B2ULL,
		0x71DAAC41097DD729ULL,
		0x7C6A215C78D05726ULL,
		0x56CD28FAD37FA2F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27F7DF21FB992F89ULL,
		0x0BCBD91A2AE66BABULL,
		0x1B6CDDFD825D4BA3ULL,
		0x0CB56549B0768545ULL,
		0xB9F0FF509B8C416FULL,
		0x73581EA079B5F859ULL,
		0x6791F84D7D47F18AULL,
		0x4B77CF1923312AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6584EF50FC6D77C7ULL,
		0x2C68CC95183CEDDFULL,
		0x745B60EF00783102ULL,
		0x880AE06C57CFD513ULL,
		0x9C5B19D3A84E8C91ULL,
		0xDB517FB82728B00CULL,
		0xBAF75039D7A029D4ULL,
		0xF656EA83347C9F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26B3005D1A548CDAULL,
		0x705EA30153A2393EULL,
		0x46066FF918CCBF95ULL,
		0x278C731EC77363F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA32E360495719923ULL,
		0xA6ED6C7975C0A4ADULL,
		0x466587CE991BFA4AULL,
		0xFB9D3F8B36ACEA96ULL,
		0xDB21F50B4400D1FAULL,
		0xEFA8721D61252675ULL,
		0x658653FA5D9C9016ULL,
		0xA3545571D2000C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842EABCAC733D544ULL,
		0x56F5D50A74FDF7FBULL,
		0xB4A2DB4FED2E1782ULL,
		0x0597AF4DEB552D23ULL,
		0xECD16B7D141D3712ULL,
		0x147EF24B675942BEULL,
		0x115B0CFDC6D0103EULL,
		0x1852F581F292E8AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EF3F554EA06C580ULL,
		0xD820909A150679D9ULL,
		0x102F35FD0E48DCF8ULL,
		0x1839CDD8758AFF15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE5673A57DD8C9F3ULL,
		0x85F8EA44F6F44DCBULL,
		0x96018CBE180864BFULL,
		0x0122C1D47DB55ED5ULL,
		0x79ACA897E29204C2ULL,
		0xFD5187E69306C317ULL,
		0xF0559EC1494A9B32ULL,
		0xE2C9F67430A2CD06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45FD749F96980749ULL,
		0xF6BE4AFCF3078EF2ULL,
		0x79E3EB61A51A0037ULL,
		0x696E68AB178029CBULL,
		0x595F19752EF28358ULL,
		0x446C96C8ABE2AEA6ULL,
		0xF188478C24C89441ULL,
		0xEBABA8A01EE601EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53DC3E2C90EDF81AULL,
		0x013669B85347C7A4ULL,
		0xEE98933FDE3B6C69ULL,
		0x4633E6A4083B5A99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61AC2ACFF681E4A0ULL,
		0x03D289E5FDE90092ULL,
		0xA1391ED2AA0C4570ULL,
		0x9DA58FEADFA4B5B7ULL,
		0x61D8484F9B29DB1CULL,
		0xF3E36373856EEAECULL,
		0x3D98AEE2183460F2ULL,
		0x87E21A68F5C214D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19535B06769A008EULL,
		0xFC93A86E709EEC58ULL,
		0x823BD964BDEC2E6DULL,
		0x092669B17FE476E7ULL,
		0x901E2CFE7436818DULL,
		0xDB9B618EE78A6482ULL,
		0xEAA515682F600584ULL,
		0xD904681FC72DECB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69F8DDD548072D97ULL,
		0xA1EF2966FD3607EFULL,
		0x6F260D867BA5A959ULL,
		0x09679D1649BE3304ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6BFE3AF105714CCULL,
		0x904DC5B103E04692ULL,
		0x7CC185514D7CCFF9ULL,
		0xAF9ABB2DFFF58822ULL,
		0x3CF3DD551F271E47ULL,
		0x7ED64B1AD27D54CBULL,
		0x1719FB60F2DA1D91ULL,
		0xEAFA86470B9348DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195860DBBAF51B4CULL,
		0xC19FA12498BD1417ULL,
		0x2747A961E5406F28ULL,
		0xB4F8D7C8A801814AULL,
		0x1E49BFB91630F61CULL,
		0x54FDD628C768A46CULL,
		0x71190AF8693A1D8AULL,
		0x9FE5C29F2CF36246ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AA7E7FCA9EBF184ULL,
		0x04CF807A1035609AULL,
		0xF99D8B73D5FC61E1ULL,
		0x1FB6EE5063B0410EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBA668896FCBDAC0ULL,
		0x4E05CB4CA132FB13ULL,
		0x8341514CB5F62CACULL,
		0xAB9264E1B5E4C61CULL,
		0xCC8001D33B715313ULL,
		0xC12C19EB8CBD8519ULL,
		0x8EE9B2D5CA97ED61ULL,
		0x2626D6DF343C607AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35FE519246D69ADULL,
		0x86682097E1ED2E78ULL,
		0xFDC820C7460D62B2ULL,
		0x97B77D5FCE319F36ULL,
		0x8D4C25CE5A3684B9ULL,
		0xAA24464B507BB89CULL,
		0x1940DBE05B8F4AF6ULL,
		0x0FAAF317B420D931ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69F92C29BA1912E1ULL,
		0x32C7147DB10A2732ULL,
		0xFC8918F3EB30E5DFULL,
		0x6A3EB71EEBC93BCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB058993158EFD14FULL,
		0x00F6A91EA787ABB6ULL,
		0xC60BE947E714C204ULL,
		0xDAF7D9FDA84EAAEEULL,
		0xCFBBAE69A227508FULL,
		0x8072792FBAEFF68DULL,
		0x8C65EA5C2456BC04ULL,
		0x169EC530AA47FB04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AFDF17621DB6F99ULL,
		0xE82E16D2BDFECA45ULL,
		0x3AC0CDC4A3D0F975ULL,
		0x64D529EF22B47198ULL,
		0x3B7340A8E9D9D173ULL,
		0x0CC77EAF21B4F70EULL,
		0x684632D2B54B6D75ULL,
		0x96F39D8BA12EBA1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA81AF25692953D0CULL,
		0x4429C162A84ACE61ULL,
		0xE80059E9BEF171D9ULL,
		0x698A928DDF59DBF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD225CE4E7F222EE3ULL,
		0xAE09400F36C1FBC7ULL,
		0x8245D38BC57795A0ULL,
		0x1DBC749F2473403EULL,
		0x69FA68EAC892D18CULL,
		0x94D344C2A4B8E543ULL,
		0xCB050A8A2812EF37ULL,
		0xE9F8CF908D8FB10CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6986792437D342EULL,
		0x38A511A8C5EE141FULL,
		0xCF87012B76CC2A19ULL,
		0x86AA02206869CD8FULL,
		0x74D990B3AD914563ULL,
		0xDEA621BEAE73F40FULL,
		0x1A79E20C270B857CULL,
		0x6B7908845896AFACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E6D7EEA3DDFCB77ULL,
		0x801760FCFF0FB55EULL,
		0xE766D51475C51D3EULL,
		0x5E09FE4E98FFA708ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1784160FD41C6EBULL,
		0x324918ADFE0DBFACULL,
		0xE5CFB8673106AAF1ULL,
		0x63F360DC22DF1F36ULL,
		0x06A3E68FCE29EC26ULL,
		0xFE73620CE5D762B9ULL,
		0x22EAEFCBA34CDC2FULL,
		0x6DAFAB17D9633135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A34226B6DEF59F1ULL,
		0xEC9C423A03FD6A52ULL,
		0xE7B4D66461FE2DF8ULL,
		0x187A61C01DE1313AULL,
		0xB63E8847F0E4BF43ULL,
		0x964F1AB99EA7AF4BULL,
		0x24ABEA866187310DULL,
		0x6B9196EB50D0D2F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76501DA0679716BFULL,
		0xBB0F6CD08B24F794ULL,
		0xBB75AA4A925FE413ULL,
		0x1BEFFDB84AB7EBEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4187BF73CE257EDCULL,
		0x251FE51E9F14172EULL,
		0xF199ED792E9B89C0ULL,
		0xBF057A01C1D99D3BULL,
		0xE480F9CFB52786CCULL,
		0x811078BCF6801705ULL,
		0x3103AAE6C12866F7ULL,
		0xB633D7DBE8046801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x969ECD43DCF3EF84ULL,
		0xB801F7E9BA099F97ULL,
		0xF1ECDC26B8B4B22FULL,
		0xAADA038BB4B0C778ULL,
		0xBF6DA669E335BB07ULL,
		0x6E48D8A1F2F48772ULL,
		0x4FEBBBD261106DB3ULL,
		0x52DA9C5B28758DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BC7534D1B15D0BDULL,
		0x36BFB1376BC1C76EULL,
		0x693A8E58B975D7ABULL,
		0x536A4B927C5D33ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71F8592C43E580F7ULL,
		0x03B7833008EBDB27ULL,
		0x1F4CA0D51E6B69E8ULL,
		0x1CD5E8D14E952248ULL,
		0x2C68904CEE05A4EAULL,
		0xDA6B4DC51EEF35B0ULL,
		0xE9883E3465B52E53ULL,
		0xAE790E1C8A079351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4FE500F553C1CE7ULL,
		0x4CAB4AE11271E79BULL,
		0x82822A9FDF720ABEULL,
		0x878111F68C0D98E5ULL,
		0x9C59425BC51DB75CULL,
		0xE48EC1973B71B4EDULL,
		0x959DFFC8090BE42EULL,
		0x9AD8106AD2CFD460ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF3F9AE90116A770ULL,
		0x35C9071EBB1B106CULL,
		0x118FBA4B001A60A6ULL,
		0x7F3A7F3BF4CDE135ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01E3D5E083FFD8C1ULL,
		0x6AB45D77F907AD52ULL,
		0x28DFB7BE89D40EC1ULL,
		0x97BF7455AF91761FULL,
		0x492F0C70DC1CE5E1ULL,
		0xE03C00D0CEDB7257ULL,
		0x931A2094651132A9ULL,
		0x12660FCADC7A8239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CCAF5C9C3889CCULL,
		0x4671131D21F1DEF2ULL,
		0x12AA297B5E7B5B39ULL,
		0x3653234637F110F1ULL,
		0xF9862AE6E4090695ULL,
		0xC939BB80731CAE11ULL,
		0xF2C356432ACD824DULL,
		0x3937AF33776B8F9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC28A0FEBABA736CULL,
		0x8E9994487566F0A8ULL,
		0xE3179651D164E133ULL,
		0x1E4EA78877D86847ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BB20637A3D69DF1ULL,
		0x04FEB682C14C50B4ULL,
		0x9FC5CA5DD2EBEDF4ULL,
		0x6245DED34BF50988ULL,
		0xE09A7D48BB8CF9C0ULL,
		0x47AF8AFF504A84AFULL,
		0x26AA093C39F328D8ULL,
		0xAAA5C830C9431364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AB41F4727FF27FULL,
		0x33C4C00E74C5A788ULL,
		0x7F1FBEA734B4ACACULL,
		0x8489BDC08381507EULL,
		0x7DFF18B363385590ULL,
		0x71303557A595485FULL,
		0x9254B68CC5DD2F43ULL,
		0xDC0A33599F31B2CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC717B26E4DE70975ULL,
		0xA820AD57A36D9D1AULL,
		0x255051C1D97A4D5FULL,
		0x08D4390307080FD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01B21462427E423CULL,
		0xF3140EC906D1BEF6ULL,
		0xEC2EAAF9EBEB4C82ULL,
		0x6879C0A539C13903ULL,
		0x4AFABEBADEEBAC77ULL,
		0xFF9734CFCF2FFAB3ULL,
		0x4CAB330F8DE815C8ULL,
		0x53B351910D32B192ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x898FA59D6EEA43F9ULL,
		0x7F59160F89987C37ULL,
		0xA64F68368F966149ULL,
		0x9DF3FC4A8C7096DDULL,
		0xADA456ADB83348CBULL,
		0x5AE3D30DA957AB92ULL,
		0xC569E0AFD76830C8ULL,
		0xF7D447B587147B90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2F5E0B892F2C615ULL,
		0xE65B7B8B1B550195ULL,
		0x59917CF87350E951ULL,
		0x6DA13AF095CCA660ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF82A296F5A35A77ULL,
		0x6A7BA9DF5F48C13BULL,
		0x92FC6A2DB471F49AULL,
		0x6E7CB14776D87C3BULL,
		0xF0847BBD888183A7ULL,
		0xB779A2C3E147CC56ULL,
		0xBF1A59628D1E2D5CULL,
		0x128A035E5339063DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2EF460E56D1F837ULL,
		0x77121F9720724B59ULL,
		0xCDB87BB9F56FED40ULL,
		0xD1D069B46E0B2A74ULL,
		0xFEBE255B7FB933CEULL,
		0x26D605EAC6546AA5ULL,
		0x7C5F9B3988E9B118ULL,
		0x50EA0960DAA6E53EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0042F15EC8D3AFAULL,
		0x6BB2D2823EF6F625ULL,
		0xACFC288A5ECC7987ULL,
		0x5A6B6332EE7E37AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C065C83BF45C850ULL,
		0x262891CB81159205ULL,
		0x8B20313304D1201FULL,
		0xA17CAC52E8163C03ULL,
		0xA61854D49FE220E9ULL,
		0xBAD80818B413D896ULL,
		0xCFAD59D9FC1A2383ULL,
		0x7F55694F89D59C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE342D51CBD12163ULL,
		0xC08866DEFA42E424ULL,
		0x2072216BC0B7C924ULL,
		0xD7310A8AF12E90CBULL,
		0xE3DB6DF0E07C1BDEULL,
		0x7E680622C471077FULL,
		0x1B2CE96BC71436C7ULL,
		0xC9D9C53D9521C669ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32DC75005C9964DAULL,
		0x5E40756E18FDB741ULL,
		0x35BEC02322FA7AEBULL,
		0x3AA5FC7249996AB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06A9298553EB9CEDULL,
		0xAE2ECFA7A59BAC39ULL,
		0x7D6AA38108F9C271ULL,
		0x01826ED8F7F962A0ULL,
		0xCD2E249B1727E0F0ULL,
		0x0AAE236098F6A91AULL,
		0x494518BD20555119ULL,
		0x82A48E79EDA26F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F67AC7EBC4E6B8ULL,
		0xDCA230A9295E2634ULL,
		0xCC3DA1F48DE3A1D2ULL,
		0x3C7AA6172DCC856AULL,
		0x13DC41CE0FAA013BULL,
		0xBAF38E3FD1D7F060ULL,
		0x090329900A8F56FEULL,
		0x5963A5316D52A34DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFDA592C84D5EBE4ULL,
		0xA73EC1DC0ACCF1BBULL,
		0x3AF6823DB6794086ULL,
		0x64AA6984D605291BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A414FD24028A9A5ULL,
		0xB71533F28DC43B56ULL,
		0xB727A951B8EBC7B0ULL,
		0x394186796263E9C6ULL,
		0xE1DB597DD5F02ECFULL,
		0x4B949283D27FE58EULL,
		0x57996B4BAB47993CULL,
		0xA3206BF87623B01DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x054BD3EB98822146ULL,
		0x53B5C229247AFE25ULL,
		0x27A01A312830C7C5ULL,
		0x8A1DE3AFDE7A2E30ULL,
		0xA63DEAC4364C683FULL,
		0x7A05F6B3D1C74C61ULL,
		0xBEA42FB1CF7EEF3CULL,
		0x3B7E1AB36CF43AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E53EB7459F603F9ULL,
		0x7E8A92A984AFF9E8ULL,
		0x43EE67F730843BE4ULL,
		0x113BB308E0F520CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D995C8E121B5031ULL,
		0xC50663B5C13462FBULL,
		0x5A0467B5D6D3EBF0ULL,
		0xE2DA52830FFCC2BEULL,
		0xEE492CB392A4C2C7ULL,
		0xF0680DF94057D0F7ULL,
		0xE395EF76D4A2E2E0ULL,
		0xB8F40BC3589DDF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D4FD01DEB5E596ULL,
		0x7C1003E7A42A6AA4ULL,
		0x876097ADEAC08049ULL,
		0x99E377236809277CULL,
		0x3EFCE981C5C3C4CFULL,
		0x4B4CFB3BB17A1F65ULL,
		0x3182F1F1B5A19D19ULL,
		0xAA1A932E92130D24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC1658F09CCB1DB7ULL,
		0xCAFB27F151F2541CULL,
		0x417571CA8643C749ULL,
		0x7D3EC175208EC48AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52DDA17300BADD12ULL,
		0x7F3F8BDCE466FCCAULL,
		0x170EBD2AF5338651ULL,
		0xD7831FC6F87C6935ULL,
		0x8F1B8BD9FF9E5468ULL,
		0x201F73CFC47C9AF7ULL,
		0xF635C50E3951C874ULL,
		0xD1F136E641DD1A5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x497B922A69DCC48FULL,
		0x1D4E11296B5DB8F3ULL,
		0x9B589CC348666E14ULL,
		0x29C42C7F668F7F6EULL,
		0xA66EA71F3C495AADULL,
		0x4A4DBC6059FF436FULL,
		0x7D49E3F5A12F9713ULL,
		0xD8536C0794974695ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x930C0301957B2A32ULL,
		0x1F12B53D47A44203ULL,
		0x6EB98A0E41E06C9DULL,
		0x3B2B10554A4A59AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB729B92485253141ULL,
		0x03D0DA9043F0E3E9ULL,
		0x74BE7A1D0B29F478ULL,
		0xF01C39BEAEE86101ULL,
		0x5F060DD163A8073AULL,
		0x89A36FF22BC22DFDULL,
		0x8A219A80B3BDCBE0ULL,
		0x2FB80BEA5FD6E79DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D58F85BE40C45BULL,
		0x484B701E3BA599F5ULL,
		0x967CB05933C875E7ULL,
		0x5E45DC892E96DBCAULL,
		0x0D7AF1C8638FE867ULL,
		0x8356ACA37FCF68B7ULL,
		0x5869AF91E60EB083ULL,
		0x87E623E649F55553ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDFA52F4CA78FE4AULL,
		0xAAEA681F8E549263ULL,
		0x3F8EA9365F5F8E5FULL,
		0x7AFECDD0BFCD3C3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1F67F03A7637844ULL,
		0x2A01BEF233644E4BULL,
		0x819F00F59BA53825ULL,
		0x8FFD937A9D859E7DULL,
		0xAF6EBFE2AB9CFC11ULL,
		0x4291C16679694F61ULL,
		0xF17157D77CCBD43BULL,
		0x1D74B60D7952788AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9189C663273A863BULL,
		0x91E0F5E532082263ULL,
		0xC0136AD45F1F2D24ULL,
		0x7F7A1D3FAE99F972ULL,
		0xFAD2DC605BE4ED19ULL,
		0xA2B6183D1EB17FFCULL,
		0xE9F4485A0589FFFCULL,
		0x92C4BF243266036CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F907DF8557B2840ULL,
		0x52BBE53078A4F4DBULL,
		0xDE1BE2C0F04B8C4CULL,
		0x26A21CDB7605077FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5646E696EF81753EULL,
		0x4A569DEC66EE9EC1ULL,
		0xC48FBDB6295BC718ULL,
		0x26A480B9C733ACF5ULL,
		0x189582C5D34DE839ULL,
		0x8A6FC2BAD0917249ULL,
		0xA4BDEA5638B73708ULL,
		0x8EF746F186EDDEB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB84B6639ADDA99EULL,
		0x063EAC68B39DAFFCULL,
		0x9BFDA8E46F0A6A19ULL,
		0x6A6468FB6C8F4C17ULL,
		0x854EA5C81192294FULL,
		0xAC13267A5C32C74FULL,
		0x2FBC9517B9999FEBULL,
		0xA044BCCEAAB09F95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4746FDDE168221EAULL,
		0x45D72314F95E4FD0ULL,
		0x86C4BC1898B5CB48ULL,
		0x2AC098EB0BBBBEF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x031C73503E531A1DULL,
		0x06C719E49C704B72ULL,
		0xF53EC91F217EA405ULL,
		0x6070B6130B1BAF16ULL,
		0x8131DCEB505C65B9ULL,
		0xDA90C1B393DFB9FBULL,
		0xFCC8D6E236C10889ULL,
		0x1E4D17FAC1ECFE56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D95BD967E3F272AULL,
		0x25AE47B8F7CA0B73ULL,
		0x0C76741815337D8FULL,
		0x358B628F92AF7B8FULL,
		0xFB78C0A41BEC4574ULL,
		0x8E165807AD7F7488ULL,
		0x7E1FA7C79313B72EULL,
		0x8E4E643F0B00E07FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF00E84B88B8BABEULL,
		0x3B4481AFD6F08EFEULL,
		0xB5E552FB58053A03ULL,
		0x0AB401609F78A184ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D003645E409F59DULL,
		0x07035A1A2AC3D4F1ULL,
		0x47395985447EB405ULL,
		0xA568085186B1AA29ULL,
		0xA582FF65D8EE933FULL,
		0xE1438448B25A20F4ULL,
		0x20D8311A72B50E30ULL,
		0x00C9CA8F5D88E97EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5C04DC3B3D26169ULL,
		0xD342B25775AE7634ULL,
		0x6634370D39CE0104ULL,
		0x8FFB111053F7C47BULL,
		0x9749E2E753840281ULL,
		0x7D8CE42D96B19854ULL,
		0xBDD61C9F9E3855B2ULL,
		0x462D50B3EF763C8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3BA2349FE090ED9ULL,
		0x00DC6BC8D019A67EULL,
		0x93542CB3953415C3ULL,
		0x48A70DD3897F915CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC95AB84684576923ULL,
		0x328658870B5B777CULL,
		0xBA7286F7265A18E4ULL,
		0x78658447883BF023ULL,
		0x928CC66AE6189BF5ULL,
		0xA9EC475FF3AA503EULL,
		0x7BFC5D08AF70EB6CULL,
		0xADFF974432205855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E3CF71BC5C0D5B0ULL,
		0xF1B216BEFCEAF3DCULL,
		0x4417DADCD6DDC168ULL,
		0xDF9FE5D4F5D98635ULL,
		0xF581E1852BE1E6C7ULL,
		0xEA5CF1E0C08BF469ULL,
		0xEF53702C6E7ABD0BULL,
		0xAA2AA585C1D6BC16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ABBBB4462B57847ULL,
		0xB01AF2A9A4F2252FULL,
		0x576DD4CBF40739D7ULL,
		0x2A6180B73D4F9B37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x588FD4D77E7B9EE2ULL,
		0x5DD53780353C6382ULL,
		0xCF3BA7C79D1F7B70ULL,
		0x9463DF8E4D292BB4ULL,
		0x18C4566A0720031BULL,
		0xE1FADA22D2901084ULL,
		0x1B47F0117BD2B24AULL,
		0xD58F565F0A0E5DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98D8EAE463EBD993ULL,
		0x7575D9D2165126C1ULL,
		0xDABE789A1EB2EF9CULL,
		0x3938BEDEC82BB4C1ULL,
		0x68F02387F1009A1FULL,
		0xEE33A5235740FEA5ULL,
		0xAB565A7B00B6224CULL,
		0x7D22FB614DF0BEF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD936778263395CA5ULL,
		0x17F13B9A6CA7E3CEULL,
		0x92596383C4A9EB86ULL,
		0x7B40A25971630C43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB976D3168B8D2317ULL,
		0x94334651C8B472F7ULL,
		0xBB46A6077C85F763ULL,
		0x04AA615B85EA5F12ULL,
		0x4807F3B369D9FAC6ULL,
		0x26FAFDB1200DF638ULL,
		0x0294EE650E7ECF46ULL,
		0xB3437BC2D9CC330DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A36EA7BFCC2FC27ULL,
		0x41C051AAA7C18E2BULL,
		0x75FD94AA2E00E033ULL,
		0xB6D7D2767428CB16ULL,
		0x9949FF921553DF88ULL,
		0xA6249E736A45CE08ULL,
		0xACEFA689FEABC2C4ULL,
		0x02190843F12C7503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F72258D1AB235EDULL,
		0x724517D01CA8DBE0ULL,
		0xFBD1BBE1A7D8F269ULL,
		0x1A1FB3BB9977C95EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5138EF765F0083B8ULL,
		0xC4EAEEEC0AA75978ULL,
		0x514B082875A1B4DBULL,
		0x252CDFF3D7D1C7E9ULL,
		0xC80C77EED68FE29CULL,
		0x0243CE993F186856ULL,
		0x494011882E25D22FULL,
		0xE1DE2094B3221ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B05EC701C32DBBULL,
		0xB89E79615A5D65ABULL,
		0x9E487BDCA4B7932AULL,
		0x87985ACE1FDDD9C3ULL,
		0x706D07947D023C27ULL,
		0x7E45C26F35DC1FEAULL,
		0x7DAB4E3AC615FCCBULL,
		0x43E1FB736C48E369ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70333E18A8440EC5ULL,
		0xA40243C80F3CB3E1ULL,
		0xEB1789C94343CE76ULL,
		0x110208163C3226F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBC85984263036D9ULL,
		0x8B26F7DF5849EC7AULL,
		0x511E265EAE9D9DCEULL,
		0x5A0EBFE15F333422ULL,
		0x9D02B65EC7F0C079ULL,
		0x81B09BBDF7E4B9B0ULL,
		0x90342C9D67C24104ULL,
		0xB1BB09852F81B6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA8B4268A8242B9ULL,
		0x1236201D35A9FC88ULL,
		0xA4F66B90E1DC73BFULL,
		0x757ADBF084C0D76CULL,
		0x3F28E13B72A68A99ULL,
		0x090DF9771B096986ULL,
		0x963A8C6CBDC7BC41ULL,
		0xA23DF5D6955FDA68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B75489C44B1F3ACULL,
		0x6114EE46EB2DD63CULL,
		0xC735820707F0DF13ULL,
		0x3124CFDBBB7919EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE9168090C01119ULL,
		0xA0287BB2D47C88ACULL,
		0x6C2DD316C2826BE8ULL,
		0x3D13919A4D4A968CULL,
		0x770A94039C1310B2ULL,
		0xC160ABC01EB8F8FBULL,
		0x55F3B990F23BF1F7ULL,
		0xBAC1DA1614C1DC49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA20C9EAECDBD5473ULL,
		0xC87DE4A9BFE4BDB4ULL,
		0x74EB0CCF24782D69ULL,
		0x4EE3EEC1F00A63C5ULL,
		0x33ED7E26293FDE97ULL,
		0x21D852062C65B812ULL,
		0x7DBB73EA7E39F75DULL,
		0x0E55F79E076CDE79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x242DB6B0CE5C3071ULL,
		0x85E7E8A30CF36D98ULL,
		0x0F9D1CFCD6557172ULL,
		0x063340AA57DDDFA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48B93A56139D5C99ULL,
		0x9ACF45BF93C13715ULL,
		0x7DBFFBA16B6CA03FULL,
		0xB78A87BA6143352AULL,
		0x56FD2798E81B79CEULL,
		0x7C4896A03FAF9B87ULL,
		0x5516E1C4C91D4DFBULL,
		0xA660F5CEDD3D0668ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C01756B2E51338ULL,
		0x365CFD2D10AC0D41ULL,
		0xD0D47AD9ABBE04C3ULL,
		0xE9F7E3125587B50EULL,
		0xC4C871E3ABA87F5DULL,
		0xC1C49C43B4144228ULL,
		0x3402B82BAE761C2AULL,
		0xCD1A5B43E2C236F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5CC1BE659C97543ULL,
		0x1409724F3C246DDDULL,
		0x95E9AD81B4800078ULL,
		0x0E0D954939F64BA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A1AF0CAE64B76BEULL,
		0xA7057177C2980A21ULL,
		0xF96903769775277DULL,
		0x5106A355EF909933ULL,
		0xA6AD079B6A344000ULL,
		0xD0F114552AA3E0BBULL,
		0x1E53E0434F9A9C63ULL,
		0x67282DA270AA92AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062ADA76FCEC774BULL,
		0xCF36A5789E7C83A2ULL,
		0x125E2F084F601A7CULL,
		0x15236D31D5D0FE3BULL,
		0x536FC26D3EC99369ULL,
		0xE169E3BC7D09D52DULL,
		0x6D5066B921DAB888ULL,
		0xAA5245A94097D1E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF085B2E5B349C61ULL,
		0x65E002A8E8F93D9FULL,
		0x2D8EDEF11290DF80ULL,
		0x43A3A5213C88382BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A14818EAFDE0B39ULL,
		0x058E5D0039A851C9ULL,
		0x6B93ABC00486FF0EULL,
		0x45F7EFE970D39CDAULL,
		0x8ED45F21BBC2F51BULL,
		0xA64FB80073109C81ULL,
		0xC91D0E0D38F23E94ULL,
		0x0051AFAC5C02D87CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42DC82C5FF62D4FULL,
		0x340794629402EFDCULL,
		0xEC9BBCBC3B5F1485ULL,
		0xA2BB519D7DC26FDAULL,
		0x736141D07E4EC221ULL,
		0xB251A9066C24DC1EULL,
		0xE2B84662834BDE72ULL,
		0x128490C166542C8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8FD13716F276E81ULL,
		0x093D01BAACA3F0A2ULL,
		0xB1ED925ABFDA2F93ULL,
		0x6FAF352C6AFEB275ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3548F034690B09BFULL,
		0x37D6C0CCF2E83833ULL,
		0xB5DB5D9EEC4222B9ULL,
		0xF0C49F2ABD66C7ADULL,
		0x00D61FC518AEBE87ULL,
		0xE1528CBCF281BA77ULL,
		0xE883E8101C5EF87BULL,
		0xD25B9E863041A232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6EEAC541E062B0ULL,
		0x85FA1A3C2965212BULL,
		0x5603B0D860C281FBULL,
		0xD76DB9A04747334DULL,
		0xB87AB302AF301D79ULL,
		0x046A018D66C2DCA4ULL,
		0xCB4FC1DCDA5E8387ULL,
		0x05B1E54081E2084FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x586C2A4ACFF69397ULL,
		0x7C614F9F87D8043EULL,
		0xB59558625790FD16ULL,
		0x7A8865E258506C16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE115E41EDAC2836CULL,
		0xC4F13980D5E7FE8BULL,
		0x2CA226B9CE41749AULL,
		0xDC280A50B2AEE817ULL,
		0x61B14980FAE81C8AULL,
		0xD04DA02D04B16201ULL,
		0xB5370644AD98715BULL,
		0x28B0E708C7C7749DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2857882064FBF9CULL,
		0x8AD6DE99AA704969ULL,
		0x8FFEAAECDECB1B74ULL,
		0xED1FCAD5F4F17126ULL,
		0x5BC233DE39F4F892ULL,
		0xCA33FC6DB42F1606ULL,
		0x6E5BD785656B6BEAULL,
		0x064247F36D09A5D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100DA1C5788A1B5EULL,
		0x21E8A94D1ECEFC65ULL,
		0x212C6C31A62527EDULL,
		0x0B73DCA635EA28D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92AA276918A192CCULL,
		0xA711FF445918BE4DULL,
		0x6506552CC19282AFULL,
		0xF1EC9F3AD53E01D4ULL,
		0xF47DD9BB3EF47378ULL,
		0x26A5B20BB12880E0ULL,
		0xA76400952E357B7BULL,
		0x0302986A58B90C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A74D641646F120ULL,
		0xD2AA15BF2C668C29ULL,
		0x1FFA8E7A2D309BC5ULL,
		0xE84A30C3E23B2503ULL,
		0xCA5348003BDB9C1EULL,
		0x7D1BDC891BD999EBULL,
		0xA10801C5244884BCULL,
		0x5B4FDFD0EC89AD8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1547BC7780A9707ULL,
		0xFEDD9AE756687A88ULL,
		0x36B399940D8E8736ULL,
		0x6E29D53D020AE360ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA8EC2C1BF9CB650ULL,
		0xD25DE253BE71FDEEULL,
		0xA72D2466651D6191ULL,
		0x618518FF151EFE6BULL,
		0xE93F07993BC482C0ULL,
		0x657E585826F0BAB2ULL,
		0xB17142E8AA5CA75AULL,
		0xFFC3551238C153D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A10A839A888EF3ULL,
		0xED67A2676D782ECBULL,
		0x533A9663F013FFB3ULL,
		0xBF5B6116CC0028A5ULL,
		0x4BE995CC75DFEF52ULL,
		0x96793FEBAA204289ULL,
		0x08CBCD6B277BD40AULL,
		0x7D98E72119DF3378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB9C9CA385020C70ULL,
		0x9FB7E006D7EBA550ULL,
		0x5C81FEA3E268BFB6ULL,
		0x747609B2DEAFA3F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE0F713F5249EE05ULL,
		0xA0F3317E53A82319ULL,
		0x3D1D0AD4DD34794FULL,
		0x4CCFCB817FFAA09FULL,
		0xC422692F56235A90ULL,
		0x0A607061DDB9448BULL,
		0x4D147BF9DD3DEAA9ULL,
		0x8360A9B313D7B993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A4DD8D49D61783BULL,
		0xA4CBAE7DA094CFF3ULL,
		0x7455A223B45ABE8DULL,
		0xC515BE272CC1B250ULL,
		0xE83C62DD5FA6A8CAULL,
		0xCFA758071C5A139DULL,
		0x3B7719ED8F174ADCULL,
		0xF9098FC0EE40326FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47E688954B6AD682ULL,
		0xB3A1207967349675ULL,
		0x6623F684C2957312ULL,
		0x10A7E74BE7B6FDA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74D21E2DB08D917BULL,
		0xF36CB9F825E6A388ULL,
		0xB366B478721E67C8ULL,
		0x46BB215851318B34ULL,
		0x5A648F8F165A8BB1ULL,
		0xE3923C8C76666134ULL,
		0x77DBFF748752F877ULL,
		0x0B000541C3894C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D778D176009D96BULL,
		0x0BA348082BF34AA6ULL,
		0x1F7E8A7F47A1B50DULL,
		0x018A722E4514C96CULL,
		0xBDA096E1C7C4C62FULL,
		0x27E1D22D7314B6F1ULL,
		0xA8CD552126CAD649ULL,
		0x8EA0B673F4B4E7C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C717ACFFABF0677ULL,
		0xC3F93C0A78129EC5ULL,
		0x501572597EB1C5ABULL,
		0x3B5661B6BFA3A38DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD606016B294D0F0ULL,
		0x63A2B4A53B7904ACULL,
		0x4C95C838F87B9276ULL,
		0x025FF2B3C99ACF89ULL,
		0xD4328A0977E3F017ULL,
		0x54F01F1E1CB3A203ULL,
		0x8B249DD2CEA2D339ULL,
		0x9AE6DBDF3361B984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DCEE028C316779ULL,
		0xC917B69157357CCCULL,
		0x8D78A545A781B147ULL,
		0x5D438EB08467B431ULL,
		0x603AACF96B90FB22ULL,
		0x1C1E8A38932C10D0ULL,
		0xC360F12077ABB5E7ULL,
		0x15CE3420775841A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x614E4275FAB3C8A7ULL,
		0x09A718264E631583ULL,
		0x6628C56C39A83B63ULL,
		0x66C54A532E9AE669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90E5CB584EC36975ULL,
		0xAAF169B915F669DAULL,
		0x513619E7DCE75337ULL,
		0xCF25FAD9FE543ED5ULL,
		0x99BFB3FA1A3F320DULL,
		0x5025766A42BC5AB5ULL,
		0xC31DECAAB965217AULL,
		0xA1F945FD88379E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074D65852849C061ULL,
		0xBFBEEA00B45169B1ULL,
		0xEC4AB2BC9639FF93ULL,
		0xECB9A159CA19DC05ULL,
		0x8A914F073BCE8492ULL,
		0x9FF0E49B9BFA72D5ULL,
		0xB249A38A6A97CF0CULL,
		0x589DD9AAD917003DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7B61E02B336AE5ULL,
		0x13002465226D6B6BULL,
		0xE46E41F6F9278FECULL,
		0x45FE6DC63311DE3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86CF7980AAD7BF7BULL,
		0xCEBBEA5FCCF20D6AULL,
		0x163528E5430AFA1DULL,
		0xAC5A12498E04DFC5ULL,
		0xB8C06724D45E8B42ULL,
		0x1F2DBC7D9C791432ULL,
		0xC44AB1AA6B79384EULL,
		0xAF866E1172B50275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BAC48309BCC71F1ULL,
		0x4316EC6709DB8371ULL,
		0x1E63C6859FAE1DE0ULL,
		0x4C846EB0180A59A0ULL,
		0x88B5E1B178A2B5E1ULL,
		0x17801DD3C6AD0B3BULL,
		0x2B65AACBEA3FCA00ULL,
		0x3A483C791F0D7956ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CB3006FACECFC89ULL,
		0xAF6A8B2E7F5FDEAAULL,
		0xA9D06766D1E33BD2ULL,
		0x47110035E0D8E0D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64DB69E98848FAF1ULL,
		0x6F55F6D9E6FC993CULL,
		0x984BBDC27F1846C7ULL,
		0x408217A5E7F8D481ULL,
		0x7D7ED1EF1CC428E1ULL,
		0xF43A25F7D805C801ULL,
		0xBDFDFF4A3147F19CULL,
		0xA6F96F8E512BE53EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CE50F35FCF761B3ULL,
		0xF60A0A772C6D4ADCULL,
		0xA0AAFED1BE71F6F4ULL,
		0x4071465EFB466F81ULL,
		0x22DC0B8B210D1ECCULL,
		0x56AC0B4D8045F0CCULL,
		0x91B514372434260FULL,
		0x4B1EFCE7EB68110BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C1FCD8AE87D1A5DULL,
		0xDC63E1ABC109404BULL,
		0x8A73A3C4B19686D7ULL,
		0x227DD5FA07C3E498ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE791EF27D103F617ULL,
		0xA7331F4988B07CE5ULL,
		0x00431BA185A6FE4BULL,
		0x41DF7B91125972A5ULL,
		0x2C5052C44EA490DEULL,
		0x69C5A25E14A7FCD9ULL,
		0x545824F91724596AULL,
		0xA8A80E7CB4748086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68CBE11047A2EA2ULL,
		0x4FFE3ADEB75964A7ULL,
		0xC45B119CB8FD9F68ULL,
		0xFFFC44F84832539DULL,
		0xF47A25D1D864D590ULL,
		0xB26B92E783BE11BDULL,
		0x7A0549AEB3FD02BBULL,
		0x9593BAD067E72418ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ACFDD1459FF9555ULL,
		0x8E933004540FFE48ULL,
		0xA434970F84803CD2ULL,
		0x16E7A22C2722D755ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04FEBE8A3BD290E7ULL,
		0x51E5D40892B7FD03ULL,
		0xA2A16773B9050818ULL,
		0xBA3C6E1B204701C3ULL,
		0xFEC0877DF0511BFCULL,
		0xD704F99AE9112FC4ULL,
		0x5D37CF1031BA58FCULL,
		0xE73AACDF798E4ADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0ED72329449449DULL,
		0x0729DD72D630E494ULL,
		0x567753B476FFF0F5ULL,
		0x69A69C5B49A298A5ULL,
		0x0F89A0927073BFC7ULL,
		0xD00725B44AC22CB5ULL,
		0x5C1CADE8721F8F35ULL,
		0xD74AC43F9BFDB18FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9637934CA264FC87ULL,
		0x54696AD13C418CCBULL,
		0x7630FFA5B2FF0AAEULL,
		0x2E32597ABA1B2AB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD775D8C810CA94A2ULL,
		0x1CFD17362D758C11ULL,
		0x5A336FD80B020B83ULL,
		0xF37CF4360F732FFEULL,
		0xA5216B83A970E2E0ULL,
		0x2B0678DF9BF605D5ULL,
		0x8712BFE2D326BC08ULL,
		0x0336F1DD3C3C847AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5320A985B215152BULL,
		0xB0A6DCA8CC032526ULL,
		0x2F9C6C89509C22CFULL,
		0x694962EF65E58AA8ULL,
		0x887C29EB2826CEB9ULL,
		0x5D6592AB1B1E2F4CULL,
		0xDF20178AFCE0C1D1ULL,
		0x7E46C4216003F995ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4DCEBE58FB47A95ULL,
		0xF2386658817C3F45ULL,
		0x189C005888C90CD5ULL,
		0x45DA5B2959F24347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E878721AD190FAFULL,
		0xB65D3D92912CE5FDULL,
		0x565071E82F99D502ULL,
		0x50CAB57D8A1321E8ULL,
		0x123BC22487A4B35DULL,
		0xC0DAAFA79D8E2773ULL,
		0xA5A82DA85E0CD796ULL,
		0xEA0E8C2EF048765BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA41BB0BB25195288ULL,
		0x3538046BB9CB1C36ULL,
		0x75F0A833E2B760A5ULL,
		0x02BCCB1EE51A2F87ULL,
		0x4D5004FDC147CDFCULL,
		0x5CC973A7665F927AULL,
		0x7ABBC5BE6FAEDAF0ULL,
		0x57A07BC0E213A10AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD569EA27F9C9CCD1ULL,
		0x5BB4212F084BE6B3ULL,
		0x3F77366DAED5F510ULL,
		0x0A645AB4C0D09C6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCF44E995FEF08BFULL,
		0x126B829CF4587666ULL,
		0xDE2FB936539AC420ULL,
		0x7E20C6BCEDB8D8B6ULL,
		0xD808EE058C6BE2B7ULL,
		0x3AD9585AB5DFA251ULL,
		0xCA69ED341DFE6E42ULL,
		0x4F6A76138D87F407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22961DCA6334E93ULL,
		0x83A0DCA6959F67EFULL,
		0xD2A64D321BC98AA1ULL,
		0x314F3A8508C41EA6ULL,
		0xE9DBA6918726A568ULL,
		0x291F441527F04F6AULL,
		0x2545E631D0BD79C4ULL,
		0x8ACD361FB6CD24E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x458387F58202D290ULL,
		0x3069A849703F5CBEULL,
		0x8EE2765BAF758435ULL,
		0x7C290A69C4AF79CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B1C758758937CB3ULL,
		0x1F8C128030A520A5ULL,
		0x3530887D389AAB4AULL,
		0xFDFD92B825CF9A55ULL,
		0x8E0CEC2CF028AF13ULL,
		0xC786DF65AA747611ULL,
		0x85AE5551C20F55E6ULL,
		0xDA0966C675153C1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C521F02A659155ULL,
		0x7A80E14F2029DD6FULL,
		0x82A396C02895A1B0ULL,
		0xD1CD2D6AC548371FULL,
		0xA4797C56A4FB29CAULL,
		0xFF190EF3B6BDACBBULL,
		0x58746938DE48CE31ULL,
		0xF4FC3B3E96A9EE4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5239ED6656EFB39CULL,
		0x6558221B3D9D25F6ULL,
		0x6925FD6EDF7D2E6FULL,
		0x2C24DB786474F0DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EC611420ACD05BEULL,
		0x8821D5104B33E6FCULL,
		0xCD95388C8C9C530BULL,
		0xDB9C64C3501DAEBEULL,
		0x8BB276D6691FF8F0ULL,
		0x18191C365D7821E3ULL,
		0x136628C1CC006AF2ULL,
		0xDB49AFE9BD70ED60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A7DD6106138950EULL,
		0x71CDF3C6FF905C1BULL,
		0x6C0A90F83A6C0839ULL,
		0x9F4BFA1757FEB66FULL,
		0xEE38B9E8D0855209ULL,
		0x6CA4DF78A79482B7ULL,
		0xBF15DB0247C768CDULL,
		0x5364E45BCCEB5677ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x345A4676508939F2ULL,
		0x8994E5724B6D2B5AULL,
		0xE5763201F2A69C43ULL,
		0x6846A1BDABF35ECBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30EBAE97F0AC3482ULL,
		0x33C805FACC7C89E2ULL,
		0x5E1575F26E4F066FULL,
		0x7407A53804B47796ULL,
		0x775835338484DBF1ULL,
		0x88E5221CB95B1F29ULL,
		0xFC04D150E1368681ULL,
		0x449AA31310CBA95FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76CC79E204EC4AF2ULL,
		0xC8F0B4D0B9458BDCULL,
		0x92DC296D84337928ULL,
		0x70435408CED0041FULL,
		0x468D81FB639C763CULL,
		0x32BD3CEDC494E256ULL,
		0xA8797C0C7719766BULL,
		0xC39D269B82FF9CF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF835CF0ACE3EFF9CULL,
		0x34C3562268A4055EULL,
		0x31E7F4ACAA6BF097ULL,
		0x2964CAEE422E4B19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2EC6E04959762B4ULL,
		0x81CE06FBA185F1CFULL,
		0xAAA33228A036C7B7ULL,
		0xAC27D7FD8BF26AF1ULL,
		0x86A8F48F9ED3AEB4ULL,
		0xA5616B4F8F54227BULL,
		0xDE4D67BAB85BF16DULL,
		0xA4AC5C5E103547C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B7F8CBA8D20C65ULL,
		0x0FE934A2FB3FBD2FULL,
		0xA580018F6D85C4FAULL,
		0x13C4DC8E43CAC349ULL,
		0x868C0F4537A585C3ULL,
		0xA1B2BBE3E3DAE784ULL,
		0x66E3C84A54DAEDAAULL,
		0xA9855D4386AE5E8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E7E7E443D9F6A02ULL,
		0xFDD2DC541A44F54AULL,
		0xBED0DB47F7D791AFULL,
		0x602CD95FB22E45BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF73F0C2C0611FA4ULL,
		0x57A31CD121BB4DF2ULL,
		0x8E7CB4066E7B848FULL,
		0x3E74D1CE7466DD49ULL,
		0xF493C204459986B6ULL,
		0x8DC0E9D588004CA0ULL,
		0x2A4FA27E545659B8ULL,
		0x9E0E7BFC2F642BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCF76305FEC586A4ULL,
		0x2096751F07E42F7CULL,
		0x38A8843F9E651AA0ULL,
		0x4350536AB2B8E962ULL,
		0x86E064C2FFD6FE2AULL,
		0xC1B2D26A58700CD5ULL,
		0xDC54C10F2E81E54CULL,
		0xCF38C4432DE65F83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B1C656D1C7BDCABULL,
		0x8124219B294096A8ULL,
		0xE911A6466D9FB1EFULL,
		0x2EDDC3D9FA5A4D04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40FF3893DFE86417ULL,
		0x33B234208979B4CFULL,
		0x7C3A6AF6B22222A4ULL,
		0xE224F0777C0A20B3ULL,
		0x2158F9F9FCC250C2ULL,
		0xEFB06299AC8D5AAEULL,
		0x7E37F30FDF756930ULL,
		0x12F0EB47993342CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98EA20430C44DD3EULL,
		0xDDFE5AFDB2D6E60FULL,
		0x188EAE70377313A0ULL,
		0xFB50AE8D07F597BCULL,
		0xA6DC32E95296A555ULL,
		0x0784FC12C068E97DULL,
		0x95BA807CBA59CCFBULL,
		0x8FEDC96EC93DBC01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD69AA4CA161EF635ULL,
		0xCC251129E40B9BF1ULL,
		0xE64ABE5DFCC83F03ULL,
		0x594B481952868AEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39892E1FC82EBE83ULL,
		0x89EE4F951F701EE2ULL,
		0x487EFBE2016288FCULL,
		0xA1A64F5131BFC369ULL,
		0xDE34289372901C47ULL,
		0x62724C692E34F8C0ULL,
		0xD80443ECD054FB92ULL,
		0xB32863CCB73860D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB71997FFDD4B1FAULL,
		0x15322BF6A47D52DFULL,
		0xE5EC657E4B2154E8ULL,
		0xD68896D3C86EEFB5ULL,
		0xC8025042F5919FADULL,
		0x29C6DE62DE47B416ULL,
		0x8CBFC1EBCF6AEA9BULL,
		0xBE9DC11D78443496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x997DB09258208B19ULL,
		0xDE2E788E582AFD41ULL,
		0x8EBDE289D8FFB8C6ULL,
		0x17B1DE80C18F64CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BCDC970FFBAE241ULL,
		0x1D0B25D1F19A8849ULL,
		0xCB8404A249E581B2ULL,
		0x2EEF5FA3A6072DCAULL,
		0x608BF4833329C4F8ULL,
		0x78C87735ACA936CAULL,
		0x71BE77FC9B746938ULL,
		0x5711A4F3725CA31BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC6161B3E8CC261ULL,
		0xDE8C25846E2E91ADULL,
		0xEB8A0E58E8EF2C25ULL,
		0x9FD6337162A897C3ULL,
		0x57C6DEF204C35C33ULL,
		0x5EDE00E5C4BB6974ULL,
		0x93A652CE1B711C87ULL,
		0x12329D476D8D72EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A48E6E2A461AE87ULL,
		0x174C9029F0B87161ULL,
		0xD78F7B306173B7D6ULL,
		0x48344FBAFA1FBCAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74AF5C08B85918CFULL,
		0x1611AE92B1A0AB76ULL,
		0x228F6D48A6D26751ULL,
		0xB9DA8E08F2B9899FULL,
		0xD80F98FAA49B799DULL,
		0xFFB293F837283ADDULL,
		0xED46F6AB1DEE15E4ULL,
		0xBA738FE5B7BE7A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C0BC354C53661BULL,
		0x616767D134FA4824ULL,
		0x8D48B214219F3AE1ULL,
		0x1974363A39F3F459ULL,
		0xDF1B74E41BD888DFULL,
		0xD450C44FB3D00144ULL,
		0xDA941AC4459D8A5FULL,
		0x5AA26DAC2DF12611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x842BFB2BB8F5710FULL,
		0x252F19C4FBBEF006ULL,
		0x5BD35F78A127E234ULL,
		0x59716C592D4013AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x417BA631E75A15F2ULL,
		0xF7D2ED19FAF07C59ULL,
		0xEF36058034AE3D9DULL,
		0xE96E10F645BF521FULL,
		0xB5EE840C206D7285ULL,
		0xF881143CF0374843ULL,
		0xA21C40C763F022C8ULL,
		0xA0C1C91936A66084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BEC4FA75F996E3ULL,
		0x882025A60C549B71ULL,
		0xC16CD3232BFD2ABEULL,
		0x247AEAA081C7D62FULL,
		0xAC502BA9CF893733ULL,
		0x15E74FB3CA0260ACULL,
		0x59F5B67363A05971ULL,
		0xC0A2163843156307ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C3DFFCF73414CA3ULL,
		0x1285F3CF9A764153ULL,
		0xE381BAD51488F5EBULL,
		0x09A7B3B9EB7D1C88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x264DD43EF6BD6751ULL,
		0x644695F2CDE6B875ULL,
		0x9225B973A35E91F1ULL,
		0x3399ED33D49A3B88ULL,
		0x44C8D46C70EECD76ULL,
		0x3160B66582C864ECULL,
		0x790D4B9F7C98310AULL,
		0x7536895CDB756AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6C7EFC4E8AE1C25ULL,
		0x8045C874D5C62762ULL,
		0xC3B64173EFDA55DEULL,
		0x20AF78873FE81DF9ULL,
		0x58F5AB9824221F25ULL,
		0x5E60EBBA6EFECE51ULL,
		0xB5D0A8E1AE683E31ULL,
		0xB0509EBBC83A86B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50DDF3FD747129DCULL,
		0x35F8E2E2E80CEC11ULL,
		0xC96FA02C4EA24842ULL,
		0x4D0B48956F6FFD63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1136AFAD399AB78EULL,
		0x3C7D3079AC047E00ULL,
		0xE9BF282E4CB3B3FFULL,
		0xC1657B622A076201ULL,
		0x893B099A2AACDA89ULL,
		0xB4F74FAB978CD0EFULL,
		0x4475B80D6827F9D5ULL,
		0xA08CC8AC70F3BAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB6421643E88FDF6ULL,
		0xE6F8E665AF7FB762ULL,
		0x7B51B5B8E39E0A8AULL,
		0xF01D6EB64BA51A12ULL,
		0xBC271E01C3FA3561ULL,
		0xEBA1C12F86953EA3ULL,
		0xE21E31B6784D8C1FULL,
		0xCF5CD18B6A340E8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C786E839963C6BULL,
		0x3837707E81447DDDULL,
		0x076B635D0381F270ULL,
		0x5E66BB92DED5DEFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF681D7BE430BDF4ULL,
		0x86D3BA17B83EE2B5ULL,
		0x59B8A237A896FA97ULL,
		0x49E8B46F8C91EB13ULL,
		0xF23F01EBAC977585ULL,
		0x2D19C62087B5F160ULL,
		0x868AD7134C526137ULL,
		0xE4C7DCBB1E7A2D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8D748FC30989D0ULL,
		0x17816E29A2A4A2A3ULL,
		0x9D70578D0E651E1DULL,
		0x357CAC000393D140ULL,
		0x0857918BA7F9E027ULL,
		0xAB1E2E7F88990224ULL,
		0xA0044A0A476566DBULL,
		0x2878563B477C679DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D35572CD08B6440ULL,
		0xBAAACDD3F3E5C31DULL,
		0xF4413A01555F060FULL,
		0x0839FF6972A96BD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB2911C7AF857A17ULL,
		0xCE2382C522ACB4EFULL,
		0x709F4248D11591F6ULL,
		0x732E4482F905FC6EULL,
		0xCCDF457950B6AC57ULL,
		0xCB5ECBB36D305CADULL,
		0x151A9948EE7D2541ULL,
		0x8B2299FE02A180A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB199E4B307030CCBULL,
		0x335ACE992DB9F3EEULL,
		0xCB71972AB65DE295ULL,
		0x59EAE6FBC5D25D4CULL,
		0x80C1D7D77342DEC4ULL,
		0x1EA90AC5CAAC54AFULL,
		0x826F06A613D9A3EEULL,
		0x9C65A5D686318FCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95ED731B87B2F0BFULL,
		0x3DC35772148BF0C0ULL,
		0x6AA56F4A8EFCE1CDULL,
		0x094F9B63ABD15E63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B941408DA53881FULL,
		0x0CB06A37B135844DULL,
		0x5B3A0B007244B8AFULL,
		0x09021B0C4DFC5F04ULL,
		0x84AF0D071278AB0AULL,
		0x73E65683DFC2551BULL,
		0x78334244681D7A0BULL,
		0x538F5AA47F6ADC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A155490826923BULL,
		0xF63A02141E212CBDULL,
		0x6F46062EBD49EF60ULL,
		0x5857E93970171718ULL,
		0x8E752C0C3A13B79FULL,
		0xB5B483B68CD0172EULL,
		0x35CF472464144678ULL,
		0x4D6CA6970ECF134AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58A23FBF12917D9ULL,
		0x51DBB29DE30988BCULL,
		0xC6CB4B924E587116ULL,
		0x19D0EBD195052691ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63B87CD2C2BE6DD1ULL,
		0x53528F66B3C81CA0ULL,
		0x770DFE55DD7AC6B8ULL,
		0x4C6FB933BB3B0CD2ULL,
		0x90AADD3214597D5AULL,
		0x2F6EDD424AC785F8ULL,
		0xA071D9BBAFDB9211ULL,
		0x6B6EB6C446E41F77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2ED54F03B6DF8DULL,
		0x6C5A1C3CDFA54AE8ULL,
		0x74B07D166579BA3FULL,
		0xFA87E7D383CB8F79ULL,
		0x05D4C4D9F42BE16AULL,
		0xFF766A746D9879ECULL,
		0xF16DC37DA827B045ULL,
		0x0A57BDE3FBEE3421ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE051449885CCB5E5ULL,
		0x05D97DB8A91E9B94ULL,
		0xFCF8CE749CB490A2ULL,
		0x3B50C2AB57F06C10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7DD3C169F7759B1ULL,
		0x3FDF85F65938AF16ULL,
		0x7C3DDC85A8C81709ULL,
		0x51CC74A1C2EDAFCFULL,
		0xC5D2990F4EDEA042ULL,
		0x96292F04F2C0D387ULL,
		0x7E7A2921B6341504ULL,
		0xED096D3E9A2AF869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AA0368D9161886ULL,
		0x1DA2F894FAA777C4ULL,
		0x942723FCA4A7F19FULL,
		0x51DDA821688461BBULL,
		0x4C23698BDE84657CULL,
		0x040784B9A924F578ULL,
		0x3E23655E14AD964CULL,
		0x03D9B4382DC07D32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6134463073C5FFAEULL,
		0xD33BD48E4BB42D9EULL,
		0x74F7C792FE16F4CFULL,
		0x1D04437472379847ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5DDD8269656AA7DULL,
		0xB254805617615BC8ULL,
		0x2887C9CCC5DA86ECULL,
		0x0C5E2120CCDD0ECAULL,
		0x586099FA86BB11E7ULL,
		0xDA8480D8F07F63B3ULL,
		0xDC5CC6C3EB10FF3BULL,
		0xBB348AD5825A4E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E39A7A672D4AD29ULL,
		0x7469ED667F092291ULL,
		0x7F4ED576826D0099ULL,
		0x058ADE59DFD1FEF6ULL,
		0xF0AB2A21F5F4527FULL,
		0xA496AF0B634463F5ULL,
		0xA24F3D506ACE40BEULL,
		0x5487DCED75EEB34FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C92CAA5A10268FEULL,
		0x3F37B7728F1A2F54ULL,
		0x473B5B7B4D55CCE9ULL,
		0x44751338C5040EBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AC1F7672DCDDA31ULL,
		0xA1CCE8D60FDFDC8AULL,
		0x86296FAB5CBF97A8ULL,
		0xD18B232761AADBDDULL,
		0xF4ABC91CD0A8B0B6ULL,
		0xD30835E449AB3B12ULL,
		0x105E5C5C3D4F5846ULL,
		0x3B5B33A87FAA9721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C9C606E4BB12A5ULL,
		0x651B67B805CFF636ULL,
		0x06384D963D630FB2ULL,
		0x2AA5441B50483F1AULL,
		0xA5A9AF82C636D722ULL,
		0x5C1D9E0F3658CD51ULL,
		0x7DA7B25CD5CF5765ULL,
		0xEA06AB8B813B6C64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF47FE3DD5F90FBBULL,
		0xE3840ABEE84C3105ULL,
		0x470E5DFE7C5CA96DULL,
		0x39721359D5E2F4C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CCC473916CA20E1ULL,
		0x0A3DA1D7E260602AULL,
		0xB833E93D21528FB1ULL,
		0x7C8585831D89322AULL,
		0x4D0CDDBFE2965B4FULL,
		0x972C5017BF2EEF3EULL,
		0x209D088302AF927FULL,
		0x917B33BFEA4654A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F138A38181C9116ULL,
		0x3EE5BD1D3ECE4D01ULL,
		0x7935C11D2EBE9E12ULL,
		0xEBD2DFF50F3CEF25ULL,
		0x3F15046EC5BABAE1ULL,
		0x49E8C5181A3CF192ULL,
		0x9457C13A1254A196ULL,
		0x87D33F59DA038B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD082FF0B47476032ULL,
		0x435E86AD1F7DBAB2ULL,
		0x1146BCF3A013B440ULL,
		0x7FA0ECB478362CFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7DE050E364CF9B8ULL,
		0xBB5F3AE24FF4BCA6ULL,
		0x1B1988E47BD8F2CFULL,
		0xC9D52ABC6F4C971BULL,
		0x8776667875246CCBULL,
		0xC4C0BD5B9A205E52ULL,
		0x8F6EF9CA7671E849ULL,
		0x1D02FB582638D3AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8C49720D0255BEULL,
		0xDB5C0ACA360E0939ULL,
		0xA62ED55E16E6C591ULL,
		0xC90701D80985E03CULL,
		0x58D4B95A197C8534ULL,
		0x7E2C8DE6AA7F8E4FULL,
		0xAFB6F4BE56F4F056ULL,
		0x36F0694D3DE47702ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6516E1DC43703CCULL,
		0x5A023B73ABC593E5ULL,
		0xAA3B7353117EFB5AULL,
		0x278FD682E24C77C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD88CF45EE19F3094ULL,
		0xC61DA4DDDA9C0EF2ULL,
		0xB75EB01FA74F1E43ULL,
		0xC41E2E2D3A86D818ULL,
		0x42CF88A820474D6CULL,
		0xDE04698B1EEB9DD7ULL,
		0x1A3EA782587CD190ULL,
		0xFBFE87AEC51423FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD853B574975074C3ULL,
		0xEC218D8DB86924D9ULL,
		0xD2072829C6713DCFULL,
		0xBF05A69B478FDE25ULL,
		0x1D6FE93951C104BDULL,
		0xD913E139CB3464B3ULL,
		0x8A916C016651556DULL,
		0x1D502D8D25D306BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C6AE95CF23D8AB1ULL,
		0x95B053628F656576ULL,
		0x390E5D19D3524DA6ULL,
		0x12F9E88F96A151AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84F3770A4BAD5ED4ULL,
		0x2FAB26CF620DD739ULL,
		0x0357B6DBB93FED57ULL,
		0x135D03D5A9E511C7ULL,
		0x1C8AE50E9A671923ULL,
		0xF9716FCF90710695ULL,
		0x2495A541BC5DACCFULL,
		0x8EA46DE682A5600EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF76DB64211E50C08ULL,
		0x3A6BCAA761318717ULL,
		0xE040951E19CD78B7ULL,
		0x1FBA200FBCC6EB61ULL,
		0xA618EF5A7B5AA877ULL,
		0x3E7F95CB6A724725ULL,
		0x773C7AEAECF27EC4ULL,
		0xAADA979262B2DFB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22703984D5A10BA9ULL,
		0xB525B8C5A4ACBAADULL,
		0xDE536AA0695B4A5DULL,
		0x4398B442AB1D3368ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x417E763CB060CC84ULL,
		0xF6743DB5C038959DULL,
		0xF39E75EBCDE1EA67ULL,
		0x8AEF065C83C52E46ULL,
		0x1AFEAAF2EF08D6BBULL,
		0xC4A30EDA76DC7562ULL,
		0xB592608A88671E1BULL,
		0x04AC16353BBBF771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95C5E915CCA176D1ULL,
		0xA30A7880A6469731ULL,
		0xB1BFC463390FFE44ULL,
		0xC2E882ADB4695C46ULL,
		0xE3AE5C21694B7E7EULL,
		0x631C650CC02EE04FULL,
		0x1A40157F98879194ULL,
		0xED67C4BD12CF92F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1A44040BDDA698FULL,
		0xCD66F9BE37B61F1FULL,
		0x5015D5283000C83BULL,
		0x3C2A9B84E272BCA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE61959C607CEC939ULL,
		0x5CE5BF4492DB372CULL,
		0x5BAB8E5538BE9F34ULL,
		0xFA7B6962A291C838ULL,
		0xAAC70A68FC3C5796ULL,
		0x17F0FBC3747E4FABULL,
		0xF868774B44A9340CULL,
		0x05426150540199FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7D4B724B078B0AULL,
		0xD7D95F35345E8469ULL,
		0xC63D8A0D6F170C58ULL,
		0x737DA2ED483CBB8CULL,
		0x25A639ED6A243472ULL,
		0x477DC8EB4D559D94ULL,
		0xA32CE06C4372D016ULL,
		0xD310FD57D9B09B7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA7B00AB6C5C7100ULL,
		0x7625EC252E872240ULL,
		0x3C466961F7BA6958ULL,
		0x7A529D57825AD3B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7D40355B5A607D6ULL,
		0x28F34940FE057545ULL,
		0x171521D8B678A4A0ULL,
		0xB8F75F0B4158AC9FULL,
		0x54621695EE002D8EULL,
		0xCCA57FC30E88E397ULL,
		0x98C10CA6D292D69BULL,
		0x4EC222E1CCE1C214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x025DC94331182C3AULL,
		0x190695D174D0BA74ULL,
		0x157C81503261FA52ULL,
		0x9A4B3EC90D5C0235ULL,
		0xCFE4C55E72FACFE0ULL,
		0xDA47F63DFBBE922EULL,
		0x99CBA57BE99ADF38ULL,
		0xEA661E084C452953ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7010484EC759C006ULL,
		0x09CF1D30533CD055ULL,
		0xDA05F0E718E562FEULL,
		0x0454D88B4B3B570FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19B052EF58C0F75DULL,
		0x254A8711BC6185CFULL,
		0xCF03B96C90AEBE2AULL,
		0x4A9254653DDA549FULL,
		0x6DFC7B7D08E2E4A8ULL,
		0x161EAFC42D8ADF09ULL,
		0x4F6FC7ADB64DF644ULL,
		0xA13E48C5C3249EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EDF1551EB47B41ULL,
		0xAC31F071471293ACULL,
		0x5B8A33FCC71E5293ULL,
		0x1ECBAFDF5199DD87ULL,
		0xE65A238CFA7DCA96ULL,
		0x323BF9B386624493ULL,
		0x309610B755ABBA81ULL,
		0x6358ABB4F6828AD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53DB6F3C5D0E5C1EULL,
		0x4CBF9D194555DF94ULL,
		0x07CAAE0221A54A84ULL,
		0x5BDBF5044C4F6DEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD760119899CCAA09ULL,
		0x6E69B4771153EF63ULL,
		0x1292940BC170E331ULL,
		0xE4ECCE0AF30D03B4ULL,
		0x2950EB78EA87648BULL,
		0x5A550BB3E7E1AB51ULL,
		0xF94A66472DFB8B41ULL,
		0x17E6AA49498C5764ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8DDB48FA66F990ULL,
		0x45D079B887FA98A4ULL,
		0x9DF9405508339E28ULL,
		0xC55755E02ECBAF59ULL,
		0x42D359EB6738FB6EULL,
		0xEBF9605347EEA421ULL,
		0x5E5CCC6EA92E4A10ULL,
		0xDB14086912A13A39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF075D1511D094679ULL,
		0x8A34AB16476C67DBULL,
		0x73DE29DA6FB4F239ULL,
		0x26D97F72EB27A8D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCD2F40BE9EFC6EAULL,
		0x523671F4C7765FA1ULL,
		0x35593418D8DE3820ULL,
		0x40069D8C1BF6B254ULL,
		0xB4CF541BE80B4EDBULL,
		0xD93827E6CB522193ULL,
		0xC09F90F5299FBC0CULL,
		0x3252D409F659CA57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58CAE9F2E97279A6ULL,
		0x6E6DAA1EE71924E8ULL,
		0x212AFF31E85B9710ULL,
		0xB3BF6D3AD1359EDEULL,
		0xAD4D4F324490F1BEULL,
		0x7B3E1E18B7DDE1EAULL,
		0xABE4235120EC1730ULL,
		0xBCAAE35DA65B663FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC154C4C744A71C74ULL,
		0xD6E63C6CC39EADD0ULL,
		0x28007B403B2D19C5ULL,
		0x0334E9E52A83EF09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFDA650C60FCC4B9ULL,
		0xC943DE0F90A6B1EEULL,
		0x188CF27F78E6B0FAULL,
		0x86DF7487065330EEULL,
		0x19751DF52AC564E8ULL,
		0x0C8B58143EDB4818ULL,
		0xEC0405A0568EF341ULL,
		0x8E6C30BC93AC6270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91FD605EC0A03BDAULL,
		0xFAA923C8F2452C6FULL,
		0xDF8F866F812919AEULL,
		0x4D13746647B2707BULL,
		0x8E68052C11CE4B1BULL,
		0xF382411E63AA9A1CULL,
		0x409EEF030A24CEF2ULL,
		0x526C43E4BFCF0EA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11CEB287550A5EA3ULL,
		0x85F422C5279B58D6ULL,
		0xA9FEC7694F7EFAE3ULL,
		0x21C9282A317B3087ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D8DCDB06867780FULL,
		0x4F1FCC4F964C808CULL,
		0x4F9C9FB536DFE3D2ULL,
		0xE4F6173D521550B2ULL,
		0x8A7B3F5EF7E7E367ULL,
		0x25C37355A8A5785FULL,
		0x71CBD6B09C8459AFULL,
		0x66380178EF5581F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202E6E1D0F9B63F8ULL,
		0x7C3C9E5F2CD9DA1BULL,
		0xBFE70519921584C8ULL,
		0xBB29BE5C18694A4CULL,
		0x039E4A3DC49D39C1ULL,
		0x854A14D9C37E1603ULL,
		0x7DC62D53BFB2DBAEULL,
		0x95FEFEE0F903320CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x822BC280F5E141B1ULL,
		0xA4E734546D4B402DULL,
		0xC88CBE646BE31321ULL,
		0x1242BB6FC9E3E391ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44FF446680D57144ULL,
		0x4A072F74A045ECD8ULL,
		0x94F87B50E992D692ULL,
		0x823923D325D70410ULL,
		0xF907C597AB386AF5ULL,
		0xAEAC5E7D566F3B0DULL,
		0x38AAA214F9567654ULL,
		0x113A8A5D8AFC6DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD0C4D61AF652FCULL,
		0x261F01DC63E9FDEBULL,
		0xA7716979AB02E508ULL,
		0x79F68EB0AB10364DULL,
		0x09F742F8673EB0B6ULL,
		0x84CD1E19E21DECCFULL,
		0xF6095FD7AE776C01ULL,
		0x370F804909DE4906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5A1E3347CF0C2BEULL,
		0x5B0BBC5B806D8C44ULL,
		0xD176E6F05BAB79E2ULL,
		0x6AA6142DA540470CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF31F0118F5E69E81ULL,
		0xEA382ABAC275C9E3ULL,
		0xE5DA272927C7C230ULL,
		0x599A2FF48230469FULL,
		0x0F5C2F9F37E385AAULL,
		0x187D3E59C153BA77ULL,
		0xD2F92A63E6B7FEACULL,
		0x10AAE627250597B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30B53854B46CE81ULL,
		0xE0D6865030F541C3ULL,
		0x64ACA3F5A1D97755ULL,
		0x674B7AEC7D1B90B2ULL,
		0xD1FC4EAD4D5DE8B6ULL,
		0x7024A0F1195F3BBEULL,
		0x8549B89EBF1543ACULL,
		0x4AC911A9CEAE3655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C4F117C7A751AE2ULL,
		0x068901F37FCB5779ULL,
		0x0938667768160CCEULL,
		0x51D43FA2D60D297BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1393E2E6F28F9BC9ULL,
		0x25944F09782A6A7CULL,
		0x961EB54C9C5DDCEFULL,
		0xD52D1E092BB829E4ULL,
		0x879D480C45ADECBDULL,
		0x82BD84FAED9D82D1ULL,
		0xD16FF2D87256C2C9ULL,
		0x51AE10396AF2B511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D03A4081F1918CFULL,
		0x4164E663D920068FULL,
		0x503D59D3B2839B69ULL,
		0xDDA2B3BF3CA45CBBULL,
		0x971710D86AC175F1ULL,
		0x506251172EE69A69ULL,
		0xEEB5BFC07E466EE6ULL,
		0x965CCEE545377293ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A7C7091529023B3ULL,
		0x5DB91C73EE30E35AULL,
		0xED84F1072446B53FULL,
		0x459A1CC788DFABD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD48D7A891DF6E95FULL,
		0x7F8BAA48A2BBE081ULL,
		0x0EC708488F2454B6ULL,
		0xB4874601AFF93285ULL,
		0xD2BEC01C73864FC6ULL,
		0xA3822434D3EF552EULL,
		0x16BDD67381EF84F5ULL,
		0xCBEC14B25CFA21FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB393CB138363EBULL,
		0xA61AEFFCE3066361ULL,
		0x53EA39AEB1D1B15DULL,
		0x860C1081BA459B49ULL,
		0xF510224BD185BE8FULL,
		0xD71E5254FEE3E148ULL,
		0x577043A81025290CULL,
		0xAAD0A8163D2EF360ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FC553B61689145CULL,
		0x3041E1855F68B13FULL,
		0x206098CCC15C47E7ULL,
		0x188D54ACADDC82A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4371F08D6AD55C47ULL,
		0xAB637FB96266B869ULL,
		0x2851F36D9FDED055ULL,
		0x03EE2D95AF142BCCULL,
		0xD8C5461445BA23F6ULL,
		0x092C7FFD31923634ULL,
		0x45CCE690A202E7BBULL,
		0x63BF08B2AAFCB92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467C3BBBECCE9618ULL,
		0xBBD7CA1BC590D9F0ULL,
		0x3A488106BE0B844EULL,
		0xD42E49FE53EFA197ULL,
		0xFBAD5B6A29AA40A5ULL,
		0x3E3F2658AED0CEA6ULL,
		0x8B8D4C06210AAFF5ULL,
		0xA612E46750AFA2C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE828A11A8628293ULL,
		0x0EC70409058B3D87ULL,
		0x937A62F606AB9363ULL,
		0x574D46C6C295DDE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20839A7FAF430799ULL,
		0x3468104714F4CBB4ULL,
		0xCD8AFFE82C64CFD9ULL,
		0x1F919509F3C21B04ULL,
		0xE4E70B9B4BF08E68ULL,
		0x357D063C4AD73C10ULL,
		0x54F4AC7B8183BB23ULL,
		0x4CA01F77C83682DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990ACBD1DDC68538ULL,
		0x8D9917D9D70C6045ULL,
		0xB50CFE03EB2FC65CULL,
		0x7D7B5B97A35B096FULL,
		0x36B97FA6E27A632AULL,
		0x8D1B5311DCF2E22BULL,
		0x80BB69C757433E8CULL,
		0x1F5BF663E43412FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x623B94F57906EE79ULL,
		0xA54F90B98DCDC386ULL,
		0x98FDE8A286C787D9ULL,
		0x5A34526628C3AC5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE315F3F946AA249AULL,
		0x4C8E34FD53F273F4ULL,
		0x5CDE162936B98B6FULL,
		0xE47FA07B393CD29AULL,
		0x4BA4224C8C86D1FFULL,
		0xB99C29F634546982ULL,
		0x48F51A51CC2B21A2ULL,
		0x598D0585620BF741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F82E27B3FF46414ULL,
		0x3205AD1C5D58B3FBULL,
		0x7ED1E2823638E4C8ULL,
		0x55C3073A42FFBE44ULL,
		0x20AD5988594FCB28ULL,
		0x79BFD843F6ECE43EULL,
		0x5CF6B00D3CE48C4FULL,
		0x8992D66AEC28CDBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC434DE9DA0E0C366ULL,
		0x953CA85613F78817ULL,
		0xE5CFF9D444FAD102ULL,
		0x6DDF972E75F53DC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E45813F2215881DULL,
		0x1194EDE1239C5187ULL,
		0xB663BCD5ED6A9946ULL,
		0xC450A7755F3BA1E2ULL,
		0xDE359E02A5AB5939ULL,
		0x729D3D5E71824EF0ULL,
		0xFCB76A672B6B4AD6ULL,
		0x46E73FD1B94F5380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD635AF458E037A72ULL,
		0x5A498D28B00027BFULL,
		0x8C250CBC9DFABBCDULL,
		0x463E427B4C0FFE89ULL,
		0x7F1A7E75CEF02967ULL,
		0x076381822AD200DEULL,
		0x5FA8F8BA321F3019ULL,
		0xBFDA92EB5C472EC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x661680E173DB243EULL,
		0xA1DD436AF1C7C081ULL,
		0x7A638FC650BBD596ULL,
		0x09F40F2BE26117A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x015D46FFE31FE96CULL,
		0x923480EB616C6583ULL,
		0x80A197A3CD2C6075ULL,
		0x894E38DC37790F2AULL,
		0x8F9C8E73B3A52AEAULL,
		0x07B1BBFF2D89D488ULL,
		0x1084344FCB9EC578ULL,
		0xF3F9A92A1B3FB89FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1E4A120725CE61ULL,
		0xC61362C15C985271ULL,
		0xB2D6C266157274C3ULL,
		0x0EB4D186CF1E1186ULL,
		0xB065AB00EE313E89ULL,
		0x3CE78E3B65CED1F1ULL,
		0xE3E7B44B2A7AEC4DULL,
		0xC8E69DE6988C359EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9864BFF72B2F3268ULL,
		0xE623E939AA967576ULL,
		0x6D05D5EDA30C280BULL,
		0x5F6D135ACF006FAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDCAC118DA1C654AULL,
		0x41DB0A4142EFFDA7ULL,
		0x145A6047BC8C7742ULL,
		0xE89BF8ABFDB3A48CULL,
		0xFB13FBA673987713ULL,
		0xA6182B2C5E9599D8ULL,
		0x0EBE6FAD28A078AAULL,
		0x62E88B16376652FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AB86AD999369D0ULL,
		0xE30AD80318C49C4EULL,
		0x06FF566421A94C8FULL,
		0x0E256BBEBE364BEBULL,
		0x13F5765098335654ULL,
		0x8A39BA811F6579C2ULL,
		0x1E0093CDCE26E21BULL,
		0x15AB3956E1B480C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AA70529D18BD99CULL,
		0x81D4EBA98B5024C0ULL,
		0xC989AD0B08EF83F0ULL,
		0x5190AF53F7E28D3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1669F3E586A3E93CULL,
		0x9B0FAF41BE4D1EE3ULL,
		0xABBF74A32C34E2F3ULL,
		0xD2720F8C35F8FDB0ULL,
		0x14362AC90082E468ULL,
		0x1890EF3F993C0ED8ULL,
		0x572356B0AA5AA57EULL,
		0x7776328CAF042639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB2AE316C86BB2FULL,
		0xFBA0FC6FB1A2F5F3ULL,
		0xA61C5731D966A570ULL,
		0xE983815D6263C8AAULL,
		0x45C2E0E5441E4445ULL,
		0xE7BF06ED74571557ULL,
		0xBCC858511BEE038FULL,
		0xFE5E7FA3090F7337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CD43D82110CF034ULL,
		0xDE972F0386A7320EULL,
		0xEF24DFA076EE46DDULL,
		0x62731CDD75E7C742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1C87F348DC0F488ULL,
		0x8C873EF8B04061ECULL,
		0x892621D84B3AE598ULL,
		0x926C5560141E1BD6ULL,
		0x6C9B79B30CCF796DULL,
		0x4E677FFD827ED5DBULL,
		0xF7372090A4CDD68DULL,
		0x6537833827E263DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72AC993164B3E53EULL,
		0x90C6D51C7012D104ULL,
		0x041D630832B79646ULL,
		0xBFA18ED841D6AA61ULL,
		0x7CB68B6BDA1B0B3DULL,
		0x735BC898C589AEEEULL,
		0xA745A0850B8F3815ULL,
		0xEA6E63901E2C6053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B174494AFD56772ULL,
		0x7F7DA2D04C915814ULL,
		0x62E1C088D7CED51CULL,
		0x0CA57979434BF7D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35891992CF5CA200ULL,
		0x50B234EFEF47CE93ULL,
		0x534AE2BC9978944EULL,
		0x6FC7B16E4F61724EULL,
		0x8A647C4F842A3A2CULL,
		0xF83E3401B1F205FDULL,
		0x1A41D2D67E39A852ULL,
		0x6731032309D25AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AF7537B5E0341EULL,
		0x99F26D31497A2236ULL,
		0x77D64874DA87CFE4ULL,
		0x629801748D01C101ULL,
		0xCCC116D35C549530ULL,
		0xE86FBABC467BD2C1ULL,
		0x102ADFEBD914C1ECULL,
		0xF39D5ED7F9B5AB73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB91AB4C90332E82CULL,
		0x0F65C80C9959473AULL,
		0x5ADCA91C426AF790ULL,
		0x351A131E26A1B3C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85F413B0D72B0A5CULL,
		0x058CFADDE7CD6DE7ULL,
		0xF7399B8E78516869ULL,
		0xA85272212D56FF12ULL,
		0x97942E10EB23D7DDULL,
		0xF0F79E06E3F60003ULL,
		0xF7FA6B20A4FEA140ULL,
		0x3188D31CCDD5C1A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51226FE9A62710B5ULL,
		0x12AF665DDEF60DACULL,
		0xBDFEC5F6448A8EBEULL,
		0x8671C25DFB3CBF00ULL,
		0xE5011FA8CBD65A0CULL,
		0x137C5032F8FBB281ULL,
		0xC73A8C9419253268ULL,
		0xE76DB7932E42A154ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6A5C73BD684A2ABULL,
		0xD32B21F4E9FEE17BULL,
		0x75B5DE74F60D4DDBULL,
		0x21E6C630E1F10BF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CF70760DB48D541ULL,
		0x2C6540648A122E0BULL,
		0xE2EDECA3068AE4CBULL,
		0xC1757B27F8F0BA1CULL,
		0x0AF127F9B6571B02ULL,
		0x209B5F5A7BFA41C9ULL,
		0x41E2CF4925680111ULL,
		0xA42A60F03295EE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2038B576321F734CULL,
		0x46E6250BB52FA18BULL,
		0x14577B1E632F6E55ULL,
		0x8307EB3AB3B88474ULL,
		0xFFB555DB4B1CD8BAULL,
		0xAF8189104FCB25E7ULL,
		0x07727CF6EBCF79B2ULL,
		0xF86E05F323834D36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x279F826E93CF36CAULL,
		0xAF54EA5B63E0AFE8ULL,
		0x7B42A9B92FFF8E7AULL,
		0x3C63117D81FC17FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74667DFE8382D72EULL,
		0x7505A84013ED2918ULL,
		0x9E2D33AA455500F2ULL,
		0xFC32B676B375B084ULL,
		0xD98866D3A5429756ULL,
		0x572549B617615DC0ULL,
		0xF064E44B8329A797ULL,
		0x581EBB253AEA60D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E6D27BD5ABD26DULL,
		0xCEB4ECF360C60353ULL,
		0x8549867E17962CA7ULL,
		0x0B74019E1D4143CDULL,
		0xC77907C2F7D03FF8ULL,
		0xAF39C314D7DD20CFULL,
		0x8CDE7DBF71D0476EULL,
		0xF7E9D8ED611577D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DC7C7FC6CCFF94BULL,
		0x9346B73C20C8318DULL,
		0xDED6E5F6C1031A53ULL,
		0x38984922EBCF0207ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD9730F57E4B55F5ULL,
		0xE13979D8C0BA4FDEULL,
		0x6ED5E9555A7633A2ULL,
		0xB987FA1944526170ULL,
		0x3890BBA9256B682DULL,
		0x4954A8048F5C454CULL,
		0xB474ED21292BFE94ULL,
		0x46C9993816A93156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x154A7048EAA78BBDULL,
		0x9FB49FDB41E81863ULL,
		0x232815E8EF447031ULL,
		0x5218FE4F8C1D1109ULL,
		0x614E0456B3028F8FULL,
		0x34934BC0AF16F66FULL,
		0xEAC63A4318F94533ULL,
		0x477B9D31478FE0E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C33F6E98F33F1ACULL,
		0x56388C10C91BEC43ULL,
		0x3B9C6062D2B947DAULL,
		0x4D0264CC75F74197ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAEC984BFD7871BAULL,
		0x49654DCEB5035DB7ULL,
		0x76062831C98F1628ULL,
		0xBFAF47916F6D67F3ULL,
		0x55AEF3A27C19CB3AULL,
		0x1F3159887200323BULL,
		0x7EA3D8AB1C699143ULL,
		0x34F0185E9D2A95AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189E10FCCEB7B461ULL,
		0x1437E2A22FAF321CULL,
		0x7FD8D71954C1C783ULL,
		0x3595C869E7C4C8A7ULL,
		0x4CE7095C350B4369ULL,
		0x1406CEFB6486974EULL,
		0x79FD31B0117D3793ULL,
		0x42C06CBD97D87AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFFB4DBDBAE8E613ULL,
		0xDD7DFC1C85612ACAULL,
		0xA6EA1A5C13E29EC6ULL,
		0x7D2CF90E51D8A1BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E58CB1D753EE07CULL,
		0x7A6F2C9116D746F9ULL,
		0x796426AECC0918CBULL,
		0x6A47927390DEC2FFULL,
		0x0181B703406F2D51ULL,
		0x14BB258D8D4211D4ULL,
		0x2C041BAF08F08372ULL,
		0x25B497118F1C19DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B9784547383873ULL,
		0xC5E0D651A33A3D7FULL,
		0x36C29A22A79B2B9CULL,
		0xE21CBDEABE3FC9A2ULL,
		0xCED93D19120D4D25ULL,
		0x9F3204B01A54E6BEULL,
		0xAB00615A250E9DADULL,
		0x9197AB1C1D30E2F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EA16B9B108DEC1EULL,
		0x26E9371E82D16E9FULL,
		0x692F3525F7F60858ULL,
		0x0475DAF7BB891EFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB69CCD42A87B57EULL,
		0x7CF0BAC4FD5472F6ULL,
		0xEE2C7D62D257585CULL,
		0x634D1730E1E42038ULL,
		0x2E634C601B63E15BULL,
		0x490B63C5FA1D1B54ULL,
		0xFB67553797D8BFF8ULL,
		0x555F767381160244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F77706852BA1E04ULL,
		0x40EE42A6CE023F9CULL,
		0x1F9D1D34A2884389ULL,
		0xA6C809630F6C6931ULL,
		0x105E81D42B9AD70CULL,
		0x1AE25594283489FDULL,
		0x6A13AA77E4E4920CULL,
		0x1FEFEA32E50CDA2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0A86D316FA52051ULL,
		0x161A938357D7C648ULL,
		0x60FAB8A2C00DE5E2ULL,
		0x2B13DF64FBD3AA87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA06D2BCDA92D4F72ULL,
		0x6A2832F8A944F88CULL,
		0x1EF088E53EEA412CULL,
		0x2878549FC969458BULL,
		0x44681F795CE4C532ULL,
		0xCEBD187451769B7DULL,
		0xB300988F46024B56ULL,
		0x7E99BA2558A21256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB90610A47055979ULL,
		0xCD56BFC94499CB42ULL,
		0x7F3DE75E038794E6ULL,
		0x00954F10859C3BD8ULL,
		0xB2F095EBE95AD6FBULL,
		0xF7BA039E1E0C69E1ULL,
		0xCEE0B976065ABD50ULL,
		0xF0387207BE17FE67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C9B35C288A14F9DULL,
		0x87468AFB066E8A61ULL,
		0x7C6DBF46AE41C123ULL,
		0x4A53B9F4344BFF28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5C8898005747864ULL,
		0xD271C517BD2A1239ULL,
		0x4F00A5B53DFE47CDULL,
		0x163E45564E8A7189ULL,
		0xD3F5766966EA1102ULL,
		0xFADF86542A71239AULL,
		0x98C7D3305AD95B5CULL,
		0xF8C7BD4FB0A39E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5DE39490D30884ULL,
		0xF7A81694ACF958F2ULL,
		0x0BBBDF2B77FFF822ULL,
		0x27BEF41AF0AD18F1ULL,
		0x3D2116894C74546AULL,
		0x3B80BEB3B9FBD7A6ULL,
		0x14392D8D3A45526FULL,
		0x80598C93CA9A86FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EF0E12F621B7109ULL,
		0x42DB5053C199FF95ULL,
		0xF0715CC09BF7A2F5ULL,
		0x4EDA8D1F8336C687ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99726A29CBC61D36ULL,
		0x694B6638EC3FA233ULL,
		0xD6448072355FBE5EULL,
		0xEFA838E48519C3ECULL,
		0xCD9293D507A43F4FULL,
		0x3DACF41631CAC64FULL,
		0xE980735EDA7C4811ULL,
		0x8720D904BE7D5AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5C8D6B7F4008D7ULL,
		0xDEEB438B629CD299ULL,
		0x35FB3328EA2B1074ULL,
		0x6503A51890F2D3BBULL,
		0x3F947B9B21CAD9C7ULL,
		0x39F6FFB6450A216BULL,
		0xBD10111C18B57996ULL,
		0x3B4653C79CDFEC89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1CD75566ACB2844ULL,
		0x176268EAAE3B4986ULL,
		0x38F7E3320EB7542CULL,
		0x4D145ADEF1855018ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303C264CB5DB7104ULL,
		0x2C0632FB7F18856CULL,
		0xF98CEF7FF5ED6541ULL,
		0xEDE7E2B14F7F0A48ULL,
		0x5A3260D932069026ULL,
		0x456287ED3BF4AD8CULL,
		0xCA2902C467A24F16ULL,
		0x41257B6EDA6CE51BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x260E510757E011ACULL,
		0x5A80B4E5FBF06486ULL,
		0x6CEDE62F9DD307DBULL,
		0xE8B299C9AF80DCE1ULL,
		0xABCDC49C8243ACE0ULL,
		0x12EDACA93EE9B628ULL,
		0xE7BB3C044E6FF9E6ULL,
		0xEDF3936D314E2290ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED1D064774E917E0ULL,
		0x4EDE0A2D12C8D9B1ULL,
		0x28EA89D41593028DULL,
		0x5E9DB926BA8F0E05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA409ADBD5F3299CULL,
		0x50E6FE3B4C59540EULL,
		0x14CA233ACC406E63ULL,
		0x6D36DEE81D52AEB0ULL,
		0xECEEA45324E0CE08ULL,
		0x9659EFB1EEC847AAULL,
		0x4CDFFEB86ECC8601ULL,
		0x25C5EC051975B361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024AD576D980D8C5ULL,
		0x058DD4CFAA449154ULL,
		0x72F34BB138915E3AULL,
		0x0EB96F1E02F63724ULL,
		0x8C044C458053592AULL,
		0x9E38D4C4A9E6C74DULL,
		0x9519E70194F6327BULL,
		0xE92E60E33C09F717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ABED76B6971A57DULL,
		0x204328A3DB8DD097ULL,
		0xE93E5CADE97F760CULL,
		0x5CFC16D0F85A6A7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3A8E9B1A639E101ULL,
		0xF0E9EFCB5D69FCC8ULL,
		0xD2497E0B5DEEEA50ULL,
		0xF20C82D9E5FD6C18ULL,
		0x1A4AEF11BB20AF3BULL,
		0xD941CBB48090F064ULL,
		0xCF2E683653F98A60ULL,
		0x8321F71E191C4637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1EAB0ACD62E58F2ULL,
		0x426CEA060D992E3CULL,
		0x4B24A91B7484D00CULL,
		0x5F828C3C897C50C4ULL,
		0x45F715920E39850EULL,
		0x59372BF60FF6C118ULL,
		0x32149EC635A09EF1ULL,
		0x8DCEDA29F61A3BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x763081F87A5BCA84ULL,
		0xB010BC0A06B3D3CDULL,
		0xD8F8BB946A9D0CD1ULL,
		0x7CE042DA8ECEA915ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0025BEAC288947CULL,
		0xF87F71AAF2982651ULL,
		0x1FED81E53F765AC8ULL,
		0x6989319F374EE4C7ULL,
		0xAE891E61D90A90BAULL,
		0x02EB2E4B8F2BC63FULL,
		0x3A9BA866C323BDE1ULL,
		0xAE59809D92332E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x905DA7EF72149DBCULL,
		0x873DAA22B1965A83ULL,
		0xAA3EF4859BFFE0ACULL,
		0x9C06158ABAFE0F52ULL,
		0x099EB08CB3537649ULL,
		0x4721B86D29AAE607ULL,
		0x0265694050DD6BD1ULL,
		0xCC03484CEA13E69CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA71019EE9A1E2C8ULL,
		0x5129468B52231436ULL,
		0xCDBBED1499E6A872ULL,
		0x664F780D70F5831CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7FC43C7DA1B7B11ULL,
		0xA61E0E276C0282DDULL,
		0xE4897DBA60CF1436ULL,
		0xD5FC62441E0DAE42ULL,
		0xC2C25AD40F81F0A0ULL,
		0x5E147E418AB27DC9ULL,
		0x9FBB60E7E01DC085ULL,
		0x115DFE941578C002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65AD82B0638627FAULL,
		0xD5C619D6B4E2C308ULL,
		0x551873583480C5CBULL,
		0xE19ADAE9CC1AB31DULL,
		0x3D1A828CC4E4FA62ULL,
		0xA648FB308A339470ULL,
		0x6BA26AEB7EFBA75EULL,
		0x66C22AA22453888EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6938DBAC89E1DE5DULL,
		0x188D68D6C9F6631FULL,
		0x4B258DD8975E0A2AULL,
		0x4782FD441D793665ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52814760F14F42FEULL,
		0x88A7F3569727666BULL,
		0x23A2C1B27E7DD8C4ULL,
		0x54606B21BBD44BE2ULL,
		0x5430E6AFE50628F8ULL,
		0x1D9CBD3F073A145FULL,
		0x961A481ED8474B15ULL,
		0x5BEE23B7396BB496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC633EA7E4D0AB80ULL,
		0xD0970CE5336AFA36ULL,
		0x2FB2CDD0F0FCBFD4ULL,
		0xD79B6DC8C074FB65ULL,
		0x16D8DB128CCA44C6ULL,
		0xA8D3A1CB1B5D07BEULL,
		0xC2D3AFFE1E33FD85ULL,
		0xD32BA2EE2DE59BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x712FC2142562742BULL,
		0x0DEAF9A6668C4C23ULL,
		0x506A88BD2C5E9C3BULL,
		0x49A41B30B146F752ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE310292BCA25C8A9ULL,
		0xD723A13DB74CE176ULL,
		0xA4FD9BB0DE6E518AULL,
		0xECD22411761EF836ULL,
		0x397AA2703918DEFAULL,
		0xBBECC95DEAC7D478ULL,
		0xDC4B88F8B33C2251ULL,
		0x1AAAB96E4169AD70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC85F0523D18735ULL,
		0xC81D2C7FF8756290ULL,
		0xE929B9934D8FDBB0ULL,
		0xBBD2662ECA541F2CULL,
		0xBA941DE0CF5B6B62ULL,
		0x62EA23B2172DA9DEULL,
		0x6FBE513A2D9982A4ULL,
		0x621736B94A4C55F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7F777058736875ULL,
		0x456B0C3F27B9D1AEULL,
		0xD8CA286567022995ULL,
		0x16E524BF5A25D4C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE47016B5C51E78BULL,
		0x2DD876D042CF2D26ULL,
		0xB24287EAAB55124DULL,
		0xEA3A1895767894BAULL,
		0xE99EB7515D672E86ULL,
		0xBEE339ECCC6DE09BULL,
		0x4AEE5470A6161CA1ULL,
		0x9E46669307476F37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00FC5D086A038DA4ULL,
		0x04882B5DC45F55D5ULL,
		0x15CE916891393942ULL,
		0x9C63AF181D551464ULL,
		0x7599148C121D4D99ULL,
		0x57F5DE9BC91A3E91ULL,
		0xE68BBC22FDC92AF3ULL,
		0x9F57E2686AC942DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1620CDAC1F45BD15ULL,
		0x708BD978FCD9E4DFULL,
		0x831692091587B8EEULL,
		0x253E07D093DE160DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC26AED90102EF2E5ULL,
		0x2FFD17E389399B89ULL,
		0x301513178C90C6E1ULL,
		0xA33472EAA7125F5EULL,
		0x4B8D15C1E57844F5ULL,
		0xF1D05BBFA7F5C2B6ULL,
		0x3B6DE066C1633E9AULL,
		0x98B873FE38335D27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B9C6BA30B08292ULL,
		0x71877A85997CC38AULL,
		0xF391526A968947B8ULL,
		0xA7D8E8B2B9A12B4BULL,
		0xF3A55FF015399DE1ULL,
		0xB6CD2F2A8BFA9F80ULL,
		0xCB3E12DEF1CA7DDCULL,
		0x374D4FA60F54B161ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B1623FAC8CB3F5FULL,
		0x80EE3B80170411EAULL,
		0xE39C42D5C6B41B65ULL,
		0x7142EF4DFE7EB360ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71AB3102A3E12171ULL,
		0x3DD94A1B37CBD6F5ULL,
		0xF556C2EED5644BCBULL,
		0xE4F5AC447AD3B52CULL,
		0x2F25CAC1ECD66ED4ULL,
		0x3FBABD897D6DBDDBULL,
		0xDC2F6844075208AEULL,
		0x039364313F934F18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17783FEDB16AAAC8ULL,
		0xED0BD04528A0CDA1ULL,
		0x9CD3418D8C567CE3ULL,
		0x7ABA4049EF55155BULL,
		0xC1EFB656C65607B4ULL,
		0xF92E147DBB0548C0ULL,
		0xC29FCA2325EF137BULL,
		0x73A38BA6871BFB0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9039F8FCA985C2F6ULL,
		0xC9AE9194EAAC6B40ULL,
		0x23D4FA42BDBE345DULL,
		0x47D59091ED3519C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F68F59D4DA021F2ULL,
		0x56529B84F9EB9E92ULL,
		0xF14F3783016F1EB5ULL,
		0x4F236EE1B5C8162EULL,
		0xCDF411F640CAE811ULL,
		0xE617F8640091CDA6ULL,
		0xA7067D1FD565DFFEULL,
		0xAC4446782E77F248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D46C79F22750B33ULL,
		0x7A6E401FEBFB9C42ULL,
		0xE151D1EB5980AEDDULL,
		0x33A681788ED95166ULL,
		0x5C53A1EB1B573B3DULL,
		0x412AAB7B71DED842ULL,
		0x4673F5E4B05E486DULL,
		0x52B75127FBD2CF2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFF2CFA5BA56C025ULL,
		0x571DC5EA3C806F38ULL,
		0x65BD785F270EEF76ULL,
		0x66695750AB71FAFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA1600FD0CC8BD1EULL,
		0x1FF601EC648454B4ULL,
		0xA988C372088A3696ULL,
		0x1A6652E230D447E1ULL,
		0x23751F56399B272CULL,
		0x55EE37DBACBF4425ULL,
		0x0F015E8729A9161BULL,
		0x7C82388C3F06D6B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E4155408EEB9C8ULL,
		0x5ED23CF53E709AD6ULL,
		0x0EF1C2A99734C90FULL,
		0xB9C2B818FDA6DEBAULL,
		0x07BC29F839E04C7EULL,
		0x92D28C4811477521ULL,
		0xA91346044D5EE634ULL,
		0x1458FAFC5C320EF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EA6579CF9967B51ULL,
		0xB73F3CE039DC747AULL,
		0xBBEEA435245889C7ULL,
		0x56C2BE24DEC30FDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECFAEF9530B68046ULL,
		0x60D1F7F10270DCE8ULL,
		0x74252CECD79329FBULL,
		0xAA0338947045BC0FULL,
		0x5AA96068218C8A7EULL,
		0xB9B056D8C3B28E38ULL,
		0x63592B07B96207F6ULL,
		0xD43601B38A0D0F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C98E612746F994BULL,
		0xF536D0A63188292CULL,
		0xEB4D38441E01C74FULL,
		0x84846FB192E0EA44ULL,
		0x613131F00CFBDE84ULL,
		0xA50554135990F26BULL,
		0x3BA37DB676407B63ULL,
		0x86C54632B37A96ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7838EF55C9C06FCCULL,
		0x7CFD909891E5D429ULL,
		0x6DCFAEB8B08C4080ULL,
		0x243A9E02B722C382ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7985C661D3D3341ULL,
		0xFD324DD56C0909F4ULL,
		0x3D035B626B519863ULL,
		0xD881A51F86AA0532ULL,
		0x8457C2F1BA5E6613ULL,
		0xD26D24E182A570B7ULL,
		0x4A37B1CD45E581AEULL,
		0x6E34DE28909A1C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x191D1ED681B423B6ULL,
		0xBB59D6BB0A675756ULL,
		0xC4D1DBAD90E8E31CULL,
		0x26B626607E837C2CULL,
		0x51ADF706C56ED1A6ULL,
		0x1A5BA14ED5C616C0ULL,
		0x35BF15438FBA46A3ULL,
		0x88CCCC5E3A45B2E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53AF826FF7191734ULL,
		0x9471FEE00AC90D50ULL,
		0x8218BC25E4D37904ULL,
		0x3F3E22C7D8AE2BCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57E346E03D1D5A3FULL,
		0xDEF2F7F386D5B59EULL,
		0xAACFEF44FDF87433ULL,
		0xA11A9F0B0723DFE8ULL,
		0xCFC0C4233635C7CCULL,
		0xB5E0FC4109F7391BULL,
		0x161858A7B60B6693ULL,
		0xE46F1E66AB1FF69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A2A4D83B805DF06ULL,
		0x80BAA7E701260D87ULL,
		0xDAB0110AFE296306ULL,
		0xC0C4E318C5E632BEULL,
		0x514D3F200BE9E0D9ULL,
		0x559B98160EDE1326ULL,
		0x05CA3468497DEF2BULL,
		0x5AE58FEFF49F7136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02DEB7D4CC5BC643ULL,
		0xA8852E6DCB6B4A88ULL,
		0x3BB93FA41CCECAABULL,
		0x4AC0E19158517A50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBF82C0E12955750ULL,
		0x0C27685A528FCACAULL,
		0x3010BADC3DD7FD36ULL,
		0xE1F510EB085DF0B4ULL,
		0x2450275BD31AA543ULL,
		0xD7B9EEFB0D2815D3ULL,
		0xC178E48FBC6B6975ULL,
		0x1F70567890A5F81EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E300021F3FCEBCULL,
		0xCC291B9003DC7BDBULL,
		0x4D0B1FBE4C97E245ULL,
		0xD97F320D284BB3C7ULL,
		0xB1CBEF781D0CB631ULL,
		0x0EB6D785EBA402AEULL,
		0xFC7E6668C76A4BFDULL,
		0x886D4E600B642D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6B577D8F96702E0ULL,
		0x1673C82D484E2657ULL,
		0x203454E64F6A7ADEULL,
		0x72E91281A7D64C56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x944541E2AE32F907ULL,
		0x4AE74665BB1895F4ULL,
		0x1F8804595E9C762FULL,
		0x2A63627F540E810FULL,
		0xED4A787B2C2633DAULL,
		0xDC0C8F71F2821C06ULL,
		0xFB92B45308E8078BULL,
		0x535F1638C7DF2534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB3FAF76164B37DULL,
		0x456740494F5EAAF2ULL,
		0x44B7EC459CA1FBBEULL,
		0xE0442E226C0DDF04ULL,
		0xB14C0D4D9D22AB49ULL,
		0x2CB025E6121D4E04ULL,
		0x5E996E18E58101E3ULL,
		0x8743B38CB822963FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E552FAE875489CDULL,
		0x0D37B0DFBAB07F57ULL,
		0x27D084B50345517BULL,
		0x162FD9E73DFDDA80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80FBDB8834A17292ULL,
		0xF10530516C003A49ULL,
		0x90D5510B747FDA19ULL,
		0xED515AAC26174D4FULL,
		0x540BD4A627DFFE05ULL,
		0xBCAB6DA34BEFB9A3ULL,
		0xCCCDBB8918488537ULL,
		0x024E6FA10801C4A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11349FE17FB625CAULL,
		0x54FBCB00C4BB310BULL,
		0x6BE970DA26646264ULL,
		0xD2D4711D7DCD75DBULL,
		0xA6A28E7BDB8E5B16ULL,
		0xF4CE0BE74C0B5A22ULL,
		0x1DACE34F7B9832D9ULL,
		0x4B1E19ACFB33CC8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D67A5EE09097AA0ULL,
		0x46E5E738A32B3658ULL,
		0x23CBF8BE9047B1A1ULL,
		0x4BA9ABC88EDCAB6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C873E1F6C357D34ULL,
		0xB93DE284B1BBF492ULL,
		0x723922BF38CF4EA0ULL,
		0x47FD7B30D229C468ULL,
		0x20301E7D32ADEC52ULL,
		0x41417FAC7D45F28AULL,
		0xB0D1F81B889C7464ULL,
		0x6CA1417A1AC1F312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9229A92434A09E5CULL,
		0xAEF1298B0AF583A4ULL,
		0xCB2BAB1C8C11FF11ULL,
		0x0C95D9344A4779D7ULL,
		0x597B6A9AF4B4A020ULL,
		0x332285401633931AULL,
		0x51B75B7739BC9A2EULL,
		0x80AFBF0BD349D148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x093048906A962DD2ULL,
		0x22E5E510F3809B85ULL,
		0xC500B80661F7B395ULL,
		0x4140FE5B23B74E9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x849C850BDEA86734ULL,
		0x935C0043F3A95558ULL,
		0x0A4F31AD65C84772ULL,
		0x4D74FF91E861CAB8ULL,
		0x23CF4DF0B9BA3834ULL,
		0x3C3FAB46FAB7D1D5ULL,
		0x048DE2E13EB0A70BULL,
		0xAA51B183C4C4228EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67DB51307D150975ULL,
		0x4BCF363E71C348B3ULL,
		0xB0D8C073B26BF820ULL,
		0xED566940C6D095F2ULL,
		0x7E2EFC8F2C46D2A5ULL,
		0xCE582D9ADE27EA4AULL,
		0x81AECDA40164A042ULL,
		0x3922AAD87BDCBFF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB28D485660B47359ULL,
		0x97E97191BF426B39ULL,
		0xC6939850CCA55112ULL,
		0x2D1993BDF3E9D742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04DC8AF9A807541DULL,
		0xA6A251781123D6E0ULL,
		0xBB7EF2A0FFD9E1FCULL,
		0xB3DE7478BBEA54D1ULL,
		0xCC177A9D53195B5AULL,
		0xE0596DA5499951D0ULL,
		0x9CE07087B4EDE1E3ULL,
		0xDC39C4E085B51416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3D319BEA67F93CULL,
		0xF24DB878CEBD838BULL,
		0xD9CA9B06B26FF247ULL,
		0x983B1BF96A53C96BULL,
		0x03F9597E8D04DE6CULL,
		0x28C91DDFD26602CEULL,
		0x19C667178811766EULL,
		0x16FECBA9D313E9EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC1843EF24A9EA83ULL,
		0xF3C0704EF4040DBDULL,
		0x5791BE40F621E32DULL,
		0x6264569DD582CD43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0964B28B0A1B0958ULL,
		0xB408D5F5529CAC55ULL,
		0xD1952A8B0D1B9A98ULL,
		0xD7068F9392887EB5ULL,
		0xFB67DB6366496F8EULL,
		0x79185B6D1F7E99B7ULL,
		0x88D4C019E5B2CB15ULL,
		0x1DDB7CA906D5D5D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067A99C504379D08ULL,
		0x038732FA1E98402AULL,
		0x1891D899E730D3C9ULL,
		0x5FFD574A4445083CULL,
		0x9F9E5C00E84729B6ULL,
		0x1ED5DA1023F0896EULL,
		0x5D443BF821F286F8ULL,
		0x91EC93F302D9C6E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2D30164BA39C7DAULL,
		0x1660D6C88B1AD70EULL,
		0x3076EEF43474E32BULL,
		0x3C7FC34DE5ADAEB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC8A6057687F81A7ULL,
		0x1BFC5ADC60CCF96BULL,
		0xB6D21B191A3C3116ULL,
		0x964CE1D9DF796463ULL,
		0x6EA04470229DF081ULL,
		0xBCC6B338481F3DC5ULL,
		0x78EC1A014CB591CAULL,
		0xB6EDD97276A8EE92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A191B43439B8942ULL,
		0x61019EF995F89E40ULL,
		0xB4CC679591EF0A87ULL,
		0x89196913B45D187AULL,
		0x4D4B053D2A27CC54ULL,
		0x9E27382F5FA49883ULL,
		0x19A06E668481D403ULL,
		0xE0CBBB80197FB27BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD518A6A5066D561CULL,
		0x46A6FF354D08E2FCULL,
		0x27412C7D3FFB521DULL,
		0x5643EABFFF3B3761ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28D1F2CC9E4CC318ULL,
		0x2A290FE84867379DULL,
		0xBC5908DBAE3FF5B0ULL,
		0xD38AFD649E0C6ADAULL,
		0x9470FE668987606FULL,
		0xCCB418C4C86F1227ULL,
		0xA9AA35895F46B454ULL,
		0xFE8D0C5036018C1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C6C4D5C97A8BF5ULL,
		0x3D07D66E0777ADABULL,
		0x48CDFAFF044CBB8DULL,
		0x29597F608BDD34BAULL,
		0x54D787C0A645F8CBULL,
		0xA16E789BEB6D690AULL,
		0x8B0B8AA6B78E1A70ULL,
		0x3D9C4CA9704CDF78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25D2CA9690879DC9ULL,
		0x5976FF8B0F2EA449ULL,
		0xFF186B818F5A1201ULL,
		0x4DEDF0C56B00D6A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFEDF8D4A99E1FBDULL,
		0xDE24E1CF6743941FULL,
		0x71668C94B722E0F1ULL,
		0xC7F432DFCE194F11ULL,
		0x8E0C547EB48A6E79ULL,
		0xA1AFEEA02C3D2B26ULL,
		0xBA12219185852D4DULL,
		0xFF540AE64991D8ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EEDFD06F13AB85DULL,
		0x28ECA771C2671F9DULL,
		0x76144AEBC4844FE9ULL,
		0xE24317F14E520BBFULL,
		0x88FC061F2DA9505BULL,
		0x1D36953A21A3D1A5ULL,
		0xEABA4AA10501F45FULL,
		0x8FE56B9C5727BDF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x116B9DFBBDCDE234ULL,
		0x5F3B7F83379FBDA9ULL,
		0xC25C295C06190470ULL,
		0x701CBFE87B873B0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF50F8D72FCE7C34BULL,
		0xC2949AE0B5E78A72ULL,
		0xBCB7CE6D1EEB509AULL,
		0xCC0F3D6ABEBC93BAULL,
		0x239700F310C1A91AULL,
		0x271E347A3B5BFC26ULL,
		0x5229E51ABFB3A6B8ULL,
		0x8B2B54D06A7DB771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD574AFEDFC38BA16ULL,
		0xD21BB0BA59B59B05ULL,
		0x9A6E991AF281BCC0ULL,
		0xEB0F76C197949449ULL,
		0xEAB6B6CF4F75D59CULL,
		0x7C5DA0D5AC2AEB48ULL,
		0xC8ED32B8EF13353CULL,
		0x015603B40BE4A593ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90E5DED3B1F070E1ULL,
		0x490ED4939D7A7043ULL,
		0x814BAFD7243A6C35ULL,
		0x56A9D0DF31E0A653ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB848648E4231B544ULL,
		0x8E2E56F5D730EC99ULL,
		0xFFA50CC78D0412C1ULL,
		0x295500462AC4EB81ULL,
		0x6BC819188A8BAC37ULL,
		0xD42497320083B168ULL,
		0x095E43536230B8ECULL,
		0x37528DB5FA24D597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B04EAF4ED527F6BULL,
		0x5B1E6DF23949175FULL,
		0x3FDC56A60A14437EULL,
		0xB93F33DAC999F62FULL,
		0x95EE08FDDC67050EULL,
		0x52C49E9714351C7BULL,
		0x71F09A057B361B25ULL,
		0x50C436B85A34BDC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBA1DD8F2E500544ULL,
		0x674ED002B191F061ULL,
		0x3A0FD7B1CC233AE0ULL,
		0x2936B6111ECE7DD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A1B31665F086C1FULL,
		0x3E0F6B50F931B223ULL,
		0x6C952C551CCFE230ULL,
		0x3D1FE50B3931B29CULL,
		0xF81782CCFDC01F7AULL,
		0x77424D85F657D929ULL,
		0xF2EFCB39B35512C4ULL,
		0x84A47A4F25F02618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF54EAC592F6FF1ULL,
		0x883EC2081CC87FD2ULL,
		0xAA4F5033EBE62E6DULL,
		0x3EA9A763F794BDDDULL,
		0x225C8B449D444134ULL,
		0x5AD08931EB34B156ULL,
		0xC1201203855882C8ULL,
		0xC0160EB030269045ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74E6A0F8583BF93CULL,
		0xEEB3CDC283A11BC2ULL,
		0x271B5A2C0467132EULL,
		0x2B9A373FBD893218ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x142F2AC3A7BA6DEBULL,
		0x98039853570384EDULL,
		0x168B8248B8C70824ULL,
		0x6F5392D4334210CCULL,
		0xA39A71CEA8D4345EULL,
		0x2F45349AF6DBD7A1ULL,
		0x57C9FFC02DFB0FC5ULL,
		0x106832E769B3C33DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42449DF66A1CE356ULL,
		0x087C509A2E36ABA4ULL,
		0xB3F00FF54707BA87ULL,
		0x127C49638BC1A617ULL,
		0x35E3E515FF3341F5ULL,
		0xD7287E507C46EA1EULL,
		0x4B03DB654C42B690ULL,
		0x3993E7295DA16DE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B0370366B818547ULL,
		0xA3CA56C75AE81ACBULL,
		0x4804D7D0F31C8B62ULL,
		0x405A87A67239157AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB391C9323531C575ULL,
		0x2E241703988A05E9ULL,
		0x64829BF641C82152ULL,
		0xE48F3DEA97C59A28ULL,
		0x65640CED069CDD5CULL,
		0xA4E05C1E5E8B1E3AULL,
		0x399E08CA836CA341ULL,
		0xC9865802EAFE3C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCD29BFBEACBA3BULL,
		0x7640E78A0E62B459ULL,
		0x791BEDD6649F2443ULL,
		0x80F78F59BE127FE9ULL,
		0x1557B67924C98758ULL,
		0x9ECE1DFD9582D685ULL,
		0xBC0809C2ECB2E7E5ULL,
		0xB3CA31869198A07DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC99974A5FBE3D057ULL,
		0x9E9868576161F679ULL,
		0x8FAA89403CBACCB7ULL,
		0x1D8565061EC84523ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x271743BF8257C035ULL,
		0x961C455B37C05549ULL,
		0x992F8EA7E42678EEULL,
		0xBCB1C2AE3BE3DC5BULL,
		0x254E0B50EF220FF3ULL,
		0x2DEBB2801EA1FFF6ULL,
		0xC0021CD08C62C317ULL,
		0x4709E451BF901301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E3116643B0D37AULL,
		0xEB1D617F22E21C03ULL,
		0x5BAD3F3EA0AB15CFULL,
		0x44DCBAC5BAF8E16CULL,
		0x5CC723308580D7E0ULL,
		0x3B8F6DC18A1E6EE1ULL,
		0x8F4060FDAC1C6691ULL,
		0x533F2265DA09C9DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x523AA728EC953F54ULL,
		0xA4B118262065C25BULL,
		0x7A4430B68DED1F00ULL,
		0x27EDD0EC92D9D64EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA8326A7F6FD3C64ULL,
		0xA24E5BA8DDF8C419ULL,
		0xFE4496778AB06449ULL,
		0xD11C0CB465FA4945ULL,
		0xDBB97B883EEFAEBDULL,
		0xF1C57D5BF4958230ULL,
		0xB8DA7E62358809F6ULL,
		0xD22C4652A35E3C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC39689162120B081ULL,
		0xDA241955FE27AC18ULL,
		0xDEBF186D15DE1E78ULL,
		0xEAE0F577F9601F18ULL,
		0x7A1C6CC6A1B721ABULL,
		0xA57CDA7031B43256ULL,
		0x08F329B8A1E314B9ULL,
		0xDC0DC17D534F6432ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x643CCE4F2C417C43ULL,
		0x1AF27151CD42F26BULL,
		0x3BDC0F365F4EACEAULL,
		0x6EC2CEE64ECE379BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28A2E1349356B009ULL,
		0xFEBE327A683BA917ULL,
		0x9E070FBD7B53FF27ULL,
		0x92C7248506F8A8B3ULL,
		0x318236FB74180598ULL,
		0x810A7798D44C041AULL,
		0x8D8765218F9BC7DFULL,
		0xB9643C8AA79B3213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A93D2F8F1524A4DULL,
		0x7342801A78065517ULL,
		0x79C3701D9B2D1EEAULL,
		0x8792718FE7B9CCC4ULL,
		0x86933D87AFCC1C80ULL,
		0x5E5DD934A4E224CEULL,
		0x6BF1E2F6EE053643ULL,
		0x95AD7EBEE85EAE47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D88156AC549000AULL,
		0xB11B353EF9EC793BULL,
		0x2074F1F3DC807D6AULL,
		0x5854DF33823A6C3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EB9AAAA2CDA56F4ULL,
		0x94AB7FB8E04E2BCDULL,
		0xBB47F20B803E9B9FULL,
		0x03B1891B5641F301ULL,
		0x531C7D26DDCD59E2ULL,
		0x0440192AC1EC9D84ULL,
		0x4F876091C80361B5ULL,
		0xC4A267F46BFE23FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD3E2284BDAC56AAULL,
		0xC332F55C95C2F4F6ULL,
		0x11FD2F2B1F21A58FULL,
		0x8D24B7D210B580B7ULL,
		0xF9A93E10D2FF978EULL,
		0xB6E4DE66C0E32971ULL,
		0xDA5CF50CA9E0412EULL,
		0x22CA415092664041ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2896E56B09B8DC2CULL,
		0x4D03437471F27190ULL,
		0x0D96B8A2DA53C9FFULL,
		0x7CA28D9B92183FD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE75CE5F40A6FC126ULL,
		0xE03FCC942B193BEBULL,
		0x4CB41A2867AD9511ULL,
		0xD15B08847E457A96ULL,
		0x836D454A8CFA287EULL,
		0xFD41BCE0C6E39405ULL,
		0x989640D17BA12965ULL,
		0xD122FEE3665FD0E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9315DCD564B2089FULL,
		0xC024805230799611ULL,
		0xFD216370FD7EE86BULL,
		0x72EA01AC8C2CA78EULL,
		0x622497BD56AB9CA4ULL,
		0x0EB0FF3E625A3895ULL,
		0xB1096402226B2028ULL,
		0xF02907ED2541D707ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4510CC14B5667A38ULL,
		0x8997725CE703387FULL,
		0xAE7B7D7EA8340BD7ULL,
		0x438BAF659C8BEA8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ED3FF6EC59FC131ULL,
		0x7449F9A7FA74B0E5ULL,
		0x24A111AFEC1DAFB1ULL,
		0x972507E557E7E84AULL,
		0x44CB20CD5309E764ULL,
		0xBA3DF17EBCB8C43AULL,
		0x872B8CFC0FF5DEE7ULL,
		0x3D3A627012AA6455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23CE15F232089D40ULL,
		0x55E569252DBEA2FCULL,
		0x8490CA0BFAE4FEC3ULL,
		0x7F6D697DCEBECC99ULL,
		0xD6E65DC464DD73EAULL,
		0xE7FCDC178683F9ACULL,
		0x2CD6B1D267726C63ULL,
		0x82DB99A4C8F9345AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AFADCCFEE30467EULL,
		0x540DBDD4D88C1EE7ULL,
		0x08A8CFD2F4BBB07FULL,
		0x41C96C9479763B00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A22849C3993A285ULL,
		0x3A260D7B4423C184ULL,
		0x037A359F5EEF8190ULL,
		0x4AE345D889521907ULL,
		0xE626F6987AFE1C2FULL,
		0xD1A1A15B66A53A85ULL,
		0x496D6A18624FDC78ULL,
		0x77524D13C47B4D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4779A25DBEB36C13ULL,
		0xDDFDD5A5C99D0F45ULL,
		0x6F16EBA857652CC3ULL,
		0xC6B48BB031CC3A95ULL,
		0xAE43FA51CD009C4BULL,
		0x9CDC818F5D121924ULL,
		0xD39B2D118AF0AC04ULL,
		0x5FB2FFF6753F5C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E5A54BC4E8132BCULL,
		0x316AF01EE65DA6ADULL,
		0x119858FAFFAB860CULL,
		0x05D42C821A6BAEE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DCBEB7205890374ULL,
		0xA45AA1085D40E8BBULL,
		0xEA9B2A02DBF1C196ULL,
		0x55C1EA64C956185DULL,
		0x52EBFFC03CBAA0EBULL,
		0x5CB118C8056BC2B2ULL,
		0x0F46E62536A174B9ULL,
		0xDCEB9D2021BECCE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABCAC7695B113E42ULL,
		0x34BCBF792E52DDEBULL,
		0x33290DC9ECE1BF3EULL,
		0x7BE9CF239B98D9F9ULL,
		0x330C613C7B36D529ULL,
		0xE61901AEEEC48FF4ULL,
		0xBB36F0FA05C6F6A7ULL,
		0x18695F36EE163447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D32AB976408084CULL,
		0x0A314F488BBF9308ULL,
		0x31D080A22F7EB8F0ULL,
		0x052D4BDED8C3E501ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D4740C2760FF1F9ULL,
		0xA5DAE3E7541A8F77ULL,
		0x5C08004634C1B85CULL,
		0x93D94DD5F422877BULL,
		0xC0A15B91FDC5CCBCULL,
		0x519E1A48F81F2230ULL,
		0xA07501453A2B75A8ULL,
		0xE72EE5D92DAF1898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71ECD0D5B6BD26EDULL,
		0xD6DEA27E12BF413CULL,
		0x961F6646C4EB899FULL,
		0x02C704131302B933ULL,
		0x8B1A7D732890E7A7ULL,
		0x5B3B97D248D0EAD6ULL,
		0x4F2CBCA6A18D0E0AULL,
		0x5C65ACC07BBC90C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED5F6880652CCF48ULL,
		0x619B9F0746F7859EULL,
		0xD6A2C98A1759902FULL,
		0x2AF0C36D4B1FF817ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBC12DF95A627DB6ULL,
		0x5BAF44EA01DCA066ULL,
		0x25AD2C98897A5B69ULL,
		0xE1680D3ACD9832F9ULL,
		0x7DAEDD0E1EA11F16ULL,
		0x2ED667E665E81748ULL,
		0x5692146D2811C2F1ULL,
		0xB898A5583D98FBBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x941D2AEF9E2580E7ULL,
		0x8ECCBA2FAB9B305DULL,
		0x95AEAEE1945C6FFDULL,
		0x5286EE4EFB5E8F9AULL,
		0x9F8FCBDBB86680B8ULL,
		0x922B14DCBD5D4C6CULL,
		0xFEF3017E4509BE37ULL,
		0xD63845972D9790F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30409084E8F07E2BULL,
		0x0E50DE295ADB8CACULL,
		0x919B4D2CA84E9EF9ULL,
		0x292F5594326F7C83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0297548C5587936ULL,
		0x94F577D85A5442BCULL,
		0xD42547A151FB96C0ULL,
		0xBF9F83A193CE6813ULL,
		0x6EAFD3D1F106F912ULL,
		0x409DCC03826BAE92ULL,
		0x588F3D8982B9F535ULL,
		0x71F1BFA60BC07841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E67D444E610C01ULL,
		0xC1F6F0D3A56ECB75ULL,
		0xCFC1EABDDC8F881FULL,
		0x1D87CE6152C04DC0ULL,
		0x84A0F286948A902BULL,
		0xCD150041BA7F2518ULL,
		0x4BA0D8D789658F7CULL,
		0x29488E46CEFE284FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB786934316F0121ULL,
		0xF94CC5C86201DF5FULL,
		0xEFC64F4E77F32801ULL,
		0x6B35096345E5F840ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8494D2727D00717FULL,
		0x20DC9FC895420436ULL,
		0x46B7101F579CFE93ULL,
		0x88F8BB9E626B9452ULL,
		0x8DE962345B17AEBAULL,
		0xE307808A6E2A80CAULL,
		0x35648A0426ED723EULL,
		0x149F463F59A7AE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88921ABFD75C03D9ULL,
		0x13804ADF20011133ULL,
		0x906F8FC33F4A309DULL,
		0x08D4F5DB7FE5084EULL,
		0x9AD94552E65F3E43ULL,
		0xABB87B53C5A49772ULL,
		0xE03A2D9172894842ULL,
		0xF435B06DFF41FC2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10670129F9051A6AULL,
		0x43171B0679219611ULL,
		0x5A913962DF310966ULL,
		0x4FD002D64D9EF53EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93D2EABC33B14C47ULL,
		0xB048A37311A5F092ULL,
		0xD643581E2A493BD2ULL,
		0xF7935F7CC9C2062FULL,
		0xEDC80CBDD9DD9C07ULL,
		0x17BEB151E8CDFE4CULL,
		0x9139C9012ED7DA84ULL,
		0xE01442D36C8C698BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F20B4F57BDAA6F5ULL,
		0x30F05F21046EB614ULL,
		0x1FB6FC92E45433FBULL,
		0xAEF64B409BEB5FE5ULL,
		0x4A93A5C5A0DEF225ULL,
		0x1C60A80E908ACA79ULL,
		0xEE8666230346EAD4ULL,
		0xAD054AEB29DE2AA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E797E9F2DA3DDFBULL,
		0xCF4DA4512730EBE8ULL,
		0xDD2D0885BD789BF6ULL,
		0x5CD5E0B613B3FC3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBA5FB36D186EB94ULL,
		0x4E7D12F8E9BB062BULL,
		0x9DD44D9F73D896CDULL,
		0x1F26F886FC401EB0ULL,
		0xB9473DE398031232ULL,
		0x9EDD7A2EC7FC7EFFULL,
		0x32E336E1DC97E04FULL,
		0xFAEB4175DB9926FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB11DDA25AFAE6AAULL,
		0x51845D02C7391BAAULL,
		0x9B79753ECBDC0D1BULL,
		0x4A73ABA2F7D04376ULL,
		0xD55D6EAC8C2DB5D8ULL,
		0x325EF9C3DCB37E94ULL,
		0xCB571CD890DD973CULL,
		0x48062F39D822E6E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD548DFC03837BE22ULL,
		0x17BFC5D50F57FA5EULL,
		0x6126B5C1E5A36294ULL,
		0x62B401CC87FD5DCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x288F9DF6CDF2CA95ULL,
		0xA4E1244ABCA6C116ULL,
		0x94242B7ECA90B893ULL,
		0xBC2B19B8D87E84B8ULL,
		0x098B4085CD7AECA3ULL,
		0xBDC8CAB1AA387428ULL,
		0x230633F440E837CEULL,
		0x4A248921AFDF6C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47BD662542E2D45DULL,
		0x0C631D47BD9AE11EULL,
		0xFF3B92FB04294C31ULL,
		0x1EE31DAB5F291AE8ULL,
		0xD2B90EC95ABA436FULL,
		0x31DF8370AF567CDBULL,
		0x843EEF744E8337DEULL,
		0xDAFEC7E53C5888B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040599CA93A910D2ULL,
		0x5D1E9AA83C969548ULL,
		0x267CC381C1656A17ULL,
		0x1CE2AB069F5B2D1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x977161E3290D6065ULL,
		0x816F141176C18B82ULL,
		0xDD5E49B9CCF2772FULL,
		0x5E537198F810875DULL,
		0x78C7D4E35D2E8BF7ULL,
		0x12F24C0DB33A3FC5ULL,
		0x3512CF0F1D28393BULL,
		0xD4BC39A0040A83D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1015DD92E1D8E7ULL,
		0x3198AAAD94E49E14ULL,
		0x107EA85D267F1526ULL,
		0x2EBEA4496ABDF9E6ULL,
		0xF0EB096D4A832814ULL,
		0x9FA0825BDA3E9AB9ULL,
		0xF02A21AE56BBFED0ULL,
		0x12E12D0E1A2AFFE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43277F8C5B9C5F6BULL,
		0x6DFA59CA17376D24ULL,
		0x07695DBA1A840DD6ULL,
		0x7618AAF8448022B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x299CBCC55A81F097ULL,
		0xF31C2BD4896DC958ULL,
		0x40A7B71584B6B385ULL,
		0xBE94EA590B004E02ULL,
		0xD75230393F3E8836ULL,
		0x631DAFC4DE694E69ULL,
		0x964EFA4AD8628B01ULL,
		0x9B3D53DDF403951EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B7B09F2B9B0131CULL,
		0xFBAA0BC56663344FULL,
		0x661DE954455BD906ULL,
		0x096B8D7C3967A6AAULL,
		0xD8F0582F00B090CBULL,
		0x434DD073E5AADEEFULL,
		0x9CA60AA05F3060B5ULL,
		0xC4704E3492BDB583ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0A7C457E9E4968CULL,
		0xB04D46140F4F2124ULL,
		0xE99D610F3CCD21CBULL,
		0x1798340141F7D858ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA4E783729183305ULL,
		0xB5164A6F3351F847ULL,
		0xE5BA215B75331817ULL,
		0x1C588FDAA3346B45ULL,
		0xAB85B24596D0977CULL,
		0x5AF7E7A175FCBFBBULL,
		0xAB442EB6B5F811A8ULL,
		0x7D721CCC00AE1B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6F11F5252AC504ULL,
		0x8D978AB63C0E4730ULL,
		0xEC48D232DAE40178ULL,
		0xEF28664AC7FD75D1ULL,
		0x1ED55B4712016C10ULL,
		0x7B04F01CC7E8C2D6ULL,
		0x37009EAF203A2239ULL,
		0xE0E268FC7A93FED7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D0C5009BAADDDA9ULL,
		0x658F7D6ACE3B3B2AULL,
		0x3B78B048D480A114ULL,
		0x6A84DA5DC3173143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69CAAC9F2E6E2B9EULL,
		0x44F72E6806D878E9ULL,
		0xE47C168364749B8EULL,
		0xF68B458A6C5A025EULL,
		0xF6A1AA27A0723191ULL,
		0x15AE8FD40702D92DULL,
		0x7416EF8BF56404CCULL,
		0x6853A9CD8F651E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE202C1D13076D962ULL,
		0x332FBF1C54F778E0ULL,
		0x0EE591261E919E9DULL,
		0x8BCDBA487F6FC3C0ULL,
		0x2016FF7E85E8ED78ULL,
		0x43B53274C86A63AEULL,
		0x1A8D7F6656BF7C5DULL,
		0xA454867419B15A20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x605D3FE7EE576CAFULL,
		0x3CCB4B6EFC827102ULL,
		0x1FFD2AF2D24F3D64ULL,
		0x029CCA8965996324ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE067250FFCDFF60EULL,
		0x59E244284363E435ULL,
		0x69B22AA8FF4CB91AULL,
		0xA047C6E406980075ULL,
		0xA79A3D0B5ADE3EE6ULL,
		0x1B8107FD2D376572ULL,
		0x9FE250039F63E63EULL,
		0x747C147E33DCEBF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5526BE065FB98C5ULL,
		0x6230D9BC51A8BE9BULL,
		0xF7D0BE23862C5FC0ULL,
		0xA686C0DBC7E2F4A4ULL,
		0x7E5B5A6FDEC1ED0EULL,
		0xEF06B014A6423C59ULL,
		0xE0F6041D3D249A40ULL,
		0xFA44059611B01573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A6A5C4403188061ULL,
		0x91DA76EFFA1F3F56ULL,
		0xC8F4B0B80E85A0EEULL,
		0x1E133C7D515CE2C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01DCF372ADAD6D8FULL,
		0xC8EFFF3539A5AE1FULL,
		0x771EE7A27CC3C60CULL,
		0x45871553B0D2D163ULL,
		0x1F03CC9AAC27FBA3ULL,
		0xAE6A5CE33B310892ULL,
		0x1897C34A99E67D1DULL,
		0xF11AEA48972D1ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x530C04AD66718406ULL,
		0x9193EE42C3081A50ULL,
		0x700032B978F70D61ULL,
		0xD5DD4ED193F3B86FULL,
		0xA5A5ED21F16945C0ULL,
		0x3C436BC0EE5EBFF5ULL,
		0x7A6695D3393ABDD6ULL,
		0x68D830509974FE25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C01AB0FF8AEC20ULL,
		0x2923DC09DDD45B08ULL,
		0x826B74A15D4B1D46ULL,
		0x29916151C633F1FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2BD69C662C5E3CCULL,
		0x4C5153F3D2236B5EULL,
		0x4E896874F52A4DFEULL,
		0xE2B847FA2DCA3027ULL,
		0x0BF2838686B5F3F3ULL,
		0x9E21765500FC26DAULL,
		0x2EB820719ADE45DBULL,
		0x41D648EF83BB2392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE91CE0F777E32FULL,
		0xB50090D5F34B2199ULL,
		0x7E4231673FAE3476ULL,
		0xA85A4EE26A1A5C8AULL,
		0x0D1776A3C1835191ULL,
		0x7C4C41C78F1DB3F0ULL,
		0xFBA36C1589E2AB3FULL,
		0x3BAE35D9DE967042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD858368EB0D21B4FULL,
		0x9CF6901CC5DD5880ULL,
		0x6559FCB83AD50CB4ULL,
		0x2450CE4E4722715EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C1B11E1195FEE4BULL,
		0xEE89E5D4D3126E32ULL,
		0x7A653ABED38C2BE3ULL,
		0xAE4808F821F1F98AULL,
		0xF901292B5BC5CECEULL,
		0x125E6E4A612791D4ULL,
		0x622680E387451786ULL,
		0x8C309655088C6771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD0E80DEFFAA97EULL,
		0x2C68CE8D1D0F8205ULL,
		0x1B4F9FBF01EA05C7ULL,
		0x94AF8A9AB798C75FULL,
		0x2D04E33767550C6EULL,
		0x0C3FDD217ED0B0CFULL,
		0x5342E564E4BCE9C0ULL,
		0x96C077278ECB4D26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78BC8C0972221ED4ULL,
		0xAAAAA3594EE85309ULL,
		0x94DEAFCBF1D8F181ULL,
		0x083D1F1D7D03194FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6602E9AFA7C8B53AULL,
		0xAFF7F8606B63E0EFULL,
		0xA9FCF2F8D16D4253ULL,
		0xD2751BED21C251EEULL,
		0x6F747EB2373F364EULL,
		0xCC99D4F42B2C3651ULL,
		0x45F66EE2B4BFD886ULL,
		0x915FE099B505137AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740991835D155B04ULL,
		0x9138E3C3A1FEA3E0ULL,
		0xF400C394893A4CA0ULL,
		0xFCACA2DB6E6E5114ULL,
		0xCD04D165A000FB12ULL,
		0xC6497BF353DF3609ULL,
		0x3D7A51E4AF819EC0ULL,
		0xDF85048157916D98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E8D118ABDF02356ULL,
		0x0EAC4ABCBED347B1ULL,
		0xF8687D190F6F8918ULL,
		0x3C4524AF927EA066ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE46591BBF3853C29ULL,
		0x0C85C9B15A89D02EULL,
		0x624EAF029C5F1AE6ULL,
		0x461A4493BFA403C8ULL,
		0x8CC9507BCA10F562ULL,
		0x368CD2FB5646C794ULL,
		0x94A4884F128CFD6EULL,
		0xC0C2E14D6B1FFAA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B248676C7C0ADCULL,
		0xBCEED1E7E7DC1034ULL,
		0xED2BC16004C357D4ULL,
		0x27B67B36880C13C6ULL,
		0xDE09966F515FED01ULL,
		0x3085CEBC20B7335CULL,
		0x0D48DDC1883030ACULL,
		0x3BF1C9E321D948FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB428E72E71507298ULL,
		0x34A1992B65FDC03EULL,
		0x8CBE3EA5216227DEULL,
		0x556D432418164E6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A152FB668E232DEULL,
		0x21FF818E8F07D82BULL,
		0xA7E7B7F495E98FC0ULL,
		0x832D0276A428848CULL,
		0x073720CAF417CEAEULL,
		0x56A9AE71F17D4E83ULL,
		0xC5E0A6EEA401FA3CULL,
		0x00B022C06B25087FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x506235BA76377240ULL,
		0xCDF905D4F22B2763ULL,
		0x1F17D638172F967AULL,
		0x6652A5E50051953AULL,
		0x62341C008B58B381ULL,
		0xD280D75EFBFED554ULL,
		0x51421ECDBA7D804CULL,
		0xEC13BEE95C7AD96DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5825B0077F08C41AULL,
		0xF216688A0DA2ADB4ULL,
		0xD858169F286412D2ULL,
		0x2C112E7DD119EC0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DA2447C6FEE2E76ULL,
		0x2E231ABC9EEE4D37ULL,
		0x1CFCD121B9DAA75FULL,
		0x31B6BDE1338726FFULL,
		0x9904EDEBBA947388ULL,
		0xA527BF0D643D88A6ULL,
		0xD4F25B21892F32D4ULL,
		0x5DE25215D03190D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2EFB7A74B596D6ULL,
		0x97E4D23E72BE5441ULL,
		0xEC8984D7F83918A1ULL,
		0xD16599F921EF73C1ULL,
		0x7CDF439FF85B14FCULL,
		0x7C9F1D51F3E52B71ULL,
		0x744C6B5D0C75491EULL,
		0x4DDF33BD5D954D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE0A9040CFBCA0A1ULL,
		0x9A864A50D94DCED7ULL,
		0x8914E374453A3FC7ULL,
		0x40C7A50914C9BBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x497C55BF0DCD0D5EULL,
		0x31235C66277F7E73ULL,
		0x8E0699B84087D62CULL,
		0xEFDBFE38F09898CDULL,
		0x14899317377049CFULL,
		0x1F09D903461654EAULL,
		0xF4C84C0D10778D9CULL,
		0x8B884672004592FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30964658DEC21BD6ULL,
		0xF7AFF68E7261AB9EULL,
		0x7AEF55D055095F8EULL,
		0x0A9B6C15CBA2F1D6ULL,
		0x2F23348082F922D2ULL,
		0x6939438C78C14B41ULL,
		0x056D500082992442ULL,
		0x76B1AE5C67BDC2FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261819C4F8BABB9BULL,
		0x3669957A2FBD41E7ULL,
		0x9A98ADC4FA8219EEULL,
		0x7D1B2557C91E86F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71DF2206ED4C2A87ULL,
		0x4B333CA311A8E0E1ULL,
		0x92FBAC18B2028049ULL,
		0xB6AFBE578AC2C886ULL,
		0xA6778370942CE90EULL,
		0xACFC875C2E80F17AULL,
		0xF81176B78D578CD9ULL,
		0x1D3C18349515FD34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E6150ACC3D521A7ULL,
		0x209252C4871E2554ULL,
		0x60EA407E2B53EBB7ULL,
		0x668983E089230824ULL,
		0xCFA87E7FA3A38B24ULL,
		0xA2036502C760828CULL,
		0x528DEA391BF623BFULL,
		0x24910A5470F08F9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6388D1DDDDAF976ULL,
		0xCB9C0323D95B32DAULL,
		0xC398465F5B242E6FULL,
		0x398A49BC5F2E04BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x212A1B790897AF2CULL,
		0xF0841C81A540EEE5ULL,
		0x5E046491351E1AE5ULL,
		0x8135605DB88E41ABULL,
		0x511338EF10830F52ULL,
		0x1E7E755A6590B7A5ULL,
		0xFCF4EB67FB155306ULL,
		0xECF3315B1CD9A4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A66F6FB8624453ULL,
		0x84DA5F69A5ECF959ULL,
		0x36DD43C8827D9A3BULL,
		0xBC1AE99BCFDBE48BULL,
		0x640F34BEC97186C4ULL,
		0x055DBAE11C459AFBULL,
		0xA006B662F8B12B0FULL,
		0xE7A2228B53936FA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E1C4B33DCCFB000ULL,
		0x26856B18E07A36C5ULL,
		0xF282FF870D7E6F58ULL,
		0x0F22A999C91E45B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E12C8CEE18EB869ULL,
		0x9EBFFCB0E4F2227CULL,
		0xED15B1CA915E9CD7ULL,
		0x480F8B86AB198892ULL,
		0x9E1EBA1AF4723085ULL,
		0xF7296CD05FF6E00FULL,
		0x9E72BFB75ACB3B02ULL,
		0x9278CBE872876930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33F2AEBD4846B4ACULL,
		0xBA7B9F2C53E31340ULL,
		0xA4CE81819839939FULL,
		0x274686C048C92426ULL,
		0x8E4EA1F5E732E336ULL,
		0xCF451C418ED552A0ULL,
		0x833C1642AD83FFAAULL,
		0xA6F95350389AA1CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5303AF9190AD7D05ULL,
		0xD02852B79C0A0DB8ULL,
		0x5264579AB1B7D84DULL,
		0x15B4EB5EFB75FD6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24CF91165F4A84ACULL,
		0x6664A27F0202393FULL,
		0x7C89CAFCF35BE0D1ULL,
		0xC2CDFBA83CA6C7CEULL,
		0xED95B5C05F0368A3ULL,
		0x03E3802736F33D37ULL,
		0xAA2491FA4F312F8AULL,
		0xCC246251582B82ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5912FBF15FFDF3DULL,
		0x73CF10D99B431D14ULL,
		0x52E01294C9E7703CULL,
		0x3A0B915E3614B35CULL,
		0xF607D3BB04316448ULL,
		0x659864E88E23F3C5ULL,
		0xE246C7FDA4FE0FB5ULL,
		0x16B8BE86C0E0FA4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E4DEE22C4774EF3ULL,
		0x71BB9CF275840315ULL,
		0xD495B3E96D0B2A24ULL,
		0x76BCBA5C7BA25237ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F1F5D0BDB7A19DAULL,
		0x2F24CA91C684BA70ULL,
		0x92A2D344D62910C6ULL,
		0x4770D2EF1CAE76ADULL,
		0xFC83D14BD881DE94ULL,
		0x83885242F27A0C28ULL,
		0x9AA9851792964BE3ULL,
		0x9CC213FFD4DC83F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6B9B4EB9FADF8EULL,
		0x273ADA971ED7DC2AULL,
		0xA2334BB5B37DD5C1ULL,
		0x51EA1152B58915AFULL,
		0x41BDE2C1A4401DB4ULL,
		0xD9E3141A5E02417DULL,
		0x2FB89842D1444CF9ULL,
		0xA7222F589B062B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE152A40E341DB40ULL,
		0x36712A00B174F3C3ULL,
		0xD032AF23D4D711B4ULL,
		0x6B42B26EFCF6911DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x847AB616F12E4FACULL,
		0x57A493DBBA93F738ULL,
		0x44F3B1389E3EA96BULL,
		0x24885FA2B5F5AD56ULL,
		0xFD70DD9E0F2C24E8ULL,
		0xCE8AD7CAB1BB6701ULL,
		0xC4BCD0B65FABBF4FULL,
		0x5B4C22F85435049CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538DEAE57F38EF79ULL,
		0x5082F700B2D4B3E1ULL,
		0xEBD7F7C1AB6BD010ULL,
		0x661B0D972B9A9FB1ULL,
		0xF390418DE4BD3E69ULL,
		0xFE127B94C7466B19ULL,
		0x62682C74C3C31C82ULL,
		0x890AC63AE8971D87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA843F597BE6B95F0ULL,
		0xF8FF4CDBD51CA7C8ULL,
		0xF1AC1B34175B03C1ULL,
		0x7421162983CB5AD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE771CDF1CD655B3BULL,
		0xFD97FB156DAE5407ULL,
		0xD7365939595EEA6DULL,
		0x856A9DF7951B09E8ULL,
		0x3F7D147AA40937C8ULL,
		0x15FCCED3BB509810ULL,
		0xC6A4AB1D4970DF94ULL,
		0x263DE9D4EE1D1C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D6A4CA3A35F06DULL,
		0xFA7F143025603224ULL,
		0x2E57947F734D8510ULL,
		0xEA0113122B80A6CAULL,
		0x49706D6E22DD477CULL,
		0x4D7B324A125C423CULL,
		0xDC86C3F256D5AE51ULL,
		0xB1193604EA9BB1AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD97BF502BFB512E5ULL,
		0xC65623545C92DF59ULL,
		0x694F1519E91AB546ULL,
		0x7EDC3BC5EED030EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A6B3015FCFB4F29ULL,
		0x3BD59D3DB93DDE1AULL,
		0x6C41AB366F026310ULL,
		0x0CF41FAE6CBF1B33ULL,
		0x53AD700F585371D9ULL,
		0xB7199CB5C13BBDABULL,
		0x2FB101C92DD9C649ULL,
		0x86E585A736648DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055E992EC918DC6DULL,
		0xEB899FADFD799A25ULL,
		0x8FF4318F1697EC0FULL,
		0x8E40DD4F29429A07ULL,
		0x5369DE8FDE7DE124ULL,
		0x0DB34F25C4E0C572ULL,
		0x0D11B4D67B1168FDULL,
		0x1ABFB41CD0C987B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F142FD34995EFE7ULL,
		0x757B80EF31451C6BULL,
		0xFFF2E5ADE2285061ULL,
		0x0C505CEA587F6C2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x602E4882A7BB1BE2ULL,
		0xE78464C08C02866EULL,
		0x3D3D00439178DBC4ULL,
		0xE9077C5041D2BEC7ULL,
		0x24CA543843ADA57BULL,
		0xF680A467319B8426ULL,
		0x0EE72CEE987D8979ULL,
		0xCACB3310D4543044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BAA0F6F7EF30BAULL,
		0x13B04D83C8A0435AULL,
		0xEEC97F1D52E452E5ULL,
		0x4E05C041BE72F1ECULL,
		0x7234AB92770CB6EEULL,
		0x6E6551A3C74B9F88ULL,
		0x70C5F1A0AEFC3DF1ULL,
		0xCE40845DD950E82AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EAAB0280FAF5416ULL,
		0x07E2603E8B3E327CULL,
		0xC7624EB6E7C5BF24ULL,
		0x1797AA9FC5DC80A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B52554E8A723268ULL,
		0x11431AB3A938644DULL,
		0xB9C24BEE3104F39BULL,
		0x57783D168809B7DDULL,
		0x1D4B40D9028ECD9CULL,
		0xABB01FAE0C0D2DE1ULL,
		0x8CCCCD7116787D3DULL,
		0x926D3869D9F17E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA93BC3F9D3893BB6ULL,
		0x83A71694FA03EE55ULL,
		0x9D4C7C4F9664205FULL,
		0xEAA3C2BF6133C8A3ULL,
		0x3D44993A28D72880ULL,
		0x71A79F1980C932F5ULL,
		0x2044AE92001B0FEEULL,
		0x5F55D460E07F4F6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x331372E9082B79E4ULL,
		0x2ADF1A2B5B4BB4FBULL,
		0x38AA64BBEC7F0CFEULL,
		0x024D53AC2DC8DA26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE556751683931E81ULL,
		0xF6340E2F0CA3F5EDULL,
		0x40C4360ADD6FB6B8ULL,
		0x36D5B733E6C442CAULL,
		0x283E8732A4F92ED4ULL,
		0x56BAA2B4793B4059ULL,
		0x9AA77C4D7E7FA9D1ULL,
		0x6C677ACA1D6C7D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD294967B2ED87BCEULL,
		0x9ECE7B9C92DE9D8EULL,
		0x646376F53D66F5A9ULL,
		0x4A81A5C4B37BCACEULL,
		0xF9481A541A8413BBULL,
		0xB541D167EA4995C9ULL,
		0xC66B061CF495616BULL,
		0x8B585D08D92BE27DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B5607A3E21CA7ABULL,
		0x4F54A3EFB1A4A9A0ULL,
		0x5D5A4A4A18CF8025ULL,
		0x54927C1F54DF7075ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45A5476E864ADAA4ULL,
		0xC92612A89394B355ULL,
		0x305765237025A7A7ULL,
		0x519924BCF70E01EFULL,
		0x5AB8E8C5ACACF732ULL,
		0xDAB4219430EB0AEAULL,
		0xA560A1E8947ADD65ULL,
		0x77F63D807E6EC431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D636824736EA7A4ULL,
		0xE52469271F4E941BULL,
		0x5DCE12CE7347E577ULL,
		0xDF39DB4C003D5DCFULL,
		0x6354B6B76DDB1C2BULL,
		0xC420711EE75B7B02ULL,
		0x7D8FB55C0D80BFF0ULL,
		0x3CBD0883309F44C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1214D676602B73AULL,
		0x3DEDDAEA5F957BA8ULL,
		0xBB8C6F3105FE2191ULL,
		0x3CDD270A839D8E9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27F435ED4C779106ULL,
		0x4B4768D142872FEBULL,
		0x36A41EBCDACB6FEFULL,
		0x62739B7C79BE9947ULL,
		0xA5A526BACE1161A4ULL,
		0x52B2DB0A6805CAE9ULL,
		0xB23717DEBDA9D88DULL,
		0xF379C1CC6FADF330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10CBCFC8D6E802D7ULL,
		0xB7971D41198A5EB3ULL,
		0x2D3129BB13AE3286ULL,
		0xB44C2B76285E56D4ULL,
		0xD05A7E3A2D5D0F17ULL,
		0xF7D4874C0436E8B2ULL,
		0x291E8C312A34E282ULL,
		0xDC211DCAB188B5F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC03D693C5053CF8FULL,
		0x10B0B9D2F9B2655BULL,
		0x6317B0C5AA79C2F2ULL,
		0x254FC8488AE75923ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x937F28517552EA97ULL,
		0xD382D145501A3EBDULL,
		0x0B326FA6D9B7C8FBULL,
		0xD92B26C83F17C4CFULL,
		0x29771661CAC3487EULL,
		0x679CE7075FFC6471ULL,
		0xBBEAE20DCD199CDDULL,
		0x48682EDCDE7A7862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0873354292483E95ULL,
		0xC96E56727691DA0DULL,
		0xC7DD8FF035B53681ULL,
		0xE357B580E28C8E70ULL,
		0x9603DD6D4518A890ULL,
		0xB022CD287699141AULL,
		0xE34E1851CB16CC0BULL,
		0x25B0DBC810C0DE81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E26675ABA5E6A14ULL,
		0x463451E97E46518AULL,
		0x6A9AD19EF06D919BULL,
		0x1D09C65DE6180DBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}