#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x602A90007F33F596ULL,
		0x26FDBDECB21DE51FULL,
		0x5D96BA404E4900C5ULL,
		0xCEFD41289DFAC1BEULL,
		0x1DD6D560A04D0941ULL,
		0x35FD1DB420F28F6AULL,
		0xBB8FEEA0E84B9875ULL,
		0x2A9C47B4BEDF5FCEULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xC0552000FE67EB2CULL,
		0x4DFB7BD9643BCA3EULL,
		0xBB2D74809C92018AULL,
		0x9DFA82513BF5837CULL,
		0x3BADAAC1409A1283ULL,
		0x6BFA3B6841E51ED4ULL,
		0x771FDD41D09730EAULL,
		0x55388F697DBEBF9DULL
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
		0xC4D2C14915D19E55ULL,
		0xBA2CB41A625F7303ULL,
		0xCF81CDBD7697DF8DULL,
		0xAE40D07D5ACE9797ULL,
		0x46EC41C5966F7190ULL,
		0x070E7CC44934A679ULL,
		0x0576E608E4927962ULL,
		0x33D5767829ACED09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A582922BA33CAAULL,
		0x74596834C4BEE607ULL,
		0x9F039B7AED2FBF1BULL,
		0x5C81A0FAB59D2F2FULL,
		0x8DD8838B2CDEE321ULL,
		0x0E1CF98892694CF2ULL,
		0x0AEDCC11C924F2C4ULL,
		0x67AAECF05359DA12ULL
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
		0x9C8A9F5EECF3A42DULL,
		0xDE34394CEE353F44ULL,
		0x6344DB75CBF4BF08ULL,
		0xCB1BFCD578B0AC52ULL,
		0x5950CF0C6D1B808BULL,
		0x66E411FF0A56F02BULL,
		0x1A38128EBA452AFEULL,
		0x22AD97854115BB91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39153EBDD9E7485AULL,
		0xBC687299DC6A7E89ULL,
		0xC689B6EB97E97E11ULL,
		0x9637F9AAF16158A4ULL,
		0xB2A19E18DA370117ULL,
		0xCDC823FE14ADE056ULL,
		0x3470251D748A55FCULL,
		0x455B2F0A822B7722ULL
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
		0xA71CF4D4BE7B4E86ULL,
		0x99C8745655AE7D53ULL,
		0x448033FF5977D783ULL,
		0xC23F0CF964197F95ULL,
		0x5738FD75F422E564ULL,
		0x45F6C6F0B70566F0ULL,
		0xB817618C30C2D5D4ULL,
		0x13CCD1A65BA0E983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E39E9A97CF69D0CULL,
		0x3390E8ACAB5CFAA7ULL,
		0x890067FEB2EFAF07ULL,
		0x847E19F2C832FF2AULL,
		0xAE71FAEBE845CAC9ULL,
		0x8BED8DE16E0ACDE0ULL,
		0x702EC3186185ABA8ULL,
		0x2799A34CB741D307ULL
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
		0x1C61EC6F0F3F6D90ULL,
		0x3F4FDA060028798AULL,
		0x4159C919189FC295ULL,
		0xC8F890AFE4863BE3ULL,
		0x2406377408928289ULL,
		0xD7ABA10840F0BF30ULL,
		0xD3DC29791E4FBE8DULL,
		0x07DBFBC9C7E13595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C3D8DE1E7EDB20ULL,
		0x7E9FB40C0050F314ULL,
		0x82B39232313F852AULL,
		0x91F1215FC90C77C6ULL,
		0x480C6EE811250513ULL,
		0xAF57421081E17E60ULL,
		0xA7B852F23C9F7D1BULL,
		0x0FB7F7938FC26B2BULL
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
		0x68911935F0EEDD88ULL,
		0x371EF4EBE7DE439EULL,
		0xA3579B06F9F8A73DULL,
		0x3F8143640DAD7D78ULL,
		0x853A0B871029FA39ULL,
		0x65526BCE46E4BF2CULL,
		0xD6B99086E74C6F19ULL,
		0x3F50FD5A17180E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD122326BE1DDBB10ULL,
		0x6E3DE9D7CFBC873CULL,
		0x46AF360DF3F14E7AULL,
		0x7F0286C81B5AFAF1ULL,
		0x0A74170E2053F472ULL,
		0xCAA4D79C8DC97E59ULL,
		0xAD73210DCE98DE32ULL,
		0x7EA1FAB42E301CD7ULL
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
		0xDFD7DAA95D6321F2ULL,
		0x14070B1D31E8E3E5ULL,
		0xE3FEC8425B663193ULL,
		0x4E1F4B513C9AE5CAULL,
		0x5DF75D729B554B4EULL,
		0x229903E0F267A032ULL,
		0x2921DFB0BB0934E7ULL,
		0x245E9DB0B148110AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFAFB552BAC643E4ULL,
		0x280E163A63D1C7CBULL,
		0xC7FD9084B6CC6326ULL,
		0x9C3E96A27935CB95ULL,
		0xBBEEBAE536AA969CULL,
		0x453207C1E4CF4064ULL,
		0x5243BF61761269CEULL,
		0x48BD3B6162902214ULL
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
		0x4C5FD46C4A042E7EULL,
		0xA95C498C6E934852ULL,
		0xE9FDDAF1C20931A1ULL,
		0x67CBDF29155A7D82ULL,
		0xF8196E10193D5E23ULL,
		0x8A7B1E56B47E06C1ULL,
		0x26F48C0DA8FA904FULL,
		0x2A39A9CB8333B040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BFA8D894085CFCULL,
		0x52B89318DD2690A4ULL,
		0xD3FBB5E384126343ULL,
		0xCF97BE522AB4FB05ULL,
		0xF032DC20327ABC46ULL,
		0x14F63CAD68FC0D83ULL,
		0x4DE9181B51F5209FULL,
		0x5473539706676080ULL
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
		0x42DF19E19EF46343ULL,
		0x30C07686E0C72F88ULL,
		0x3F71FB8CA1DEB6A1ULL,
		0x42114AD3B0A11799ULL,
		0xC26348E2C16768E0ULL,
		0x2562BF8D961D627FULL,
		0x680A2AD1879D9CE0ULL,
		0x3749135D1069FA3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85BE33C33DE8C686ULL,
		0x6180ED0DC18E5F10ULL,
		0x7EE3F71943BD6D42ULL,
		0x842295A761422F32ULL,
		0x84C691C582CED1C0ULL,
		0x4AC57F1B2C3AC4FFULL,
		0xD01455A30F3B39C0ULL,
		0x6E9226BA20D3F478ULL
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
		0x2947BC08A3999E9EULL,
		0xD6FD19ABF15F04F9ULL,
		0x8081D4B844E0CDC2ULL,
		0x87020042DCF74BB1ULL,
		0x295CF86EED75506BULL,
		0x03B4332AEBDEB11AULL,
		0xBA077ADD43431B58ULL,
		0x1935624C0A5285A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528F781147333D3CULL,
		0xADFA3357E2BE09F2ULL,
		0x0103A97089C19B85ULL,
		0x0E040085B9EE9763ULL,
		0x52B9F0DDDAEAA0D7ULL,
		0x07686655D7BD6234ULL,
		0x740EF5BA868636B0ULL,
		0x326AC49814A50B4FULL
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
		0x50E1F60C75B16AC7ULL,
		0xAFEB24835866E4CFULL,
		0xDEE01891E5E5A3A0ULL,
		0xE5DB15D41D05E74CULL,
		0x445197D97EEC3373ULL,
		0x379357BE7E191473ULL,
		0x38A7806F2CC4D417ULL,
		0x2692DACD638DE6A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1C3EC18EB62D58EULL,
		0x5FD64906B0CDC99EULL,
		0xBDC03123CBCB4741ULL,
		0xCBB62BA83A0BCE99ULL,
		0x88A32FB2FDD866E7ULL,
		0x6F26AF7CFC3228E6ULL,
		0x714F00DE5989A82EULL,
		0x4D25B59AC71BCD4EULL
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
		0x642693F2307E2B3EULL,
		0x6A2ECD071C2892B2ULL,
		0x6C8FBB1DC21614F0ULL,
		0x5D683E344D8991DDULL,
		0x662A4E0BC7BDB48AULL,
		0xABA732C6FE16C71BULL,
		0xE3AB415B8422EE7AULL,
		0x1609FE476953ABCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84D27E460FC567CULL,
		0xD45D9A0E38512564ULL,
		0xD91F763B842C29E0ULL,
		0xBAD07C689B1323BAULL,
		0xCC549C178F7B6914ULL,
		0x574E658DFC2D8E36ULL,
		0xC75682B70845DCF5ULL,
		0x2C13FC8ED2A7579FULL
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
		0x305CF9540BC98430ULL,
		0x124CB7927A2226F1ULL,
		0x5826D48E5FA66523ULL,
		0x1718D204298CD4C5ULL,
		0x35ADFA758CBFECD7ULL,
		0x95282D64F9E3B991ULL,
		0xB47361101A179B02ULL,
		0x06669D43FBF95C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B9F2A817930860ULL,
		0x24996F24F4444DE2ULL,
		0xB04DA91CBF4CCA46ULL,
		0x2E31A4085319A98AULL,
		0x6B5BF4EB197FD9AEULL,
		0x2A505AC9F3C77322ULL,
		0x68E6C220342F3605ULL,
		0x0CCD3A87F7F2B805ULL
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
		0xCBA2FAA9E0FBB649ULL,
		0xF53FBBACF55C017AULL,
		0x8E12375DEAA1B3E0ULL,
		0x98F099F72761E9EFULL,
		0x7C4338C0D0EC57A1ULL,
		0xD34654BCF09FA120ULL,
		0x3C541906A657734BULL,
		0x0C8B4514867D0F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9745F553C1F76C92ULL,
		0xEA7F7759EAB802F5ULL,
		0x1C246EBBD54367C1ULL,
		0x31E133EE4EC3D3DFULL,
		0xF8867181A1D8AF43ULL,
		0xA68CA979E13F4240ULL,
		0x78A8320D4CAEE697ULL,
		0x19168A290CFA1E10ULL
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
		0x3823BB113DDADDF1ULL,
		0xC80AAD2BBEBA7914ULL,
		0x25AB025A554CB6EBULL,
		0x3195EAF2294F41ACULL,
		0x0C206070BE05CBFFULL,
		0xA8FD6E25D2E6D8B1ULL,
		0xEE95C7BEADB22A76ULL,
		0x04A4766F2BBC1B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x704776227BB5BBE2ULL,
		0x90155A577D74F228ULL,
		0x4B5604B4AA996DD7ULL,
		0x632BD5E4529E8358ULL,
		0x1840C0E17C0B97FEULL,
		0x51FADC4BA5CDB162ULL,
		0xDD2B8F7D5B6454EDULL,
		0x0948ECDE577836D1ULL
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
		0x8225A4B88A94D549ULL,
		0x60A674DB8CF70472ULL,
		0x2C853D232FDA2280ULL,
		0x3AA048EDC3CFE8D9ULL,
		0xC6097939BFD0D901ULL,
		0xD4A1298C24BC696AULL,
		0x4DAC1C6D6B2C0DF3ULL,
		0x1997CA06CEDC0010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044B49711529AA92ULL,
		0xC14CE9B719EE08E5ULL,
		0x590A7A465FB44500ULL,
		0x754091DB879FD1B2ULL,
		0x8C12F2737FA1B202ULL,
		0xA94253184978D2D5ULL,
		0x9B5838DAD6581BE7ULL,
		0x332F940D9DB80020ULL
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
		0x6097097F91537FA1ULL,
		0x0CDD050151A44420ULL,
		0xFE9AC4E600811488ULL,
		0x668BC8CBA72E091EULL,
		0x9DE558BB5F2E40E9ULL,
		0xCE0C68E92539B35AULL,
		0x26CDECEEA5B014DDULL,
		0x3AD0A229FA65ADA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC12E12FF22A6FF42ULL,
		0x19BA0A02A3488840ULL,
		0xFD3589CC01022910ULL,
		0xCD1791974E5C123DULL,
		0x3BCAB176BE5C81D2ULL,
		0x9C18D1D24A7366B5ULL,
		0x4D9BD9DD4B6029BBULL,
		0x75A14453F4CB5B50ULL
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
		0xD4DEC587535051F1ULL,
		0x03A3EB2E7984CA1AULL,
		0xA8240BAAFDED50C4ULL,
		0x0B2BCD3AA97E344AULL,
		0xBB50669585DA333DULL,
		0xC3F3AA69A2F35D81ULL,
		0x536F0AF9ACAD9CC1ULL,
		0x3CB2163EB39D4E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BD8B0EA6A0A3E2ULL,
		0x0747D65CF3099435ULL,
		0x50481755FBDAA188ULL,
		0x16579A7552FC6895ULL,
		0x76A0CD2B0BB4667AULL,
		0x87E754D345E6BB03ULL,
		0xA6DE15F3595B3983ULL,
		0x79642C7D673A9D34ULL
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
		0x1534D780C67DF3DAULL,
		0x16C39E729C93E133ULL,
		0x4ADA92EE8AC09479ULL,
		0x16AE5383531BBCB0ULL,
		0x2CF26075A1C6B955ULL,
		0x84A60A1A9A9922DDULL,
		0x43383EF5385B9DEDULL,
		0x1567CC7388EF6F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A69AF018CFBE7B4ULL,
		0x2D873CE53927C266ULL,
		0x95B525DD158128F2ULL,
		0x2D5CA706A6377960ULL,
		0x59E4C0EB438D72AAULL,
		0x094C1435353245BAULL,
		0x86707DEA70B73BDBULL,
		0x2ACF98E711DEDE4CULL
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
		0xDA6F02CE7B87647FULL,
		0x5F1C643C76CF557EULL,
		0xC00FEBD960D6C941ULL,
		0x7CCD7D90C6119E58ULL,
		0x4732CB9A4E973270ULL,
		0x519ADD4602D17AB6ULL,
		0x42A8CDBE4CF64E85ULL,
		0x0872D82A0FD9EAE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4DE059CF70EC8FEULL,
		0xBE38C878ED9EAAFDULL,
		0x801FD7B2C1AD9282ULL,
		0xF99AFB218C233CB1ULL,
		0x8E6597349D2E64E0ULL,
		0xA335BA8C05A2F56CULL,
		0x85519B7C99EC9D0AULL,
		0x10E5B0541FB3D5C0ULL
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
		0xCBCB6F2D6C70999DULL,
		0x8398A0527B9B0A4EULL,
		0xCA5FCEF39482D954ULL,
		0xA1E23572DAC1D1E0ULL,
		0x48B86B87A06A6155ULL,
		0x734F22CB23053466ULL,
		0x779C87BABB6DA3E1ULL,
		0x2DE43293854AE51FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9796DE5AD8E1333AULL,
		0x073140A4F736149DULL,
		0x94BF9DE72905B2A9ULL,
		0x43C46AE5B583A3C1ULL,
		0x9170D70F40D4C2ABULL,
		0xE69E4596460A68CCULL,
		0xEF390F7576DB47C2ULL,
		0x5BC865270A95CA3EULL
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
		0x09C7D57FD1DD1063ULL,
		0xE83ABDF47BCDDF89ULL,
		0xFAD82450B5381110ULL,
		0x1F6E5EB85393536EULL,
		0xC3CCC443FDC2A9E8ULL,
		0xD3C586FE5A34356CULL,
		0x7F71ABB091BFF43AULL,
		0x187B14FB2F140C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x138FAAFFA3BA20C6ULL,
		0xD0757BE8F79BBF12ULL,
		0xF5B048A16A702221ULL,
		0x3EDCBD70A726A6DDULL,
		0x87998887FB8553D0ULL,
		0xA78B0DFCB4686AD9ULL,
		0xFEE35761237FE875ULL,
		0x30F629F65E281924ULL
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
		0x7E3676A6D0E04A3EULL,
		0x19B5779D89124FC8ULL,
		0x6709766214822C48ULL,
		0x44A27CA34404F22BULL,
		0x2A49BD3F507F444AULL,
		0xE2388DDEAED12C16ULL,
		0x65EF72203D1930F2ULL,
		0x0D40B4AE21925292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6CED4DA1C0947CULL,
		0x336AEF3B12249F90ULL,
		0xCE12ECC429045890ULL,
		0x8944F9468809E456ULL,
		0x54937A7EA0FE8894ULL,
		0xC4711BBD5DA2582CULL,
		0xCBDEE4407A3261E5ULL,
		0x1A81695C4324A524ULL
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
		0xFD3A0CB3093C6C3BULL,
		0xDDAF44E54B35CAD8ULL,
		0x723C8F2D9BB71292ULL,
		0x4E8684B980370C91ULL,
		0x7F6F8D444548EF91ULL,
		0x412245F1031D5A18ULL,
		0x66AA7DFD0D38C390ULL,
		0x1B19790F22F70EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA7419661278D876ULL,
		0xBB5E89CA966B95B1ULL,
		0xE4791E5B376E2525ULL,
		0x9D0D0973006E1922ULL,
		0xFEDF1A888A91DF22ULL,
		0x82448BE2063AB430ULL,
		0xCD54FBFA1A718720ULL,
		0x3632F21E45EE1DC6ULL
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
		0xC7DC84AC4C656A96ULL,
		0xB43A5875AEDBBC0DULL,
		0x5FDF471454B052AFULL,
		0x7E18BD8B2BD8C73AULL,
		0x55D2AE9FF1BA9C70ULL,
		0x463D0C278C110349ULL,
		0x2BAC1107E35853F0ULL,
		0x1F2F508BA365FDAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB9095898CAD52CULL,
		0x6874B0EB5DB7781BULL,
		0xBFBE8E28A960A55FULL,
		0xFC317B1657B18E74ULL,
		0xABA55D3FE37538E0ULL,
		0x8C7A184F18220692ULL,
		0x5758220FC6B0A7E0ULL,
		0x3E5EA11746CBFB5EULL
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
		0x9B95DF281C80B84BULL,
		0x6EC8B703631CE80BULL,
		0x629F290CB7D81A36ULL,
		0x56AEB74F69C9D2E8ULL,
		0x28D51F4F7F519FE2ULL,
		0x0969D6C1A13D5EB0ULL,
		0x9E68932969ACC97EULL,
		0x251EDC31CC53D260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x372BBE5039017096ULL,
		0xDD916E06C639D017ULL,
		0xC53E52196FB0346CULL,
		0xAD5D6E9ED393A5D0ULL,
		0x51AA3E9EFEA33FC4ULL,
		0x12D3AD83427ABD60ULL,
		0x3CD12652D35992FCULL,
		0x4A3DB86398A7A4C1ULL
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
		0x6893E0D42CA6767DULL,
		0xD55ADD074D814F41ULL,
		0x30E476F77BC86032ULL,
		0x2D4C70DF0043DC57ULL,
		0xD1E2B714AF69C666ULL,
		0xF074755880948EE4ULL,
		0xD8A88362FCB8C7F7ULL,
		0x1F6A86DEF5CF5410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD127C1A8594CECFAULL,
		0xAAB5BA0E9B029E82ULL,
		0x61C8EDEEF790C065ULL,
		0x5A98E1BE0087B8AEULL,
		0xA3C56E295ED38CCCULL,
		0xE0E8EAB101291DC9ULL,
		0xB15106C5F9718FEFULL,
		0x3ED50DBDEB9EA821ULL
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
		0x1D7D9C89DC46C222ULL,
		0xF6A38D1F69943176ULL,
		0x124CFA9019A12C54ULL,
		0x02C723FB58BF05B9ULL,
		0x5486972BD83E11F1ULL,
		0x6555D9C475A532A6ULL,
		0xD65A2F02C96DC5D4ULL,
		0x398649F4CF64176BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFB3913B88D8444ULL,
		0xED471A3ED32862ECULL,
		0x2499F520334258A9ULL,
		0x058E47F6B17E0B72ULL,
		0xA90D2E57B07C23E2ULL,
		0xCAABB388EB4A654CULL,
		0xACB45E0592DB8BA8ULL,
		0x730C93E99EC82ED7ULL
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
		0xBACB4A16EDE2963BULL,
		0xF06EE8F893BF6DCBULL,
		0xEC4011C2085DB46FULL,
		0xA24FC98942B25E17ULL,
		0x78AFD08DE6DA1F81ULL,
		0x81B489F5A228FAC9ULL,
		0xFE5D2575E949AF78ULL,
		0x209E4EBA30B33FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7596942DDBC52C76ULL,
		0xE0DDD1F1277EDB97ULL,
		0xD880238410BB68DFULL,
		0x449F93128564BC2FULL,
		0xF15FA11BCDB43F03ULL,
		0x036913EB4451F592ULL,
		0xFCBA4AEBD2935EF1ULL,
		0x413C9D7461667F4FULL
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
		0x16BCE54BEAB7055BULL,
		0x319C0A8F927C5AB4ULL,
		0x54F04081792EB20DULL,
		0x20F8DF384674C697ULL,
		0xE5D048CA6CEB4D7AULL,
		0x6B974E062DDE9467ULL,
		0xD73C6820A23A2512ULL,
		0x0A1E402F9799FDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D79CA97D56E0AB6ULL,
		0x6338151F24F8B568ULL,
		0xA9E08102F25D641AULL,
		0x41F1BE708CE98D2EULL,
		0xCBA09194D9D69AF4ULL,
		0xD72E9C0C5BBD28CFULL,
		0xAE78D04144744A24ULL,
		0x143C805F2F33FBAFULL
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
		0x8CB16C8359F1F7A7ULL,
		0x2DDC265FD0912250ULL,
		0x0F79671787FBDF88ULL,
		0x8757D3A796E41970ULL,
		0x7DAA00AF339F8A50ULL,
		0x9D2CDF25D37F793CULL,
		0x23A899754918B8A7ULL,
		0x2B2789959760CE51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1962D906B3E3EF4EULL,
		0x5BB84CBFA12244A1ULL,
		0x1EF2CE2F0FF7BF10ULL,
		0x0EAFA74F2DC832E0ULL,
		0xFB54015E673F14A1ULL,
		0x3A59BE4BA6FEF278ULL,
		0x475132EA9231714FULL,
		0x564F132B2EC19CA2ULL
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
		0x61466EFEBC01FFB3ULL,
		0x6033D48F21036899ULL,
		0xFAFAF81500B5A906ULL,
		0x0461C1A14F30E02EULL,
		0x4464E563EA4F6816ULL,
		0x825B9195D8962872ULL,
		0x80685158B56D496AULL,
		0x0BA3B76E3FC185A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC28CDDFD7803FF66ULL,
		0xC067A91E4206D132ULL,
		0xF5F5F02A016B520CULL,
		0x08C383429E61C05DULL,
		0x88C9CAC7D49ED02CULL,
		0x04B7232BB12C50E4ULL,
		0x00D0A2B16ADA92D5ULL,
		0x17476EDC7F830B53ULL
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
		0xC8676781DDF02181ULL,
		0x5691DB929D7BF9FBULL,
		0xAB916DD88CB798A7ULL,
		0x9152FE90334D8CAFULL,
		0x4BBB91E9473C96A0ULL,
		0xC27A1B93009FD622ULL,
		0xF46DBB3CAA9FFB42ULL,
		0x32C83B1DF9EF1656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90CECF03BBE04302ULL,
		0xAD23B7253AF7F3F7ULL,
		0x5722DBB1196F314EULL,
		0x22A5FD20669B195FULL,
		0x977723D28E792D41ULL,
		0x84F43726013FAC44ULL,
		0xE8DB7679553FF685ULL,
		0x6590763BF3DE2CADULL
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
		0xDC70D38164878B8EULL,
		0xC656B8C5AB7E6855ULL,
		0x6B32DB3345EB2550ULL,
		0x4C33E13B0681EEC3ULL,
		0xD75807D3F4A58236ULL,
		0xC6951C7783381D0BULL,
		0x3D27C0730D0C1385ULL,
		0x10D269303B3E34ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E1A702C90F171CULL,
		0x8CAD718B56FCD0ABULL,
		0xD665B6668BD64AA1ULL,
		0x9867C2760D03DD86ULL,
		0xAEB00FA7E94B046CULL,
		0x8D2A38EF06703A17ULL,
		0x7A4F80E61A18270BULL,
		0x21A4D260767C69D8ULL
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
		0x13DCC87B1FE3B565ULL,
		0x712F59B69E3EDF7BULL,
		0xAFCA7668075B42D4ULL,
		0xF2FD48FA0CB2C91EULL,
		0x85FE322F510A0F5AULL,
		0x8C23433F7ACC6BEEULL,
		0x03FB2DA81596C434ULL,
		0x34BE7773CEDE3529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27B990F63FC76ACAULL,
		0xE25EB36D3C7DBEF6ULL,
		0x5F94ECD00EB685A8ULL,
		0xE5FA91F41965923DULL,
		0x0BFC645EA2141EB5ULL,
		0x1846867EF598D7DDULL,
		0x07F65B502B2D8869ULL,
		0x697CEEE79DBC6A52ULL
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
		0xC6F68623ADEC4659ULL,
		0xCD8208C43FDFACE7ULL,
		0x5D2F957838BD7F0AULL,
		0xFEC9CCD8A13D3781ULL,
		0x6D6E98326B3E5FD4ULL,
		0x6B257D9DCC8A7CF7ULL,
		0x8A7D15C94E4562EDULL,
		0x31A48B4BE7C35C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DED0C475BD88CB2ULL,
		0x9B0411887FBF59CFULL,
		0xBA5F2AF0717AFE15ULL,
		0xFD9399B1427A6F02ULL,
		0xDADD3064D67CBFA9ULL,
		0xD64AFB3B9914F9EEULL,
		0x14FA2B929C8AC5DAULL,
		0x63491697CF86B829ULL
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
		0x3F57D5EC75C64DA3ULL,
		0x86C0B85BC499405EULL,
		0xF6196EC499CBF62AULL,
		0x4FDD3462164C95D3ULL,
		0xD7A832647145D6EBULL,
		0xDF2A7B725316DAB6ULL,
		0xD805A5006330B0EBULL,
		0x13E0B3C400EA815DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EAFABD8EB8C9B46ULL,
		0x0D8170B7893280BCULL,
		0xEC32DD893397EC55ULL,
		0x9FBA68C42C992BA7ULL,
		0xAF5064C8E28BADD6ULL,
		0xBE54F6E4A62DB56DULL,
		0xB00B4A00C66161D7ULL,
		0x27C1678801D502BBULL
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
		0xD1EC09259F2CF94DULL,
		0xB1BBEE5ECC5AA8D9ULL,
		0x6F9FB700203E1138ULL,
		0x124F446F4BCECA3DULL,
		0x1292DEE34B4C7E09ULL,
		0xA2FA16ABF02569AAULL,
		0x560418E76674B0E9ULL,
		0x0C5EC8DA4AE595F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D8124B3E59F29AULL,
		0x6377DCBD98B551B3ULL,
		0xDF3F6E00407C2271ULL,
		0x249E88DE979D947AULL,
		0x2525BDC69698FC12ULL,
		0x45F42D57E04AD354ULL,
		0xAC0831CECCE961D3ULL,
		0x18BD91B495CB2BF2ULL
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
		0x51A88C81BDE6FAB1ULL,
		0x827D13F8D58F1D25ULL,
		0x0248A92FE940EF5AULL,
		0xAEE4D902914A8571ULL,
		0x48A4027E95382A3BULL,
		0x3A7115D2ADD913EDULL,
		0x2D8783FDF3457EB0ULL,
		0x0D2814BA7E18542DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35119037BCDF562ULL,
		0x04FA27F1AB1E3A4AULL,
		0x0491525FD281DEB5ULL,
		0x5DC9B20522950AE2ULL,
		0x914804FD2A705477ULL,
		0x74E22BA55BB227DAULL,
		0x5B0F07FBE68AFD60ULL,
		0x1A502974FC30A85AULL
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
		0x1F65526363C492D1ULL,
		0x01F1437C38B7BDC6ULL,
		0x3B61BD745BE5D0E6ULL,
		0x28252CA9EC5CFE64ULL,
		0x39CA058A6DD16695ULL,
		0x1B856E24BEAFC0A3ULL,
		0xFED6CD36D46D25C9ULL,
		0x2A38626D8F085CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECAA4C6C78925A2ULL,
		0x03E286F8716F7B8CULL,
		0x76C37AE8B7CBA1CCULL,
		0x504A5953D8B9FCC8ULL,
		0x73940B14DBA2CD2AULL,
		0x370ADC497D5F8146ULL,
		0xFDAD9A6DA8DA4B92ULL,
		0x5470C4DB1E10B97DULL
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
		0xBF4CCB24FBACCF26ULL,
		0x45558515E5FCF0E4ULL,
		0x6FD89B0CDF7C0741ULL,
		0xF03FC80AF269F07DULL,
		0x6FFC90A2A150B26CULL,
		0xC5F1ED631208204DULL,
		0x213A8DBE34FC88B9ULL,
		0x007A2188612E5C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E999649F7599E4CULL,
		0x8AAB0A2BCBF9E1C9ULL,
		0xDFB13619BEF80E82ULL,
		0xE07F9015E4D3E0FAULL,
		0xDFF9214542A164D9ULL,
		0x8BE3DAC62410409AULL,
		0x42751B7C69F91173ULL,
		0x00F44310C25CB938ULL
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
		0xDEFDCCF828DD2B08ULL,
		0x51B3FAE5B405EB78ULL,
		0x96A94A065BDE85F3ULL,
		0xE938599D06C072CEULL,
		0x8359679F56D2D31BULL,
		0x5B4D8ADA69F62C94ULL,
		0xA730A6E91D928F6EULL,
		0x1154F1C7EFE0E9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDFB99F051BA5610ULL,
		0xA367F5CB680BD6F1ULL,
		0x2D52940CB7BD0BE6ULL,
		0xD270B33A0D80E59DULL,
		0x06B2CF3EADA5A637ULL,
		0xB69B15B4D3EC5929ULL,
		0x4E614DD23B251EDCULL,
		0x22A9E38FDFC1D369ULL
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
		0x84BAE8C9B3BA3C33ULL,
		0xBB9C16CB927BCF93ULL,
		0x69CFE4DE0BE662F2ULL,
		0xD460231F6B2998DBULL,
		0xE93EBD2CF715BAC3ULL,
		0x3DAFE9E7CCB22DF9ULL,
		0xBB92FBD2FB81C28BULL,
		0x2EC44E40DEB8619CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0975D19367747866ULL,
		0x77382D9724F79F27ULL,
		0xD39FC9BC17CCC5E5ULL,
		0xA8C0463ED65331B6ULL,
		0xD27D7A59EE2B7587ULL,
		0x7B5FD3CF99645BF3ULL,
		0x7725F7A5F7038516ULL,
		0x5D889C81BD70C339ULL
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
		0x5D85782AAB956D35ULL,
		0x5FAB338C18DC76A1ULL,
		0x8758BB5524ECA1F1ULL,
		0x6AE6FFE9A773AF75ULL,
		0x1A2FC707C46446DEULL,
		0x9C2BE8452B6AFA64ULL,
		0x9537012BD3DAFF46ULL,
		0x36C1B4834D785B0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0AF055572ADA6AULL,
		0xBF56671831B8ED42ULL,
		0x0EB176AA49D943E2ULL,
		0xD5CDFFD34EE75EEBULL,
		0x345F8E0F88C88DBCULL,
		0x3857D08A56D5F4C8ULL,
		0x2A6E0257A7B5FE8DULL,
		0x6D8369069AF0B617ULL
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
		0x5D6B1F567FF77293ULL,
		0xE6E0314B76D2F7CAULL,
		0x4C099EBF0649165DULL,
		0x1689280DB33F86A5ULL,
		0x3F99612561D9ACD2ULL,
		0x58598B44281AE5B9ULL,
		0x164FD1AF7FD69AA4ULL,
		0x1B9640A8277B182DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD63EACFFEEE526ULL,
		0xCDC06296EDA5EF94ULL,
		0x98133D7E0C922CBBULL,
		0x2D12501B667F0D4AULL,
		0x7F32C24AC3B359A4ULL,
		0xB0B316885035CB72ULL,
		0x2C9FA35EFFAD3548ULL,
		0x372C81504EF6305AULL
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
		0xF7CBE4746BF428CCULL,
		0xDBE57026DF856DD7ULL,
		0x3FCD235C76BBCB56ULL,
		0x366156BECDDB661EULL,
		0xF3C109872B559DF0ULL,
		0xF0D8CAE1C0F9F1EDULL,
		0x723C4874056FB694ULL,
		0x2E65E72863CC50B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF97C8E8D7E85198ULL,
		0xB7CAE04DBF0ADBAFULL,
		0x7F9A46B8ED7796ADULL,
		0x6CC2AD7D9BB6CC3CULL,
		0xE782130E56AB3BE0ULL,
		0xE1B195C381F3E3DBULL,
		0xE47890E80ADF6D29ULL,
		0x5CCBCE50C798A16EULL
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
		0x5CF29C5788A3CC17ULL,
		0xA23B036BF0C35A4CULL,
		0x7EE61D3F26D08DEBULL,
		0xA5A5F29C063FED5DULL,
		0xB21219DE05C8EBC5ULL,
		0x78682D44AE4A8A7BULL,
		0x2808E00839DDA3A8ULL,
		0x1F62345E24EE213DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9E538AF1147982EULL,
		0x447606D7E186B498ULL,
		0xFDCC3A7E4DA11BD7ULL,
		0x4B4BE5380C7FDABAULL,
		0x642433BC0B91D78BULL,
		0xF0D05A895C9514F7ULL,
		0x5011C01073BB4750ULL,
		0x3EC468BC49DC427AULL
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
		0x15B73F9529CD5D7FULL,
		0x04203C05B2B83781ULL,
		0x369F4BFC396BD1A6ULL,
		0xF6E6A98FFE192E3DULL,
		0xDD3CD29908D56377ULL,
		0x1F10079864907070ULL,
		0x8477EA4B75B923C2ULL,
		0x167B3060CDC7FB75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6E7F2A539ABAFEULL,
		0x0840780B65706F02ULL,
		0x6D3E97F872D7A34CULL,
		0xEDCD531FFC325C7AULL,
		0xBA79A53211AAC6EFULL,
		0x3E200F30C920E0E1ULL,
		0x08EFD496EB724784ULL,
		0x2CF660C19B8FF6EBULL
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
		0xB6F5770079383E18ULL,
		0x194A337BF0381B15ULL,
		0x957997A52407CE88ULL,
		0x9DBE9C76B0C9CCC7ULL,
		0x90D6F2B1F3403416ULL,
		0xAA860134804E1C75ULL,
		0xCB1168C0C0689C64ULL,
		0x318F80F26D78922BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DEAEE00F2707C30ULL,
		0x329466F7E070362BULL,
		0x2AF32F4A480F9D10ULL,
		0x3B7D38ED6193998FULL,
		0x21ADE563E680682DULL,
		0x550C0269009C38EBULL,
		0x9622D18180D138C9ULL,
		0x631F01E4DAF12457ULL
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
		0xB32066BD5921124DULL,
		0x9210908A850DE686ULL,
		0x13EBA3E5290B1741ULL,
		0xFA66BC91080A523EULL,
		0x5F8105DDCC99B67AULL,
		0x592F754307499E5CULL,
		0xD3E0404647499151ULL,
		0x1AF88415ED344682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6640CD7AB242249AULL,
		0x242121150A1BCD0DULL,
		0x27D747CA52162E83ULL,
		0xF4CD79221014A47CULL,
		0xBF020BBB99336CF5ULL,
		0xB25EEA860E933CB8ULL,
		0xA7C0808C8E9322A2ULL,
		0x35F1082BDA688D05ULL
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
		0xA254BEE4DB3F8D6DULL,
		0xEFC79110299BC961ULL,
		0x7110A1A307FD0659ULL,
		0xA9B3948F1C3FD3D3ULL,
		0xA480E0AF65BC21ADULL,
		0xF03518C7DFDDB5B5ULL,
		0x74EC9A0C315C2E08ULL,
		0x0A231479B31907BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44A97DC9B67F1ADAULL,
		0xDF8F2220533792C3ULL,
		0xE22143460FFA0CB3ULL,
		0x5367291E387FA7A6ULL,
		0x4901C15ECB78435BULL,
		0xE06A318FBFBB6B6BULL,
		0xE9D9341862B85C11ULL,
		0x144628F366320F7AULL
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
		0x3F6DAEC0254B9032ULL,
		0x0C80010ABF9CCAD5ULL,
		0x9EDFFAABBC2E72D6ULL,
		0x49E790B228E80622ULL,
		0xE220AEBB0F341125ULL,
		0x8A131414220F90A1ULL,
		0x9EFCFE628C305E4DULL,
		0x0DDA62C7A7288362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EDB5D804A972064ULL,
		0x190002157F3995AAULL,
		0x3DBFF557785CE5ACULL,
		0x93CF216451D00C45ULL,
		0xC4415D761E68224AULL,
		0x14262828441F2143ULL,
		0x3DF9FCC51860BC9BULL,
		0x1BB4C58F4E5106C5ULL
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
		0xD1C7512E2A77539BULL,
		0xDA0BA2A71624F10FULL,
		0x8E5AD60BCF05B506ULL,
		0xF95ABE1168472653ULL,
		0x0DFE0D1F5ADD58E2ULL,
		0xA56B6B8901CEFBBEULL,
		0x2280A2B087DA1E68ULL,
		0x11F9BB94FC599C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA38EA25C54EEA736ULL,
		0xB417454E2C49E21FULL,
		0x1CB5AC179E0B6A0DULL,
		0xF2B57C22D08E4CA7ULL,
		0x1BFC1A3EB5BAB1C5ULL,
		0x4AD6D712039DF77CULL,
		0x450145610FB43CD1ULL,
		0x23F37729F8B33868ULL
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
		0x1E3E9EB0A6BDCAB6ULL,
		0x2376BF2176176593ULL,
		0x57EF5E2F14A14C43ULL,
		0x94920C84166EB010ULL,
		0x089DB150486DCC0BULL,
		0xDCC40EDD029855C2ULL,
		0x9A10808F13E6D5CCULL,
		0x32EE7D6066A3FB20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C7D3D614D7B956CULL,
		0x46ED7E42EC2ECB26ULL,
		0xAFDEBC5E29429886ULL,
		0x292419082CDD6020ULL,
		0x113B62A090DB9817ULL,
		0xB9881DBA0530AB84ULL,
		0x3421011E27CDAB99ULL,
		0x65DCFAC0CD47F641ULL
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
		0x7DA28273006FC989ULL,
		0x1B8EBE15DC5C9E62ULL,
		0x83E90DF4264E76E5ULL,
		0xA81EA9EA3E935CCFULL,
		0x89A13AA4743DE021ULL,
		0xF4CAE096CF5C6080ULL,
		0xA49888B391F63C6AULL,
		0x01FA9D31A0A0F879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4504E600DF9312ULL,
		0x371D7C2BB8B93CC4ULL,
		0x07D21BE84C9CEDCAULL,
		0x503D53D47D26B99FULL,
		0x13427548E87BC043ULL,
		0xE995C12D9EB8C101ULL,
		0x4931116723EC78D5ULL,
		0x03F53A634141F0F3ULL
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
		0xA963A3A2F9B567B0ULL,
		0x433A46ECEE54E61FULL,
		0x7237DFDE6E9D1809ULL,
		0xC791C1F1E3C193C4ULL,
		0x21E47644D0AE41AFULL,
		0x05B340128FFBE051ULL,
		0xA7F8BACF7012DCA3ULL,
		0x358CFD95B811D6F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C74745F36ACF60ULL,
		0x86748DD9DCA9CC3FULL,
		0xE46FBFBCDD3A3012ULL,
		0x8F2383E3C7832788ULL,
		0x43C8EC89A15C835FULL,
		0x0B6680251FF7C0A2ULL,
		0x4FF1759EE025B946ULL,
		0x6B19FB2B7023ADEDULL
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
		0xB7D97C0E10D3DF49ULL,
		0xB233C64EE5496B7BULL,
		0xAAC43EBFEFC0AA06ULL,
		0x90DB7DD81587A6B5ULL,
		0x15DD50B803F23F78ULL,
		0xED84CA5B341ED30AULL,
		0x79EE599952431462ULL,
		0x35E5867B47C3F518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FB2F81C21A7BE92ULL,
		0x64678C9DCA92D6F7ULL,
		0x55887D7FDF81540DULL,
		0x21B6FBB02B0F4D6BULL,
		0x2BBAA17007E47EF1ULL,
		0xDB0994B6683DA614ULL,
		0xF3DCB332A48628C5ULL,
		0x6BCB0CF68F87EA30ULL
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
		0xBC836A903F11A2D4ULL,
		0x1762DC65653566A0ULL,
		0x4C217F6C9BD3C8DAULL,
		0xFF3943DFC26C37E9ULL,
		0x1BFCEBE2CF3C39E1ULL,
		0x8B1A1575C063AC11ULL,
		0x300DEA3A71E5E628ULL,
		0x19FD92A01083A4F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7906D5207E2345A8ULL,
		0x2EC5B8CACA6ACD41ULL,
		0x9842FED937A791B4ULL,
		0xFE7287BF84D86FD2ULL,
		0x37F9D7C59E7873C3ULL,
		0x16342AEB80C75822ULL,
		0x601BD474E3CBCC51ULL,
		0x33FB2540210749E6ULL
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
		0xA9A4D71AAF95A0E9ULL,
		0x9EBEAA3214FC84CEULL,
		0xA7C5616196AAB4CBULL,
		0xD6A7E7CC7B697AF1ULL,
		0x790D09A84CF83361ULL,
		0x8A9B01977561C92EULL,
		0x06895F16136D94DBULL,
		0x3DDE4B312685C1D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5349AE355F2B41D2ULL,
		0x3D7D546429F9099DULL,
		0x4F8AC2C32D556997ULL,
		0xAD4FCF98F6D2F5E3ULL,
		0xF21A135099F066C3ULL,
		0x1536032EEAC3925CULL,
		0x0D12BE2C26DB29B7ULL,
		0x7BBC96624D0B83ACULL
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
		0x73917A0A095D2D44ULL,
		0x489D9665C71790E2ULL,
		0x6A463246D0570AA1ULL,
		0xF2DA6A60B9D626AFULL,
		0xFAAD29198F34AEBFULL,
		0x458D0C5B9040E43AULL,
		0x0DF591C883386DD7ULL,
		0x3384F1823E8737EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE722F41412BA5A88ULL,
		0x913B2CCB8E2F21C4ULL,
		0xD48C648DA0AE1542ULL,
		0xE5B4D4C173AC4D5EULL,
		0xF55A52331E695D7FULL,
		0x8B1A18B72081C875ULL,
		0x1BEB23910670DBAEULL,
		0x6709E3047D0E6FD6ULL
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
		0x0AC123806EB13019ULL,
		0x2EE73B6048C14AC3ULL,
		0x827550EDD07A5ECFULL,
		0x19A5ED7A7DD9B5ABULL,
		0x98058363420C445DULL,
		0xE825D89D963E06BDULL,
		0xAC0229CBE6141AA0ULL,
		0x16BDA178466EB7C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15824700DD626032ULL,
		0x5DCE76C091829586ULL,
		0x04EAA1DBA0F4BD9EULL,
		0x334BDAF4FBB36B57ULL,
		0x300B06C6841888BAULL,
		0xD04BB13B2C7C0D7BULL,
		0x58045397CC283541ULL,
		0x2D7B42F08CDD6F8FULL
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
		0xCCC44CF168D9AC69ULL,
		0x7F99D117E8E9E591ULL,
		0xEEC2198A0B19E7EEULL,
		0x1AD14422B01CB246ULL,
		0xCF01C92A72251D0DULL,
		0x2F6E9843A5D6B3EBULL,
		0x7BBE6740F092CDD6ULL,
		0x366BFDEDD1D8D25EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998899E2D1B358D2ULL,
		0xFF33A22FD1D3CB23ULL,
		0xDD8433141633CFDCULL,
		0x35A288456039648DULL,
		0x9E039254E44A3A1AULL,
		0x5EDD30874BAD67D7ULL,
		0xF77CCE81E1259BACULL,
		0x6CD7FBDBA3B1A4BCULL
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
		0xF87A3F50CF47BC39ULL,
		0xC8A160C8A54DF3A7ULL,
		0x6F948FB0862C8F2EULL,
		0x97F98DD69EAD1D0EULL,
		0x40AF9D3892948F98ULL,
		0x820EA8E39A9BFB23ULL,
		0x356772D94DD91750ULL,
		0x164A51CCF4C7A0B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F47EA19E8F7872ULL,
		0x9142C1914A9BE74FULL,
		0xDF291F610C591E5DULL,
		0x2FF31BAD3D5A3A1CULL,
		0x815F3A7125291F31ULL,
		0x041D51C73537F646ULL,
		0x6ACEE5B29BB22EA1ULL,
		0x2C94A399E98F416EULL
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
		0x6146C370DA8342C9ULL,
		0xD70152C41778A4AEULL,
		0x907D21757DA830E7ULL,
		0x183B4E8258B2072DULL,
		0x718C387099C0845AULL,
		0x9466DC56EE4A5F4EULL,
		0x4311ED38716C7A90ULL,
		0x2B5CE32A6DBC432FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC28D86E1B5068592ULL,
		0xAE02A5882EF1495CULL,
		0x20FA42EAFB5061CFULL,
		0x30769D04B1640E5BULL,
		0xE31870E1338108B4ULL,
		0x28CDB8ADDC94BE9CULL,
		0x8623DA70E2D8F521ULL,
		0x56B9C654DB78865EULL
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
		0x2224E96907AE0DBAULL,
		0xE4E3E97A53884456ULL,
		0xB3AEFA68A9FB6C1AULL,
		0xD2A72BDDAB963D3FULL,
		0x08DC705425A9B7F9ULL,
		0x18D0E775C4CCB414ULL,
		0x27D6F344196F4C04ULL,
		0x0B43E5FF85E4DBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4449D2D20F5C1B74ULL,
		0xC9C7D2F4A71088ACULL,
		0x675DF4D153F6D835ULL,
		0xA54E57BB572C7A7FULL,
		0x11B8E0A84B536FF3ULL,
		0x31A1CEEB89996828ULL,
		0x4FADE68832DE9808ULL,
		0x1687CBFF0BC9B7BCULL
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
		0x04D3AC1F83236687ULL,
		0xB31A6F8F7910D0A3ULL,
		0x8EC1CC284AE36A0DULL,
		0xEF0A28881D9A8CC3ULL,
		0x02379EFC73100C27ULL,
		0xC9E99DF727490BB2ULL,
		0x46BD90B52F5C9740ULL,
		0x237FD219B4421D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A7583F0646CD0EULL,
		0x6634DF1EF221A146ULL,
		0x1D83985095C6D41BULL,
		0xDE1451103B351987ULL,
		0x046F3DF8E620184FULL,
		0x93D33BEE4E921764ULL,
		0x8D7B216A5EB92E81ULL,
		0x46FFA43368843B10ULL
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
		0xB9BCF58E848295DFULL,
		0x143F115ED2F567E0ULL,
		0xF311F1402A14E552ULL,
		0xEF78062F513F9406ULL,
		0xDD69187624F9BD26ULL,
		0xFCAD1E306673A89AULL,
		0x2B00CFD41FFBF49DULL,
		0x1E93B489A3B725DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7379EB1D09052BBEULL,
		0x287E22BDA5EACFC1ULL,
		0xE623E2805429CAA4ULL,
		0xDEF00C5EA27F280DULL,
		0xBAD230EC49F37A4DULL,
		0xF95A3C60CCE75135ULL,
		0x56019FA83FF7E93BULL,
		0x3D276913476E4BB8ULL
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
		0xFB8AA51B27443893ULL,
		0x8828D366DA9E6EF4ULL,
		0x2D2F8D89D5F758E2ULL,
		0x7D1968F6A032FEB4ULL,
		0x618D2140AF7BAED9ULL,
		0x71369501AF5632B9ULL,
		0xA129A42B4756C21AULL,
		0x151289973A705243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7154A364E887126ULL,
		0x1051A6CDB53CDDE9ULL,
		0x5A5F1B13ABEEB1C5ULL,
		0xFA32D1ED4065FD68ULL,
		0xC31A42815EF75DB2ULL,
		0xE26D2A035EAC6572ULL,
		0x425348568EAD8434ULL,
		0x2A25132E74E0A487ULL
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
		0xDA4816862AD03084ULL,
		0x448C4A5BB1D00524ULL,
		0x63814FD9DE781852ULL,
		0xA2343992911C63FBULL,
		0x5ADA4E554E6C6BCAULL,
		0x15979B8510253555ULL,
		0x51B68762B3DB9644ULL,
		0x0C315950E1DC68C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4902D0C55A06108ULL,
		0x891894B763A00A49ULL,
		0xC7029FB3BCF030A4ULL,
		0x446873252238C7F6ULL,
		0xB5B49CAA9CD8D795ULL,
		0x2B2F370A204A6AAAULL,
		0xA36D0EC567B72C88ULL,
		0x1862B2A1C3B8D186ULL
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
		0xC6ED77D03A249442ULL,
		0xFBBF8589A80601A9ULL,
		0xE204EB2F0370FE4BULL,
		0x6097D510B9FA48ACULL,
		0x368C58A64FDE5B4FULL,
		0x5BB7FB10A4E369D3ULL,
		0x3859F83D037573EFULL,
		0x0A118B8B796225DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DDAEFA074492884ULL,
		0xF77F0B13500C0353ULL,
		0xC409D65E06E1FC97ULL,
		0xC12FAA2173F49159ULL,
		0x6D18B14C9FBCB69EULL,
		0xB76FF62149C6D3A6ULL,
		0x70B3F07A06EAE7DEULL,
		0x14231716F2C44BBCULL
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
		0x6F244717F53549A2ULL,
		0x7BFB79D61D67F749ULL,
		0xDC06B110A1E3C75CULL,
		0xB5C1C1CD1F88D475ULL,
		0xB11BB579B4158AFFULL,
		0x9648844EED06DAEEULL,
		0x4F5FE9FF8B26CA6EULL,
		0x234278312C7F9529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE488E2FEA6A9344ULL,
		0xF7F6F3AC3ACFEE92ULL,
		0xB80D622143C78EB8ULL,
		0x6B83839A3F11A8EBULL,
		0x62376AF3682B15FFULL,
		0x2C91089DDA0DB5DDULL,
		0x9EBFD3FF164D94DDULL,
		0x4684F06258FF2A52ULL
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
		0xDAE5344329718372ULL,
		0x869831F3D3362716ULL,
		0x9C2150925856BD3BULL,
		0xAAAB2BBABADF7E21ULL,
		0xA91D323E359A1408ULL,
		0x35E2B6E49A08FB1CULL,
		0x5B90E2F274BB1AE0ULL,
		0x05D9CFC79202A464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5CA688652E306E4ULL,
		0x0D3063E7A66C4E2DULL,
		0x3842A124B0AD7A77ULL,
		0x5556577575BEFC43ULL,
		0x523A647C6B342811ULL,
		0x6BC56DC93411F639ULL,
		0xB721C5E4E97635C0ULL,
		0x0BB39F8F240548C8ULL
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
		0x17DCA4E1FBBF7A91ULL,
		0x2837C6DD7E7B5C49ULL,
		0x24DE07B771E8DC36ULL,
		0xC5871A4F18DD8A38ULL,
		0x3141F290947055CEULL,
		0x2D98C793C39B00EAULL,
		0x622CF92CECFF5280ULL,
		0x0BE3A4A9B50BF03BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FB949C3F77EF522ULL,
		0x506F8DBAFCF6B892ULL,
		0x49BC0F6EE3D1B86CULL,
		0x8B0E349E31BB1470ULL,
		0x6283E52128E0AB9DULL,
		0x5B318F27873601D4ULL,
		0xC459F259D9FEA500ULL,
		0x17C749536A17E076ULL
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
		0xA91DA34A26FBC505ULL,
		0x96B73EF66553F7F2ULL,
		0xEE27267E2C0DF2E9ULL,
		0xE4C39B41B4E22218ULL,
		0x22B54F9969A2BA5EULL,
		0xC0CC7CE012991AE2ULL,
		0xB7DACB138A9FF63EULL,
		0x0E650F5B8BCF9773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x523B46944DF78A0AULL,
		0x2D6E7DECCAA7EFE5ULL,
		0xDC4E4CFC581BE5D3ULL,
		0xC987368369C44431ULL,
		0x456A9F32D34574BDULL,
		0x8198F9C0253235C4ULL,
		0x6FB59627153FEC7DULL,
		0x1CCA1EB7179F2EE7ULL
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
		0xA653511F0653AD6EULL,
		0x377922F0D161B506ULL,
		0x2524AFDD1D351EEDULL,
		0xEFBEC23A486C56BEULL,
		0x48B41F130C7A4A9AULL,
		0xFDA45B40DF2A3A73ULL,
		0xD77EDD1F90E19A38ULL,
		0x1144CBA21DD6CBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CA6A23E0CA75ADCULL,
		0x6EF245E1A2C36A0DULL,
		0x4A495FBA3A6A3DDAULL,
		0xDF7D847490D8AD7CULL,
		0x91683E2618F49535ULL,
		0xFB48B681BE5474E6ULL,
		0xAEFDBA3F21C33471ULL,
		0x228997443BAD974BULL
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
		0x113E46AF0A981478ULL,
		0x15179A7FF1DCBB1EULL,
		0xC07062DE0B908405ULL,
		0x9C62DEA44FCDDEC1ULL,
		0x0179C5E6CCF8A60AULL,
		0x08CE7E64F3E27432ULL,
		0xDD5A94BB7AAC98C8ULL,
		0x1FD1E8388769E0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227C8D5E153028F0ULL,
		0x2A2F34FFE3B9763CULL,
		0x80E0C5BC1721080AULL,
		0x38C5BD489F9BBD83ULL,
		0x02F38BCD99F14C15ULL,
		0x119CFCC9E7C4E864ULL,
		0xBAB52976F5593190ULL,
		0x3FA3D0710ED3C177ULL
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
		0x9B3EDCC0640F2B83ULL,
		0xBF87C15213CE2834ULL,
		0xE3F66AA765E902CEULL,
		0x0C737A1D5F23D856ULL,
		0x07C7D945BD3EE7F9ULL,
		0x918986E5638C5FC8ULL,
		0x7C5684797B7919B7ULL,
		0x0A6A852A9FF3808EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x367DB980C81E5706ULL,
		0x7F0F82A4279C5069ULL,
		0xC7ECD54ECBD2059DULL,
		0x18E6F43ABE47B0ADULL,
		0x0F8FB28B7A7DCFF2ULL,
		0x23130DCAC718BF90ULL,
		0xF8AD08F2F6F2336FULL,
		0x14D50A553FE7011CULL
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
		0x225CC5FBBD66D125ULL,
		0xB3C4A7D46B46ABDBULL,
		0xE325A1E84A65D026ULL,
		0x5823437FE4B0FEFCULL,
		0x44309880C7E5DC31ULL,
		0x2B6A31803F409B7BULL,
		0x8FABFF6A34D8C86BULL,
		0x24A903DC6554BF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44B98BF77ACDA24AULL,
		0x67894FA8D68D57B6ULL,
		0xC64B43D094CBA04DULL,
		0xB04686FFC961FDF9ULL,
		0x886131018FCBB862ULL,
		0x56D463007E8136F6ULL,
		0x1F57FED469B190D6ULL,
		0x495207B8CAA97EF7ULL
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
		0x8127F93C3AC73510ULL,
		0xAC31E192730C8FFCULL,
		0xCECA7D7F528D4595ULL,
		0x6A29BA5E95569B0EULL,
		0xF5E4486EFB6244EEULL,
		0x00E3024265C1766FULL,
		0xCDC801A2D6F0EB17ULL,
		0x002A18F4E5B968E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024FF278758E6A20ULL,
		0x5863C324E6191FF9ULL,
		0x9D94FAFEA51A8B2BULL,
		0xD45374BD2AAD361DULL,
		0xEBC890DDF6C489DCULL,
		0x01C60484CB82ECDFULL,
		0x9B900345ADE1D62EULL,
		0x005431E9CB72D1D3ULL
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
		0xC244EA3B11BA442DULL,
		0xA2E8533A2A129951ULL,
		0xDD770609FC6BEECCULL,
		0x48652BB0E833774EULL,
		0xC7F7B9FF3E9F0598ULL,
		0x4E37202D370A000EULL,
		0x9A23134396A15068ULL,
		0x315BD424EAA61741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8489D4762374885AULL,
		0x45D0A674542532A3ULL,
		0xBAEE0C13F8D7DD99ULL,
		0x90CA5761D066EE9DULL,
		0x8FEF73FE7D3E0B30ULL,
		0x9C6E405A6E14001DULL,
		0x344626872D42A0D0ULL,
		0x62B7A849D54C2E83ULL
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
		0x88FB1893F73FE5FFULL,
		0xE65B50A257235C9DULL,
		0x085FE03C5EC31287ULL,
		0xA83B7A0704D7704DULL,
		0x9BF370C8DDB5290DULL,
		0x544530C529730CA0ULL,
		0xA425356069C21B8EULL,
		0x2760F24B6B63152FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F63127EE7FCBFEULL,
		0xCCB6A144AE46B93BULL,
		0x10BFC078BD86250FULL,
		0x5076F40E09AEE09AULL,
		0x37E6E191BB6A521BULL,
		0xA88A618A52E61941ULL,
		0x484A6AC0D384371CULL,
		0x4EC1E496D6C62A5FULL
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
		0xFEB67313FE1112EAULL,
		0x6E773A1AD61C396EULL,
		0x91A94C3814FE68D0ULL,
		0x4F1CFC5BF049E7BDULL,
		0xE15B218D8EDF4B4DULL,
		0x86D1624653D86449ULL,
		0x945E1BE20EB91D96ULL,
		0x20C9FC699297774BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD6CE627FC2225D4ULL,
		0xDCEE7435AC3872DDULL,
		0x2352987029FCD1A0ULL,
		0x9E39F8B7E093CF7BULL,
		0xC2B6431B1DBE969AULL,
		0x0DA2C48CA7B0C893ULL,
		0x28BC37C41D723B2DULL,
		0x4193F8D3252EEE97ULL
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
		0xED737A487AA955AEULL,
		0xC56BBAC67B5EA62AULL,
		0xDB7E01D25CAE7ABEULL,
		0x71A48CCF6CD4B3ACULL,
		0x5964043A32800F16ULL,
		0xEA989E6616C282C8ULL,
		0x0501F43F9380F7B0ULL,
		0x3AFEDBDEC60A394DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAE6F490F552AB5CULL,
		0x8AD7758CF6BD4C55ULL,
		0xB6FC03A4B95CF57DULL,
		0xE349199ED9A96759ULL,
		0xB2C8087465001E2CULL,
		0xD5313CCC2D850590ULL,
		0x0A03E87F2701EF61ULL,
		0x75FDB7BD8C14729AULL
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
		0x5A422E9B2D801D69ULL,
		0x6EF68E18CED3427EULL,
		0x0EEC30EF2C7113A0ULL,
		0x798D13A6B60F9CBBULL,
		0xBDBFA6EB0025A14FULL,
		0x8F895DB2F7DD6AEBULL,
		0x652D58D0838147B2ULL,
		0x2A64DB035D943B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4845D365B003AD2ULL,
		0xDDED1C319DA684FCULL,
		0x1DD861DE58E22740ULL,
		0xF31A274D6C1F3976ULL,
		0x7B7F4DD6004B429EULL,
		0x1F12BB65EFBAD5D7ULL,
		0xCA5AB1A107028F65ULL,
		0x54C9B606BB287604ULL
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
		0xBE6061CC08E0AC19ULL,
		0xBD7B598461565F8DULL,
		0xEE85EC4CFDA9FC23ULL,
		0x05704CAA0190835FULL,
		0xB9379CBA13BB6584ULL,
		0xE8FCC2AB656F4E04ULL,
		0xD6F3E131C0799F9CULL,
		0x15E409E7D94A5F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC0C39811C15832ULL,
		0x7AF6B308C2ACBF1BULL,
		0xDD0BD899FB53F847ULL,
		0x0AE09954032106BFULL,
		0x726F39742776CB08ULL,
		0xD1F98556CADE9C09ULL,
		0xADE7C26380F33F39ULL,
		0x2BC813CFB294BE5BULL
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
		0x2B1CEF86654B0B46ULL,
		0xE16CC69AD728EFB4ULL,
		0x54EFC40924672B20ULL,
		0x85EDF2CE80C25596ULL,
		0x76E590D260EC218CULL,
		0x4C33894DDB45AEA7ULL,
		0xD6BCFDB219F4BEC8ULL,
		0x3FB6C1ED65C71429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5639DF0CCA96168CULL,
		0xC2D98D35AE51DF68ULL,
		0xA9DF881248CE5641ULL,
		0x0BDBE59D0184AB2CULL,
		0xEDCB21A4C1D84319ULL,
		0x9867129BB68B5D4EULL,
		0xAD79FB6433E97D90ULL,
		0x7F6D83DACB8E2853ULL
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
		0xA905CEF286F574D7ULL,
		0xA51A2A8F7F6C5ADBULL,
		0xF01BBBCC6AC0F902ULL,
		0xAA4DDFB7FE3E618DULL,
		0x271D312B959AF9C4ULL,
		0xF097FAA185021F40ULL,
		0xE5CBEC7C5D85598AULL,
		0x140B9E07F922E5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x520B9DE50DEAE9AEULL,
		0x4A34551EFED8B5B7ULL,
		0xE0377798D581F205ULL,
		0x549BBF6FFC7CC31BULL,
		0x4E3A62572B35F389ULL,
		0xE12FF5430A043E80ULL,
		0xCB97D8F8BB0AB315ULL,
		0x28173C0FF245CB81ULL
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
		0xDADC49CA2E614A21ULL,
		0x50607B271CB3ECBFULL,
		0x51B5C2B85C728EE5ULL,
		0xE64120D077DE3F60ULL,
		0x2606011231C55BC4ULL,
		0x5FF9FC77F1B01BDEULL,
		0x218DFA94AEB115D3ULL,
		0x0720696C625A5C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B893945CC29442ULL,
		0xA0C0F64E3967D97FULL,
		0xA36B8570B8E51DCAULL,
		0xCC8241A0EFBC7EC0ULL,
		0x4C0C0224638AB789ULL,
		0xBFF3F8EFE36037BCULL,
		0x431BF5295D622BA6ULL,
		0x0E40D2D8C4B4B8CEULL
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
		0xE6503EB6F745C34EULL,
		0x770C5F78FFFD5770ULL,
		0x84F9857E965BEB52ULL,
		0x125C8A99E075837EULL,
		0x550C2AE8F76EEA58ULL,
		0x1309588E39B1063DULL,
		0x745CAAC0FA212469ULL,
		0x31EB0EAEF479A028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA07D6DEE8B869CULL,
		0xEE18BEF1FFFAAEE1ULL,
		0x09F30AFD2CB7D6A4ULL,
		0x24B91533C0EB06FDULL,
		0xAA1855D1EEDDD4B0ULL,
		0x2612B11C73620C7AULL,
		0xE8B95581F44248D2ULL,
		0x63D61D5DE8F34050ULL
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
		0x8165B9839D68B8E2ULL,
		0xA81FD68A747AEFE2ULL,
		0xCFD9BEB8E26AA800ULL,
		0x6934B04DEA93B766ULL,
		0x45D4D8AFC8FC90B3ULL,
		0x4003A1DB8A97ACB5ULL,
		0x0C30A2BB4872F9FFULL,
		0x24E8CD8EB4EB0D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CB73073AD171C4ULL,
		0x503FAD14E8F5DFC5ULL,
		0x9FB37D71C4D55001ULL,
		0xD269609BD5276ECDULL,
		0x8BA9B15F91F92166ULL,
		0x800743B7152F596AULL,
		0x1861457690E5F3FEULL,
		0x49D19B1D69D61A1CULL
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
		0xA7DBD68E7E980806ULL,
		0x6F3887A97A4FA837ULL,
		0x97BC0B24B3EE7D7AULL,
		0x00D4FFBCAD23C117ULL,
		0xF651E3D22A05EA4BULL,
		0x0C24855F2F5118D4ULL,
		0xE80A007D77A6FCF3ULL,
		0x222672130464517DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FB7AD1CFD30100CULL,
		0xDE710F52F49F506FULL,
		0x2F78164967DCFAF4ULL,
		0x01A9FF795A47822FULL,
		0xECA3C7A4540BD496ULL,
		0x18490ABE5EA231A9ULL,
		0xD01400FAEF4DF9E6ULL,
		0x444CE42608C8A2FBULL
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
		0xA13F01B7F678619DULL,
		0x47AD3D34F88116F9ULL,
		0x49A72DC2A07B0FB5ULL,
		0x559390F89598DFA0ULL,
		0x91C4CF07B958A847ULL,
		0x506056D668FD2FA8ULL,
		0xC393E81760C915FFULL,
		0x184F6765F543311FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427E036FECF0C33AULL,
		0x8F5A7A69F1022DF3ULL,
		0x934E5B8540F61F6AULL,
		0xAB2721F12B31BF40ULL,
		0x23899E0F72B1508EULL,
		0xA0C0ADACD1FA5F51ULL,
		0x8727D02EC1922BFEULL,
		0x309ECECBEA86623FULL
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
		0x7C1FD5EB614BE58DULL,
		0x4ADDF563E18A3547ULL,
		0x6E6447EAECE0E7EEULL,
		0xB48D971D5DCAA13CULL,
		0x6A0BD76BD5660AA6ULL,
		0x513C6BA35BEF0690ULL,
		0xE58752734B0BC159ULL,
		0x2727AB2366895467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF83FABD6C297CB1AULL,
		0x95BBEAC7C3146A8EULL,
		0xDCC88FD5D9C1CFDCULL,
		0x691B2E3ABB954278ULL,
		0xD417AED7AACC154DULL,
		0xA278D746B7DE0D20ULL,
		0xCB0EA4E6961782B2ULL,
		0x4E4F5646CD12A8CFULL
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
		0x833F8DFBD3EF2C66ULL,
		0x66423BE89DB8256CULL,
		0xB204BB687DF312D1ULL,
		0x4799A26ECE6E50ADULL,
		0xE4D8281F03948CD7ULL,
		0x9C2CD1B63F1CE4F5ULL,
		0xC5E1B5956DB686E5ULL,
		0x3E74D9D4DEC8A6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067F1BF7A7DE58CCULL,
		0xCC8477D13B704AD9ULL,
		0x640976D0FBE625A2ULL,
		0x8F3344DD9CDCA15BULL,
		0xC9B0503E072919AEULL,
		0x3859A36C7E39C9EBULL,
		0x8BC36B2ADB6D0DCBULL,
		0x7CE9B3A9BD914D8BULL
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
		0x1451F3F09CD37FCBULL,
		0x0A97E78B32224ED1ULL,
		0x5BECC734749367A9ULL,
		0x25A282D4272168FFULL,
		0x4C641F3FA9350F71ULL,
		0xE36D4F28D73798FBULL,
		0x363DCB8A38337DE0ULL,
		0x3C66DE0BEA4F5FE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A3E7E139A6FF96ULL,
		0x152FCF1664449DA2ULL,
		0xB7D98E68E926CF52ULL,
		0x4B4505A84E42D1FEULL,
		0x98C83E7F526A1EE2ULL,
		0xC6DA9E51AE6F31F6ULL,
		0x6C7B97147066FBC1ULL,
		0x78CDBC17D49EBFC4ULL
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
		0x5ACF981046E5D92CULL,
		0xE3AC20FEC5501AF8ULL,
		0x55DD683DC30AA2B2ULL,
		0xC02BF66EA2660920ULL,
		0x3BE59B1019A94056ULL,
		0xEB0AEEC103AADB6BULL,
		0xE7B18327E4447BBBULL,
		0x30201A7664806C96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59F30208DCBB258ULL,
		0xC75841FD8AA035F0ULL,
		0xABBAD07B86154565ULL,
		0x8057ECDD44CC1240ULL,
		0x77CB3620335280ADULL,
		0xD615DD820755B6D6ULL,
		0xCF63064FC888F777ULL,
		0x604034ECC900D92DULL
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
		0x7FA97FFB1424206DULL,
		0x7DB3AAFF3A09FE72ULL,
		0x9BBB146362EF23D4ULL,
		0xC4EC8570A5F138A8ULL,
		0xE4C8AAA68138D1C4ULL,
		0xB0C333A78CCDE48CULL,
		0xCC4F70C225D11102ULL,
		0x07FDA15877A6ED56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF52FFF6284840DAULL,
		0xFB6755FE7413FCE4ULL,
		0x377628C6C5DE47A8ULL,
		0x89D90AE14BE27151ULL,
		0xC991554D0271A389ULL,
		0x6186674F199BC919ULL,
		0x989EE1844BA22205ULL,
		0x0FFB42B0EF4DDAADULL
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
		0x1DE7C647E3B5CFEBULL,
		0xB2FADF0E2FBC88ADULL,
		0xFA27D5966119754CULL,
		0xDB500B87629B8838ULL,
		0x7C5D8CDD8C0AC363ULL,
		0x2624B586A8C30F64ULL,
		0xFCF0B1DB7FD4142BULL,
		0x30799C4ABDAE48FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BCF8C8FC76B9FD6ULL,
		0x65F5BE1C5F79115AULL,
		0xF44FAB2CC232EA99ULL,
		0xB6A0170EC5371071ULL,
		0xF8BB19BB181586C7ULL,
		0x4C496B0D51861EC8ULL,
		0xF9E163B6FFA82856ULL,
		0x60F338957B5C91FDULL
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
		0x6B795AA321131661ULL,
		0x50E3DD0A06BD9564ULL,
		0x0CD4A1494DA45C96ULL,
		0x28C20609DAFB5E8FULL,
		0xB05712F25C38F2F3ULL,
		0x22212B2E782F4428ULL,
		0xC7713F6F865F8233ULL,
		0x1C246F9D5AEBA0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6F2B54642262CC2ULL,
		0xA1C7BA140D7B2AC8ULL,
		0x19A942929B48B92CULL,
		0x51840C13B5F6BD1EULL,
		0x60AE25E4B871E5E6ULL,
		0x4442565CF05E8851ULL,
		0x8EE27EDF0CBF0466ULL,
		0x3848DF3AB5D74143ULL
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
		0xE25CE1519108F91EULL,
		0xD8C0050CBAD045A9ULL,
		0x29CB102257A581D9ULL,
		0x3193E4FB93D84B7EULL,
		0xA01900B9FB8D65E0ULL,
		0x8660B5B4C06DE2ADULL,
		0x56481E83B904B28FULL,
		0x0FB95678677A4A78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B9C2A32211F23CULL,
		0xB1800A1975A08B53ULL,
		0x53962044AF4B03B3ULL,
		0x6327C9F727B096FCULL,
		0x40320173F71ACBC0ULL,
		0x0CC16B6980DBC55BULL,
		0xAC903D077209651FULL,
		0x1F72ACF0CEF494F0ULL
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
		0xA3E982B7F86B6CAEULL,
		0xBA49C16C30961A55ULL,
		0xAB5810B67937322AULL,
		0x987CF126FE1FB885ULL,
		0x179DE66313D146CBULL,
		0xB18021F2DF6EEF33ULL,
		0x9E41B7CD4FA68B5BULL,
		0x0AC8CBA7F4954E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D3056FF0D6D95CULL,
		0x749382D8612C34ABULL,
		0x56B0216CF26E6455ULL,
		0x30F9E24DFC3F710BULL,
		0x2F3BCCC627A28D97ULL,
		0x630043E5BEDDDE66ULL,
		0x3C836F9A9F4D16B7ULL,
		0x1591974FE92A9D1DULL
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
		0x8914FCFE5CA04648ULL,
		0x0FEBC91886C9099FULL,
		0xB359861EDEBCE2F1ULL,
		0x3807AF2683BE93C4ULL,
		0xE5976139551C61DBULL,
		0xB9F7271215739565ULL,
		0xD797685DFC803D3AULL,
		0x2B39D09EF0FED603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1229F9FCB9408C90ULL,
		0x1FD792310D92133FULL,
		0x66B30C3DBD79C5E2ULL,
		0x700F5E4D077D2789ULL,
		0xCB2EC272AA38C3B6ULL,
		0x73EE4E242AE72ACBULL,
		0xAF2ED0BBF9007A75ULL,
		0x5673A13DE1FDAC07ULL
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
		0x615D85570B1B20A8ULL,
		0x4D2D6E1B8F1873D6ULL,
		0x8BABF7ECA8B12272ULL,
		0x3B444CC979B2D991ULL,
		0x86FD9DB28BF4653DULL,
		0xE73F18A085137764ULL,
		0xA9EACB42968399F5ULL,
		0x1C580D34A565DB6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BB0AAE16364150ULL,
		0x9A5ADC371E30E7ACULL,
		0x1757EFD9516244E4ULL,
		0x76889992F365B323ULL,
		0x0DFB3B6517E8CA7AULL,
		0xCE7E31410A26EEC9ULL,
		0x53D596852D0733EBULL,
		0x38B01A694ACBB6DDULL
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
		0x270F44E63CD1655AULL,
		0xFF9BCF25C5B217D5ULL,
		0x27D2512C1962F403ULL,
		0x9567BB031554FE2BULL,
		0xB98C88F28CFFAF80ULL,
		0x7713FAEE4574BBBDULL,
		0x5036EE8E08A1BAEAULL,
		0x3BAD65F883137241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1E89CC79A2CAB4ULL,
		0xFF379E4B8B642FAAULL,
		0x4FA4A25832C5E807ULL,
		0x2ACF76062AA9FC56ULL,
		0x731911E519FF5F01ULL,
		0xEE27F5DC8AE9777BULL,
		0xA06DDD1C114375D4ULL,
		0x775ACBF10626E482ULL
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
		0x7DAF94A58E34E926ULL,
		0x805E86AD0B3194B2ULL,
		0xFB9E51986422A0F5ULL,
		0x120E45B3717DD91DULL,
		0xDC1091221811DBB7ULL,
		0xFBE495B80E2B6A85ULL,
		0xF8C4117D31635613ULL,
		0x288AA38BE74D4E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5F294B1C69D24CULL,
		0x00BD0D5A16632964ULL,
		0xF73CA330C84541EBULL,
		0x241C8B66E2FBB23BULL,
		0xB82122443023B76EULL,
		0xF7C92B701C56D50BULL,
		0xF18822FA62C6AC27ULL,
		0x51154717CE9A9C13ULL
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
		0x01138CCE6451C392ULL,
		0xBFBA848F37858CAAULL,
		0xE03135F879B4B057ULL,
		0x93B4080311376A2AULL,
		0xE2DF8E3B5B18F7FBULL,
		0xD04D3373B9068AD9ULL,
		0x9DB0F8233671C160ULL,
		0x0EAF27828517FD19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0227199CC8A38724ULL,
		0x7F75091E6F0B1954ULL,
		0xC0626BF0F36960AFULL,
		0x27681006226ED455ULL,
		0xC5BF1C76B631EFF7ULL,
		0xA09A66E7720D15B3ULL,
		0x3B61F0466CE382C1ULL,
		0x1D5E4F050A2FFA33ULL
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
		0xC2CA2414784F0215ULL,
		0xB44723C1D21090EAULL,
		0x0C889C128BC7CEB5ULL,
		0xC9AC4DFE26EAECFFULL,
		0xF7E2DE0074F0B51EULL,
		0xF683EF315F2A6D1BULL,
		0x9EA00C6CB3A51F70ULL,
		0x205B78B6F447DF93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85944828F09E042AULL,
		0x688E4783A42121D5ULL,
		0x19113825178F9D6BULL,
		0x93589BFC4DD5D9FEULL,
		0xEFC5BC00E9E16A3DULL,
		0xED07DE62BE54DA37ULL,
		0x3D4018D9674A3EE1ULL,
		0x40B6F16DE88FBF27ULL
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
		0x4D6F1E366A31B1DDULL,
		0xE07F932D7951310AULL,
		0x098C9BF67B6CA17AULL,
		0x265CD91BA99AB018ULL,
		0x6279B6068493827CULL,
		0xAD3883EC11C04088ULL,
		0x9EDFC9DF546DF93CULL,
		0x155C400E5E97FC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ADE3C6CD46363BAULL,
		0xC0FF265AF2A26214ULL,
		0x131937ECF6D942F5ULL,
		0x4CB9B23753356030ULL,
		0xC4F36C0D092704F8ULL,
		0x5A7107D823808110ULL,
		0x3DBF93BEA8DBF279ULL,
		0x2AB8801CBD2FF851ULL
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
		0x3571E1FFEAD725ADULL,
		0x003C227B98782E43ULL,
		0x7A3B5B3EBF850C1BULL,
		0xFE459809CA735C68ULL,
		0x543719C60B344D89ULL,
		0xBD4C2A3FD779C095ULL,
		0x3EEA0B86DB28E939ULL,
		0x11B4307B95149860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE3C3FFD5AE4B5AULL,
		0x007844F730F05C86ULL,
		0xF476B67D7F0A1836ULL,
		0xFC8B301394E6B8D0ULL,
		0xA86E338C16689B13ULL,
		0x7A98547FAEF3812AULL,
		0x7DD4170DB651D273ULL,
		0x236860F72A2930C0ULL
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
		0xD7DF79C788C8FFD8ULL,
		0xB9AF586C9B614C4CULL,
		0xA8C12D978DE71FDBULL,
		0xD7C3DDB4E15BDB5DULL,
		0xFE34272369A7C67CULL,
		0x6C76F5FBEA12D90EULL,
		0xC172294653F07401ULL,
		0x11A7F7860B977664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFBEF38F1191FFB0ULL,
		0x735EB0D936C29899ULL,
		0x51825B2F1BCE3FB7ULL,
		0xAF87BB69C2B7B6BBULL,
		0xFC684E46D34F8CF9ULL,
		0xD8EDEBF7D425B21DULL,
		0x82E4528CA7E0E802ULL,
		0x234FEF0C172EECC9ULL
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
		0x31F724E646B7169BULL,
		0x03EC3988374EBC09ULL,
		0xB08B511926426385ULL,
		0xE876810C0C6A7201ULL,
		0x4EBA09358223A279ULL,
		0xBE03F92408155BC9ULL,
		0xE1C253F4517DF840ULL,
		0x01B6E99FC71C57FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EE49CC8D6E2D36ULL,
		0x07D873106E9D7812ULL,
		0x6116A2324C84C70AULL,
		0xD0ED021818D4E403ULL,
		0x9D74126B044744F3ULL,
		0x7C07F248102AB792ULL,
		0xC384A7E8A2FBF081ULL,
		0x036DD33F8E38AFF5ULL
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
		0x4EF9C26344539287ULL,
		0xAEE778D0416B40ADULL,
		0x8E369241F3AD0FDCULL,
		0x7F457E320165FAB7ULL,
		0xCADF3B2F8F1AD2F0ULL,
		0xC58A281C78148D25ULL,
		0x8AE89512641AB3DFULL,
		0x3F9DF7B79D18A62AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF384C688A7250EULL,
		0x5DCEF1A082D6815AULL,
		0x1C6D2483E75A1FB9ULL,
		0xFE8AFC6402CBF56FULL,
		0x95BE765F1E35A5E0ULL,
		0x8B145038F0291A4BULL,
		0x15D12A24C83567BFULL,
		0x7F3BEF6F3A314C55ULL
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
		0xAA53469B0B4D29F2ULL,
		0x54578F45E76381E7ULL,
		0x2F46D08A9812600BULL,
		0x71900E00F23618C7ULL,
		0xA4230A52A89B66C0ULL,
		0xDBE33D09D0D20AA4ULL,
		0xD058D4F501B481F1ULL,
		0x2FCFECF714E37F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A68D36169A53E4ULL,
		0xA8AF1E8BCEC703CFULL,
		0x5E8DA1153024C016ULL,
		0xE3201C01E46C318EULL,
		0x484614A55136CD80ULL,
		0xB7C67A13A1A41549ULL,
		0xA0B1A9EA036903E3ULL,
		0x5F9FD9EE29C6FE35ULL
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
		0x33A1FA958AAA909CULL,
		0xEBA003649766599FULL,
		0x35409816114C7E96ULL,
		0x9CAC2390F71FF218ULL,
		0xB47CDD42D249B094ULL,
		0x2CDF8F342BD62D77ULL,
		0x6E9F4E3027BBB078ULL,
		0x27689400525A6E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6743F52B15552138ULL,
		0xD74006C92ECCB33EULL,
		0x6A81302C2298FD2DULL,
		0x39584721EE3FE430ULL,
		0x68F9BA85A4936129ULL,
		0x59BF1E6857AC5AEFULL,
		0xDD3E9C604F7760F0ULL,
		0x4ED12800A4B4DCB8ULL
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
		0xA3A440BB29E8CD52ULL,
		0xE3A3316CE9173A4BULL,
		0x7106A02899B195C0ULL,
		0xD1F1CAC870683773ULL,
		0x25934FCA5CE0A384ULL,
		0xD968DADDA44B2089ULL,
		0x70FA5C26A22E16F0ULL,
		0x17A1B8C6CA025983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4748817653D19AA4ULL,
		0xC74662D9D22E7497ULL,
		0xE20D405133632B81ULL,
		0xA3E39590E0D06EE6ULL,
		0x4B269F94B9C14709ULL,
		0xB2D1B5BB48964112ULL,
		0xE1F4B84D445C2DE1ULL,
		0x2F43718D9404B306ULL
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
		0xBF995BEE4A35DE17ULL,
		0x31FC688C46A91B2CULL,
		0xCF9799874EAC25F4ULL,
		0xC6E4AD3C58C7D55AULL,
		0x78AF331C98AA98F1ULL,
		0x55B09A04EE824A04ULL,
		0x50F1DE75A61F656DULL,
		0x09631A51F4D00BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F32B7DC946BBC2EULL,
		0x63F8D1188D523659ULL,
		0x9F2F330E9D584BE8ULL,
		0x8DC95A78B18FAAB5ULL,
		0xF15E6639315531E3ULL,
		0xAB613409DD049408ULL,
		0xA1E3BCEB4C3ECADAULL,
		0x12C634A3E9A01774ULL
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
		0x452A363A2B8A68ECULL,
		0x80E33B807DA18FB1ULL,
		0xADDBB9C7F4FD04EFULL,
		0x44DE4AC46566663BULL,
		0xDDC5675059A0E6A8ULL,
		0xF8BD6E015C3F1C3AULL,
		0x534FCD2D04A27365ULL,
		0x38D09445E79C8CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A546C745714D1D8ULL,
		0x01C67700FB431F62ULL,
		0x5BB7738FE9FA09DFULL,
		0x89BC9588CACCCC77ULL,
		0xBB8ACEA0B341CD50ULL,
		0xF17ADC02B87E3875ULL,
		0xA69F9A5A0944E6CBULL,
		0x71A1288BCF3919D8ULL
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
		0x060102A197DE5535ULL,
		0x60C29745E137D00BULL,
		0x207090011AD97DB5ULL,
		0xAF04E9016405D9E1ULL,
		0xF764C1A1746D1A88ULL,
		0xF7DDD6DDB24DFA3DULL,
		0xD3D17717995CADAEULL,
		0x0808DD5854739F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0205432FBCAA6AULL,
		0xC1852E8BC26FA016ULL,
		0x40E1200235B2FB6AULL,
		0x5E09D202C80BB3C2ULL,
		0xEEC98342E8DA3511ULL,
		0xEFBBADBB649BF47BULL,
		0xA7A2EE2F32B95B5DULL,
		0x1011BAB0A8E73F15ULL
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
		0x2A97448A1AC16CAFULL,
		0xCAC46571FC741BD9ULL,
		0xF86D8B0DD806A52CULL,
		0xF8B22F0E8946507FULL,
		0x5443A7B4888789DFULL,
		0xCBF6F0E7F63A5827ULL,
		0xC8CA35C926E165BBULL,
		0x283751CB2BFB615BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x552E89143582D95EULL,
		0x9588CAE3F8E837B2ULL,
		0xF0DB161BB00D4A59ULL,
		0xF1645E1D128CA0FFULL,
		0xA8874F69110F13BFULL,
		0x97EDE1CFEC74B04EULL,
		0x91946B924DC2CB77ULL,
		0x506EA39657F6C2B7ULL
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
		0x7353BAE4B61A96DCULL,
		0x3BED3B267E984099ULL,
		0x69EDAAC589D4772AULL,
		0x21F3E43F80B8D642ULL,
		0xCC33E31555CA6BD5ULL,
		0x46048DC39EA3ECACULL,
		0xE55847F579D71E8DULL,
		0x056B74FA4A2FD38DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6A775C96C352DB8ULL,
		0x77DA764CFD308132ULL,
		0xD3DB558B13A8EE54ULL,
		0x43E7C87F0171AC84ULL,
		0x9867C62AAB94D7AAULL,
		0x8C091B873D47D959ULL,
		0xCAB08FEAF3AE3D1AULL,
		0x0AD6E9F4945FA71BULL
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
		0x0DAC144AE70CED53ULL,
		0x83C353C15AF98251ULL,
		0x586F166261DF7931ULL,
		0x65D1A8843ECE13ADULL,
		0xECEC3EA892CB63AFULL,
		0x8D35DD3A32A8AE46ULL,
		0x401F6FE87962FF9AULL,
		0x10DD44A34BE1715EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B582895CE19DAA6ULL,
		0x0786A782B5F304A2ULL,
		0xB0DE2CC4C3BEF263ULL,
		0xCBA351087D9C275AULL,
		0xD9D87D512596C75EULL,
		0x1A6BBA7465515C8DULL,
		0x803EDFD0F2C5FF35ULL,
		0x21BA894697C2E2BCULL
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
		0x0C67A0A5741B0601ULL,
		0x124E090179D0A970ULL,
		0x003D7F5D5C4160BBULL,
		0xA8CE2C80B36B3372ULL,
		0xE1C868F9386EA67FULL,
		0x756783A9FB975940ULL,
		0x16B181BAA903D6EEULL,
		0x1EC8833856E383D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CF414AE8360C02ULL,
		0x249C1202F3A152E0ULL,
		0x007AFEBAB882C176ULL,
		0x519C590166D666E4ULL,
		0xC390D1F270DD4CFFULL,
		0xEACF0753F72EB281ULL,
		0x2D6303755207ADDCULL,
		0x3D910670ADC707A2ULL
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
		0x4A16316D53BB130AULL,
		0xC44F5A1CFD14FCFAULL,
		0xEBDBA637FF9D4AA7ULL,
		0x1AF6A464F84E1E8CULL,
		0xAD1F7E74127FE4EDULL,
		0x78A8B6471000DDF9ULL,
		0xFFE8E54206D5E973ULL,
		0x3FBD5295F25D824EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x942C62DAA7762614ULL,
		0x889EB439FA29F9F4ULL,
		0xD7B74C6FFF3A954FULL,
		0x35ED48C9F09C3D19ULL,
		0x5A3EFCE824FFC9DAULL,
		0xF1516C8E2001BBF3ULL,
		0xFFD1CA840DABD2E6ULL,
		0x7F7AA52BE4BB049DULL
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
		0xDF1BDD0FEACD0CA5ULL,
		0x77A384AF4B814D56ULL,
		0x404A82920C8CFDA5ULL,
		0xF5EAE9ED78E7E60CULL,
		0x3D21322CA79FEAFBULL,
		0x585EA80AC32D548CULL,
		0x1EEF78073C4329F1ULL,
		0x3253C2FBC0B2DBF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE37BA1FD59A194AULL,
		0xEF47095E97029AADULL,
		0x809505241919FB4AULL,
		0xEBD5D3DAF1CFCC18ULL,
		0x7A4264594F3FD5F7ULL,
		0xB0BD5015865AA918ULL,
		0x3DDEF00E788653E2ULL,
		0x64A785F78165B7ECULL
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
		0x86EBF0CD5943D8E3ULL,
		0xC818886CE23B9813ULL,
		0x8FCEC17A44EB48F1ULL,
		0xFA5B05984A985A06ULL,
		0x3BA7AE494A1C0480ULL,
		0x44DEC2DC01D54604ULL,
		0x45789A3E74C346E5ULL,
		0x21323A946663A635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD7E19AB287B1C6ULL,
		0x903110D9C4773027ULL,
		0x1F9D82F489D691E3ULL,
		0xF4B60B309530B40DULL,
		0x774F5C9294380901ULL,
		0x89BD85B803AA8C08ULL,
		0x8AF1347CE9868DCAULL,
		0x42647528CCC74C6AULL
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
		0x652DC8BF3C149A18ULL,
		0xC977AC97EBFECC92ULL,
		0x1439AF31B7BB9A1FULL,
		0xBEA25A4EEA6F0F29ULL,
		0xB2F11C1B8A83361AULL,
		0xD03DAFC57C1069ECULL,
		0xA20FB667A75C5E01ULL,
		0x1F20630B8B95DDD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA5B917E78293430ULL,
		0x92EF592FD7FD9924ULL,
		0x28735E636F77343FULL,
		0x7D44B49DD4DE1E52ULL,
		0x65E2383715066C35ULL,
		0xA07B5F8AF820D3D9ULL,
		0x441F6CCF4EB8BC03ULL,
		0x3E40C617172BBBB1ULL
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
		0xC608D4AEBC1E0F18ULL,
		0x8FFA186340977E70ULL,
		0xABF653008F94B1C0ULL,
		0x095277889C7561EDULL,
		0xC805BC5BD43C3B94ULL,
		0x3D94E17CE4769EFDULL,
		0x85D4F49471B8DB8FULL,
		0x39D050B035602629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C11A95D783C1E30ULL,
		0x1FF430C6812EFCE1ULL,
		0x57ECA6011F296381ULL,
		0x12A4EF1138EAC3DBULL,
		0x900B78B7A8787728ULL,
		0x7B29C2F9C8ED3DFBULL,
		0x0BA9E928E371B71EULL,
		0x73A0A1606AC04C53ULL
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
		0x7066D3BC6FAF6550ULL,
		0x209BB93B02CDB13EULL,
		0x29B90610596AF74EULL,
		0x65BC9DE235E57272ULL,
		0xA0D157835E3B0094ULL,
		0x8CECE744B7A4433DULL,
		0x6085BCB817802EDFULL,
		0x0CE390F8E71FCC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0CDA778DF5ECAA0ULL,
		0x41377276059B627CULL,
		0x53720C20B2D5EE9CULL,
		0xCB793BC46BCAE4E4ULL,
		0x41A2AF06BC760128ULL,
		0x19D9CE896F48867BULL,
		0xC10B79702F005DBFULL,
		0x19C721F1CE3F9858ULL
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
		0x3DEA31CEB9EC16C8ULL,
		0x1B09AD27FAA9638DULL,
		0x2184BE0E7E2BE0FFULL,
		0x33DECF1D658C90AEULL,
		0x0D1A3E6ED63D4CC2ULL,
		0xCF03AA4D003C7296ULL,
		0x5A2C57439BCE7D46ULL,
		0x057163648C55523BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD4639D73D82D90ULL,
		0x36135A4FF552C71AULL,
		0x43097C1CFC57C1FEULL,
		0x67BD9E3ACB19215CULL,
		0x1A347CDDAC7A9984ULL,
		0x9E07549A0078E52CULL,
		0xB458AE87379CFA8DULL,
		0x0AE2C6C918AAA476ULL
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
		0xFCB4A67CC7A9D24EULL,
		0x98ED5768E669BAD2ULL,
		0x46DFDBDE19BAA08AULL,
		0x25712AAF8E8478D6ULL,
		0x47F0CE5E7BC44A30ULL,
		0x9985ACB78F9BE9C8ULL,
		0x9B3EB31048751FD5ULL,
		0x08BDA7F7BB119950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9694CF98F53A49CULL,
		0x31DAAED1CCD375A5ULL,
		0x8DBFB7BC33754115ULL,
		0x4AE2555F1D08F1ACULL,
		0x8FE19CBCF7889460ULL,
		0x330B596F1F37D390ULL,
		0x367D662090EA3FABULL,
		0x117B4FEF762332A1ULL
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
		0x64297AE1F3D81E43ULL,
		0xECC057622DAA3DA8ULL,
		0xF626E1B3E2841D8DULL,
		0x7C6D4183A72840F5ULL,
		0xC4E24418454EABD9ULL,
		0x03E7279FF58F7677ULL,
		0x44D278AF4D4D6682ULL,
		0x31B63A358AA81121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC852F5C3E7B03C86ULL,
		0xD980AEC45B547B50ULL,
		0xEC4DC367C5083B1BULL,
		0xF8DA83074E5081EBULL,
		0x89C488308A9D57B2ULL,
		0x07CE4F3FEB1EECEFULL,
		0x89A4F15E9A9ACD04ULL,
		0x636C746B15502242ULL
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
		0x72CAC66B20C30DB8ULL,
		0x0276FEFD3329E3E5ULL,
		0xA0AC5F83C1E2F4E9ULL,
		0x938D1DDF497C98FCULL,
		0x132A74DF4378E33EULL,
		0x7634B713E0B1BC1AULL,
		0xD0A5C06CC5E6E941ULL,
		0x0CC3038DB6CF1EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5958CD641861B70ULL,
		0x04EDFDFA6653C7CAULL,
		0x4158BF0783C5E9D2ULL,
		0x271A3BBE92F931F9ULL,
		0x2654E9BE86F1C67DULL,
		0xEC696E27C1637834ULL,
		0xA14B80D98BCDD282ULL,
		0x1986071B6D9E3D8BULL
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
		0x18EF8D2C02760DADULL,
		0xC29B952FBC118A1BULL,
		0x8A09AF140F955E7EULL,
		0x633D1432EA8F01EEULL,
		0x9229BAF4BD11FA86ULL,
		0xC9C6B74BFEB15890ULL,
		0xE52B6998C7258D12ULL,
		0x0C9DF4486843C810ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31DF1A5804EC1B5AULL,
		0x85372A5F78231436ULL,
		0x14135E281F2ABCFDULL,
		0xC67A2865D51E03DDULL,
		0x245375E97A23F50CULL,
		0x938D6E97FD62B121ULL,
		0xCA56D3318E4B1A25ULL,
		0x193BE890D0879021ULL
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
		0x93F18F7C92E3E131ULL,
		0x7C77CD08DF67E3D4ULL,
		0xEBDA6DDB98636C46ULL,
		0xF143B69159A30B6BULL,
		0x795BA6685D94A848ULL,
		0xD2ED5FA3DFA6E9DAULL,
		0x0C0806FEFE93F8B6ULL,
		0x022CB8F79FD6FC9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27E31EF925C7C262ULL,
		0xF8EF9A11BECFC7A9ULL,
		0xD7B4DBB730C6D88CULL,
		0xE2876D22B34616D7ULL,
		0xF2B74CD0BB295091ULL,
		0xA5DABF47BF4DD3B4ULL,
		0x18100DFDFD27F16DULL,
		0x045971EF3FADF934ULL
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
		0x7C23779108F5B30FULL,
		0x8E25A2212264F751ULL,
		0x99F13B46C618C882ULL,
		0x7E16D0DD7B6F97D8ULL,
		0xE416DDD2D70A7246ULL,
		0xF28172687E2331F0ULL,
		0xD41A15F8F3E92185ULL,
		0x051E6BDB3DD454F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF846EF2211EB661EULL,
		0x1C4B444244C9EEA2ULL,
		0x33E2768D8C319105ULL,
		0xFC2DA1BAF6DF2FB1ULL,
		0xC82DBBA5AE14E48CULL,
		0xE502E4D0FC4663E1ULL,
		0xA8342BF1E7D2430BULL,
		0x0A3CD7B67BA8A9EFULL
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
		0x6876688A1D5839B8ULL,
		0x0828283345608D03ULL,
		0x831D6A29D8130DBEULL,
		0xCF0A8965A4484E65ULL,
		0x79C77A8F94447689ULL,
		0xB5C114AF5540D9E8ULL,
		0x4A91009E84C4515BULL,
		0x19EA17D142C61F87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0ECD1143AB07370ULL,
		0x105050668AC11A06ULL,
		0x063AD453B0261B7CULL,
		0x9E1512CB48909CCBULL,
		0xF38EF51F2888ED13ULL,
		0x6B82295EAA81B3D0ULL,
		0x9522013D0988A2B7ULL,
		0x33D42FA2858C3F0EULL
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
		0xEA5DBDDFC628CDCAULL,
		0x23F22C545ADB1144ULL,
		0xA11BD37F88E2919FULL,
		0x93A7CC906226CCA6ULL,
		0xE0350A71BDA50ACDULL,
		0xB8756B498697FCBBULL,
		0xE76A96A9DC243C89ULL,
		0x24F3DA994D181A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BB7BBF8C519B94ULL,
		0x47E458A8B5B62289ULL,
		0x4237A6FF11C5233EULL,
		0x274F9920C44D994DULL,
		0xC06A14E37B4A159BULL,
		0x70EAD6930D2FF977ULL,
		0xCED52D53B8487913ULL,
		0x49E7B5329A303497ULL
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
		0xE9435E2CC5517692ULL,
		0x1BF79F9D777AC02DULL,
		0xD3ED265CF7C34E4EULL,
		0x458DC05BC9C35422ULL,
		0xD2324968DC8A2311ULL,
		0x092979842414F088ULL,
		0x31AC97E11FF7B100ULL,
		0x3D1BFD4798B5A811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD286BC598AA2ED24ULL,
		0x37EF3F3AEEF5805BULL,
		0xA7DA4CB9EF869C9CULL,
		0x8B1B80B79386A845ULL,
		0xA46492D1B9144622ULL,
		0x1252F3084829E111ULL,
		0x63592FC23FEF6200ULL,
		0x7A37FA8F316B5022ULL
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
		0x0D4A6D0FAD1D9CD1ULL,
		0x71BD14C4E4B58144ULL,
		0x2B6228C849885A3DULL,
		0x896FB6D120919688ULL,
		0xFBE3B283BB328093ULL,
		0x49C57B9192DD89E6ULL,
		0xC08136021F0213E1ULL,
		0x0616F666ED6F8254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A94DA1F5A3B39A2ULL,
		0xE37A2989C96B0288ULL,
		0x56C451909310B47AULL,
		0x12DF6DA241232D10ULL,
		0xF7C7650776650127ULL,
		0x938AF72325BB13CDULL,
		0x81026C043E0427C2ULL,
		0x0C2DECCDDADF04A9ULL
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
		0x35A4A5FCB8209447ULL,
		0xC6540B7B9134B018ULL,
		0x731969AAE383EC24ULL,
		0xFB1605EB616D814DULL,
		0x20C5BCBE8A69CD2EULL,
		0xBB865A82511C03E8ULL,
		0x6A229D75E0ECF5F2ULL,
		0x2D470A88C3692CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B494BF97041288EULL,
		0x8CA816F722696030ULL,
		0xE632D355C707D849ULL,
		0xF62C0BD6C2DB029AULL,
		0x418B797D14D39A5DULL,
		0x770CB504A23807D0ULL,
		0xD4453AEBC1D9EBE5ULL,
		0x5A8E151186D25976ULL
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
		0x6A7D8DBDDB4C1EE3ULL,
		0x2935157D9C29BCBEULL,
		0x9127AE00E329EDCBULL,
		0x15A85D48069F5620ULL,
		0x0178A2F23A351B17ULL,
		0xAD30205AD4ED68D9ULL,
		0xD3B6EB1304684D9CULL,
		0x3C7F1CCACF3539F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4FB1B7BB6983DC6ULL,
		0x526A2AFB3853797CULL,
		0x224F5C01C653DB96ULL,
		0x2B50BA900D3EAC41ULL,
		0x02F145E4746A362EULL,
		0x5A6040B5A9DAD1B2ULL,
		0xA76DD62608D09B39ULL,
		0x78FE39959E6A73EBULL
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
		0xA0F82F4701505B35ULL,
		0x4B2F2896CD5E77A5ULL,
		0xD789BAD1454275F6ULL,
		0x61B8AA9A41BA5136ULL,
		0x23FCD4E44D6B352BULL,
		0x50CDE8430C6DBBA8ULL,
		0x2A7BB091E107AE23ULL,
		0x23ECE919FC76EF66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F05E8E02A0B66AULL,
		0x965E512D9ABCEF4BULL,
		0xAF1375A28A84EBECULL,
		0xC37155348374A26DULL,
		0x47F9A9C89AD66A56ULL,
		0xA19BD08618DB7750ULL,
		0x54F76123C20F5C46ULL,
		0x47D9D233F8EDDECCULL
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
		0xD86ADCED43897BA9ULL,
		0x30B979704C9BB484ULL,
		0x537469C58C3AD09FULL,
		0xFB9B0A0C085C725FULL,
		0xFBB30F18A046C976ULL,
		0x853FB4E3F7AF4514ULL,
		0xC304EA5A154490B1ULL,
		0x284672CB3D6A71B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D5B9DA8712F752ULL,
		0x6172F2E099376909ULL,
		0xA6E8D38B1875A13EULL,
		0xF736141810B8E4BEULL,
		0xF7661E31408D92EDULL,
		0x0A7F69C7EF5E8A29ULL,
		0x8609D4B42A892163ULL,
		0x508CE5967AD4E363ULL
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
		0x02A0A7391B20F367ULL,
		0x79A829391F3EF0F0ULL,
		0x8F38C7EEF2BCEF81ULL,
		0x4C73C2A8A2763556ULL,
		0x335A82E626BE9955ULL,
		0x132818A7162ED6D1ULL,
		0x8A5927D54E918AA0ULL,
		0x14E040289419F5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05414E723641E6CEULL,
		0xF35052723E7DE1E0ULL,
		0x1E718FDDE579DF02ULL,
		0x98E7855144EC6AADULL,
		0x66B505CC4D7D32AAULL,
		0x2650314E2C5DADA2ULL,
		0x14B24FAA9D231540ULL,
		0x29C080512833EB85ULL
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
		0xF23CEE378B6551C3ULL,
		0xBCFB835F1891BCB6ULL,
		0xB3FA94CF2D0E9352ULL,
		0x4ABAFF1532614F3DULL,
		0x1FA0CDD28BD8048AULL,
		0x38EEBA8617DC5596ULL,
		0xD42C5078F0595751ULL,
		0x386A708E49B8741AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE479DC6F16CAA386ULL,
		0x79F706BE3123796DULL,
		0x67F5299E5A1D26A5ULL,
		0x9575FE2A64C29E7BULL,
		0x3F419BA517B00914ULL,
		0x71DD750C2FB8AB2CULL,
		0xA858A0F1E0B2AEA2ULL,
		0x70D4E11C9370E835ULL
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
		0x60C1600C23464299ULL,
		0x6193FACE68DAA575ULL,
		0x46FDFD726F3F17C7ULL,
		0xE4F0A13CF2086D21ULL,
		0x9FC85130AED151E0ULL,
		0xA28606CDAC50FF20ULL,
		0x4752442329491EA5ULL,
		0x04F01F48DB45A887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC182C018468C8532ULL,
		0xC327F59CD1B54AEAULL,
		0x8DFBFAE4DE7E2F8EULL,
		0xC9E14279E410DA42ULL,
		0x3F90A2615DA2A3C1ULL,
		0x450C0D9B58A1FE41ULL,
		0x8EA4884652923D4BULL,
		0x09E03E91B68B510EULL
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
		0xF828CF53F516E3BFULL,
		0x11CA1ED2FDDDA499ULL,
		0x5EA4374050B943FAULL,
		0xAA78F2A981B4CCA2ULL,
		0x7B433BE10DBCA8FCULL,
		0x25DBD62E2CF37B10ULL,
		0xC6F6374E58FC6775ULL,
		0x11F019A965E09AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0519EA7EA2DC77EULL,
		0x23943DA5FBBB4933ULL,
		0xBD486E80A17287F4ULL,
		0x54F1E55303699944ULL,
		0xF68677C21B7951F9ULL,
		0x4BB7AC5C59E6F620ULL,
		0x8DEC6E9CB1F8CEEAULL,
		0x23E03352CBC13573ULL
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
		0x02FF369820C9A671ULL,
		0x87CADC4FB564FCDFULL,
		0x556E9E65B6DF9DA6ULL,
		0x9B7DCF6A69497F8BULL,
		0x177F92B922BC1C6EULL,
		0xE3C161AD6D731F62ULL,
		0xFD1FD6A6CB3450A4ULL,
		0x2F8A8AE93CE938CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05FE6D3041934CE2ULL,
		0x0F95B89F6AC9F9BEULL,
		0xAADD3CCB6DBF3B4DULL,
		0x36FB9ED4D292FF16ULL,
		0x2EFF2572457838DDULL,
		0xC782C35ADAE63EC4ULL,
		0xFA3FAD4D9668A149ULL,
		0x5F1515D279D2719FULL
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
		0x33D69299A57986BAULL,
		0xBC6BFDB07733B3B4ULL,
		0xFD2951C7F0B54BEEULL,
		0x66642BD7247F6D95ULL,
		0x9D316A43B398140BULL,
		0x5150ABA760714CFEULL,
		0xF050A86C7061B0C2ULL,
		0x2D5DFF8E0CC6322EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AD25334AF30D74ULL,
		0x78D7FB60EE676768ULL,
		0xFA52A38FE16A97DDULL,
		0xCCC857AE48FEDB2BULL,
		0x3A62D48767302816ULL,
		0xA2A1574EC0E299FDULL,
		0xE0A150D8E0C36184ULL,
		0x5ABBFF1C198C645DULL
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
		0x40A767C60307B0B2ULL,
		0x3B61F5355B4E0993ULL,
		0xA899EA304CFDB3F5ULL,
		0xC18ED6E13A3AC836ULL,
		0x4B61A84948318426ULL,
		0x4B0247DE6E15B639ULL,
		0x525C1338CE1AD6F3ULL,
		0x3EAF87A1AFBB44DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814ECF8C060F6164ULL,
		0x76C3EA6AB69C1326ULL,
		0x5133D46099FB67EAULL,
		0x831DADC27475906DULL,
		0x96C350929063084DULL,
		0x96048FBCDC2B6C72ULL,
		0xA4B826719C35ADE6ULL,
		0x7D5F0F435F7689B8ULL
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
		0xC0115FC0AC6751C4ULL,
		0x683CC75D1C5B904FULL,
		0x35BD1B23E14843B5ULL,
		0x33928A5815BF1CBFULL,
		0x3B0CDB7C1F5DC96BULL,
		0xE1B189AD273A65C1ULL,
		0x2132CCE4CA59333EULL,
		0x26C3C176A6A6EC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8022BF8158CEA388ULL,
		0xD0798EBA38B7209FULL,
		0x6B7A3647C290876AULL,
		0x672514B02B7E397EULL,
		0x7619B6F83EBB92D6ULL,
		0xC363135A4E74CB82ULL,
		0x426599C994B2667DULL,
		0x4D8782ED4D4DD938ULL
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
		0x5AC93B290017EDF8ULL,
		0xE206A8C921429FECULL,
		0x8AA1FDFE2D99A33EULL,
		0x6A65F6D4AB36A39FULL,
		0x128B8CF12230DF06ULL,
		0xD4DAD18245DA19F6ULL,
		0xA3BF64F314D9C52AULL,
		0x2593F1FD6E8F7F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5927652002FDBF0ULL,
		0xC40D519242853FD8ULL,
		0x1543FBFC5B33467DULL,
		0xD4CBEDA9566D473FULL,
		0x251719E24461BE0CULL,
		0xA9B5A3048BB433ECULL,
		0x477EC9E629B38A55ULL,
		0x4B27E3FADD1EFE59ULL
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
		0x91DD85E801C688CCULL,
		0x758086D4FF8C8A23ULL,
		0x487ACD11971485F2ULL,
		0x0C5A5D83ED873D57ULL,
		0x988ACBCFF77952A0ULL,
		0x533003D888F85475ULL,
		0x1185719CAB5149A4ULL,
		0x14147FBA728C16F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BB0BD0038D1198ULL,
		0xEB010DA9FF191447ULL,
		0x90F59A232E290BE4ULL,
		0x18B4BB07DB0E7AAEULL,
		0x3115979FEEF2A540ULL,
		0xA66007B111F0A8EBULL,
		0x230AE33956A29348ULL,
		0x2828FF74E5182DEEULL
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
		0x9D2D1FC3BD9ADCA4ULL,
		0xF776E20D98391C43ULL,
		0x678535094C95DDC4ULL,
		0x82EE83210F343E30ULL,
		0xD3AE6DF018A62CDBULL,
		0x5EA0DBE18CF96F93ULL,
		0x0DD7419B27BB4C24ULL,
		0x31AC0FAA5A191478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5A3F877B35B948ULL,
		0xEEEDC41B30723887ULL,
		0xCF0A6A12992BBB89ULL,
		0x05DD06421E687C60ULL,
		0xA75CDBE0314C59B7ULL,
		0xBD41B7C319F2DF27ULL,
		0x1BAE83364F769848ULL,
		0x63581F54B43228F0ULL
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
		0xF34E84716CF626C4ULL,
		0xC4D8E2A08409DD94ULL,
		0x1EAA056BF1C3B3AAULL,
		0x072D4A2ECC4C6321ULL,
		0x23E0DBE403AF71F9ULL,
		0xE0D0B35B2BCD982CULL,
		0xE1F45F58DBBD946EULL,
		0x229D17A766E72BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE69D08E2D9EC4D88ULL,
		0x89B1C5410813BB29ULL,
		0x3D540AD7E3876755ULL,
		0x0E5A945D9898C642ULL,
		0x47C1B7C8075EE3F2ULL,
		0xC1A166B6579B3058ULL,
		0xC3E8BEB1B77B28DDULL,
		0x453A2F4ECDCE577BULL
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
		0xECE9ED2ED3A7A4AFULL,
		0xA7874F21E9AC41A8ULL,
		0x9B37050E880E352BULL,
		0x9105DDCE91BE6F0BULL,
		0x4D3ABACCFC6B3079ULL,
		0xE224C3D78FBF308CULL,
		0xE94C6DEC4D038B6DULL,
		0x3FC22850D0D7ADE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D3DA5DA74F495EULL,
		0x4F0E9E43D3588351ULL,
		0x366E0A1D101C6A57ULL,
		0x220BBB9D237CDE17ULL,
		0x9A757599F8D660F3ULL,
		0xC44987AF1F7E6118ULL,
		0xD298DBD89A0716DBULL,
		0x7F8450A1A1AF5BCFULL
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
		0x6689F93375F49BEBULL,
		0x1D30640FBCF24707ULL,
		0x8F0E8958A2FA7E4EULL,
		0xEDF7DAAC10ACF55CULL,
		0xC73B83516FF804DAULL,
		0x87E6D9222D0F82BCULL,
		0x60D6554896B43821ULL,
		0x2A3D3E961F63A108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD13F266EBE937D6ULL,
		0x3A60C81F79E48E0EULL,
		0x1E1D12B145F4FC9CULL,
		0xDBEFB5582159EAB9ULL,
		0x8E7706A2DFF009B5ULL,
		0x0FCDB2445A1F0579ULL,
		0xC1ACAA912D687043ULL,
		0x547A7D2C3EC74210ULL
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
		0x02695D13C584652DULL,
		0xED053B71BF5B975FULL,
		0xA9D33895BF64C20AULL,
		0x87285A9BA5395E0CULL,
		0x34D36A6BAD883F10ULL,
		0x861BF2F495EB440AULL,
		0xBE680052864C25D7ULL,
		0x32795DC6AA18C5E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04D2BA278B08CA5AULL,
		0xDA0A76E37EB72EBEULL,
		0x53A6712B7EC98415ULL,
		0x0E50B5374A72BC19ULL,
		0x69A6D4D75B107E21ULL,
		0x0C37E5E92BD68814ULL,
		0x7CD000A50C984BAFULL,
		0x64F2BB8D54318BCDULL
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
		0x1F12955FD5C33A62ULL,
		0xE7CA158756C51B14ULL,
		0x4FF4CB594A9735C2ULL,
		0xDC189984537FAB16ULL,
		0x72142EEBBED88E82ULL,
		0x7F8F85E3D9455002ULL,
		0x813AD12CF276C136ULL,
		0x1E913BB54DEFB94EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E252ABFAB8674C4ULL,
		0xCF942B0EAD8A3628ULL,
		0x9FE996B2952E6B85ULL,
		0xB8313308A6FF562CULL,
		0xE4285DD77DB11D05ULL,
		0xFF1F0BC7B28AA004ULL,
		0x0275A259E4ED826CULL,
		0x3D22776A9BDF729DULL
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
		0x551275CE8B7DF135ULL,
		0xCAEF4C998ACC0D39ULL,
		0x647AADD29262E0D8ULL,
		0x03D7CA3335674B0BULL,
		0x44DAFDAA6F786453ULL,
		0x66A0639DB00D76F8ULL,
		0xF7C93195A6AB6C16ULL,
		0x0DA7FD44A2E74635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA24EB9D16FBE26AULL,
		0x95DE993315981A72ULL,
		0xC8F55BA524C5C1B1ULL,
		0x07AF94666ACE9616ULL,
		0x89B5FB54DEF0C8A6ULL,
		0xCD40C73B601AEDF0ULL,
		0xEF92632B4D56D82CULL,
		0x1B4FFA8945CE8C6BULL
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
		0x271B585B2DFCE256ULL,
		0x9CD1DF920486CFF1ULL,
		0xF8459762F4FFF206ULL,
		0x1C2D1DEDBCDEEF47ULL,
		0xD3C622AC81A7FD4CULL,
		0xD1FE483B20CAF634ULL,
		0xDE3AB4D6F676DF27ULL,
		0x2CC1DC8C5D8AC9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E36B0B65BF9C4ACULL,
		0x39A3BF24090D9FE2ULL,
		0xF08B2EC5E9FFE40DULL,
		0x385A3BDB79BDDE8FULL,
		0xA78C4559034FFA98ULL,
		0xA3FC90764195EC69ULL,
		0xBC7569ADECEDBE4FULL,
		0x5983B918BB15935FULL
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
		0xFF3F90116FDAA1B8ULL,
		0x2E1F4F64F4B34B75ULL,
		0x7B310F8CBA98C6A1ULL,
		0x068B884332A26170ULL,
		0xB1C8AC5EC8B2AA02ULL,
		0xCB0236AB271A8D05ULL,
		0x5753DAC6461212F7ULL,
		0x36E207D2ECDBA01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7F2022DFB54370ULL,
		0x5C3E9EC9E96696EBULL,
		0xF6621F1975318D42ULL,
		0x0D1710866544C2E0ULL,
		0x639158BD91655404ULL,
		0x96046D564E351A0BULL,
		0xAEA7B58C8C2425EFULL,
		0x6DC40FA5D9B7403CULL
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
		0xBA46DB3F6A97C329ULL,
		0xAB74DBFA6E08A2CFULL,
		0xFF7095B79363D3F4ULL,
		0x13CFD7BEAED443DDULL,
		0x6C3F292F7C2D637DULL,
		0x558673F52B6B9793ULL,
		0xE6EE6C3455765FC5ULL,
		0x13479501A69FB242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x748DB67ED52F8652ULL,
		0x56E9B7F4DC11459FULL,
		0xFEE12B6F26C7A7E9ULL,
		0x279FAF7D5DA887BBULL,
		0xD87E525EF85AC6FAULL,
		0xAB0CE7EA56D72F26ULL,
		0xCDDCD868AAECBF8AULL,
		0x268F2A034D3F6485ULL
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
		0xE456DD041FC006F3ULL,
		0xD9807A36698659F9ULL,
		0xFB202DD8A34FFB71ULL,
		0x523D4BCFFA8F1949ULL,
		0xB7D47435104DE91CULL,
		0x0BE76C79E7AE3B15ULL,
		0x31AF374154FFB21EULL,
		0x02AE87579A93BB82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8ADBA083F800DE6ULL,
		0xB300F46CD30CB3F3ULL,
		0xF6405BB1469FF6E3ULL,
		0xA47A979FF51E3293ULL,
		0x6FA8E86A209BD238ULL,
		0x17CED8F3CF5C762BULL,
		0x635E6E82A9FF643CULL,
		0x055D0EAF35277704ULL
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
		0xDCED1A7F33584BCAULL,
		0x0336FDA82B400056ULL,
		0x8490402444728607ULL,
		0x8D6A2B29ED13702CULL,
		0x1008CBEFDE3B6518ULL,
		0xFB96BE3222DE336EULL,
		0x9DDFD9A670903FE9ULL,
		0x18873E6A7CD02673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DA34FE66B09794ULL,
		0x066DFB50568000ADULL,
		0x0920804888E50C0EULL,
		0x1AD45653DA26E059ULL,
		0x201197DFBC76CA31ULL,
		0xF72D7C6445BC66DCULL,
		0x3BBFB34CE1207FD3ULL,
		0x310E7CD4F9A04CE7ULL
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
		0x54625247FB07C1FFULL,
		0xB87376FA32557702ULL,
		0xF6543551F88D7206ULL,
		0x2C7E75831702DA66ULL,
		0xFE959D079F5AFE64ULL,
		0xB6FCC185AB8995E3ULL,
		0x94E3910953E67B53ULL,
		0x0419E8B4F0A3D49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8C4A48FF60F83FEULL,
		0x70E6EDF464AAEE04ULL,
		0xECA86AA3F11AE40DULL,
		0x58FCEB062E05B4CDULL,
		0xFD2B3A0F3EB5FCC8ULL,
		0x6DF9830B57132BC7ULL,
		0x29C72212A7CCF6A7ULL,
		0x0833D169E147A939ULL
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
		0xBD7F071F291768CBULL,
		0xBB5946A817208F29ULL,
		0xB0A393E475D1F21DULL,
		0x5FC578CB1157DCE7ULL,
		0x747A1942636535CDULL,
		0xD4EE221A04490078ULL,
		0x19A7D21732C43750ULL,
		0x3FF05306FC3D6F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFE0E3E522ED196ULL,
		0x76B28D502E411E53ULL,
		0x614727C8EBA3E43BULL,
		0xBF8AF19622AFB9CFULL,
		0xE8F43284C6CA6B9AULL,
		0xA9DC4434089200F0ULL,
		0x334FA42E65886EA1ULL,
		0x7FE0A60DF87ADEB4ULL
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
		0xBC93E2237C588DF8ULL,
		0xF7204CF092419797ULL,
		0xAB63D07A730993F4ULL,
		0x568016A7D651F331ULL,
		0x011E00B6F51D9272ULL,
		0xE1F67215E97BC10BULL,
		0x9C154FF6EE07E737ULL,
		0x24BE4B3BA08FCDD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7927C446F8B11BF0ULL,
		0xEE4099E124832F2FULL,
		0x56C7A0F4E61327E9ULL,
		0xAD002D4FACA3E663ULL,
		0x023C016DEA3B24E4ULL,
		0xC3ECE42BD2F78216ULL,
		0x382A9FEDDC0FCE6FULL,
		0x497C9677411F9BA5ULL
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
		0x2C9A4D355BBB6CE8ULL,
		0x0A25804BED82F80DULL,
		0xFD0C93AE671CA958ULL,
		0x69867AD20C9BC8C0ULL,
		0xE1E55195B28FFC7AULL,
		0x70304EB3D5B08E62ULL,
		0x34C7F46D50B2D81FULL,
		0x04BADBDAF6D470A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59349A6AB776D9D0ULL,
		0x144B0097DB05F01AULL,
		0xFA19275CCE3952B0ULL,
		0xD30CF5A419379181ULL,
		0xC3CAA32B651FF8F4ULL,
		0xE0609D67AB611CC5ULL,
		0x698FE8DAA165B03EULL,
		0x0975B7B5EDA8E144ULL
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
		0x9A55EA39B698A3B6ULL,
		0x08E4C9E97F4A417AULL,
		0xC07F1283BE9B4E66ULL,
		0xD9EC89DFF00804C7ULL,
		0x257977F92F418FCAULL,
		0x936E10591DA0E19DULL,
		0x778B5784D1A5EDE6ULL,
		0x1E3699376A32D5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34ABD4736D31476CULL,
		0x11C993D2FE9482F5ULL,
		0x80FE25077D369CCCULL,
		0xB3D913BFE010098FULL,
		0x4AF2EFF25E831F95ULL,
		0x26DC20B23B41C33AULL,
		0xEF16AF09A34BDBCDULL,
		0x3C6D326ED465ABC6ULL
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
		0x35280ACFCABF1C3CULL,
		0xBD0E1A947A89E711ULL,
		0x9C0E02A962687E96ULL,
		0x354E5A53876E464FULL,
		0x249137C8E6895B3AULL,
		0xCEB54C9589BAB370ULL,
		0x7D3287C102D7AC01ULL,
		0x18C253F5C105D421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A50159F957E3878ULL,
		0x7A1C3528F513CE22ULL,
		0x381C0552C4D0FD2DULL,
		0x6A9CB4A70EDC8C9FULL,
		0x49226F91CD12B674ULL,
		0x9D6A992B137566E0ULL,
		0xFA650F8205AF5803ULL,
		0x3184A7EB820BA842ULL
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
		0x9089E0F4A6C911CDULL,
		0x19A76D6132314E6EULL,
		0x2B875E8EF232C24EULL,
		0xF53B9FB5BD2B610DULL,
		0x677C9003D63F2098ULL,
		0x61C313E66DB0BB69ULL,
		0x99E57B40763D3370ULL,
		0x300E90E156309069ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2113C1E94D92239AULL,
		0x334EDAC264629CDDULL,
		0x570EBD1DE465849CULL,
		0xEA773F6B7A56C21AULL,
		0xCEF92007AC7E4131ULL,
		0xC38627CCDB6176D2ULL,
		0x33CAF680EC7A66E0ULL,
		0x601D21C2AC6120D3ULL
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
		0xC30214E6E4157644ULL,
		0x972D9A76F273B5B6ULL,
		0x59C6F6954D7EC312ULL,
		0x096613E856E9ECEFULL,
		0xEA4AC6826BBE13D4ULL,
		0x376D0BE618785910ULL,
		0xC5DA961BB1BAB4B7ULL,
		0x0DFDEC41618D5B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860429CDC82AEC88ULL,
		0x2E5B34EDE4E76B6DULL,
		0xB38DED2A9AFD8625ULL,
		0x12CC27D0ADD3D9DEULL,
		0xD4958D04D77C27A8ULL,
		0x6EDA17CC30F0B221ULL,
		0x8BB52C376375696EULL,
		0x1BFBD882C31AB6A7ULL
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
		0x954855CACF0AA7E5ULL,
		0x6FDD20D631D981ADULL,
		0x7B1E4045ABA4887EULL,
		0x61D94BBDF4CDA5F4ULL,
		0x706F043C95ACF60CULL,
		0x10445DAA32B5510FULL,
		0x261ACB7583B534C7ULL,
		0x1538E8CE3BB2BDE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A90AB959E154FCAULL,
		0xDFBA41AC63B3035BULL,
		0xF63C808B574910FCULL,
		0xC3B2977BE99B4BE8ULL,
		0xE0DE08792B59EC18ULL,
		0x2088BB54656AA21EULL,
		0x4C3596EB076A698EULL,
		0x2A71D19C77657BC2ULL
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
		0xA6B6E8856498FC83ULL,
		0xBB0336B47C95DECDULL,
		0x70EF9C906FFED695ULL,
		0x8AF1A0499A085FFEULL,
		0xF8E7615C104B229EULL,
		0x7D023799A2AAFB63ULL,
		0x3166B84475C28EB0ULL,
		0x1EB3D1D8271B5F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6DD10AC931F906ULL,
		0x76066D68F92BBD9BULL,
		0xE1DF3920DFFDAD2BULL,
		0x15E340933410BFFCULL,
		0xF1CEC2B82096453DULL,
		0xFA046F334555F6C7ULL,
		0x62CD7088EB851D60ULL,
		0x3D67A3B04E36BF28ULL
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
		0xDE1316302FA3CE5DULL,
		0xB9F55169694E7EF6ULL,
		0x6BDEFA3017143BC7ULL,
		0x25E4CFE572629007ULL,
		0xBE893C3C8D26B637ULL,
		0x929AD9488B3B89CCULL,
		0xA385C9E4CB144CD9ULL,
		0x0634F5C96CD5485DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC262C605F479CBAULL,
		0x73EAA2D2D29CFDEDULL,
		0xD7BDF4602E28778FULL,
		0x4BC99FCAE4C5200EULL,
		0x7D1278791A4D6C6EULL,
		0x2535B29116771399ULL,
		0x470B93C9962899B3ULL,
		0x0C69EB92D9AA90BBULL
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
		0x2EB8A2BF18F8B35BULL,
		0xEA933777AED996ADULL,
		0xB6A2E6052E4EABE7ULL,
		0x47651565B98E7BD8ULL,
		0xA952AAF3F7CAD06BULL,
		0xCFC45CF0B33833E4ULL,
		0x9C81A53E01B31F09ULL,
		0x308E84452D428847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D71457E31F166B6ULL,
		0xD5266EEF5DB32D5AULL,
		0x6D45CC0A5C9D57CFULL,
		0x8ECA2ACB731CF7B1ULL,
		0x52A555E7EF95A0D6ULL,
		0x9F88B9E1667067C9ULL,
		0x39034A7C03663E13ULL,
		0x611D088A5A85108FULL
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
		0xD1FF4BEEDA5BB43EULL,
		0xA343383CDE352912ULL,
		0x6DDDBEB911F4202DULL,
		0xB8219F45D9EF90E8ULL,
		0x7D484F19A0B8148AULL,
		0x65CB0364FE627961ULL,
		0x16756F6D55DCC726ULL,
		0x33A73E18B311EC43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3FE97DDB4B7687CULL,
		0x46867079BC6A5225ULL,
		0xDBBB7D7223E8405BULL,
		0x70433E8BB3DF21D0ULL,
		0xFA909E3341702915ULL,
		0xCB9606C9FCC4F2C2ULL,
		0x2CEADEDAABB98E4CULL,
		0x674E7C316623D886ULL
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
		0x61A32F6D0BEDBD92ULL,
		0xF68F7494927CCAD3ULL,
		0xA991A9E95278DA6CULL,
		0x04D6D9BD2DE17743ULL,
		0xF7F43482202C67C5ULL,
		0x155F6165BBF6F136ULL,
		0xE2EF605B589CC774ULL,
		0x30CE02C68851F8F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3465EDA17DB7B24ULL,
		0xED1EE92924F995A6ULL,
		0x532353D2A4F1B4D9ULL,
		0x09ADB37A5BC2EE87ULL,
		0xEFE869044058CF8AULL,
		0x2ABEC2CB77EDE26DULL,
		0xC5DEC0B6B1398EE8ULL,
		0x619C058D10A3F1E1ULL
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
		0x87D3B8692116A0CCULL,
		0x0424A1BE6A1FED78ULL,
		0x14E394ACD543876BULL,
		0x2B747DFC5F6ABEE4ULL,
		0x7989C2FC3BF17E6EULL,
		0x7492161C6736F213ULL,
		0xF38ADFB6B8899EFFULL,
		0x2036F3C9A655B784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA770D2422D4198ULL,
		0x0849437CD43FDAF1ULL,
		0x29C72959AA870ED6ULL,
		0x56E8FBF8BED57DC8ULL,
		0xF31385F877E2FCDCULL,
		0xE9242C38CE6DE426ULL,
		0xE715BF6D71133DFEULL,
		0x406DE7934CAB6F09ULL
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
		0xCDE0C5353B8BC52FULL,
		0xD55F4C0AB66F233DULL,
		0x8E69DDD7B5C5AE68ULL,
		0x41F0506DE507E00CULL,
		0x1B2F0EE058A43661ULL,
		0x5E06E924F39DB1E5ULL,
		0xB49678B203232D1AULL,
		0x2852B5B5D83857A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC18A6A77178A5EULL,
		0xAABE98156CDE467BULL,
		0x1CD3BBAF6B8B5CD1ULL,
		0x83E0A0DBCA0FC019ULL,
		0x365E1DC0B1486CC2ULL,
		0xBC0DD249E73B63CAULL,
		0x692CF16406465A34ULL,
		0x50A56B6BB070AF45ULL
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
		0x5C3729406645A554ULL,
		0xD4D19A52D0C8A8F4ULL,
		0x2CE84550FC378886ULL,
		0x40CB9677E3823E64ULL,
		0x96EE97E8DE90FDB5ULL,
		0x12AF996E1C19729EULL,
		0xA134F4AD1F5DBBE2ULL,
		0x13B3BF043ECD1966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86E5280CC8B4AA8ULL,
		0xA9A334A5A19151E8ULL,
		0x59D08AA1F86F110DULL,
		0x81972CEFC7047CC8ULL,
		0x2DDD2FD1BD21FB6AULL,
		0x255F32DC3832E53DULL,
		0x4269E95A3EBB77C4ULL,
		0x27677E087D9A32CDULL
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
		0x29622CBFA34157ABULL,
		0x509C4E36F2E68EC8ULL,
		0x575B889E733620CEULL,
		0xD60024AB5E9110BCULL,
		0x7970E8973307EB34ULL,
		0x08738A0EEE016C45ULL,
		0xED228C6D9E99BC2BULL,
		0x10F2FD2157B8DDF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C4597F4682AF56ULL,
		0xA1389C6DE5CD1D90ULL,
		0xAEB7113CE66C419CULL,
		0xAC004956BD222178ULL,
		0xF2E1D12E660FD669ULL,
		0x10E7141DDC02D88AULL,
		0xDA4518DB3D337856ULL,
		0x21E5FA42AF71BBE1ULL
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
		0xA3C29C2E774A749BULL,
		0x66A1FFF0A3B37807ULL,
		0xAEDC48C46489709FULL,
		0x96E59F0E3DF02BF8ULL,
		0x70EE348EA54EB71BULL,
		0x0AB1979CF3890111ULL,
		0x6F61D31742BCF538ULL,
		0x336737F34A5B1AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4785385CEE94E936ULL,
		0xCD43FFE14766F00FULL,
		0x5DB89188C912E13EULL,
		0x2DCB3E1C7BE057F1ULL,
		0xE1DC691D4A9D6E37ULL,
		0x15632F39E7120222ULL,
		0xDEC3A62E8579EA70ULL,
		0x66CE6FE694B635E8ULL
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
		0x9132110BCDFCC807ULL,
		0xC43D4CD1794C6826ULL,
		0xE1F5A1DF8145C0F2ULL,
		0x7017D223DC544EC2ULL,
		0x2DECDEBC878A0FA9ULL,
		0x44D7315FDD11BB3BULL,
		0x3C7F44AA875ABD48ULL,
		0x1CE4B8EBC8ECD0A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x226422179BF9900EULL,
		0x887A99A2F298D04DULL,
		0xC3EB43BF028B81E5ULL,
		0xE02FA447B8A89D85ULL,
		0x5BD9BD790F141F52ULL,
		0x89AE62BFBA237676ULL,
		0x78FE89550EB57A90ULL,
		0x39C971D791D9A144ULL
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
		0xAE2FAED58895630DULL,
		0x5A27255552C9B3BFULL,
		0xC92FC2476DFBD79CULL,
		0x3235360FB363D342ULL,
		0x585C3C0FEEB2911BULL,
		0x248EA158C9682B0DULL,
		0xCDDF579B337C4FF3ULL,
		0x03EF07EEE6667C64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5F5DAB112AC61AULL,
		0xB44E4AAAA593677FULL,
		0x925F848EDBF7AF38ULL,
		0x646A6C1F66C7A685ULL,
		0xB0B8781FDD652236ULL,
		0x491D42B192D0561AULL,
		0x9BBEAF3666F89FE6ULL,
		0x07DE0FDDCCCCF8C9ULL
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
		0xFBCBB254C743DE3AULL,
		0xA0CE9B3ABB486EC5ULL,
		0xC97C88909A5A0AAFULL,
		0x4500DB2DE48C3F04ULL,
		0x0F0AA041D707925FULL,
		0x22B3DDAAAE163693ULL,
		0x98BE6AD28AC0A759ULL,
		0x1E22BF506DB916C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79764A98E87BC74ULL,
		0x419D36757690DD8BULL,
		0x92F9112134B4155FULL,
		0x8A01B65BC9187E09ULL,
		0x1E154083AE0F24BEULL,
		0x4567BB555C2C6D26ULL,
		0x317CD5A515814EB2ULL,
		0x3C457EA0DB722D89ULL
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
		0x602D454E859AD03DULL,
		0x10207B0EFE0242AEULL,
		0x3D06105F5F70040BULL,
		0x5EDC655FB031CAC3ULL,
		0x1C9D0D1141CD89B6ULL,
		0x955DC194AA377A7FULL,
		0x480332ED69F4812FULL,
		0x0FD54A9399D91A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC05A8A9D0B35A07AULL,
		0x2040F61DFC04855CULL,
		0x7A0C20BEBEE00816ULL,
		0xBDB8CABF60639586ULL,
		0x393A1A22839B136CULL,
		0x2ABB8329546EF4FEULL,
		0x900665DAD3E9025FULL,
		0x1FAA952733B2346CULL
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
		0xAA9FC60AA6B8096AULL,
		0x04B6046D79400CE4ULL,
		0x5C934CD9228F2C00ULL,
		0x8E862D5E6E9B855AULL,
		0x1415C7A798597FB5ULL,
		0xBF7CD3E09AADCB51ULL,
		0xB036D194CF37F3F6ULL,
		0x0D918D9F089D326BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x553F8C154D7012D4ULL,
		0x096C08DAF28019C9ULL,
		0xB92699B2451E5800ULL,
		0x1D0C5ABCDD370AB4ULL,
		0x282B8F4F30B2FF6BULL,
		0x7EF9A7C1355B96A2ULL,
		0x606DA3299E6FE7EDULL,
		0x1B231B3E113A64D7ULL
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
		0x568AFC1C344D7FECULL,
		0xA87C8B994E38A53DULL,
		0x9D2FBB068CCC98A1ULL,
		0x312A2D5F0F36C7CEULL,
		0x7F3C8497D20DF35BULL,
		0x09327FE6273447F1ULL,
		0x5752644557079942ULL,
		0x2405C93B4916CF2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD15F838689AFFD8ULL,
		0x50F917329C714A7AULL,
		0x3A5F760D19993143ULL,
		0x62545ABE1E6D8F9DULL,
		0xFE79092FA41BE6B6ULL,
		0x1264FFCC4E688FE2ULL,
		0xAEA4C88AAE0F3284ULL,
		0x480B9276922D9E5CULL
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
		0x9FE9524CA68F1AABULL,
		0xB08D8C23237081E8ULL,
		0x6B3B62B52C08CD71ULL,
		0xE68947DAA41536F9ULL,
		0xE6469D23B21917C2ULL,
		0x860CFC5DF78D6605ULL,
		0x8E868F0C1385F201ULL,
		0x1135D1D3BF8D7D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD2A4994D1E3556ULL,
		0x611B184646E103D1ULL,
		0xD676C56A58119AE3ULL,
		0xCD128FB5482A6DF2ULL,
		0xCC8D3A4764322F85ULL,
		0x0C19F8BBEF1ACC0BULL,
		0x1D0D1E18270BE403ULL,
		0x226BA3A77F1AFA31ULL
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
		0xDD0B4BFCC6BDF3F7ULL,
		0x623B32B44BE513B9ULL,
		0x693B8A4AEBB69E72ULL,
		0x8C17ED6A32D13652ULL,
		0x18D3AB427B9441D4ULL,
		0xEB933EB135B4F2AAULL,
		0x75BC9EF517BFB21AULL,
		0x1451868A63731FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1697F98D7BE7EEULL,
		0xC476656897CA2773ULL,
		0xD2771495D76D3CE4ULL,
		0x182FDAD465A26CA4ULL,
		0x31A75684F72883A9ULL,
		0xD7267D626B69E554ULL,
		0xEB793DEA2F7F6435ULL,
		0x28A30D14C6E63FFAULL
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
		0x3B1E622645D1C7C0ULL,
		0x1D229258B33629AAULL,
		0xDC5E4FAC055B9827ULL,
		0x8EDDC4BCDB2C4AB1ULL,
		0x3FAEDCC6B788E622ULL,
		0x228E604177AC9307ULL,
		0x7718ABBBEFFEAA77ULL,
		0x0252646F2993FD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763CC44C8BA38F80ULL,
		0x3A4524B1666C5354ULL,
		0xB8BC9F580AB7304EULL,
		0x1DBB8979B6589563ULL,
		0x7F5DB98D6F11CC45ULL,
		0x451CC082EF59260EULL,
		0xEE315777DFFD54EEULL,
		0x04A4C8DE5327FB3AULL
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
		0x811A21696B05E3B9ULL,
		0xCDB6FDC01311335AULL,
		0xB3F22AD3D62EBD36ULL,
		0xAB4064E2D11EBD0BULL,
		0xBA568E4D9AB14EFFULL,
		0x892F83D95FF089E3ULL,
		0x715BBAC3667A9FD2ULL,
		0x06AEDBF4813DE07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023442D2D60BC772ULL,
		0x9B6DFB80262266B5ULL,
		0x67E455A7AC5D7A6DULL,
		0x5680C9C5A23D7A17ULL,
		0x74AD1C9B35629DFFULL,
		0x125F07B2BFE113C7ULL,
		0xE2B77586CCF53FA5ULL,
		0x0D5DB7E9027BC0FCULL
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
		0x486634603D54D742ULL,
		0x590C9E1AEC278233ULL,
		0x3CB4A870F1930B08ULL,
		0x08B5AB0C8C193215ULL,
		0x7797E090132ECEC7ULL,
		0x7E9EDAB9FF0A82B5ULL,
		0xC9BFD24DE56B8227ULL,
		0x1EA3156ECE5757F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90CC68C07AA9AE84ULL,
		0xB2193C35D84F0466ULL,
		0x796950E1E3261610ULL,
		0x116B56191832642AULL,
		0xEF2FC120265D9D8EULL,
		0xFD3DB573FE15056AULL,
		0x937FA49BCAD7044EULL,
		0x3D462ADD9CAEAFF1ULL
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
		0xF010903C0FCEA26CULL,
		0xEF949058610D72EFULL,
		0x976C692FF8E184B1ULL,
		0x78C0EF29AB29F44DULL,
		0x745557E790B0B6C9ULL,
		0x22F1AD6B56EEFB53ULL,
		0xD134A6BDF5950181ULL,
		0x08E1A3FC75332473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02120781F9D44D8ULL,
		0xDF2920B0C21AE5DFULL,
		0x2ED8D25FF1C30963ULL,
		0xF181DE535653E89BULL,
		0xE8AAAFCF21616D92ULL,
		0x45E35AD6ADDDF6A6ULL,
		0xA2694D7BEB2A0302ULL,
		0x11C347F8EA6648E7ULL
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
		0x2DE2C1A990321668ULL,
		0xCAA56FFB39406DE9ULL,
		0x542A4C5A0BB46073ULL,
		0xADBE01D5E40E2AFAULL,
		0x4C6F2DF2AEFF7098ULL,
		0x55B734F3A9F98E6CULL,
		0x30A0A114BAE96ADCULL,
		0x21EF9E5A390EA9A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC5835320642CD0ULL,
		0x954ADFF67280DBD2ULL,
		0xA85498B41768C0E7ULL,
		0x5B7C03ABC81C55F4ULL,
		0x98DE5BE55DFEE131ULL,
		0xAB6E69E753F31CD8ULL,
		0x6141422975D2D5B8ULL,
		0x43DF3CB4721D5350ULL
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
		0xFAF978B2B36FD673ULL,
		0xCB4F64A0DD2E2D0FULL,
		0x6B86C5AE6EAC3F6EULL,
		0xBB5F8FB9D3F7A564ULL,
		0xD21E97EA939F4723ULL,
		0x21AFA0361717A73BULL,
		0x35561DB5C2833824ULL,
		0x3F5292EC8A7D0B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F2F16566DFACE6ULL,
		0x969EC941BA5C5A1FULL,
		0xD70D8B5CDD587EDDULL,
		0x76BF1F73A7EF4AC8ULL,
		0xA43D2FD5273E8E47ULL,
		0x435F406C2E2F4E77ULL,
		0x6AAC3B6B85067048ULL,
		0x7EA525D914FA168AULL
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
		0x9AD08CDA329701E6ULL,
		0xB2EA70AB263152B6ULL,
		0xD6BC213A22965684ULL,
		0x4EC28D95E78A4596ULL,
		0x73BB01CDE18827C7ULL,
		0x0DED37A71840D86CULL,
		0x6F56D4A535CCB20EULL,
		0x00865561D317C5F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A119B4652E03CCULL,
		0x65D4E1564C62A56DULL,
		0xAD784274452CAD09ULL,
		0x9D851B2BCF148B2DULL,
		0xE776039BC3104F8EULL,
		0x1BDA6F4E3081B0D8ULL,
		0xDEADA94A6B99641CULL,
		0x010CAAC3A62F8BEAULL
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
		0xC02981FB884F8428ULL,
		0x6FD304495A2EE958ULL,
		0x3D85011D18E4FE57ULL,
		0xD98B7D528E4AA4BDULL,
		0x6AFD9BA6B859E074ULL,
		0xCD4DC439DE592236ULL,
		0xD5A187501EE5380DULL,
		0x341C8EE50924CC43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805303F7109F0850ULL,
		0xDFA60892B45DD2B1ULL,
		0x7B0A023A31C9FCAEULL,
		0xB316FAA51C95497AULL,
		0xD5FB374D70B3C0E9ULL,
		0x9A9B8873BCB2446CULL,
		0xAB430EA03DCA701BULL,
		0x68391DCA12499887ULL
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
	return 0;
}