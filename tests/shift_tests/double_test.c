#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x1BE2817ADBDD9997ULL,
		0x57133FD9ABC70E89ULL,
		0x36EA5D553765BD1BULL,
		0xCF42D31ABFD8FF10ULL,
		0xDD1A30A3F515F307ULL,
		0x9E85DD943B1A8BA9ULL,
		0x9038B872F1F17DBEULL,
		0x187BD0106A1C0457ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x37C502F5B7BB332EULL,
		0xAE267FB3578E1D12ULL,
		0x6DD4BAAA6ECB7A36ULL,
		0x9E85A6357FB1FE20ULL,
		0xBA346147EA2BE60FULL,
		0x3D0BBB2876351753ULL,
		0x207170E5E3E2FB7DULL,
		0x30F7A020D43808AFULL
	}};
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
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
		0x0DF8EBCAB6A7C996ULL,
		0xE9E71EB10EB0F7AEULL,
		0x933F1A4F2ACA88D8ULL,
		0xC6D2A5BBED53DE18ULL,
		0x21357B5A389EB577ULL,
		0x964BED3E55439DECULL,
		0x00870A84180A5DD1ULL,
		0x258C1BF3CB97C28CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BF1D7956D4F932CULL,
		0xD3CE3D621D61EF5CULL,
		0x267E349E559511B1ULL,
		0x8DA54B77DAA7BC31ULL,
		0x426AF6B4713D6AEFULL,
		0x2C97DA7CAA873BD8ULL,
		0x010E15083014BBA3ULL,
		0x4B1837E7972F8518ULL
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
		0x1DC52A30E034EA22ULL,
		0x42A85D4DC9F7FAFCULL,
		0x773C77CB759BBEE0ULL,
		0x4D9BD427E4E33F77ULL,
		0x13005512D660AA1FULL,
		0x37A5E0792C5F647CULL,
		0x8CE9CAC446A82C34ULL,
		0x0EE29620E7383254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8A5461C069D444ULL,
		0x8550BA9B93EFF5F8ULL,
		0xEE78EF96EB377DC0ULL,
		0x9B37A84FC9C67EEEULL,
		0x2600AA25ACC1543EULL,
		0x6F4BC0F258BEC8F8ULL,
		0x19D395888D505868ULL,
		0x1DC52C41CE7064A9ULL
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
		0x8621141B2AAD171CULL,
		0xDADEFA539305E575ULL,
		0xD514922684777A44ULL,
		0xEAD41CCDE64DB20BULL,
		0x02DF8EDE363F7139ULL,
		0x9B19859901FC61FEULL,
		0x3F2CBD7DED9A16FCULL,
		0x26CF1D1C38C18EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C422836555A2E38ULL,
		0xB5BDF4A7260BCAEBULL,
		0xAA29244D08EEF489ULL,
		0xD5A8399BCC9B6417ULL,
		0x05BF1DBC6C7EE273ULL,
		0x36330B3203F8C3FCULL,
		0x7E597AFBDB342DF9ULL,
		0x4D9E3A3871831D58ULL
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
		0xAE330E35B20DDBD4ULL,
		0x0056972874BCDEC7ULL,
		0x03F1F1CE9AAE5501ULL,
		0x73F19FC36D5FD561ULL,
		0x8A6954E103F34159ULL,
		0x73CE80BCA3B68627ULL,
		0xFB961A8DD736397EULL,
		0x27B041710C0BB360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C661C6B641BB7A8ULL,
		0x00AD2E50E979BD8FULL,
		0x07E3E39D355CAA02ULL,
		0xE7E33F86DABFAAC2ULL,
		0x14D2A9C207E682B2ULL,
		0xE79D0179476D0C4FULL,
		0xF72C351BAE6C72FCULL,
		0x4F6082E2181766C1ULL
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
		0x6ADB453BB3436857ULL,
		0xC21818A1F05AF267ULL,
		0x15DC76AC08B7FD82ULL,
		0xEE904037FAD1EF99ULL,
		0x2651A827A0C50D30ULL,
		0xC35BB859120A30CBULL,
		0x6599A6E11A265C82ULL,
		0x0DC58D27C44D740FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B68A776686D0AEULL,
		0x84303143E0B5E4CEULL,
		0x2BB8ED58116FFB05ULL,
		0xDD20806FF5A3DF32ULL,
		0x4CA3504F418A1A61ULL,
		0x86B770B224146196ULL,
		0xCB334DC2344CB905ULL,
		0x1B8B1A4F889AE81EULL
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
		0x47C382C7FCD3D296ULL,
		0xC7DA7ACE36DB7FB8ULL,
		0x56296590A48D21DBULL,
		0xE265C3329BF5063FULL,
		0x70597719FC5A175DULL,
		0x788AF0F021E9BB88ULL,
		0xE108CD5ABA75CAC3ULL,
		0x01B1E302282919FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F87058FF9A7A52CULL,
		0x8FB4F59C6DB6FF70ULL,
		0xAC52CB21491A43B7ULL,
		0xC4CB866537EA0C7EULL,
		0xE0B2EE33F8B42EBBULL,
		0xF115E1E043D37710ULL,
		0xC2119AB574EB9586ULL,
		0x0363C604505233FDULL
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
		0x4DA5A2B2FD05D1BBULL,
		0xBE50DE4A5A633C10ULL,
		0xAB76EC83565DA54BULL,
		0x92F43F22B486C10AULL,
		0xC8BA3A53E74F4A10ULL,
		0x3BA6D1BED96B937BULL,
		0xB0A98B7D1243D2E1ULL,
		0x3F99F67031D341E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B4B4565FA0BA376ULL,
		0x7CA1BC94B4C67820ULL,
		0x56EDD906ACBB4A97ULL,
		0x25E87E45690D8215ULL,
		0x917474A7CE9E9421ULL,
		0x774DA37DB2D726F7ULL,
		0x615316FA2487A5C2ULL,
		0x7F33ECE063A683C5ULL
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
		0x518DFE3DEBED21B8ULL,
		0x1A6FD4D12CD23486ULL,
		0x75D086AAECB6BE90ULL,
		0xC4B10A0C49DA18E5ULL,
		0x78A7A5CFA0B03C6EULL,
		0xF82627F4649CA90EULL,
		0x87E5E8BC64C83BB5ULL,
		0x147480A519D89D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA31BFC7BD7DA4370ULL,
		0x34DFA9A259A4690CULL,
		0xEBA10D55D96D7D20ULL,
		0x8962141893B431CAULL,
		0xF14F4B9F416078DDULL,
		0xF04C4FE8C939521CULL,
		0x0FCBD178C990776BULL,
		0x28E9014A33B13B15ULL
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
		0xC0791DFF6825B501ULL,
		0xF85C4E6B6369EC28ULL,
		0xA40215CF4DEFAFDDULL,
		0x8A043ED8D0EAAE93ULL,
		0xAE944A7A2E6F772FULL,
		0x0CF4AA82E8BDE898ULL,
		0x05DE17C56A5FB011ULL,
		0x121651BD452BD725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F23BFED04B6A02ULL,
		0xF0B89CD6C6D3D851ULL,
		0x48042B9E9BDF5FBBULL,
		0x14087DB1A1D55D27ULL,
		0x5D2894F45CDEEE5FULL,
		0x19E95505D17BD131ULL,
		0x0BBC2F8AD4BF6022ULL,
		0x242CA37A8A57AE4AULL
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
		0xFF4FA9D297F2F2DAULL,
		0x4E64F3814C55AED9ULL,
		0x37D16E4B8212B138ULL,
		0x13DFB22458B1C1A1ULL,
		0x17B8FCA1C6655E56ULL,
		0x3E935070B89D86A3ULL,
		0xCBA9945FBABB1E4DULL,
		0x2BB97EDAB8F98F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE9F53A52FE5E5B4ULL,
		0x9CC9E70298AB5DB3ULL,
		0x6FA2DC9704256270ULL,
		0x27BF6448B1638342ULL,
		0x2F71F9438CCABCACULL,
		0x7D26A0E1713B0D46ULL,
		0x975328BF75763C9AULL,
		0x5772FDB571F31E6BULL
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
		0xE25BC9B13175D241ULL,
		0x335434A4549685F5ULL,
		0x25A52E1292D8E2C3ULL,
		0x8ADAFD9584206DEAULL,
		0xD5201C10E398D734ULL,
		0xFD173484DAE98CB8ULL,
		0x68E77E77F19DD56AULL,
		0x352AB75EAEAC0A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B7936262EBA482ULL,
		0x66A86948A92D0BEBULL,
		0x4B4A5C2525B1C586ULL,
		0x15B5FB2B0840DBD4ULL,
		0xAA403821C731AE69ULL,
		0xFA2E6909B5D31971ULL,
		0xD1CEFCEFE33BAAD5ULL,
		0x6A556EBD5D581422ULL
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
		0xB9199B7863CE8B3AULL,
		0x5094D39BEA2B5B9CULL,
		0x4EE8A673E0545A09ULL,
		0x0D5563BF566EA81AULL,
		0xD7A368BBB0E9170AULL,
		0x484CE5C73C981798ULL,
		0xE7BD609043E9DBD4ULL,
		0x0E38F130A80B4B5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x723336F0C79D1674ULL,
		0xA129A737D456B739ULL,
		0x9DD14CE7C0A8B412ULL,
		0x1AAAC77EACDD5034ULL,
		0xAF46D17761D22E14ULL,
		0x9099CB8E79302F31ULL,
		0xCF7AC12087D3B7A8ULL,
		0x1C71E261501696BDULL
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
		0x503C4D19C0B748E8ULL,
		0xFBBD0C48F0097995ULL,
		0x9A742D9B9B40C67DULL,
		0x5E7C94B460078950ULL,
		0x538CD1C9E451F8E9ULL,
		0x10E0708FD0CA41D7ULL,
		0x9E8D4007DFE0FC7AULL,
		0x3F084597BB176844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0789A33816E91D0ULL,
		0xF77A1891E012F32AULL,
		0x34E85B3736818CFBULL,
		0xBCF92968C00F12A1ULL,
		0xA719A393C8A3F1D2ULL,
		0x21C0E11FA19483AEULL,
		0x3D1A800FBFC1F8F4ULL,
		0x7E108B2F762ED089ULL
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
		0x6A849FB325D15BAAULL,
		0xE2A71910941CAD45ULL,
		0xB8267FC27259923CULL,
		0xA22EA22C4D62D66AULL,
		0x91495EC329DFAD27ULL,
		0x7B2A9E2EEE0815F8ULL,
		0x761D6A8157C814BEULL,
		0x337E37F21FBC6230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5093F664BA2B754ULL,
		0xC54E322128395A8AULL,
		0x704CFF84E4B32479ULL,
		0x445D44589AC5ACD5ULL,
		0x2292BD8653BF5A4FULL,
		0xF6553C5DDC102BF1ULL,
		0xEC3AD502AF90297CULL,
		0x66FC6FE43F78C460ULL
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
		0xEC28B1F2DAC15AA8ULL,
		0xAFC93CE25DE73EF2ULL,
		0xA235519F1D99DAE4ULL,
		0xD4E730CF17DF64A5ULL,
		0x22F3E4F160A1FAC8ULL,
		0xB56B06477006A0F7ULL,
		0x980C7BEBA3533FACULL,
		0x16AD025DEECB3620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85163E5B582B550ULL,
		0x5F9279C4BBCE7DE5ULL,
		0x446AA33E3B33B5C9ULL,
		0xA9CE619E2FBEC94BULL,
		0x45E7C9E2C143F591ULL,
		0x6AD60C8EE00D41EEULL,
		0x3018F7D746A67F59ULL,
		0x2D5A04BBDD966C41ULL
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
		0xD26094C092A8EA1CULL,
		0x92EB4AEF6BE89492ULL,
		0x91791899FA1249CCULL,
		0xEC935CB4314F48B6ULL,
		0x7DD38E49DEBEC9BDULL,
		0xA1B953BC785F2C71ULL,
		0x4174D8B3BAE1EEACULL,
		0x10FEAE1FAD8C2454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4C129812551D438ULL,
		0x25D695DED7D12925ULL,
		0x22F23133F4249399ULL,
		0xD926B968629E916DULL,
		0xFBA71C93BD7D937BULL,
		0x4372A778F0BE58E2ULL,
		0x82E9B16775C3DD59ULL,
		0x21FD5C3F5B1848A8ULL
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
		0x5652F2DB8AD2F650ULL,
		0xD576385F725EAB48ULL,
		0xA215C1C8D81BA574ULL,
		0x6B4EF46F644AC5ACULL,
		0xA4D74D4DEF312C8AULL,
		0xE5C0E59778AC0EE1ULL,
		0xB2B4A892E76E959CULL,
		0x1AA6B401F6F3F95DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA5E5B715A5ECA0ULL,
		0xAAEC70BEE4BD5690ULL,
		0x442B8391B0374AE9ULL,
		0xD69DE8DEC8958B59ULL,
		0x49AE9A9BDE625914ULL,
		0xCB81CB2EF1581DC3ULL,
		0x65695125CEDD2B39ULL,
		0x354D6803EDE7F2BBULL
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
		0x86A1313A398CC1B9ULL,
		0x122431A9C66756C1ULL,
		0x0EAEDD76E63465EDULL,
		0xBF7DF4562A5FE7A4ULL,
		0xB673AACF72A2C644ULL,
		0x5994AFD0C250D338ULL,
		0x4582777E76264A5FULL,
		0x0308DB264DA689D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D42627473198372ULL,
		0x244863538CCEAD83ULL,
		0x1D5DBAEDCC68CBDAULL,
		0x7EFBE8AC54BFCF48ULL,
		0x6CE7559EE5458C89ULL,
		0xB3295FA184A1A671ULL,
		0x8B04EEFCEC4C94BEULL,
		0x0611B64C9B4D13B0ULL
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
		0x6D6B7CE5A26467E8ULL,
		0x8C244BF8D2A2E14FULL,
		0xAEE82A74EEA1D73FULL,
		0x4B283C1590DB6C48ULL,
		0x1D8489A418E19046ULL,
		0x3B4B50A6A580754CULL,
		0x914B65F48A7052AAULL,
		0x1A2ED056D0227770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD6F9CB44C8CFD0ULL,
		0x184897F1A545C29EULL,
		0x5DD054E9DD43AE7FULL,
		0x9650782B21B6D891ULL,
		0x3B09134831C3208CULL,
		0x7696A14D4B00EA98ULL,
		0x2296CBE914E0A554ULL,
		0x345DA0ADA044EEE1ULL
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
		0x70848E0A15876251ULL,
		0x30C818E8FD8D65CDULL,
		0x47C82A9E24120DAEULL,
		0x3A2DF49B98E1D90BULL,
		0x27DAA34849FD7302ULL,
		0x73F2CCE360D7C8E4ULL,
		0xD41C1E04ADEDFB51ULL,
		0x36B83FEE2315D4C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1091C142B0EC4A2ULL,
		0x619031D1FB1ACB9AULL,
		0x8F90553C48241B5CULL,
		0x745BE93731C3B216ULL,
		0x4FB5469093FAE604ULL,
		0xE7E599C6C1AF91C8ULL,
		0xA8383C095BDBF6A2ULL,
		0x6D707FDC462BA98FULL
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
		0x1B277573ACAF2BC4ULL,
		0x16020333C5D4C880ULL,
		0x020040AD9D22F382ULL,
		0x486E65A49FE774F7ULL,
		0xF16680C687D31698ULL,
		0x2798D0F8347DAD3FULL,
		0xE06C01BD6283B68AULL,
		0x0ECA4801EB1129B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x364EEAE7595E5788ULL,
		0x2C0406678BA99100ULL,
		0x0400815B3A45E704ULL,
		0x90DCCB493FCEE9EEULL,
		0xE2CD018D0FA62D30ULL,
		0x4F31A1F068FB5A7FULL,
		0xC0D8037AC5076D14ULL,
		0x1D949003D6225363ULL
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
		0x922BD97275773276ULL,
		0xA230E6A90E38DBCFULL,
		0x48461492B9ED7571ULL,
		0xBE91AC799DE75C4EULL,
		0x605C2BA948F7EB64ULL,
		0x5C363925D53B76A4ULL,
		0xD801009EF69F64E9ULL,
		0x17E450A4897065AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2457B2E4EAEE64ECULL,
		0x4461CD521C71B79FULL,
		0x908C292573DAEAE3ULL,
		0x7D2358F33BCEB89CULL,
		0xC0B8575291EFD6C9ULL,
		0xB86C724BAA76ED48ULL,
		0xB002013DED3EC9D2ULL,
		0x2FC8A14912E0CB5DULL
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
		0x69F022D9EFA083C7ULL,
		0x99FFE5D743238DB7ULL,
		0x373AECD97B30B880ULL,
		0xABE9392619AEA662ULL,
		0x7047CFC63A20F646ULL,
		0x963CE16A8F380F20ULL,
		0xFF6D92CFC5BC9D1DULL,
		0x2CEC01213EAB8C60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E045B3DF41078EULL,
		0x33FFCBAE86471B6EULL,
		0x6E75D9B2F6617101ULL,
		0x57D2724C335D4CC4ULL,
		0xE08F9F8C7441EC8DULL,
		0x2C79C2D51E701E40ULL,
		0xFEDB259F8B793A3BULL,
		0x59D802427D5718C1ULL
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
		0xF8ED5430CCA495D4ULL,
		0x2203A21E96E7B8DCULL,
		0xA4D937E96AEF9C9FULL,
		0x8D1E3AC82E0AD6F3ULL,
		0xC3D869BAC6C0B28CULL,
		0x9448BA36AB34600CULL,
		0x2387AC57FA720C9EULL,
		0x102B6902630EB9DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DAA86199492BA8ULL,
		0x4407443D2DCF71B9ULL,
		0x49B26FD2D5DF393EULL,
		0x1A3C75905C15ADE7ULL,
		0x87B0D3758D816519ULL,
		0x2891746D5668C019ULL,
		0x470F58AFF4E4193DULL,
		0x2056D204C61D73B6ULL
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
		0x57F54C92874A8AFEULL,
		0x1484989827619B51ULL,
		0x4360C4B12A367772ULL,
		0x157774163E284BB5ULL,
		0x72FF1412E5E0A22FULL,
		0x61CFB79B4E9AC9E2ULL,
		0x9E0E7977F9300E4CULL,
		0x22402139ABC80E4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFEA99250E9515FCULL,
		0x290931304EC336A2ULL,
		0x86C18962546CEEE4ULL,
		0x2AEEE82C7C50976AULL,
		0xE5FE2825CBC1445EULL,
		0xC39F6F369D3593C4ULL,
		0x3C1CF2EFF2601C98ULL,
		0x4480427357901C9FULL
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
		0x02AA5A4449AC6A2DULL,
		0x2E6AFAE640636EB5ULL,
		0x94A27B75D345E8D1ULL,
		0xB40397468A22FE44ULL,
		0xE2EB52834F030149ULL,
		0x2EA74561D68DE25BULL,
		0x5C8E3CA48AB8717BULL,
		0x24BA308CBFA78345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0554B4889358D45AULL,
		0x5CD5F5CC80C6DD6AULL,
		0x2944F6EBA68BD1A2ULL,
		0x68072E8D1445FC89ULL,
		0xC5D6A5069E060293ULL,
		0x5D4E8AC3AD1BC4B7ULL,
		0xB91C79491570E2F6ULL,
		0x497461197F4F068AULL
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
		0x38DF74FBC4EF5F16ULL,
		0x9904FDAF43885997ULL,
		0x963CBA64AA28BABCULL,
		0xE984BFBBE4EE47BAULL,
		0xB20BE0F279D0C367ULL,
		0x857F42111CA43FC0ULL,
		0x6F38B83A15303E1BULL,
		0x03BEA39AEEFBFF68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71BEE9F789DEBE2CULL,
		0x3209FB5E8710B32EULL,
		0x2C7974C954517579ULL,
		0xD3097F77C9DC8F75ULL,
		0x6417C1E4F3A186CFULL,
		0x0AFE842239487F81ULL,
		0xDE7170742A607C37ULL,
		0x077D4735DDF7FED0ULL
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
		0x4039546BE49C71DAULL,
		0xC480480B877EF1A3ULL,
		0x6AD6BD0ADADE8868ULL,
		0xCEBE403FBDFBAA5EULL,
		0x3478D07922111A3CULL,
		0xD7C486B8A9CAA394ULL,
		0xBEB0BAD525CD881EULL,
		0x37AC8CA4F0E8E354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8072A8D7C938E3B4ULL,
		0x890090170EFDE346ULL,
		0xD5AD7A15B5BD10D1ULL,
		0x9D7C807F7BF754BCULL,
		0x68F1A0F244223479ULL,
		0xAF890D7153954728ULL,
		0x7D6175AA4B9B103DULL,
		0x6F591949E1D1C6A9ULL
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
		0x5E57B4A0A6B3A758ULL,
		0xB4DDDE7FA3CB6E49ULL,
		0xCE145A886A07E595ULL,
		0x71EAAD99D23388A3ULL,
		0xA57C4AA51BEE6D6FULL,
		0x22FFFB9281A47FACULL,
		0x49D1439AF78E8E8CULL,
		0x09D04C8204178F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAF69414D674EB0ULL,
		0x69BBBCFF4796DC92ULL,
		0x9C28B510D40FCB2BULL,
		0xE3D55B33A4671147ULL,
		0x4AF8954A37DCDADEULL,
		0x45FFF7250348FF59ULL,
		0x93A28735EF1D1D18ULL,
		0x13A09904082F1E94ULL
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
		0xF1C17AD90E5FA860ULL,
		0x1588A023E12829FBULL,
		0x1BCE178FEF862490ULL,
		0xC481B4066F009FC8ULL,
		0xF6CA660A7F80ACE6ULL,
		0x474CED62A7C462EEULL,
		0x6A5A06C97C1BD56FULL,
		0x26DD5333A3C34523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE382F5B21CBF50C0ULL,
		0x2B114047C25053F7ULL,
		0x379C2F1FDF0C4920ULL,
		0x8903680CDE013F90ULL,
		0xED94CC14FF0159CDULL,
		0x8E99DAC54F88C5DDULL,
		0xD4B40D92F837AADEULL,
		0x4DBAA66747868A46ULL
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
		0xEAA138356A2A2AF3ULL,
		0x35EB919D5A5C638CULL,
		0x88D10F312B57A86FULL,
		0xFFD962894A0AD701ULL,
		0x5E3D9BD035D119ABULL,
		0x0BCA3D46BF10F480ULL,
		0xD3E33E7A41AAC42AULL,
		0x017FDA06AA80A4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD542706AD45455E6ULL,
		0x6BD7233AB4B8C719ULL,
		0x11A21E6256AF50DEULL,
		0xFFB2C5129415AE03ULL,
		0xBC7B37A06BA23357ULL,
		0x17947A8D7E21E900ULL,
		0xA7C67CF483558854ULL,
		0x02FFB40D550149CFULL
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
		0xDBBF9574126EF9DCULL,
		0xC2798C16FF4E6AF5ULL,
		0xD4C4CF6F10917867ULL,
		0x3CF6C2A5D00AC7B4ULL,
		0x09BB11B4F49275E0ULL,
		0x4E0A2780CD85D63FULL,
		0x8B5000C29E3AA259ULL,
		0x2BAA135F615E305CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77F2AE824DDF3B8ULL,
		0x84F3182DFE9CD5EBULL,
		0xA9899EDE2122F0CFULL,
		0x79ED854BA0158F69ULL,
		0x13762369E924EBC0ULL,
		0x9C144F019B0BAC7EULL,
		0x16A001853C7544B2ULL,
		0x575426BEC2BC60B9ULL
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
		0x8BE0D30508A86188ULL,
		0x5B4171AB73FA13B4ULL,
		0xE791867B70C6A7E1ULL,
		0xFBF004AA120532B3ULL,
		0xDA6E2EF88D71D48BULL,
		0x2D9FAAD1307DE3F1ULL,
		0xFDCF731BE4D12741ULL,
		0x1022052EE61FFBF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C1A60A1150C310ULL,
		0xB682E356E7F42769ULL,
		0xCF230CF6E18D4FC2ULL,
		0xF7E00954240A6567ULL,
		0xB4DC5DF11AE3A917ULL,
		0x5B3F55A260FBC7E3ULL,
		0xFB9EE637C9A24E82ULL,
		0x20440A5DCC3FF7EBULL
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
		0x1D385FB9D486BCCDULL,
		0x67E4324022209A18ULL,
		0x4AAB3AD81AF8915EULL,
		0x67D4C932939CF67CULL,
		0x9E1158DF4780B549ULL,
		0x1C102B8D75FB78C1ULL,
		0xC4510B81292A1EE5ULL,
		0x11AFE74E4CA0EC58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A70BF73A90D799AULL,
		0xCFC8648044413430ULL,
		0x955675B035F122BCULL,
		0xCFA992652739ECF8ULL,
		0x3C22B1BE8F016A92ULL,
		0x3820571AEBF6F183ULL,
		0x88A2170252543DCAULL,
		0x235FCE9C9941D8B1ULL
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
		0xC855456EFF046A39ULL,
		0x9B30657B6404B892ULL,
		0xB72FD6F28B337B31ULL,
		0xB541EB056D1EDEFFULL,
		0x5DF8D113182DC148ULL,
		0xB724154333392AE2ULL,
		0xA5C1101D055515A3ULL,
		0x0B02F52B937ACE84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90AA8ADDFE08D472ULL,
		0x3660CAF6C8097125ULL,
		0x6E5FADE51666F663ULL,
		0x6A83D60ADA3DBDFFULL,
		0xBBF1A226305B8291ULL,
		0x6E482A86667255C4ULL,
		0x4B82203A0AAA2B47ULL,
		0x1605EA5726F59D09ULL
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
		0xCC8D45AFC6F68759ULL,
		0x343F807396707797ULL,
		0x29B8CB5D459B0573ULL,
		0xB56A7C58F40B7D2AULL,
		0xA5B13ADC28518EAFULL,
		0x2177A87C7147C9F5ULL,
		0x91520D6EB04FF8AEULL,
		0x0B789CE532ACB137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x991A8B5F8DED0EB2ULL,
		0x687F00E72CE0EF2FULL,
		0x537196BA8B360AE6ULL,
		0x6AD4F8B1E816FA54ULL,
		0x4B6275B850A31D5FULL,
		0x42EF50F8E28F93EBULL,
		0x22A41ADD609FF15CULL,
		0x16F139CA6559626FULL
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
		0x72DA70D8BC048B4CULL,
		0x6C1055D4851D1467ULL,
		0xAAC4D03177EAE866ULL,
		0xCA19A36AAB3D0A4CULL,
		0xD581FD33287BD6D7ULL,
		0xF0FFEC4896878F63ULL,
		0xA1A9274521F2A776ULL,
		0x1D41DB1ED41059BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B4E1B178091698ULL,
		0xD820ABA90A3A28CEULL,
		0x5589A062EFD5D0CCULL,
		0x943346D5567A1499ULL,
		0xAB03FA6650F7ADAFULL,
		0xE1FFD8912D0F1EC7ULL,
		0x43524E8A43E54EEDULL,
		0x3A83B63DA820B375ULL
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
		0xE485A48FE538B14BULL,
		0xF27FAC2AD30A3439ULL,
		0xBEB2D1B67893C180ULL,
		0x054AEDEEE0A49435ULL,
		0xCF30669321345B98ULL,
		0x9D11489D715A8050ULL,
		0x10DE6F0E37264B39ULL,
		0x28EDA5573D1F5171ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC90B491FCA716296ULL,
		0xE4FF5855A6146873ULL,
		0x7D65A36CF1278301ULL,
		0x0A95DBDDC149286BULL,
		0x9E60CD264268B730ULL,
		0x3A22913AE2B500A1ULL,
		0x21BCDE1C6E4C9673ULL,
		0x51DB4AAE7A3EA2E2ULL
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
		0x18FEFC528AAEA55CULL,
		0x1BA84527A5B32D02ULL,
		0x22C4CBCB2DE6B6E8ULL,
		0x7251438362EDC5E7ULL,
		0xB0C38631D544BB8AULL,
		0xA170636A0012A115ULL,
		0x65AAF846CC5BBDCCULL,
		0x01044EE42A69F0E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31FDF8A5155D4AB8ULL,
		0x37508A4F4B665A04ULL,
		0x458997965BCD6DD0ULL,
		0xE4A28706C5DB8BCEULL,
		0x61870C63AA897714ULL,
		0x42E0C6D40025422BULL,
		0xCB55F08D98B77B99ULL,
		0x02089DC854D3E1CCULL
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
		0xB6E87386F96AECBDULL,
		0xBFBEDB55FD4B3B93ULL,
		0x29E4023BD787D04FULL,
		0xD73B352F5EF28D07ULL,
		0x1A83E67B83E277A7ULL,
		0x1667BB7095328715ULL,
		0x5979D49B4A9C21C5ULL,
		0x35173CD7BCBD7487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD0E70DF2D5D97AULL,
		0x7F7DB6ABFA967727ULL,
		0x53C80477AF0FA09FULL,
		0xAE766A5EBDE51A0EULL,
		0x3507CCF707C4EF4FULL,
		0x2CCF76E12A650E2AULL,
		0xB2F3A9369538438AULL,
		0x6A2E79AF797AE90EULL
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
		0x4BCE5A5F18E91E14ULL,
		0x3A6C05BCE45075E6ULL,
		0xE828C198A7CDB274ULL,
		0x265397A17FF682BAULL,
		0x299C6EDA894F3498ULL,
		0xE4F39F60DC502006ULL,
		0xDF4E6E77FCA7AF6FULL,
		0x13A78FA8B8AD8B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979CB4BE31D23C28ULL,
		0x74D80B79C8A0EBCCULL,
		0xD05183314F9B64E8ULL,
		0x4CA72F42FFED0575ULL,
		0x5338DDB5129E6930ULL,
		0xC9E73EC1B8A0400CULL,
		0xBE9CDCEFF94F5EDFULL,
		0x274F1F51715B16B9ULL
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
		0x7CEB837F144478ECULL,
		0xB5BE6937C589368CULL,
		0xEBD99E0F3754B788ULL,
		0x89260F4D5F79B480ULL,
		0x38AA2EC3089C8FA5ULL,
		0x6C227BFD1CD80580ULL,
		0x32B7600588245EFCULL,
		0x0C4C758020A86AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D706FE2888F1D8ULL,
		0x6B7CD26F8B126D18ULL,
		0xD7B33C1E6EA96F11ULL,
		0x124C1E9ABEF36901ULL,
		0x71545D8611391F4BULL,
		0xD844F7FA39B00B00ULL,
		0x656EC00B1048BDF8ULL,
		0x1898EB004150D5EAULL
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
		0x582105DB500D5FE6ULL,
		0x3B9B040E282C29E8ULL,
		0x579BB9C60B4CC0B6ULL,
		0x63D8DB39BC587001ULL,
		0x163ADE448A64CC69ULL,
		0x1A04B2C5AB613195ULL,
		0x05419E245E3F7E41ULL,
		0x1110752D87458B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0420BB6A01ABFCCULL,
		0x7736081C505853D0ULL,
		0xAF37738C1699816CULL,
		0xC7B1B67378B0E002ULL,
		0x2C75BC8914C998D2ULL,
		0x3409658B56C2632AULL,
		0x0A833C48BC7EFC82ULL,
		0x2220EA5B0E8B161CULL
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
		0xC903323E4807AD69ULL,
		0x1948CEFB4F1E15CFULL,
		0xBD69BF3D37C4F33CULL,
		0x06FCEC0E31210549ULL,
		0x590A6D671E355FA1ULL,
		0x2559B79567EF595AULL,
		0x1F687E0243DA0004ULL,
		0x31C9EC2E39519A09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9206647C900F5AD2ULL,
		0x32919DF69E3C2B9FULL,
		0x7AD37E7A6F89E678ULL,
		0x0DF9D81C62420A93ULL,
		0xB214DACE3C6ABF42ULL,
		0x4AB36F2ACFDEB2B4ULL,
		0x3ED0FC0487B40008ULL,
		0x6393D85C72A33412ULL
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
		0xCBE832E7FF4E87D7ULL,
		0x275A81D39E0E240CULL,
		0xD6DEE04D1EE1B9A8ULL,
		0x3D3F5C59B9830792ULL,
		0x7EA27F52A0290401ULL,
		0x1009223B865A3F00ULL,
		0xADAED19C918D96B0ULL,
		0x2E998C49A9679FF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D065CFFE9D0FAEULL,
		0x4EB503A73C1C4819ULL,
		0xADBDC09A3DC37350ULL,
		0x7A7EB8B373060F25ULL,
		0xFD44FEA540520802ULL,
		0x201244770CB47E00ULL,
		0x5B5DA339231B2D60ULL,
		0x5D33189352CF3FE1ULL
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
		0x3594E32F857DA7F0ULL,
		0x7B5D0EFE6F927FEDULL,
		0xBEEF24483E6E0FE6ULL,
		0xEC597B3DEE6CCF1CULL,
		0xC40F7865BE0EECA3ULL,
		0x371F927B19C2D183ULL,
		0xD81CC55BCB0D523BULL,
		0x2B4261AFB395DF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B29C65F0AFB4FE0ULL,
		0xF6BA1DFCDF24FFDAULL,
		0x7DDE48907CDC1FCCULL,
		0xD8B2F67BDCD99E39ULL,
		0x881EF0CB7C1DD947ULL,
		0x6E3F24F63385A307ULL,
		0xB0398AB7961AA476ULL,
		0x5684C35F672BBF17ULL
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
		0xA65EA78C8C7E34EFULL,
		0xCA765EA111F04E46ULL,
		0x96F12B7FA7C83529ULL,
		0xAADE8BC6AA844D03ULL,
		0xD0E4A716EB112128ULL,
		0x8FE311E502DBBE17ULL,
		0x6A1910DF4F284B02ULL,
		0x20DD9F19B7414A1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBD4F1918FC69DEULL,
		0x94ECBD4223E09C8DULL,
		0x2DE256FF4F906A53ULL,
		0x55BD178D55089A07ULL,
		0xA1C94E2DD6224251ULL,
		0x1FC623CA05B77C2FULL,
		0xD43221BE9E509605ULL,
		0x41BB3E336E82943EULL
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
		0x83E7247238D98CEEULL,
		0xC23D9BF9062CF564ULL,
		0xCCD7E4B1674D9BCAULL,
		0xEFF7EA0E2BF01B29ULL,
		0x62972EA53B9443B8ULL,
		0x02EB8599C8E9FBE2ULL,
		0x341867079D027FC2ULL,
		0x2E2D7376A61C977EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CE48E471B319DCULL,
		0x847B37F20C59EAC9ULL,
		0x99AFC962CE9B3795ULL,
		0xDFEFD41C57E03653ULL,
		0xC52E5D4A77288771ULL,
		0x05D70B3391D3F7C4ULL,
		0x6830CE0F3A04FF84ULL,
		0x5C5AE6ED4C392EFCULL
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
		0xB30EA91C6A46CB44ULL,
		0xB30789AE1526289AULL,
		0x2F4500C4145F5B3AULL,
		0x597AA984EB8C63B4ULL,
		0xAF431B2A8C98D578ULL,
		0x5790521687A73D56ULL,
		0x10359264E62121FFULL,
		0x17363A737912FA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661D5238D48D9688ULL,
		0x660F135C2A4C5135ULL,
		0x5E8A018828BEB675ULL,
		0xB2F55309D718C768ULL,
		0x5E8636551931AAF0ULL,
		0xAF20A42D0F4E7AADULL,
		0x206B24C9CC4243FEULL,
		0x2E6C74E6F225F44EULL
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
		0xDA3A75F57A05B6BFULL,
		0x01BFE8F11D282DD5ULL,
		0x5B025A3A84946D9DULL,
		0x1519123A2827556DULL,
		0x041D9CAE9BB97238ULL,
		0xAFBC3A92CDD4629EULL,
		0x66FA650EAB844FBFULL,
		0x14EDC32FDEC4D779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB474EBEAF40B6D7EULL,
		0x037FD1E23A505BABULL,
		0xB604B4750928DB3AULL,
		0x2A322474504EAADAULL,
		0x083B395D3772E470ULL,
		0x5F7875259BA8C53CULL,
		0xCDF4CA1D57089F7FULL,
		0x29DB865FBD89AEF2ULL
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
		0xFF64774EA4BB970BULL,
		0xFCAC7A21DF7A9426ULL,
		0x02A82B0ACE39800DULL,
		0x169821A278DAD813ULL,
		0x250E081F3CDB2FDFULL,
		0x6DFC6BA1993AB948ULL,
		0xF31F73AB9B183FEAULL,
		0x3E637A40CA97EEE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC8EE9D49772E16ULL,
		0xF958F443BEF5284DULL,
		0x055056159C73001BULL,
		0x2D304344F1B5B026ULL,
		0x4A1C103E79B65FBEULL,
		0xDBF8D74332757290ULL,
		0xE63EE75736307FD4ULL,
		0x7CC6F481952FDDCFULL
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
		0xCC61B8ADC17F8332ULL,
		0x4916361F57B0F447ULL,
		0xB022455299FCFFD2ULL,
		0x0939B51D6D39A2AEULL,
		0xC0EF2ADCE304ECCEULL,
		0x01118399ADD0251AULL,
		0xA969155C97C07F34ULL,
		0x2E28FD0D005E8EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C3715B82FF0664ULL,
		0x922C6C3EAF61E88FULL,
		0x60448AA533F9FFA4ULL,
		0x12736A3ADA73455DULL,
		0x81DE55B9C609D99CULL,
		0x022307335BA04A35ULL,
		0x52D22AB92F80FE68ULL,
		0x5C51FA1A00BD1D4BULL
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
		0xC7ECEE2506F86C8EULL,
		0x4D4FAE38AE494ABCULL,
		0x5961E966AE1DA9CFULL,
		0xB632C2FC60EBC22DULL,
		0xAD3028E4715E6625ULL,
		0x7F3E15FB29CAF95EULL,
		0xEBB9FCD0769C4DA5ULL,
		0x3BCB41C7625CDD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FD9DC4A0DF0D91CULL,
		0x9A9F5C715C929579ULL,
		0xB2C3D2CD5C3B539EULL,
		0x6C6585F8C1D7845AULL,
		0x5A6051C8E2BCCC4BULL,
		0xFE7C2BF65395F2BDULL,
		0xD773F9A0ED389B4AULL,
		0x7796838EC4B9BA67ULL
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
		0xE97814274DA88B3AULL,
		0x16E4591FDB6E168CULL,
		0x6DE72ED8A13B5B32ULL,
		0x5F48EE453C3004CDULL,
		0xB426D44982A93AC7ULL,
		0x9750707E4B863787ULL,
		0xFD36AA14F9A78846ULL,
		0x2123D626424BD516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F0284E9B511674ULL,
		0x2DC8B23FB6DC2D19ULL,
		0xDBCE5DB14276B664ULL,
		0xBE91DC8A7860099AULL,
		0x684DA8930552758EULL,
		0x2EA0E0FC970C6F0FULL,
		0xFA6D5429F34F108DULL,
		0x4247AC4C8497AA2DULL
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
		0xD16330C45DF244DCULL,
		0xD6784614663988E6ULL,
		0xDFD1157D4611D68BULL,
		0xE8F30F7B981E2FA1ULL,
		0xEA87F21CE57C6713ULL,
		0x2C952DAD55E14224ULL,
		0xECC146792CFAE73DULL,
		0x3851FED930030B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2C66188BBE489B8ULL,
		0xACF08C28CC7311CDULL,
		0xBFA22AFA8C23AD17ULL,
		0xD1E61EF7303C5F43ULL,
		0xD50FE439CAF8CE27ULL,
		0x592A5B5AABC28449ULL,
		0xD9828CF259F5CE7AULL,
		0x70A3FDB2600616ABULL
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
		0x1DD87967958E7EA0ULL,
		0x90A5CCED14E76E3DULL,
		0xD9F4A70518C21F93ULL,
		0xEE855BDF6101D30FULL,
		0xC1C07E8203B9DF62ULL,
		0x934F1BFBA29D7210ULL,
		0x03AE2D245B128CBBULL,
		0x0F69183CE662E134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB0F2CF2B1CFD40ULL,
		0x214B99DA29CEDC7AULL,
		0xB3E94E0A31843F27ULL,
		0xDD0AB7BEC203A61FULL,
		0x8380FD040773BEC5ULL,
		0x269E37F7453AE421ULL,
		0x075C5A48B6251977ULL,
		0x1ED23079CCC5C268ULL
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
		0x1F9057DE1F0412E9ULL,
		0x859A89FA152B8D95ULL,
		0x697276AFEA768629ULL,
		0xBA96B8B6D5379221ULL,
		0xA6716E5DF25E27DEULL,
		0x620D7D514B8215FCULL,
		0xE1ABB776EB2ED78EULL,
		0x3665344637FB6AF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F20AFBC3E0825D2ULL,
		0x0B3513F42A571B2AULL,
		0xD2E4ED5FD4ED0C53ULL,
		0x752D716DAA6F2442ULL,
		0x4CE2DCBBE4BC4FBDULL,
		0xC41AFAA297042BF9ULL,
		0xC3576EEDD65DAF1CULL,
		0x6CCA688C6FF6D5E7ULL
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
		0xC2C5A95D3696B987ULL,
		0x0A9F9B0DF8FA06EAULL,
		0x09A4BDDEB10E5D5AULL,
		0xDA46CBAA562C0AC4ULL,
		0x8965D907153F1643ULL,
		0xAFCF930D16CE5A38ULL,
		0xB26A11872146BA27ULL,
		0x0D217892D60CAEB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858B52BA6D2D730EULL,
		0x153F361BF1F40DD5ULL,
		0x13497BBD621CBAB4ULL,
		0xB48D9754AC581588ULL,
		0x12CBB20E2A7E2C87ULL,
		0x5F9F261A2D9CB471ULL,
		0x64D4230E428D744FULL,
		0x1A42F125AC195D67ULL
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
		0x80F430B7D9C5FB35ULL,
		0x00284792103FBB93ULL,
		0xC387757E9E07632AULL,
		0xD81A45E85AEDB2FFULL,
		0xAEEB2B29F1734430ULL,
		0x4E380A59812B3E93ULL,
		0x3B352B933AFE1B04ULL,
		0x27CCC32A984324A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E8616FB38BF66AULL,
		0x00508F24207F7727ULL,
		0x870EEAFD3C0EC654ULL,
		0xB0348BD0B5DB65FFULL,
		0x5DD65653E2E68861ULL,
		0x9C7014B302567D27ULL,
		0x766A572675FC3608ULL,
		0x4F99865530864952ULL
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
		0x399A9A753046F6F2ULL,
		0x7AB317AF618B0846ULL,
		0x382F574C9D021515ULL,
		0xF2912B261908B53DULL,
		0x53E5ED270F935398ULL,
		0xBB3AE732777DA1B2ULL,
		0xB8C0D870E0DDD14BULL,
		0x1C3ED5B6423FDC5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733534EA608DEDE4ULL,
		0xF5662F5EC316108CULL,
		0x705EAE993A042A2AULL,
		0xE522564C32116A7AULL,
		0xA7CBDA4E1F26A731ULL,
		0x7675CE64EEFB4364ULL,
		0x7181B0E1C1BBA297ULL,
		0x387DAB6C847FB8B9ULL
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
		0x69A3B566318F7DC3ULL,
		0xB5D2D7812F3AE863ULL,
		0x8F5B6CFE7D0A4791ULL,
		0x9C8A665CAE3BD31CULL,
		0x97664E470AA27834ULL,
		0xD71A064431D06758ULL,
		0xBE0FCE5B5B0EEE6AULL,
		0x0D20C80F1E7EC2B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3476ACC631EFB86ULL,
		0x6BA5AF025E75D0C6ULL,
		0x1EB6D9FCFA148F23ULL,
		0x3914CCB95C77A639ULL,
		0x2ECC9C8E1544F069ULL,
		0xAE340C8863A0CEB1ULL,
		0x7C1F9CB6B61DDCD5ULL,
		0x1A41901E3CFD8573ULL
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
		0xF827EAB997C23ABBULL,
		0xC468F1E47F01CAACULL,
		0x3ADC5F559E00E309ULL,
		0x3816C1FBB8F479A5ULL,
		0xBC1F112537BEB309ULL,
		0x61B3CAC12DF0A1BDULL,
		0x56F3B848A50E8CC9ULL,
		0x2AD54F1AD9219F1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04FD5732F847576ULL,
		0x88D1E3C8FE039559ULL,
		0x75B8BEAB3C01C613ULL,
		0x702D83F771E8F34AULL,
		0x783E224A6F7D6612ULL,
		0xC36795825BE1437BULL,
		0xADE770914A1D1992ULL,
		0x55AA9E35B2433E3EULL
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
		0x6B43C692FDB315E1ULL,
		0xF407F38F736B0FE0ULL,
		0xBB8D11C8EB0525B1ULL,
		0xF885B9DB3EF4329CULL,
		0xC8B38B1266BA6F1DULL,
		0x15FE3FE9247DB057ULL,
		0x9E8C2F9059C20C18ULL,
		0x064BC0AABCE6BADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6878D25FB662BC2ULL,
		0xE80FE71EE6D61FC0ULL,
		0x771A2391D60A4B63ULL,
		0xF10B73B67DE86539ULL,
		0x91671624CD74DE3BULL,
		0x2BFC7FD248FB60AFULL,
		0x3D185F20B3841830ULL,
		0x0C97815579CD75B7ULL
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
		0x1735FDE3E81BAC51ULL,
		0xB67633D55B033FEDULL,
		0x2BEEFAF2F2A22DA7ULL,
		0xB58C8CF9A9CC0A88ULL,
		0x284EFC1CA3D6E919ULL,
		0xAD29679CFAFB537FULL,
		0xAD82B0DC07BD8E3CULL,
		0x3867A974F13D7720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E6BFBC7D03758A2ULL,
		0x6CEC67AAB6067FDAULL,
		0x57DDF5E5E5445B4FULL,
		0x6B1919F353981510ULL,
		0x509DF83947ADD233ULL,
		0x5A52CF39F5F6A6FEULL,
		0x5B0561B80F7B1C79ULL,
		0x70CF52E9E27AEE41ULL
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
		0x66464F4FED445316ULL,
		0xCB2362ED1FA8EF4DULL,
		0xD4E0C9A629BA5897ULL,
		0xFE1005031BD15A14ULL,
		0xC507B5D183C44744ULL,
		0x53B248AF8869917AULL,
		0x9972460C8F35A3DBULL,
		0x239EDC6B3B882D78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC8C9E9FDA88A62CULL,
		0x9646C5DA3F51DE9AULL,
		0xA9C1934C5374B12FULL,
		0xFC200A0637A2B429ULL,
		0x8A0F6BA307888E89ULL,
		0xA764915F10D322F5ULL,
		0x32E48C191E6B47B6ULL,
		0x473DB8D677105AF1ULL
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
		0xD454B0AD04441752ULL,
		0xD00EC2F5584CD505ULL,
		0x7975C0F606AA4863ULL,
		0xFEED39167D1FD839ULL,
		0xCCDE5BAAC806742AULL,
		0x4CCBAF5697C8A7CFULL,
		0x8660F81D7FF9FCAAULL,
		0x350BA0EE2FEB9B8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8A9615A08882EA4ULL,
		0xA01D85EAB099AA0BULL,
		0xF2EB81EC0D5490C7ULL,
		0xFDDA722CFA3FB072ULL,
		0x99BCB755900CE855ULL,
		0x99975EAD2F914F9FULL,
		0x0CC1F03AFFF3F954ULL,
		0x6A1741DC5FD7371BULL
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
		0x71C332B52BE37BC5ULL,
		0x6C503C8BA2A1A6E2ULL,
		0x7E8B215524D51DBDULL,
		0xD2BEC6F2BB231B22ULL,
		0xE3420AFD96A118ACULL,
		0xDF89F4662BE0CC6CULL,
		0x7FCDDAE823CBE8EFULL,
		0x1E14AD1BCB65827AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE386656A57C6F78AULL,
		0xD8A0791745434DC4ULL,
		0xFD1642AA49AA3B7AULL,
		0xA57D8DE576463644ULL,
		0xC68415FB2D423159ULL,
		0xBF13E8CC57C198D9ULL,
		0xFF9BB5D04797D1DFULL,
		0x3C295A3796CB04F4ULL
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
		0x5ED2A8C47D2765ADULL,
		0xBA8BD9312BEC4AC0ULL,
		0xBE8CF823F7794661ULL,
		0xEAF4CC42764E944DULL,
		0xAC4E8B394D3D6B93ULL,
		0xE508D611A09E4166ULL,
		0xC476E29C2DAF235CULL,
		0x1713CA41609684A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA55188FA4ECB5AULL,
		0x7517B26257D89580ULL,
		0x7D19F047EEF28CC3ULL,
		0xD5E99884EC9D289BULL,
		0x589D16729A7AD727ULL,
		0xCA11AC23413C82CDULL,
		0x88EDC5385B5E46B9ULL,
		0x2E279482C12D0945ULL
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
		0x46FB90A2EC71D018ULL,
		0x80AF0073D6ECBBABULL,
		0x1099D74A9A9EA2CCULL,
		0x13B8DBE2D259CC0FULL,
		0x122498296E85ADBDULL,
		0x47D392CCD343738FULL,
		0xB7FE988A7FE239E3ULL,
		0x39BB092315F66775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DF72145D8E3A030ULL,
		0x015E00E7ADD97756ULL,
		0x2133AE95353D4599ULL,
		0x2771B7C5A4B3981EULL,
		0x24493052DD0B5B7AULL,
		0x8FA72599A686E71EULL,
		0x6FFD3114FFC473C6ULL,
		0x737612462BECCEEBULL
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
		0x376154C0CEBCCAE8ULL,
		0xCCF995203471199BULL,
		0xD3327DC99A347A17ULL,
		0xB1D07F31F991D096ULL,
		0xBB2D0C6F7B957C72ULL,
		0x3BDCAB5B3848C9FFULL,
		0x7EAE33FF535C2AADULL,
		0x231658D0B163FE43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EC2A9819D7995D0ULL,
		0x99F32A4068E23336ULL,
		0xA664FB933468F42FULL,
		0x63A0FE63F323A12DULL,
		0x765A18DEF72AF8E5ULL,
		0x77B956B6709193FFULL,
		0xFD5C67FEA6B8555AULL,
		0x462CB1A162C7FC86ULL
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
		0x448B7FD452B5AC6FULL,
		0xC00EABCAAA156E10ULL,
		0xAB7C6312F48D05B6ULL,
		0x999C8FB152F86BA7ULL,
		0x818820212CC44FE6ULL,
		0x85862D03115388C6ULL,
		0x1E60E108030B86C1ULL,
		0x1F615F8F0FABB59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8916FFA8A56B58DEULL,
		0x801D5795542ADC20ULL,
		0x56F8C625E91A0B6DULL,
		0x33391F62A5F0D74FULL,
		0x0310404259889FCDULL,
		0x0B0C5A0622A7118DULL,
		0x3CC1C21006170D83ULL,
		0x3EC2BF1E1F576B34ULL
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
		0xF4C40D196DD1649FULL,
		0x14F44DBED1781C5CULL,
		0xFABC91E2F3DDEA5DULL,
		0x3D7405262628988BULL,
		0xC1C6740080DE7E38ULL,
		0x86D7558A09CB975BULL,
		0x7A35BCBFFA107BEEULL,
		0x0C27A0E9E02873F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9881A32DBA2C93EULL,
		0x29E89B7DA2F038B9ULL,
		0xF57923C5E7BBD4BAULL,
		0x7AE80A4C4C513117ULL,
		0x838CE80101BCFC70ULL,
		0x0DAEAB1413972EB7ULL,
		0xF46B797FF420F7DDULL,
		0x184F41D3C050E7E2ULL
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
		0xAD9708548B1EFB28ULL,
		0xFEA1C11CEE518D62ULL,
		0x9FADF5FA58F05B46ULL,
		0xA6C7370E920CCFF1ULL,
		0x2572874EFCC1B1C2ULL,
		0x760F6678B0AF9C88ULL,
		0xEADAD29E01E498E0ULL,
		0x2471EC9F7DB0E570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B2E10A9163DF650ULL,
		0xFD438239DCA31AC5ULL,
		0x3F5BEBF4B1E0B68DULL,
		0x4D8E6E1D24199FE3ULL,
		0x4AE50E9DF9836385ULL,
		0xEC1ECCF1615F3910ULL,
		0xD5B5A53C03C931C0ULL,
		0x48E3D93EFB61CAE1ULL
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
		0xD50523F1FD5BDD75ULL,
		0x21F7D669B6DE6AC8ULL,
		0xCB1FF9761FA30227ULL,
		0xD0EB40472E3ED4E6ULL,
		0x89950B0C1FFA04CFULL,
		0x4644F616727937D9ULL,
		0x7E3EC24F0F81CA81ULL,
		0x318FEEA04BFC5D54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA0A47E3FAB7BAEAULL,
		0x43EFACD36DBCD591ULL,
		0x963FF2EC3F46044EULL,
		0xA1D6808E5C7DA9CDULL,
		0x132A16183FF4099FULL,
		0x8C89EC2CE4F26FB3ULL,
		0xFC7D849E1F039502ULL,
		0x631FDD4097F8BAA8ULL
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
		0xCA47F7872838B341ULL,
		0x6B4811717FDC1BE4ULL,
		0x80AF6B92B1845A7FULL,
		0x12F147BBB1206BF5ULL,
		0x6319638651286BF3ULL,
		0x7C8F57E85781ACCEULL,
		0xD399640427093A41ULL,
		0x3FEA9C5B6B97F9D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948FEF0E50716682ULL,
		0xD69022E2FFB837C9ULL,
		0x015ED7256308B4FEULL,
		0x25E28F776240D7EBULL,
		0xC632C70CA250D7E6ULL,
		0xF91EAFD0AF03599CULL,
		0xA732C8084E127482ULL,
		0x7FD538B6D72FF3B3ULL
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
		0xF7F02A4A83B9EE81ULL,
		0xD7BA356BC9AD0C1CULL,
		0xB5FF6892CDD06FCDULL,
		0x96A71F0420E2AC79ULL,
		0xA7659BA04F7292D7ULL,
		0x1BA5AF0A4D8C0966ULL,
		0x4F9FA2F98898F253ULL,
		0x15287578A1A40E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE054950773DD02ULL,
		0xAF746AD7935A1839ULL,
		0x6BFED1259BA0DF9BULL,
		0x2D4E3E0841C558F3ULL,
		0x4ECB37409EE525AFULL,
		0x374B5E149B1812CDULL,
		0x9F3F45F31131E4A6ULL,
		0x2A50EAF143481CB0ULL
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
		0xAF409E3A51E21EDBULL,
		0x2479A541ED703DB3ULL,
		0xF289A9DF167B7718ULL,
		0x12AA677092B26435ULL,
		0xD7BA474C9BC793FCULL,
		0x0A12BE06AEAC9AB4ULL,
		0x14BACBB4D5CD00D8ULL,
		0x09D60361FAFB3671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E813C74A3C43DB6ULL,
		0x48F34A83DAE07B67ULL,
		0xE51353BE2CF6EE30ULL,
		0x2554CEE12564C86BULL,
		0xAF748E99378F27F8ULL,
		0x14257C0D5D593569ULL,
		0x29759769AB9A01B0ULL,
		0x13AC06C3F5F66CE2ULL
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
		0x21FE062A6FC782FDULL,
		0x926EA8447FCA6BB5ULL,
		0xC54AA3D150BC0475ULL,
		0x134646739486246BULL,
		0xF9E6FF0350AAC42AULL,
		0x33BAEBA6446BD89BULL,
		0xEBF0B703232AC753ULL,
		0x26D3833E365EF98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43FC0C54DF8F05FAULL,
		0x24DD5088FF94D76AULL,
		0x8A9547A2A17808EBULL,
		0x268C8CE7290C48D7ULL,
		0xF3CDFE06A1558854ULL,
		0x6775D74C88D7B137ULL,
		0xD7E16E0646558EA6ULL,
		0x4DA7067C6CBDF315ULL
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
		0x3FA703EF72E1A51AULL,
		0x16D923EF88123C24ULL,
		0x721FB5BD2AF648C2ULL,
		0x05860DF7BC1EE712ULL,
		0x6C63F7DDDE752FAEULL,
		0x41C236F434A1F09BULL,
		0xF51D4BF3893583B6ULL,
		0x15408430B7F4225BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F4E07DEE5C34A34ULL,
		0x2DB247DF10247848ULL,
		0xE43F6B7A55EC9184ULL,
		0x0B0C1BEF783DCE24ULL,
		0xD8C7EFBBBCEA5F5CULL,
		0x83846DE86943E136ULL,
		0xEA3A97E7126B076CULL,
		0x2A8108616FE844B7ULL
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
		0x2A51E6BED3A98CA5ULL,
		0x73E986BA1D81EC49ULL,
		0xA7DB00CA8F06BF30ULL,
		0xB0722B392E0FCA66ULL,
		0x1DE45A47278EE856ULL,
		0xF9BCA1E7E5A62CA3ULL,
		0x167CFD90AB4DD2D5ULL,
		0x11BB24540517CAE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A3CD7DA753194AULL,
		0xE7D30D743B03D892ULL,
		0x4FB601951E0D7E60ULL,
		0x60E456725C1F94CDULL,
		0x3BC8B48E4F1DD0ADULL,
		0xF37943CFCB4C5946ULL,
		0x2CF9FB21569BA5ABULL,
		0x237648A80A2F95C6ULL
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
		0xCEC98CFBDF31C462ULL,
		0x9FE1EBE29665A506ULL,
		0x46EFCE97BDB41ADDULL,
		0x92C9167B3EDFAAE3ULL,
		0x773204FDF37E0A1CULL,
		0x6A1BD1F1E012E763ULL,
		0xBAC9CC8935B3A115ULL,
		0x075873AF1D72183FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9319F7BE6388C4ULL,
		0x3FC3D7C52CCB4A0DULL,
		0x8DDF9D2F7B6835BBULL,
		0x25922CF67DBF55C6ULL,
		0xEE6409FBE6FC1439ULL,
		0xD437A3E3C025CEC6ULL,
		0x759399126B67422AULL,
		0x0EB0E75E3AE4307FULL
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
		0xEE13C2166FB103DEULL,
		0x71A83EFC7D250845ULL,
		0xA810F53D0622B5A1ULL,
		0x5CDAF2B80EA11155ULL,
		0xE37298AD9D53EDB1ULL,
		0xC1C98DC924DFB4EAULL,
		0xE47B90F095C117E0ULL,
		0x25A657DB0BA69361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC27842CDF6207BCULL,
		0xE3507DF8FA4A108BULL,
		0x5021EA7A0C456B42ULL,
		0xB9B5E5701D4222ABULL,
		0xC6E5315B3AA7DB62ULL,
		0x83931B9249BF69D5ULL,
		0xC8F721E12B822FC1ULL,
		0x4B4CAFB6174D26C3ULL
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
		0x8599BEE5ED327572ULL,
		0x24888C0004F9533EULL,
		0xAF6E410BC2364062ULL,
		0x3E00FBB4BDCF35B3ULL,
		0x4E8196600397875BULL,
		0x07948300805E30BAULL,
		0xD6DE8D865521144DULL,
		0x363B9348B36BC653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B337DCBDA64EAE4ULL,
		0x4911180009F2A67DULL,
		0x5EDC8217846C80C4ULL,
		0x7C01F7697B9E6B67ULL,
		0x9D032CC0072F0EB6ULL,
		0x0F29060100BC6174ULL,
		0xADBD1B0CAA42289AULL,
		0x6C77269166D78CA7ULL
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
		0xEC1819098717B1FEULL,
		0xDCEA15759C6D8A26ULL,
		0xDD4ECBADA0CA6757ULL,
		0x0472EB43A5BB637BULL,
		0x43D4018513109475ULL,
		0x201FA739885F1B47ULL,
		0xFAECBE8B53BA83B8ULL,
		0x3BCF069A0148E760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83032130E2F63FCULL,
		0xB9D42AEB38DB144DULL,
		0xBA9D975B4194CEAFULL,
		0x08E5D6874B76C6F7ULL,
		0x87A8030A262128EAULL,
		0x403F4E7310BE368EULL,
		0xF5D97D16A7750770ULL,
		0x779E0D340291CEC1ULL
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
		0xE1B52D7B4F818D58ULL,
		0xD317B17967E7F9F8ULL,
		0xFAEDD4E4351ABA89ULL,
		0xDA322789B3623FC4ULL,
		0x9A52BBFD4F37727AULL,
		0x71F9019CB78426E9ULL,
		0x3CE0239D5FBB3B03ULL,
		0x0B223EB65FD245E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36A5AF69F031AB0ULL,
		0xA62F62F2CFCFF3F1ULL,
		0xF5DBA9C86A357513ULL,
		0xB4644F1366C47F89ULL,
		0x34A577FA9E6EE4F5ULL,
		0xE3F203396F084DD3ULL,
		0x79C0473ABF767606ULL,
		0x16447D6CBFA48BC0ULL
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
		0x470D8E2E222E589FULL,
		0x305B695051294E09ULL,
		0x51CDB269B2D68B3CULL,
		0xBE6E0DC7362769F2ULL,
		0xA8CF6C2226BF86B5ULL,
		0x2B6048B3A7109FF1ULL,
		0x198DA42478D4EB28ULL,
		0x3AD822B7AE5D88BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E1B1C5C445CB13EULL,
		0x60B6D2A0A2529C12ULL,
		0xA39B64D365AD1678ULL,
		0x7CDC1B8E6C4ED3E4ULL,
		0x519ED8444D7F0D6BULL,
		0x56C091674E213FE3ULL,
		0x331B4848F1A9D650ULL,
		0x75B0456F5CBB117AULL
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
		0x616F301745B1E492ULL,
		0x6C842782CD70E1AEULL,
		0x69132451387DA7ECULL,
		0xFE3D211B48198DC2ULL,
		0x74E1B3EF61665148ULL,
		0x75AA9F595342A03EULL,
		0x0C3025DA6474824FULL,
		0x1CF15B228F48F493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DE602E8B63C924ULL,
		0xD9084F059AE1C35CULL,
		0xD22648A270FB4FD8ULL,
		0xFC7A423690331B84ULL,
		0xE9C367DEC2CCA291ULL,
		0xEB553EB2A685407CULL,
		0x18604BB4C8E9049EULL,
		0x39E2B6451E91E926ULL
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
		0xBB5A43AACB98CDE1ULL,
		0x8A6893A61422ED38ULL,
		0xBD5731414E2730BAULL,
		0x4A9279C491030470ULL,
		0x8095A99ADF4A589EULL,
		0x67B5AB276DD8E53BULL,
		0xA68F9D5CF720329CULL,
		0x315CFD3A06B9701CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B4875597319BC2ULL,
		0x14D1274C2845DA71ULL,
		0x7AAE62829C4E6175ULL,
		0x9524F389220608E1ULL,
		0x012B5335BE94B13CULL,
		0xCF6B564EDBB1CA77ULL,
		0x4D1F3AB9EE406538ULL,
		0x62B9FA740D72E039ULL
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
		0x639092899678706AULL,
		0xAB5C99C4CB276808ULL,
		0x69CB3D9A2F28D421ULL,
		0x88AA1E960CC1DE2DULL,
		0x1125E6888F3C3BABULL,
		0xB6B7353BD3A5D759ULL,
		0xA8EBD370735DA086ULL,
		0x2EBBFADAA3452D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC72125132CF0E0D4ULL,
		0x56B93389964ED010ULL,
		0xD3967B345E51A843ULL,
		0x11543D2C1983BC5AULL,
		0x224BCD111E787757ULL,
		0x6D6E6A77A74BAEB2ULL,
		0x51D7A6E0E6BB410DULL,
		0x5D77F5B5468A5AF7ULL
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
		0x27BEC72FBE5C5EFEULL,
		0x1CED505577A4316AULL,
		0x3161787D0B9E6881ULL,
		0xAC8A2AE616FF1638ULL,
		0x330B73C98BF532BEULL,
		0x9E62364C763C2ACDULL,
		0x48AA23C759E68FFFULL,
		0x37A791C962DCF7EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7D8E5F7CB8BDFCULL,
		0x39DAA0AAEF4862D4ULL,
		0x62C2F0FA173CD102ULL,
		0x591455CC2DFE2C70ULL,
		0x6616E79317EA657DULL,
		0x3CC46C98EC78559AULL,
		0x9154478EB3CD1FFFULL,
		0x6F4F2392C5B9EFDAULL
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
		0x212C166F8CA81AAEULL,
		0xEE0714B436EECBDEULL,
		0xACF68922BF102F4AULL,
		0x0B0FEECB3806D87EULL,
		0xDE1169AADC1D36C9ULL,
		0x75936142E927CD3DULL,
		0x12CA0B3DBE4D8332ULL,
		0x2F69D81642AC64E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42582CDF1950355CULL,
		0xDC0E29686DDD97BCULL,
		0x59ED12457E205E95ULL,
		0x161FDD96700DB0FDULL,
		0xBC22D355B83A6D92ULL,
		0xEB26C285D24F9A7BULL,
		0x2594167B7C9B0664ULL,
		0x5ED3B02C8558C9CCULL
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
		0x7A193A17729C1D1BULL,
		0xF2E97492C892454BULL,
		0xF2CF55762739B584ULL,
		0xACCD1AD0C65643BBULL,
		0x1545E1C45A753883ULL,
		0xFAB4C62C54C98AC3ULL,
		0x8044E2421F472834ULL,
		0x3D11DFFA925B6835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF432742EE5383A36ULL,
		0xE5D2E92591248A96ULL,
		0xE59EAAEC4E736B09ULL,
		0x599A35A18CAC8777ULL,
		0x2A8BC388B4EA7107ULL,
		0xF5698C58A9931586ULL,
		0x0089C4843E8E5069ULL,
		0x7A23BFF524B6D06BULL
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
		0xCE3CE279F7C54E3BULL,
		0x53E949E6FEC0C703ULL,
		0x11BF9AA69E632C47ULL,
		0x65B1EF65462A0ED8ULL,
		0xBA1CADA1242159DBULL,
		0xD0C80B9F7F465112ULL,
		0x270577B080D32754ULL,
		0x14DB3D3C10AC077AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C79C4F3EF8A9C76ULL,
		0xA7D293CDFD818E07ULL,
		0x237F354D3CC6588EULL,
		0xCB63DECA8C541DB0ULL,
		0x74395B424842B3B6ULL,
		0xA190173EFE8CA225ULL,
		0x4E0AEF6101A64EA9ULL,
		0x29B67A7821580EF4ULL
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
		0x2BC895E05E19C67CULL,
		0xFB5FD196835E7C13ULL,
		0x21758E27760EB5E4ULL,
		0xB4AB8FFDF1414D73ULL,
		0x937DCEDDA9983F0DULL,
		0xC086521C8097410DULL,
		0xE9A50C0073115A57ULL,
		0x3DFBDB65523DF2D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57912BC0BC338CF8ULL,
		0xF6BFA32D06BCF826ULL,
		0x42EB1C4EEC1D6BC9ULL,
		0x69571FFBE2829AE6ULL,
		0x26FB9DBB53307E1BULL,
		0x810CA439012E821BULL,
		0xD34A1800E622B4AFULL,
		0x7BF7B6CAA47BE5A9ULL
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
		0x67FF26DB6D092D4CULL,
		0x36B2BA138ABD6727ULL,
		0x5E8603596688671EULL,
		0x1863BD6EF8F65F98ULL,
		0xD179E4D801F611E1ULL,
		0x1408433E60ECFD66ULL,
		0xF9377135BF91A4BBULL,
		0x068E7A189BEFBE40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFFE4DB6DA125A98ULL,
		0x6D657427157ACE4EULL,
		0xBD0C06B2CD10CE3CULL,
		0x30C77ADDF1ECBF30ULL,
		0xA2F3C9B003EC23C2ULL,
		0x2810867CC1D9FACDULL,
		0xF26EE26B7F234976ULL,
		0x0D1CF43137DF7C81ULL
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
		0xF5BF26EA6255DE33ULL,
		0xAE8A95830733B964ULL,
		0xB117B1FF8B5CF1FCULL,
		0xB808328617889DF4ULL,
		0x4CED47487D8FE6B3ULL,
		0xDE67FA9EF62FCB25ULL,
		0x50A37B33CD97C4D3ULL,
		0x01DA987663F17E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB7E4DD4C4ABBC66ULL,
		0x5D152B060E6772C9ULL,
		0x622F63FF16B9E3F9ULL,
		0x7010650C2F113BE9ULL,
		0x99DA8E90FB1FCD67ULL,
		0xBCCFF53DEC5F964AULL,
		0xA146F6679B2F89A7ULL,
		0x03B530ECC7E2FCE2ULL
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
		0x8AF34F17169DCCF6ULL,
		0xB5A6EAD2A00CF69CULL,
		0xC2B41CCA019358B5ULL,
		0xAC20936158D25402ULL,
		0x435265110AA3C057ULL,
		0xBE4639DD16A7C52BULL,
		0xB5E1E90497B40EAAULL,
		0x047C2CB6143BFD97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E69E2E2D3B99ECULL,
		0x6B4DD5A54019ED39ULL,
		0x856839940326B16BULL,
		0x584126C2B1A4A805ULL,
		0x86A4CA22154780AFULL,
		0x7C8C73BA2D4F8A56ULL,
		0x6BC3D2092F681D55ULL,
		0x08F8596C2877FB2FULL
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
		0x04E3517FD0DCA4C3ULL,
		0x0EE439178341C94CULL,
		0xD8AD8D7DEF2EFECBULL,
		0xD8E0DC6B2999BD17ULL,
		0x411F14373448A02CULL,
		0x141C06E2A69E4F9AULL,
		0xFB455FD4FC03E95FULL,
		0x37D0F14D369ABB63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C6A2FFA1B94986ULL,
		0x1DC8722F06839298ULL,
		0xB15B1AFBDE5DFD96ULL,
		0xB1C1B8D653337A2FULL,
		0x823E286E68914059ULL,
		0x28380DC54D3C9F34ULL,
		0xF68ABFA9F807D2BEULL,
		0x6FA1E29A6D3576C7ULL
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
		0x770C7BE31A423D20ULL,
		0xBB02495BB3B7E908ULL,
		0x70890D15C561F92DULL,
		0xA94E28A226B8B21AULL,
		0xE170197F58CFA04AULL,
		0x9C6EEF122D2003B3ULL,
		0xA0DA04DEBE950CA5ULL,
		0x1492CF79EAB06E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE18F7C634847A40ULL,
		0x760492B7676FD210ULL,
		0xE1121A2B8AC3F25BULL,
		0x529C51444D716434ULL,
		0xC2E032FEB19F4095ULL,
		0x38DDDE245A400767ULL,
		0x41B409BD7D2A194BULL,
		0x29259EF3D560DCEBULL
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
		0xA1DE42F55E4D7878ULL,
		0x2DC2B68425F698BCULL,
		0x4DFA91F4A03A5877ULL,
		0x7F28A00D41CB080BULL,
		0xC0D428D85F0634DDULL,
		0xFA3510CA17848BB5ULL,
		0x374145BF2DDB1CC2ULL,
		0x1CDE10FBDFF686D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BC85EABC9AF0F0ULL,
		0x5B856D084BED3179ULL,
		0x9BF523E94074B0EEULL,
		0xFE51401A83961016ULL,
		0x81A851B0BE0C69BAULL,
		0xF46A21942F09176BULL,
		0x6E828B7E5BB63985ULL,
		0x39BC21F7BFED0DB2ULL
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
		0x2CEC1BA798859777ULL,
		0x4FA984101219E97FULL,
		0x612E8575876959E7ULL,
		0x7171D35CD940108CULL,
		0x5FEBCD1EC7414D1DULL,
		0xF7AE93F68F7DDD5DULL,
		0xD8A523AC8490F140ULL,
		0x2E267D0EA23D0CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59D8374F310B2EEEULL,
		0x9F5308202433D2FEULL,
		0xC25D0AEB0ED2B3CEULL,
		0xE2E3A6B9B2802118ULL,
		0xBFD79A3D8E829A3AULL,
		0xEF5D27ED1EFBBABAULL,
		0xB14A47590921E281ULL,
		0x5C4CFA1D447A19C5ULL
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
		0x79A6D97CF66BE5EDULL,
		0x2A83F3568C0D95BEULL,
		0xC9D579DCC9C6A858ULL,
		0xB58E39C9B0E1F730ULL,
		0xF61F91130976581FULL,
		0x6B2160B0F00DBAE1ULL,
		0x1A73CAA04985B307ULL,
		0x2DD3C249328A2458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF34DB2F9ECD7CBDAULL,
		0x5507E6AD181B2B7CULL,
		0x93AAF3B9938D50B0ULL,
		0x6B1C739361C3EE61ULL,
		0xEC3F222612ECB03FULL,
		0xD642C161E01B75C3ULL,
		0x34E79540930B660EULL,
		0x5BA78492651448B0ULL
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
		0x81ABAC0E4EF9879FULL,
		0xB26FC56141C2CAE3ULL,
		0x273A8AFB3AC7DC98ULL,
		0x8042E60D77514FC3ULL,
		0x82061B3CF10D416CULL,
		0x0E3B5D8A93518B83ULL,
		0x56782A597173DE43ULL,
		0x0FCAD8CC76E726F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0357581C9DF30F3EULL,
		0x64DF8AC2838595C7ULL,
		0x4E7515F6758FB931ULL,
		0x0085CC1AEEA29F86ULL,
		0x040C3679E21A82D9ULL,
		0x1C76BB1526A31707ULL,
		0xACF054B2E2E7BC86ULL,
		0x1F95B198EDCE4DEAULL
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
		0x1B55ABA5C32DD76EULL,
		0x67355D98B160BD92ULL,
		0xD9F959C4AF1E6B81ULL,
		0x0DDEC2C2C211AE20ULL,
		0x9E7C60E1BEE1689CULL,
		0xCF0AE60A5A990983ULL,
		0x681B8D4047B19F86ULL,
		0x312724D0DD9BA36BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36AB574B865BAEDCULL,
		0xCE6ABB3162C17B24ULL,
		0xB3F2B3895E3CD702ULL,
		0x1BBD858584235C41ULL,
		0x3CF8C1C37DC2D138ULL,
		0x9E15CC14B5321307ULL,
		0xD0371A808F633F0DULL,
		0x624E49A1BB3746D6ULL
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
		0x55100B5C86943E94ULL,
		0x5FD08F9D8DC3C041ULL,
		0xB69455FF88C4DB80ULL,
		0x774CC3C1AFCF5B99ULL,
		0x60DFA216D326A7D8ULL,
		0x39437E7DFEC91488ULL,
		0x22270A06EE324820ULL,
		0x000E5E5C46403A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA2016B90D287D28ULL,
		0xBFA11F3B1B878082ULL,
		0x6D28ABFF1189B700ULL,
		0xEE9987835F9EB733ULL,
		0xC1BF442DA64D4FB0ULL,
		0x7286FCFBFD922910ULL,
		0x444E140DDC649040ULL,
		0x001CBCB88C80745EULL
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
		0xA5095FE3EF88B24FULL,
		0xA6CE824B1A7DCAEAULL,
		0xDE6C77C8AA2C59E8ULL,
		0x3DFDB9FEB78CFCECULL,
		0x01A3340C1EF75E2EULL,
		0xC635CADD5F9F738FULL,
		0x46AC8B824AC77069ULL,
		0x185DECF2163BB433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A12BFC7DF11649EULL,
		0x4D9D049634FB95D5ULL,
		0xBCD8EF915458B3D1ULL,
		0x7BFB73FD6F19F9D9ULL,
		0x034668183DEEBC5CULL,
		0x8C6B95BABF3EE71EULL,
		0x8D591704958EE0D3ULL,
		0x30BBD9E42C776866ULL
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
		0x05E141065C8BD6C9ULL,
		0xB40EAED647D6EC04ULL,
		0x92A7383C4AE51DC6ULL,
		0x3BD28C450A51EC7EULL,
		0xE4EF628921EF1B6EULL,
		0x3821E700E253CDF4ULL,
		0x6751CDDDD1284BA5ULL,
		0x17F429052460ACBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BC2820CB917AD92ULL,
		0x681D5DAC8FADD808ULL,
		0x254E707895CA3B8DULL,
		0x77A5188A14A3D8FDULL,
		0xC9DEC51243DE36DCULL,
		0x7043CE01C4A79BE9ULL,
		0xCEA39BBBA250974AULL,
		0x2FE8520A48C1597EULL
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
		0x6FF45BA40F422D66ULL,
		0x6539670897BF41E8ULL,
		0x3464A9D1D8BD198BULL,
		0xC9614431B82F3A85ULL,
		0xB3258B85787DFE35ULL,
		0x09BD20C91C71FD1EULL,
		0xF86BBB7FF937F3B5ULL,
		0x190914BE03BF21C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE8B7481E845ACCULL,
		0xCA72CE112F7E83D0ULL,
		0x68C953A3B17A3316ULL,
		0x92C28863705E750AULL,
		0x664B170AF0FBFC6BULL,
		0x137A419238E3FA3DULL,
		0xF0D776FFF26FE76AULL,
		0x3212297C077E4393ULL
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
		0xF4F385AD1203DA65ULL,
		0x657D259C76694E32ULL,
		0x733B92BFBBED541DULL,
		0x103FCE38845BCE4BULL,
		0x635C968DE4B640CEULL,
		0x3D161D64A994AAC5ULL,
		0xBDB107FC103602E8ULL,
		0x012459A69A21F5DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E70B5A2407B4CAULL,
		0xCAFA4B38ECD29C65ULL,
		0xE677257F77DAA83AULL,
		0x207F9C7108B79C96ULL,
		0xC6B92D1BC96C819CULL,
		0x7A2C3AC95329558AULL,
		0x7B620FF8206C05D0ULL,
		0x0248B34D3443EBBDULL
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
		0x49D82DC75895D3A6ULL,
		0x3CAB85CF3D2B294AULL,
		0xBAD618989B3248EFULL,
		0x38DC3FFE521B8BCCULL,
		0xA668860C011C7855ULL,
		0x0465CE410A9ED5DBULL,
		0x715E2DC15DD9144DULL,
		0x13C140D0E837E7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B05B8EB12BA74CULL,
		0x79570B9E7A565294ULL,
		0x75AC3131366491DEULL,
		0x71B87FFCA4371799ULL,
		0x4CD10C180238F0AAULL,
		0x08CB9C82153DABB7ULL,
		0xE2BC5B82BBB2289AULL,
		0x278281A1D06FCF5AULL
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
		0x140F770FC85E9851ULL,
		0x793314C81D6243D8ULL,
		0xA9B7097B109E4F6AULL,
		0x7EA89CF548DD3938ULL,
		0x6B87FA03EBDB08E9ULL,
		0x0CF3BBF6A58E06D5ULL,
		0xF6525162F72C9597ULL,
		0x30DFFEF9949B14AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x281EEE1F90BD30A2ULL,
		0xF26629903AC487B0ULL,
		0x536E12F6213C9ED4ULL,
		0xFD5139EA91BA7271ULL,
		0xD70FF407D7B611D2ULL,
		0x19E777ED4B1C0DAAULL,
		0xECA4A2C5EE592B2EULL,
		0x61BFFDF329362955ULL
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
		0xA1463633B429C1E7ULL,
		0x50F2FEF5E1AF5C96ULL,
		0xC2AE2547268641E7ULL,
		0xA28FC3135E68AFABULL,
		0xAE064C6199F2DEA3ULL,
		0x75BCF85D388ED004ULL,
		0xFAE6F5C33CC07754ULL,
		0x029383477481010BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428C6C67685383CEULL,
		0xA1E5FDEBC35EB92DULL,
		0x855C4A8E4D0C83CEULL,
		0x451F8626BCD15F57ULL,
		0x5C0C98C333E5BD47ULL,
		0xEB79F0BA711DA009ULL,
		0xF5CDEB867980EEA8ULL,
		0x0527068EE9020217ULL
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
		0x0330E876BC6C3C0FULL,
		0x287AE2890B071A2CULL,
		0x5F02C5D1CE8A2953ULL,
		0xF8009BAD56FAF55BULL,
		0xD248BE0C5359E915ULL,
		0xA02D028289AAC7D1ULL,
		0x79A4798772E5237AULL,
		0x12BC8736A60DB0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0661D0ED78D8781EULL,
		0x50F5C512160E3458ULL,
		0xBE058BA39D1452A6ULL,
		0xF001375AADF5EAB6ULL,
		0xA4917C18A6B3D22BULL,
		0x405A050513558FA3ULL,
		0xF348F30EE5CA46F5ULL,
		0x25790E6D4C1B6188ULL
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
		0xC00242105C93498EULL,
		0x5ED246D0868545C4ULL,
		0x1853F94BB8A8787DULL,
		0x9E0FF12F40F36D8BULL,
		0xB8F7761A77F3A79FULL,
		0xB0E2D6253002D22BULL,
		0x9EF2157699EF7B2EULL,
		0x2C19395686030904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80048420B926931CULL,
		0xBDA48DA10D0A8B89ULL,
		0x30A7F2977150F0FAULL,
		0x3C1FE25E81E6DB16ULL,
		0x71EEEC34EFE74F3FULL,
		0x61C5AC4A6005A457ULL,
		0x3DE42AED33DEF65DULL,
		0x583272AD0C061209ULL
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
		0xBB773D02EEC41585ULL,
		0x285B995C8E0C7DB0ULL,
		0x52D09B2D303D326CULL,
		0xD5286D3227C6DF54ULL,
		0x7B9D1479A4A0516AULL,
		0xA1BFD49130769A65ULL,
		0xE82C2E9892C96359ULL,
		0x1AE0F1C52A69A1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76EE7A05DD882B0AULL,
		0x50B732B91C18FB61ULL,
		0xA5A1365A607A64D8ULL,
		0xAA50DA644F8DBEA8ULL,
		0xF73A28F34940A2D5ULL,
		0x437FA92260ED34CAULL,
		0xD0585D312592C6B3ULL,
		0x35C1E38A54D34355ULL
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
		0x6573F2CFAE551C65ULL,
		0x25BF49DB044DEDA8ULL,
		0xC2E8A20B5748B070ULL,
		0xBA940F4AFCAD56F9ULL,
		0x735D2FD9567F9AAEULL,
		0x736F41C52F5561BEULL,
		0x079312A1B88CC17AULL,
		0x327347A464D155A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE7E59F5CAA38CAULL,
		0x4B7E93B6089BDB50ULL,
		0x85D14416AE9160E0ULL,
		0x75281E95F95AADF3ULL,
		0xE6BA5FB2ACFF355DULL,
		0xE6DE838A5EAAC37CULL,
		0x0F262543711982F4ULL,
		0x64E68F48C9A2AB4AULL
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
		0x09AE21726C8C303CULL,
		0x28EB82B6F7BF4AB6ULL,
		0xE341B266DD5927FAULL,
		0xC2228AA1A824CA22ULL,
		0xE2FECE2809AA682BULL,
		0xFE99B44C2E2FEE32ULL,
		0xC6DBC1AF5BB9366CULL,
		0x17F1AD3DE0918E3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135C42E4D9186078ULL,
		0x51D7056DEF7E956CULL,
		0xC68364CDBAB24FF4ULL,
		0x8445154350499445ULL,
		0xC5FD9C501354D057ULL,
		0xFD3368985C5FDC65ULL,
		0x8DB7835EB7726CD9ULL,
		0x2FE35A7BC1231C7BULL
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
		0x8DF3CA69B3F741F0ULL,
		0x5E9BECFC2153C3C3ULL,
		0xBBC0FE70F72BDDEEULL,
		0xECED0EEDB7014A5EULL,
		0x8988DB963A5B860EULL,
		0xCA3FF996E18ECB94ULL,
		0x5D8FB35C574811BFULL,
		0x0B879A02D52BA202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE794D367EE83E0ULL,
		0xBD37D9F842A78787ULL,
		0x7781FCE1EE57BBDCULL,
		0xD9DA1DDB6E0294BDULL,
		0x1311B72C74B70C1DULL,
		0x947FF32DC31D9729ULL,
		0xBB1F66B8AE90237FULL,
		0x170F3405AA574404ULL
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
		0xED71328537416403ULL,
		0xA106B001644A6655ULL,
		0x37555756F872F99AULL,
		0x3096C80EB570DFE7ULL,
		0x5D73C81ADB392D8BULL,
		0xCAF35C2EBA80DF76ULL,
		0xDA8191C9981514AAULL,
		0x159F08CBD26D3C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAE2650A6E82C806ULL,
		0x420D6002C894CCABULL,
		0x6EAAAEADF0E5F335ULL,
		0x612D901D6AE1BFCEULL,
		0xBAE79035B6725B16ULL,
		0x95E6B85D7501BEECULL,
		0xB5032393302A2955ULL,
		0x2B3E1197A4DA7887ULL
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
		0xB1A01711CBEE4AD9ULL,
		0xF4F117000DBF989DULL,
		0x8E20BD1EE1CDE844ULL,
		0xA8E487B2D015C390ULL,
		0x3A66C9E5C2631013ULL,
		0x4498A2C9F717133FULL,
		0xD263F2C893ABCD53ULL,
		0x00318DCE8951913EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63402E2397DC95B2ULL,
		0xE9E22E001B7F313BULL,
		0x1C417A3DC39BD089ULL,
		0x51C90F65A02B8721ULL,
		0x74CD93CB84C62027ULL,
		0x89314593EE2E267EULL,
		0xA4C7E59127579AA6ULL,
		0x00631B9D12A3227DULL
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
		0x0EA078931C630578ULL,
		0x6CB57DDB3B4144C5ULL,
		0x1BAB6F25E3C77B53ULL,
		0x1BDFF5BA65A289FAULL,
		0xBBB14BA8B3AA5C07ULL,
		0x273BA793B7783D72ULL,
		0x2B87020C4C9E30ABULL,
		0x337C6CD1F70F592EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D40F12638C60AF0ULL,
		0xD96AFBB67682898AULL,
		0x3756DE4BC78EF6A6ULL,
		0x37BFEB74CB4513F4ULL,
		0x776297516754B80EULL,
		0x4E774F276EF07AE5ULL,
		0x570E0418993C6156ULL,
		0x66F8D9A3EE1EB25CULL
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
		0x989BFFC82E4085D1ULL,
		0xAEA824ABE9F4838EULL,
		0xBB7522F3D272A0E4ULL,
		0x1334507FA404205DULL,
		0x0036C0DCD5A3F609ULL,
		0x0C6BD7BB95AA0B31ULL,
		0x5B5619D33E6B0DC7ULL,
		0x01B5FF7630D3A217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3137FF905C810BA2ULL,
		0x5D504957D3E9071DULL,
		0x76EA45E7A4E541C9ULL,
		0x2668A0FF480840BBULL,
		0x006D81B9AB47EC12ULL,
		0x18D7AF772B541662ULL,
		0xB6AC33A67CD61B8EULL,
		0x036BFEEC61A7442EULL
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
		0xCC217CB9BFA14F03ULL,
		0x517241021D806C77ULL,
		0x3533DEAEB10C0264ULL,
		0x646127E69F348EA8ULL,
		0x32FA2B4B53421B50ULL,
		0xE78E5E2B55409031ULL,
		0xBDD3458433911BEFULL,
		0x08783B70CD2E8DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9842F9737F429E06ULL,
		0xA2E482043B00D8EFULL,
		0x6A67BD5D621804C8ULL,
		0xC8C24FCD3E691D50ULL,
		0x65F45696A68436A0ULL,
		0xCF1CBC56AA812062ULL,
		0x7BA68B08672237DFULL,
		0x10F076E19A5D1BE3ULL
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
		0xE4723A0AA826CD92ULL,
		0xB7D9E252E71824EFULL,
		0x6F80A427CB5618C2ULL,
		0x155C966F0DB43503ULL,
		0x12440B16F5DAE8E6ULL,
		0x84FD035255CD0782ULL,
		0x1F7D29E0B33B9C4AULL,
		0x37D6C679377DE6BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E47415504D9B24ULL,
		0x6FB3C4A5CE3049DFULL,
		0xDF01484F96AC3185ULL,
		0x2AB92CDE1B686A06ULL,
		0x2488162DEBB5D1CCULL,
		0x09FA06A4AB9A0F04ULL,
		0x3EFA53C166773895ULL,
		0x6FAD8CF26EFBCD74ULL
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
		0x9DE9673B534C66BAULL,
		0xC72A5D410B662430ULL,
		0x6822053C5A12664CULL,
		0x18B81B27081ED9E4ULL,
		0x2BFF82E3B85C8A49ULL,
		0xFB941334E458A3BCULL,
		0xB4574EFF1EA7D2E1ULL,
		0x030BBE589DBD136FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD2CE76A698CD74ULL,
		0x8E54BA8216CC4861ULL,
		0xD0440A78B424CC99ULL,
		0x3170364E103DB3C8ULL,
		0x57FF05C770B91492ULL,
		0xF7282669C8B14778ULL,
		0x68AE9DFE3D4FA5C3ULL,
		0x06177CB13B7A26DFULL
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
		0xA86F4E6ED166DD89ULL,
		0xCA515640D3C83C13ULL,
		0xFCB0E5331C50A33CULL,
		0x4A24CF4EF9D37EF7ULL,
		0x3210D742BF99F8A1ULL,
		0xD3AED51DA0397B2EULL,
		0x1302C10700FC947DULL,
		0x2819D38F309D98E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50DE9CDDA2CDBB12ULL,
		0x94A2AC81A7907827ULL,
		0xF961CA6638A14679ULL,
		0x94499E9DF3A6FDEFULL,
		0x6421AE857F33F142ULL,
		0xA75DAA3B4072F65CULL,
		0x2605820E01F928FBULL,
		0x5033A71E613B31C2ULL
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
		0x19B1B716C1D490B1ULL,
		0x0C3C380B88C8ED6BULL,
		0xCF0AB737891440F5ULL,
		0xC7BC4DB8C43E6161ULL,
		0xDEAA4C6014988B61ULL,
		0x79516474A715B0C4ULL,
		0x9C05C3AA95C26851ULL,
		0x207D1211C8D662EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33636E2D83A92162ULL,
		0x187870171191DAD6ULL,
		0x9E156E6F122881EAULL,
		0x8F789B71887CC2C3ULL,
		0xBD5498C0293116C3ULL,
		0xF2A2C8E94E2B6189ULL,
		0x380B87552B84D0A2ULL,
		0x40FA242391ACC5DDULL
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
		0x77BBECC042570B0DULL,
		0xDFCA8B24A4201A26ULL,
		0x1E553D77915FBDB3ULL,
		0x0FA295C4C23052B6ULL,
		0x3EB23A8A11D91A09ULL,
		0xE2F4BDFF55A36A0FULL,
		0x07D0358A4870E61EULL,
		0x18324164EA96A359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF77D98084AE161AULL,
		0xBF9516494840344CULL,
		0x3CAA7AEF22BF7B67ULL,
		0x1F452B898460A56CULL,
		0x7D64751423B23412ULL,
		0xC5E97BFEAB46D41EULL,
		0x0FA06B1490E1CC3DULL,
		0x306482C9D52D46B2ULL
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
		0x1B2CED8747AF7441ULL,
		0xC54FE69D6ED4F588ULL,
		0xDE0D74FAEBC6BA7CULL,
		0xAE97AD27FE30086DULL,
		0x399893E2F7976D39ULL,
		0x1417854D32AC2939ULL,
		0x246EBC4E2C694032ULL,
		0x0B698C50C300F4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3659DB0E8F5EE882ULL,
		0x8A9FCD3ADDA9EB10ULL,
		0xBC1AE9F5D78D74F9ULL,
		0x5D2F5A4FFC6010DBULL,
		0x733127C5EF2EDA73ULL,
		0x282F0A9A65585272ULL,
		0x48DD789C58D28064ULL,
		0x16D318A18601E97EULL
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
		0x7CBFEE6D0426C6C1ULL,
		0x1E3BC4F0701F3B28ULL,
		0x7C3470002DFD9423ULL,
		0x3DA08EE4451572BCULL,
		0x3F83C088832CC1A4ULL,
		0x05535075A3116BF1ULL,
		0x209DBC635CD3623DULL,
		0x02581565597A8019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97FDCDA084D8D82ULL,
		0x3C7789E0E03E7650ULL,
		0xF868E0005BFB2846ULL,
		0x7B411DC88A2AE578ULL,
		0x7F07811106598348ULL,
		0x0AA6A0EB4622D7E2ULL,
		0x413B78C6B9A6C47AULL,
		0x04B02ACAB2F50032ULL
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
		0x4FCEC85C22B38DE1ULL,
		0xC1ED008834AB8DDEULL,
		0xA6DABB31C272F627ULL,
		0x2F2489EAA772B428ULL,
		0x2B4E79400C69ABEFULL,
		0x20A2ACDB8FFD309FULL,
		0xF6F87696ADB08812ULL,
		0x248CF35A5C160193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9D90B845671BC2ULL,
		0x83DA011069571BBCULL,
		0x4DB5766384E5EC4FULL,
		0x5E4913D54EE56851ULL,
		0x569CF28018D357DEULL,
		0x414559B71FFA613EULL,
		0xEDF0ED2D5B611024ULL,
		0x4919E6B4B82C0327ULL
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
		0x44A7D7A932173CAEULL,
		0x1621B8AAD4257D80ULL,
		0x571750326631FAF4ULL,
		0xED4F67DE4DF4E62AULL,
		0x5050442BC3AFE878ULL,
		0xFE2DB9EAAAA249E8ULL,
		0x7E5B4CC0C80C488FULL,
		0x0AE5D3EF2FE19834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x894FAF52642E795CULL,
		0x2C437155A84AFB00ULL,
		0xAE2EA064CC63F5E8ULL,
		0xDA9ECFBC9BE9CC54ULL,
		0xA0A08857875FD0F1ULL,
		0xFC5B73D5554493D0ULL,
		0xFCB699819018911FULL,
		0x15CBA7DE5FC33068ULL
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
		0x32B051CF3F05A0F7ULL,
		0xCCB5370D0B8433C5ULL,
		0x70A2B33EDB3035E1ULL,
		0xF9715EE6AB9E760CULL,
		0x4FAB19C5F4919226ULL,
		0xA4CD95FFB6C7208DULL,
		0x3D65EC2B1726ACB2ULL,
		0x28F42037C54A3B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6560A39E7E0B41EEULL,
		0x996A6E1A1708678AULL,
		0xE145667DB6606BC3ULL,
		0xF2E2BDCD573CEC18ULL,
		0x9F56338BE923244DULL,
		0x499B2BFF6D8E411AULL,
		0x7ACBD8562E4D5965ULL,
		0x51E8406F8A94767CULL
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
		0x0F8C1CB693FD5504ULL,
		0x308D665F76E03D15ULL,
		0xB0EA1B13FAC8E6FEULL,
		0xC58B8C9BCB2798CEULL,
		0xC446C16A32D55BE0ULL,
		0xB3D4BC11F1FDBFEAULL,
		0xFB2ED0ACC5FCD8F6ULL,
		0x0D700B8677009550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F18396D27FAAA08ULL,
		0x611ACCBEEDC07A2AULL,
		0x61D43627F591CDFCULL,
		0x8B171937964F319DULL,
		0x888D82D465AAB7C1ULL,
		0x67A97823E3FB7FD5ULL,
		0xF65DA1598BF9B1EDULL,
		0x1AE0170CEE012AA1ULL
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
		0xD25A73A82280D73BULL,
		0xFFAD3CDED8397656ULL,
		0xCD75E58A25F5D01BULL,
		0x3B86C5AB618251D4ULL,
		0xAEEBBCB6B099D310ULL,
		0x843B12F1EE909AE3ULL,
		0xE5264EAAED268D40ULL,
		0x2EFFA7662E06B59CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4B4E7504501AE76ULL,
		0xFF5A79BDB072ECADULL,
		0x9AEBCB144BEBA037ULL,
		0x770D8B56C304A3A9ULL,
		0x5DD7796D6133A620ULL,
		0x087625E3DD2135C7ULL,
		0xCA4C9D55DA4D1A81ULL,
		0x5DFF4ECC5C0D6B39ULL
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
		0x5AC9CD999004D2F9ULL,
		0x1DA0E448B7FE82DBULL,
		0x3BD74ED47B92E8F9ULL,
		0x5EFE7F78FC825455ULL,
		0x540809D652FAA67BULL,
		0xFE22988AE801A1DDULL,
		0xABBE29F1A964C0FFULL,
		0x37C61038F2456FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5939B332009A5F2ULL,
		0x3B41C8916FFD05B6ULL,
		0x77AE9DA8F725D1F2ULL,
		0xBDFCFEF1F904A8AAULL,
		0xA81013ACA5F54CF6ULL,
		0xFC453115D00343BAULL,
		0x577C53E352C981FFULL,
		0x6F8C2071E48ADFD5ULL
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
		0xF1E3D6DC17EE931EULL,
		0x3F8E4D88F2492160ULL,
		0x17EF1C5DB8873CF2ULL,
		0x914F116BC4F3F0C2ULL,
		0x286968681A384B54ULL,
		0x4E3917A8D34E529FULL,
		0x5A8CD9E02259FEA1ULL,
		0x3BE6621FA6697BA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C7ADB82FDD263CULL,
		0x7F1C9B11E49242C1ULL,
		0x2FDE38BB710E79E4ULL,
		0x229E22D789E7E184ULL,
		0x50D2D0D0347096A9ULL,
		0x9C722F51A69CA53EULL,
		0xB519B3C044B3FD42ULL,
		0x77CCC43F4CD2F750ULL
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
		0xBF6C2AD39B4D7733ULL,
		0xB926C5E1D395A651ULL,
		0xC95B1FA5C6F402B9ULL,
		0xB785E08AD24D3346ULL,
		0xFDDDC4ED2568CECCULL,
		0x079005F422560AA0ULL,
		0x6DA937B7BC0CDBB9ULL,
		0x2B5BDD3A1A57ED42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ED855A7369AEE66ULL,
		0x724D8BC3A72B4CA3ULL,
		0x92B63F4B8DE80573ULL,
		0x6F0BC115A49A668DULL,
		0xFBBB89DA4AD19D99ULL,
		0x0F200BE844AC1541ULL,
		0xDB526F6F7819B772ULL,
		0x56B7BA7434AFDA84ULL
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
		0x70913AA86BEFF44CULL,
		0x6C42B84C94BAFDACULL,
		0x498251BC3CCC2EB7ULL,
		0x9B140283F7628A39ULL,
		0x73644059C56B3B58ULL,
		0x4E0C5107A1F19396ULL,
		0xCC956D54C08BF080ULL,
		0x3DE0196019B9BD2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1227550D7DFE898ULL,
		0xD88570992975FB58ULL,
		0x9304A37879985D6EULL,
		0x36280507EEC51472ULL,
		0xE6C880B38AD676B1ULL,
		0x9C18A20F43E3272CULL,
		0x992ADAA98117E100ULL,
		0x7BC032C033737A5DULL
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
		0x4C3858FB601456A1ULL,
		0x2442A4D7E839A250ULL,
		0xB85D0098C78083C3ULL,
		0xA9C3217E17D3C6A0ULL,
		0x1CB84D25F659E6B2ULL,
		0x65E8BF0F7C44B098ULL,
		0xCBA91FF5696B0A1EULL,
		0x022E64B759CD3FCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9870B1F6C028AD42ULL,
		0x488549AFD07344A0ULL,
		0x70BA01318F010786ULL,
		0x538642FC2FA78D41ULL,
		0x39709A4BECB3CD65ULL,
		0xCBD17E1EF8896130ULL,
		0x97523FEAD2D6143CULL,
		0x045CC96EB39A7F97ULL
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
		0x6A96587D62E30EFCULL,
		0xCA1A225F56E1F2E4ULL,
		0xF6825F7D4A694E74ULL,
		0x477D4ECEBE9CE33FULL,
		0xDBF7482BE8924D9BULL,
		0x973322B89AA52E8BULL,
		0xE8AE8BD7D724A51DULL,
		0x2923A194650BCC99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52CB0FAC5C61DF8ULL,
		0x943444BEADC3E5C8ULL,
		0xED04BEFA94D29CE9ULL,
		0x8EFA9D9D7D39C67FULL,
		0xB7EE9057D1249B36ULL,
		0x2E664571354A5D17ULL,
		0xD15D17AFAE494A3BULL,
		0x52474328CA179933ULL
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
		0x39E1372AEFE4D529ULL,
		0x5B94CC29519A216BULL,
		0xDFCD8816780C16BEULL,
		0xD6927B175C4EED8BULL,
		0xC27825865E6EA8AEULL,
		0x6E8DC113E3B3D58BULL,
		0x9D5B9497F0ED473EULL,
		0x313FDFEBC100CAF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C26E55DFC9AA52ULL,
		0xB7299852A33442D6ULL,
		0xBF9B102CF0182D7CULL,
		0xAD24F62EB89DDB17ULL,
		0x84F04B0CBCDD515DULL,
		0xDD1B8227C767AB17ULL,
		0x3AB7292FE1DA8E7CULL,
		0x627FBFD7820195EDULL
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
		0xD97697C43A5CB051ULL,
		0x8FF977F772C94330ULL,
		0x9ACF2EDC3729E892ULL,
		0xA83895580EAA2CB7ULL,
		0x746FCC2885F9C971ULL,
		0x24BA530E9E056EAEULL,
		0x274F124EA17C2FF8ULL,
		0x134F4EEF0DB73E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ED2F8874B960A2ULL,
		0x1FF2EFEEE5928661ULL,
		0x359E5DB86E53D125ULL,
		0x50712AB01D54596FULL,
		0xE8DF98510BF392E3ULL,
		0x4974A61D3C0ADD5CULL,
		0x4E9E249D42F85FF0ULL,
		0x269E9DDE1B6E7D3EULL
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
		0x2D4552F67077770DULL,
		0x7E5AE8C620EB932EULL,
		0x9BBF743C483C1EA9ULL,
		0xDB4D510E27EBA10DULL,
		0xC43F8BEB687E550BULL,
		0xE70B5D3228801AFAULL,
		0xAC5E303DFE717073ULL,
		0x2962E12DF100AC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8AA5ECE0EEEE1AULL,
		0xFCB5D18C41D7265CULL,
		0x377EE87890783D52ULL,
		0xB69AA21C4FD7421BULL,
		0x887F17D6D0FCAA17ULL,
		0xCE16BA64510035F5ULL,
		0x58BC607BFCE2E0E7ULL,
		0x52C5C25BE201583DULL
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
		0x64F48149B829295EULL,
		0x3A721FE9C7069ABAULL,
		0xA19B749CEDB4F42BULL,
		0xF9F710CFA88C1499ULL,
		0x582D21CB62820915ULL,
		0x3BA623704297EE67ULL,
		0x396D88A5CF2A250DULL,
		0x0A8B44703AD63A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E90293705252BCULL,
		0x74E43FD38E0D3574ULL,
		0x4336E939DB69E856ULL,
		0xF3EE219F51182933ULL,
		0xB05A4396C504122BULL,
		0x774C46E0852FDCCEULL,
		0x72DB114B9E544A1AULL,
		0x151688E075AC749AULL
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
		0x8D6B1774C3C2132EULL,
		0x10AD1B36B1B1D121ULL,
		0x79D04C41A7CCB130ULL,
		0x45531EE6F5D31807ULL,
		0x62FA9A102B195B21ULL,
		0x77DF761A37F230BCULL,
		0x6C44B60B20D8924DULL,
		0x0F31668B3195AB75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD62EE98784265CULL,
		0x215A366D6363A243ULL,
		0xF3A098834F996260ULL,
		0x8AA63DCDEBA6300EULL,
		0xC5F534205632B642ULL,
		0xEFBEEC346FE46178ULL,
		0xD8896C1641B1249AULL,
		0x1E62CD16632B56EAULL
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
		0xC160E51EC7AD76D1ULL,
		0x6F604A3CF2CF0200ULL,
		0x39F541D7A89A1521ULL,
		0x51E93A8B2D0D8C17ULL,
		0xAAD48BDFC9191FF6ULL,
		0xA58C1C9DDE413AB0ULL,
		0x5AD1C29B8F2F9216ULL,
		0x3A4AEC12BEF1CA88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C1CA3D8F5AEDA2ULL,
		0xDEC09479E59E0401ULL,
		0x73EA83AF51342A42ULL,
		0xA3D275165A1B182EULL,
		0x55A917BF92323FECULL,
		0x4B18393BBC827561ULL,
		0xB5A385371E5F242DULL,
		0x7495D8257DE39510ULL
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
		0x4D56D8EDCA9A09DCULL,
		0x22FF28FE510432C8ULL,
		0x6EFD6CB5BDAFCB46ULL,
		0x92FE4D8B2A7DA838ULL,
		0x366A1A849822428CULL,
		0xE56F743CA40F60E3ULL,
		0xC0900F9AC1A0705BULL,
		0x1239966C266E9269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AADB1DB953413B8ULL,
		0x45FE51FCA2086590ULL,
		0xDDFAD96B7B5F968CULL,
		0x25FC9B1654FB5070ULL,
		0x6CD4350930448519ULL,
		0xCADEE879481EC1C6ULL,
		0x81201F358340E0B7ULL,
		0x24732CD84CDD24D3ULL
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
		0x231D135736E4B046ULL,
		0xB0D3EC7E88810831ULL,
		0xE34932E6D3A84182ULL,
		0xC5BA05C879748085ULL,
		0x18787914C98903B7ULL,
		0xED292921968A5D44ULL,
		0xFE091815FDB9D529ULL,
		0x36F8B11434D1B64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x463A26AE6DC9608CULL,
		0x61A7D8FD11021062ULL,
		0xC69265CDA7508305ULL,
		0x8B740B90F2E9010BULL,
		0x30F0F2299312076FULL,
		0xDA5252432D14BA88ULL,
		0xFC12302BFB73AA53ULL,
		0x6DF1622869A36C95ULL
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
		0x3017B058B7B8E20BULL,
		0xE3C89AECD2DC2391ULL,
		0x9254AABF61D71755ULL,
		0x95A26FBAB11E2E41ULL,
		0x10BA1500B3437149ULL,
		0x92DC021520C2595BULL,
		0x216ABF08C459F370ULL,
		0x127F30A942A4EB3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602F60B16F71C416ULL,
		0xC79135D9A5B84722ULL,
		0x24A9557EC3AE2EABULL,
		0x2B44DF75623C5C83ULL,
		0x21742A016686E293ULL,
		0x25B8042A4184B2B6ULL,
		0x42D57E1188B3E6E1ULL,
		0x24FE61528549D67CULL
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
		0x0027FC4CE3D72C5AULL,
		0x62E96EB523F31AFFULL,
		0xFADC8654149A493DULL,
		0xA4A152544047CBA2ULL,
		0x0E5784B85DDB9069ULL,
		0xC14358B854ED1E1AULL,
		0x6D5CDBCE78EC4574ULL,
		0x0C7F58E2D67A82B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x004FF899C7AE58B4ULL,
		0xC5D2DD6A47E635FEULL,
		0xF5B90CA82934927AULL,
		0x4942A4A8808F9745ULL,
		0x1CAF0970BBB720D3ULL,
		0x8286B170A9DA3C34ULL,
		0xDAB9B79CF1D88AE9ULL,
		0x18FEB1C5ACF5056CULL
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
		0xC4D62378975AB248ULL,
		0x5B31835DE27BFA8FULL,
		0xD6EE1B743EDE92BEULL,
		0x9E02BAA5BA2FDEB5ULL,
		0xB94417991AB79ED8ULL,
		0x3A780629422E9DADULL,
		0x1923B91E1DF963DAULL,
		0x25A9D5B183ADCF41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89AC46F12EB56490ULL,
		0xB66306BBC4F7F51FULL,
		0xADDC36E87DBD257CULL,
		0x3C05754B745FBD6BULL,
		0x72882F32356F3DB1ULL,
		0x74F00C52845D3B5BULL,
		0x3247723C3BF2C7B4ULL,
		0x4B53AB63075B9E82ULL
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
		0x708BA9CE95343498ULL,
		0x976100CD9408DE48ULL,
		0x4F34385426C87018ULL,
		0xE8502B289B539297ULL,
		0xFB81CED4EFAD28ADULL,
		0xD98432C0755DB416ULL,
		0x3F4301783FE57A9CULL,
		0x0AF9B41084C3A29CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE117539D2A686930ULL,
		0x2EC2019B2811BC90ULL,
		0x9E6870A84D90E031ULL,
		0xD0A0565136A7252EULL,
		0xF7039DA9DF5A515BULL,
		0xB3086580EABB682DULL,
		0x7E8602F07FCAF539ULL,
		0x15F3682109874538ULL
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
		0x0AF9BA27835477C2ULL,
		0xFA58D7C3E0D22C3BULL,
		0x54D43A30435E58AEULL,
		0x3C1544CEEC5773A7ULL,
		0xEFDB7AD790ECAA7BULL,
		0x3CDAFA6E78DBD6C7ULL,
		0xD2560284FBCA7A70ULL,
		0x075D7C38C129F0CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15F3744F06A8EF84ULL,
		0xF4B1AF87C1A45876ULL,
		0xA9A8746086BCB15DULL,
		0x782A899DD8AEE74EULL,
		0xDFB6F5AF21D954F6ULL,
		0x79B5F4DCF1B7AD8FULL,
		0xA4AC0509F794F4E0ULL,
		0x0EBAF8718253E199ULL
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
		0x80BDF30A46C68DA7ULL,
		0x61173450E75CF134ULL,
		0x08D925037579CFD7ULL,
		0x6D7F3920E13961A0ULL,
		0x94E3B11C0DFA6CEDULL,
		0x45FA652D5915A25BULL,
		0x3BFBA4D4C8306171ULL,
		0x030D78E5C9784E13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017BE6148D8D1B4EULL,
		0xC22E68A1CEB9E269ULL,
		0x11B24A06EAF39FAEULL,
		0xDAFE7241C272C340ULL,
		0x29C762381BF4D9DAULL,
		0x8BF4CA5AB22B44B7ULL,
		0x77F749A99060C2E2ULL,
		0x061AF1CB92F09C26ULL
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
		0x12CFCBCDBE7A3EE7ULL,
		0x42715F1A4CFF8C41ULL,
		0xE57781CCB7892922ULL,
		0xAF532609363FA217ULL,
		0xA5C56D754FF007DBULL,
		0x1355DE681184F7A7ULL,
		0xA450EE76AEB1E2F8ULL,
		0x1E8099C2BC9FC5D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x259F979B7CF47DCEULL,
		0x84E2BE3499FF1882ULL,
		0xCAEF03996F125244ULL,
		0x5EA64C126C7F442FULL,
		0x4B8ADAEA9FE00FB7ULL,
		0x26ABBCD02309EF4FULL,
		0x48A1DCED5D63C5F0ULL,
		0x3D013385793F8BA9ULL
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
		0xE27E62224E9AE4E4ULL,
		0x9D70608827DB3B02ULL,
		0x78BB42AA129EED7EULL,
		0xD00DE45E9AF29DDEULL,
		0x5BB01DCA3F0C0656ULL,
		0x334CDFAAB88910B8ULL,
		0xD938E4C56AC2E115ULL,
		0x036AB939D90C1CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4FCC4449D35C9C8ULL,
		0x3AE0C1104FB67605ULL,
		0xF1768554253DDAFDULL,
		0xA01BC8BD35E53BBCULL,
		0xB7603B947E180CADULL,
		0x6699BF5571122170ULL,
		0xB271C98AD585C22AULL,
		0x06D57273B21839CBULL
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
		0x20CEAEEB7FD9D4C7ULL,
		0xB8874772698BBBFBULL,
		0x9B981D26E095CC03ULL,
		0x4CB3E368CE665B55ULL,
		0xA07958CB1EF5EB4DULL,
		0xB81DF184DB4D178EULL,
		0x721F697874D8D96FULL,
		0x2557178AC5416279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x419D5DD6FFB3A98EULL,
		0x710E8EE4D31777F6ULL,
		0x37303A4DC12B9807ULL,
		0x9967C6D19CCCB6ABULL,
		0x40F2B1963DEBD69AULL,
		0x703BE309B69A2F1DULL,
		0xE43ED2F0E9B1B2DFULL,
		0x4AAE2F158A82C4F2ULL
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
		0x4F0132E7D2904E72ULL,
		0x4DAAD1E543FC2537ULL,
		0xC2192577F6BBCF11ULL,
		0x3BFA8474834227A0ULL,
		0x06F994F92E8ABCAFULL,
		0xFB5E42B728FA24BBULL,
		0xCDC099CE453F04EEULL,
		0x394118FFFFDA9CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0265CFA5209CE4ULL,
		0x9B55A3CA87F84A6EULL,
		0x84324AEFED779E22ULL,
		0x77F508E906844F41ULL,
		0x0DF329F25D15795EULL,
		0xF6BC856E51F44976ULL,
		0x9B81339C8A7E09DDULL,
		0x728231FFFFB53945ULL
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
		0xDEEE5640C073E7BFULL,
		0xC5C1DBFFA3856818ULL,
		0xED237F85D8DA3276ULL,
		0x7DA8A69FF9E3A983ULL,
		0xED563F7094119493ULL,
		0x8978D6365671F840ULL,
		0x4CC485471205CE50ULL,
		0x24174711441396B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDDCAC8180E7CF7EULL,
		0x8B83B7FF470AD031ULL,
		0xDA46FF0BB1B464EDULL,
		0xFB514D3FF3C75307ULL,
		0xDAAC7EE128232926ULL,
		0x12F1AC6CACE3F081ULL,
		0x99890A8E240B9CA1ULL,
		0x482E8E2288272D6AULL
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
		0x2321AFE14AC22ADDULL,
		0x8FA7E7A60883F0FEULL,
		0xB55D97030B995837ULL,
		0xC27C43219B01A4B4ULL,
		0x630EBC7AF27A071CULL,
		0x0FB99A30FFDB265EULL,
		0x634D3F6BB7BCCA86ULL,
		0x05E1C722A35CFA1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46435FC2958455BAULL,
		0x1F4FCF4C1107E1FCULL,
		0x6ABB2E061732B06FULL,
		0x84F8864336034969ULL,
		0xC61D78F5E4F40E39ULL,
		0x1F733461FFB64CBCULL,
		0xC69A7ED76F79950CULL,
		0x0BC38E4546B9F43EULL
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
		0x4B7EA7A02760E326ULL,
		0x9A4F233AD6D015D2ULL,
		0x7CAD145045989EE6ULL,
		0x8B2B746EE8276DFEULL,
		0xFEEDA7ECEFBAD717ULL,
		0x18255C81B90ED1DAULL,
		0xDB4E0CEE43BA5BC1ULL,
		0x2FDBD639B21C8A35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FD4F404EC1C64CULL,
		0x349E4675ADA02BA4ULL,
		0xF95A28A08B313DCDULL,
		0x1656E8DDD04EDBFCULL,
		0xFDDB4FD9DF75AE2FULL,
		0x304AB903721DA3B5ULL,
		0xB69C19DC8774B782ULL,
		0x5FB7AC736439146BULL
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
		0x33F0F1DA7AF3B040ULL,
		0x370755BC5C960736ULL,
		0xCA121A221901C6BAULL,
		0xDFC94C5234C61DAEULL,
		0xE429E7A30E004FB7ULL,
		0xF212215A57D58925ULL,
		0x178824BF72060C1DULL,
		0x0587FBADE785459BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67E1E3B4F5E76080ULL,
		0x6E0EAB78B92C0E6CULL,
		0x9424344432038D74ULL,
		0xBF9298A4698C3B5DULL,
		0xC853CF461C009F6FULL,
		0xE42442B4AFAB124BULL,
		0x2F10497EE40C183BULL,
		0x0B0FF75BCF0A8B36ULL
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
		0x095D6754BEF5984AULL,
		0x278E1B2BCC1A2260ULL,
		0xC29EC7F91D162CCBULL,
		0x9303B9064F86DF3BULL,
		0x7BF7AC67560C5AA7ULL,
		0x46A0F69564D1C407ULL,
		0xE31CF3ACFC79E745ULL,
		0x293ECFBEB9AEB835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12BACEA97DEB3094ULL,
		0x4F1C3657983444C0ULL,
		0x853D8FF23A2C5996ULL,
		0x2607720C9F0DBE77ULL,
		0xF7EF58CEAC18B54FULL,
		0x8D41ED2AC9A3880EULL,
		0xC639E759F8F3CE8AULL,
		0x527D9F7D735D706BULL
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
		0xE662DE3FB6D8159EULL,
		0xC848A9E0BAF1790FULL,
		0x75757A96AA109E0EULL,
		0x4DA01059173799A8ULL,
		0x224332B38C9F87A7ULL,
		0x3A52066390248747ULL,
		0xAF6D0E502B0FBECDULL,
		0x2647C71A1AB1F497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC5BC7F6DB02B3CULL,
		0x909153C175E2F21FULL,
		0xEAEAF52D54213C1DULL,
		0x9B4020B22E6F3350ULL,
		0x44866567193F0F4EULL,
		0x74A40CC720490E8EULL,
		0x5EDA1CA0561F7D9AULL,
		0x4C8F8E343563E92FULL
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
		0x84AF50A642E0541CULL,
		0x64634697617FFE60ULL,
		0xDABDC509B9DE6300ULL,
		0x7BE9F510AAA0B4D2ULL,
		0x0B975E1BDD5954FCULL,
		0x894321BCAFB003D9ULL,
		0x002664CB3D16CC18ULL,
		0x29FEDC77C91BF7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095EA14C85C0A838ULL,
		0xC8C68D2EC2FFFCC1ULL,
		0xB57B8A1373BCC600ULL,
		0xF7D3EA21554169A5ULL,
		0x172EBC37BAB2A9F8ULL,
		0x128643795F6007B2ULL,
		0x004CC9967A2D9831ULL,
		0x53FDB8EF9237EFC8ULL
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
		0x38FCB182990F2802ULL,
		0x0997730B0002CDCDULL,
		0x284CCCC40144C505ULL,
		0x8CE43D2595114247ULL,
		0x404162207CA467A3ULL,
		0xFB7282525EDDC1E3ULL,
		0xFB89A65D91B306AEULL,
		0x13935A7A4EC2D181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F96305321E5004ULL,
		0x132EE61600059B9AULL,
		0x5099998802898A0AULL,
		0x19C87A4B2A22848EULL,
		0x8082C440F948CF47ULL,
		0xF6E504A4BDBB83C6ULL,
		0xF7134CBB23660D5DULL,
		0x2726B4F49D85A303ULL
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
		0x84192DBDBF79D099ULL,
		0xC8A1F170F1807CBFULL,
		0xAFEA7C452164B875ULL,
		0x4AAF12F5C254EF48ULL,
		0x32EAE7083D030F87ULL,
		0xE2CA5B66FEBEA440ULL,
		0x3EA14DEF4E517D5FULL,
		0x1AF1A637E793F9E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08325B7B7EF3A132ULL,
		0x9143E2E1E300F97FULL,
		0x5FD4F88A42C970EBULL,
		0x955E25EB84A9DE91ULL,
		0x65D5CE107A061F0EULL,
		0xC594B6CDFD7D4880ULL,
		0x7D429BDE9CA2FABFULL,
		0x35E34C6FCF27F3D0ULL
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
		0xEB68D5421DF1994CULL,
		0x2B1F0C7FED9D70E4ULL,
		0xA5E20C2787ACA408ULL,
		0xBA1920317449C588ULL,
		0x7E2B5FF753355905ULL,
		0x0C13B653CB56D07AULL,
		0xED59F5ABC5846E67ULL,
		0x0393CD907E2331BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D1AA843BE33298ULL,
		0x563E18FFDB3AE1C9ULL,
		0x4BC4184F0F594810ULL,
		0x74324062E8938B11ULL,
		0xFC56BFEEA66AB20BULL,
		0x18276CA796ADA0F4ULL,
		0xDAB3EB578B08DCCEULL,
		0x07279B20FC466379ULL
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
		0x772749B7EFC7B5CCULL,
		0xB40086ADD73884A5ULL,
		0x8E465A5C3BFC5C4BULL,
		0x76B2D0562C04F81FULL,
		0x745EB67631B31CBDULL,
		0xB84D360BAFC66895ULL,
		0x54E51D7D3AAB273AULL,
		0x017D6B6D4708B305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE4E936FDF8F6B98ULL,
		0x68010D5BAE71094AULL,
		0x1C8CB4B877F8B897ULL,
		0xED65A0AC5809F03FULL,
		0xE8BD6CEC6366397AULL,
		0x709A6C175F8CD12AULL,
		0xA9CA3AFA75564E75ULL,
		0x02FAD6DA8E11660AULL
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
		0x6D2080F63D1CDE2CULL,
		0xCCB669D3E6E7036BULL,
		0x204C358CA4008C86ULL,
		0xCB00E6D97E6CF749ULL,
		0xFF3BE50CD3DE6DACULL,
		0xD221215B1CBCF94BULL,
		0xC468B76634D72F71ULL,
		0x08EC2F06269CD97BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA4101EC7A39BC58ULL,
		0x996CD3A7CDCE06D6ULL,
		0x40986B194801190DULL,
		0x9601CDB2FCD9EE92ULL,
		0xFE77CA19A7BCDB59ULL,
		0xA44242B63979F297ULL,
		0x88D16ECC69AE5EE3ULL,
		0x11D85E0C4D39B2F7ULL
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
		0xF1C74745FD22BBB2ULL,
		0x8BC7545FECF056A2ULL,
		0x4D21512D49EF73E1ULL,
		0x8D2095269953D3DAULL,
		0xE48A9A70389E9930ULL,
		0x7490D9A9E551F33FULL,
		0xA56B1431212800EFULL,
		0x1CF17A7773D79F62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE38E8E8BFA457764ULL,
		0x178EA8BFD9E0AD45ULL,
		0x9A42A25A93DEE7C3ULL,
		0x1A412A4D32A7A7B4ULL,
		0xC91534E0713D3261ULL,
		0xE921B353CAA3E67FULL,
		0x4AD62862425001DEULL,
		0x39E2F4EEE7AF3EC5ULL
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
		0x4F8F8C959FCE28E6ULL,
		0xA3CF2F03E4923F2DULL,
		0xEA9CFBAC6CE449CAULL,
		0x02DC2CE2E576AC27ULL,
		0xA0267EBA22DE59BBULL,
		0x73669F506F01E038ULL,
		0xC06C7ED62B8DD157ULL,
		0x23ADB2126C69FB06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1F192B3F9C51CCULL,
		0x479E5E07C9247E5AULL,
		0xD539F758D9C89395ULL,
		0x05B859C5CAED584FULL,
		0x404CFD7445BCB376ULL,
		0xE6CD3EA0DE03C071ULL,
		0x80D8FDAC571BA2AEULL,
		0x475B6424D8D3F60DULL
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
		0x8AD235CC79A70F81ULL,
		0x7EFA7D2E475872FBULL,
		0xF6E3349B1F964DFCULL,
		0x077662CF5F671D3AULL,
		0x544D76C271680758ULL,
		0x12A51B330E507E5EULL,
		0x4CC584A3FA3D599BULL,
		0x09A514509DB906FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A46B98F34E1F02ULL,
		0xFDF4FA5C8EB0E5F7ULL,
		0xEDC669363F2C9BF8ULL,
		0x0EECC59EBECE3A75ULL,
		0xA89AED84E2D00EB0ULL,
		0x254A36661CA0FCBCULL,
		0x998B0947F47AB336ULL,
		0x134A28A13B720DFAULL
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
		0x674F80F07955D83FULL,
		0x90319766E4BD38EDULL,
		0x4745ABF57D423029ULL,
		0x58F2D1863223ED64ULL,
		0xED99F4F5C46EB025ULL,
		0xC21C829F518D74DCULL,
		0x68BDD6FAD21CD431ULL,
		0x13575CD124E317FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9F01E0F2ABB07EULL,
		0x20632ECDC97A71DAULL,
		0x8E8B57EAFA846053ULL,
		0xB1E5A30C6447DAC8ULL,
		0xDB33E9EB88DD604AULL,
		0x8439053EA31AE9B9ULL,
		0xD17BADF5A439A863ULL,
		0x26AEB9A249C62FF8ULL
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
		0x0999F79EFAA0100BULL,
		0xA6CF5EE4EE1FEE53ULL,
		0x896C9F4258ED935EULL,
		0x60E2C5D510F30240ULL,
		0x3986AEF9D052479FULL,
		0x36F3379E2C7ED628ULL,
		0xD0F9BB77A9C9A544ULL,
		0x2D4D2DA46E2A2906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1333EF3DF5402016ULL,
		0x4D9EBDC9DC3FDCA6ULL,
		0x12D93E84B1DB26BDULL,
		0xC1C58BAA21E60481ULL,
		0x730D5DF3A0A48F3EULL,
		0x6DE66F3C58FDAC50ULL,
		0xA1F376EF53934A88ULL,
		0x5A9A5B48DC54520DULL
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
		0x365C9A364C67BEE9ULL,
		0x981F0530487E78F5ULL,
		0x62020B7034BB3A31ULL,
		0x7BF0D84D57AFD3E3ULL,
		0xB47011D9352D69E9ULL,
		0x22DDC7149E055A29ULL,
		0xEC2907F13C4587DFULL,
		0x164BBF13941BDB40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CB9346C98CF7DD2ULL,
		0x303E0A6090FCF1EAULL,
		0xC40416E069767463ULL,
		0xF7E1B09AAF5FA7C6ULL,
		0x68E023B26A5AD3D2ULL,
		0x45BB8E293C0AB453ULL,
		0xD8520FE2788B0FBEULL,
		0x2C977E272837B681ULL
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
		0x28123ABFC86E7449ULL,
		0x4BAAD4DFE90C0097ULL,
		0xADB4ECF2BCA6CB8DULL,
		0xAC618517AF453ABAULL,
		0x81BB9C88579939B1ULL,
		0x481640B949B35AA1ULL,
		0xB7B0A836C3BB110CULL,
		0x32943927A42ADAC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5024757F90DCE892ULL,
		0x9755A9BFD218012EULL,
		0x5B69D9E5794D971AULL,
		0x58C30A2F5E8A7575ULL,
		0x03773910AF327363ULL,
		0x902C81729366B543ULL,
		0x6F61506D87762218ULL,
		0x6528724F4855B58DULL
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
		0xBD4AB5EA94A043B0ULL,
		0xE3FFA44F53190422ULL,
		0xA1321E1CF52F4C6BULL,
		0xF60F2D9BE86265EDULL,
		0xC01FBBE66D637956ULL,
		0x5A34FE6629696711ULL,
		0x2D6B8581EFC8F29EULL,
		0x3E98317F98850FE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A956BD529408760ULL,
		0xC7FF489EA6320845ULL,
		0x42643C39EA5E98D7ULL,
		0xEC1E5B37D0C4CBDBULL,
		0x803F77CCDAC6F2ADULL,
		0xB469FCCC52D2CE23ULL,
		0x5AD70B03DF91E53CULL,
		0x7D3062FF310A1FCEULL
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
		0x28638BC46E15FE2BULL,
		0x472017D2E3BE1EEEULL,
		0x7B3FBABC3C535AB7ULL,
		0x666222F09B4C67DDULL,
		0x9F27E06B593EBA4BULL,
		0x1541CED91CF5326DULL,
		0xB6E1BBA0B5CA813BULL,
		0x299F5F38FDBA177AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C71788DC2BFC56ULL,
		0x8E402FA5C77C3DDCULL,
		0xF67F757878A6B56EULL,
		0xCCC445E13698CFBAULL,
		0x3E4FC0D6B27D7496ULL,
		0x2A839DB239EA64DBULL,
		0x6DC377416B950276ULL,
		0x533EBE71FB742EF5ULL
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
		0xB2D047992990A68FULL,
		0x8CB9F138C132340BULL,
		0x0F344205B111154BULL,
		0xAC5B09D15DB798D3ULL,
		0x9323CCB884E37C2AULL,
		0x524E65923BACD1AFULL,
		0xB51AABC954FB3BE7ULL,
		0x3C94697F773CF740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A08F3253214D1EULL,
		0x1973E27182646817ULL,
		0x1E68840B62222A97ULL,
		0x58B613A2BB6F31A6ULL,
		0x2647997109C6F855ULL,
		0xA49CCB247759A35FULL,
		0x6A355792A9F677CEULL,
		0x7928D2FEEE79EE81ULL
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
		0xBC5BF72F872178B2ULL,
		0x91D97D9D0CB9F313ULL,
		0xDA420481AA3A4E8BULL,
		0x536CA47941450C6BULL,
		0xBE1D3D0D7039CFE8ULL,
		0xF64BA20F75FFED78ULL,
		0xCE9B4A30C6E21284ULL,
		0x263F2E5FD662FE34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B7EE5F0E42F164ULL,
		0x23B2FB3A1973E627ULL,
		0xB484090354749D17ULL,
		0xA6D948F2828A18D7ULL,
		0x7C3A7A1AE0739FD0ULL,
		0xEC97441EEBFFDAF1ULL,
		0x9D3694618DC42509ULL,
		0x4C7E5CBFACC5FC69ULL
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
		0xC04978949C708048ULL,
		0x2994BB8608C07AFEULL,
		0x7DAF9D53ED436961ULL,
		0x5304F3A80C1B3659ULL,
		0xC3E201C69166E574ULL,
		0x927E9760B1A779EFULL,
		0x3AB3B1ACDBCE339BULL,
		0x3D676D32AF093DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8092F12938E10090ULL,
		0x5329770C1180F5FDULL,
		0xFB5F3AA7DA86D2C2ULL,
		0xA609E75018366CB2ULL,
		0x87C4038D22CDCAE8ULL,
		0x24FD2EC1634EF3DFULL,
		0x75676359B79C6737ULL,
		0x7ACEDA655E127BFCULL
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
		0x3C56085C450C8E84ULL,
		0x1FF96AA9ADE36B50ULL,
		0x5E0095362B0CCC40ULL,
		0xF810292A3E9ACA9BULL,
		0xCB8D0E1CADFF6C1BULL,
		0x0ACF08C16A5050ABULL,
		0x3019691E62B54D33ULL,
		0x2F2FD8B40001E57DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78AC10B88A191D08ULL,
		0x3FF2D5535BC6D6A0ULL,
		0xBC012A6C56199880ULL,
		0xF02052547D359536ULL,
		0x971A1C395BFED837ULL,
		0x159E1182D4A0A157ULL,
		0x6032D23CC56A9A66ULL,
		0x5E5FB1680003CAFAULL
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
		0x69F3375D330E4259ULL,
		0xE2B0B5666ABC5CA9ULL,
		0xECDAEF9DD3C5AB15ULL,
		0xDBF56248757E79B1ULL,
		0x921782F7D4E06070ULL,
		0x6153E5BB015C38F8ULL,
		0xEB525338367FC550ULL,
		0x1855754306B94E3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E66EBA661C84B2ULL,
		0xC5616ACCD578B952ULL,
		0xD9B5DF3BA78B562BULL,
		0xB7EAC490EAFCF363ULL,
		0x242F05EFA9C0C0E1ULL,
		0xC2A7CB7602B871F1ULL,
		0xD6A4A6706CFF8AA0ULL,
		0x30AAEA860D729C77ULL
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
		0x971D66823436651BULL,
		0x40B4EA942821EF0DULL,
		0xD75BCEE2E0C05918ULL,
		0xD25DAFD56015E593ULL,
		0x85791A4050B48B34ULL,
		0x8D8439D851041019ULL,
		0xEC8B9B9A488B72A7ULL,
		0x278F2ED73D30DB88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3ACD04686CCA36ULL,
		0x8169D5285043DE1BULL,
		0xAEB79DC5C180B230ULL,
		0xA4BB5FAAC02BCB27ULL,
		0x0AF23480A1691669ULL,
		0x1B0873B0A2082033ULL,
		0xD91737349116E54FULL,
		0x4F1E5DAE7A61B711ULL
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
		0x8775B14E88D1C3CAULL,
		0xA72F28C131225905ULL,
		0x467A1A4DAA369BB7ULL,
		0x56CB814A442F6F61ULL,
		0x5BD35F7E7CFB4573ULL,
		0xACD5A3A9623F3EE0ULL,
		0xEA7F2557BA190A6AULL,
		0x24EE3F191820150CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEB629D11A38794ULL,
		0x4E5E51826244B20BULL,
		0x8CF4349B546D376FULL,
		0xAD970294885EDEC2ULL,
		0xB7A6BEFCF9F68AE6ULL,
		0x59AB4752C47E7DC0ULL,
		0xD4FE4AAF743214D5ULL,
		0x49DC7E3230402A19ULL
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
		0x6337499963D4BFF0ULL,
		0x23637B84E1B8F667ULL,
		0x486BDF12E879A57CULL,
		0xC97FB5EC3C498B18ULL,
		0x93C92BE2568D6385ULL,
		0x98D7F9D4C42D36A5ULL,
		0xE65FC462D72C8011ULL,
		0x2C99681D669457EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66E9332C7A97FE0ULL,
		0x46C6F709C371ECCEULL,
		0x90D7BE25D0F34AF8ULL,
		0x92FF6BD878931630ULL,
		0x279257C4AD1AC70BULL,
		0x31AFF3A9885A6D4BULL,
		0xCCBF88C5AE590023ULL,
		0x5932D03ACD28AFD5ULL
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
		0xBD019989917958A2ULL,
		0x3F3C0635B482F402ULL,
		0xFBFB3FBF7907C8F7ULL,
		0x9455E0E0550EB7C0ULL,
		0x8B8A937B68D9E105ULL,
		0xD4A499ED18ECFA50ULL,
		0xE21FB57A355F18A4ULL,
		0x06606C0206691AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A03331322F2B144ULL,
		0x7E780C6B6905E805ULL,
		0xF7F67F7EF20F91EEULL,
		0x28ABC1C0AA1D6F81ULL,
		0x171526F6D1B3C20BULL,
		0xA94933DA31D9F4A1ULL,
		0xC43F6AF46ABE3149ULL,
		0x0CC0D8040CD235CFULL
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
		0x23C2BFF5FA053D36ULL,
		0xA02B0464B168D68FULL,
		0x78EA6AF7F2BD8DE6ULL,
		0x83FD03D5F81F7CA7ULL,
		0xB00012E5BCFE38F0ULL,
		0xBBF0D459687E9ECFULL,
		0x067C1A75E5A328B5ULL,
		0x216E6005E2BD1D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47857FEBF40A7A6CULL,
		0x405608C962D1AD1EULL,
		0xF1D4D5EFE57B1BCDULL,
		0x07FA07ABF03EF94EULL,
		0x600025CB79FC71E1ULL,
		0x77E1A8B2D0FD3D9FULL,
		0x0CF834EBCB46516BULL,
		0x42DCC00BC57A3A7CULL
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
		0x1FB3F028AC0B9C2DULL,
		0x18255074E8A82F7DULL,
		0x8994BD105AC887B4ULL,
		0xB757EBB0B6A5294CULL,
		0xACCC3761E705939CULL,
		0x27F8F60E65A3D642ULL,
		0xB691CF59E7995A41ULL,
		0x33FEB9A627D8D36BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F67E0515817385AULL,
		0x304AA0E9D1505EFAULL,
		0x13297A20B5910F68ULL,
		0x6EAFD7616D4A5299ULL,
		0x59986EC3CE0B2739ULL,
		0x4FF1EC1CCB47AC85ULL,
		0x6D239EB3CF32B482ULL,
		0x67FD734C4FB1A6D7ULL
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
		0x14FA03149D626D1CULL,
		0x9BF7E1B3A88337EDULL,
		0x365DDDA24A31A6F2ULL,
		0xE639050936105B66ULL,
		0x194666938A411015ULL,
		0xA96AC5FF1783A1FFULL,
		0x284BEA09E237FE76ULL,
		0x09D7199FF4F4FB94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F406293AC4DA38ULL,
		0x37EFC36751066FDAULL,
		0x6CBBBB4494634DE5ULL,
		0xCC720A126C20B6CCULL,
		0x328CCD271482202BULL,
		0x52D58BFE2F0743FEULL,
		0x5097D413C46FFCEDULL,
		0x13AE333FE9E9F728ULL
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
		0x4792C9EF7CCA42E4ULL,
		0x441EBAAA6CCC1999ULL,
		0x4B4B5FA651AC2D58ULL,
		0x677B3FDE2E18B75AULL,
		0x0B99A52BF25FC217ULL,
		0x826640563141E7ADULL,
		0x7123658930A8B883ULL,
		0x37132D7D2A837495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F2593DEF99485C8ULL,
		0x883D7554D9983332ULL,
		0x9696BF4CA3585AB0ULL,
		0xCEF67FBC5C316EB4ULL,
		0x17334A57E4BF842EULL,
		0x04CC80AC6283CF5AULL,
		0xE246CB1261517107ULL,
		0x6E265AFA5506E92AULL
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
		0x377958A92483D260ULL,
		0xFF26E62A00744832ULL,
		0x7949ED2412127B82ULL,
		0x4350367E234AA237ULL,
		0xFBA3A0691F70B5F4ULL,
		0x38BC239C025B3517ULL,
		0xC2DDDFC89A383CB9ULL,
		0x34DAFB1B19073945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF2B1524907A4C0ULL,
		0xFE4DCC5400E89064ULL,
		0xF293DA482424F705ULL,
		0x86A06CFC4695446EULL,
		0xF74740D23EE16BE8ULL,
		0x7178473804B66A2FULL,
		0x85BBBF9134707972ULL,
		0x69B5F636320E728BULL
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
		0x2622B3A3D071183BULL,
		0xD6F3FE7E8CB96558ULL,
		0x27BBBE650CEDB01EULL,
		0x46B00B70B1B72DD5ULL,
		0x0CA351BCA2501F17ULL,
		0x12133D75B6EEEF62ULL,
		0x1DAAE4DE95E42371ULL,
		0x21D1890A41AD3D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C456747A0E23076ULL,
		0xADE7FCFD1972CAB0ULL,
		0x4F777CCA19DB603DULL,
		0x8D6016E1636E5BAAULL,
		0x1946A37944A03E2EULL,
		0x24267AEB6DDDDEC4ULL,
		0x3B55C9BD2BC846E2ULL,
		0x43A31214835A7A5EULL
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
		0xA46467EC1192A2F5ULL,
		0x556FB9C482C4EF33ULL,
		0x742AE80601A55712ULL,
		0x3F04FF07DD6D6697ULL,
		0xC77F96282A46A1DAULL,
		0xFCCBD846A2E68DE7ULL,
		0x810AEC96D3D14FFBULL,
		0x392DD1A0A5C071E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C8CFD8232545EAULL,
		0xAADF73890589DE67ULL,
		0xE855D00C034AAE24ULL,
		0x7E09FE0FBADACD2EULL,
		0x8EFF2C50548D43B4ULL,
		0xF997B08D45CD1BCFULL,
		0x0215D92DA7A29FF7ULL,
		0x725BA3414B80E3C7ULL
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
		0x1F2358E89A683860ULL,
		0xB1437897367152B6ULL,
		0x00CFA8D23CBF2A49ULL,
		0x08A04F281D745F9CULL,
		0x15A8D5DB0139FA15ULL,
		0x66268EC855C78850ULL,
		0xB20FB8D19A18F087ULL,
		0x3DF84C1E3D8FDCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E46B1D134D070C0ULL,
		0x6286F12E6CE2A56CULL,
		0x019F51A4797E5493ULL,
		0x11409E503AE8BF38ULL,
		0x2B51ABB60273F42AULL,
		0xCC4D1D90AB8F10A0ULL,
		0x641F71A33431E10EULL,
		0x7BF0983C7B1FB947ULL
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
		0xEECF476BCDFDA065ULL,
		0xB78446B99491CC0FULL,
		0xEE51F14D2576D8ACULL,
		0xAB6703D5FA49E349ULL,
		0xA544FA6EE1050194ULL,
		0xB8C0ABC4032531D7ULL,
		0x1F8F9C3FDBADA782ULL,
		0x3232C47DFB223465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9E8ED79BFB40CAULL,
		0x6F088D732923981FULL,
		0xDCA3E29A4AEDB159ULL,
		0x56CE07ABF493C693ULL,
		0x4A89F4DDC20A0329ULL,
		0x71815788064A63AFULL,
		0x3F1F387FB75B4F05ULL,
		0x646588FBF64468CAULL
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
		0xD9FF6F3ED705E9ADULL,
		0xBF7CA62C0604B8F9ULL,
		0x871E25B592DBBAB1ULL,
		0x25880B8DD3F46DC4ULL,
		0x52DE26FE09E8FD83ULL,
		0xE9634B71A6E6CA71ULL,
		0x53D9A3C1558730E1ULL,
		0x1E4489AD7F3B6A88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3FEDE7DAE0BD35AULL,
		0x7EF94C580C0971F3ULL,
		0x0E3C4B6B25B77563ULL,
		0x4B10171BA7E8DB89ULL,
		0xA5BC4DFC13D1FB06ULL,
		0xD2C696E34DCD94E2ULL,
		0xA7B34782AB0E61C3ULL,
		0x3C89135AFE76D510ULL
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