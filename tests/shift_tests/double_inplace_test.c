#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x88C86930EAA3AA67ULL,
		0xD75C3A910AF01689ULL,
		0x7EA0029C34EC09C5ULL,
		0xC7403F5E95612301ULL,
		0xE20FFA7665D06FA3ULL,
		0xB1A639D209C5B3EAULL,
		0xF84FC258380EEC38ULL,
		0x18EB04EC17A34E9FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x1190D261D54754CEULL,
		0xAEB8752215E02D13ULL,
		0xFD40053869D8138BULL,
		0x8E807EBD2AC24602ULL,
		0xC41FF4ECCBA0DF47ULL,
		0x634C73A4138B67D5ULL,
		0xF09F84B0701DD871ULL,
		0x31D609D82F469D3FULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD718271606DB8A1ULL,
		0xAEE854B4E9B8CE5BULL,
		0x4608152ABBCCA4CCULL,
		0xCFD986C91AE68DFEULL,
		0x905126FFCA485FF6ULL,
		0x9808E9F76BFE7FC0ULL,
		0xE65280BE309172DCULL,
		0x1D71CABCB68F1E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE304E2C0DB7142ULL,
		0x5DD0A969D3719CB7ULL,
		0x8C102A5577994999ULL,
		0x9FB30D9235CD1BFCULL,
		0x20A24DFF9490BFEDULL,
		0x3011D3EED7FCFF81ULL,
		0xCCA5017C6122E5B9ULL,
		0x3AE395796D1E3D3BULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x803E851340129388ULL,
		0x4CA04B7BADFC5811ULL,
		0x5D66CE57A5058CF5ULL,
		0x8D2549438A225515ULL,
		0x19D6035ABC92B9A9ULL,
		0x8D7A9E136254DF77ULL,
		0x6D7CE4C5895A5B2FULL,
		0x2D91104FD7AA1058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007D0A2680252710ULL,
		0x994096F75BF8B023ULL,
		0xBACD9CAF4A0B19EAULL,
		0x1A4A92871444AA2AULL,
		0x33AC06B579257353ULL,
		0x1AF53C26C4A9BEEEULL,
		0xDAF9C98B12B4B65FULL,
		0x5B22209FAF5420B0ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2EA4A2A2313D2000ULL,
		0x213C9357A12FE517ULL,
		0xC498A8D85EB071A2ULL,
		0xEB260CDBB82F45FCULL,
		0xF113DF3D570AF556ULL,
		0xC7543B8F9850F9DEULL,
		0x8A5B0BF609D569DBULL,
		0x28F83A4651BF0AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D494544627A4000ULL,
		0x427926AF425FCA2EULL,
		0x893151B0BD60E344ULL,
		0xD64C19B7705E8BF9ULL,
		0xE227BE7AAE15EAADULL,
		0x8EA8771F30A1F3BDULL,
		0x14B617EC13AAD3B7ULL,
		0x51F0748CA37E154DULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x98903AA5EF332124ULL,
		0x6DC8F543428F230FULL,
		0xF085027B6B552831ULL,
		0x7ACB0F01127CFC6FULL,
		0xDD318A7D8F802803ULL,
		0x50347A6CD71F8D89ULL,
		0x9480DBEA971C2A42ULL,
		0x15663950E7E0A658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3120754BDE664248ULL,
		0xDB91EA86851E461FULL,
		0xE10A04F6D6AA5062ULL,
		0xF5961E0224F9F8DFULL,
		0xBA6314FB1F005006ULL,
		0xA068F4D9AE3F1B13ULL,
		0x2901B7D52E385484ULL,
		0x2ACC72A1CFC14CB1ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1DE9D2D176ECB6CAULL,
		0x5A33E46CB3369589ULL,
		0x2A4427E905381AD2ULL,
		0x971A4CFD2928436BULL,
		0x2E74F0F313606B6CULL,
		0x9349E956F0D014DFULL,
		0x4D884CA3A17725D7ULL,
		0x009832E20A7C7FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD3A5A2EDD96D94ULL,
		0xB467C8D9666D2B12ULL,
		0x54884FD20A7035A4ULL,
		0x2E3499FA525086D6ULL,
		0x5CE9E1E626C0D6D9ULL,
		0x2693D2ADE1A029BEULL,
		0x9B10994742EE4BAFULL,
		0x013065C414F8FFD2ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3DFD29CA0C82E12CULL,
		0x8CF7A6EF2B964E55ULL,
		0xEC09EF839ACDFD7DULL,
		0x61BF99EE6B7A5EBDULL,
		0x49706B613C288EAFULL,
		0x7C498AAFAA08A395ULL,
		0xF15834D7C64AF3D6ULL,
		0x2A6EAC3860D26C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BFA53941905C258ULL,
		0x19EF4DDE572C9CAAULL,
		0xD813DF07359BFAFBULL,
		0xC37F33DCD6F4BD7BULL,
		0x92E0D6C278511D5EULL,
		0xF893155F5411472AULL,
		0xE2B069AF8C95E7ACULL,
		0x54DD5870C1A4D851ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x66656E47A6326744ULL,
		0x9CB327E028B0F8E7ULL,
		0x6456B20D9C525CA6ULL,
		0xD86EDEBBEBE38236ULL,
		0x01934530C18A3618ULL,
		0x96D3FDD8D9B3A14DULL,
		0xAF6AA146930DA709ULL,
		0x1CA202804B299ACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCCADC8F4C64CE88ULL,
		0x39664FC05161F1CEULL,
		0xC8AD641B38A4B94DULL,
		0xB0DDBD77D7C7046CULL,
		0x03268A6183146C31ULL,
		0x2DA7FBB1B367429AULL,
		0x5ED5428D261B4E13ULL,
		0x394405009653359DULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC2280834116D5811ULL,
		0xAD7C47EEDC9CC1EEULL,
		0x85E2ACF0E517630EULL,
		0x7D522093BAFE586FULL,
		0x361B1EDED5A829A1ULL,
		0x5F88CA316F167FB4ULL,
		0x19D374192A3363E3ULL,
		0x36C0ECAD48994FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8450106822DAB022ULL,
		0x5AF88FDDB93983DDULL,
		0x0BC559E1CA2EC61DULL,
		0xFAA4412775FCB0DFULL,
		0x6C363DBDAB505342ULL,
		0xBF119462DE2CFF68ULL,
		0x33A6E8325466C7C6ULL,
		0x6D81D95A91329FAAULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F0C27AEDE6FF626ULL,
		0x065F7E5D145A96BBULL,
		0x68994B971B3234C0ULL,
		0xF2FC65CB742B8AFBULL,
		0x56F8A0B398400533ULL,
		0x209514001D15E352ULL,
		0x13A10D18769262C1ULL,
		0x07E0F933BF9483FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E184F5DBCDFEC4CULL,
		0x0CBEFCBA28B52D76ULL,
		0xD132972E36646980ULL,
		0xE5F8CB96E85715F6ULL,
		0xADF1416730800A67ULL,
		0x412A28003A2BC6A4ULL,
		0x27421A30ED24C582ULL,
		0x0FC1F2677F2907F4ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE68CD7B9CA3428C9ULL,
		0x0703FA57B05F233EULL,
		0x57FC17332D3FD10AULL,
		0x35858274B9315920ULL,
		0x119C36BA38878CE4ULL,
		0x3D9828119CD57AD0ULL,
		0xAA68F45A5CAA787FULL,
		0x15BEC21D3F9D63D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD19AF7394685192ULL,
		0x0E07F4AF60BE467DULL,
		0xAFF82E665A7FA214ULL,
		0x6B0B04E97262B240ULL,
		0x23386D74710F19C8ULL,
		0x7B30502339AAF5A0ULL,
		0x54D1E8B4B954F0FEULL,
		0x2B7D843A7F3AC7ADULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA856DC17C9C218EBULL,
		0xFEEA9B2E273ECAD3ULL,
		0x90E30882DCB4CD0AULL,
		0x548622B4E593D281ULL,
		0x39602F6FE2B693AEULL,
		0xEF2BE80E4B8F9991ULL,
		0x3155F5E2C563BB5FULL,
		0x2E60223C650F80A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50ADB82F938431D6ULL,
		0xFDD5365C4E7D95A7ULL,
		0x21C61105B9699A15ULL,
		0xA90C4569CB27A503ULL,
		0x72C05EDFC56D275CULL,
		0xDE57D01C971F3322ULL,
		0x62ABEBC58AC776BFULL,
		0x5CC04478CA1F0144ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x48E88377256DC2F9ULL,
		0x1210A45AE154FC0BULL,
		0xC7C513698D774DD9ULL,
		0x9C560CB2BFF806FFULL,
		0x56B6C8410E467F7BULL,
		0x0D5B156DC3C09701ULL,
		0x01623006768AC629ULL,
		0x100618470B1DE9A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D106EE4ADB85F2ULL,
		0x242148B5C2A9F816ULL,
		0x8F8A26D31AEE9BB2ULL,
		0x38AC19657FF00DFFULL,
		0xAD6D90821C8CFEF7ULL,
		0x1AB62ADB87812E02ULL,
		0x02C4600CED158C52ULL,
		0x200C308E163BD34EULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCA1297F0CFC3F627ULL,
		0xFC171EE9E905C1AAULL,
		0x76B490E6FA31EDB9ULL,
		0xF88CA0D2FAE44768ULL,
		0x8A6B62E882440D61ULL,
		0x26F58FAEF8F3FEFCULL,
		0xE9E9B7A14BA3D1F1ULL,
		0x0BE3E2067357E10DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94252FE19F87EC4EULL,
		0xF82E3DD3D20B8355ULL,
		0xED6921CDF463DB73ULL,
		0xF11941A5F5C88ED0ULL,
		0x14D6C5D104881AC3ULL,
		0x4DEB1F5DF1E7FDF9ULL,
		0xD3D36F429747A3E2ULL,
		0x17C7C40CE6AFC21BULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB22AD0A75CB591E8ULL,
		0xA1CFEE9B201CA33BULL,
		0xF78B3C7276661E12ULL,
		0x43DBF4AEFED2DEACULL,
		0x50B4F00A02DDD6F2ULL,
		0x650FE61189DC09B6ULL,
		0x5E15645BE91854CBULL,
		0x2CBD1C465EAB6800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6455A14EB96B23D0ULL,
		0x439FDD3640394677ULL,
		0xEF1678E4ECCC3C25ULL,
		0x87B7E95DFDA5BD59ULL,
		0xA169E01405BBADE4ULL,
		0xCA1FCC2313B8136CULL,
		0xBC2AC8B7D230A996ULL,
		0x597A388CBD56D000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6270D70F6AA9E681ULL,
		0x9EEF355D5C0429ECULL,
		0x238D6E3FE80A3FA8ULL,
		0x569A76E6CFFE47F5ULL,
		0x80E04A4BBCCEA0A4ULL,
		0x6C42D5356E068BFAULL,
		0xD0C2B1E7A57AF3DFULL,
		0x20FF672BC0E828CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E1AE1ED553CD02ULL,
		0x3DDE6ABAB80853D8ULL,
		0x471ADC7FD0147F51ULL,
		0xAD34EDCD9FFC8FEAULL,
		0x01C09497799D4148ULL,
		0xD885AA6ADC0D17F5ULL,
		0xA18563CF4AF5E7BEULL,
		0x41FECE5781D05195ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0204056E73888308ULL,
		0x6875F8398F653B82ULL,
		0x1AFBBB6D8D52A8D3ULL,
		0x746377C46AC59889ULL,
		0x2E39F13458FF745BULL,
		0x5A7CEE0D2D030E1EULL,
		0xBE5BD27BC026249EULL,
		0x18831FA0262CAD32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04080ADCE7110610ULL,
		0xD0EBF0731ECA7704ULL,
		0x35F776DB1AA551A6ULL,
		0xE8C6EF88D58B3112ULL,
		0x5C73E268B1FEE8B6ULL,
		0xB4F9DC1A5A061C3CULL,
		0x7CB7A4F7804C493CULL,
		0x31063F404C595A65ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7E4CEEDDE7C8824ULL,
		0x2CA0CFE7FC804B0AULL,
		0x3F4ABAB147EB10EAULL,
		0x35243C7C26501E83ULL,
		0x8419AC1B2F19BA76ULL,
		0x4C2E6B6760B4C864ULL,
		0x367B6D9775AADE83ULL,
		0x014C6A1BB68E0A3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FC99DDBBCF91048ULL,
		0x59419FCFF9009615ULL,
		0x7E9575628FD621D4ULL,
		0x6A4878F84CA03D06ULL,
		0x083358365E3374ECULL,
		0x985CD6CEC16990C9ULL,
		0x6CF6DB2EEB55BD06ULL,
		0x0298D4376D1C1474ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x32E503320FE63F9BULL,
		0xB0FF2541A5A3D3FCULL,
		0xB85AA68F134EB367ULL,
		0x3293CA0756111CA5ULL,
		0x9400057D6F9F3F1CULL,
		0xF406490D8FEDF4A3ULL,
		0xDFD1279177DDC2ACULL,
		0x18BC783C30A763A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65CA06641FCC7F36ULL,
		0x61FE4A834B47A7F8ULL,
		0x70B54D1E269D66CFULL,
		0x6527940EAC22394BULL,
		0x28000AFADF3E7E38ULL,
		0xE80C921B1FDBE947ULL,
		0xBFA24F22EFBB8559ULL,
		0x3178F078614EC74DULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x481BAFB44644FBE7ULL,
		0xD10287583E74CA8EULL,
		0x195E84E3E17F226CULL,
		0xE1FA4EDA3E71C932ULL,
		0x6DA3268E1AFFE0DFULL,
		0x2FDADC1372B51BEBULL,
		0x164C3050F771DB7CULL,
		0x38513DF6D5474391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90375F688C89F7CEULL,
		0xA2050EB07CE9951CULL,
		0x32BD09C7C2FE44D9ULL,
		0xC3F49DB47CE39264ULL,
		0xDB464D1C35FFC1BFULL,
		0x5FB5B826E56A37D6ULL,
		0x2C9860A1EEE3B6F8ULL,
		0x70A27BEDAA8E8722ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC937751AE0D0CC0EULL,
		0x8262B5D149B98255ULL,
		0x848BB74399E9A83AULL,
		0x86E4DBC442A67056ULL,
		0x0DA27176C553DE10ULL,
		0xBD071DCD33A3506FULL,
		0xB8D9DD00804E4772ULL,
		0x0D26579EB9ED8B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x926EEA35C1A1981CULL,
		0x04C56BA2937304ABULL,
		0x09176E8733D35075ULL,
		0x0DC9B788854CE0ADULL,
		0x1B44E2ED8AA7BC21ULL,
		0x7A0E3B9A6746A0DEULL,
		0x71B3BA01009C8EE5ULL,
		0x1A4CAF3D73DB163DULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFBBE2FC941ACD5B8ULL,
		0xD0EF0ADA7EE91CE1ULL,
		0x4CA4BFC5A9AE87EEULL,
		0xFC590DEF824EF88EULL,
		0x4E2E441A56463A52ULL,
		0x605209BEAF1938F2ULL,
		0x31A8E68E833D3D9AULL,
		0x1E61300CD5874869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77C5F928359AB70ULL,
		0xA1DE15B4FDD239C3ULL,
		0x99497F8B535D0FDDULL,
		0xF8B21BDF049DF11CULL,
		0x9C5C8834AC8C74A5ULL,
		0xC0A4137D5E3271E4ULL,
		0x6351CD1D067A7B34ULL,
		0x3CC26019AB0E90D2ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x234F652B64D445C6ULL,
		0x026362A559FF5486ULL,
		0x9D1C2B9734C9EB54ULL,
		0x3323159824CE36ECULL,
		0xBF3DCA86F6304E3AULL,
		0x1FA368D77DCD0847ULL,
		0xA9C18A930295C9D5ULL,
		0x1BE8DD680B7A54BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x469ECA56C9A88B8CULL,
		0x04C6C54AB3FEA90CULL,
		0x3A38572E6993D6A8ULL,
		0x66462B30499C6DD9ULL,
		0x7E7B950DEC609C74ULL,
		0x3F46D1AEFB9A108FULL,
		0x53831526052B93AAULL,
		0x37D1BAD016F4A979ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9E207CCB70A5A881ULL,
		0xEF41CBE7727E3503ULL,
		0xA6BB7F48FF821202ULL,
		0xBCB98A001D428E08ULL,
		0x0287C6DDEA1CCE41ULL,
		0x75F774587FFCF7CBULL,
		0xB4641F8279C468DCULL,
		0x3271619CC30751F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C40F996E14B5102ULL,
		0xDE8397CEE4FC6A07ULL,
		0x4D76FE91FF042405ULL,
		0x797314003A851C11ULL,
		0x050F8DBBD4399C83ULL,
		0xEBEEE8B0FFF9EF96ULL,
		0x68C83F04F388D1B8ULL,
		0x64E2C339860EA3E7ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D8695E0E0AFB93BULL,
		0x32B71EDF605BD8F1ULL,
		0x701F1045F856EB61ULL,
		0x70A9BF21F786D06CULL,
		0xB7DF30A3164B7B35ULL,
		0xB9E5423A18DE0BC7ULL,
		0xFBBB9BDCB3B82AAAULL,
		0x1406C9995CB7EC92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0D2BC1C15F7276ULL,
		0x656E3DBEC0B7B1E2ULL,
		0xE03E208BF0ADD6C2ULL,
		0xE1537E43EF0DA0D8ULL,
		0x6FBE61462C96F66AULL,
		0x73CA847431BC178FULL,
		0xF77737B967705555ULL,
		0x280D9332B96FD925ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA0CB6C6CC6D1F33EULL,
		0xDC637669D15E6C1DULL,
		0xECAE1FF0F1788740ULL,
		0x6DEF7CDE9548CB74ULL,
		0xDC6CDEDDF0CB5285ULL,
		0xA1F4DBB58C4F27A5ULL,
		0x5A5DDDE671F9560AULL,
		0x1E902B53E917F74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4196D8D98DA3E67CULL,
		0xB8C6ECD3A2BCD83BULL,
		0xD95C3FE1E2F10E81ULL,
		0xDBDEF9BD2A9196E9ULL,
		0xB8D9BDBBE196A50AULL,
		0x43E9B76B189E4F4BULL,
		0xB4BBBBCCE3F2AC15ULL,
		0x3D2056A7D22FEE94ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x130DEF936C21EA2CULL,
		0xB718EC465E303095ULL,
		0x2A2A33C92A385C77ULL,
		0xC51FD7F00399E674ULL,
		0x31349A237D2E937FULL,
		0xDD72787865E28A09ULL,
		0x695FEB9123028A65ULL,
		0x276316DA8E4E2808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261BDF26D843D458ULL,
		0x6E31D88CBC60612AULL,
		0x545467925470B8EFULL,
		0x8A3FAFE00733CCE8ULL,
		0x62693446FA5D26FFULL,
		0xBAE4F0F0CBC51412ULL,
		0xD2BFD722460514CBULL,
		0x4EC62DB51C9C5010ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF3008D89122A8B11ULL,
		0x7D19F98DC31F6678ULL,
		0x3CCDE801EC1F0FDFULL,
		0xBBB48212091B3C63ULL,
		0x65A862E812760A75ULL,
		0x6D95B347B1BF384AULL,
		0x497E28E5406CDD44ULL,
		0x1F41034973DA6565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6011B1224551622ULL,
		0xFA33F31B863ECCF1ULL,
		0x799BD003D83E1FBEULL,
		0x77690424123678C6ULL,
		0xCB50C5D024EC14EBULL,
		0xDB2B668F637E7094ULL,
		0x92FC51CA80D9BA88ULL,
		0x3E820692E7B4CACAULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x706377F48AF42B7EULL,
		0x3B0870D3996269C3ULL,
		0x04368CCF8B24BAF2ULL,
		0xC42EB9F4BF8EB707ULL,
		0x774F8C2F260F23A5ULL,
		0x6696CFA25137177BULL,
		0x7C0234FB6A7EF008ULL,
		0x0F0428D08F33937AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C6EFE915E856FCULL,
		0x7610E1A732C4D386ULL,
		0x086D199F164975E4ULL,
		0x885D73E97F1D6E0EULL,
		0xEE9F185E4C1E474BULL,
		0xCD2D9F44A26E2EF6ULL,
		0xF80469F6D4FDE010ULL,
		0x1E0851A11E6726F4ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8DEB0D469D9732CFULL,
		0xA7593B46AAC76DA0ULL,
		0x0CF4D10CA074735EULL,
		0x3246D496647309DDULL,
		0xBE945E192634F128ULL,
		0x056217488299E83AULL,
		0xD359F445FA22C919ULL,
		0x19A8072C487D87AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD61A8D3B2E659EULL,
		0x4EB2768D558EDB41ULL,
		0x19E9A21940E8E6BDULL,
		0x648DA92CC8E613BAULL,
		0x7D28BC324C69E250ULL,
		0x0AC42E910533D075ULL,
		0xA6B3E88BF4459232ULL,
		0x33500E5890FB0F5FULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0BB064A3BDD03E78ULL,
		0x8037111AF22D95BAULL,
		0x246FA6DC083A4D48ULL,
		0x542A4922DB974340ULL,
		0x786EB5F1BFC114E0ULL,
		0x50825EB99B86E84BULL,
		0x676D037DE123F94CULL,
		0x3694AA7B19640652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1760C9477BA07CF0ULL,
		0x006E2235E45B2B74ULL,
		0x48DF4DB810749A91ULL,
		0xA8549245B72E8680ULL,
		0xF0DD6BE37F8229C0ULL,
		0xA104BD73370DD096ULL,
		0xCEDA06FBC247F298ULL,
		0x6D2954F632C80CA4ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC3E2A12F35DCF7EULL,
		0xA7EADDD48D2B68DEULL,
		0x01479E8A8D74F513ULL,
		0x258662AB13A5B9D1ULL,
		0x721A46ECB4CEE1ABULL,
		0x2A91DB6BB4814F52ULL,
		0x88BE3A05C29B7412ULL,
		0x0577EE8A6A328FF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x587C5425E6BB9EFCULL,
		0x4FD5BBA91A56D1BDULL,
		0x028F3D151AE9EA27ULL,
		0x4B0CC556274B73A2ULL,
		0xE4348DD9699DC356ULL,
		0x5523B6D769029EA4ULL,
		0x117C740B8536E824ULL,
		0x0AEFDD14D4651FE1ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBF355FB9525150B2ULL,
		0x9D1E64AEFB37B946ULL,
		0x64AC8F4B6EC92996ULL,
		0x6778F0596D9C2566ULL,
		0xC11ED99CF789E5F3ULL,
		0x975AD28E8838993AULL,
		0xCB32ECB75E5E85EBULL,
		0x317E7F329D9ED929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6ABF72A4A2A164ULL,
		0x3A3CC95DF66F728DULL,
		0xC9591E96DD92532DULL,
		0xCEF1E0B2DB384ACCULL,
		0x823DB339EF13CBE6ULL,
		0x2EB5A51D10713275ULL,
		0x9665D96EBCBD0BD7ULL,
		0x62FCFE653B3DB253ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x45AF53904254C34CULL,
		0xC3F459131AD869F0ULL,
		0x0AB43DE91DB400BFULL,
		0xA6D7045DAE3D8131ULL,
		0x968329E95788C085ULL,
		0x13CF3B8193DE4A92ULL,
		0xC1753AA88A377BA1ULL,
		0x25BD285F543B0593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B5EA72084A98698ULL,
		0x87E8B22635B0D3E0ULL,
		0x15687BD23B68017FULL,
		0x4DAE08BB5C7B0262ULL,
		0x2D0653D2AF11810BULL,
		0x279E770327BC9525ULL,
		0x82EA7551146EF742ULL,
		0x4B7A50BEA8760B27ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB2CF1A85F0142FDAULL,
		0x86EBA657E3FEC811ULL,
		0xD32A2FB1CC71ED4CULL,
		0x595E89900A5E65CFULL,
		0x82B662C4C4BCA606ULL,
		0x9735A345BAA57088ULL,
		0x265A202B7BFD1530ULL,
		0x35408F5C99FE0964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659E350BE0285FB4ULL,
		0x0DD74CAFC7FD9023ULL,
		0xA6545F6398E3DA99ULL,
		0xB2BD132014BCCB9FULL,
		0x056CC58989794C0CULL,
		0x2E6B468B754AE111ULL,
		0x4CB44056F7FA2A61ULL,
		0x6A811EB933FC12C8ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC4225941A66AF7DFULL,
		0xE8305AB08154EE27ULL,
		0x4DDC901FE14FA48DULL,
		0xF05EC41B0D8BDFF4ULL,
		0x6C40A88A78D9C29FULL,
		0xC3659C50C1573319ULL,
		0x1CAFEBF5AB918EC4ULL,
		0x1535AAE67C2CA009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8844B2834CD5EFBEULL,
		0xD060B56102A9DC4FULL,
		0x9BB9203FC29F491BULL,
		0xE0BD88361B17BFE8ULL,
		0xD8815114F1B3853FULL,
		0x86CB38A182AE6632ULL,
		0x395FD7EB57231D89ULL,
		0x2A6B55CCF8594012ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x665A10D8AAC1F877ULL,
		0x3F462F5E7956E4ECULL,
		0x0C9D44BC933FD8E9ULL,
		0xAF1A12453A237150ULL,
		0xDE01A92D27450A0EULL,
		0x0F8AF9711DD83C40ULL,
		0xE03271A05A9E9C64ULL,
		0x205B9B18A44E773EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB421B15583F0EEULL,
		0x7E8C5EBCF2ADC9D8ULL,
		0x193A8979267FB1D2ULL,
		0x5E34248A7446E2A0ULL,
		0xBC03525A4E8A141DULL,
		0x1F15F2E23BB07881ULL,
		0xC064E340B53D38C8ULL,
		0x40B73631489CEE7DULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x836110E6E8D53D78ULL,
		0x76C5C36EB072DBF0ULL,
		0x1057A6078C3ED193ULL,
		0xEC149A6CCBDB543FULL,
		0x4A4F257E5FCC6FBAULL,
		0xEAEC422074265870ULL,
		0x7EF21EBC382BC617ULL,
		0x1B290A7B1F61CEC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C221CDD1AA7AF0ULL,
		0xED8B86DD60E5B7E1ULL,
		0x20AF4C0F187DA326ULL,
		0xD82934D997B6A87EULL,
		0x949E4AFCBF98DF75ULL,
		0xD5D88440E84CB0E0ULL,
		0xFDE43D7870578C2FULL,
		0x365214F63EC39D90ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEF748F8704D62DD1ULL,
		0x9568FDFB71AF294DULL,
		0x8E2B37B8F1AFD4A1ULL,
		0x2CDCC9B667AB0C3EULL,
		0x29FF77ACD546F4DAULL,
		0xD335E9B7BD15BBEDULL,
		0xCBBD9AED10FAAF5FULL,
		0x0648366A14B15C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE91F0E09AC5BA2ULL,
		0x2AD1FBF6E35E529BULL,
		0x1C566F71E35FA943ULL,
		0x59B9936CCF56187DULL,
		0x53FEEF59AA8DE9B4ULL,
		0xA66BD36F7A2B77DAULL,
		0x977B35DA21F55EBFULL,
		0x0C906CD42962B917ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCBD2EE11DC8DF710ULL,
		0xD6DAC8C385FE453FULL,
		0x44F2FE1A860BF30FULL,
		0x29724AA0812792B6ULL,
		0x4379B7BC523CCC6EULL,
		0xC8BFD40C47D0304CULL,
		0x3A59D25B5B3EE4A5ULL,
		0x02E6ED137D3C9D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A5DC23B91BEE20ULL,
		0xADB591870BFC8A7FULL,
		0x89E5FC350C17E61FULL,
		0x52E49541024F256CULL,
		0x86F36F78A47998DCULL,
		0x917FA8188FA06098ULL,
		0x74B3A4B6B67DC94BULL,
		0x05CDDA26FA793AD6ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B7941C20841A1FEULL,
		0xDC2F7BB9856FEC81ULL,
		0x112FC278DBAE22A6ULL,
		0xAA0713CA29817CBFULL,
		0x58ABAFE797FD5040ULL,
		0xE7403698589B1F62ULL,
		0x966062F63EF78DC6ULL,
		0x3201514A36A64C44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F28384108343FCULL,
		0xB85EF7730ADFD902ULL,
		0x225F84F1B75C454DULL,
		0x540E27945302F97EULL,
		0xB1575FCF2FFAA081ULL,
		0xCE806D30B1363EC4ULL,
		0x2CC0C5EC7DEF1B8DULL,
		0x6402A2946D4C9889ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x84769FF881EDC633ULL,
		0x8322C5C0A29A4C44ULL,
		0xABBB02DFFA48A2DCULL,
		0x61D766ABDC46B116ULL,
		0x4771348882FFACDAULL,
		0x48CA896FB72D7B9BULL,
		0xDE0988B752C7A137ULL,
		0x07E85B54530376FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08ED3FF103DB8C66ULL,
		0x06458B8145349889ULL,
		0x577605BFF49145B9ULL,
		0xC3AECD57B88D622DULL,
		0x8EE2691105FF59B4ULL,
		0x919512DF6E5AF736ULL,
		0xBC13116EA58F426EULL,
		0x0FD0B6A8A606EDFBULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6065076DB35E2228ULL,
		0x3CF53479F423F3AAULL,
		0x191574ACEE78610DULL,
		0xD2B32C94C35F514FULL,
		0xB37B7E167784C896ULL,
		0x67113AFC78CA8760ULL,
		0x9AD56FEE03E05DB4ULL,
		0x015757AD37A13697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0CA0EDB66BC4450ULL,
		0x79EA68F3E847E754ULL,
		0x322AE959DCF0C21AULL,
		0xA566592986BEA29EULL,
		0x66F6FC2CEF09912DULL,
		0xCE2275F8F1950EC1ULL,
		0x35AADFDC07C0BB68ULL,
		0x02AEAF5A6F426D2FULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEA52AFBD5DFFE7CDULL,
		0xED048E997B4D3C84ULL,
		0x8D68F17A8E785346ULL,
		0xE249EBA9004F03D3ULL,
		0x3080040F8D5243BDULL,
		0x2506622FCC56E462ULL,
		0x6EE421BC369E33FEULL,
		0x237D4A17F59F5A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A55F7ABBFFCF9AULL,
		0xDA091D32F69A7909ULL,
		0x1AD1E2F51CF0A68DULL,
		0xC493D752009E07A7ULL,
		0x6100081F1AA4877BULL,
		0x4A0CC45F98ADC8C4ULL,
		0xDDC843786D3C67FCULL,
		0x46FA942FEB3EB4CAULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0DDA4E2D906293D7ULL,
		0x4D7B6A9CF5AE2C4AULL,
		0xD7B3D00D6F943716ULL,
		0x0232C059F5745417ULL,
		0xE19D417752269F79ULL,
		0x301F041B14120BA7ULL,
		0x3EEFA22A090F0340ULL,
		0x2FB6E7AD4C438D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BB49C5B20C527AEULL,
		0x9AF6D539EB5C5894ULL,
		0xAF67A01ADF286E2CULL,
		0x046580B3EAE8A82FULL,
		0xC33A82EEA44D3EF2ULL,
		0x603E08362824174FULL,
		0x7DDF4454121E0680ULL,
		0x5F6DCF5A98871B12ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x779CC6FD8C2172FDULL,
		0x3DE7B5FEB3F505EEULL,
		0x34565C705A2AFD97ULL,
		0x6761C60460BD6C81ULL,
		0x27D69586316F1617ULL,
		0xE3CD510080301911ULL,
		0xF3E2B4CD49944C0FULL,
		0x06481566D4107D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF398DFB1842E5FAULL,
		0x7BCF6BFD67EA0BDCULL,
		0x68ACB8E0B455FB2EULL,
		0xCEC38C08C17AD902ULL,
		0x4FAD2B0C62DE2C2EULL,
		0xC79AA20100603222ULL,
		0xE7C5699A9328981FULL,
		0x0C902ACDA820FA0BULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3D32F3950BE1D4BDULL,
		0x1909C674F8A8E558ULL,
		0xF682828572B87D56ULL,
		0x41C83DEB973CEF3FULL,
		0xDF6A7F429EF04676ULL,
		0xFAC8828FE4AA259BULL,
		0x5018BF79ACA377F4ULL,
		0x36EC868DF83ECA47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A65E72A17C3A97AULL,
		0x32138CE9F151CAB0ULL,
		0xED05050AE570FAACULL,
		0x83907BD72E79DE7FULL,
		0xBED4FE853DE08CECULL,
		0xF591051FC9544B37ULL,
		0xA0317EF35946EFE9ULL,
		0x6DD90D1BF07D948EULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x33C89998F659D232ULL,
		0xAF1565F94D79E4F0ULL,
		0xD40B552CD95B8720ULL,
		0x5195D85B1ABE2162ULL,
		0xB6A55C267E35FD65ULL,
		0xF45A250658DAD4BEULL,
		0xE47370099FE3ABC7ULL,
		0x3A4286EE32ABEC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67913331ECB3A464ULL,
		0x5E2ACBF29AF3C9E0ULL,
		0xA816AA59B2B70E41ULL,
		0xA32BB0B6357C42C5ULL,
		0x6D4AB84CFC6BFACAULL,
		0xE8B44A0CB1B5A97DULL,
		0xC8E6E0133FC7578FULL,
		0x74850DDC6557D8C7ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8308E58053E83179ULL,
		0x320C075ADAA6A846ULL,
		0xE56F5E0DE6BFEB01ULL,
		0xFE099883D78AC3B5ULL,
		0xE12E5D91456731E4ULL,
		0xCE76E246490F2AD6ULL,
		0x2A1827683258B607ULL,
		0x3A9CFE0ED9CAFD65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0611CB00A7D062F2ULL,
		0x64180EB5B54D508DULL,
		0xCADEBC1BCD7FD602ULL,
		0xFC133107AF15876BULL,
		0xC25CBB228ACE63C9ULL,
		0x9CEDC48C921E55ADULL,
		0x54304ED064B16C0FULL,
		0x7539FC1DB395FACAULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0AD41733B6FDA2C6ULL,
		0xA8562832C5C35403ULL,
		0xA8D506F1A5ED7154ULL,
		0xA48D65DFD4CDF745ULL,
		0x3FD224D0D337BB8BULL,
		0xA703B78376585EA8ULL,
		0x8097B931DAE90F09ULL,
		0x0167AD32FE7DB83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A82E676DFB458CULL,
		0x50AC50658B86A806ULL,
		0x51AA0DE34BDAE2A9ULL,
		0x491ACBBFA99BEE8BULL,
		0x7FA449A1A66F7717ULL,
		0x4E076F06ECB0BD50ULL,
		0x012F7263B5D21E13ULL,
		0x02CF5A65FCFB7075ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9B0EBD4FF9E37C6EULL,
		0x58F090286736D02AULL,
		0x969BA6E49C4241CAULL,
		0xCA9EFBC0A8A0542DULL,
		0x8F95104DE87800DEULL,
		0xAA9018F18E99578EULL,
		0x6F4A611D3CFC2089ULL,
		0x20BF7C9937C15562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x361D7A9FF3C6F8DCULL,
		0xB1E12050CE6DA055ULL,
		0x2D374DC938848394ULL,
		0x953DF7815140A85BULL,
		0x1F2A209BD0F001BDULL,
		0x552031E31D32AF1DULL,
		0xDE94C23A79F84113ULL,
		0x417EF9326F82AAC4ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2006F4CA3D777F17ULL,
		0x8C5A675025ACF5F4ULL,
		0xEA036CE56ABF9FDDULL,
		0xE468183A5605974DULL,
		0x34A8B1125287A145ULL,
		0xBACCAEB6FB65386DULL,
		0x3B053341A1ACC760ULL,
		0x27E023674B73E3C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x400DE9947AEEFE2EULL,
		0x18B4CEA04B59EBE8ULL,
		0xD406D9CAD57F3FBBULL,
		0xC8D03074AC0B2E9BULL,
		0x69516224A50F428BULL,
		0x75995D6DF6CA70DAULL,
		0x760A668343598EC1ULL,
		0x4FC046CE96E7C784ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF42684653F56016FULL,
		0xB17C5128DA8138D8ULL,
		0xF8EB63B4FD5CBD68ULL,
		0x2E2C5CF08FB77D3DULL,
		0xC352F5607B5D6315ULL,
		0x7DA48E6728DA2F7EULL,
		0xCBA7F9E4F145D3AFULL,
		0x18EA586A00B9B560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE84D08CA7EAC02DEULL,
		0x62F8A251B50271B1ULL,
		0xF1D6C769FAB97AD1ULL,
		0x5C58B9E11F6EFA7BULL,
		0x86A5EAC0F6BAC62AULL,
		0xFB491CCE51B45EFDULL,
		0x974FF3C9E28BA75EULL,
		0x31D4B0D401736AC1ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x110F90338C03DC54ULL,
		0x7DC14B0F514F10C4ULL,
		0x6FBC9E6A7E34F2E9ULL,
		0x0E440B7ECC14FD15ULL,
		0xE7E3CEA7CD5652E9ULL,
		0x921C1F29D3940A79ULL,
		0xC66FC776F68183E4ULL,
		0x0D020A6F21FE89CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x221F20671807B8A8ULL,
		0xFB82961EA29E2188ULL,
		0xDF793CD4FC69E5D2ULL,
		0x1C8816FD9829FA2AULL,
		0xCFC79D4F9AACA5D2ULL,
		0x24383E53A72814F3ULL,
		0x8CDF8EEDED0307C9ULL,
		0x1A0414DE43FD139DULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFC8A6E797837E1C9ULL,
		0xB32B3038CF15359FULL,
		0xD0D716231405193AULL,
		0x650E0F0581F20D6EULL,
		0xEAE9EDD1EA862022ULL,
		0x50DA0C89A5128B14ULL,
		0xCB4EDEA62090738BULL,
		0x1F5A6A95F490F844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF914DCF2F06FC392ULL,
		0x665660719E2A6B3FULL,
		0xA1AE2C46280A3275ULL,
		0xCA1C1E0B03E41ADDULL,
		0xD5D3DBA3D50C4044ULL,
		0xA1B419134A251629ULL,
		0x969DBD4C4120E716ULL,
		0x3EB4D52BE921F089ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x56D539FC2D0B171BULL,
		0xE687DBEA8D917915ULL,
		0xBD4B53E52ECD3F7FULL,
		0x6D39FA7B152BB565ULL,
		0x2102596870E9E5D6ULL,
		0x37018E2E2830F952ULL,
		0xBA3726C16ACF9851ULL,
		0x052FE8ED66DCB1EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADAA73F85A162E36ULL,
		0xCD0FB7D51B22F22AULL,
		0x7A96A7CA5D9A7EFFULL,
		0xDA73F4F62A576ACBULL,
		0x4204B2D0E1D3CBACULL,
		0x6E031C5C5061F2A4ULL,
		0x746E4D82D59F30A2ULL,
		0x0A5FD1DACDB963D5ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4136DAC10515AE2ULL,
		0x5EB8089040A00937ULL,
		0x575EB53E8D301E49ULL,
		0xFB7F05DD77ED862CULL,
		0x53BAF85B7F26CEEEULL,
		0xE4C9D5F11DA8EF2DULL,
		0xDF29F914A7C6EB7DULL,
		0x24365FF24EFB8CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE826DB5820A2B5C4ULL,
		0xBD7011208140126FULL,
		0xAEBD6A7D1A603C92ULL,
		0xF6FE0BBAEFDB0C58ULL,
		0xA775F0B6FE4D9DDDULL,
		0xC993ABE23B51DE5AULL,
		0xBE53F2294F8DD6FBULL,
		0x486CBFE49DF719AFULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6CFFF80AE2C5B6EFULL,
		0x79C5D81962E59E65ULL,
		0xB35FE25076F9C89BULL,
		0x2F5BF5B3729D42EEULL,
		0x931A4DE3B8EA042DULL,
		0x634D361E46DBF98BULL,
		0xC369C4E30771B881ULL,
		0x0470D4A4564593D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9FFF015C58B6DDEULL,
		0xF38BB032C5CB3CCAULL,
		0x66BFC4A0EDF39136ULL,
		0x5EB7EB66E53A85DDULL,
		0x26349BC771D4085AULL,
		0xC69A6C3C8DB7F317ULL,
		0x86D389C60EE37102ULL,
		0x08E1A948AC8B27B3ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC9C1533B37378591ULL,
		0x8E94E0FA0CD8159AULL,
		0x39DFD58142E831BBULL,
		0x19C414FBA32F435BULL,
		0x2167B330509116B6ULL,
		0x37965D4591D1035AULL,
		0x69119F873544EB29ULL,
		0x0223283DF1AF13F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9382A6766E6F0B22ULL,
		0x1D29C1F419B02B35ULL,
		0x73BFAB0285D06377ULL,
		0x338829F7465E86B6ULL,
		0x42CF6660A1222D6CULL,
		0x6F2CBA8B23A206B4ULL,
		0xD2233F0E6A89D652ULL,
		0x0446507BE35E27E6ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD37C9BD25B2EB878ULL,
		0x5BF79028045A8AF0ULL,
		0x165B013AC5FECC5CULL,
		0xDD307AF3C3251F79ULL,
		0xC4083F662B5A673CULL,
		0x10C8558EDDCC85A0ULL,
		0xE9FFA8906D58E677ULL,
		0x20059211069C94FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F937A4B65D70F0ULL,
		0xB7EF205008B515E1ULL,
		0x2CB602758BFD98B8ULL,
		0xBA60F5E7864A3EF2ULL,
		0x88107ECC56B4CE79ULL,
		0x2190AB1DBB990B41ULL,
		0xD3FF5120DAB1CCEEULL,
		0x400B24220D3929F5ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1230B9E02DF4C25BULL,
		0x5B2A024477FDC91FULL,
		0xC4BF765A087391B3ULL,
		0xBD790987DC9EA764ULL,
		0xE0BD36457221CC25ULL,
		0x3171967C941168C8ULL,
		0x0F6C34A746BD1545ULL,
		0x002FDB925E2CF0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x246173C05BE984B6ULL,
		0xB6540488EFFB923EULL,
		0x897EECB410E72366ULL,
		0x7AF2130FB93D4EC9ULL,
		0xC17A6C8AE443984BULL,
		0x62E32CF92822D191ULL,
		0x1ED8694E8D7A2A8AULL,
		0x005FB724BC59E1BCULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB0EAB0074C8EA7E9ULL,
		0x52DBC4E8170EB544ULL,
		0xF8F983BFE1789F5CULL,
		0x72B92CCA61955BB8ULL,
		0xEBC20EEE072A3649ULL,
		0x3DDE806E26831FC1ULL,
		0x6D203F385A9A7AD1ULL,
		0x204DA2DBA98E401EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D5600E991D4FD2ULL,
		0xA5B789D02E1D6A89ULL,
		0xF1F3077FC2F13EB8ULL,
		0xE5725994C32AB771ULL,
		0xD7841DDC0E546C92ULL,
		0x7BBD00DC4D063F83ULL,
		0xDA407E70B534F5A2ULL,
		0x409B45B7531C803CULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5CBC53611429117EULL,
		0xDFDB7C0490C7D011ULL,
		0x2AA984E960239AF0ULL,
		0xE867761D45318182ULL,
		0xE64BB6DFB899B74EULL,
		0x9F23E02A54EEBAA1ULL,
		0x1550C1D849EFBF65ULL,
		0x28EAC5BC35A426F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB978A6C2285222FCULL,
		0xBFB6F809218FA022ULL,
		0x555309D2C04735E1ULL,
		0xD0CEEC3A8A630304ULL,
		0xCC976DBF71336E9DULL,
		0x3E47C054A9DD7543ULL,
		0x2AA183B093DF7ECBULL,
		0x51D58B786B484DE4ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0BA1E505D55B59B8ULL,
		0x9BF44B77FCEC6826ULL,
		0x290C8DFFC28666CFULL,
		0xF133D2F005ED6750ULL,
		0x48837FE7CDB5C403ULL,
		0x04E29C5CC6A22EFCULL,
		0xC94B143AECE38E05ULL,
		0x1A307891B349C629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1743CA0BAAB6B370ULL,
		0x37E896EFF9D8D04CULL,
		0x52191BFF850CCD9FULL,
		0xE267A5E00BDACEA0ULL,
		0x9106FFCF9B6B8807ULL,
		0x09C538B98D445DF8ULL,
		0x92962875D9C71C0AULL,
		0x3460F12366938C53ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5B08ADC2E3B8C31CULL,
		0x3F3855D7872B489FULL,
		0x60E9AF4EBDB5B24CULL,
		0x3BD8D2B76921B387ULL,
		0x6972CB82B0797F76ULL,
		0x5B9B941CEC64FB9AULL,
		0x4FF9E091B20A539BULL,
		0x3DB568E40C22E8BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6115B85C7718638ULL,
		0x7E70ABAF0E56913EULL,
		0xC1D35E9D7B6B6498ULL,
		0x77B1A56ED243670EULL,
		0xD2E5970560F2FEECULL,
		0xB7372839D8C9F734ULL,
		0x9FF3C1236414A736ULL,
		0x7B6AD1C81845D174ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8D52D9436C6D1535ULL,
		0x21574F2381EE2729ULL,
		0xD2BBCAB154C98598ULL,
		0x281011252500B39DULL,
		0x9A4091A4BEF82B6CULL,
		0x918FD9952D4244E2ULL,
		0xD9AC71D271CE2928ULL,
		0x39BA003D69488492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA5B286D8DA2A6AULL,
		0x42AE9E4703DC4E53ULL,
		0xA5779562A9930B30ULL,
		0x5020224A4A01673BULL,
		0x348123497DF056D8ULL,
		0x231FB32A5A8489C5ULL,
		0xB358E3A4E39C5251ULL,
		0x7374007AD2910925ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2E095C035F2AD7E7ULL,
		0xE5724CC3665C504DULL,
		0x159FBD4DBFA3FCD4ULL,
		0xC14A5850877EC25EULL,
		0xAA660252E355381AULL,
		0x889399C0EC1365A7ULL,
		0x6EC146F1D4841401ULL,
		0x07176F3234E8798EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C12B806BE55AFCEULL,
		0xCAE49986CCB8A09AULL,
		0x2B3F7A9B7F47F9A9ULL,
		0x8294B0A10EFD84BCULL,
		0x54CC04A5C6AA7035ULL,
		0x11273381D826CB4FULL,
		0xDD828DE3A9082803ULL,
		0x0E2EDE6469D0F31CULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3EFED9FC3FA2DD5AULL,
		0x0EE79C3065237B43ULL,
		0x941354E12FCEA9E2ULL,
		0x1B67A267BA8EF62AULL,
		0x8542235BB88E1E58ULL,
		0x20B6191A9079B37BULL,
		0xF04F221DD7935ECFULL,
		0x0D89613433E8A5BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DFDB3F87F45BAB4ULL,
		0x1DCF3860CA46F686ULL,
		0x2826A9C25F9D53C4ULL,
		0x36CF44CF751DEC55ULL,
		0x0A8446B7711C3CB0ULL,
		0x416C323520F366F7ULL,
		0xE09E443BAF26BD9EULL,
		0x1B12C26867D14B7DULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD71973BF1E156B76ULL,
		0xBCD858DAE590B093ULL,
		0x8D136877F9DC2A74ULL,
		0xF19B8006D67CB1E7ULL,
		0xC4B1DD705B2FB44AULL,
		0x3F0B2AC9C9ACFE6CULL,
		0x24380D86AD86CDCAULL,
		0x1DF9BEA604865F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE32E77E3C2AD6ECULL,
		0x79B0B1B5CB216127ULL,
		0x1A26D0EFF3B854E9ULL,
		0xE337000DACF963CFULL,
		0x8963BAE0B65F6895ULL,
		0x7E1655939359FCD9ULL,
		0x48701B0D5B0D9B94ULL,
		0x3BF37D4C090CBE24ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x67B06454E1480389ULL,
		0x685AA525EA38A782ULL,
		0xC9EB9B99E22192E2ULL,
		0x8C2BCE4E64970833ULL,
		0x9F2AD830DA31B207ULL,
		0x34C1555E39591B26ULL,
		0x30DADFADEE581B24ULL,
		0x05F9B8F1E4CEA9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF60C8A9C2900712ULL,
		0xD0B54A4BD4714F04ULL,
		0x93D73733C44325C4ULL,
		0x18579C9CC92E1067ULL,
		0x3E55B061B463640FULL,
		0x6982AABC72B2364DULL,
		0x61B5BF5BDCB03648ULL,
		0x0BF371E3C99D53C0ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x45E679EE7622A543ULL,
		0xE20DC99BF6243DCCULL,
		0xD8CB68F8BD76A458ULL,
		0x3C4EA513E999603DULL,
		0x3DF939108E166390ULL,
		0xE659B2A2C16EB27EULL,
		0x0714FE3C2EB036C5ULL,
		0x3C882037E706AAA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCCF3DCEC454A86ULL,
		0xC41B9337EC487B98ULL,
		0xB196D1F17AED48B1ULL,
		0x789D4A27D332C07BULL,
		0x7BF272211C2CC720ULL,
		0xCCB3654582DD64FCULL,
		0x0E29FC785D606D8BULL,
		0x7910406FCE0D554AULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x87A83D8697AE4E0FULL,
		0x7137D74876EE3FF2ULL,
		0x98399F9291899467ULL,
		0x9A133BE97122EF23ULL,
		0x653982D48C9918C5ULL,
		0xF1FF971F3DD50BF5ULL,
		0x23705B0F6C6D21C3ULL,
		0x193412238C6953C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F507B0D2F5C9C1EULL,
		0xE26FAE90EDDC7FE5ULL,
		0x30733F25231328CEULL,
		0x342677D2E245DE47ULL,
		0xCA7305A91932318BULL,
		0xE3FF2E3E7BAA17EAULL,
		0x46E0B61ED8DA4387ULL,
		0x3268244718D2A78AULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF872DE776B425354ULL,
		0x3806247DFDCDF1AFULL,
		0x4499FF559007DEA1ULL,
		0x6DD2FC4F80DAD8D4ULL,
		0x10DCB49CFE045213ULL,
		0x5E8E25EEA0E5F98AULL,
		0xA869803AC9F2112FULL,
		0x3D4AE1C78B3BF586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E5BCEED684A6A8ULL,
		0x700C48FBFB9BE35FULL,
		0x8933FEAB200FBD42ULL,
		0xDBA5F89F01B5B1A8ULL,
		0x21B96939FC08A426ULL,
		0xBD1C4BDD41CBF314ULL,
		0x50D3007593E4225EULL,
		0x7A95C38F1677EB0DULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12916ACB932CE2DAULL,
		0xF42068939CE7CA11ULL,
		0x5F7E2EDC9237FAFDULL,
		0xBF07247FDF9BAF10ULL,
		0xCA759A7DF31FF456ULL,
		0x7DC7A6BC3C2574BBULL,
		0x167A1149798A4998ULL,
		0x33545157BBD75711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2522D5972659C5B4ULL,
		0xE840D12739CF9422ULL,
		0xBEFC5DB9246FF5FBULL,
		0x7E0E48FFBF375E20ULL,
		0x94EB34FBE63FE8ADULL,
		0xFB8F4D78784AE977ULL,
		0x2CF42292F3149330ULL,
		0x66A8A2AF77AEAE22ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E48CD765B648052ULL,
		0x2C1BEC8683BC80BBULL,
		0xB2FF3394B2615D09ULL,
		0xA20D5D386EB67225ULL,
		0x3E2B9A269BC35CC8ULL,
		0x69C110CDD1C9C4AFULL,
		0xBCFAA8BA6F25D64CULL,
		0x2CC4C171D691F992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C919AECB6C900A4ULL,
		0x5837D90D07790177ULL,
		0x65FE672964C2BA12ULL,
		0x441ABA70DD6CE44BULL,
		0x7C57344D3786B991ULL,
		0xD382219BA393895EULL,
		0x79F55174DE4BAC98ULL,
		0x598982E3AD23F325ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF911A80D868243FBULL,
		0xA57DBF4F2962A0F3ULL,
		0xEEB940C512D87F86ULL,
		0x2220AEECC22B699CULL,
		0xD63E2649FD6D9185ULL,
		0x8A3895E5C035ACA9ULL,
		0x09B8C710F9704794ULL,
		0x14BA628AC0706010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF223501B0D0487F6ULL,
		0x4AFB7E9E52C541E7ULL,
		0xDD72818A25B0FF0DULL,
		0x44415DD98456D339ULL,
		0xAC7C4C93FADB230AULL,
		0x14712BCB806B5953ULL,
		0x13718E21F2E08F29ULL,
		0x2974C51580E0C020ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x043E6984CD4A57F4ULL,
		0xA224B5FA670B484FULL,
		0xD805B44C75E459F7ULL,
		0x705847C3717EAA10ULL,
		0xB9393535D3B8AD52ULL,
		0xB42B752C066F7512ULL,
		0xFC60300A57250F4DULL,
		0x0CEA16F33A18C1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x087CD3099A94AFE8ULL,
		0x44496BF4CE16909EULL,
		0xB00B6898EBC8B3EFULL,
		0xE0B08F86E2FD5421ULL,
		0x72726A6BA7715AA4ULL,
		0x6856EA580CDEEA25ULL,
		0xF8C06014AE4A1E9BULL,
		0x19D42DE67431838FULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2BAC026CC116C6CULL,
		0x2E46A39ABE0D758AULL,
		0x0F137E7ACC78526AULL,
		0xE6629ABA6415C0C6ULL,
		0x71E04D4E0F0D6E56ULL,
		0xCAED3D6C19488F9AULL,
		0x93160BCB5DA87B65ULL,
		0x1AD5AD9E5BB769F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC575804D9822D8D8ULL,
		0x5C8D47357C1AEB15ULL,
		0x1E26FCF598F0A4D4ULL,
		0xCCC53574C82B818CULL,
		0xE3C09A9C1E1ADCADULL,
		0x95DA7AD832911F34ULL,
		0x262C1796BB50F6CBULL,
		0x35AB5B3CB76ED3E3ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x48B10FBEF1316D16ULL,
		0x612C0BBFD89418E0ULL,
		0x957D88B5968AA0B1ULL,
		0xA0261451322C4BECULL,
		0xA7F5FCEECFA2DAE4ULL,
		0x8F161118F8F0ECE5ULL,
		0x53D39C65E84514E9ULL,
		0x155EF08CC5D6609BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91621F7DE262DA2CULL,
		0xC258177FB12831C0ULL,
		0x2AFB116B2D154162ULL,
		0x404C28A2645897D9ULL,
		0x4FEBF9DD9F45B5C9ULL,
		0x1E2C2231F1E1D9CBULL,
		0xA7A738CBD08A29D3ULL,
		0x2ABDE1198BACC136ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x89C48EE7F65A2C77ULL,
		0xF3B4DCEC9A2C3276ULL,
		0xD4539CE92CB6EBAAULL,
		0x19D5B4895386BFF2ULL,
		0xDC598D2074FABBCEULL,
		0xBD77D67263B25469ULL,
		0xDCA8012E80B63867ULL,
		0x0267C0544DDD1D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13891DCFECB458EEULL,
		0xE769B9D9345864EDULL,
		0xA8A739D2596DD755ULL,
		0x33AB6912A70D7FE5ULL,
		0xB8B31A40E9F5779CULL,
		0x7AEFACE4C764A8D3ULL,
		0xB950025D016C70CFULL,
		0x04CF80A89BBA3B29ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x027A41E65F1C164CULL,
		0xBE65B0135AC91D79ULL,
		0xD98E1D7A744AF2CBULL,
		0x58F0EF3BFEE91583ULL,
		0x83F47C543EB5A564ULL,
		0xE1EF83F725078CE4ULL,
		0xE2802F142C559104ULL,
		0x20B306CB0B6D2063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F483CCBE382C98ULL,
		0x7CCB6026B5923AF2ULL,
		0xB31C3AF4E895E597ULL,
		0xB1E1DE77FDD22B07ULL,
		0x07E8F8A87D6B4AC8ULL,
		0xC3DF07EE4A0F19C9ULL,
		0xC5005E2858AB2209ULL,
		0x41660D9616DA40C7ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D33B82960F497C6ULL,
		0xDFE0CCC3F4244A74ULL,
		0x7828A8CD72446BE6ULL,
		0x11F6645E9BA7EC35ULL,
		0x7D0DDFE3D006DC80ULL,
		0x57655A0485E3585AULL,
		0xEDF64C679DF92051ULL,
		0x192829B6D862D01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A677052C1E92F8CULL,
		0xBFC19987E84894E8ULL,
		0xF051519AE488D7CDULL,
		0x23ECC8BD374FD86AULL,
		0xFA1BBFC7A00DB900ULL,
		0xAECAB4090BC6B0B4ULL,
		0xDBEC98CF3BF240A2ULL,
		0x3250536DB0C5A03DULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5F131A6B34DE31EDULL,
		0x8E0D431C4E2C6176ULL,
		0x4E076B96690AE862ULL,
		0xD65ADCE82898F897ULL,
		0x1BBA94ED53007224ULL,
		0xC3FEB9122A540F8BULL,
		0x8CB31C2A174F0084ULL,
		0x3E3A41FF0BFBEA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE2634D669BC63DAULL,
		0x1C1A86389C58C2ECULL,
		0x9C0ED72CD215D0C5ULL,
		0xACB5B9D05131F12EULL,
		0x377529DAA600E449ULL,
		0x87FD722454A81F16ULL,
		0x196638542E9E0109ULL,
		0x7C7483FE17F7D4CBULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x635EF37DF484BE8DULL,
		0x7C7BFB351E26F9C1ULL,
		0xF1D8C55FEEF9ECB6ULL,
		0xF7A4AE7BE3D6F2ECULL,
		0xC3E3FB3679A49A4BULL,
		0x83F1917F2F3CB2CCULL,
		0x5BF6C8812CDB6644ULL,
		0x119F7125EDD32E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BDE6FBE9097D1AULL,
		0xF8F7F66A3C4DF382ULL,
		0xE3B18ABFDDF3D96CULL,
		0xEF495CF7C7ADE5D9ULL,
		0x87C7F66CF3493497ULL,
		0x07E322FE5E796599ULL,
		0xB7ED910259B6CC89ULL,
		0x233EE24BDBA65CA4ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFDF58AAE02FD2F60ULL,
		0xA39880E303DE3A4BULL,
		0x76845B7A364434F4ULL,
		0xF84A2931D72D8B74ULL,
		0x419E33F2EF49C2A8ULL,
		0x8D1181ADFFDE7DCEULL,
		0xFE6CB9FE6F2891B7ULL,
		0x385877D478721D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEB155C05FA5EC0ULL,
		0x473101C607BC7497ULL,
		0xED08B6F46C8869E9ULL,
		0xF0945263AE5B16E8ULL,
		0x833C67E5DE938551ULL,
		0x1A23035BFFBCFB9CULL,
		0xFCD973FCDE51236FULL,
		0x70B0EFA8F0E43B13ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18B37138E784797DULL,
		0xB341DE812CD95AFBULL,
		0xF77E46EE91520EEAULL,
		0x6F99EB86B9FDB7F6ULL,
		0xEC4E1F2919BD6AF6ULL,
		0x526FB416C5DF8A0DULL,
		0x11726AF8EB4A8937ULL,
		0x04355D5DB4175100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3166E271CF08F2FAULL,
		0x6683BD0259B2B5F6ULL,
		0xEEFC8DDD22A41DD5ULL,
		0xDF33D70D73FB6FEDULL,
		0xD89C3E52337AD5ECULL,
		0xA4DF682D8BBF141BULL,
		0x22E4D5F1D695126EULL,
		0x086ABABB682EA200ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9194C6EDFF6BAB75ULL,
		0x8D953A935CD239DBULL,
		0xC633BDF6CBA66B15ULL,
		0xD38AD27FFB2C2A61ULL,
		0x7B3FA76931BA1B1AULL,
		0x5F9D44E3C479DE2DULL,
		0xFA280F1DFBFD9AD7ULL,
		0x1D3E6E49D9EF480BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23298DDBFED756EAULL,
		0x1B2A7526B9A473B7ULL,
		0x8C677BED974CD62BULL,
		0xA715A4FFF65854C3ULL,
		0xF67F4ED263743635ULL,
		0xBF3A89C788F3BC5AULL,
		0xF4501E3BF7FB35AEULL,
		0x3A7CDC93B3DE9017ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x453C45F9D795ADE4ULL,
		0xD825E586AF941557ULL,
		0x5F50615E7B6443D4ULL,
		0x46B6878A1F8B34F0ULL,
		0x1B2CD27EB59A8741ULL,
		0x653588D45E7FF545ULL,
		0x8FB08D5C2B02CD57ULL,
		0x28D54466DE7F4600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A788BF3AF2B5BC8ULL,
		0xB04BCB0D5F282AAEULL,
		0xBEA0C2BCF6C887A9ULL,
		0x8D6D0F143F1669E0ULL,
		0x3659A4FD6B350E82ULL,
		0xCA6B11A8BCFFEA8AULL,
		0x1F611AB856059AAEULL,
		0x51AA88CDBCFE8C01ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9F299E1F061438CULL,
		0x7046DA04CEAB6D73ULL,
		0xDC30BEAA208694EEULL,
		0x4986209A757261A2ULL,
		0x8C58F3C8129D471EULL,
		0x1FD1ADD57E7695C7ULL,
		0xF561925EA050E17BULL,
		0x2AE7A5A8D18F2D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E533C3E0C28718ULL,
		0xE08DB4099D56DAE7ULL,
		0xB8617D54410D29DCULL,
		0x930C4134EAE4C345ULL,
		0x18B1E790253A8E3CULL,
		0x3FA35BAAFCED2B8FULL,
		0xEAC324BD40A1C2F6ULL,
		0x55CF4B51A31E5A91ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF54E191F04E6AA7BULL,
		0x9F47426737D1B7B7ULL,
		0x2231BC65DCB43045ULL,
		0x9D41A4497CD19457ULL,
		0x9A7FCD9DEBDC6501ULL,
		0x77F31C30CDEA6C3DULL,
		0xF424FC2D71602339ULL,
		0x26E108B1AB8DB56CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9C323E09CD54F6ULL,
		0x3E8E84CE6FA36F6FULL,
		0x446378CBB968608BULL,
		0x3A834892F9A328AEULL,
		0x34FF9B3BD7B8CA03ULL,
		0xEFE638619BD4D87BULL,
		0xE849F85AE2C04672ULL,
		0x4DC21163571B6AD9ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6366E613A4F657AFULL,
		0x53F9EE61248A7159ULL,
		0xAA8F5E0197210A78ULL,
		0x97A917DF128F1409ULL,
		0x8DF13B69F4E03820ULL,
		0x7C0C91FA3A073416ULL,
		0x34BC11E09A89C319ULL,
		0x0DF9FA7ABF941F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CDCC2749ECAF5EULL,
		0xA7F3DCC24914E2B2ULL,
		0x551EBC032E4214F0ULL,
		0x2F522FBE251E2813ULL,
		0x1BE276D3E9C07041ULL,
		0xF81923F4740E682DULL,
		0x697823C135138632ULL,
		0x1BF3F4F57F283E78ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5C9B8465D4FC8BEULL,
		0x20C23B87B1CEED64ULL,
		0x7578DC3FD0BBD6A8ULL,
		0x3B237494BB8304DFULL,
		0xB96F60751A3F74EBULL,
		0xB87F1CBC3ED9A593ULL,
		0x787D1CF0E198ED96ULL,
		0x142241F30A73C12AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB93708CBA9F917CULL,
		0x4184770F639DDAC9ULL,
		0xEAF1B87FA177AD50ULL,
		0x7646E929770609BEULL,
		0x72DEC0EA347EE9D6ULL,
		0x70FE39787DB34B27ULL,
		0xF0FA39E1C331DB2DULL,
		0x284483E614E78254ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x086A2FC49635DCBBULL,
		0xC6879A001EFB3CECULL,
		0x923FBC0B88663C09ULL,
		0xC884EAEC6D65151AULL,
		0x82D95D9FC761125DULL,
		0x8D56D132925B6C99ULL,
		0xF514364D28C4E85DULL,
		0x1CB76F2B8E770EDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10D45F892C6BB976ULL,
		0x8D0F34003DF679D8ULL,
		0x247F781710CC7813ULL,
		0x9109D5D8DACA2A35ULL,
		0x05B2BB3F8EC224BBULL,
		0x1AADA26524B6D933ULL,
		0xEA286C9A5189D0BBULL,
		0x396EDE571CEE1DBFULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA818EC4528C50B84ULL,
		0x3F06BCFD911841D1ULL,
		0xE11B7EB244F5FC69ULL,
		0xF188042D0CFAF99CULL,
		0x87ABCFD1CE470919ULL,
		0x365E0A39355FBE34ULL,
		0xE3C24EC501C62474ULL,
		0x27296143443DA66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5031D88A518A1708ULL,
		0x7E0D79FB223083A3ULL,
		0xC236FD6489EBF8D2ULL,
		0xE310085A19F5F339ULL,
		0x0F579FA39C8E1233ULL,
		0x6CBC14726ABF7C69ULL,
		0xC7849D8A038C48E8ULL,
		0x4E52C286887B4CDDULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x501B8B9D184F433AULL,
		0x884388FD94A332B2ULL,
		0xA53A061BC528C3A9ULL,
		0x00AABF4C8C4BF40BULL,
		0x5B8C10F57C9F54AAULL,
		0x420A43BAC2B6A494ULL,
		0xFDC90EF0EDF327BAULL,
		0x31637B30F37C50DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA037173A309E8674ULL,
		0x108711FB29466564ULL,
		0x4A740C378A518753ULL,
		0x01557E991897E817ULL,
		0xB71821EAF93EA954ULL,
		0x84148775856D4928ULL,
		0xFB921DE1DBE64F74ULL,
		0x62C6F661E6F8A1BDULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB6A792DA3BE6A46ULL,
		0x497FE266B348801BULL,
		0xA595C633988B003AULL,
		0x46A1B2C59E9D019DULL,
		0x42109FBBE0FD20ABULL,
		0x576CBD1CF0C8BAB0ULL,
		0xE2BB2331DADE24F8ULL,
		0x1DFF321FE73686AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D4F25B477CD48CULL,
		0x92FFC4CD66910037ULL,
		0x4B2B8C6731160074ULL,
		0x8D43658B3D3A033BULL,
		0x84213F77C1FA4156ULL,
		0xAED97A39E1917560ULL,
		0xC5764663B5BC49F0ULL,
		0x3BFE643FCE6D0D5DULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x270D19ABB424C6C9ULL,
		0xAD8B946A28E59BB6ULL,
		0x2E60E601146FEE37ULL,
		0xD63F222D24947A81ULL,
		0x3FC5F157FA011B45ULL,
		0xDA182CC560DF776FULL,
		0xE3C93B8137224997ULL,
		0x0E7903D297FF3FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1A335768498D92ULL,
		0x5B1728D451CB376CULL,
		0x5CC1CC0228DFDC6FULL,
		0xAC7E445A4928F502ULL,
		0x7F8BE2AFF402368BULL,
		0xB430598AC1BEEEDEULL,
		0xC79277026E44932FULL,
		0x1CF207A52FFE7FC7ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4EAED966CD13CC27ULL,
		0x2BE0F9943F59F735ULL,
		0x271F2647F9E990E2ULL,
		0x6A52BD1C36E1C056ULL,
		0x6EE8DEFDEA46B305ULL,
		0x19AD383C5350525FULL,
		0x6A5D50580F2B5A25ULL,
		0x19477EB952F2E194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D5DB2CD9A27984EULL,
		0x57C1F3287EB3EE6AULL,
		0x4E3E4C8FF3D321C4ULL,
		0xD4A57A386DC380ACULL,
		0xDDD1BDFBD48D660AULL,
		0x335A7078A6A0A4BEULL,
		0xD4BAA0B01E56B44AULL,
		0x328EFD72A5E5C328ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x38B2F23073EC2108ULL,
		0xB07FC0D89E94F1CEULL,
		0x1A7AC7FAF369225FULL,
		0x2D9CA93E53E802A9ULL,
		0x4410375BA31CA567ULL,
		0xC85808F5050B53BFULL,
		0xAC3A8390813F0624ULL,
		0x37E8642159D8B07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7165E460E7D84210ULL,
		0x60FF81B13D29E39CULL,
		0x34F58FF5E6D244BFULL,
		0x5B39527CA7D00552ULL,
		0x88206EB746394ACEULL,
		0x90B011EA0A16A77EULL,
		0x58750721027E0C49ULL,
		0x6FD0C842B3B160FDULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5884C7C4A9C07EEAULL,
		0x3CE31AFA279A1063ULL,
		0x31F9F01B3FF6735AULL,
		0xED53F0FC924684A5ULL,
		0x9BD6689AF0FD0DF2ULL,
		0xD804352462032DF0ULL,
		0xE17B5087E1628F95ULL,
		0x09D2816686BB0F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1098F895380FDD4ULL,
		0x79C635F44F3420C6ULL,
		0x63F3E0367FECE6B4ULL,
		0xDAA7E1F9248D094AULL,
		0x37ACD135E1FA1BE5ULL,
		0xB0086A48C4065BE1ULL,
		0xC2F6A10FC2C51F2BULL,
		0x13A502CD0D761EA3ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x66593C102327D07AULL,
		0xCB28602D4CDA4A93ULL,
		0x862DFBCA00EA7C32ULL,
		0x74D31FC9F2C0A474ULL,
		0xDE62450B5080529CULL,
		0x4F300F4342440089ULL,
		0x8731C681CDAB84F4ULL,
		0x2F7B071A4B738980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB27820464FA0F4ULL,
		0x9650C05A99B49526ULL,
		0x0C5BF79401D4F865ULL,
		0xE9A63F93E58148E9ULL,
		0xBCC48A16A100A538ULL,
		0x9E601E8684880113ULL,
		0x0E638D039B5709E8ULL,
		0x5EF60E3496E71301ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x22A35181CA2F30BBULL,
		0x848791159A658EB2ULL,
		0xACC2392C5F12B493ULL,
		0xF79D2117688D6EAEULL,
		0xA6BDFCB9EC592E33ULL,
		0x2C8A320A5D78CF41ULL,
		0x815446CB008597D2ULL,
		0x1AF4E1F7BA760448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4546A303945E6176ULL,
		0x090F222B34CB1D64ULL,
		0x59847258BE256927ULL,
		0xEF3A422ED11ADD5DULL,
		0x4D7BF973D8B25C67ULL,
		0x59146414BAF19E83ULL,
		0x02A88D96010B2FA4ULL,
		0x35E9C3EF74EC0891ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC6040ED029710E5AULL,
		0xCDF37E5F2D5AB115ULL,
		0x4015D50961FE5475ULL,
		0x762D2373C0582C5DULL,
		0xC53BC253A71D920BULL,
		0xDB51C2B3F65418DCULL,
		0xF5845E8607EA8F59ULL,
		0x0C32B109ECCE70A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C081DA052E21CB4ULL,
		0x9BE6FCBE5AB5622BULL,
		0x802BAA12C3FCA8EBULL,
		0xEC5A46E780B058BAULL,
		0x8A7784A74E3B2416ULL,
		0xB6A38567ECA831B9ULL,
		0xEB08BD0C0FD51EB3ULL,
		0x18656213D99CE153ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x279DD126CB50551BULL,
		0xFA063313620CAD88ULL,
		0x4D9DF94A0F80745FULL,
		0x150F26D6351EE3D8ULL,
		0xE52407E26F4DB255ULL,
		0x4C5F172D55C7BEDCULL,
		0x66355F939EE24CCDULL,
		0x05876D1C98BAE1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3BA24D96A0AA36ULL,
		0xF40C6626C4195B10ULL,
		0x9B3BF2941F00E8BFULL,
		0x2A1E4DAC6A3DC7B0ULL,
		0xCA480FC4DE9B64AAULL,
		0x98BE2E5AAB8F7DB9ULL,
		0xCC6ABF273DC4999AULL,
		0x0B0EDA393175C3E0ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x282117E745F55DDBULL,
		0x89C2BC379C65084FULL,
		0x1892E33850D43030ULL,
		0xC029295322E397F7ULL,
		0x8F5FAD6DA7159EB4ULL,
		0xBAD345C13BA1BFA6ULL,
		0x3D2E9FF5031B774FULL,
		0x368893CB81B416BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50422FCE8BEABBB6ULL,
		0x1385786F38CA109EULL,
		0x3125C670A1A86061ULL,
		0x805252A645C72FEEULL,
		0x1EBF5ADB4E2B3D69ULL,
		0x75A68B8277437F4DULL,
		0x7A5D3FEA0636EE9FULL,
		0x6D11279703682D74ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB4B872F0780F6AFULL,
		0xB52B563942345EDBULL,
		0x33762903DA73B674ULL,
		0x13EFA2938FB524DBULL,
		0x36EF555C61A1DDACULL,
		0x5F753D294EF9CD10ULL,
		0x7880A35F5B9A5361ULL,
		0x11869539151EBFCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96970E5E0F01ED5EULL,
		0x6A56AC728468BDB7ULL,
		0x66EC5207B4E76CE9ULL,
		0x27DF45271F6A49B6ULL,
		0x6DDEAAB8C343BB58ULL,
		0xBEEA7A529DF39A20ULL,
		0xF10146BEB734A6C2ULL,
		0x230D2A722A3D7F96ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FBD80D5AAEA73B4ULL,
		0xD86EBA65B070B074ULL,
		0xFCB9BD3122D2C4D8ULL,
		0xEE6AD43E87E97584ULL,
		0x1B68BA6B014EB912ULL,
		0x966ADB4A019D68B8ULL,
		0xFC8C728E2B3DF961ULL,
		0x3749EAB587FD967DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F7B01AB55D4E768ULL,
		0xB0DD74CB60E160E8ULL,
		0xF9737A6245A589B1ULL,
		0xDCD5A87D0FD2EB09ULL,
		0x36D174D6029D7225ULL,
		0x2CD5B694033AD170ULL,
		0xF918E51C567BF2C3ULL,
		0x6E93D56B0FFB2CFBULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB67DFE93B034FFDULL,
		0xC1731B281B98E40AULL,
		0x1A95E8475F5F18CDULL,
		0x32EA30EEFAFE9EFAULL,
		0x7A4FA3F26BE36A6BULL,
		0x92546588BB423193ULL,
		0x21DAB8CCF8102732ULL,
		0x14C31E7A508AED75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6CFBFD276069FFAULL,
		0x82E636503731C815ULL,
		0x352BD08EBEBE319BULL,
		0x65D461DDF5FD3DF4ULL,
		0xF49F47E4D7C6D4D6ULL,
		0x24A8CB1176846326ULL,
		0x43B57199F0204E65ULL,
		0x29863CF4A115DAEAULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6B9D7749BE340B64ULL,
		0x15AA58BF6BE15ECEULL,
		0xC325EA58D52C26E1ULL,
		0xB9701E3AC772E9DAULL,
		0x9274F0750E612FB0ULL,
		0xC1C74725D6993F77ULL,
		0x85823CB94AAAECF8ULL,
		0x0FADE2A145141CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD73AEE937C6816C8ULL,
		0x2B54B17ED7C2BD9CULL,
		0x864BD4B1AA584DC2ULL,
		0x72E03C758EE5D3B5ULL,
		0x24E9E0EA1CC25F61ULL,
		0x838E8E4BAD327EEFULL,
		0x0B0479729555D9F1ULL,
		0x1F5BC5428A283945ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7BE096D285C52178ULL,
		0x7729AEE80EB76282ULL,
		0xDDC2025405720007ULL,
		0xF69ACBBDCDF29645ULL,
		0xAF93658C56BFAD07ULL,
		0xD3BF4A8F46A23A5FULL,
		0x6AE28C8898135FCEULL,
		0x1C6A90B5558C2346ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C12DA50B8A42F0ULL,
		0xEE535DD01D6EC504ULL,
		0xBB8404A80AE4000EULL,
		0xED35977B9BE52C8BULL,
		0x5F26CB18AD7F5A0FULL,
		0xA77E951E8D4474BFULL,
		0xD5C519113026BF9DULL,
		0x38D5216AAB18468CULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8AD1BCB3D1FBED9EULL,
		0xCE46F45A3BCC5FB1ULL,
		0x1B0B4371D5069CE7ULL,
		0x9FD6DCA188196AF8ULL,
		0xBF46FE352EAA4F7EULL,
		0x359654851E629D8AULL,
		0x4F09047C689E4CE1ULL,
		0x126FF1AE9B5C7848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A37967A3F7DB3CULL,
		0x9C8DE8B47798BF63ULL,
		0x361686E3AA0D39CFULL,
		0x3FADB9431032D5F0ULL,
		0x7E8DFC6A5D549EFDULL,
		0x6B2CA90A3CC53B15ULL,
		0x9E1208F8D13C99C2ULL,
		0x24DFE35D36B8F090ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A811F9B1C104C82ULL,
		0x4D9239579EFFFBF8ULL,
		0x56697CC1BB8C2FD7ULL,
		0xAC85D7F034EDE10AULL,
		0xAF50976A9BA68CB5ULL,
		0x386BE2E73F135563ULL,
		0xEF7DC6F023FE10A8ULL,
		0x3B41BC2B24CFDF8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15023F3638209904ULL,
		0x9B2472AF3DFFF7F0ULL,
		0xACD2F98377185FAEULL,
		0x590BAFE069DBC214ULL,
		0x5EA12ED5374D196BULL,
		0x70D7C5CE7E26AAC7ULL,
		0xDEFB8DE047FC2150ULL,
		0x76837856499FBF1FULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x733B5772F55EF96FULL,
		0x1EDE1C35BE79A231ULL,
		0x68863DB1D1406144ULL,
		0x74E736FD1E030318ULL,
		0x2394CFEF07CDF9AEULL,
		0x48A21DBC70F433C2ULL,
		0x16D447F3FF57D368ULL,
		0x1416AB2C9F3773E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE676AEE5EABDF2DEULL,
		0x3DBC386B7CF34462ULL,
		0xD10C7B63A280C288ULL,
		0xE9CE6DFA3C060630ULL,
		0x47299FDE0F9BF35CULL,
		0x91443B78E1E86784ULL,
		0x2DA88FE7FEAFA6D0ULL,
		0x282D56593E6EE7C4ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x192BE568C48A0287ULL,
		0xF25341CF1DB3E68BULL,
		0x3D63421948BEF1D6ULL,
		0x7881D39B0591E2BBULL,
		0xD320AC9BE7EAB300ULL,
		0xDDE3747E1D9444D3ULL,
		0x66A3120A63327461ULL,
		0x02DC196D1298064AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3257CAD18914050EULL,
		0xE4A6839E3B67CD16ULL,
		0x7AC68432917DE3ADULL,
		0xF103A7360B23C576ULL,
		0xA6415937CFD56600ULL,
		0xBBC6E8FC3B2889A7ULL,
		0xCD462414C664E8C3ULL,
		0x05B832DA25300C94ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18C87558AC5C6DE3ULL,
		0x835D89FC5C4F011BULL,
		0x24876CC6E74FD920ULL,
		0x859C6AC95C110FD1ULL,
		0x82C15F26AE5C5CFCULL,
		0xA085F730EC28CFCBULL,
		0x1FFAEBA9E5CB74DEULL,
		0x1DF9EC6D2542DED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3190EAB158B8DBC6ULL,
		0x06BB13F8B89E0236ULL,
		0x490ED98DCE9FB241ULL,
		0x0B38D592B8221FA2ULL,
		0x0582BE4D5CB8B9F9ULL,
		0x410BEE61D8519F97ULL,
		0x3FF5D753CB96E9BDULL,
		0x3BF3D8DA4A85BDAEULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDD4F4589F44B3B93ULL,
		0xA4B428DA868020CBULL,
		0x3223CE4438077207ULL,
		0x46D1933D079CC979ULL,
		0x4D9508A59800C561ULL,
		0x95F89C1944CC7D19ULL,
		0x7F5ED0282BCB9CEDULL,
		0x19022B033DC8A1C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA9E8B13E8967726ULL,
		0x496851B50D004197ULL,
		0x64479C88700EE40FULL,
		0x8DA3267A0F3992F2ULL,
		0x9B2A114B30018AC2ULL,
		0x2BF138328998FA32ULL,
		0xFEBDA050579739DBULL,
		0x320456067B914382ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x707ABB8FFC8B05F8ULL,
		0x13CFB806DB9D0A42ULL,
		0x8F9DF0CCAF62C7D6ULL,
		0x30D066FD7EBD9ED4ULL,
		0x1C71FAFA642F6C55ULL,
		0x938288EBFF34D31EULL,
		0x1C870DAF1FE477AAULL,
		0x01899CC1A171832DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0F5771FF9160BF0ULL,
		0x279F700DB73A1484ULL,
		0x1F3BE1995EC58FACULL,
		0x61A0CDFAFD7B3DA9ULL,
		0x38E3F5F4C85ED8AAULL,
		0x270511D7FE69A63CULL,
		0x390E1B5E3FC8EF55ULL,
		0x0313398342E3065AULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6E38837F60AA9184ULL,
		0xDA7EA25003FE695AULL,
		0x7CC4250032E6AF44ULL,
		0x6E7D8CEF150CD7B4ULL,
		0xAAED6C413B0B6AA6ULL,
		0x20C6DF8286210E33ULL,
		0x0FC5F92BCF4BCD71ULL,
		0x0C7C38BC738C7FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC7106FEC1552308ULL,
		0xB4FD44A007FCD2B4ULL,
		0xF9884A0065CD5E89ULL,
		0xDCFB19DE2A19AF68ULL,
		0x55DAD8827616D54CULL,
		0x418DBF050C421C67ULL,
		0x1F8BF2579E979AE2ULL,
		0x18F87178E718FF4EULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D81C3809217C419ULL,
		0x5A772BB8487826E1ULL,
		0x9B5038CB66878DF0ULL,
		0x6C355070073D7BF6ULL,
		0xE8165701EBD10F73ULL,
		0x96135B190DEE5A3CULL,
		0x912D0AB4AD0ABFFAULL,
		0x37BD400C99D98118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B038701242F8832ULL,
		0xB4EE577090F04DC2ULL,
		0x36A07196CD0F1BE0ULL,
		0xD86AA0E00E7AF7EDULL,
		0xD02CAE03D7A21EE6ULL,
		0x2C26B6321BDCB479ULL,
		0x225A15695A157FF5ULL,
		0x6F7A801933B30231ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x02BAE35CAD10120FULL,
		0x4933C6AF5CDD149FULL,
		0x59C134334E12D7B5ULL,
		0xAEBCBB2A8CAF9052ULL,
		0x6AB7960927BE0A25ULL,
		0xD92ACF8FB414E2E2ULL,
		0xC57352AE4B05F9B5ULL,
		0x21A99FC4357C7FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0575C6B95A20241EULL,
		0x92678D5EB9BA293EULL,
		0xB38268669C25AF6AULL,
		0x5D797655195F20A4ULL,
		0xD56F2C124F7C144BULL,
		0xB2559F1F6829C5C4ULL,
		0x8AE6A55C960BF36BULL,
		0x43533F886AF8FF49ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA79600DE5BA20F65ULL,
		0x708D035679139F30ULL,
		0x7624518F33E0C161ULL,
		0x7CDC72125F5D8378ULL,
		0x68C2BA5F79A8816CULL,
		0x7EEB4CAC3EEF12B1ULL,
		0x5BC2D9E5BFD03901ULL,
		0x230ECBC1176CD872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F2C01BCB7441ECAULL,
		0xE11A06ACF2273E61ULL,
		0xEC48A31E67C182C2ULL,
		0xF9B8E424BEBB06F0ULL,
		0xD18574BEF35102D8ULL,
		0xFDD699587DDE2562ULL,
		0xB785B3CB7FA07202ULL,
		0x461D97822ED9B0E4ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA4D6BA891F79502DULL,
		0xD13E046296540D86ULL,
		0x43C8870644AB69D1ULL,
		0x4E61C3B90CA10163ULL,
		0xE3060AC2A92F7821ULL,
		0x1991819CFA9E1F45ULL,
		0xA661C6566D42AD7BULL,
		0x32B535870F0B8F7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AD75123EF2A05AULL,
		0xA27C08C52CA81B0DULL,
		0x87910E0C8956D3A3ULL,
		0x9CC38772194202C6ULL,
		0xC60C1585525EF042ULL,
		0x33230339F53C3E8BULL,
		0x4CC38CACDA855AF6ULL,
		0x656A6B0E1E171EFBULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x76BC5E9593285C6CULL,
		0x12E75E9D20D9BFCBULL,
		0xA73BF9FDC7C49DC2ULL,
		0x2E9E529C65B3BCB9ULL,
		0x7C9EFB60A088B39DULL,
		0x3BDAC8E7EC57463BULL,
		0xEE2E2700B0388AD8ULL,
		0x3AAEC1B43C5E078EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED78BD2B2650B8D8ULL,
		0x25CEBD3A41B37F96ULL,
		0x4E77F3FB8F893B84ULL,
		0x5D3CA538CB677973ULL,
		0xF93DF6C14111673AULL,
		0x77B591CFD8AE8C76ULL,
		0xDC5C4E01607115B0ULL,
		0x755D836878BC0F1DULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73DBF406E4A37F91ULL,
		0x146BB5A82048F87AULL,
		0x46F977470AD6BD32ULL,
		0x96A884CC3DDCDF04ULL,
		0xF499954380A84184ULL,
		0x6B14DA13A71A16E9ULL,
		0xE6A9839E4D94277FULL,
		0x14DAEF454E6FFEBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B7E80DC946FF22ULL,
		0x28D76B504091F0F4ULL,
		0x8DF2EE8E15AD7A64ULL,
		0x2D5109987BB9BE08ULL,
		0xE9332A8701508309ULL,
		0xD629B4274E342DD3ULL,
		0xCD53073C9B284EFEULL,
		0x29B5DE8A9CDFFD7DULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x44460BDBDA2E5E31ULL,
		0x2F323FBAA826B9DCULL,
		0x4238CD48277F1349ULL,
		0xEE71F57F6BBA3D15ULL,
		0x5B10DF07CD77BD3AULL,
		0x031191EBC2FFCFA4ULL,
		0xDEE232E892CB3E4DULL,
		0x2B9F5AE15ABC872EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x888C17B7B45CBC62ULL,
		0x5E647F75504D73B8ULL,
		0x84719A904EFE2692ULL,
		0xDCE3EAFED7747A2AULL,
		0xB621BE0F9AEF7A75ULL,
		0x062323D785FF9F48ULL,
		0xBDC465D125967C9AULL,
		0x573EB5C2B5790E5DULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73DE4CDFF15CAFE4ULL,
		0x96643FE1F50A18EDULL,
		0x0F86283A1FE11537ULL,
		0x4BDC457969C2464DULL,
		0x0320A2E9952DF943ULL,
		0x00EFA53AB65239C7ULL,
		0x5372ED43EC21DABDULL,
		0x2281B5A59B6B3CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7BC99BFE2B95FC8ULL,
		0x2CC87FC3EA1431DAULL,
		0x1F0C50743FC22A6FULL,
		0x97B88AF2D3848C9AULL,
		0x064145D32A5BF286ULL,
		0x01DF4A756CA4738EULL,
		0xA6E5DA87D843B57AULL,
		0x45036B4B36D679D4ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2973EF397219333BULL,
		0x95787BE9674D7A3AULL,
		0xDB70667A47FB4187ULL,
		0x8676085AC2EB9CA2ULL,
		0x65F8D80BA40D6989ULL,
		0x3099D2707271BBD4ULL,
		0x1FA900533D5AB304ULL,
		0x1037FCC2D4C4028BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E7DE72E4326676ULL,
		0x2AF0F7D2CE9AF474ULL,
		0xB6E0CCF48FF6830FULL,
		0x0CEC10B585D73945ULL,
		0xCBF1B017481AD313ULL,
		0x6133A4E0E4E377A8ULL,
		0x3F5200A67AB56608ULL,
		0x206FF985A9880516ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC84B0858593F9FCEULL,
		0xF595842EEFD4C518ULL,
		0x4B7A258F8060EE69ULL,
		0xE3CC3696007C78F9ULL,
		0x214CBA21A00A38ACULL,
		0xE33E7A0B52CCF111ULL,
		0x9689824194F32B6CULL,
		0x346AD779C8D71ED0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909610B0B27F3F9CULL,
		0xEB2B085DDFA98A31ULL,
		0x96F44B1F00C1DCD3ULL,
		0xC7986D2C00F8F1F2ULL,
		0x4299744340147159ULL,
		0xC67CF416A599E222ULL,
		0x2D13048329E656D9ULL,
		0x68D5AEF391AE3DA1ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20953261301AD1CBULL,
		0x680E0743393EB67DULL,
		0xA7CA57C258D0A76AULL,
		0x905143D5FEC93355ULL,
		0x29B899914342C036ULL,
		0xDD61F28A13DCBEBFULL,
		0xF23293030FE255FCULL,
		0x147265D76A46CE92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x412A64C26035A396ULL,
		0xD01C0E86727D6CFAULL,
		0x4F94AF84B1A14ED4ULL,
		0x20A287ABFD9266ABULL,
		0x537133228685806DULL,
		0xBAC3E51427B97D7EULL,
		0xE46526061FC4ABF9ULL,
		0x28E4CBAED48D9D25ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3C9EF880314763EULL,
		0x82E5DDE0404C44D1ULL,
		0x63A86C1DFD7F0A1DULL,
		0x0FE4EC3A19E2669CULL,
		0x3CE78A655F53A91BULL,
		0xBE1072F81D4E0BAFULL,
		0x8F2243CEB437FC23ULL,
		0x2EBFC385BF28B5ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC793DF100628EC7CULL,
		0x05CBBBC0809889A3ULL,
		0xC750D83BFAFE143BULL,
		0x1FC9D87433C4CD38ULL,
		0x79CF14CABEA75236ULL,
		0x7C20E5F03A9C175EULL,
		0x1E44879D686FF847ULL,
		0x5D7F870B7E516BD9ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x04CAAACA0100976CULL,
		0x20883772A01B1C5AULL,
		0x4E8B97D826E6B6D8ULL,
		0x31EC4047245EC885ULL,
		0xC67599FD56F96802ULL,
		0x0670B77359983877ULL,
		0x4AC0723816B1B5B4ULL,
		0x35058841BE68A62EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0995559402012ED8ULL,
		0x41106EE5403638B4ULL,
		0x9D172FB04DCD6DB0ULL,
		0x63D8808E48BD910AULL,
		0x8CEB33FAADF2D004ULL,
		0x0CE16EE6B33070EFULL,
		0x9580E4702D636B68ULL,
		0x6A0B10837CD14C5CULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9CA542A02D2BC1CULL,
		0x70179EA3E170020BULL,
		0x17810EEDF3BC495CULL,
		0x83E086CECFB00F4CULL,
		0x20758A64A93D13E3ULL,
		0x13CFDDE86937CDCEULL,
		0x31D0E5EE4BFAC4C9ULL,
		0x2124F1D57F53C9A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB394A85405A57838ULL,
		0xE02F3D47C2E00417ULL,
		0x2F021DDBE77892B8ULL,
		0x07C10D9D9F601E98ULL,
		0x40EB14C9527A27C7ULL,
		0x279FBBD0D26F9B9CULL,
		0x63A1CBDC97F58992ULL,
		0x4249E3AAFEA79346ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x577501927F3E63BDULL,
		0xD25277A2C4D6CB27ULL,
		0x2F58BFB14D3E889CULL,
		0xB081D07CE6E0297AULL,
		0xAE62F0D04263D55AULL,
		0x32AB0A6F57E334D2ULL,
		0x7257336B977A5E80ULL,
		0x316B5BC15728B3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEEA0324FE7CC77AULL,
		0xA4A4EF4589AD964EULL,
		0x5EB17F629A7D1139ULL,
		0x6103A0F9CDC052F4ULL,
		0x5CC5E1A084C7AAB5ULL,
		0x655614DEAFC669A5ULL,
		0xE4AE66D72EF4BD00ULL,
		0x62D6B782AE516788ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x58E38B5231797CE5ULL,
		0xC9DC6A8D9857DDAFULL,
		0x7D549331F1B8BD76ULL,
		0xA971DFA21412029DULL,
		0x91DF241BF14A189AULL,
		0x202B616ABA2DDB92ULL,
		0x3D3F03A17C2B6BEFULL,
		0x0698B13EE721B355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C716A462F2F9CAULL,
		0x93B8D51B30AFBB5EULL,
		0xFAA92663E3717AEDULL,
		0x52E3BF442824053AULL,
		0x23BE4837E2943135ULL,
		0x4056C2D5745BB725ULL,
		0x7A7E0742F856D7DEULL,
		0x0D31627DCE4366AAULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6ADA2E695B390D07ULL,
		0x5A6398196ABD9049ULL,
		0x781100ED3DBC5136ULL,
		0x7F3EAE558A734056ULL,
		0xE569CE34B7534B8DULL,
		0xCC1694E455213DCEULL,
		0xED86011A51E7A950ULL,
		0x307008D9701D45D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B45CD2B6721A0EULL,
		0xB4C73032D57B2092ULL,
		0xF02201DA7B78A26CULL,
		0xFE7D5CAB14E680ACULL,
		0xCAD39C696EA6971AULL,
		0x982D29C8AA427B9DULL,
		0xDB0C0234A3CF52A1ULL,
		0x60E011B2E03A8BA3ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FC8861586447EB0ULL,
		0x3CFDE45A08CB44F5ULL,
		0xD7A0986089F8834EULL,
		0x8D8A983BF3463AE4ULL,
		0x5958F7B13AFE9AD1ULL,
		0x53E48435AE37C64DULL,
		0x22E6A15568BED555ULL,
		0x1F884BB4CAF82C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F910C2B0C88FD60ULL,
		0x79FBC8B4119689EAULL,
		0xAF4130C113F1069CULL,
		0x1B153077E68C75C9ULL,
		0xB2B1EF6275FD35A3ULL,
		0xA7C9086B5C6F8C9AULL,
		0x45CD42AAD17DAAAAULL,
		0x3F10976995F0592EULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x83F548F3B43263ADULL,
		0xDD5D69F400821176ULL,
		0x3B7DF31C9F899318ULL,
		0xAAEF720B8E564A75ULL,
		0xE7F46AE47A2EDDDBULL,
		0xB779961F6017EBD5ULL,
		0xD601AF7316CB5552ULL,
		0x3B6837E1DA8BBCABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EA91E76864C75AULL,
		0xBABAD3E8010422EDULL,
		0x76FBE6393F132631ULL,
		0x55DEE4171CAC94EAULL,
		0xCFE8D5C8F45DBBB7ULL,
		0x6EF32C3EC02FD7ABULL,
		0xAC035EE62D96AAA5ULL,
		0x76D06FC3B5177957ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD1E3BA5DD05786D9ULL,
		0x183CCEB4205FD3C9ULL,
		0x13E8CB7B68C81E39ULL,
		0x2F4A9A85FC0E3F94ULL,
		0x76E479F4993BB311ULL,
		0x3E70108EF1E698AEULL,
		0xAA4193F2BA5BF73CULL,
		0x23060674A7A56308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C774BBA0AF0DB2ULL,
		0x30799D6840BFA793ULL,
		0x27D196F6D1903C72ULL,
		0x5E95350BF81C7F28ULL,
		0xEDC8F3E932776622ULL,
		0x7CE0211DE3CD315CULL,
		0x548327E574B7EE78ULL,
		0x460C0CE94F4AC611ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5296614B63F2937AULL,
		0xDD26686063E24B54ULL,
		0x823F3B09A50621B0ULL,
		0x41BF1616518E7888ULL,
		0xF83FDF4CFE8729D9ULL,
		0xE0D869BE9FFD5487ULL,
		0x6DD2BB99FF1B5629ULL,
		0x0FC4483A30B97E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA52CC296C7E526F4ULL,
		0xBA4CD0C0C7C496A8ULL,
		0x047E76134A0C4361ULL,
		0x837E2C2CA31CF111ULL,
		0xF07FBE99FD0E53B2ULL,
		0xC1B0D37D3FFAA90FULL,
		0xDBA57733FE36AC53ULL,
		0x1F8890746172FC58ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4B62E6CB43BFE6FCULL,
		0xFDBB92D9859851CDULL,
		0x7DE692FDE8EAB772ULL,
		0xCC13FADC1F3F54C0ULL,
		0x627B9DE6C2D4F3AEULL,
		0xB6B29AA200B08D6CULL,
		0x2B4C862E0B0EF74DULL,
		0x32AE97809BC20BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96C5CD96877FCDF8ULL,
		0xFB7725B30B30A39AULL,
		0xFBCD25FBD1D56EE5ULL,
		0x9827F5B83E7EA980ULL,
		0xC4F73BCD85A9E75DULL,
		0x6D65354401611AD8ULL,
		0x56990C5C161DEE9BULL,
		0x655D2F0137841762ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7B41E4136A130E3ULL,
		0x01FADEE1C7E810F7ULL,
		0x1B32DE23D0000822ULL,
		0x47C6A25AF688D16DULL,
		0xD4AF05B57B5BE17BULL,
		0x1F03D073C4269913ULL,
		0xEDE59C1B7F3FC875ULL,
		0x31CD36D50B5DAF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F683C826D4261C6ULL,
		0x03F5BDC38FD021EFULL,
		0x3665BC47A0001044ULL,
		0x8F8D44B5ED11A2DAULL,
		0xA95E0B6AF6B7C2F6ULL,
		0x3E07A0E7884D3227ULL,
		0xDBCB3836FE7F90EAULL,
		0x639A6DAA16BB5E39ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA90CA55158BD7A7EULL,
		0x6A12B580BB7BD6F8ULL,
		0xAD353E0C9870BFD0ULL,
		0xE6FD5B28DFB52DDAULL,
		0x0F4619D3A8D554E3ULL,
		0x223557B24E05DE17ULL,
		0x2FD27A52F8FFE47EULL,
		0x3FAD61A4BEA40CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52194AA2B17AF4FCULL,
		0xD4256B0176F7ADF1ULL,
		0x5A6A7C1930E17FA0ULL,
		0xCDFAB651BF6A5BB5ULL,
		0x1E8C33A751AAA9C7ULL,
		0x446AAF649C0BBC2EULL,
		0x5FA4F4A5F1FFC8FCULL,
		0x7F5AC3497D4819CCULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F3EC826B3C2A27AULL,
		0x9CAF8CF95E5E1C52ULL,
		0x54F90ACA9F78C1CCULL,
		0xBBBAFFBA1F2CCE01ULL,
		0xFBA1AE99B6A59145ULL,
		0x172B489F5A252A9CULL,
		0x0CDB7A58CCFF064FULL,
		0x20790B395DA5A289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E7D904D678544F4ULL,
		0x395F19F2BCBC38A4ULL,
		0xA9F215953EF18399ULL,
		0x7775FF743E599C02ULL,
		0xF7435D336D4B228BULL,
		0x2E56913EB44A5539ULL,
		0x19B6F4B199FE0C9EULL,
		0x40F21672BB4B4512ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x163B13A620DEA5C6ULL,
		0x7267592034442597ULL,
		0xD5590ABA1035E4F9ULL,
		0x775E5A24C8E7378CULL,
		0x275BE015594E5C30ULL,
		0xF36E79904995E015ULL,
		0x48F1106BCC3A06C4ULL,
		0x2E8248203AA20606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C76274C41BD4B8CULL,
		0xE4CEB24068884B2EULL,
		0xAAB21574206BC9F2ULL,
		0xEEBCB44991CE6F19ULL,
		0x4EB7C02AB29CB860ULL,
		0xE6DCF320932BC02AULL,
		0x91E220D798740D89ULL,
		0x5D04904075440C0CULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBEFA527A719D2E96ULL,
		0x23A967B251ACF5BBULL,
		0x0284FAE67F8CD374ULL,
		0x84A8D8E0474830FFULL,
		0x6BF6C8F1CB0F030AULL,
		0x5DCD09CCE0F60932ULL,
		0x0E8451F69C4AAC0DULL,
		0x38C5F9769DE5EB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF4A4F4E33A5D2CULL,
		0x4752CF64A359EB77ULL,
		0x0509F5CCFF19A6E8ULL,
		0x0951B1C08E9061FEULL,
		0xD7ED91E3961E0615ULL,
		0xBB9A1399C1EC1264ULL,
		0x1D08A3ED3895581AULL,
		0x718BF2ED3BCBD64CULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7A72C11C637AF74BULL,
		0x5900D5DE27C6464FULL,
		0xD1466CF0D87465C3ULL,
		0xBD36A357843E6832ULL,
		0xB096646313335DD9ULL,
		0x687566AFA5CC1164ULL,
		0x03916C26C59709C3ULL,
		0x0658723EC8C340E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E58238C6F5EE96ULL,
		0xB201ABBC4F8C8C9EULL,
		0xA28CD9E1B0E8CB86ULL,
		0x7A6D46AF087CD065ULL,
		0x612CC8C62666BBB3ULL,
		0xD0EACD5F4B9822C9ULL,
		0x0722D84D8B2E1386ULL,
		0x0CB0E47D918681CAULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8D09680A9F48A799ULL,
		0xA157972A95AD0BA1ULL,
		0x6E1880F61C75DCA3ULL,
		0xDAACC4B89CA06F34ULL,
		0xBE04956B5E5AD048ULL,
		0x27BB587E9BAE9F79ULL,
		0x4C493B533353A341ULL,
		0x379211BEDCA89A32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A12D0153E914F32ULL,
		0x42AF2E552B5A1743ULL,
		0xDC3101EC38EBB947ULL,
		0xB55989713940DE68ULL,
		0x7C092AD6BCB5A091ULL,
		0x4F76B0FD375D3EF3ULL,
		0x989276A666A74682ULL,
		0x6F24237DB9513464ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x181ADADAEAF2CA15ULL,
		0x9308E065DA58C619ULL,
		0x381D983E03F8A1D5ULL,
		0xE882252CBBB2A2ECULL,
		0x58EF55C3286ED40BULL,
		0xB976B475D290FAB9ULL,
		0x1C5B787551279BC0ULL,
		0x0AB47785D990D511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3035B5B5D5E5942AULL,
		0x2611C0CBB4B18C32ULL,
		0x703B307C07F143ABULL,
		0xD1044A59776545D8ULL,
		0xB1DEAB8650DDA817ULL,
		0x72ED68EBA521F572ULL,
		0x38B6F0EAA24F3781ULL,
		0x1568EF0BB321AA22ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA024AE8AD6AD75D0ULL,
		0xA65C46338F9E7096ULL,
		0x75F0A9460625B38DULL,
		0x0D71A95144551510ULL,
		0xA25AD72E4BD56661ULL,
		0x19B0AC503EECCC58ULL,
		0x8A61ED05FC235A37ULL,
		0x1E03F8A4CAEB620CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40495D15AD5AEBA0ULL,
		0x4CB88C671F3CE12DULL,
		0xEBE1528C0C4B671BULL,
		0x1AE352A288AA2A20ULL,
		0x44B5AE5C97AACCC2ULL,
		0x336158A07DD998B1ULL,
		0x14C3DA0BF846B46EULL,
		0x3C07F14995D6C419ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3E34FB33C50A30B3ULL,
		0xD61457F7E0A4CD50ULL,
		0x82A0FF90F0B153D2ULL,
		0x2C976836D3A9F725ULL,
		0xED9174D87582A11AULL,
		0x7DCF44B73BE3E151ULL,
		0x30EECB743136DEBCULL,
		0x31F56EB342298A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C69F6678A146166ULL,
		0xAC28AFEFC1499AA0ULL,
		0x0541FF21E162A7A5ULL,
		0x592ED06DA753EE4BULL,
		0xDB22E9B0EB054234ULL,
		0xFB9E896E77C7C2A3ULL,
		0x61DD96E8626DBD78ULL,
		0x63EADD66845314CAULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x37FB197D45F85ACFULL,
		0xCEF13087D13E3CCCULL,
		0x6A4D04D4F61840ACULL,
		0xEB6A1B47B19E4DA5ULL,
		0xEABB22941C1D5C52ULL,
		0x4F913C162045BB9FULL,
		0xA6F51C3385BE3068ULL,
		0x2511F3A9AA318D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF632FA8BF0B59EULL,
		0x9DE2610FA27C7998ULL,
		0xD49A09A9EC308159ULL,
		0xD6D4368F633C9B4AULL,
		0xD5764528383AB8A5ULL,
		0x9F22782C408B773FULL,
		0x4DEA38670B7C60D0ULL,
		0x4A23E75354631A75ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x61F41D63493B4063ULL,
		0x227D009078A242CFULL,
		0x027DA84464833584ULL,
		0xD29E2C8BBC63D608ULL,
		0xE11B72EE765AF112ULL,
		0xBB0F4082BCA4DCB4ULL,
		0x5023E641CE40B237ULL,
		0x29ADE8255D9E5DE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3E83AC6927680C6ULL,
		0x44FA0120F144859EULL,
		0x04FB5088C9066B08ULL,
		0xA53C591778C7AC10ULL,
		0xC236E5DCECB5E225ULL,
		0x761E81057949B969ULL,
		0xA047CC839C81646FULL,
		0x535BD04ABB3CBBCCULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCFA5D03B5A2C16F8ULL,
		0xA5398F74AF600E2BULL,
		0xC67FC61CDF3A4189ULL,
		0x22BAACEBFFAF1F96ULL,
		0x00BEF5D622D96BD9ULL,
		0x3B3AF2E9B5001E73ULL,
		0x311F9200FC9C3335ULL,
		0x3C8612C4C2682AE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F4BA076B4582DF0ULL,
		0x4A731EE95EC01C57ULL,
		0x8CFF8C39BE748313ULL,
		0x457559D7FF5E3F2DULL,
		0x017DEBAC45B2D7B2ULL,
		0x7675E5D36A003CE6ULL,
		0x623F2401F938666AULL,
		0x790C258984D055CCULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF089106DF8792A8FULL,
		0x9D5BE8B57D525967ULL,
		0xC8280EC2BAD03194ULL,
		0xD98CF85E5A16F765ULL,
		0xAD3B12617B7E9C59ULL,
		0xBA05F7056C77590DULL,
		0x1A5F749DD2FE2765ULL,
		0x23472020226D8DBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11220DBF0F2551EULL,
		0x3AB7D16AFAA4B2CFULL,
		0x90501D8575A06329ULL,
		0xB319F0BCB42DEECBULL,
		0x5A7624C2F6FD38B3ULL,
		0x740BEE0AD8EEB21BULL,
		0x34BEE93BA5FC4ECBULL,
		0x468E404044DB1B74ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8945A22CD30F35D3ULL,
		0x0AE65538218D39F5ULL,
		0xC561519ADDBB01EDULL,
		0x14BFE5B41D05CD93ULL,
		0x1DBCD53543C235FFULL,
		0x7D4B0E3000DE43A6ULL,
		0x558CE6E090DF2E96ULL,
		0x35E312ED0066CCADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128B4459A61E6BA6ULL,
		0x15CCAA70431A73EBULL,
		0x8AC2A335BB7603DAULL,
		0x297FCB683A0B9B27ULL,
		0x3B79AA6A87846BFEULL,
		0xFA961C6001BC874CULL,
		0xAB19CDC121BE5D2CULL,
		0x6BC625DA00CD995AULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x062FEE1B03C36553ULL,
		0x47F70A2B8A5C0B35ULL,
		0x90CEB521A635F283ULL,
		0x18BA70CD224082B0ULL,
		0x1CE6AAEE6CD95C4DULL,
		0x666B6BA563CE0CA1ULL,
		0xD514846214FEBBFAULL,
		0x2E1C7642515086E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C5FDC360786CAA6ULL,
		0x8FEE145714B8166AULL,
		0x219D6A434C6BE506ULL,
		0x3174E19A44810561ULL,
		0x39CD55DCD9B2B89AULL,
		0xCCD6D74AC79C1942ULL,
		0xAA2908C429FD77F4ULL,
		0x5C38EC84A2A10DCBULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07E85F277B5FEA00ULL,
		0xB0AB7B5765DC2EA7ULL,
		0x998D591DB1D50B8DULL,
		0xD66478B96C2AF229ULL,
		0xDEC5F02F1BE386F1ULL,
		0x4AD259C926922AA0ULL,
		0x10FA5889939AA833ULL,
		0x2D798603A94FE409ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD0BE4EF6BFD400ULL,
		0x6156F6AECBB85D4EULL,
		0x331AB23B63AA171BULL,
		0xACC8F172D855E453ULL,
		0xBD8BE05E37C70DE3ULL,
		0x95A4B3924D245541ULL,
		0x21F4B11327355066ULL,
		0x5AF30C07529FC812ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x866B468C988C5A74ULL,
		0x60B69EFD6ED335B1ULL,
		0xEEDC826D7553F4FAULL,
		0x752BF3F4F97AA319ULL,
		0x58449B8EA356B5F2ULL,
		0xE4C8C0448A7F0A2BULL,
		0x8E878EAFC63587B8ULL,
		0x3E3A19E57225A304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD68D193118B4E8ULL,
		0xC16D3DFADDA66B63ULL,
		0xDDB904DAEAA7E9F4ULL,
		0xEA57E7E9F2F54633ULL,
		0xB089371D46AD6BE4ULL,
		0xC991808914FE1456ULL,
		0x1D0F1D5F8C6B0F71ULL,
		0x7C7433CAE44B4609ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x70FCFD4591F7FE1AULL,
		0x7CA7B6C9D648C923ULL,
		0x09D893138242FCB5ULL,
		0xAC3C43B425F62F27ULL,
		0xCD86F936214C1D46ULL,
		0x6425553333390DEFULL,
		0x54ABD4D1B9AB311FULL,
		0x2F6BCF2EDD702A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1F9FA8B23EFFC34ULL,
		0xF94F6D93AC919246ULL,
		0x13B126270485F96AULL,
		0x587887684BEC5E4EULL,
		0x9B0DF26C42983A8DULL,
		0xC84AAA6666721BDFULL,
		0xA957A9A37356623EULL,
		0x5ED79E5DBAE0547CULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x89C173957091362EULL,
		0x089CCF3EB34E0336ULL,
		0x70BE454F6FA436A3ULL,
		0x7B549641F5F27479ULL,
		0x6A8B9D9AB6D61CE3ULL,
		0x7C69857C9E0192D8ULL,
		0x9D6039DB40478FD4ULL,
		0x02320639923D0BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1382E72AE1226C5CULL,
		0x11399E7D669C066DULL,
		0xE17C8A9EDF486D46ULL,
		0xF6A92C83EBE4E8F2ULL,
		0xD5173B356DAC39C6ULL,
		0xF8D30AF93C0325B0ULL,
		0x3AC073B6808F1FA8ULL,
		0x04640C73247A17E3ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA328BF9F736754C5ULL,
		0x8774D46285F80BC1ULL,
		0x6032526A04F07C8EULL,
		0x96324F87464F6EBCULL,
		0x6A80EF84EEDC4C4FULL,
		0x3503B94BD1EFACDDULL,
		0x347BAA5AE7E0D03CULL,
		0x1D6B29CBE656C758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46517F3EE6CEA98AULL,
		0x0EE9A8C50BF01783ULL,
		0xC064A4D409E0F91DULL,
		0x2C649F0E8C9EDD78ULL,
		0xD501DF09DDB8989FULL,
		0x6A077297A3DF59BAULL,
		0x68F754B5CFC1A078ULL,
		0x3AD65397CCAD8EB0ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x175EFB388143650CULL,
		0x2BF955C757A0C090ULL,
		0x1A0C71A6A1F4E531ULL,
		0x196C7226B589A998ULL,
		0x604263072F240B5AULL,
		0x9EB84A1C71C34434ULL,
		0x4911DC5544858915ULL,
		0x09B08A498CBC1A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBDF6710286CA18ULL,
		0x57F2AB8EAF418120ULL,
		0x3418E34D43E9CA62ULL,
		0x32D8E44D6B135330ULL,
		0xC084C60E5E4816B4ULL,
		0x3D709438E3868868ULL,
		0x9223B8AA890B122BULL,
		0x13611493197834F2ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x74134B0C88A7407BULL,
		0xFD056139EC381B76ULL,
		0x981C218F6EFBE748ULL,
		0x558F2B79CD6955CDULL,
		0x39037C128E8F7AEBULL,
		0xE15B524F892108E7ULL,
		0x8FEFAA8366BEE344ULL,
		0x37B6929596860A3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8269619114E80F6ULL,
		0xFA0AC273D87036ECULL,
		0x3038431EDDF7CE91ULL,
		0xAB1E56F39AD2AB9BULL,
		0x7206F8251D1EF5D6ULL,
		0xC2B6A49F124211CEULL,
		0x1FDF5506CD7DC689ULL,
		0x6F6D252B2D0C1477ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE77D75C3DD271078ULL,
		0xAAD556C66D53E07FULL,
		0x2295B2E1F66BD647ULL,
		0xB26668DDFE7EA25CULL,
		0xA3A7A522FCE50169ULL,
		0xF00010C5B2F13BB1ULL,
		0xA7BDCEC6C2FBFCE3ULL,
		0x3590CDCC54723F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEFAEB87BA4E20F0ULL,
		0x55AAAD8CDAA7C0FFULL,
		0x452B65C3ECD7AC8FULL,
		0x64CCD1BBFCFD44B8ULL,
		0x474F4A45F9CA02D3ULL,
		0xE000218B65E27763ULL,
		0x4F7B9D8D85F7F9C7ULL,
		0x6B219B98A8E47F3BULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC545F0A9B50E1F51ULL,
		0xFFFE39A053E18EFDULL,
		0xDDCFE9E7F949BEB5ULL,
		0x932B62AD1B7E4FA3ULL,
		0x326353B35F7AA580ULL,
		0xC218D64990A5B774ULL,
		0x38763C8B3BDD2FC2ULL,
		0x3F028874EDE89E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A8BE1536A1C3EA2ULL,
		0xFFFC7340A7C31DFBULL,
		0xBB9FD3CFF2937D6BULL,
		0x2656C55A36FC9F47ULL,
		0x64C6A766BEF54B01ULL,
		0x8431AC93214B6EE8ULL,
		0x70EC791677BA5F85ULL,
		0x7E0510E9DBD13C14ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9730BE8710EDBA47ULL,
		0x234ACE83CF84FACFULL,
		0xC179BEB5182D02C6ULL,
		0x8E7A5AB6C1AD7D47ULL,
		0x0AE4AD449EA49288ULL,
		0x3F11A9E96B3A2D00ULL,
		0x7CB29BEC9DE3A24CULL,
		0x3AB0BAB70B0A05D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E617D0E21DB748EULL,
		0x46959D079F09F59FULL,
		0x82F37D6A305A058CULL,
		0x1CF4B56D835AFA8FULL,
		0x15C95A893D492511ULL,
		0x7E2353D2D6745A00ULL,
		0xF96537D93BC74498ULL,
		0x7561756E16140BAAULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFF6F136CE0C447DDULL,
		0x6DA5952BFB0F1B9EULL,
		0x87A2D4A15C8C9B19ULL,
		0x22518A4DB2536195ULL,
		0xEB8100CC792A7939ULL,
		0x372EFD8C621B79E8ULL,
		0x13C8B8F37BBA6026ULL,
		0x3DA776D67D4C36B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEDE26D9C1888FBAULL,
		0xDB4B2A57F61E373DULL,
		0x0F45A942B9193632ULL,
		0x44A3149B64A6C32BULL,
		0xD7020198F254F272ULL,
		0x6E5DFB18C436F3D1ULL,
		0x279171E6F774C04CULL,
		0x7B4EEDACFA986D64ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE886A58D19C1C15CULL,
		0xDBEBFA0D1402F97CULL,
		0x8B5DFB572AFA15E9ULL,
		0x47B05F3FDBDCCFFDULL,
		0x86DA8D7221B1209BULL,
		0xC4814CED09705A08ULL,
		0xDEBC3F7E527EEEFEULL,
		0x35420049DD5FB30CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD10D4B1A338382B8ULL,
		0xB7D7F41A2805F2F9ULL,
		0x16BBF6AE55F42BD3ULL,
		0x8F60BE7FB7B99FFBULL,
		0x0DB51AE443624136ULL,
		0x890299DA12E0B411ULL,
		0xBD787EFCA4FDDDFDULL,
		0x6A840093BABF6619ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9B2BB90AB8583E68ULL,
		0x62EF06C313D7F897ULL,
		0x3FDD37133CECA8FDULL,
		0xB4D1D51079466EF1ULL,
		0x22822C459F2005EDULL,
		0x2D288F520F3F45A3ULL,
		0xE6BEEBE482F4C364ULL,
		0x3D5F8D5AD60369BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3657721570B07CD0ULL,
		0xC5DE0D8627AFF12FULL,
		0x7FBA6E2679D951FAULL,
		0x69A3AA20F28CDDE2ULL,
		0x4504588B3E400BDBULL,
		0x5A511EA41E7E8B46ULL,
		0xCD7DD7C905E986C8ULL,
		0x7ABF1AB5AC06D37FULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD3E677634BE81DCCULL,
		0x1E9590BF9E59C720ULL,
		0x2DBF2684EE8E0A8EULL,
		0x8FF1FE651C1E37CFULL,
		0x8792988C65DE4455ULL,
		0xAAA5B1DE605CF90AULL,
		0xA57AC19FE4A684BAULL,
		0x18E4814FB167A16FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7CCEEC697D03B98ULL,
		0x3D2B217F3CB38E41ULL,
		0x5B7E4D09DD1C151CULL,
		0x1FE3FCCA383C6F9EULL,
		0x0F253118CBBC88ABULL,
		0x554B63BCC0B9F215ULL,
		0x4AF5833FC94D0975ULL,
		0x31C9029F62CF42DFULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0E206C9BC2F271FEULL,
		0x6FFD9931293CC0C3ULL,
		0x5F3E164F6C3BA115ULL,
		0x5A70C4B2D3A1E847ULL,
		0x3B614CFAD583B762ULL,
		0x7EF3D96E46FA019AULL,
		0x17DEF00806FC0325ULL,
		0x319312AD582FB24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C40D93785E4E3FCULL,
		0xDFFB326252798186ULL,
		0xBE7C2C9ED877422AULL,
		0xB4E18965A743D08EULL,
		0x76C299F5AB076EC4ULL,
		0xFDE7B2DC8DF40334ULL,
		0x2FBDE0100DF8064AULL,
		0x6326255AB05F649CULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x43DAA725E519DE16ULL,
		0xFE4A8FA58285AC84ULL,
		0xD3DB221243B61408ULL,
		0xE8AA41E5965E9D20ULL,
		0x13D494EED757B1ABULL,
		0x0E3CF68772D76029ULL,
		0x2E8A7191BE0F9D2AULL,
		0x0E5AB66E279A93EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B54E4BCA33BC2CULL,
		0xFC951F4B050B5908ULL,
		0xA7B64424876C2811ULL,
		0xD15483CB2CBD3A41ULL,
		0x27A929DDAEAF6357ULL,
		0x1C79ED0EE5AEC052ULL,
		0x5D14E3237C1F3A54ULL,
		0x1CB56CDC4F3527DEULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7F57E44CDE140CBEULL,
		0x880FFCE83FF793E6ULL,
		0xEFE580C45075AA55ULL,
		0xBD57D1141F52294BULL,
		0xF85353CBE321E5D2ULL,
		0xDDE8815DB7247C8BULL,
		0xA8313E6A4AE26718ULL,
		0x25A28C8EDD3BD70DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEAFC899BC28197CULL,
		0x101FF9D07FEF27CCULL,
		0xDFCB0188A0EB54ABULL,
		0x7AAFA2283EA45297ULL,
		0xF0A6A797C643CBA5ULL,
		0xBBD102BB6E48F917ULL,
		0x50627CD495C4CE31ULL,
		0x4B45191DBA77AE1BULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB075CD8CD8B42D30ULL,
		0xB1411D36111CD097ULL,
		0xE79F97E7977C3647ULL,
		0xB38986C4F34818CFULL,
		0x4619ED409BE408E7ULL,
		0x5D0845892AD78991ULL,
		0x4C687F299F9E8122ULL,
		0x267C0AC8EC9CCD8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60EB9B19B1685A60ULL,
		0x62823A6C2239A12FULL,
		0xCF3F2FCF2EF86C8FULL,
		0x67130D89E690319FULL,
		0x8C33DA8137C811CFULL,
		0xBA108B1255AF1322ULL,
		0x98D0FE533F3D0244ULL,
		0x4CF81591D9399B16ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB23E641B4052C2EDULL,
		0xF328BD070802416DULL,
		0xADC62F94B0E28DA9ULL,
		0xF9F9C5326707C592ULL,
		0xB5D6D4BA0650B788ULL,
		0x1BE29F74F1D92F1BULL,
		0x1C166DBE22FF0524ULL,
		0x113700AAEF5743F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647CC83680A585DAULL,
		0xE6517A0E100482DBULL,
		0x5B8C5F2961C51B53ULL,
		0xF3F38A64CE0F8B25ULL,
		0x6BADA9740CA16F11ULL,
		0x37C53EE9E3B25E37ULL,
		0x382CDB7C45FE0A48ULL,
		0x226E0155DEAE87E6ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCED2905238D21CF7ULL,
		0x21447EB98D703E8BULL,
		0x98B66AEC3EB25F62ULL,
		0xE15FC0B390B72E05ULL,
		0xDA99EAFD8DFA1997ULL,
		0x7AE18E5BA7D2D029ULL,
		0x5A3CAB8F6E9B6441ULL,
		0x1B8DDAF7AB392CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA520A471A439EEULL,
		0x4288FD731AE07D17ULL,
		0x316CD5D87D64BEC4ULL,
		0xC2BF8167216E5C0BULL,
		0xB533D5FB1BF4332FULL,
		0xF5C31CB74FA5A053ULL,
		0xB479571EDD36C882ULL,
		0x371BB5EF56725996ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19C372000CCCF639ULL,
		0x2F934B73D31DA986ULL,
		0xC7D214074EF56235ULL,
		0x37049B1110556706ULL,
		0xCCC8C74763671C37ULL,
		0x5BF71EA97FF96AEDULL,
		0xAA5668439D41D133ULL,
		0x1302C6388EA79452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3386E4001999EC72ULL,
		0x5F2696E7A63B530CULL,
		0x8FA4280E9DEAC46AULL,
		0x6E09362220AACE0DULL,
		0x99918E8EC6CE386EULL,
		0xB7EE3D52FFF2D5DBULL,
		0x54ACD0873A83A266ULL,
		0x26058C711D4F28A5ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12D66BF97CDA0070ULL,
		0xA99DC027C5CB0B44ULL,
		0xFAF13E6B5691B5FBULL,
		0x07AC7D0A3A0918C4ULL,
		0xAF0386F617FDEA93ULL,
		0x9904206FB7222148ULL,
		0xB6FD83332C501AA0ULL,
		0x3197FDD201D3D2E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25ACD7F2F9B400E0ULL,
		0x533B804F8B961688ULL,
		0xF5E27CD6AD236BF7ULL,
		0x0F58FA1474123189ULL,
		0x5E070DEC2FFBD526ULL,
		0x320840DF6E444291ULL,
		0x6DFB066658A03541ULL,
		0x632FFBA403A7A5CDULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x59C60C650AE0BB58ULL,
		0xFFD11B42EDCE7780ULL,
		0x12288381A1BA1B1DULL,
		0x3E4F8A3973718A6FULL,
		0x4C9399B1EDC1AE11ULL,
		0x88AB5E7AA39B7486ULL,
		0xD6411564ECCA3F27ULL,
		0x00B5F3F9556919CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB38C18CA15C176B0ULL,
		0xFFA23685DB9CEF00ULL,
		0x245107034374363BULL,
		0x7C9F1472E6E314DEULL,
		0x99273363DB835C22ULL,
		0x1156BCF54736E90CULL,
		0xAC822AC9D9947E4FULL,
		0x016BE7F2AAD23395ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF10DE8F5A50ABE4BULL,
		0x4F386E6A2A287ED5ULL,
		0xCC0448C1A8ED118EULL,
		0x1B1BB49DD6FE37B2ULL,
		0x96C7ED590B4CE4BEULL,
		0xBB68C9EF672FC7FAULL,
		0x0DDEB29C35E9FCFFULL,
		0x086CC3CC938DD382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21BD1EB4A157C96ULL,
		0x9E70DCD45450FDABULL,
		0x9808918351DA231CULL,
		0x3637693BADFC6F65ULL,
		0x2D8FDAB21699C97CULL,
		0x76D193DECE5F8FF5ULL,
		0x1BBD65386BD3F9FFULL,
		0x10D98799271BA704ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x994CD4D776C54F31ULL,
		0xFC70A85F48F70198ULL,
		0xD282B126F87A3D00ULL,
		0xE61EEA1FBD39C0CEULL,
		0x331EC28D96CBDD7AULL,
		0x37686280C0047087ULL,
		0xE387ECA144897A5DULL,
		0x1605B690D98C8272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3299A9AEED8A9E62ULL,
		0xF8E150BE91EE0331ULL,
		0xA505624DF0F47A01ULL,
		0xCC3DD43F7A73819DULL,
		0x663D851B2D97BAF5ULL,
		0x6ED0C5018008E10EULL,
		0xC70FD9428912F4BAULL,
		0x2C0B6D21B31904E5ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB8C053732CCF8E86ULL,
		0xE49E5CCB4C1C5493ULL,
		0xF0D6D42C115ABC49ULL,
		0xE0BBC00F388BFF7FULL,
		0x7AD95CF6C62EC93AULL,
		0x88DD193135A29051ULL,
		0x682535E4A66C6068ULL,
		0x0927FE7F3D9B842DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7180A6E6599F1D0CULL,
		0xC93CB9969838A927ULL,
		0xE1ADA85822B57893ULL,
		0xC177801E7117FEFFULL,
		0xF5B2B9ED8C5D9275ULL,
		0x11BA32626B4520A2ULL,
		0xD04A6BC94CD8C0D1ULL,
		0x124FFCFE7B37085AULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF19158B552219F4DULL,
		0x8BD82ABBA2102736ULL,
		0x689EFC962D23A737ULL,
		0x221E67F91C2BB302ULL,
		0x4AB087341FAA9B2FULL,
		0x325A919F67A6B3A8ULL,
		0xC0955B9ED8A7A627ULL,
		0x2BC5934989B1F43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE322B16AA4433E9AULL,
		0x17B0557744204E6DULL,
		0xD13DF92C5A474E6FULL,
		0x443CCFF238576604ULL,
		0x95610E683F55365EULL,
		0x64B5233ECF4D6750ULL,
		0x812AB73DB14F4C4EULL,
		0x578B26931363E87BULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x614E95CD76FF555FULL,
		0x4EE6AA4D2A23345AULL,
		0x80E4B959C0CF3F4AULL,
		0xFFA9C6633883955FULL,
		0x12B44D22646289BCULL,
		0xA59B8142A0787718ULL,
		0xDB5ED16C6702690AULL,
		0x2A23294EEEC12B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29D2B9AEDFEAABEULL,
		0x9DCD549A544668B4ULL,
		0x01C972B3819E7E94ULL,
		0xFF538CC671072ABFULL,
		0x25689A44C8C51379ULL,
		0x4B37028540F0EE30ULL,
		0xB6BDA2D8CE04D215ULL,
		0x5446529DDD825711ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x69F4085DD556071DULL,
		0x16AD188616C8C96CULL,
		0x5CA4947BF231778FULL,
		0xD02D47DACC17260FULL,
		0xE58F094EA539C824ULL,
		0xEBB30D3D0EB39612ULL,
		0xC8B95B693FCBCB31ULL,
		0x358811FD1BD6DA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E810BBAAAC0E3AULL,
		0x2D5A310C2D9192D8ULL,
		0xB94928F7E462EF1EULL,
		0xA05A8FB5982E4C1EULL,
		0xCB1E129D4A739049ULL,
		0xD7661A7A1D672C25ULL,
		0x9172B6D27F979663ULL,
		0x6B1023FA37ADB47DULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x818323C095DFF065ULL,
		0xE6FB8BF8DF8F3BF0ULL,
		0xA45D517567676AFBULL,
		0x515606DFB6E7150EULL,
		0xA55FA9A91D8B7473ULL,
		0xE5712FA827446B9FULL,
		0x4A3AA9D7D87DD72DULL,
		0x0B1C473A38D74E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030647812BBFE0CAULL,
		0xCDF717F1BF1E77E1ULL,
		0x48BAA2EACECED5F7ULL,
		0xA2AC0DBF6DCE2A1DULL,
		0x4ABF53523B16E8E6ULL,
		0xCAE25F504E88D73FULL,
		0x947553AFB0FBAE5BULL,
		0x16388E7471AE9C82ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xED780D99A8000B5DULL,
		0x22900BCAB0B7905FULL,
		0x591319161DF2CEF0ULL,
		0x46F4C4FDA4526C30ULL,
		0xE43D55DE393E688EULL,
		0x44A79EFE7046A744ULL,
		0x955EADA66B2B652DULL,
		0x015BCF53660F98FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAF01B33500016BAULL,
		0x45201795616F20BFULL,
		0xB226322C3BE59DE0ULL,
		0x8DE989FB48A4D860ULL,
		0xC87AABBC727CD11CULL,
		0x894F3DFCE08D4E89ULL,
		0x2ABD5B4CD656CA5AULL,
		0x02B79EA6CC1F31FBULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19E7668B29635DBFULL,
		0xD08FF73CC310ACC7ULL,
		0x262F7E19AB764898ULL,
		0x6FB3973E9155343CULL,
		0xEFF9F39BF4AB55BFULL,
		0xE2A71CA18DE9040BULL,
		0xDB47302EB13E7207ULL,
		0x01EDFEE42B818263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CECD1652C6BB7EULL,
		0xA11FEE798621598EULL,
		0x4C5EFC3356EC9131ULL,
		0xDF672E7D22AA6878ULL,
		0xDFF3E737E956AB7EULL,
		0xC54E39431BD20817ULL,
		0xB68E605D627CE40FULL,
		0x03DBFDC8570304C7ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD475100463A8F64FULL,
		0x1C651F9F63AE380EULL,
		0x4E8FE0E97BCFA0B2ULL,
		0x36523BF1A038A9C3ULL,
		0xC06453DEFB21F0F3ULL,
		0xD15FF7734522E3AFULL,
		0x30191E954740FA78ULL,
		0x0DCD5A7377A1F8F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8EA2008C751EC9EULL,
		0x38CA3F3EC75C701DULL,
		0x9D1FC1D2F79F4164ULL,
		0x6CA477E340715386ULL,
		0x80C8A7BDF643E1E6ULL,
		0xA2BFEEE68A45C75FULL,
		0x60323D2A8E81F4F1ULL,
		0x1B9AB4E6EF43F1E2ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEBBD93013D943A16ULL,
		0x8313915BD6F0CB7CULL,
		0x88C0AACF9D30EF00ULL,
		0xCEB3BB8807C3F7DFULL,
		0x2ACCB8DC57BA0CFBULL,
		0x146B83F9F3E92F67ULL,
		0xF408AFCD27922EF8ULL,
		0x28C4008F08552A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD77B26027B28742CULL,
		0x062722B7ADE196F9ULL,
		0x1181559F3A61DE01ULL,
		0x9D6777100F87EFBFULL,
		0x559971B8AF7419F7ULL,
		0x28D707F3E7D25ECEULL,
		0xE8115F9A4F245DF0ULL,
		0x5188011E10AA54D9ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE40CDDFCE21C17C1ULL,
		0xE53E7317D2CD346FULL,
		0x64923CED99B392B1ULL,
		0xD4CCC6B03FC89F3AULL,
		0xE61A661B37F5A55AULL,
		0xD899EE92B8093FB2ULL,
		0x6D139E1ECDEEDB23ULL,
		0x21670FAD939D7166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC819BBF9C4382F82ULL,
		0xCA7CE62FA59A68DFULL,
		0xC92479DB33672563ULL,
		0xA9998D607F913E74ULL,
		0xCC34CC366FEB4AB5ULL,
		0xB133DD2570127F65ULL,
		0xDA273C3D9BDDB647ULL,
		0x42CE1F5B273AE2CCULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x43EC3C70905F36E1ULL,
		0xB911EEA891FBF002ULL,
		0xC61E738672AE1DAFULL,
		0x26BC618700E65C52ULL,
		0xB0429A469E3201E7ULL,
		0x17623D7445DA3A44ULL,
		0xCA112E3A3F7F5C0AULL,
		0x1A35D4304A356A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D878E120BE6DC2ULL,
		0x7223DD5123F7E004ULL,
		0x8C3CE70CE55C3B5FULL,
		0x4D78C30E01CCB8A5ULL,
		0x6085348D3C6403CEULL,
		0x2EC47AE88BB47489ULL,
		0x94225C747EFEB814ULL,
		0x346BA860946AD453ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7BBEC3A4C8EA3B51ULL,
		0x6682E7D0F52044A4ULL,
		0x59DA873CE9E00E08ULL,
		0x1FD4544580384EE6ULL,
		0x3849E8E06E6669C5ULL,
		0xAE4AC39E014E083BULL,
		0x879DD757B7F3CBA5ULL,
		0x29327A6B7964622AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77D874991D476A2ULL,
		0xCD05CFA1EA408948ULL,
		0xB3B50E79D3C01C10ULL,
		0x3FA8A88B00709DCCULL,
		0x7093D1C0DCCCD38AULL,
		0x5C95873C029C1076ULL,
		0x0F3BAEAF6FE7974BULL,
		0x5264F4D6F2C8C455ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x444D35810ED6DE3FULL,
		0xD73739450E8B723BULL,
		0x2EECAE0DC3D564A2ULL,
		0xB4DD65C5C9B3BB45ULL,
		0x99B294A09CA62144ULL,
		0x83894B9F21E1BF5BULL,
		0x0D0C43619559D4BFULL,
		0x0C1BF4B102E1ED66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889A6B021DADBC7EULL,
		0xAE6E728A1D16E476ULL,
		0x5DD95C1B87AAC945ULL,
		0x69BACB8B9367768AULL,
		0x33652941394C4289ULL,
		0x0712973E43C37EB7ULL,
		0x1A1886C32AB3A97FULL,
		0x1837E96205C3DACCULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x844E7F6AA6470BB2ULL,
		0xAC3300C254283F74ULL,
		0xCAFD6C0ADC581CD2ULL,
		0x2152D437B2DD9845ULL,
		0xE98D1E037E3E9922ULL,
		0x1837B0E718E6417EULL,
		0x5437C5DA0A7A28CEULL,
		0x351B1921BDBA2B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x089CFED54C8E1764ULL,
		0x58660184A8507EE9ULL,
		0x95FAD815B8B039A5ULL,
		0x42A5A86F65BB308BULL,
		0xD31A3C06FC7D3244ULL,
		0x306F61CE31CC82FDULL,
		0xA86F8BB414F4519CULL,
		0x6A3632437B7456ECULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0C56D8EC7E4CF1FDULL,
		0x94114F4D4759DE25ULL,
		0x87E37A3D3BC644C4ULL,
		0x0D1B5B1DA9BE2113ULL,
		0x8743800F69F97428ULL,
		0x6CFB65ECD7C24066ULL,
		0x6CFB75AAE753580FULL,
		0x2E195B0061FB4403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18ADB1D8FC99E3FAULL,
		0x28229E9A8EB3BC4AULL,
		0x0FC6F47A778C8989ULL,
		0x1A36B63B537C4227ULL,
		0x0E87001ED3F2E850ULL,
		0xD9F6CBD9AF8480CDULL,
		0xD9F6EB55CEA6B01EULL,
		0x5C32B600C3F68806ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9F6D23DF95232FBULL,
		0xE8D4F9EEF1C76E89ULL,
		0x9DC1C2E89F3EBE3AULL,
		0xB2E472DC7B8ACC70ULL,
		0x6D34C35663F3FD42ULL,
		0x0D1ABC90B5056304ULL,
		0x5F20F646DA8FE175ULL,
		0x188A224FFC55C70BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EDA47BF2A465F6ULL,
		0xD1A9F3DDE38EDD13ULL,
		0x3B8385D13E7D7C75ULL,
		0x65C8E5B8F71598E1ULL,
		0xDA6986ACC7E7FA85ULL,
		0x1A3579216A0AC608ULL,
		0xBE41EC8DB51FC2EAULL,
		0x3114449FF8AB8E16ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBB838AA920009ACFULL,
		0x88E2F8C323D7C2E4ULL,
		0xD08BD8149F9B9B8AULL,
		0xA774496EE9116E64ULL,
		0x7F90B902B8C8E7B9ULL,
		0xD1285614E272BEC1ULL,
		0x338205D7D735C07FULL,
		0x2B67C6D8BA67AE1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770715524001359EULL,
		0x11C5F18647AF85C9ULL,
		0xA117B0293F373715ULL,
		0x4EE892DDD222DCC9ULL,
		0xFF2172057191CF73ULL,
		0xA250AC29C4E57D82ULL,
		0x67040BAFAE6B80FFULL,
		0x56CF8DB174CF5C38ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7C56B7BDD18F406ULL,
		0x3951AF7059EC9BAEULL,
		0xB72D719E51AEA7B2ULL,
		0xA208FBE3D7879CCFULL,
		0xE633A22ACE453F5FULL,
		0x2B91752C3572AA3EULL,
		0x5A7D9C576C5524B9ULL,
		0x317BD52D9A37FCFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8AD6F7BA31E80CULL,
		0x72A35EE0B3D9375DULL,
		0x6E5AE33CA35D4F64ULL,
		0x4411F7C7AF0F399FULL,
		0xCC6744559C8A7EBFULL,
		0x5722EA586AE5547DULL,
		0xB4FB38AED8AA4972ULL,
		0x62F7AA5B346FF9FCULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9745E1858D8FA187ULL,
		0x925676979158B47FULL,
		0x29FC057254D6FF6FULL,
		0x202D3CD5F1209BCBULL,
		0x665411B8292C41BBULL,
		0xA1E78BC3BEB812A8ULL,
		0x07F40D95F754EAC0ULL,
		0x2377B828A553A64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8BC30B1B1F430EULL,
		0x24ACED2F22B168FFULL,
		0x53F80AE4A9ADFEDFULL,
		0x405A79ABE2413796ULL,
		0xCCA8237052588376ULL,
		0x43CF17877D702550ULL,
		0x0FE81B2BEEA9D581ULL,
		0x46EF70514AA74C94ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x283B7CC61246D97FULL,
		0xD1C92289E31C39A6ULL,
		0x8FB8B428E5E88826ULL,
		0x9D0CEA466E231F98ULL,
		0x9328DCCCFE6ABDCAULL,
		0x67C46B6362CE97AAULL,
		0x6EC83C85179BAA7FULL,
		0x2F293D5923FC476BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5076F98C248DB2FEULL,
		0xA3924513C638734CULL,
		0x1F716851CBD1104DULL,
		0x3A19D48CDC463F31ULL,
		0x2651B999FCD57B95ULL,
		0xCF88D6C6C59D2F55ULL,
		0xDD90790A2F3754FEULL,
		0x5E527AB247F88ED6ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x171F8885F8CF1DC6ULL,
		0xB14E6D065E644DF8ULL,
		0x4746EE101D46D12EULL,
		0x2F3C40670B198F1DULL,
		0xB13175FBAE7AF1A5ULL,
		0x7AB1C6C52907C296ULL,
		0x395C5A6B97A87533ULL,
		0x022B9DBCC0BF871FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3F110BF19E3B8CULL,
		0x629CDA0CBCC89BF0ULL,
		0x8E8DDC203A8DA25DULL,
		0x5E7880CE16331E3AULL,
		0x6262EBF75CF5E34AULL,
		0xF5638D8A520F852DULL,
		0x72B8B4D72F50EA66ULL,
		0x04573B79817F0E3EULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0F55CB4A6DE6BE88ULL,
		0xAC0A6509AA04874CULL,
		0xB05B12D239833212ULL,
		0xD5B30005F658C37BULL,
		0x4A51799F1C01B726ULL,
		0x6C6CD307E1EEDC75ULL,
		0xE6B1DE4B5105391BULL,
		0x3582F0E842498FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EAB9694DBCD7D10ULL,
		0x5814CA1354090E98ULL,
		0x60B625A473066425ULL,
		0xAB66000BECB186F7ULL,
		0x94A2F33E38036E4DULL,
		0xD8D9A60FC3DDB8EAULL,
		0xCD63BC96A20A7236ULL,
		0x6B05E1D084931FDFULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7FDF1ED6AB794C2ULL,
		0x77EE2472141757E9ULL,
		0x70D09B4AE94A8CBFULL,
		0xDFF766576CD8E513ULL,
		0x5D3B88C68FACB908ULL,
		0x7549F99D68EEF0B8ULL,
		0xC9AEFA077F0A9166ULL,
		0x0EB2FAE435D0B0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFBE3DAD56F2984ULL,
		0xEFDC48E4282EAFD3ULL,
		0xE1A13695D295197EULL,
		0xBFEECCAED9B1CA26ULL,
		0xBA77118D1F597211ULL,
		0xEA93F33AD1DDE170ULL,
		0x935DF40EFE1522CCULL,
		0x1D65F5C86BA161FFULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA673F9BB15E2AAD2ULL,
		0xF02380687A116314ULL,
		0x799F246408F23976ULL,
		0x41464315CC990DEAULL,
		0xC53B1EA880E70F4EULL,
		0x373EFFBBFAEAE226ULL,
		0x27C6AB437E44E725ULL,
		0x1D8C199A9A965AEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE7F3762BC555A4ULL,
		0xE04700D0F422C629ULL,
		0xF33E48C811E472EDULL,
		0x828C862B99321BD4ULL,
		0x8A763D5101CE1E9CULL,
		0x6E7DFF77F5D5C44DULL,
		0x4F8D5686FC89CE4AULL,
		0x3B183335352CB5DEULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x70107B225C4B09D3ULL,
		0x83E0ADDAC5BB2C55ULL,
		0xD7C7F204090AF164ULL,
		0x8268BBAED9A2F6E1ULL,
		0x843294500142030EULL,
		0x634531DE1255F017ULL,
		0x1F5660571E0B1ADDULL,
		0x2A8E41A1AE39FD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE020F644B89613A6ULL,
		0x07C15BB58B7658AAULL,
		0xAF8FE4081215E2C9ULL,
		0x04D1775DB345EDC3ULL,
		0x086528A00284061DULL,
		0xC68A63BC24ABE02FULL,
		0x3EACC0AE3C1635BAULL,
		0x551C83435C73FA38ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x281CC4D44BC12898ULL,
		0x58D7B07C1EFDB6F1ULL,
		0x35BC4886308588E3ULL,
		0xD6C85D30B0BB34BEULL,
		0x499F45A5E7BB1A8FULL,
		0xFB6CDCBEA5304013ULL,
		0x331DF24275AE3EF8ULL,
		0x2301416B780800B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x503989A897825130ULL,
		0xB1AF60F83DFB6DE2ULL,
		0x6B78910C610B11C6ULL,
		0xAD90BA616176697CULL,
		0x933E8B4BCF76351FULL,
		0xF6D9B97D4A608026ULL,
		0x663BE484EB5C7DF1ULL,
		0x460282D6F0100168ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF475A7DF779254B4ULL,
		0x77F1E215083851AFULL,
		0xEB885B2BE7076D68ULL,
		0x78C3A77C046CF881ULL,
		0x96B516B22904A4C5ULL,
		0x955FD3DF636D1625ULL,
		0x182F32F748922C44ULL,
		0x00F8AEC2517683B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EB4FBEEF24A968ULL,
		0xEFE3C42A1070A35FULL,
		0xD710B657CE0EDAD0ULL,
		0xF1874EF808D9F103ULL,
		0x2D6A2D645209498AULL,
		0x2ABFA7BEC6DA2C4BULL,
		0x305E65EE91245889ULL,
		0x01F15D84A2ED0764ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x578825E7521311EBULL,
		0xC506B7FD1B495702ULL,
		0x7408CA5159EC537EULL,
		0x8C6D6ECE9BDDA7B5ULL,
		0x6ADEBB8B17018A88ULL,
		0x8A346B601E7F6B87ULL,
		0xB4B2E1706CA25B68ULL,
		0x3F512C1AD540F956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF104BCEA42623D6ULL,
		0x8A0D6FFA3692AE04ULL,
		0xE81194A2B3D8A6FDULL,
		0x18DADD9D37BB4F6AULL,
		0xD5BD77162E031511ULL,
		0x1468D6C03CFED70EULL,
		0x6965C2E0D944B6D1ULL,
		0x7EA25835AA81F2ADULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A275AD76C619886ULL,
		0x86A7360AEDCB9A08ULL,
		0x544DE83EAAE644C9ULL,
		0xD5EFBECF42CFCF24ULL,
		0xA6DDF690E2941FB8ULL,
		0xAAF36127ECAEB499ULL,
		0x86FB620306E65210ULL,
		0x187AF782DF41C899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD44EB5AED8C3310CULL,
		0x0D4E6C15DB973410ULL,
		0xA89BD07D55CC8993ULL,
		0xABDF7D9E859F9E48ULL,
		0x4DBBED21C5283F71ULL,
		0x55E6C24FD95D6933ULL,
		0x0DF6C4060DCCA421ULL,
		0x30F5EF05BE839133ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE68A8A8D1545B1A5ULL,
		0x872836575BBD212CULL,
		0x722F1FE8CAA2689AULL,
		0x12EF97B846E56B0CULL,
		0xA5D9B5E3445F9842ULL,
		0x227C3C35C9CA5693ULL,
		0xA2720B9D67BFD02DULL,
		0x07B4E84F91A87D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD15151A2A8B634AULL,
		0x0E506CAEB77A4259ULL,
		0xE45E3FD19544D135ULL,
		0x25DF2F708DCAD618ULL,
		0x4BB36BC688BF3084ULL,
		0x44F8786B9394AD27ULL,
		0x44E4173ACF7FA05AULL,
		0x0F69D09F2350FA8BULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC8C7F5AB19155E47ULL,
		0xDB106B2F93629790ULL,
		0x6299C03809D1C3AAULL,
		0x60EADB122E7CCB4DULL,
		0x49D33E755A55198CULL,
		0x2519921D97F9379EULL,
		0xA498BAD367C92CA7ULL,
		0x069E26F89346FC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918FEB56322ABC8EULL,
		0xB620D65F26C52F21ULL,
		0xC533807013A38755ULL,
		0xC1D5B6245CF9969AULL,
		0x93A67CEAB4AA3318ULL,
		0x4A33243B2FF26F3CULL,
		0x493175A6CF92594EULL,
		0x0D3C4DF1268DF815ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC3723B78EA3B5278ULL,
		0x709AB2AAFBE91A86ULL,
		0xB95594CE903778CEULL,
		0x831B8190D3699C24ULL,
		0xCBDAC603556A86ECULL,
		0xD60B7B6E85FCCBBBULL,
		0xF7AA1D97F5D66943ULL,
		0x1A5DE1615D6E3B3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E476F1D476A4F0ULL,
		0xE1356555F7D2350DULL,
		0x72AB299D206EF19CULL,
		0x06370321A6D33849ULL,
		0x97B58C06AAD50DD9ULL,
		0xAC16F6DD0BF99777ULL,
		0xEF543B2FEBACD287ULL,
		0x34BBC2C2BADC767BULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1F205004C7CDBA71ULL,
		0x85ED625E877A55B5ULL,
		0x7E35554DF090360BULL,
		0x744C7C0E0E91FD00ULL,
		0x32D55BC000CC2219ULL,
		0x9DBDAE9231D8C027ULL,
		0x41C098E51B36E234ULL,
		0x27D28F0B9B331CB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E40A0098F9B74E2ULL,
		0x0BDAC4BD0EF4AB6AULL,
		0xFC6AAA9BE1206C17ULL,
		0xE898F81C1D23FA00ULL,
		0x65AAB78001984432ULL,
		0x3B7B5D2463B1804EULL,
		0x838131CA366DC469ULL,
		0x4FA51E1736663962ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E84F7948644058AULL,
		0x78690F5A4D5CD3F6ULL,
		0xD2526DA8D245A130ULL,
		0x21B7BC054D72159CULL,
		0xCD551EEBF892730FULL,
		0x1443B43A96A3ED55ULL,
		0x4FDCEBE5688B29EDULL,
		0x11C49444450BCF79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D09EF290C880B14ULL,
		0xF0D21EB49AB9A7EDULL,
		0xA4A4DB51A48B4260ULL,
		0x436F780A9AE42B39ULL,
		0x9AAA3DD7F124E61EULL,
		0x288768752D47DAABULL,
		0x9FB9D7CAD11653DAULL,
		0x238928888A179EF2ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2240F9E4DE2A63CCULL,
		0x2195F3542D9074A1ULL,
		0x790A916A2E8D1D91ULL,
		0x620475094D4FF827ULL,
		0x5EA94438650FA1F8ULL,
		0x64B200E6D840EC92ULL,
		0xD89879CC3FFF42A3ULL,
		0x140186BE5B89C672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4481F3C9BC54C798ULL,
		0x432BE6A85B20E942ULL,
		0xF21522D45D1A3B22ULL,
		0xC408EA129A9FF04EULL,
		0xBD528870CA1F43F0ULL,
		0xC96401CDB081D924ULL,
		0xB130F3987FFE8546ULL,
		0x28030D7CB7138CE5ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB9D194C51AC26F1ULL,
		0xFB44AB86B0CD6883ULL,
		0x3F4138BE82D7A8C8ULL,
		0x934EB6171771B8AEULL,
		0x3C7BD7B330AA7CBCULL,
		0xA814FFF99B781920ULL,
		0x31C325B720AB402EULL,
		0x12FC3387ED49D029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73A3298A3584DE2ULL,
		0xF689570D619AD107ULL,
		0x7E82717D05AF5191ULL,
		0x269D6C2E2EE3715CULL,
		0x78F7AF666154F979ULL,
		0x5029FFF336F03240ULL,
		0x63864B6E4156805DULL,
		0x25F8670FDA93A052ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6E50BE50DAD5D958ULL,
		0x202136576196519FULL,
		0xD57C7563670633DFULL,
		0x27920DF9C811A1D8ULL,
		0x5C108A58BF81BDDDULL,
		0x695CA7FE72A33263ULL,
		0x39F393FE72262E7BULL,
		0x3DA813609A9C71C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA17CA1B5ABB2B0ULL,
		0x40426CAEC32CA33EULL,
		0xAAF8EAC6CE0C67BEULL,
		0x4F241BF3902343B1ULL,
		0xB82114B17F037BBAULL,
		0xD2B94FFCE54664C6ULL,
		0x73E727FCE44C5CF6ULL,
		0x7B5026C13538E380ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x491675684AFAC840ULL,
		0xEDBB445EF6748F6DULL,
		0xC3FF6D29A25BB551ULL,
		0x8D75526140C594F5ULL,
		0x6FA0E67C93E917C4ULL,
		0x98956599F2DF7129ULL,
		0x7A939481DF83CD7AULL,
		0x3483915DC86A16C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x922CEAD095F59080ULL,
		0xDB7688BDECE91EDAULL,
		0x87FEDA5344B76AA3ULL,
		0x1AEAA4C2818B29EBULL,
		0xDF41CCF927D22F89ULL,
		0x312ACB33E5BEE252ULL,
		0xF5272903BF079AF5ULL,
		0x690722BB90D42D80ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x25DB60E7B269D66AULL,
		0xAF24A44EF2787C18ULL,
		0x742597F2931FB5EBULL,
		0xEC72D11768F44F9AULL,
		0xC25E2494EB2D5FD2ULL,
		0xD141FF71B982D679ULL,
		0x4B384D4D2A4945EEULL,
		0x055D90B4296A813EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB6C1CF64D3ACD4ULL,
		0x5E49489DE4F0F830ULL,
		0xE84B2FE5263F6BD7ULL,
		0xD8E5A22ED1E89F34ULL,
		0x84BC4929D65ABFA5ULL,
		0xA283FEE37305ACF3ULL,
		0x96709A9A54928BDDULL,
		0x0ABB216852D5027CULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x138D41F21EEBFB10ULL,
		0xE704AF2FC6408325ULL,
		0x8B8ACB0B21464387ULL,
		0xA59308F7F7204FD1ULL,
		0x8CDC197B3C572E95ULL,
		0x4EF348E42AEDBE3AULL,
		0x1507D97BB4316131ULL,
		0x37C8956C2BBF04A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271A83E43DD7F620ULL,
		0xCE095E5F8C81064AULL,
		0x17159616428C870FULL,
		0x4B2611EFEE409FA3ULL,
		0x19B832F678AE5D2BULL,
		0x9DE691C855DB7C75ULL,
		0x2A0FB2F76862C262ULL,
		0x6F912AD8577E094CULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x187E73F089E97AD7ULL,
		0xE1F49AD26965DCD9ULL,
		0x4F859A44CFA6D633ULL,
		0x4FC6CD33ABBE6A70ULL,
		0x330D9039455B8B1AULL,
		0x03BE67EC6FCB5933ULL,
		0x050E059C211E170CULL,
		0x347610CB056CDCE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FCE7E113D2F5AEULL,
		0xC3E935A4D2CBB9B2ULL,
		0x9F0B34899F4DAC67ULL,
		0x9F8D9A67577CD4E0ULL,
		0x661B20728AB71634ULL,
		0x077CCFD8DF96B266ULL,
		0x0A1C0B38423C2E18ULL,
		0x68EC21960AD9B9C6ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD599096073C0DE0AULL,
		0xF375170738914165ULL,
		0x2DF7EAD26FD03F41ULL,
		0x2B442E86E857D564ULL,
		0xEAB2D5EDA6BE4EB2ULL,
		0x9DF775996D9C5EE9ULL,
		0x008C3D6E073A4AA6ULL,
		0x0A85A5AA3F4465F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB3212C0E781BC14ULL,
		0xE6EA2E0E712282CBULL,
		0x5BEFD5A4DFA07E83ULL,
		0x56885D0DD0AFAAC8ULL,
		0xD565ABDB4D7C9D64ULL,
		0x3BEEEB32DB38BDD3ULL,
		0x01187ADC0E74954DULL,
		0x150B4B547E88CBE0ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCFC659F6BDF02F2ULL,
		0xA0336ED355097DACULL,
		0xE900513F2F115EB3ULL,
		0x8D02E5058D8DD968ULL,
		0x8CD48EB49684BC93ULL,
		0x993626B8509A503AULL,
		0x3E9FFEB031CA1636ULL,
		0x3558876C6C318121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79F8CB3ED7BE05E4ULL,
		0x4066DDA6AA12FB59ULL,
		0xD200A27E5E22BD67ULL,
		0x1A05CA0B1B1BB2D1ULL,
		0x19A91D692D097927ULL,
		0x326C4D70A134A075ULL,
		0x7D3FFD6063942C6DULL,
		0x6AB10ED8D8630242ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x745840968A155DA1ULL,
		0xF1B1ACC078E0C5A1ULL,
		0x8E2185D0B2FE3B21ULL,
		0x847473AE297B3406ULL,
		0xEB89B5B92A5DF40BULL,
		0xBD82CF652E622EE1ULL,
		0x62AB1438A27A9DE7ULL,
		0x1A8F58FA1A71C4CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B0812D142ABB42ULL,
		0xE3635980F1C18B42ULL,
		0x1C430BA165FC7643ULL,
		0x08E8E75C52F6680DULL,
		0xD7136B7254BBE817ULL,
		0x7B059ECA5CC45DC3ULL,
		0xC556287144F53BCFULL,
		0x351EB1F434E38998ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x358243BF6A30E667ULL,
		0xDDF0BFF164D2E788ULL,
		0xDD453AC23517CCBFULL,
		0x12FEE64169C5A873ULL,
		0xDC7F0A6E2A26A576ULL,
		0xF2A400CA02E184F2ULL,
		0x0A1B8DD98DFA5747ULL,
		0x1D4583DAB9292E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B04877ED461CCCEULL,
		0xBBE17FE2C9A5CF10ULL,
		0xBA8A75846A2F997FULL,
		0x25FDCC82D38B50E7ULL,
		0xB8FE14DC544D4AECULL,
		0xE548019405C309E5ULL,
		0x14371BB31BF4AE8FULL,
		0x3A8B07B572525C36ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF5B48B773D87106DULL,
		0x3E096716B845E26BULL,
		0xEF53AFDC851E20E3ULL,
		0x59422ED0DC956B40ULL,
		0x23814FE63D1DBDE7ULL,
		0xEEF842657EC82CE0ULL,
		0xBFE9D4F6540BAA01ULL,
		0x3DE3B0A306778F0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6916EE7B0E20DAULL,
		0x7C12CE2D708BC4D7ULL,
		0xDEA75FB90A3C41C6ULL,
		0xB2845DA1B92AD681ULL,
		0x47029FCC7A3B7BCEULL,
		0xDDF084CAFD9059C0ULL,
		0x7FD3A9ECA8175403ULL,
		0x7BC761460CEF1E1FULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD181A126384CE50ULL,
		0xD40784AA1FA9E0B9ULL,
		0x686F7FD64C97EDCCULL,
		0xDD6EF6A98E5542C2ULL,
		0x6CD1852315E1FAD2ULL,
		0x63F1F24BC7C52D37ULL,
		0x8FB3AC3878BDC4D3ULL,
		0x160FD07121F8C60BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA303424C7099CA0ULL,
		0xA80F09543F53C173ULL,
		0xD0DEFFAC992FDB99ULL,
		0xBADDED531CAA8584ULL,
		0xD9A30A462BC3F5A5ULL,
		0xC7E3E4978F8A5A6EULL,
		0x1F675870F17B89A6ULL,
		0x2C1FA0E243F18C17ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5DD6B721454D34B1ULL,
		0xAE78AFEA63069E33ULL,
		0x075C13A142AB9D20ULL,
		0x5E07EBEA220C0198ULL,
		0xED3C244895451C9AULL,
		0x84DE3A92D9D58CE5ULL,
		0x7900AB886A186F9FULL,
		0x11566C7CD1F5AC2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBAD6E428A9A6962ULL,
		0x5CF15FD4C60D3C66ULL,
		0x0EB8274285573A41ULL,
		0xBC0FD7D444180330ULL,
		0xDA7848912A8A3934ULL,
		0x09BC7525B3AB19CBULL,
		0xF2015710D430DF3FULL,
		0x22ACD8F9A3EB5856ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x205063413F8F984EULL,
		0x07769AB55684B111ULL,
		0xFB64397861A1ABB8ULL,
		0x7F34D46C88343574ULL,
		0xDBE8EC1FD22F0464ULL,
		0x8246F8068F478F03ULL,
		0xF0BE0C2D43C4D54EULL,
		0x0E897DCB628D8F09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A0C6827F1F309CULL,
		0x0EED356AAD096222ULL,
		0xF6C872F0C3435770ULL,
		0xFE69A8D910686AE9ULL,
		0xB7D1D83FA45E08C8ULL,
		0x048DF00D1E8F1E07ULL,
		0xE17C185A8789AA9DULL,
		0x1D12FB96C51B1E13ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2056FAF2B20475EEULL,
		0xCB7A41C639100C81ULL,
		0x03EB87F6318DFFC1ULL,
		0xF0894AE3CF9F4FEDULL,
		0x8E5AC7FD0D12AFC8ULL,
		0x6A3743F8AAD3586FULL,
		0xB641873C8F0458B3ULL,
		0x11A6FC27C0C85DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40ADF5E56408EBDCULL,
		0x96F4838C72201902ULL,
		0x07D70FEC631BFF83ULL,
		0xE11295C79F3E9FDAULL,
		0x1CB58FFA1A255F91ULL,
		0xD46E87F155A6B0DFULL,
		0x6C830E791E08B166ULL,
		0x234DF84F8190BBE9ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x77FAB373B5FE1ADDULL,
		0x86BE1D3355907FF6ULL,
		0xE5A07FE605CA69DAULL,
		0x2A37D9F498EF5DBCULL,
		0x55349AA55B1C9902ULL,
		0x27D45CA4BE045E9AULL,
		0x32C0F5CBA84DB55EULL,
		0x1E063DFE14BA88C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF566E76BFC35BAULL,
		0x0D7C3A66AB20FFECULL,
		0xCB40FFCC0B94D3B5ULL,
		0x546FB3E931DEBB79ULL,
		0xAA69354AB6393204ULL,
		0x4FA8B9497C08BD34ULL,
		0x6581EB97509B6ABCULL,
		0x3C0C7BFC29751180ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB26D877092A90FE1ULL,
		0xA2556D800C89D54FULL,
		0x70170221F535653BULL,
		0xDC0E45FB57242749ULL,
		0xEC4D0C862620E971ULL,
		0x50CA52F1BABE976DULL,
		0xBB7F35673C76DA18ULL,
		0x24DE19E55B35AF5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64DB0EE125521FC2ULL,
		0x44AADB001913AA9FULL,
		0xE02E0443EA6ACA77ULL,
		0xB81C8BF6AE484E92ULL,
		0xD89A190C4C41D2E3ULL,
		0xA194A5E3757D2EDBULL,
		0x76FE6ACE78EDB430ULL,
		0x49BC33CAB66B5EBFULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDEAECE878FAD6FFBULL,
		0x81E96B21B0E4B9AAULL,
		0xAE4A8DED909AEFADULL,
		0xBC89F4184CF81F01ULL,
		0x8D462495C5EB31B1ULL,
		0xBB964AD40A26DE3EULL,
		0xE6DBC7A3A598C0CEULL,
		0x24050173F3DD4F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5D9D0F1F5ADFF6ULL,
		0x03D2D64361C97355ULL,
		0x5C951BDB2135DF5BULL,
		0x7913E83099F03E03ULL,
		0x1A8C492B8BD66363ULL,
		0x772C95A8144DBC7DULL,
		0xCDB78F474B31819DULL,
		0x480A02E7E7BA9E23ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x71982C3BF285529EULL,
		0x3D102EFD0F74C135ULL,
		0x07873EA3EBCF8340ULL,
		0x10EDED467B4F10D0ULL,
		0xA024055B91799DD1ULL,
		0xC69D21433A9F7194ULL,
		0x2800F8B69D995A29ULL,
		0x129CD44DEA4A118FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3305877E50AA53CULL,
		0x7A205DFA1EE9826AULL,
		0x0F0E7D47D79F0680ULL,
		0x21DBDA8CF69E21A0ULL,
		0x40480AB722F33BA2ULL,
		0x8D3A4286753EE329ULL,
		0x5001F16D3B32B453ULL,
		0x2539A89BD494231EULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8DF8B84BA54E9149ULL,
		0xC466AD476B8398FCULL,
		0xE8F3643CE99AD945ULL,
		0xC79A4B63CA125310ULL,
		0xA93FFCB26C71DA74ULL,
		0xF946EF3FBE9CDB0EULL,
		0x9C969C6B8F4B7B26ULL,
		0x3B95DF1EB828B99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BF170974A9D2292ULL,
		0x88CD5A8ED70731F9ULL,
		0xD1E6C879D335B28BULL,
		0x8F3496C79424A621ULL,
		0x527FF964D8E3B4E9ULL,
		0xF28DDE7F7D39B61DULL,
		0x392D38D71E96F64DULL,
		0x772BBE3D70517335ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA8B6E39427E03A0AULL,
		0x8431F1894F771539ULL,
		0xDC01DA5198BC34FBULL,
		0x45EE11CBC72CF3C1ULL,
		0x86D3B8AB3AF150A9ULL,
		0x18F72230928D245BULL,
		0x0BB1532916A483B3ULL,
		0x14E19B8AC6F9FAD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516DC7284FC07414ULL,
		0x0863E3129EEE2A73ULL,
		0xB803B4A3317869F7ULL,
		0x8BDC23978E59E783ULL,
		0x0DA7715675E2A152ULL,
		0x31EE4461251A48B7ULL,
		0x1762A6522D490766ULL,
		0x29C337158DF3F5B2ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3BB57766C2935765ULL,
		0xB18439C83208DC74ULL,
		0x6BBE3A5F3965DF93ULL,
		0x3BDF392EB588AF04ULL,
		0x1F4B23A16FCAD4DEULL,
		0x7302A66DBAE02719ULL,
		0x0367953CD067B9B5ULL,
		0x3400C0DFB3E71AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x776AEECD8526AECAULL,
		0x630873906411B8E8ULL,
		0xD77C74BE72CBBF27ULL,
		0x77BE725D6B115E08ULL,
		0x3E964742DF95A9BCULL,
		0xE6054CDB75C04E32ULL,
		0x06CF2A79A0CF736AULL,
		0x680181BF67CE35C6ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73ADE692009FD353ULL,
		0x6788076B2506DD60ULL,
		0xB838E696A92AC445ULL,
		0x884E6C750945E85BULL,
		0x25F3BD6E50874A66ULL,
		0xF4DACD607C53F0FAULL,
		0x8A2485FFF379ADB1ULL,
		0x0B015F1178671FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE75BCD24013FA6A6ULL,
		0xCF100ED64A0DBAC0ULL,
		0x7071CD2D5255888AULL,
		0x109CD8EA128BD0B7ULL,
		0x4BE77ADCA10E94CDULL,
		0xE9B59AC0F8A7E1F4ULL,
		0x14490BFFE6F35B63ULL,
		0x1602BE22F0CE3FFFULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3C7060F5CD8161DFULL,
		0x11762051712A27DBULL,
		0x91475CE53090ADD1ULL,
		0xAC116A9FE55DB618ULL,
		0x538B5065733DB996ULL,
		0x27F2E0C6B870D12BULL,
		0x59A705A05546567BULL,
		0x1A29DDF8C912A7C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E0C1EB9B02C3BEULL,
		0x22EC40A2E2544FB6ULL,
		0x228EB9CA61215BA2ULL,
		0x5822D53FCABB6C31ULL,
		0xA716A0CAE67B732DULL,
		0x4FE5C18D70E1A256ULL,
		0xB34E0B40AA8CACF6ULL,
		0x3453BBF192254F92ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA48EE94B55E1D94FULL,
		0xBDC16683003C47CAULL,
		0x7F1094DA6085819BULL,
		0x6C5A8E268CB5066DULL,
		0x7C566792AA238AD2ULL,
		0xF9F5B0F1BC30C3F8ULL,
		0x333BA804C5AD843AULL,
		0x3F7AD6E2EC1B6CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491DD296ABC3B29EULL,
		0x7B82CD0600788F95ULL,
		0xFE2129B4C10B0337ULL,
		0xD8B51C4D196A0CDAULL,
		0xF8ACCF25544715A4ULL,
		0xF3EB61E3786187F0ULL,
		0x667750098B5B0875ULL,
		0x7EF5ADC5D836D9E2ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18E15A45EF1C2144ULL,
		0x861CA0C6F741C578ULL,
		0xF29EBDC29A1978F9ULL,
		0x8EFE0CC521D98E60ULL,
		0xCACCF52A5B9A7327ULL,
		0x64B2F1E26E67BB65ULL,
		0xE0494363B9D01A50ULL,
		0x008549232CC3E79EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C2B48BDE384288ULL,
		0x0C39418DEE838AF0ULL,
		0xE53D7B853432F1F3ULL,
		0x1DFC198A43B31CC1ULL,
		0x9599EA54B734E64FULL,
		0xC965E3C4DCCF76CBULL,
		0xC09286C773A034A0ULL,
		0x010A92465987CF3DULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDDCDBC39D23351D1ULL,
		0x0CFEB1A24A6219D5ULL,
		0xA4D62CDCE24453B3ULL,
		0x21A0051AF5637979ULL,
		0x8CA15FB21D5BBAE4ULL,
		0xFB5B694FCD65F9DCULL,
		0x6D7FBFCA2ACFBDCBULL,
		0x2D2B2C8BCFDC470AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB9B7873A466A3A2ULL,
		0x19FD634494C433ABULL,
		0x49AC59B9C488A766ULL,
		0x43400A35EAC6F2F3ULL,
		0x1942BF643AB775C8ULL,
		0xF6B6D29F9ACBF3B9ULL,
		0xDAFF7F94559F7B97ULL,
		0x5A5659179FB88E14ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81DB62E8EAD04EAFULL,
		0xCD34E9C586759241ULL,
		0x20F302EAD445E385ULL,
		0x6F929706F2D30A37ULL,
		0x5D599E28680AF3D0ULL,
		0x099DB69BB51E82DCULL,
		0xAB497DEC85D78649ULL,
		0x0812D4A362B27141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B6C5D1D5A09D5EULL,
		0x9A69D38B0CEB2483ULL,
		0x41E605D5A88BC70BULL,
		0xDF252E0DE5A6146EULL,
		0xBAB33C50D015E7A0ULL,
		0x133B6D376A3D05B8ULL,
		0x5692FBD90BAF0C92ULL,
		0x1025A946C564E283ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24867CD6B2E766A8ULL,
		0x88784B620CB7F49BULL,
		0x905946D788B7BB39ULL,
		0xB0765ED9BF695C58ULL,
		0xDDFD91B4A457A1B7ULL,
		0x28C05DD306E75776ULL,
		0x411C781C7819A92CULL,
		0x1EB9B83F8FFE3946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x490CF9AD65CECD50ULL,
		0x10F096C4196FE936ULL,
		0x20B28DAF116F7673ULL,
		0x60ECBDB37ED2B8B1ULL,
		0xBBFB236948AF436FULL,
		0x5180BBA60DCEAEEDULL,
		0x8238F038F0335258ULL,
		0x3D73707F1FFC728CULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x054030F8948E296FULL,
		0xCA7B22943E400DCCULL,
		0xDE7BF5448114F47CULL,
		0xEC186F178827DF1DULL,
		0x3C3035E412104C22ULL,
		0xDC2FEDC756A08EA3ULL,
		0x9777761D3E3EAB2CULL,
		0x15A14BC37FBFD029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8061F1291C52DEULL,
		0x94F645287C801B98ULL,
		0xBCF7EA890229E8F9ULL,
		0xD830DE2F104FBE3BULL,
		0x78606BC824209845ULL,
		0xB85FDB8EAD411D46ULL,
		0x2EEEEC3A7C7D5659ULL,
		0x2B429786FF7FA053ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7696F1DBB837FFDEULL,
		0x2192813B77FA53B4ULL,
		0xCB6629B02491C26BULL,
		0xB9AC005FE897F296ULL,
		0x577248EAA98F1D41ULL,
		0xBD7C1DDF8A218B34ULL,
		0x845B5FAACE78763CULL,
		0x310E728D8C7A91EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2DE3B7706FFFBCULL,
		0x43250276EFF4A768ULL,
		0x96CC5360492384D6ULL,
		0x735800BFD12FE52DULL,
		0xAEE491D5531E3A83ULL,
		0x7AF83BBF14431668ULL,
		0x08B6BF559CF0EC79ULL,
		0x621CE51B18F523DBULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xACB54E57223DFF3CULL,
		0xC4523EC6DFF1CFA0ULL,
		0xF8FDEEC4A4511A18ULL,
		0x4DAF9A0DBFE8970BULL,
		0x8A599CA59F17496DULL,
		0x6F222B23683769C8ULL,
		0x61F5A349B33F8D6CULL,
		0x0C3F5076701273A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x596A9CAE447BFE78ULL,
		0x88A47D8DBFE39F41ULL,
		0xF1FBDD8948A23431ULL,
		0x9B5F341B7FD12E17ULL,
		0x14B3394B3E2E92DAULL,
		0xDE445646D06ED391ULL,
		0xC3EB4693667F1AD8ULL,
		0x187EA0ECE024E752ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x884B0880491D59FDULL,
		0x67605CDF66A7FB73ULL,
		0x5CC47FD28E0A5140ULL,
		0x8A0738B58FE77FD3ULL,
		0x7FC63AAB48157E5DULL,
		0x582D1B59336A04AAULL,
		0xCD8A16FCAE733F19ULL,
		0x350BABCFB88CE13EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10961100923AB3FAULL,
		0xCEC0B9BECD4FF6E7ULL,
		0xB988FFA51C14A280ULL,
		0x140E716B1FCEFFA6ULL,
		0xFF8C7556902AFCBBULL,
		0xB05A36B266D40954ULL,
		0x9B142DF95CE67E32ULL,
		0x6A17579F7119C27DULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB2F4CC810E231420ULL,
		0x6D56579FBECA2296ULL,
		0x56CE27B567A8AEE7ULL,
		0x0D9584E5FCE10A27ULL,
		0x00D09ED9FD10AA4EULL,
		0x316459509CD46F65ULL,
		0x400BA1FCC09E971AULL,
		0x1AC30EFF8170F7FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E999021C462840ULL,
		0xDAACAF3F7D94452DULL,
		0xAD9C4F6ACF515DCEULL,
		0x1B2B09CBF9C2144EULL,
		0x01A13DB3FA21549CULL,
		0x62C8B2A139A8DECAULL,
		0x801743F9813D2E34ULL,
		0x35861DFF02E1EFFCULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7CA65454CA310E8FULL,
		0xDC45918C113AE0DEULL,
		0xC10D624E9FB5279BULL,
		0x38172A54EF631780ULL,
		0xA84FAC605BED98A3ULL,
		0xBB089F3D391CB79AULL,
		0xC2F848EB689A9783ULL,
		0x281789FDE9EC0DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF94CA8A994621D1EULL,
		0xB88B23182275C1BCULL,
		0x821AC49D3F6A4F37ULL,
		0x702E54A9DEC62F01ULL,
		0x509F58C0B7DB3146ULL,
		0x76113E7A72396F35ULL,
		0x85F091D6D1352F07ULL,
		0x502F13FBD3D81B91ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x969FB4B77724F597ULL,
		0x3EED0392F55831D8ULL,
		0xA374C49D2A59AA90ULL,
		0x730DE95254EC85B9ULL,
		0xDBEA25B7A459BBD5ULL,
		0x686B27E45871BFB3ULL,
		0x049407375D94CB21ULL,
		0x3BD1319D6A373B8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3F696EEE49EB2EULL,
		0x7DDA0725EAB063B1ULL,
		0x46E9893A54B35520ULL,
		0xE61BD2A4A9D90B73ULL,
		0xB7D44B6F48B377AAULL,
		0xD0D64FC8B0E37F67ULL,
		0x09280E6EBB299642ULL,
		0x77A2633AD46E7718ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7792290B5D490D18ULL,
		0xFE84C00277F4E250ULL,
		0xEB4D38A0C09D5F3EULL,
		0x0B932037B5A3662FULL,
		0x261864AD0E571DF7ULL,
		0xD980061BC3083253ULL,
		0xB75562458614D49DULL,
		0x2A81E34853D0B41CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF245216BA921A30ULL,
		0xFD098004EFE9C4A0ULL,
		0xD69A7141813ABE7DULL,
		0x1726406F6B46CC5FULL,
		0x4C30C95A1CAE3BEEULL,
		0xB3000C37861064A6ULL,
		0x6EAAC48B0C29A93BULL,
		0x5503C690A7A16839ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB14690EEA0DC1D52ULL,
		0x3B3C0BA9D6A64F07ULL,
		0x1F230F39B7C62386ULL,
		0x7E13F0240505E779ULL,
		0xDC0C943B24055FA3ULL,
		0x369160DAA54F2D94ULL,
		0x8A1B1E6CFA13028AULL,
		0x08A09C0A8AC6FEA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x628D21DD41B83AA4ULL,
		0x76781753AD4C9E0FULL,
		0x3E461E736F8C470CULL,
		0xFC27E0480A0BCEF2ULL,
		0xB8192876480ABF46ULL,
		0x6D22C1B54A9E5B29ULL,
		0x14363CD9F4260514ULL,
		0x11413815158DFD43ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x42763EFBD02DD731ULL,
		0x43EB5B544643ED82ULL,
		0x0024EF7646360B38ULL,
		0x7553813AE1E1274FULL,
		0x4D40AE9808BF9131ULL,
		0x984375E4E0F9D16BULL,
		0xAD67DEACFC7818ECULL,
		0x026417ECCC008671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84EC7DF7A05BAE62ULL,
		0x87D6B6A88C87DB04ULL,
		0x0049DEEC8C6C1670ULL,
		0xEAA70275C3C24E9EULL,
		0x9A815D30117F2262ULL,
		0x3086EBC9C1F3A2D6ULL,
		0x5ACFBD59F8F031D9ULL,
		0x04C82FD998010CE3ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2359D179729D6378ULL,
		0x895F14E37D3444D4ULL,
		0x8B9758740C9F4824ULL,
		0x323E9A720222F9ABULL,
		0x32853D81BE384BFDULL,
		0xE2C32D3A4A66FF54ULL,
		0xC03ACCC6F7CE3F49ULL,
		0x09EA64DE5810887BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B3A2F2E53AC6F0ULL,
		0x12BE29C6FA6889A8ULL,
		0x172EB0E8193E9049ULL,
		0x647D34E40445F357ULL,
		0x650A7B037C7097FAULL,
		0xC5865A7494CDFEA8ULL,
		0x8075998DEF9C7E93ULL,
		0x13D4C9BCB02110F7ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF5E689AA7370444FULL,
		0xD0E094A356529B70ULL,
		0x2DE069928BF951E3ULL,
		0x04265B3CE63D7915ULL,
		0xA24F3E5E1C6ECC15ULL,
		0x892B6F48FA042567ULL,
		0xC1FD7DC0091505D7ULL,
		0x0B788E6DE394AA61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCD1354E6E0889EULL,
		0xA1C12946ACA536E1ULL,
		0x5BC0D32517F2A3C7ULL,
		0x084CB679CC7AF22AULL,
		0x449E7CBC38DD982AULL,
		0x1256DE91F4084ACFULL,
		0x83FAFB80122A0BAFULL,
		0x16F11CDBC72954C3ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73FA0D7B4DE23872ULL,
		0xD636DEB50570B888ULL,
		0xAB0E6A7D205C44ABULL,
		0x5A63C15ADB04CC9EULL,
		0x44CC31B6FA242F95ULL,
		0x0B0D32DC796A8B2FULL,
		0x90D7AD43E3AB5DC6ULL,
		0x3DDEA3B47FA83BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7F41AF69BC470E4ULL,
		0xAC6DBD6A0AE17110ULL,
		0x561CD4FA40B88957ULL,
		0xB4C782B5B609993DULL,
		0x8998636DF4485F2AULL,
		0x161A65B8F2D5165EULL,
		0x21AF5A87C756BB8CULL,
		0x7BBD4768FF50774BULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0DE76B57001AA7B0ULL,
		0x59C1DDF7790D9796ULL,
		0xF7237C24F94D4750ULL,
		0x7BBA847F883CCBFFULL,
		0x3F0E240D64AE512BULL,
		0x5B6C64C7456B3B07ULL,
		0x2FF14181638C0460ULL,
		0x15CC685E92DA3193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCED6AE00354F60ULL,
		0xB383BBEEF21B2F2CULL,
		0xEE46F849F29A8EA0ULL,
		0xF77508FF107997FFULL,
		0x7E1C481AC95CA256ULL,
		0xB6D8C98E8AD6760EULL,
		0x5FE28302C71808C0ULL,
		0x2B98D0BD25B46326ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x584C8DF9C7494A08ULL,
		0x405D99796FAA4212ULL,
		0x224BC2CBDE80FFF5ULL,
		0x768739586656DD96ULL,
		0x6ACEE8EE4D16DDB9ULL,
		0x1C0FC4FBE3F79540ULL,
		0xCCE51F56DFD23AC8ULL,
		0x3B3E4EA2E622CE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0991BF38E929410ULL,
		0x80BB32F2DF548424ULL,
		0x44978597BD01FFEAULL,
		0xED0E72B0CCADBB2CULL,
		0xD59DD1DC9A2DBB72ULL,
		0x381F89F7C7EF2A80ULL,
		0x99CA3EADBFA47590ULL,
		0x767C9D45CC459CF1ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9E052B07D326D177ULL,
		0xC7B7331A52A9A3D8ULL,
		0xA6D8427399C092D5ULL,
		0x1E9F10CE662C1A7CULL,
		0x7B55B20FCBBEDB7BULL,
		0xD0D27C73F9249675ULL,
		0x83065EE88D1069DDULL,
		0x0BB504FA769C60CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C0A560FA64DA2EEULL,
		0x8F6E6634A55347B1ULL,
		0x4DB084E7338125ABULL,
		0x3D3E219CCC5834F9ULL,
		0xF6AB641F977DB6F6ULL,
		0xA1A4F8E7F2492CEAULL,
		0x060CBDD11A20D3BBULL,
		0x176A09F4ED38C197ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x69307F5F194B3224ULL,
		0x676F243BE06AF705ULL,
		0x71E3BA953A0007A4ULL,
		0x7114ACCE42AD3892ULL,
		0x11D82A897806C91AULL,
		0x5A87D0F41EF51EA9ULL,
		0x4300AB1CEB04EB14ULL,
		0x2A353CE77F9A485BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD260FEBE32966448ULL,
		0xCEDE4877C0D5EE0AULL,
		0xE3C7752A74000F48ULL,
		0xE229599C855A7124ULL,
		0x23B05512F00D9234ULL,
		0xB50FA1E83DEA3D52ULL,
		0x86015639D609D628ULL,
		0x546A79CEFF3490B6ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9AF5C4E7953E4662ULL,
		0x1E474E19AB11D18CULL,
		0x390B315D4C8C71CEULL,
		0x9DB980FC03DFC2DBULL,
		0x723767A9B2A452CAULL,
		0x497362269B3921C0ULL,
		0x8141CC7661FB7526ULL,
		0x3B7F4308B4362C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EB89CF2A7C8CC4ULL,
		0x3C8E9C335623A319ULL,
		0x721662BA9918E39CULL,
		0x3B7301F807BF85B6ULL,
		0xE46ECF536548A595ULL,
		0x92E6C44D36724380ULL,
		0x028398ECC3F6EA4CULL,
		0x76FE8611686C58D7ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB0E2CAA9B8139013ULL,
		0x35A9748D83788EF4ULL,
		0xBCF1A934F2C01BA0ULL,
		0x5316ACCF868F9DB9ULL,
		0x5A444D724F7492B6ULL,
		0x5991A592B1622FD3ULL,
		0xA54F4162E0730438ULL,
		0x03D2C5C472718C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61C5955370272026ULL,
		0x6B52E91B06F11DE9ULL,
		0x79E35269E5803740ULL,
		0xA62D599F0D1F3B73ULL,
		0xB4889AE49EE9256CULL,
		0xB3234B2562C45FA6ULL,
		0x4A9E82C5C0E60870ULL,
		0x07A58B88E4E318CFULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD70965772EAA5DB2ULL,
		0x82E9558D85F74547ULL,
		0xC027D851F062B56CULL,
		0x01FEDF7F03F7EA9FULL,
		0x09E429CD253B6CF2ULL,
		0x109C9C23451F13E7ULL,
		0x9703FD3C81BD1473ULL,
		0x1BD1636E3FCD4B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE12CAEE5D54BB64ULL,
		0x05D2AB1B0BEE8A8FULL,
		0x804FB0A3E0C56AD9ULL,
		0x03FDBEFE07EFD53FULL,
		0x13C8539A4A76D9E4ULL,
		0x213938468A3E27CEULL,
		0x2E07FA79037A28E6ULL,
		0x37A2C6DC7F9A9725ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7CB0D222304E2BCBULL,
		0xBE8D7B66F675A336ULL,
		0x8319BB3A8C01AD5DULL,
		0x9150A04B2369EDFAULL,
		0x235B003406ED0FF8ULL,
		0xA7A6046BB60FB03FULL,
		0x270B96EDEC2594C2ULL,
		0x0BD2AC2324073209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF961A444609C5796ULL,
		0x7D1AF6CDECEB466CULL,
		0x0633767518035ABBULL,
		0x22A1409646D3DBF5ULL,
		0x46B600680DDA1FF1ULL,
		0x4F4C08D76C1F607EULL,
		0x4E172DDBD84B2985ULL,
		0x17A55846480E6412ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB1859E71E1D463FULL,
		0x800F0834798F73D2ULL,
		0x53932E220F8B01E2ULL,
		0x88B00F292FF7E827ULL,
		0xE6AD184632C53140ULL,
		0xFB06F0DD6734C385ULL,
		0x264C84311E5ED856ULL,
		0x01708786DD2FFC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5630B3CE3C3A8C7EULL,
		0x001E1068F31EE7A5ULL,
		0xA7265C441F1603C5ULL,
		0x11601E525FEFD04EULL,
		0xCD5A308C658A6281ULL,
		0xF60DE1BACE69870BULL,
		0x4C9908623CBDB0ADULL,
		0x02E10F0DBA5FF928ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x41101A1C708CC3D0ULL,
		0x735B8FF699810BB1ULL,
		0x22FE125C55326801ULL,
		0xDA06F4D3C1D5F3E6ULL,
		0x9F66EDE04DE675CBULL,
		0xD492E8035ADFBD85ULL,
		0x11DAD91AA90B76D7ULL,
		0x34D5629322AB698FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82203438E11987A0ULL,
		0xE6B71FED33021762ULL,
		0x45FC24B8AA64D002ULL,
		0xB40DE9A783ABE7CCULL,
		0x3ECDDBC09BCCEB97ULL,
		0xA925D006B5BF7B0BULL,
		0x23B5B2355216EDAFULL,
		0x69AAC5264556D31EULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x420F678283A389A1ULL,
		0x2E76900618936B19ULL,
		0x56D24B13E6738923ULL,
		0xB9C8B57024F4BA4AULL,
		0xDA0B1E1532C397FDULL,
		0x279760ADE0AFCDCEULL,
		0x59788917FCD79A7CULL,
		0x360E5122179D3649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841ECF0507471342ULL,
		0x5CED200C3126D632ULL,
		0xADA49627CCE71246ULL,
		0x73916AE049E97494ULL,
		0xB4163C2A65872FFBULL,
		0x4F2EC15BC15F9B9DULL,
		0xB2F1122FF9AF34F8ULL,
		0x6C1CA2442F3A6C92ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08A9A779520A548DULL,
		0xFF8C0424BD2EDA5BULL,
		0x39BE3E3AEF9AB586ULL,
		0xD28D08E6752B80DEULL,
		0xB820AFCF4D5A2332ULL,
		0xB173FC5FFDAA786DULL,
		0xA7FE5618DD212F77ULL,
		0x30B25056BE32869AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11534EF2A414A91AULL,
		0xFF1808497A5DB4B6ULL,
		0x737C7C75DF356B0DULL,
		0xA51A11CCEA5701BCULL,
		0x70415F9E9AB44665ULL,
		0x62E7F8BFFB54F0DBULL,
		0x4FFCAC31BA425EEFULL,
		0x6164A0AD7C650D35ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x79B691DBF14C969DULL,
		0x57A084663B41AF0CULL,
		0x26D67B5238C06D6DULL,
		0xA2E3984E05C8E15CULL,
		0xBBECE765FC606206ULL,
		0xCBE492587EC81B6FULL,
		0x4C8A37B3E3D6FB0CULL,
		0x2886F29C176041A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF36D23B7E2992D3AULL,
		0xAF4108CC76835E18ULL,
		0x4DACF6A47180DADAULL,
		0x45C7309C0B91C2B8ULL,
		0x77D9CECBF8C0C40DULL,
		0x97C924B0FD9036DFULL,
		0x99146F67C7ADF619ULL,
		0x510DE5382EC0834AULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x046694A27D81DFEAULL,
		0x13B04B149FCDD2F7ULL,
		0x4B4D470E71E55EA7ULL,
		0xF2581C1686021A8DULL,
		0xF681EB9E08924959ULL,
		0x47BE0B31966114B2ULL,
		0xE8A61715C65A2586ULL,
		0x02BF0434ADF94A04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08CD2944FB03BFD4ULL,
		0x276096293F9BA5EEULL,
		0x969A8E1CE3CABD4EULL,
		0xE4B0382D0C04351AULL,
		0xED03D73C112492B3ULL,
		0x8F7C16632CC22965ULL,
		0xD14C2E2B8CB44B0CULL,
		0x057E08695BF29409ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7809E10DBEAC4602ULL,
		0x501A43FC2557BE7CULL,
		0xB3B95BAD4937149CULL,
		0xAAC7165E8D649C8AULL,
		0x3167537B5C392400ULL,
		0x1E60534C016251D8ULL,
		0x4BECF8D5BD530B99ULL,
		0x30E26DAF230E3AFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF013C21B7D588C04ULL,
		0xA03487F84AAF7CF8ULL,
		0x6772B75A926E2938ULL,
		0x558E2CBD1AC93915ULL,
		0x62CEA6F6B8724801ULL,
		0x3CC0A69802C4A3B0ULL,
		0x97D9F1AB7AA61732ULL,
		0x61C4DB5E461C75F4ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B604E896AB7A8F7ULL,
		0xDA68DD59709DF40DULL,
		0x7E4834E247D29076ULL,
		0x3E775ACF5193C1BDULL,
		0xC7D726AF6A88479BULL,
		0x77991C7DB46F6DD9ULL,
		0x90DA2C0C0E14704AULL,
		0x05A6D4054ADE181AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C09D12D56F51EEULL,
		0xB4D1BAB2E13BE81AULL,
		0xFC9069C48FA520EDULL,
		0x7CEEB59EA327837AULL,
		0x8FAE4D5ED5108F36ULL,
		0xEF3238FB68DEDBB3ULL,
		0x21B458181C28E094ULL,
		0x0B4DA80A95BC3035ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x144E36EDC5B1E890ULL,
		0xE19C11C1172D5FD1ULL,
		0x27923E15E9EE99FDULL,
		0x7E5FC6CFD356DF69ULL,
		0x73726D3F3ADA934DULL,
		0xEB23976FB452DE03ULL,
		0xA9B378D1EC6A4EAEULL,
		0x1F250C319D50B5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x289C6DDB8B63D120ULL,
		0xC33823822E5ABFA2ULL,
		0x4F247C2BD3DD33FBULL,
		0xFCBF8D9FA6ADBED2ULL,
		0xE6E4DA7E75B5269AULL,
		0xD6472EDF68A5BC06ULL,
		0x5366F1A3D8D49D5DULL,
		0x3E4A18633AA16BCBULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1A9EC1B9CC5CB0EBULL,
		0x30B7D178AEDDDAEAULL,
		0x5584BBFBF016DBFEULL,
		0x1CE0511F86243031ULL,
		0x6B485BDE38E2D4D3ULL,
		0x31309CDAA1FE2BB2ULL,
		0xEA756AB33E31D8D1ULL,
		0x1BBF4A7274E6D608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x353D837398B961D6ULL,
		0x616FA2F15DBBB5D4ULL,
		0xAB0977F7E02DB7FCULL,
		0x39C0A23F0C486062ULL,
		0xD690B7BC71C5A9A6ULL,
		0x626139B543FC5764ULL,
		0xD4EAD5667C63B1A2ULL,
		0x377E94E4E9CDAC11ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9044F31E4B37805DULL,
		0xF3CCC7BB403E8B33ULL,
		0x3DB4AC964E0118CBULL,
		0x5FDA5B8D1F935489ULL,
		0xF98DB0DFE47AA8F8ULL,
		0x83932418822C0646ULL,
		0xA09965ECE09205FBULL,
		0x160273F838384D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2089E63C966F00BAULL,
		0xE7998F76807D1667ULL,
		0x7B69592C9C023197ULL,
		0xBFB4B71A3F26A912ULL,
		0xF31B61BFC8F551F0ULL,
		0x0726483104580C8DULL,
		0x4132CBD9C1240BF7ULL,
		0x2C04E7F070709A85ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x098A941D69B13736ULL,
		0x3265E449308CE130ULL,
		0x8EA07807ECF89DE3ULL,
		0x0040B9E3F9557901ULL,
		0xF4F2DA180C7B8ED6ULL,
		0x4DB12370911924AEULL,
		0xA2A0D250FE336A54ULL,
		0x1071A232824D8C4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1315283AD3626E6CULL,
		0x64CBC8926119C260ULL,
		0x1D40F00FD9F13BC6ULL,
		0x008173C7F2AAF203ULL,
		0xE9E5B43018F71DACULL,
		0x9B6246E12232495DULL,
		0x4541A4A1FC66D4A8ULL,
		0x20E34465049B189FULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4FDD0FCD4D4D14D6ULL,
		0xC2EF6B1921EEDAF5ULL,
		0x72BD1BBB3F921B42ULL,
		0x5757EF04B39DBDDDULL,
		0xCA3F1FFFAB13611FULL,
		0x53D7CD157AF1F9A1ULL,
		0xD2173DA39B9FD4F7ULL,
		0x052D4BE845254F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBA1F9A9A9A29ACULL,
		0x85DED63243DDB5EAULL,
		0xE57A37767F243685ULL,
		0xAEAFDE09673B7BBAULL,
		0x947E3FFF5626C23EULL,
		0xA7AF9A2AF5E3F343ULL,
		0xA42E7B47373FA9EEULL,
		0x0A5A97D08A4A9E51ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x14E233FB5DFCB7B7ULL,
		0x375A8A5308DB6C65ULL,
		0x552F4940DFC82FBAULL,
		0x9AFC6C4F469B96B2ULL,
		0x387EA045E3C19E8FULL,
		0x79906B861626B299ULL,
		0x2CF760BA57892AACULL,
		0x2C5596D58BB78196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C467F6BBF96F6EULL,
		0x6EB514A611B6D8CAULL,
		0xAA5E9281BF905F74ULL,
		0x35F8D89E8D372D64ULL,
		0x70FD408BC7833D1FULL,
		0xF320D70C2C4D6532ULL,
		0x59EEC174AF125558ULL,
		0x58AB2DAB176F032CULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x39323459DFE3EEE0ULL,
		0x8B5EF19039E3508DULL,
		0x83995E95C579AEC4ULL,
		0xC4F6519D34B66E27ULL,
		0xD85138B0B876E61EULL,
		0xC8BBC984FE2A5768ULL,
		0x1109D4940D103618ULL,
		0x3F957CBC0CC3AAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726468B3BFC7DDC0ULL,
		0x16BDE32073C6A11AULL,
		0x0732BD2B8AF35D89ULL,
		0x89ECA33A696CDC4FULL,
		0xB0A2716170EDCC3DULL,
		0x91779309FC54AED1ULL,
		0x2213A9281A206C31ULL,
		0x7F2AF97819875540ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBA1244F473C80475ULL,
		0xABFC881DB7A7BBC7ULL,
		0xE5B09EED834CA576ULL,
		0x88D6386834521144ULL,
		0x337C2B4EA8C8AA1CULL,
		0x12BA30E9AA88D235ULL,
		0x13935DA1DACBFEC8ULL,
		0x354BDDC4AEF7D858ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742489E8E79008EAULL,
		0x57F9103B6F4F778FULL,
		0xCB613DDB06994AEDULL,
		0x11AC70D068A42289ULL,
		0x66F8569D51915439ULL,
		0x257461D35511A46AULL,
		0x2726BB43B597FD90ULL,
		0x6A97BB895DEFB0B0ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x418CDDA804DA5895ULL,
		0xBC8C4820F2C5CF6DULL,
		0x15852694E7162B66ULL,
		0x77B0AD3A866DC4F1ULL,
		0xBD2A5A79C619F61EULL,
		0x761ACD1C1384ADD4ULL,
		0xCDD27E6ED0652FD8ULL,
		0x166D79C96545D896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8319BB5009B4B12AULL,
		0x79189041E58B9EDAULL,
		0x2B0A4D29CE2C56CDULL,
		0xEF615A750CDB89E2ULL,
		0x7A54B4F38C33EC3CULL,
		0xEC359A3827095BA9ULL,
		0x9BA4FCDDA0CA5FB0ULL,
		0x2CDAF392CA8BB12DULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x009C709BECC6C343ULL,
		0xC8612ED47A1A05BDULL,
		0x1EFA2BEFA822FB32ULL,
		0xC1FC8787F41E0EA2ULL,
		0xD23EC6F56F973D5CULL,
		0xDA3695FC8002BA3DULL,
		0xBBFB68E58DE8A250ULL,
		0x389CB8B38AF39C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0138E137D98D8686ULL,
		0x90C25DA8F4340B7AULL,
		0x3DF457DF5045F665ULL,
		0x83F90F0FE83C1D44ULL,
		0xA47D8DEADF2E7AB9ULL,
		0xB46D2BF90005747BULL,
		0x77F6D1CB1BD144A1ULL,
		0x7139716715E73839ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x00886853C8663D2AULL,
		0xDD7D0E844CAB3F0DULL,
		0x397AC1410F4F5988ULL,
		0x76AB7324093748C2ULL,
		0xCCEAFE516CF44CAEULL,
		0x3EB7082285774DCDULL,
		0x6BD4884B8BF73283ULL,
		0x15865A95FD9D2B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0110D0A790CC7A54ULL,
		0xBAFA1D0899567E1AULL,
		0x72F582821E9EB311ULL,
		0xED56E648126E9184ULL,
		0x99D5FCA2D9E8995CULL,
		0x7D6E10450AEE9B9BULL,
		0xD7A9109717EE6506ULL,
		0x2B0CB52BFB3A5720ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2475B49D8A1AC4FULL,
		0xD7AA6107D825E591ULL,
		0x95CFEDA7A6D81CB0ULL,
		0x0EE29277BBF6AE56ULL,
		0xBF0DAD100723370EULL,
		0x5BCE17DFA5DE30B7ULL,
		0xAA078B5B9694B48CULL,
		0x3F84272359CC9DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448EB693B143589EULL,
		0xAF54C20FB04BCB23ULL,
		0x2B9FDB4F4DB03961ULL,
		0x1DC524EF77ED5CADULL,
		0x7E1B5A200E466E1CULL,
		0xB79C2FBF4BBC616FULL,
		0x540F16B72D296918ULL,
		0x7F084E46B3993BE1ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC23EB8DB0AA0C1A9ULL,
		0xED125F22F9BC8A22ULL,
		0xBFADD8FAE6B4E756ULL,
		0x8D1EBAC2E4B926AEULL,
		0x9ECE70C2557C448CULL,
		0x386EA50488BE1E75ULL,
		0x6D4FE10CFFB2F054ULL,
		0x3EACF4CF3E65A47EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x847D71B615418352ULL,
		0xDA24BE45F3791445ULL,
		0x7F5BB1F5CD69CEADULL,
		0x1A3D7585C9724D5DULL,
		0x3D9CE184AAF88919ULL,
		0x70DD4A09117C3CEBULL,
		0xDA9FC219FF65E0A8ULL,
		0x7D59E99E7CCB48FCULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA80E089E3CA88184ULL,
		0x97C54B031470C003ULL,
		0xB2BC621077707D3CULL,
		0x0E51F573E373864CULL,
		0x57A0D80949F8AA6AULL,
		0x858F221100B8521CULL,
		0x9D06654DA6789CC2ULL,
		0x018A91361D31668DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501C113C79510308ULL,
		0x2F8A960628E18007ULL,
		0x6578C420EEE0FA79ULL,
		0x1CA3EAE7C6E70C99ULL,
		0xAF41B01293F154D4ULL,
		0x0B1E44220170A438ULL,
		0x3A0CCA9B4CF13985ULL,
		0x0315226C3A62CD1BULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x64305C333F02AFADULL,
		0xA5C31F03834DB6CEULL,
		0x1000A1551877F829ULL,
		0x300EA580A8D1751BULL,
		0xD322EF5C2BF96B39ULL,
		0x0EB775C184EDB2A7ULL,
		0x40AAE06CDC3536D8ULL,
		0x208A3AFFB4A0DD11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC860B8667E055F5AULL,
		0x4B863E07069B6D9CULL,
		0x200142AA30EFF053ULL,
		0x601D4B0151A2EA36ULL,
		0xA645DEB857F2D672ULL,
		0x1D6EEB8309DB654FULL,
		0x8155C0D9B86A6DB0ULL,
		0x411475FF6941BA22ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x27DE1847AE6F21D8ULL,
		0x8EC33DF7E62C152CULL,
		0x0FEA708B10869E30ULL,
		0x80CE14E491B78A19ULL,
		0xD732F8935A5F47F4ULL,
		0x03B300DC30215F10ULL,
		0xC2FBB123B7ACB0C4ULL,
		0x2B10D22A4DBDDC49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FBC308F5CDE43B0ULL,
		0x1D867BEFCC582A58ULL,
		0x1FD4E116210D3C61ULL,
		0x019C29C9236F1432ULL,
		0xAE65F126B4BE8FE9ULL,
		0x076601B86042BE21ULL,
		0x85F762476F596188ULL,
		0x5621A4549B7BB893ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF2AE05148696FD03ULL,
		0xBEEDB9E19A0E6FEBULL,
		0x6B18E93B81C4915EULL,
		0xEEF23C1FA1566D95ULL,
		0x99E8E800E9D0E169ULL,
		0x6A1C210A758F672EULL,
		0x64301A487C8B9617ULL,
		0x359D2579F2A5FACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55C0A290D2DFA06ULL,
		0x7DDB73C3341CDFD7ULL,
		0xD631D277038922BDULL,
		0xDDE4783F42ACDB2AULL,
		0x33D1D001D3A1C2D3ULL,
		0xD4384214EB1ECE5DULL,
		0xC8603490F9172C2EULL,
		0x6B3A4AF3E54BF59CULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFED94A6CCEB97DD3ULL,
		0xB4F9D3A8F18E07D9ULL,
		0x539E2D97A770025AULL,
		0x33193DAA65407429ULL,
		0x4CFD5163E5EE3C81ULL,
		0x3345BF9591436C17ULL,
		0x3BE1666427E1F85DULL,
		0x3651001E1DF55979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB294D99D72FBA6ULL,
		0x69F3A751E31C0FB3ULL,
		0xA73C5B2F4EE004B5ULL,
		0x66327B54CA80E852ULL,
		0x99FAA2C7CBDC7902ULL,
		0x668B7F2B2286D82EULL,
		0x77C2CCC84FC3F0BAULL,
		0x6CA2003C3BEAB2F2ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24F5B13635CCA414ULL,
		0xB0E6C40EF119FFCEULL,
		0xBF500246A37D7994ULL,
		0x526F56A5526CD0E9ULL,
		0x9044F3C17297062DULL,
		0x2246098402DFC410ULL,
		0xBB2CA3DE1DC08CF5ULL,
		0x237D5B1CB2B31C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49EB626C6B994828ULL,
		0x61CD881DE233FF9CULL,
		0x7EA0048D46FAF329ULL,
		0xA4DEAD4AA4D9A1D3ULL,
		0x2089E782E52E0C5AULL,
		0x448C130805BF8821ULL,
		0x765947BC3B8119EAULL,
		0x46FAB63965663803ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEBF29E14A5E72EECULL,
		0x56D7602E3B3C3D5FULL,
		0xB5E37439659725D9ULL,
		0xB972BA1B95187574ULL,
		0x295FD9E02B0AAD64ULL,
		0x3F89C6E4A878B414ULL,
		0x288D4E8223CFD45AULL,
		0x1DC9C778EEF0E0BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E53C294BCE5DD8ULL,
		0xADAEC05C76787ABFULL,
		0x6BC6E872CB2E4BB2ULL,
		0x72E574372A30EAE9ULL,
		0x52BFB3C056155AC9ULL,
		0x7F138DC950F16828ULL,
		0x511A9D04479FA8B4ULL,
		0x3B938EF1DDE1C17AULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2E84141F0B08CC52ULL,
		0x2F6617807844DF48ULL,
		0x45185BE2CAD064E0ULL,
		0x72BE5885CEC4B6C8ULL,
		0x64165DA937D3A317ULL,
		0xC16DD585126F8E7EULL,
		0xDC552D08F8C67EF1ULL,
		0x397789280C31116FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D08283E161198A4ULL,
		0x5ECC2F00F089BE90ULL,
		0x8A30B7C595A0C9C0ULL,
		0xE57CB10B9D896D90ULL,
		0xC82CBB526FA7462EULL,
		0x82DBAB0A24DF1CFCULL,
		0xB8AA5A11F18CFDE3ULL,
		0x72EF1250186222DFULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x96EE271094A16E1EULL,
		0x5D39D30763FE545DULL,
		0xBA4AE938FF825C65ULL,
		0xEE889A00BB608C60ULL,
		0x7523756B02A1E846ULL,
		0xA5A99B44450E3856ULL,
		0x76C4582D20FDC4B1ULL,
		0x103E235007B21D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDC4E212942DC3CULL,
		0xBA73A60EC7FCA8BBULL,
		0x7495D271FF04B8CAULL,
		0xDD11340176C118C1ULL,
		0xEA46EAD60543D08DULL,
		0x4B5336888A1C70ACULL,
		0xED88B05A41FB8963ULL,
		0x207C46A00F643A98ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7CF22B53458C898ULL,
		0xBD44A8E53915A0C8ULL,
		0xCE2888B968710F41ULL,
		0xBE0970AF6F75E7BFULL,
		0x466DC30B4655F62BULL,
		0xCA550E9B86FCF9EFULL,
		0x519E4BFC8DAECF63ULL,
		0x3408B136F016D459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9E456A68B19130ULL,
		0x7A8951CA722B4191ULL,
		0x9C511172D0E21E83ULL,
		0x7C12E15EDEEBCF7FULL,
		0x8CDB86168CABEC57ULL,
		0x94AA1D370DF9F3DEULL,
		0xA33C97F91B5D9EC7ULL,
		0x6811626DE02DA8B2ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5B5B93F2C0F2C0B1ULL,
		0x42B5E1D7C00E6548ULL,
		0x180A15C16A3B668DULL,
		0xB6700DEF58AD96A6ULL,
		0x7CAB59A8F68E7595ULL,
		0xF0A4C15858C0488FULL,
		0xBBF6D712335EB39AULL,
		0x39AF69289164A5BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B727E581E58162ULL,
		0x856BC3AF801CCA90ULL,
		0x30142B82D476CD1AULL,
		0x6CE01BDEB15B2D4CULL,
		0xF956B351ED1CEB2BULL,
		0xE14982B0B180911EULL,
		0x77EDAE2466BD6735ULL,
		0x735ED25122C94B75ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD588DB3E4210B6A3ULL,
		0xFC0161593F3F48A8ULL,
		0xBE60417EA39444B1ULL,
		0xA4432935769AAA41ULL,
		0x1543D4418AB8A1DFULL,
		0x339210E928BF2C14ULL,
		0xAE7D95BE475CA602ULL,
		0x0D0DB5D950790B42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB11B67C84216D46ULL,
		0xF802C2B27E7E9151ULL,
		0x7CC082FD47288963ULL,
		0x4886526AED355483ULL,
		0x2A87A883157143BFULL,
		0x672421D2517E5828ULL,
		0x5CFB2B7C8EB94C04ULL,
		0x1A1B6BB2A0F21685ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4ADAEE5B0AD1956ULL,
		0x22D71489A827C962ULL,
		0x905EABB4C21027FEULL,
		0x6F803F2CCCEA416AULL,
		0xF0D430C915ACFA1BULL,
		0xBD0AEDC191DF7512ULL,
		0xD3149FFA670C8C44ULL,
		0x3D18FFB0EB64D753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95B5DCB615A32ACULL,
		0x45AE2913504F92C5ULL,
		0x20BD576984204FFCULL,
		0xDF007E5999D482D5ULL,
		0xE1A861922B59F436ULL,
		0x7A15DB8323BEEA25ULL,
		0xA6293FF4CE191889ULL,
		0x7A31FF61D6C9AEA7ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73814065DE4C1549ULL,
		0x8E347857D182A4D0ULL,
		0x57F419EC83D1B7DFULL,
		0x50CC10CC8FD01F17ULL,
		0xDFCCE1F9B526D0E7ULL,
		0x4DE37F01056F9BFDULL,
		0xD6CE6F77CF514C4BULL,
		0x1DCCD7FAE3994264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70280CBBC982A92ULL,
		0x1C68F0AFA30549A0ULL,
		0xAFE833D907A36FBFULL,
		0xA19821991FA03E2EULL,
		0xBF99C3F36A4DA1CEULL,
		0x9BC6FE020ADF37FBULL,
		0xAD9CDEEF9EA29896ULL,
		0x3B99AFF5C73284C9ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6348CBD81CDECD8CULL,
		0x9ED7812D7AA5E2B4ULL,
		0x6FB9E3AE5A5CCE45ULL,
		0x7A68798BDBDA3A04ULL,
		0x09A67EFE89AB4D0EULL,
		0x599B4CDE53A393FBULL,
		0x316A075B5C73256EULL,
		0x0CE390DD7FAB07FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69197B039BD9B18ULL,
		0x3DAF025AF54BC568ULL,
		0xDF73C75CB4B99C8BULL,
		0xF4D0F317B7B47408ULL,
		0x134CFDFD13569A1CULL,
		0xB33699BCA74727F6ULL,
		0x62D40EB6B8E64ADCULL,
		0x19C721BAFF560FFCULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x40E72E6D217CE812ULL,
		0x86F103104512646CULL,
		0xF573A48551F7470FULL,
		0x85B5E72C3D3DB0F0ULL,
		0xAB1FE1A4C150E030ULL,
		0xC64BC747140CDDB2ULL,
		0x880EB06BF19CAAE2ULL,
		0x073F0A797F2526CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81CE5CDA42F9D024ULL,
		0x0DE206208A24C8D8ULL,
		0xEAE7490AA3EE8E1FULL,
		0x0B6BCE587A7B61E1ULL,
		0x563FC34982A1C061ULL,
		0x8C978E8E2819BB65ULL,
		0x101D60D7E33955C5ULL,
		0x0E7E14F2FE4A4D99ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x04109AE92F1B5E9AULL,
		0xEBF929076B1906E8ULL,
		0xE525F85F6AE43E6CULL,
		0x5729854CAA861B66ULL,
		0xDC17E5685DB8C98CULL,
		0x5484DB4CF23C9013ULL,
		0x26CFC0DB163C19AEULL,
		0x32CFF20392EE2277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x082135D25E36BD34ULL,
		0xD7F2520ED6320DD0ULL,
		0xCA4BF0BED5C87CD9ULL,
		0xAE530A99550C36CDULL,
		0xB82FCAD0BB719318ULL,
		0xA909B699E4792027ULL,
		0x4D9F81B62C78335CULL,
		0x659FE40725DC44EEULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73C51442364F7E40ULL,
		0x8EA90D623A34D614ULL,
		0x5D1D31F68B3DAB8EULL,
		0x627FCB18A138D9DBULL,
		0x8BCEC4EDCDD8A933ULL,
		0x901FAD7641D36196ULL,
		0x32917E24AC9E430AULL,
		0x1BCFA2DB8B1E11E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE78A28846C9EFC80ULL,
		0x1D521AC47469AC28ULL,
		0xBA3A63ED167B571DULL,
		0xC4FF96314271B3B6ULL,
		0x179D89DB9BB15266ULL,
		0x203F5AEC83A6C32DULL,
		0x6522FC49593C8615ULL,
		0x379F45B7163C23C8ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E4BEE2471239B95ULL,
		0x8BFCED82DCA42E88ULL,
		0xD0B18AFB00E3D901ULL,
		0xDC34DE3399BAAF3AULL,
		0x7777D8C954E1E5FEULL,
		0x165B3FCCE7B2BFC7ULL,
		0x28942704851E9803ULL,
		0x03598523F7A92C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C97DC48E247372AULL,
		0x17F9DB05B9485D10ULL,
		0xA16315F601C7B203ULL,
		0xB869BC6733755E75ULL,
		0xEEEFB192A9C3CBFDULL,
		0x2CB67F99CF657F8EULL,
		0x51284E090A3D3006ULL,
		0x06B30A47EF525826ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18844FC4ABF08605ULL,
		0xA9D6CCF42CD669C6ULL,
		0x5C30A4C47F60B262ULL,
		0xD862788A8219BD18ULL,
		0x05E55C120FDAB271ULL,
		0x1B3262078DC5661CULL,
		0x5194DC59761AFDE0ULL,
		0x1F2ACC12F86D110BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31089F8957E10C0AULL,
		0x53AD99E859ACD38CULL,
		0xB8614988FEC164C5ULL,
		0xB0C4F11504337A30ULL,
		0x0BCAB8241FB564E3ULL,
		0x3664C40F1B8ACC38ULL,
		0xA329B8B2EC35FBC0ULL,
		0x3E559825F0DA2216ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0275EBEE993CA5D3ULL,
		0xA7842EA2FF0079C0ULL,
		0xDA332167D160B623ULL,
		0x3CDA5A257F59674CULL,
		0x42D6E335BF9E3264ULL,
		0x25D90C3421BCADC5ULL,
		0x2358B3C2074E38C9ULL,
		0x19E70470DBAC47EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04EBD7DD32794BA6ULL,
		0x4F085D45FE00F380ULL,
		0xB46642CFA2C16C47ULL,
		0x79B4B44AFEB2CE99ULL,
		0x85ADC66B7F3C64C8ULL,
		0x4BB2186843795B8AULL,
		0x46B167840E9C7192ULL,
		0x33CE08E1B7588FDEULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8BDBC77F363A3A0FULL,
		0x4FF05715C215A9C7ULL,
		0xF54E57C0CB59D54BULL,
		0x44639337C23383B7ULL,
		0xB84F3C60A54172D7ULL,
		0xDF1438F9ECEFB7D0ULL,
		0x180E48A4451A33D9ULL,
		0x2F6B3781ADEEFBD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17B78EFE6C74741EULL,
		0x9FE0AE2B842B538FULL,
		0xEA9CAF8196B3AA96ULL,
		0x88C7266F8467076FULL,
		0x709E78C14A82E5AEULL,
		0xBE2871F3D9DF6FA1ULL,
		0x301C91488A3467B3ULL,
		0x5ED66F035BDDF7B2ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7684AA2C54592550ULL,
		0x2BCC052B47C0F02BULL,
		0x56FCF5C3EAE3CDE9ULL,
		0xE1E530F38A950317ULL,
		0xB3B64C326C6408B5ULL,
		0xF1493C49FEED1340ULL,
		0x87B317874FC26DDBULL,
		0x3978B81E76714309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED095458A8B24AA0ULL,
		0x57980A568F81E056ULL,
		0xADF9EB87D5C79BD2ULL,
		0xC3CA61E7152A062EULL,
		0x676C9864D8C8116BULL,
		0xE2927893FDDA2681ULL,
		0x0F662F0E9F84DBB7ULL,
		0x72F1703CECE28613ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5BF26497A8ACBCE3ULL,
		0xD6CF64D26506DFC2ULL,
		0xD487E76A92C30111ULL,
		0x10BF498C0A58B562ULL,
		0x679AE0D866154429ULL,
		0x096B3EA50621664AULL,
		0x49CBF356252E550CULL,
		0x31575D2095322934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7E4C92F515979C6ULL,
		0xAD9EC9A4CA0DBF84ULL,
		0xA90FCED525860223ULL,
		0x217E931814B16AC5ULL,
		0xCF35C1B0CC2A8852ULL,
		0x12D67D4A0C42CC94ULL,
		0x9397E6AC4A5CAA18ULL,
		0x62AEBA412A645268ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDA0D6D0B55F1D4A0ULL,
		0xBFCD48562B5C7830ULL,
		0x62FA46DCCC58A81AULL,
		0xA9668E5D56356340ULL,
		0xEABCF2E22063FCCAULL,
		0x97193B9F256D3642ULL,
		0xFB4C807914263F1CULL,
		0x01BA5CD658453D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41ADA16ABE3A940ULL,
		0x7F9A90AC56B8F061ULL,
		0xC5F48DB998B15035ULL,
		0x52CD1CBAAC6AC680ULL,
		0xD579E5C440C7F995ULL,
		0x2E32773E4ADA6C85ULL,
		0xF69900F2284C7E39ULL,
		0x0374B9ACB08A7A9DULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4AC7BA8E0BD73C3BULL,
		0x4129962C3CDBB719ULL,
		0x3E62F65359AAB18EULL,
		0xA2D6063DB0715925ULL,
		0xF74D1AD59FD04376ULL,
		0xAFCBC0A42AE3CE90ULL,
		0x8C7B09338BE8FB76ULL,
		0x22E0C1329863DC8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958F751C17AE7876ULL,
		0x82532C5879B76E32ULL,
		0x7CC5ECA6B355631CULL,
		0x45AC0C7B60E2B24AULL,
		0xEE9A35AB3FA086EDULL,
		0x5F97814855C79D21ULL,
		0x18F6126717D1F6EDULL,
		0x45C1826530C7B91BULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x362E6E1384AFFB75ULL,
		0xEF833EDEF883991BULL,
		0x82940E5911C8D004ULL,
		0x77B318AB3246A801ULL,
		0xFE2E51902780333BULL,
		0xDF349F67DF455947ULL,
		0x63ECD9CFE7B0910EULL,
		0x2BCDE0AD757AB02DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C5CDC27095FF6EAULL,
		0xDF067DBDF1073236ULL,
		0x05281CB22391A009ULL,
		0xEF663156648D5003ULL,
		0xFC5CA3204F006676ULL,
		0xBE693ECFBE8AB28FULL,
		0xC7D9B39FCF61221DULL,
		0x579BC15AEAF5605AULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE2757EDAEAEA69BULL,
		0x829B2D41549F4D16ULL,
		0x9E3B06AB86150ECDULL,
		0x0372E242C00D690AULL,
		0x4F11AAC8BFD6972BULL,
		0xA9849C68629EA4DAULL,
		0x21254E7E1030A6D8ULL,
		0x007051FB2B88C2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4EAFDB5D5D4D36ULL,
		0x05365A82A93E9A2DULL,
		0x3C760D570C2A1D9BULL,
		0x06E5C485801AD215ULL,
		0x9E2355917FAD2E56ULL,
		0x530938D0C53D49B4ULL,
		0x424A9CFC20614DB1ULL,
		0x00E0A3F6571185C2ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x58B6B978F8856EA2ULL,
		0x97841A3FAFEF4478ULL,
		0x7272E53E49DECC40ULL,
		0x42B8F90F85634874ULL,
		0x08E50CED44680304ULL,
		0xB79ADCE498832B06ULL,
		0xF4AECA9EB7808712ULL,
		0x0C1E8A421ED5C97CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16D72F1F10ADD44ULL,
		0x2F08347F5FDE88F0ULL,
		0xE4E5CA7C93BD9881ULL,
		0x8571F21F0AC690E8ULL,
		0x11CA19DA88D00608ULL,
		0x6F35B9C93106560CULL,
		0xE95D953D6F010E25ULL,
		0x183D14843DAB92F9ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF833DBD46CDB904ULL,
		0xA89A590C022D5A3DULL,
		0xAC3A7DC5DD53B85EULL,
		0xC3CF002CE5971BF0ULL,
		0x921EF6059F2451CBULL,
		0xA97AF19F2A6051D7ULL,
		0x2EAAE53C7849940DULL,
		0x12A324FB2566BF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF067B7A8D9B7208ULL,
		0x5134B218045AB47BULL,
		0x5874FB8BBAA770BDULL,
		0x879E0059CB2E37E1ULL,
		0x243DEC0B3E48A397ULL,
		0x52F5E33E54C0A3AFULL,
		0x5D55CA78F093281BULL,
		0x254649F64ACD7E22ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7F136E06FAA62E5CULL,
		0xDEBC9469B5FE13BEULL,
		0xD6B3AD9F9C4B7A75ULL,
		0xEF043B70D4C4CFE0ULL,
		0x3CD3A83D9823F8EFULL,
		0x4BCB3118BCD7FE0AULL,
		0x08A439C5A940E067ULL,
		0x1EB698BCC7A54B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE26DC0DF54C5CB8ULL,
		0xBD7928D36BFC277CULL,
		0xAD675B3F3896F4EBULL,
		0xDE0876E1A9899FC1ULL,
		0x79A7507B3047F1DFULL,
		0x9796623179AFFC14ULL,
		0x1148738B5281C0CEULL,
		0x3D6D31798F4A9686ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2DD25B1894C932B2ULL,
		0x81A94F9D488C3F2BULL,
		0x3DD451660C988550ULL,
		0x6BA87D54E366DA20ULL,
		0x0387EEFC14C4602DULL,
		0xBCC8AE19004044AFULL,
		0xDA6B3F4CE54E2B4EULL,
		0x38F67E15E774EBEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA4B63129926564ULL,
		0x03529F3A91187E56ULL,
		0x7BA8A2CC19310AA1ULL,
		0xD750FAA9C6CDB440ULL,
		0x070FDDF82988C05AULL,
		0x79915C320080895EULL,
		0xB4D67E99CA9C569DULL,
		0x71ECFC2BCEE9D7DBULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C50920D2797432FULL,
		0x0B56FB0C8370A81FULL,
		0x7E27772D4AC978FDULL,
		0x62AD501A362FDAA6ULL,
		0xA345AD74453DD483ULL,
		0x7364A3B116A379C3ULL,
		0xB0D2CF9E4F29DE7CULL,
		0x3E6462A8C30AB5ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A1241A4F2E865EULL,
		0x16ADF61906E1503EULL,
		0xFC4EEE5A9592F1FAULL,
		0xC55AA0346C5FB54CULL,
		0x468B5AE88A7BA906ULL,
		0xE6C947622D46F387ULL,
		0x61A59F3C9E53BCF8ULL,
		0x7CC8C55186156B57ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEC93E84ADA9CE7F7ULL,
		0xB1C05E5299C85856ULL,
		0x6F796305D2546EF0ULL,
		0x00F231580EB5080BULL,
		0x629529F992351584ULL,
		0x6841532A2F71BBE4ULL,
		0x95B815F8B3A7AC60ULL,
		0x20E16925A931FBABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD927D095B539CFEEULL,
		0x6380BCA53390B0ADULL,
		0xDEF2C60BA4A8DDE1ULL,
		0x01E462B01D6A1016ULL,
		0xC52A53F3246A2B08ULL,
		0xD082A6545EE377C8ULL,
		0x2B702BF1674F58C0ULL,
		0x41C2D24B5263F757ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF50A9EBC64973275ULL,
		0xBF57ADD82732A0A5ULL,
		0x66D920CAFD9A18AFULL,
		0x69F7CA837296A344ULL,
		0x1EAC46EB46FD8544ULL,
		0xBD8EEF40FE8CF334ULL,
		0x54D8D4F606E99037ULL,
		0x2DF4DD153F33A22AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA153D78C92E64EAULL,
		0x7EAF5BB04E65414BULL,
		0xCDB24195FB34315FULL,
		0xD3EF9506E52D4688ULL,
		0x3D588DD68DFB0A88ULL,
		0x7B1DDE81FD19E668ULL,
		0xA9B1A9EC0DD3206FULL,
		0x5BE9BA2A7E674454ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x867F31C655A46E6AULL,
		0xD1D727E9F3005EC8ULL,
		0x83BBE93EEFA72941ULL,
		0x6436618CCF1A50D3ULL,
		0x808DF346CCA53C07ULL,
		0x2C4A8DC9B65B5708ULL,
		0x9E938956607E8DA1ULL,
		0x3ADA2995E3934EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CFE638CAB48DCD4ULL,
		0xA3AE4FD3E600BD91ULL,
		0x0777D27DDF4E5283ULL,
		0xC86CC3199E34A1A7ULL,
		0x011BE68D994A780EULL,
		0x58951B936CB6AE11ULL,
		0x3D2712ACC0FD1B42ULL,
		0x75B4532BC7269DE1ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x42687FEB4B4C540CULL,
		0xA2A7544BB07C155CULL,
		0xF837AE1834496D99ULL,
		0x977268CD1E7A9E81ULL,
		0x2C176DB6E6F412FDULL,
		0x4DC5402B8E5FE91AULL,
		0xD94E8D13C0093402ULL,
		0x2BB86858B96BE5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84D0FFD69698A818ULL,
		0x454EA89760F82AB8ULL,
		0xF06F5C306892DB33ULL,
		0x2EE4D19A3CF53D03ULL,
		0x582EDB6DCDE825FBULL,
		0x9B8A80571CBFD234ULL,
		0xB29D1A2780126804ULL,
		0x5770D0B172D7CB53ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC0F8362EE63CC208ULL,
		0xFD1E27C5858ECB57ULL,
		0xC0AA6B75F30D4A8BULL,
		0x39345446C0E0AD37ULL,
		0x4A9A0CFB564D1271ULL,
		0x77F8B5CF374EDCAFULL,
		0x4C8D71E0BED2A7AEULL,
		0x1AB0649F61CCC001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81F06C5DCC798410ULL,
		0xFA3C4F8B0B1D96AFULL,
		0x8154D6EBE61A9517ULL,
		0x7268A88D81C15A6FULL,
		0x953419F6AC9A24E2ULL,
		0xEFF16B9E6E9DB95EULL,
		0x991AE3C17DA54F5CULL,
		0x3560C93EC3998002ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1742B7875EE472FEULL,
		0x976A42F221056627ULL,
		0xEC3AA62940600111ULL,
		0x270D3BAF335EB3B9ULL,
		0xEB3B93E78019299CULL,
		0xFF34C0C376315C8EULL,
		0x1C14B42F656BCCB1ULL,
		0x168A509201CE8CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E856F0EBDC8E5FCULL,
		0x2ED485E4420ACC4EULL,
		0xD8754C5280C00223ULL,
		0x4E1A775E66BD6773ULL,
		0xD67727CF00325338ULL,
		0xFE698186EC62B91DULL,
		0x3829685ECAD79963ULL,
		0x2D14A124039D19C4ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75103154F7E6975DULL,
		0xA24F1E2DE3FA14AEULL,
		0x7A6B88B46A794D77ULL,
		0xA271D6722CCFBAAFULL,
		0xE47969BEC03F223DULL,
		0x855E9F320FD5F044ULL,
		0x004B249AED573C55ULL,
		0x2B51D3B81002997FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2062A9EFCD2EBAULL,
		0x449E3C5BC7F4295CULL,
		0xF4D71168D4F29AEFULL,
		0x44E3ACE4599F755EULL,
		0xC8F2D37D807E447BULL,
		0x0ABD3E641FABE089ULL,
		0x00964935DAAE78ABULL,
		0x56A3A770200532FEULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0BF0162735B1BD57ULL,
		0x022328CC8FBEA23DULL,
		0x3237B8A8E68CA898ULL,
		0xC8DAD22AB7D1E982ULL,
		0x962D2DD54A823496ULL,
		0xF6B7D2DC2471AE6DULL,
		0x20A6E7AA8A8A251AULL,
		0x0432B31EA1079811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17E02C4E6B637AAEULL,
		0x044651991F7D447AULL,
		0x646F7151CD195130ULL,
		0x91B5A4556FA3D304ULL,
		0x2C5A5BAA9504692DULL,
		0xED6FA5B848E35CDBULL,
		0x414DCF5515144A35ULL,
		0x0865663D420F3022ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24906E8D55B7B081ULL,
		0x6253FCEC091AC095ULL,
		0x22744FDFF9561BC9ULL,
		0x80F2DF05FB8EE9E6ULL,
		0xA9099EC78F45119BULL,
		0x43738F5542277E0FULL,
		0xCEA4F48E3576E496ULL,
		0x04EC387ABCCEB16EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4920DD1AAB6F6102ULL,
		0xC4A7F9D81235812AULL,
		0x44E89FBFF2AC3792ULL,
		0x01E5BE0BF71DD3CCULL,
		0x52133D8F1E8A2337ULL,
		0x86E71EAA844EFC1FULL,
		0x9D49E91C6AEDC92CULL,
		0x09D870F5799D62DDULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA182499E1B0AC4A3ULL,
		0x041E60D3BE4C62E9ULL,
		0xC6E40CDA082789E2ULL,
		0x678E1A53B88A8FA4ULL,
		0xAE2FCEC1F4F8BF21ULL,
		0x1992BDA0F4025D6EULL,
		0x80272295D6F46BCBULL,
		0x02B4CC8EF2535462ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4304933C36158946ULL,
		0x083CC1A77C98C5D3ULL,
		0x8DC819B4104F13C4ULL,
		0xCF1C34A771151F49ULL,
		0x5C5F9D83E9F17E42ULL,
		0x33257B41E804BADDULL,
		0x004E452BADE8D796ULL,
		0x0569991DE4A6A8C5ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9BEC996FB8AE17F3ULL,
		0x8299291B8FDE0963ULL,
		0x6E1CDE842C5594B9ULL,
		0x8150D123961F971BULL,
		0x1A6264A7FCC6089DULL,
		0x0A52104D13DB69C2ULL,
		0x2281FDED6B568C50ULL,
		0x1B12DA4DE30F25DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D932DF715C2FE6ULL,
		0x053252371FBC12C7ULL,
		0xDC39BD0858AB2973ULL,
		0x02A1A2472C3F2E36ULL,
		0x34C4C94FF98C113BULL,
		0x14A4209A27B6D384ULL,
		0x4503FBDAD6AD18A0ULL,
		0x3625B49BC61E4BBCULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC475D3D89D35E057ULL,
		0x4358D846A48F24FFULL,
		0x6D2B8E7BF15AEA94ULL,
		0xF2BACC8DCFC9E9E2ULL,
		0x7AE5DAB2239D8F3CULL,
		0x33C8D69709BA6715ULL,
		0x3C2F4F22C172B49FULL,
		0x38A27855D6AD05CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EBA7B13A6BC0AEULL,
		0x86B1B08D491E49FFULL,
		0xDA571CF7E2B5D528ULL,
		0xE575991B9F93D3C4ULL,
		0xF5CBB564473B1E79ULL,
		0x6791AD2E1374CE2AULL,
		0x785E9E4582E5693EULL,
		0x7144F0ABAD5A0B9CULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDB98E4CDBECD7E2BULL,
		0x79BDBAB157DA42F7ULL,
		0x56541C0422365148ULL,
		0xDB535FB807E115ECULL,
		0x2330A5B0A63106CDULL,
		0x92B1A7A4FD802894ULL,
		0x2E85979792F160B1ULL,
		0x29711E09C5D3384BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB731C99B7D9AFC56ULL,
		0xF37B7562AFB485EFULL,
		0xACA83808446CA290ULL,
		0xB6A6BF700FC22BD8ULL,
		0x46614B614C620D9BULL,
		0x25634F49FB005128ULL,
		0x5D0B2F2F25E2C163ULL,
		0x52E23C138BA67096ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF172FA807A5E751EULL,
		0x7075BDB4936B0B5EULL,
		0xD8268036ABFFA7B4ULL,
		0xD2E29146E6D9EAFAULL,
		0xF39B37F9341ABBBDULL,
		0xE0FEED933256C34BULL,
		0xA27C304CA2EFD019ULL,
		0x13AE78D2EB2CDE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E5F500F4BCEA3CULL,
		0xE0EB7B6926D616BDULL,
		0xB04D006D57FF4F68ULL,
		0xA5C5228DCDB3D5F5ULL,
		0xE7366FF26835777BULL,
		0xC1FDDB2664AD8697ULL,
		0x44F8609945DFA033ULL,
		0x275CF1A5D659BC13ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDC8869D345DA2E00ULL,
		0x49ECB3A9F2BA8F44ULL,
		0x496411210476D926ULL,
		0xD147A3C3844BBE28ULL,
		0x44AD6B478E2AC780ULL,
		0x6B9739629D4FC6A0ULL,
		0xFD12A92CEFDA4D64ULL,
		0x36B2AD5F8ED58CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB910D3A68BB45C00ULL,
		0x93D96753E5751E89ULL,
		0x92C8224208EDB24CULL,
		0xA28F478708977C50ULL,
		0x895AD68F1C558F01ULL,
		0xD72E72C53A9F8D40ULL,
		0xFA255259DFB49AC8ULL,
		0x6D655ABF1DAB1973ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1227D621B094CA90ULL,
		0x29BADED0B83284A1ULL,
		0x54F25AE47F608D7FULL,
		0x26F5B02B5650514FULL,
		0xFFD6F83CD2E3C08CULL,
		0xE5070EF7D7967A9CULL,
		0x6BAF621BAB02D5C4ULL,
		0x31E58309514BB8D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x244FAC4361299520ULL,
		0x5375BDA170650942ULL,
		0xA9E4B5C8FEC11AFEULL,
		0x4DEB6056ACA0A29EULL,
		0xFFADF079A5C78118ULL,
		0xCA0E1DEFAF2CF539ULL,
		0xD75EC4375605AB89ULL,
		0x63CB0612A29771B0ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9631492B74BB2C9ULL,
		0xFD7BDA9C64FDE4A1ULL,
		0x0D57A05B329A45DEULL,
		0xFCA0D1525ABB29CBULL,
		0xB1056DCB41998F3EULL,
		0x5E2EE30AEE4241E9ULL,
		0x6F3EAC2928ADFC79ULL,
		0x1D6409D004E8DDAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C629256E976592ULL,
		0xFAF7B538C9FBC943ULL,
		0x1AAF40B665348BBDULL,
		0xF941A2A4B5765396ULL,
		0x620ADB9683331E7DULL,
		0xBC5DC615DC8483D3ULL,
		0xDE7D5852515BF8F2ULL,
		0x3AC813A009D1BB5EULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7B5267FA5AFF0F2AULL,
		0x760EAD3F4D6E14B8ULL,
		0xFDF8040E74A4A9E2ULL,
		0x61B69057A21FFD37ULL,
		0xFA6ECD10163A1953ULL,
		0xD8C0C693CC28515DULL,
		0x9C64373ADB84724BULL,
		0x11B749C070F3EF1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A4CFF4B5FE1E54ULL,
		0xEC1D5A7E9ADC2970ULL,
		0xFBF0081CE94953C4ULL,
		0xC36D20AF443FFA6FULL,
		0xF4DD9A202C7432A6ULL,
		0xB1818D279850A2BBULL,
		0x38C86E75B708E497ULL,
		0x236E9380E1E7DE37ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA507BE8EA1D6FE1BULL,
		0xAC7887A4EC0532C7ULL,
		0x9FF035A9E81D3306ULL,
		0xB372AC65E178D6F3ULL,
		0xA386641C0B60B7B0ULL,
		0xD48A39C3E16903D0ULL,
		0xC52123384E6F3599ULL,
		0x04622A65488ADA77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0F7D1D43ADFC36ULL,
		0x58F10F49D80A658FULL,
		0x3FE06B53D03A660DULL,
		0x66E558CBC2F1ADE7ULL,
		0x470CC83816C16F61ULL,
		0xA9147387C2D207A1ULL,
		0x8A4246709CDE6B33ULL,
		0x08C454CA9115B4EFULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x610E71204CE10BB0ULL,
		0x2A7CCC8D80B5F18EULL,
		0x678F7134D431705AULL,
		0xB3302A924BF6BF23ULL,
		0xC9ADBC9F39332DA7ULL,
		0x1FCEF466FBE553A0ULL,
		0x8E97FF66E260589AULL,
		0x2E36A490E8F398A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC21CE24099C21760ULL,
		0x54F9991B016BE31CULL,
		0xCF1EE269A862E0B4ULL,
		0x6660552497ED7E46ULL,
		0x935B793E72665B4FULL,
		0x3F9DE8CDF7CAA741ULL,
		0x1D2FFECDC4C0B134ULL,
		0x5C6D4921D1E73151ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5B36EB3725753F3ULL,
		0xBE1908829FDE8479ULL,
		0xBB7EED3F6D610E21ULL,
		0x21A86478F7775CABULL,
		0x5D75D4C10CD87BDAULL,
		0xC25572574A1A6D34ULL,
		0x4918BDB4F1C9DC5BULL,
		0x1FF0166542F91999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB66DD66E4AEA7E6ULL,
		0x7C3211053FBD08F3ULL,
		0x76FDDA7EDAC21C43ULL,
		0x4350C8F1EEEEB957ULL,
		0xBAEBA98219B0F7B4ULL,
		0x84AAE4AE9434DA68ULL,
		0x92317B69E393B8B7ULL,
		0x3FE02CCA85F23332ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0F13EC2FF0B7928FULL,
		0x0C099349E106E5A4ULL,
		0x12F8C23AD9CFBA04ULL,
		0xB08A1962274E27BEULL,
		0x035E71F01B5A2F82ULL,
		0x274565E543FDCB80ULL,
		0x31F856CD18825F4AULL,
		0x28A6B42C39E7E224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E27D85FE16F251EULL,
		0x18132693C20DCB48ULL,
		0x25F18475B39F7408ULL,
		0x611432C44E9C4F7CULL,
		0x06BCE3E036B45F05ULL,
		0x4E8ACBCA87FB9700ULL,
		0x63F0AD9A3104BE94ULL,
		0x514D685873CFC448ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA857C89B603A3672ULL,
		0x197771D2728DD41CULL,
		0xABB8A11EA17FEAFDULL,
		0x1CC0755DA701F132ULL,
		0x1F87A3AAAA4168EDULL,
		0x82493488B5938C2BULL,
		0x41E14C98D7DC3DC6ULL,
		0x38CEBA59DCA9904BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50AF9136C0746CE4ULL,
		0x32EEE3A4E51BA839ULL,
		0x5771423D42FFD5FAULL,
		0x3980EABB4E03E265ULL,
		0x3F0F47555482D1DAULL,
		0x049269116B271856ULL,
		0x83C29931AFB87B8DULL,
		0x719D74B3B9532096ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE55148D77285274ULL,
		0xB4A65BA842D652D6ULL,
		0x44CD61C31020FAEEULL,
		0x496F309B7E6F0305ULL,
		0x2C8B6AD5316192FDULL,
		0xBF3CB086C1378B05ULL,
		0x20C2CC46C7D098B7ULL,
		0x047A3328C70A3F1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAA291AEE50A4E8ULL,
		0x694CB75085ACA5ADULL,
		0x899AC3862041F5DDULL,
		0x92DE6136FCDE060AULL,
		0x5916D5AA62C325FAULL,
		0x7E79610D826F160AULL,
		0x4185988D8FA1316FULL,
		0x08F466518E147E3EULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x56B4EC82CE5A7D18ULL,
		0xA0EE44761A95F99EULL,
		0x5433FB7B1C6CA76DULL,
		0xD46C6354EF6BDE31ULL,
		0xDCA13B28C88585E1ULL,
		0x647DF658DCBB4FF4ULL,
		0xD1238DC0A03234E3ULL,
		0x1EA830841FDB9ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD69D9059CB4FA30ULL,
		0x41DC88EC352BF33CULL,
		0xA867F6F638D94EDBULL,
		0xA8D8C6A9DED7BC62ULL,
		0xB9427651910B0BC3ULL,
		0xC8FBECB1B9769FE9ULL,
		0xA2471B81406469C6ULL,
		0x3D5061083FB73D99ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDA07D36C7A6F432DULL,
		0x7444351F9FAFF387ULL,
		0x17D4A36667E20790ULL,
		0xE0E922B2C2182E96ULL,
		0xA72A282C3804980CULL,
		0x8C69CD727EDBCD30ULL,
		0xC98A8491398F763FULL,
		0x31D9912728073F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB40FA6D8F4DE865AULL,
		0xE8886A3F3F5FE70FULL,
		0x2FA946CCCFC40F20ULL,
		0xC1D2456584305D2CULL,
		0x4E54505870093019ULL,
		0x18D39AE4FDB79A61ULL,
		0x93150922731EEC7FULL,
		0x63B3224E500E7F29ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD352C2827EC15E2ULL,
		0xCB091EA7668C667FULL,
		0x4C8F09A64F6912C4ULL,
		0x338CCE6E411CFAD0ULL,
		0x51F8EF7608BF127EULL,
		0x9E5850DA89604C5CULL,
		0xA94F44250DBBB698ULL,
		0x0C5104F7E1249692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6A58504FD82BC4ULL,
		0x96123D4ECD18CCFFULL,
		0x991E134C9ED22589ULL,
		0x67199CDC8239F5A0ULL,
		0xA3F1DEEC117E24FCULL,
		0x3CB0A1B512C098B8ULL,
		0x529E884A1B776D31ULL,
		0x18A209EFC2492D25ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF02C7C5C2E67F062ULL,
		0x18780E506793A7CCULL,
		0x231947561723F29DULL,
		0x4E2472C105B54813ULL,
		0x99642BA05DDD14B1ULL,
		0x0F7AA1EAE2F00295ULL,
		0xF361B3D781F0D0B9ULL,
		0x388567330851F68FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE058F8B85CCFE0C4ULL,
		0x30F01CA0CF274F99ULL,
		0x46328EAC2E47E53AULL,
		0x9C48E5820B6A9026ULL,
		0x32C85740BBBA2962ULL,
		0x1EF543D5C5E0052BULL,
		0xE6C367AF03E1A172ULL,
		0x710ACE6610A3ED1FULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x810F35E523370A98ULL,
		0x9007949FC8F6647CULL,
		0xB013B6FE0B54E453ULL,
		0xD27D8C72C2F3E0E2ULL,
		0xFC532A93D2421247ULL,
		0x9B960073BCBF1C70ULL,
		0x374046293C3B03DEULL,
		0x3640FBBFBA942123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021E6BCA466E1530ULL,
		0x200F293F91ECC8F9ULL,
		0x60276DFC16A9C8A7ULL,
		0xA4FB18E585E7C1C5ULL,
		0xF8A65527A484248FULL,
		0x372C00E7797E38E1ULL,
		0x6E808C52787607BDULL,
		0x6C81F77F75284246ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD86F3ECD12BA3D7ULL,
		0xE9CAD31EDE2D64B5ULL,
		0x19038A17581BC802ULL,
		0xA9497F23BB80C106ULL,
		0x8FB7711E215FA3D9ULL,
		0x5CBFFCF8E6AF0382ULL,
		0x2B168AC90D15A857ULL,
		0x1FBDDD5504031455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0DE7D9A25747AEULL,
		0xD395A63DBC5AC96BULL,
		0x3207142EB0379005ULL,
		0x5292FE477701820CULL,
		0x1F6EE23C42BF47B3ULL,
		0xB97FF9F1CD5E0705ULL,
		0x562D15921A2B50AEULL,
		0x3F7BBAAA080628AAULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xED0B6232E78B8CD6ULL,
		0x61448BCC9BDE34EEULL,
		0x89D675CD23C41D8AULL,
		0x72679B08CAFE5136ULL,
		0x498C0383232AFEA2ULL,
		0x471DB6D5F9326B5AULL,
		0x8FA86CB53D6EEC4DULL,
		0x2508AA3DCF7A462FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA16C465CF1719ACULL,
		0xC289179937BC69DDULL,
		0x13ACEB9A47883B14ULL,
		0xE4CF361195FCA26DULL,
		0x931807064655FD44ULL,
		0x8E3B6DABF264D6B4ULL,
		0x1F50D96A7ADDD89AULL,
		0x4A11547B9EF48C5FULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFAE9C2B12935913DULL,
		0x3C24E9275D6DF7CCULL,
		0xFE52EEAB52B141A7ULL,
		0x272CAFC1144057A1ULL,
		0xCA41D87DC7880DD8ULL,
		0xD952F20697AC0DFAULL,
		0xD986AC3C1E5F9D03ULL,
		0x0F2CD998AC4EB52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5D38562526B227AULL,
		0x7849D24EBADBEF99ULL,
		0xFCA5DD56A562834EULL,
		0x4E595F822880AF43ULL,
		0x9483B0FB8F101BB0ULL,
		0xB2A5E40D2F581BF5ULL,
		0xB30D58783CBF3A07ULL,
		0x1E59B331589D6A59ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDFD9AEC5154095F6ULL,
		0x1FD8736A10D1FD9CULL,
		0x3EBA7020357AB0EFULL,
		0x9524F0AC45EF9BEBULL,
		0xAA2283A73D210ED0ULL,
		0xAFE2F26147BAED82ULL,
		0x12BDC0154BD2A6DAULL,
		0x00427E64A6AF8DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB35D8A2A812BECULL,
		0x3FB0E6D421A3FB39ULL,
		0x7D74E0406AF561DEULL,
		0x2A49E1588BDF37D6ULL,
		0x5445074E7A421DA1ULL,
		0x5FC5E4C28F75DB05ULL,
		0x257B802A97A54DB5ULL,
		0x0084FCC94D5F1B6CULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB643659D3DABB428ULL,
		0xD47E3F7A93B18361ULL,
		0xD1B1290B38154BFDULL,
		0xB492D4D4B008BEDFULL,
		0x3B0EC063D0B31434ULL,
		0x19A994A2D7559D86ULL,
		0x794B37CA72EDC9DDULL,
		0x2754BBF528433FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C86CB3A7B576850ULL,
		0xA8FC7EF5276306C3ULL,
		0xA3625216702A97FBULL,
		0x6925A9A960117DBFULL,
		0x761D80C7A1662869ULL,
		0x33532945AEAB3B0CULL,
		0xF2966F94E5DB93BAULL,
		0x4EA977EA50867F94ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x45FE44EA047BFF37ULL,
		0x2CC8D3C6466FC782ULL,
		0xB3F472E51BDF9030ULL,
		0x2287C41E88C0ECEDULL,
		0xA66A52B60FA4A72AULL,
		0xC2462184069555B6ULL,
		0x1C628F8E8EB7D6ABULL,
		0x273807A29C32E78CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BFC89D408F7FE6EULL,
		0x5991A78C8CDF8F04ULL,
		0x67E8E5CA37BF2060ULL,
		0x450F883D1181D9DBULL,
		0x4CD4A56C1F494E54ULL,
		0x848C43080D2AAB6DULL,
		0x38C51F1D1D6FAD57ULL,
		0x4E700F453865CF18ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0380891CAC4E348FULL,
		0xEEFC121894551266ULL,
		0xCC687AF550FEC071ULL,
		0x8D0594B7159CCDCAULL,
		0xA2A28FEBA4A07324ULL,
		0x0D961FB71DA50F89ULL,
		0xFD717A4E5DC4349DULL,
		0x3E9D1CB36862670BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07011239589C691EULL,
		0xDDF8243128AA24CCULL,
		0x98D0F5EAA1FD80E3ULL,
		0x1A0B296E2B399B95ULL,
		0x45451FD74940E649ULL,
		0x1B2C3F6E3B4A1F13ULL,
		0xFAE2F49CBB88693AULL,
		0x7D3A3966D0C4CE17ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x67BAFA93D20E7318ULL,
		0x3B43229644021C3CULL,
		0x0CF9A2A9C0F0326BULL,
		0x9A22C7D0BBD15563ULL,
		0x9B877B4C8C691B2EULL,
		0xC511EEAB5CDD8C2FULL,
		0x5B2B2250AEEEEB06ULL,
		0x0E603B644038DE3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF75F527A41CE630ULL,
		0x7686452C88043878ULL,
		0x19F3455381E064D6ULL,
		0x34458FA177A2AAC6ULL,
		0x370EF69918D2365DULL,
		0x8A23DD56B9BB185FULL,
		0xB65644A15DDDD60DULL,
		0x1CC076C88071BC7EULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE97A1EF2E40E819CULL,
		0x3B091FC77E0EF15AULL,
		0x996EDC4DBE6ED203ULL,
		0x8EC87F93D480C8B7ULL,
		0xD5ADD3235EA1B516ULL,
		0x5153A6BF227B020BULL,
		0x8F2628D052D65160ULL,
		0x367C42B6E4579B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F43DE5C81D0338ULL,
		0x76123F8EFC1DE2B5ULL,
		0x32DDB89B7CDDA406ULL,
		0x1D90FF27A901916FULL,
		0xAB5BA646BD436A2DULL,
		0xA2A74D7E44F60417ULL,
		0x1E4C51A0A5ACA2C0ULL,
		0x6CF8856DC8AF360BULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4FF0498035DEEDCDULL,
		0x53EA0BDA25DDE903ULL,
		0xCDBC9BCBE70C5DBEULL,
		0xEA64DC40AD113A58ULL,
		0x30F06F22180FB6AFULL,
		0x0C5E3F8CD8F467C6ULL,
		0xEE19ACE13B001B95ULL,
		0x0C900B354EF43759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FE093006BBDDB9AULL,
		0xA7D417B44BBBD206ULL,
		0x9B793797CE18BB7CULL,
		0xD4C9B8815A2274B1ULL,
		0x61E0DE44301F6D5FULL,
		0x18BC7F19B1E8CF8CULL,
		0xDC3359C27600372AULL,
		0x1920166A9DE86EB3ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x582CB923DA9B3F19ULL,
		0xE1D1A4F994871D40ULL,
		0xEA8E029C7BCD53B3ULL,
		0x7A772D78FA2B827FULL,
		0xF41B224346937A99ULL,
		0x355F5B5EB497DFB0ULL,
		0xC21A5333CD14DA21ULL,
		0x04F55A12BE49EB48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0597247B5367E32ULL,
		0xC3A349F3290E3A80ULL,
		0xD51C0538F79AA767ULL,
		0xF4EE5AF1F45704FFULL,
		0xE83644868D26F532ULL,
		0x6ABEB6BD692FBF61ULL,
		0x8434A6679A29B442ULL,
		0x09EAB4257C93D691ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x592C0F2A7A455154ULL,
		0x2A89551F087C971DULL,
		0x15DAA853BA56FC4EULL,
		0xDACC3459A137D1D7ULL,
		0x009A5C73BCC14515ULL,
		0xD055788B42344F98ULL,
		0xE122F93F4194FB8DULL,
		0x0748FBFFF043AF4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2581E54F48AA2A8ULL,
		0x5512AA3E10F92E3AULL,
		0x2BB550A774ADF89CULL,
		0xB59868B3426FA3AEULL,
		0x0134B8E779828A2BULL,
		0xA0AAF11684689F30ULL,
		0xC245F27E8329F71BULL,
		0x0E91F7FFE0875E9BULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x01BC9FB0F4ECEF21ULL,
		0xB79BA2003D12FC07ULL,
		0x020C3F28DC7FE7A0ULL,
		0xECADD7201E4EE694ULL,
		0x3EE80B4222E90291ULL,
		0xC93716D4EB5AD97AULL,
		0x8BA4A6CA43F3F6FCULL,
		0x20AD0CE3BE85C212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03793F61E9D9DE42ULL,
		0x6F3744007A25F80EULL,
		0x04187E51B8FFCF41ULL,
		0xD95BAE403C9DCD28ULL,
		0x7DD0168445D20523ULL,
		0x926E2DA9D6B5B2F4ULL,
		0x17494D9487E7EDF9ULL,
		0x415A19C77D0B8425ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9EA26A1B4BCC034DULL,
		0xDCFC50A677AC3F52ULL,
		0x8BAB88AD463E3C2AULL,
		0xCC2C902DC2A717B6ULL,
		0x564F21CBEFEC1E98ULL,
		0x744EB9C4225C981EULL,
		0x5BD49C93605E0030ULL,
		0x267A70F8F8673CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D44D4369798069AULL,
		0xB9F8A14CEF587EA5ULL,
		0x1757115A8C7C7855ULL,
		0x9859205B854E2F6DULL,
		0xAC9E4397DFD83D31ULL,
		0xE89D738844B9303CULL,
		0xB7A93926C0BC0060ULL,
		0x4CF4E1F1F0CE7954ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5C73B5C93DA796D1ULL,
		0xFCBD0396377EF9A1ULL,
		0x32B9A59EE714AD27ULL,
		0x1E4D22E6E612DD2DULL,
		0xB205239032D1BA8DULL,
		0x68D8F135B31CD4A7ULL,
		0xDE377D1DEA89C9F0ULL,
		0x21C9B26E9B13EDBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E76B927B4F2DA2ULL,
		0xF97A072C6EFDF342ULL,
		0x65734B3DCE295A4FULL,
		0x3C9A45CDCC25BA5AULL,
		0x640A472065A3751AULL,
		0xD1B1E26B6639A94FULL,
		0xBC6EFA3BD51393E0ULL,
		0x439364DD3627DB7BULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBC4D41BCF442D1F7ULL,
		0xF4ABE0DA264DCDA4ULL,
		0xF192284A78ED6018ULL,
		0x53BEE1D934CB1E99ULL,
		0x05BE82E7D0F1DF50ULL,
		0x94D0B4204C197FD9ULL,
		0xBD5B38482BEE0A0EULL,
		0x0DA451EAD8F6DE87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789A8379E885A3EEULL,
		0xE957C1B44C9B9B49ULL,
		0xE3245094F1DAC031ULL,
		0xA77DC3B269963D33ULL,
		0x0B7D05CFA1E3BEA0ULL,
		0x29A168409832FFB2ULL,
		0x7AB6709057DC141DULL,
		0x1B48A3D5B1EDBD0FULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F097C1B80B9A830ULL,
		0xD9A68BE489F8195DULL,
		0x259F543E6EAAF07FULL,
		0xB76AFD4843C8E562ULL,
		0x162937EA9A4E77FCULL,
		0x3E34257E0DAF165AULL,
		0x315A1738C5D469DCULL,
		0x2D5B25964C9AFC24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E12F83701735060ULL,
		0xB34D17C913F032BAULL,
		0x4B3EA87CDD55E0FFULL,
		0x6ED5FA908791CAC4ULL,
		0x2C526FD5349CEFF9ULL,
		0x7C684AFC1B5E2CB4ULL,
		0x62B42E718BA8D3B8ULL,
		0x5AB64B2C9935F848ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2CD2742B2F855A58ULL,
		0x3CE56E8B42BE2988ULL,
		0x7DD3CC2E35ECB253ULL,
		0x5CF6B417C897E6FEULL,
		0xE7E31C90C27C0BF7ULL,
		0x754FA65E5AD148A9ULL,
		0x969515E12834416AULL,
		0x0B43F074297DA763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A4E8565F0AB4B0ULL,
		0x79CADD16857C5310ULL,
		0xFBA7985C6BD964A6ULL,
		0xB9ED682F912FCDFCULL,
		0xCFC6392184F817EEULL,
		0xEA9F4CBCB5A29153ULL,
		0x2D2A2BC2506882D4ULL,
		0x1687E0E852FB4EC7ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6AF6CB09ABC595DFULL,
		0xABBDE6634F03D166ULL,
		0x2140705674B6F348ULL,
		0x57600CCC443EDDFFULL,
		0xD9F032629D3CE12AULL,
		0x7BD21AC977A96B9EULL,
		0xE81A3D7251A205D2ULL,
		0x2655DFC2568F4161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5ED9613578B2BBEULL,
		0x577BCCC69E07A2CCULL,
		0x4280E0ACE96DE691ULL,
		0xAEC01998887DBBFEULL,
		0xB3E064C53A79C254ULL,
		0xF7A43592EF52D73DULL,
		0xD0347AE4A3440BA4ULL,
		0x4CABBF84AD1E82C3ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C3B48E9F6F88C10ULL,
		0x0535B718046F593BULL,
		0xDE64058AEC41DDBDULL,
		0xF0D6CE3D962C45EEULL,
		0xE518DE2C161BF9BBULL,
		0xAE81BDD859DDF62AULL,
		0x50CC1C924A5B18BDULL,
		0x1955A12F089EAA74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387691D3EDF11820ULL,
		0x0A6B6E3008DEB276ULL,
		0xBCC80B15D883BB7AULL,
		0xE1AD9C7B2C588BDDULL,
		0xCA31BC582C37F377ULL,
		0x5D037BB0B3BBEC55ULL,
		0xA198392494B6317BULL,
		0x32AB425E113D54E8ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9FD1FFC451C7652ULL,
		0x61E0747B551C3022ULL,
		0xBF5831A2BD7171A8ULL,
		0x862C871308392ED2ULL,
		0x37E63ECE489C4717ULL,
		0x6C1DDE407F1F6054ULL,
		0x4BBDF1C1BE5CD67BULL,
		0x284AAB2A313280CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3FA3FF88A38ECA4ULL,
		0xC3C0E8F6AA386045ULL,
		0x7EB063457AE2E350ULL,
		0x0C590E2610725DA5ULL,
		0x6FCC7D9C91388E2FULL,
		0xD83BBC80FE3EC0A8ULL,
		0x977BE3837CB9ACF6ULL,
		0x5095565462650198ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8392AE19F0C54C48ULL,
		0xB66B31E0B041F541ULL,
		0xE4D8DD02CF04A32DULL,
		0xAD72BE26E2619146ULL,
		0x325FEC3431EB6F28ULL,
		0x1A87B97D767A7DFDULL,
		0xCA0DDDA0EB8F3A53ULL,
		0x01E90366D9527841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07255C33E18A9890ULL,
		0x6CD663C16083EA83ULL,
		0xC9B1BA059E09465BULL,
		0x5AE57C4DC4C3228DULL,
		0x64BFD86863D6DE51ULL,
		0x350F72FAECF4FBFAULL,
		0x941BBB41D71E74A6ULL,
		0x03D206CDB2A4F083ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8B55A7241B18A6C0ULL,
		0xE539293AEB94EBB2ULL,
		0x5764A14360767C39ULL,
		0x8C6C3963B03BD0BDULL,
		0x2AE2549C96460170ULL,
		0xD6D8144E62B8C50BULL,
		0x8EDA1535BE17DF1FULL,
		0x0412CD10AAB4C5ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16AB4E4836314D80ULL,
		0xCA725275D729D765ULL,
		0xAEC94286C0ECF873ULL,
		0x18D872C76077A17AULL,
		0x55C4A9392C8C02E1ULL,
		0xADB0289CC5718A16ULL,
		0x1DB42A6B7C2FBE3FULL,
		0x08259A2155698B59ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3CC68EAA28125773ULL,
		0x614C9BC5755C6C2CULL,
		0x8117ADDE1389FD08ULL,
		0xA4C51AD15B4E268CULL,
		0x7562CB6214A64DC2ULL,
		0xE9258B7D2C9AEE29ULL,
		0x54B5D37EEBA8415DULL,
		0x2B089F19939C0C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x798D1D545024AEE6ULL,
		0xC299378AEAB8D858ULL,
		0x022F5BBC2713FA10ULL,
		0x498A35A2B69C4D19ULL,
		0xEAC596C4294C9B85ULL,
		0xD24B16FA5935DC52ULL,
		0xA96BA6FDD75082BBULL,
		0x56113E332738188EULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBAEEFE63B3FC5DE9ULL,
		0xE1D1A45F77EA19D4ULL,
		0xE24483EDFA05195CULL,
		0xA328170FACAE18EFULL,
		0xB9CFEBF6E55C7017ULL,
		0xAF9A5F12B25DCF71ULL,
		0x4AD676A6C7327DBDULL,
		0x3712E81BB3EB4A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DDFCC767F8BBD2ULL,
		0xC3A348BEEFD433A9ULL,
		0xC48907DBF40A32B9ULL,
		0x46502E1F595C31DFULL,
		0x739FD7EDCAB8E02FULL,
		0x5F34BE2564BB9EE3ULL,
		0x95ACED4D8E64FB7BULL,
		0x6E25D03767D69528ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x06444C14311E7BEFULL,
		0xFF23E5D77852E03FULL,
		0xC6B7474BF36CA31FULL,
		0x230DF84BAF3B1871ULL,
		0x377AAFB86C3650C5ULL,
		0x68649BF7E9251BB1ULL,
		0x9EDC5B2E31E3D055ULL,
		0x0594241E016422A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C889828623CF7DEULL,
		0xFE47CBAEF0A5C07EULL,
		0x8D6E8E97E6D9463FULL,
		0x461BF0975E7630E3ULL,
		0x6EF55F70D86CA18AULL,
		0xD0C937EFD24A3762ULL,
		0x3DB8B65C63C7A0AAULL,
		0x0B28483C02C8454DULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x03EDDDA04C6B7388ULL,
		0x29A8758551567E83ULL,
		0x33DC1946C169EACBULL,
		0xEC0AA558E32209DAULL,
		0x9176116FC4791BB9ULL,
		0xA1CBCDF00A229483ULL,
		0xFE31B72AC039C3CCULL,
		0x330AC720C063D5DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07DBBB4098D6E710ULL,
		0x5350EB0AA2ACFD06ULL,
		0x67B8328D82D3D596ULL,
		0xD8154AB1C64413B4ULL,
		0x22EC22DF88F23773ULL,
		0x43979BE014452907ULL,
		0xFC636E5580738799ULL,
		0x66158E4180C7ABB5ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B45611A5AD6E781ULL,
		0xE3D663EE9FB194D8ULL,
		0x3DB07E449158285DULL,
		0xA913C986D35ECE9AULL,
		0xCA69C42774DB5B3DULL,
		0x7ED1E54B4283165EULL,
		0x32C40C6B492506C0ULL,
		0x10B4EBDB60D2FF31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x168AC234B5ADCF02ULL,
		0xC7ACC7DD3F6329B0ULL,
		0x7B60FC8922B050BBULL,
		0x5227930DA6BD9D34ULL,
		0x94D3884EE9B6B67BULL,
		0xFDA3CA9685062CBDULL,
		0x658818D6924A0D80ULL,
		0x2169D7B6C1A5FE62ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x321EFB57F79E2DA6ULL,
		0x2FB37694BF1C65C9ULL,
		0x1BD98C9E4B9E8C58ULL,
		0x691B59591A1FA36BULL,
		0x404BDCB794526253ULL,
		0x34B1FDDDD73DDBC3ULL,
		0x8EFE8AB59A99BC8FULL,
		0x1D1525D2A9C41F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643DF6AFEF3C5B4CULL,
		0x5F66ED297E38CB92ULL,
		0x37B3193C973D18B0ULL,
		0xD236B2B2343F46D6ULL,
		0x8097B96F28A4C4A6ULL,
		0x6963FBBBAE7BB786ULL,
		0x1DFD156B3533791EULL,
		0x3A2A4BA553883E01ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFE1954EE1E72017DULL,
		0xE40F22CF69F340CDULL,
		0xDAF604ACF5EA2737ULL,
		0x939C93F1227EC3C0ULL,
		0xD4A031268F5BCD82ULL,
		0x93062A655D5B0BA3ULL,
		0x72FD842A76B0B5CCULL,
		0x0E07BC305D52C5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC32A9DC3CE402FAULL,
		0xC81E459ED3E6819BULL,
		0xB5EC0959EBD44E6FULL,
		0x273927E244FD8781ULL,
		0xA940624D1EB79B05ULL,
		0x260C54CABAB61747ULL,
		0xE5FB0854ED616B99ULL,
		0x1C0F7860BAA58BF6ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x79C8C68F6677F0ACULL,
		0x491D6CA5879CB968ULL,
		0xAD0128110F366DE4ULL,
		0x407A2BF4EEBB61E3ULL,
		0xCB2B9403BD28F6DDULL,
		0xAF82A2DB4B2853B9ULL,
		0xA71704EEC1F32965ULL,
		0x39D767AB751AD84FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3918D1ECCEFE158ULL,
		0x923AD94B0F3972D0ULL,
		0x5A0250221E6CDBC8ULL,
		0x80F457E9DD76C3C7ULL,
		0x965728077A51EDBAULL,
		0x5F0545B69650A773ULL,
		0x4E2E09DD83E652CBULL,
		0x73AECF56EA35B09FULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2E1D067E2E9E6AB5ULL,
		0x630267CB0087968DULL,
		0xBA15EC9DF3A701B4ULL,
		0x8DC6DDF304282A18ULL,
		0x3E919E4993B5A6E4ULL,
		0xCC78A90A874339E0ULL,
		0x7B1A56FCAE612F69ULL,
		0x080C670705621697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3A0CFC5D3CD56AULL,
		0xC604CF96010F2D1AULL,
		0x742BD93BE74E0368ULL,
		0x1B8DBBE608505431ULL,
		0x7D233C93276B4DC9ULL,
		0x98F152150E8673C0ULL,
		0xF634ADF95CC25ED3ULL,
		0x1018CE0E0AC42D2EULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEDF3AA969A77C61EULL,
		0x2EBA7D5121D2EDABULL,
		0xD3C526AE803CC843ULL,
		0x2C93793F64DCD5CDULL,
		0x819998B814E44A93ULL,
		0xDE530CE0BF9F6D37ULL,
		0x475A191BDAB5718AULL,
		0x23145E3C2D9F2F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBE7552D34EF8C3CULL,
		0x5D74FAA243A5DB57ULL,
		0xA78A4D5D00799086ULL,
		0x5926F27EC9B9AB9BULL,
		0x0333317029C89526ULL,
		0xBCA619C17F3EDA6FULL,
		0x8EB43237B56AE315ULL,
		0x4628BC785B3E5E9EULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3C2C423883AB275BULL,
		0xBFABD8B78CB44172ULL,
		0xC63817286F79D041ULL,
		0xB1F20CC3A6323EB9ULL,
		0xEB8A026AAAD4F59DULL,
		0x3E160290867AEC72ULL,
		0x98600122871B6C5EULL,
		0x3142BA3900E41364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7858847107564EB6ULL,
		0x7F57B16F196882E4ULL,
		0x8C702E50DEF3A083ULL,
		0x63E419874C647D73ULL,
		0xD71404D555A9EB3BULL,
		0x7C2C05210CF5D8E5ULL,
		0x30C002450E36D8BCULL,
		0x6285747201C826C9ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3EB234A242F50D4BULL,
		0x62D0E7530C354CC8ULL,
		0x69E640605203FBF8ULL,
		0xD4BC1572479F6703ULL,
		0xE0829C11EA957798ULL,
		0x7AF1897268EEEF89ULL,
		0x001CFF89A1E5A78AULL,
		0x0344FB2EEDC44963ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D64694485EA1A96ULL,
		0xC5A1CEA6186A9990ULL,
		0xD3CC80C0A407F7F0ULL,
		0xA9782AE48F3ECE06ULL,
		0xC1053823D52AEF31ULL,
		0xF5E312E4D1DDDF13ULL,
		0x0039FF1343CB4F14ULL,
		0x0689F65DDB8892C6ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x645C66A1442F5993ULL,
		0x1FB660A0424381F6ULL,
		0x6CDC1C2739AB0257ULL,
		0x6BA835093CB26B5BULL,
		0x0DCD626EB52B6544ULL,
		0xC42C2E3E6B746093ULL,
		0x9FDC981E0256A78FULL,
		0x047C3EF2A032293BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B8CD42885EB326ULL,
		0x3F6CC140848703ECULL,
		0xD9B8384E735604AEULL,
		0xD7506A127964D6B6ULL,
		0x1B9AC4DD6A56CA88ULL,
		0x88585C7CD6E8C126ULL,
		0x3FB9303C04AD4F1FULL,
		0x08F87DE540645277ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D3307B7A711E35CULL,
		0xB7769D9DE73B9ACDULL,
		0xB9DA5AE3472ECD71ULL,
		0x1522084DBEEE5FC9ULL,
		0xBD90E5D557A29CF6ULL,
		0xDED96165D8C693A6ULL,
		0x3BFB45BFF89ACAB9ULL,
		0x27BE9D86AD594428ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A660F6F4E23C6B8ULL,
		0x6EED3B3BCE77359AULL,
		0x73B4B5C68E5D9AE3ULL,
		0x2A44109B7DDCBF93ULL,
		0x7B21CBAAAF4539ECULL,
		0xBDB2C2CBB18D274DULL,
		0x77F68B7FF1359573ULL,
		0x4F7D3B0D5AB28850ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB40C78C9516D364ULL,
		0xEDB93DBA823C0579ULL,
		0x3446501C0C6C4148ULL,
		0xD6163C0CB24ECFA1ULL,
		0x08BBD26C2083DF07ULL,
		0x7CD8EBB6C3428A63ULL,
		0x4F79DD150236A5B9ULL,
		0x32CE4A16DC0F4413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56818F192A2DA6C8ULL,
		0xDB727B7504780AF3ULL,
		0x688CA03818D88291ULL,
		0xAC2C7819649D9F42ULL,
		0x1177A4D84107BE0FULL,
		0xF9B1D76D868514C6ULL,
		0x9EF3BA2A046D4B72ULL,
		0x659C942DB81E8826ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFC670CD91D54F71CULL,
		0x2B17291046636E70ULL,
		0x61F134B438392F2BULL,
		0x6B56EEEA8BEC7BE6ULL,
		0x2AB3004EC01B9530ULL,
		0xE6FFC2970B89DEA5ULL,
		0x1B6C837E1E59BBAFULL,
		0x160AB53D7B5B5EF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8CE19B23AA9EE38ULL,
		0x562E52208CC6DCE1ULL,
		0xC3E2696870725E56ULL,
		0xD6ADDDD517D8F7CCULL,
		0x5566009D80372A60ULL,
		0xCDFF852E1713BD4AULL,
		0x36D906FC3CB3775FULL,
		0x2C156A7AF6B6BDE8ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE8A8B85B0B11D498ULL,
		0x3237406ECC1589CDULL,
		0xC2D9C0EEC1328E22ULL,
		0x368FF369038B0C05ULL,
		0x97FEA314CE98F0F9ULL,
		0xFA4D311B931AA12CULL,
		0xBD262412E250DBF4ULL,
		0x0BA2D005BE62F6CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15170B61623A930ULL,
		0x646E80DD982B139BULL,
		0x85B381DD82651C44ULL,
		0x6D1FE6D20716180BULL,
		0x2FFD46299D31E1F2ULL,
		0xF49A623726354259ULL,
		0x7A4C4825C4A1B7E9ULL,
		0x1745A00B7CC5ED95ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E1F0834EF5062BCULL,
		0x23DD1E187C685331ULL,
		0xB40EE31875AA87EDULL,
		0x0744B8744D883E4CULL,
		0x2B6654C096BD95A7ULL,
		0x49ACD98EA2E021EBULL,
		0x63BC3D152EE56CE4ULL,
		0x0104AD8D574DCBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3E1069DEA0C578ULL,
		0x47BA3C30F8D0A662ULL,
		0x681DC630EB550FDAULL,
		0x0E8970E89B107C99ULL,
		0x56CCA9812D7B2B4EULL,
		0x9359B31D45C043D6ULL,
		0xC7787A2A5DCAD9C8ULL,
		0x02095B1AAE9B975EULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCD17F64531B08F46ULL,
		0xFA51D0AC8848770FULL,
		0x3D324C29D3895276ULL,
		0x4045DBCEBE202716ULL,
		0x5096DE204E8B8EBCULL,
		0x03FC7BF775D15D56ULL,
		0x7BCCAF9BEB15B416ULL,
		0x20F7156BEA8CF0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A2FEC8A63611E8CULL,
		0xF4A3A1591090EE1FULL,
		0x7A649853A712A4EDULL,
		0x808BB79D7C404E2CULL,
		0xA12DBC409D171D78ULL,
		0x07F8F7EEEBA2BAACULL,
		0xF7995F37D62B682CULL,
		0x41EE2AD7D519E166ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAA278C1112C1717AULL,
		0xC0AD32F2921A8411ULL,
		0xE7E247F701A0A9FFULL,
		0x9CA588130C384DC4ULL,
		0x91EE33E8A43B9E31ULL,
		0x12C5C5280E7C680CULL,
		0x3648C199B1C6FB40ULL,
		0x26CC7923A9FCA7EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x544F18222582E2F4ULL,
		0x815A65E524350823ULL,
		0xCFC48FEE034153FFULL,
		0x394B102618709B89ULL,
		0x23DC67D148773C63ULL,
		0x258B8A501CF8D019ULL,
		0x6C918333638DF680ULL,
		0x4D98F24753F94FDCULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D1DB0B0ABCBD3F7ULL,
		0x14C30864F8675D7DULL,
		0xEEFA3D21FF9AA3FDULL,
		0x12378ACC1DC01C44ULL,
		0x653DE7B003F37DBDULL,
		0xE3C3B0DE78CF8508ULL,
		0x6C8EE9BBFA241F02ULL,
		0x212C22D408756838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3B61615797A7EEULL,
		0x298610C9F0CEBAFAULL,
		0xDDF47A43FF3547FAULL,
		0x246F15983B803889ULL,
		0xCA7BCF6007E6FB7AULL,
		0xC78761BCF19F0A10ULL,
		0xD91DD377F4483E05ULL,
		0x425845A810EAD070ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFCC122D35D20351EULL,
		0x9CCEC1E80DEA798FULL,
		0xD9EBDCDB2124FBB8ULL,
		0x59AC3AE3A31E68F3ULL,
		0x462A104754A762EEULL,
		0x858243F490CC7213ULL,
		0x3B26DAB3385A1C5DULL,
		0x33BF25487413312FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF98245A6BA406A3CULL,
		0x399D83D01BD4F31FULL,
		0xB3D7B9B64249F771ULL,
		0xB35875C7463CD1E7ULL,
		0x8C54208EA94EC5DCULL,
		0x0B0487E92198E426ULL,
		0x764DB56670B438BBULL,
		0x677E4A90E826625EULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C6401699AC03265ULL,
		0x7087D3DDB840D47BULL,
		0x71CD3280B45A5DD8ULL,
		0xCD73F74EE8423629ULL,
		0x10C09352B52B197AULL,
		0x1F66ED2693FBE095ULL,
		0x242B9E3A5CEAB597ULL,
		0x19E49E86BB5486E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C802D3358064CAULL,
		0xE10FA7BB7081A8F7ULL,
		0xE39A650168B4BBB0ULL,
		0x9AE7EE9DD0846C52ULL,
		0x218126A56A5632F5ULL,
		0x3ECDDA4D27F7C12AULL,
		0x48573C74B9D56B2EULL,
		0x33C93D0D76A90DD2ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D73964445F580F0ULL,
		0x2452DD7C6C5B08A5ULL,
		0x414D0D87B95DFFFFULL,
		0x5F0F6E95541F4754ULL,
		0x7D9C5A11052221C8ULL,
		0x2B91FD1998D73750ULL,
		0x48A51BA1C967E103ULL,
		0x0278B266A2873E6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE72C888BEB01E0ULL,
		0x48A5BAF8D8B6114AULL,
		0x829A1B0F72BBFFFEULL,
		0xBE1EDD2AA83E8EA8ULL,
		0xFB38B4220A444390ULL,
		0x5723FA3331AE6EA0ULL,
		0x914A374392CFC206ULL,
		0x04F164CD450E7CDAULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6D918929BA561D0EULL,
		0x9D8DEF570B5B65B8ULL,
		0x353481503E6C3A23ULL,
		0xA3E3CAF145523510ULL,
		0x76A88A957ADEDB35ULL,
		0x469D6C6CA2041CC2ULL,
		0x916AE9F7CF8F6AA7ULL,
		0x00CE0462A10247CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB23125374AC3A1CULL,
		0x3B1BDEAE16B6CB70ULL,
		0x6A6902A07CD87447ULL,
		0x47C795E28AA46A20ULL,
		0xED51152AF5BDB66BULL,
		0x8D3AD8D944083984ULL,
		0x22D5D3EF9F1ED54EULL,
		0x019C08C542048F9FULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6BA031C6B5873A65ULL,
		0x59E9D1BB1B7D98EAULL,
		0xBFB0ADA7C4777741ULL,
		0xFA02F5E7BB696358ULL,
		0xAF0EFC53605CE348ULL,
		0xE59FDEF9997D1C8FULL,
		0xCCA5EDE9C768F2D1ULL,
		0x303428E43388BACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD740638D6B0E74CAULL,
		0xB3D3A37636FB31D4ULL,
		0x7F615B4F88EEEE82ULL,
		0xF405EBCF76D2C6B1ULL,
		0x5E1DF8A6C0B9C691ULL,
		0xCB3FBDF332FA391FULL,
		0x994BDBD38ED1E5A3ULL,
		0x606851C86711759FULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x631DCEA57BBF2BBCULL,
		0x13DBBACE3BF02E04ULL,
		0x9046A304D8CC785AULL,
		0xE66DED7839B37CDAULL,
		0x2F6493A4BB4AD720ULL,
		0xDF058734758FB9C4ULL,
		0x2D14A7E6C6752C1AULL,
		0x21D1DC1A14F1A117ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63B9D4AF77E5778ULL,
		0x27B7759C77E05C08ULL,
		0x208D4609B198F0B4ULL,
		0xCCDBDAF07366F9B5ULL,
		0x5EC927497695AE41ULL,
		0xBE0B0E68EB1F7388ULL,
		0x5A294FCD8CEA5835ULL,
		0x43A3B83429E3422EULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAFF3F583DD58FC4FULL,
		0x1C7965621A1CCEE5ULL,
		0x5A662DD704F2EF5CULL,
		0x68D28F9516608C2DULL,
		0x2FF331442210677BULL,
		0x146A81F094F07EBFULL,
		0x9D5A3E2F4F73115FULL,
		0x0F83D0F6270873C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE7EB07BAB1F89EULL,
		0x38F2CAC434399DCBULL,
		0xB4CC5BAE09E5DEB8ULL,
		0xD1A51F2A2CC1185AULL,
		0x5FE662884420CEF6ULL,
		0x28D503E129E0FD7EULL,
		0x3AB47C5E9EE622BEULL,
		0x1F07A1EC4E10E787ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBFAF9CBDFAFDBA98ULL,
		0x116BC2ADBCECC0EFULL,
		0x62FA2C0B6FB374ECULL,
		0x37DD37380085D030ULL,
		0x3E62F47C24066A70ULL,
		0x3755FCBBEC29A48FULL,
		0x4EC9C651F48E52F9ULL,
		0x00E9702026454909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F5F397BF5FB7530ULL,
		0x22D7855B79D981DFULL,
		0xC5F45816DF66E9D8ULL,
		0x6FBA6E70010BA060ULL,
		0x7CC5E8F8480CD4E0ULL,
		0x6EABF977D853491EULL,
		0x9D938CA3E91CA5F2ULL,
		0x01D2E0404C8A9212ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x79F570711B497749ULL,
		0xFC77458FA3EC90AAULL,
		0xF77261323A49D9B1ULL,
		0x7E9F54F3E06803DCULL,
		0xE455FD4566CD6E1EULL,
		0x187053B02E2B6D57ULL,
		0x48C196A71D32511DULL,
		0x2DC70C48174F68B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3EAE0E23692EE92ULL,
		0xF8EE8B1F47D92154ULL,
		0xEEE4C2647493B363ULL,
		0xFD3EA9E7C0D007B9ULL,
		0xC8ABFA8ACD9ADC3CULL,
		0x30E0A7605C56DAAFULL,
		0x91832D4E3A64A23AULL,
		0x5B8E18902E9ED16CULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9E86D575CD47A797ULL,
		0xDB5C473301C585DBULL,
		0x348CCDFFE445F6B1ULL,
		0x876668EBCA0C919AULL,
		0x36A0B036BDC53CE1ULL,
		0x49A07C1ED3160A07ULL,
		0xE63D2599BE4B2831ULL,
		0x03EAA3CEAD706CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0DAAEB9A8F4F2EULL,
		0xB6B88E66038B0BB7ULL,
		0x69199BFFC88BED63ULL,
		0x0ECCD1D794192334ULL,
		0x6D41606D7B8A79C3ULL,
		0x9340F83DA62C140EULL,
		0xCC7A4B337C965062ULL,
		0x07D5479D5AE0D959ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A210C01BA739B50ULL,
		0xA7F3320C7D50C61BULL,
		0x7B7246ABA31724E1ULL,
		0xFFE109C977FF3C0BULL,
		0x91647F91FEDE0521ULL,
		0xF67045E7439E7181ULL,
		0xEDC2BFB77C915A7BULL,
		0x141259E206EF4E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD442180374E736A0ULL,
		0x4FE66418FAA18C36ULL,
		0xF6E48D57462E49C3ULL,
		0xFFC21392EFFE7816ULL,
		0x22C8FF23FDBC0A43ULL,
		0xECE08BCE873CE303ULL,
		0xDB857F6EF922B4F7ULL,
		0x2824B3C40DDE9C31ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD27C4AFB5704DF97ULL,
		0x5DE561B029D57789ULL,
		0xD3A07F3DE45E26FBULL,
		0x306F3BF8B3208E39ULL,
		0x27FC32F0B426EF5CULL,
		0x3D5BB65C75A60A46ULL,
		0x96F187D676F8838CULL,
		0x17BADF7D25686FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F895F6AE09BF2EULL,
		0xBBCAC36053AAEF13ULL,
		0xA740FE7BC8BC4DF6ULL,
		0x60DE77F166411C73ULL,
		0x4FF865E1684DDEB8ULL,
		0x7AB76CB8EB4C148CULL,
		0x2DE30FACEDF10718ULL,
		0x2F75BEFA4AD0DFA5ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2100B7033FF53193ULL,
		0xF3155E9BE4CA9031ULL,
		0xFA8D609983ADEE17ULL,
		0x9794C9C6EAA1F42DULL,
		0x1BC8173FDD0C56B1ULL,
		0x4A6AF9D6612EDEFEULL,
		0x25EDF976DDA5A9D8ULL,
		0x1751D59D7E4BEA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42016E067FEA6326ULL,
		0xE62ABD37C9952062ULL,
		0xF51AC133075BDC2FULL,
		0x2F29938DD543E85BULL,
		0x37902E7FBA18AD63ULL,
		0x94D5F3ACC25DBDFCULL,
		0x4BDBF2EDBB4B53B0ULL,
		0x2EA3AB3AFC97D494ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB223BC83F0BEF5FEULL,
		0x0333B7BB09E4077EULL,
		0xD0F60D2182EEBACFULL,
		0x12B2178C4A7C5641ULL,
		0xB601908E2BD8DEAFULL,
		0x2649C5C73E43AE8FULL,
		0x64FFCDACFFB59FA8ULL,
		0x2A824E977C309B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64477907E17DEBFCULL,
		0x06676F7613C80EFDULL,
		0xA1EC1A4305DD759EULL,
		0x25642F1894F8AC83ULL,
		0x6C03211C57B1BD5EULL,
		0x4C938B8E7C875D1FULL,
		0xC9FF9B59FF6B3F50ULL,
		0x55049D2EF8613608ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCD0FD0171F7C59FULL,
		0xCA8E3FAA39809F3EULL,
		0xED629D964AAF3281ULL,
		0x36862D0ED4827FB6ULL,
		0x0FDD86AD1E1FC613ULL,
		0x9BCF29A841C8EBC6ULL,
		0x107532D42E660644ULL,
		0x3651A9E6206489B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99A1FA02E3EF8B3EULL,
		0x951C7F5473013E7DULL,
		0xDAC53B2C955E6503ULL,
		0x6D0C5A1DA904FF6DULL,
		0x1FBB0D5A3C3F8C26ULL,
		0x379E53508391D78CULL,
		0x20EA65A85CCC0C89ULL,
		0x6CA353CC40C91362ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC11BA2D65A27C5BBULL,
		0x65C84A948DD94660ULL,
		0xEC63621D4AC722FBULL,
		0x25001F16951A48BFULL,
		0xC3A41290D5E36FD0ULL,
		0x6399FC697E8B9D9AULL,
		0x9AF0849749673D2CULL,
		0x19A30FDC177BB511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x823745ACB44F8B76ULL,
		0xCB9095291BB28CC1ULL,
		0xD8C6C43A958E45F6ULL,
		0x4A003E2D2A34917FULL,
		0x87482521ABC6DFA0ULL,
		0xC733F8D2FD173B35ULL,
		0x35E1092E92CE7A58ULL,
		0x33461FB82EF76A23ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x70CDF9AEC3FA28B9ULL,
		0xC0F1058EA469D85BULL,
		0xC5AB56FFFBBD1DA4ULL,
		0xFBEBDF32B3983BFAULL,
		0x6FE2415AFB2D0EC7ULL,
		0x99C67FE067DBCA4EULL,
		0x896EE43D20F8D219ULL,
		0x22A2A81E6455D490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19BF35D87F45172ULL,
		0x81E20B1D48D3B0B6ULL,
		0x8B56ADFFF77A3B49ULL,
		0xF7D7BE65673077F5ULL,
		0xDFC482B5F65A1D8FULL,
		0x338CFFC0CFB7949CULL,
		0x12DDC87A41F1A433ULL,
		0x4545503CC8ABA921ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x10BFDAC1DA9474DCULL,
		0xFB63E318B3737207ULL,
		0xE00F78BD4A77FE1DULL,
		0x4C70F9DDC2B5E9A5ULL,
		0x6D8ACDFD21DEA278ULL,
		0x938EE8E56FB39519ULL,
		0xCB7C115C47BA4819ULL,
		0x191044CB9C24F6AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x217FB583B528E9B8ULL,
		0xF6C7C63166E6E40EULL,
		0xC01EF17A94EFFC3BULL,
		0x98E1F3BB856BD34BULL,
		0xDB159BFA43BD44F0ULL,
		0x271DD1CADF672A32ULL,
		0x96F822B88F749033ULL,
		0x322089973849ED55ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFFE0140AD752293DULL,
		0x1E0194F1D2CB01BCULL,
		0xA00F9BD9E67A45F4ULL,
		0xFF4190706EB33D9DULL,
		0xAC52A0983C623F87ULL,
		0x86607F9521BD5692ULL,
		0x0C8905A2A0A7FD19ULL,
		0x03D51A274E5F863EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC02815AEA4527AULL,
		0x3C0329E3A5960379ULL,
		0x401F37B3CCF48BE8ULL,
		0xFE8320E0DD667B3BULL,
		0x58A5413078C47F0FULL,
		0x0CC0FF2A437AAD25ULL,
		0x19120B45414FFA33ULL,
		0x07AA344E9CBF0C7CULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE723513B8F5EA17BULL,
		0xF098CFDB9ADD868EULL,
		0xA681B4F36118CE9AULL,
		0xC0700AD54DF336AFULL,
		0x11DCFEB285AFD0B5ULL,
		0x015DE3DD0B9A0436ULL,
		0x933CFF96C1C3BEC4ULL,
		0x13B1622AF65ACE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE46A2771EBD42F6ULL,
		0xE1319FB735BB0D1DULL,
		0x4D0369E6C2319D35ULL,
		0x80E015AA9BE66D5FULL,
		0x23B9FD650B5FA16BULL,
		0x02BBC7BA1734086CULL,
		0x2679FF2D83877D88ULL,
		0x2762C455ECB59C2BULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9EAD011CDE05FCA0ULL,
		0xB26A0C286831837BULL,
		0xB464316433DE8532ULL,
		0x9B4B9D563B6061A9ULL,
		0xAC519B142BA5AC5DULL,
		0x44DD6CD7B2B1807AULL,
		0xAEB8A9DB3FAB0F5EULL,
		0x3D68AAC8F2538B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5A0239BC0BF940ULL,
		0x64D41850D06306F7ULL,
		0x68C862C867BD0A65ULL,
		0x36973AAC76C0C353ULL,
		0x58A33628574B58BBULL,
		0x89BAD9AF656300F5ULL,
		0x5D7153B67F561EBCULL,
		0x7AD15591E4A71711ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3DB9755095D540AULL,
		0xCD575E7AF63FC2AAULL,
		0xE5B18AB179FA3EF9ULL,
		0xC4ECC2A8931F6CD4ULL,
		0x3CFB61A3AF129C21ULL,
		0x9ECD18EA5DF0BFF2ULL,
		0xFCD022D0162913BDULL,
		0x2233EB4E2FB20DC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B72EAA12BAA814ULL,
		0x9AAEBCF5EC7F8555ULL,
		0xCB631562F3F47DF3ULL,
		0x89D98551263ED9A9ULL,
		0x79F6C3475E253843ULL,
		0x3D9A31D4BBE17FE4ULL,
		0xF9A045A02C52277BULL,
		0x4467D69C5F641B8FULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07B0D5EE418CF1ECULL,
		0x7F209DDFA917762AULL,
		0xB57F0C215E3D0917ULL,
		0x03E4541FB6A10312ULL,
		0x624B48E2B5C452C8ULL,
		0xD477C8B413A0AF03ULL,
		0xB2E358A77743ED6DULL,
		0x247EA7C19997F865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F61ABDC8319E3D8ULL,
		0xFE413BBF522EEC54ULL,
		0x6AFE1842BC7A122EULL,
		0x07C8A83F6D420625ULL,
		0xC49691C56B88A590ULL,
		0xA8EF916827415E06ULL,
		0x65C6B14EEE87DADBULL,
		0x48FD4F83332FF0CBULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE505A5EA48DD4C01ULL,
		0x47D012E4ACC40021ULL,
		0xC6C4CAA44B403D30ULL,
		0x02A59D6A208368C2ULL,
		0x843EA159C5321E82ULL,
		0x36BBFB6A9B228BC2ULL,
		0x70E844004E3DBA14ULL,
		0x30517E62166ACE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0B4BD491BA9802ULL,
		0x8FA025C959880043ULL,
		0x8D89954896807A60ULL,
		0x054B3AD44106D185ULL,
		0x087D42B38A643D04ULL,
		0x6D77F6D536451785ULL,
		0xE1D088009C7B7428ULL,
		0x60A2FCC42CD59C94ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A37E465D7B41106ULL,
		0x2682554340166030ULL,
		0x7B1F02AE1EC62C70ULL,
		0xE505D74F415815ADULL,
		0x94F597F350634FE8ULL,
		0xF8339DE3E4D92155ULL,
		0x8671F524EA1DA845ULL,
		0x2666CBAA6EBC2D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146FC8CBAF68220CULL,
		0x4D04AA86802CC060ULL,
		0xF63E055C3D8C58E0ULL,
		0xCA0BAE9E82B02B5AULL,
		0x29EB2FE6A0C69FD1ULL,
		0xF0673BC7C9B242ABULL,
		0x0CE3EA49D43B508BULL,
		0x4CCD9754DD785A6FULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEEFDECD24D31E6B5ULL,
		0x8F15F6C7F2ADC8C1ULL,
		0xC203D11A14775BD8ULL,
		0xA302CB6E61BDDE9AULL,
		0x96670E5865BD919EULL,
		0xDED6C86543580F68ULL,
		0x821CE025DBADF3B1ULL,
		0x1718FF48864EC26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFBD9A49A63CD6AULL,
		0x1E2BED8FE55B9183ULL,
		0x8407A23428EEB7B1ULL,
		0x460596DCC37BBD35ULL,
		0x2CCE1CB0CB7B233DULL,
		0xBDAD90CA86B01ED1ULL,
		0x0439C04BB75BE763ULL,
		0x2E31FE910C9D84D9ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4B25435E404EBD8CULL,
		0x27B9DC6ED1A80160ULL,
		0x71073102AE3E71C0ULL,
		0xB4D0D7C555A3FDBEULL,
		0xBE86613C98C4E9BDULL,
		0x3C8725A22687AD88ULL,
		0x36E94461CE04DF98ULL,
		0x0DF46DA39E5E02D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x964A86BC809D7B18ULL,
		0x4F73B8DDA35002C0ULL,
		0xE20E62055C7CE380ULL,
		0x69A1AF8AAB47FB7CULL,
		0x7D0CC2793189D37BULL,
		0x790E4B444D0F5B11ULL,
		0x6DD288C39C09BF30ULL,
		0x1BE8DB473CBC05A6ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x27E00E46BACC6ECBULL,
		0xD9044FFF0FE76460ULL,
		0x1E538D27C79C1D03ULL,
		0x816920323629F279ULL,
		0xE6883D5D466DC168ULL,
		0x4B5CD9948A14F11FULL,
		0x2404320A1B07AEE9ULL,
		0x03331B3B995A1EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC01C8D7598DD96ULL,
		0xB2089FFE1FCEC8C0ULL,
		0x3CA71A4F8F383A07ULL,
		0x02D240646C53E4F2ULL,
		0xCD107ABA8CDB82D1ULL,
		0x96B9B3291429E23FULL,
		0x48086414360F5DD2ULL,
		0x0666367732B43D62ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12B8510088A7BCE3ULL,
		0x361C746A7CEE5440ULL,
		0xB6930F69892A03E5ULL,
		0x7AF71903210DCD9CULL,
		0x55AB9543C415AB8FULL,
		0xFD343C154F1250A1ULL,
		0xF9AFB93140361F03ULL,
		0x07FF0B04604EE793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2570A201114F79C6ULL,
		0x6C38E8D4F9DCA880ULL,
		0x6D261ED3125407CAULL,
		0xF5EE3206421B9B39ULL,
		0xAB572A87882B571EULL,
		0xFA68782A9E24A142ULL,
		0xF35F7262806C3E07ULL,
		0x0FFE1608C09DCF27ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF0DA9E755F78A859ULL,
		0x7D07B286197DB1A4ULL,
		0x572827E7CAF97C2BULL,
		0x8E82D8347514BE84ULL,
		0x98A95D8A6A01E894ULL,
		0x6D5FDAC6B32980FBULL,
		0xBBAA4412EAE10686ULL,
		0x3BB7A523C1DF5E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B53CEABEF150B2ULL,
		0xFA0F650C32FB6349ULL,
		0xAE504FCF95F2F856ULL,
		0x1D05B068EA297D08ULL,
		0x3152BB14D403D129ULL,
		0xDABFB58D665301F7ULL,
		0x77548825D5C20D0CULL,
		0x776F4A4783BEBD0FULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3024F8BC6A263FB0ULL,
		0x19B8B577E34189AEULL,
		0x94620EEB0D387412ULL,
		0x496441DC3ED8A07CULL,
		0xC5790AE56B40A88BULL,
		0xFA75CCD5BDEAAC68ULL,
		0xED8050CA430E4DD5ULL,
		0x2D5F8D8DEE215083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6049F178D44C7F60ULL,
		0x33716AEFC683135CULL,
		0x28C41DD61A70E824ULL,
		0x92C883B87DB140F9ULL,
		0x8AF215CAD6815116ULL,
		0xF4EB99AB7BD558D1ULL,
		0xDB00A194861C9BABULL,
		0x5ABF1B1BDC42A107ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x83A78964D61B6D5DULL,
		0x38CD0E973C0E10B3ULL,
		0x574FBAF868782EB3ULL,
		0x7DD627B35469AF18ULL,
		0xFB8C25A94546EDBEULL,
		0xD64EE01387FFA1DEULL,
		0x1B486218A16AFE6CULL,
		0x3A81B95B94955D79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074F12C9AC36DABAULL,
		0x719A1D2E781C2167ULL,
		0xAE9F75F0D0F05D66ULL,
		0xFBAC4F66A8D35E30ULL,
		0xF7184B528A8DDB7CULL,
		0xAC9DC0270FFF43BDULL,
		0x3690C43142D5FCD9ULL,
		0x750372B7292ABAF2ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x90D84FA778EB1E17ULL,
		0x98202F08F0375511ULL,
		0x1E8FDAFDFCDF8E4AULL,
		0xFC4D1463BE372D31ULL,
		0x40DC679F7CA25453ULL,
		0x10D42B305925E3A9ULL,
		0xB02E8F7ED5B44944ULL,
		0x3B096997F4C3CB77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B09F4EF1D63C2EULL,
		0x30405E11E06EAA23ULL,
		0x3D1FB5FBF9BF1C95ULL,
		0xF89A28C77C6E5A62ULL,
		0x81B8CF3EF944A8A7ULL,
		0x21A85660B24BC752ULL,
		0x605D1EFDAB689288ULL,
		0x7612D32FE98796EFULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x635B9FC2950ACA22ULL,
		0xC5C49F46A97285BFULL,
		0x46B32D12E9762183ULL,
		0xEBF0733B8BDE86D5ULL,
		0xD154CE65E8221AAAULL,
		0x2C22DDC3D8BDB972ULL,
		0x8878591603F424E3ULL,
		0x165D99B1629D8792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B73F852A159444ULL,
		0x8B893E8D52E50B7EULL,
		0x8D665A25D2EC4307ULL,
		0xD7E0E67717BD0DAAULL,
		0xA2A99CCBD0443555ULL,
		0x5845BB87B17B72E5ULL,
		0x10F0B22C07E849C6ULL,
		0x2CBB3362C53B0F25ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x87423F3757CB669AULL,
		0x80E878E523B3F80EULL,
		0xCA80E12DC6622E4AULL,
		0x93606C3B6CEFF46CULL,
		0x75A29D2589C4B0F0ULL,
		0x062A5BC77BC897FBULL,
		0x8476B5E21914C728ULL,
		0x290457414AF8520CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E847E6EAF96CD34ULL,
		0x01D0F1CA4767F01DULL,
		0x9501C25B8CC45C95ULL,
		0x26C0D876D9DFE8D9ULL,
		0xEB453A4B138961E1ULL,
		0x0C54B78EF7912FF6ULL,
		0x08ED6BC432298E50ULL,
		0x5208AE8295F0A419ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF2BA502EADCEB756ULL,
		0xDCDCF8A0D4BAE49AULL,
		0x462F64F0EC32D762ULL,
		0xBA8CD620E2FE4002ULL,
		0x87AECCD88B1B4F1EULL,
		0x1A6D7790F2BE26C7ULL,
		0xFF69656A85CEF4DAULL,
		0x0A6445514CAFCE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE574A05D5B9D6EACULL,
		0xB9B9F141A975C935ULL,
		0x8C5EC9E1D865AEC5ULL,
		0x7519AC41C5FC8004ULL,
		0x0F5D99B116369E3DULL,
		0x34DAEF21E57C4D8FULL,
		0xFED2CAD50B9DE9B4ULL,
		0x14C88AA2995F9CC5ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08934BC1ABEB959EULL,
		0x1EF2A530FDD14B61ULL,
		0xA47054BC9D377EF4ULL,
		0xA508699CA05D1A2FULL,
		0x70864F43CD975659ULL,
		0x249F707EAB0003A2ULL,
		0x0C4F1CB9131A814BULL,
		0x0250CE2209524499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1126978357D72B3CULL,
		0x3DE54A61FBA296C2ULL,
		0x48E0A9793A6EFDE8ULL,
		0x4A10D33940BA345FULL,
		0xE10C9E879B2EACB3ULL,
		0x493EE0FD56000744ULL,
		0x189E397226350296ULL,
		0x04A19C4412A48932ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0C5F889CC7F367E6ULL,
		0x49DD8803A9880436ULL,
		0x60BA24DB26A05E8DULL,
		0x0A374E7B1A7B4BDAULL,
		0x9BCB371957487487ULL,
		0xBE7D07894744FDD7ULL,
		0x2FDAA47463EF0B21ULL,
		0x123B3CCA1D94F588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18BF11398FE6CFCCULL,
		0x93BB10075310086CULL,
		0xC17449B64D40BD1AULL,
		0x146E9CF634F697B4ULL,
		0x37966E32AE90E90EULL,
		0x7CFA0F128E89FBAFULL,
		0x5FB548E8C7DE1643ULL,
		0x247679943B29EB10ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB75FDBFC6D23CD49ULL,
		0x2A8F448570A30658ULL,
		0xFDF90FD1863014A2ULL,
		0x422220E0A72B8249ULL,
		0x72566D7AB641060FULL,
		0x95192EB342073318ULL,
		0xD477646592A11E63ULL,
		0x01B025F63E54C404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBFB7F8DA479A92ULL,
		0x551E890AE1460CB1ULL,
		0xFBF21FA30C602944ULL,
		0x844441C14E570493ULL,
		0xE4ACDAF56C820C1EULL,
		0x2A325D66840E6630ULL,
		0xA8EEC8CB25423CC7ULL,
		0x03604BEC7CA98809ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DF609DF117B06D7ULL,
		0x3EB7DFEC7DBFA545ULL,
		0x30BFD55F1B9A2C9BULL,
		0x99D592933CF1EC7AULL,
		0x105C34BB5AB7A691ULL,
		0xA448980651F136D1ULL,
		0x378BAC891500583CULL,
		0x391DCD8975FD9460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEC13BE22F60DAEULL,
		0x7D6FBFD8FB7F4A8AULL,
		0x617FAABE37345936ULL,
		0x33AB252679E3D8F4ULL,
		0x20B86976B56F4D23ULL,
		0x4891300CA3E26DA2ULL,
		0x6F1759122A00B079ULL,
		0x723B9B12EBFB28C0ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x60936B676FB5033EULL,
		0x4F82B79889A752ACULL,
		0x4B80D8FFF5ADE745ULL,
		0xF827F25EBD63C918ULL,
		0xD5B6074E3F98E4DDULL,
		0x41A752BA2EBC99E1ULL,
		0x6602E4B78837EB08ULL,
		0x3D182373107CB72BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC126D6CEDF6A067CULL,
		0x9F056F31134EA558ULL,
		0x9701B1FFEB5BCE8AULL,
		0xF04FE4BD7AC79230ULL,
		0xAB6C0E9C7F31C9BBULL,
		0x834EA5745D7933C3ULL,
		0xCC05C96F106FD610ULL,
		0x7A3046E620F96E56ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF2000994BAF6E7EAULL,
		0x9062E4B496DF39B3ULL,
		0x40BB3F17D3E61DE4ULL,
		0xA322E125BEC36A6CULL,
		0x47D31FF51FC8F27AULL,
		0x70B5A4BA73BCBA39ULL,
		0x7F71A369F3E8DCC1ULL,
		0x2415C11EB03FDAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE400132975EDCFD4ULL,
		0x20C5C9692DBE7367ULL,
		0x81767E2FA7CC3BC9ULL,
		0x4645C24B7D86D4D8ULL,
		0x8FA63FEA3F91E4F5ULL,
		0xE16B4974E7797472ULL,
		0xFEE346D3E7D1B982ULL,
		0x482B823D607FB5F8ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x03B1077563620EFCULL,
		0xBBADC6FD6EA24826ULL,
		0x345190040B153425ULL,
		0x4785320F2E45A338ULL,
		0xC9C80805922DF550ULL,
		0xA5D69B1486541D47ULL,
		0x0DF7E356AD8584DEULL,
		0x2E5D3AF46E26B47AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07620EEAC6C41DF8ULL,
		0x775B8DFADD44904CULL,
		0x68A32008162A684BULL,
		0x8F0A641E5C8B4670ULL,
		0x9390100B245BEAA0ULL,
		0x4BAD36290CA83A8FULL,
		0x1BEFC6AD5B0B09BDULL,
		0x5CBA75E8DC4D68F4ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0358C84518AB082EULL,
		0x0941DEB0338741E7ULL,
		0xC93C96BCD8E530D6ULL,
		0xA72FBA78BBED9F4FULL,
		0xC503EEA01DBCEFC3ULL,
		0xEEDDC8E6AA179217ULL,
		0x9B432DFE34F9A9FEULL,
		0x229D496057A101A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B1908A3156105CULL,
		0x1283BD60670E83CEULL,
		0x92792D79B1CA61ACULL,
		0x4E5F74F177DB3E9FULL,
		0x8A07DD403B79DF87ULL,
		0xDDBB91CD542F242FULL,
		0x36865BFC69F353FDULL,
		0x453A92C0AF420345ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x191B44CA9554BC1CULL,
		0x35D5E2717F9563C0ULL,
		0x4BEAE2168BB2F093ULL,
		0xDFCC959FCF41A731ULL,
		0xD9D6422C2678865AULL,
		0xAE1156DC31EB9AC5ULL,
		0x28EA73FDF32E8CA8ULL,
		0x2DC6E915CB7A044AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323689952AA97838ULL,
		0x6BABC4E2FF2AC780ULL,
		0x97D5C42D1765E126ULL,
		0xBF992B3F9E834E62ULL,
		0xB3AC84584CF10CB5ULL,
		0x5C22ADB863D7358BULL,
		0x51D4E7FBE65D1951ULL,
		0x5B8DD22B96F40894ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81CAE2810E016F9CULL,
		0x97D0121F86C043ACULL,
		0x523902A41957E3FFULL,
		0x6790923F96B3F2D1ULL,
		0x6D63CC5BF09FF719ULL,
		0x98808E077E3B5DBDULL,
		0x49798F3FB3289235ULL,
		0x135B4BAF108F434EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0395C5021C02DF38ULL,
		0x2FA0243F0D808759ULL,
		0xA472054832AFC7FFULL,
		0xCF21247F2D67E5A2ULL,
		0xDAC798B7E13FEE32ULL,
		0x31011C0EFC76BB7AULL,
		0x92F31E7F6651246BULL,
		0x26B6975E211E869CULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4073BFE3A37AC03FULL,
		0x0C3721E982F1D4A0ULL,
		0x5BCE66EE539FBD25ULL,
		0xA5C700BD86ADA40CULL,
		0x43BF49984EAA1F4FULL,
		0x270B01D47901414EULL,
		0xD82347A4A77F390FULL,
		0x377ED88475F93FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E77FC746F5807EULL,
		0x186E43D305E3A940ULL,
		0xB79CCDDCA73F7A4AULL,
		0x4B8E017B0D5B4818ULL,
		0x877E93309D543E9FULL,
		0x4E1603A8F202829CULL,
		0xB0468F494EFE721EULL,
		0x6EFDB108EBF27F8FULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x899C6901C5CF2400ULL,
		0xEE4E57A2F467ECCDULL,
		0xC2A22661BA966B0FULL,
		0xDEB60BACB883A5F4ULL,
		0xDD76355105321E93ULL,
		0x40A8FAA9D6E13FA9ULL,
		0x490687A70DEEEB89ULL,
		0x2BA1BD1753100074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1338D2038B9E4800ULL,
		0xDC9CAF45E8CFD99BULL,
		0x85444CC3752CD61FULL,
		0xBD6C175971074BE9ULL,
		0xBAEC6AA20A643D27ULL,
		0x8151F553ADC27F53ULL,
		0x920D0F4E1BDDD712ULL,
		0x57437A2EA62000E8ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x842F146BBC29CD21ULL,
		0x2D7C22AE47F92096ULL,
		0x14161562AB96B425ULL,
		0xFDBCCD75A3851827ULL,
		0x9396E4536D87F3A3ULL,
		0xC89EBEFE5870A10DULL,
		0x9154F2A47E64C116ULL,
		0x19ED1CD922A6D504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085E28D778539A42ULL,
		0x5AF8455C8FF2412DULL,
		0x282C2AC5572D684AULL,
		0xFB799AEB470A304EULL,
		0x272DC8A6DB0FE747ULL,
		0x913D7DFCB0E1421BULL,
		0x22A9E548FCC9822DULL,
		0x33DA39B2454DAA09ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20A480B5E246276AULL,
		0x4451D76A22C15801ULL,
		0x4CF02F72FE5397A6ULL,
		0xA7352821BD305783ULL,
		0x36E81C348F20DE1EULL,
		0x748972DCB96D036CULL,
		0x0133F535C7195A1FULL,
		0x13A918F8F3AA65A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4149016BC48C4ED4ULL,
		0x88A3AED44582B002ULL,
		0x99E05EE5FCA72F4CULL,
		0x4E6A50437A60AF06ULL,
		0x6DD038691E41BC3DULL,
		0xE912E5B972DA06D8ULL,
		0x0267EA6B8E32B43EULL,
		0x275231F1E754CB4AULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x91FDEF81104C7891ULL,
		0x8CE83FE16BCC7BBCULL,
		0x7445243CF4E3D13EULL,
		0x261ED11DDFBA831AULL,
		0x84C0A416744AC9BCULL,
		0xA38D0E464747CD0AULL,
		0x6694238312014B1EULL,
		0x366ACD5437B6251AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23FBDF022098F122ULL,
		0x19D07FC2D798F779ULL,
		0xE88A4879E9C7A27DULL,
		0x4C3DA23BBF750634ULL,
		0x0981482CE8959378ULL,
		0x471A1C8C8E8F9A15ULL,
		0xCD2847062402963DULL,
		0x6CD59AA86F6C4A34ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E5AB853BFB51F26ULL,
		0x49229E2C669C87D0ULL,
		0xE75424CADAD8CBE9ULL,
		0xD1DDFA625C7DD3BAULL,
		0xAD790800BAE89EA0ULL,
		0x1503724489B14A3CULL,
		0xCFE55113451CD9EAULL,
		0x036C7D550998162AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB570A77F6A3E4CULL,
		0x92453C58CD390FA0ULL,
		0xCEA84995B5B197D2ULL,
		0xA3BBF4C4B8FBA775ULL,
		0x5AF2100175D13D41ULL,
		0x2A06E48913629479ULL,
		0x9FCAA2268A39B3D4ULL,
		0x06D8FAAA13302C55ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6C3F8AA18FA4B1E7ULL,
		0xB4FBAB05D517A767ULL,
		0x8DF82EE1A2A3870DULL,
		0x9CF04C7E435E1F61ULL,
		0x03F71E31B2055660ULL,
		0x3635123922BE3EE4ULL,
		0xFD3F5ED2ED6A7175ULL,
		0x3A03D07C21B76BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD87F15431F4963CEULL,
		0x69F7560BAA2F4ECEULL,
		0x1BF05DC345470E1BULL,
		0x39E098FC86BC3EC3ULL,
		0x07EE3C63640AACC1ULL,
		0x6C6A2472457C7DC8ULL,
		0xFA7EBDA5DAD4E2EAULL,
		0x7407A0F8436ED77FULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCFF9E54049AFDC00ULL,
		0x78E484258015D0A8ULL,
		0x1011BEE5CE9647E0ULL,
		0x0F8F791DBB1DE711ULL,
		0x5B853034F5AAA77EULL,
		0x222BEB18D373A61EULL,
		0x67D3138D24D967F7ULL,
		0x03F9FEE72673806CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF3CA80935FB800ULL,
		0xF1C9084B002BA151ULL,
		0x20237DCB9D2C8FC0ULL,
		0x1F1EF23B763BCE22ULL,
		0xB70A6069EB554EFCULL,
		0x4457D631A6E74C3CULL,
		0xCFA6271A49B2CFEEULL,
		0x07F3FDCE4CE700D8ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA1D383297B0587ABULL,
		0xA2816D9F6CFA4474ULL,
		0x5F0BD8F2CBB65925ULL,
		0xB569A7691547BF82ULL,
		0x85820A3C50D9261CULL,
		0x5123C0C042B22F7CULL,
		0x1A5F883703BE4B19ULL,
		0x22A180C367C55C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A70652F60B0F56ULL,
		0x4502DB3ED9F488E9ULL,
		0xBE17B1E5976CB24BULL,
		0x6AD34ED22A8F7F04ULL,
		0x0B041478A1B24C39ULL,
		0xA247818085645EF9ULL,
		0x34BF106E077C9632ULL,
		0x45430186CF8AB814ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6260234CD8EEA9CBULL,
		0x9BE7DB823A644816ULL,
		0x2C16598F3868CD84ULL,
		0xA6799985DE1F77CFULL,
		0xBCA2EF289837D9ACULL,
		0x324868801B7FA7BAULL,
		0x758D1C37340AACF9ULL,
		0x3E0E4580687CF7A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C04699B1DD5396ULL,
		0x37CFB70474C8902CULL,
		0x582CB31E70D19B09ULL,
		0x4CF3330BBC3EEF9EULL,
		0x7945DE51306FB359ULL,
		0x6490D10036FF4F75ULL,
		0xEB1A386E681559F2ULL,
		0x7C1C8B00D0F9EF48ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75785000B8ED4479ULL,
		0x60440D3CECFB50FBULL,
		0x425D3AD48BC47DFEULL,
		0xBA9EB9C98887AF17ULL,
		0xBE84887B8141D3CFULL,
		0xE6984C0FE62EA8AFULL,
		0xED162786F989805DULL,
		0x12A3AACAFD36F0BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAF0A00171DA88F2ULL,
		0xC0881A79D9F6A1F6ULL,
		0x84BA75A91788FBFCULL,
		0x753D7393110F5E2EULL,
		0x7D0910F70283A79FULL,
		0xCD30981FCC5D515FULL,
		0xDA2C4F0DF31300BBULL,
		0x25475595FA6DE175ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x841580B829EE5660ULL,
		0xAD4C03E2A6D78C88ULL,
		0x32DD2BA01F14B772ULL,
		0x31AEC242E3648EA0ULL,
		0x1893D0E701115538ULL,
		0x3A5B40A2DC837F9CULL,
		0x952FCA04ABE88313ULL,
		0x2CF3F819B6EA4E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x082B017053DCACC0ULL,
		0x5A9807C54DAF1911ULL,
		0x65BA57403E296EE5ULL,
		0x635D8485C6C91D40ULL,
		0x3127A1CE0222AA70ULL,
		0x74B68145B906FF38ULL,
		0x2A5F940957D10626ULL,
		0x59E7F0336DD49C8DULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x84F3C92A57B36332ULL,
		0x104A167C132C276BULL,
		0xC11F5F022725F12CULL,
		0x11378E1453CFF6D3ULL,
		0xECAF4DEB931FB809ULL,
		0x7991AEB3E52A0A63ULL,
		0x8C8959D56F66766CULL,
		0x0B818D8C3C1DFB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E79254AF66C664ULL,
		0x20942CF826584ED7ULL,
		0x823EBE044E4BE258ULL,
		0x226F1C28A79FEDA7ULL,
		0xD95E9BD7263F7012ULL,
		0xF3235D67CA5414C7ULL,
		0x1912B3AADECCECD8ULL,
		0x17031B18783BF6A5ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x101583EABCD9C86AULL,
		0xB96557E7A0D29D7EULL,
		0x40E9EC973E702B58ULL,
		0x2F0FC57A8D797D3EULL,
		0x58BC22B9E0AE2348ULL,
		0x836093F50D439B32ULL,
		0x802829FE8E955D95ULL,
		0x3F60C7FCEDB9C8ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202B07D579B390D4ULL,
		0x72CAAFCF41A53AFCULL,
		0x81D3D92E7CE056B1ULL,
		0x5E1F8AF51AF2FA7CULL,
		0xB1784573C15C4690ULL,
		0x06C127EA1A873664ULL,
		0x005053FD1D2ABB2BULL,
		0x7EC18FF9DB7391D9ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x153BD4F191562625ULL,
		0x2BF926D53A9A395DULL,
		0x9FB05339C3A613B8ULL,
		0x7497B655EB8AF046ULL,
		0xDE99128FD904F452ULL,
		0x3F7C70A823201FA1ULL,
		0x1397A577EA7BC152ULL,
		0x0B780AABEA41400BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A77A9E322AC4C4AULL,
		0x57F24DAA753472BAULL,
		0x3F60A673874C2770ULL,
		0xE92F6CABD715E08DULL,
		0xBD32251FB209E8A4ULL,
		0x7EF8E15046403F43ULL,
		0x272F4AEFD4F782A4ULL,
		0x16F01557D4828016ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFCB18A62CD83284DULL,
		0xFDEF81445E89F34DULL,
		0xF34956DB1F7154CCULL,
		0x1B4230E636D57277ULL,
		0xF98E6DCB058C76DBULL,
		0x5B91296C8D1FA9D2ULL,
		0x72072CD98DCABEB1ULL,
		0x1A77D407B8F3C503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF96314C59B06509AULL,
		0xFBDF0288BD13E69BULL,
		0xE692ADB63EE2A999ULL,
		0x368461CC6DAAE4EFULL,
		0xF31CDB960B18EDB6ULL,
		0xB72252D91A3F53A5ULL,
		0xE40E59B31B957D62ULL,
		0x34EFA80F71E78A06ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B744BE51051822EULL,
		0x4024489BC1FD7F43ULL,
		0x2BCF662375FDE59CULL,
		0x79F4E6DAACF349A5ULL,
		0xB869DD905FEC5237ULL,
		0x4948BFD41CF7EA0CULL,
		0x945456A5EBBCDAC4ULL,
		0x01F7B57369E5D384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E897CA20A3045CULL,
		0x8048913783FAFE86ULL,
		0x579ECC46EBFBCB38ULL,
		0xF3E9CDB559E6934AULL,
		0x70D3BB20BFD8A46EULL,
		0x92917FA839EFD419ULL,
		0x28A8AD4BD779B588ULL,
		0x03EF6AE6D3CBA709ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA7BF3451A858E2DAULL,
		0x8987783A03988995ULL,
		0x139EDF22D6B10B44ULL,
		0x97538957913FC1FFULL,
		0x2E9912D1C0DBE49FULL,
		0xDDE9E604E8EDB3E0ULL,
		0x6E90DC9626DCDE65ULL,
		0x10A5777062B7C2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7E68A350B1C5B4ULL,
		0x130EF0740731132BULL,
		0x273DBE45AD621689ULL,
		0x2EA712AF227F83FEULL,
		0x5D3225A381B7C93FULL,
		0xBBD3CC09D1DB67C0ULL,
		0xDD21B92C4DB9BCCBULL,
		0x214AEEE0C56F8568ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C849CDBD86C5194ULL,
		0x84CCE3933E56D5DFULL,
		0x500F8B7621AF8291ULL,
		0x22A4E9DEC83FE3CAULL,
		0xA0FE2BDD1FDCFB7AULL,
		0x61E87AF9076C07E0ULL,
		0x482237A5BE193738ULL,
		0x37F85ADABBCD04C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390939B7B0D8A328ULL,
		0x0999C7267CADABBFULL,
		0xA01F16EC435F0523ULL,
		0x4549D3BD907FC794ULL,
		0x41FC57BA3FB9F6F4ULL,
		0xC3D0F5F20ED80FC1ULL,
		0x90446F4B7C326E70ULL,
		0x6FF0B5B5779A0984ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF2224E7A267BDEB3ULL,
		0x3169207654E0498BULL,
		0x4B8A4D7E220B4926ULL,
		0x1D2629994454FC49ULL,
		0x7F11F47C413FFA17ULL,
		0xC6C4D3E7EDEBB5A7ULL,
		0x0B80FC5B0E7BD0EDULL,
		0x1A3E4EF946421221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4449CF44CF7BD66ULL,
		0x62D240ECA9C09317ULL,
		0x97149AFC4416924CULL,
		0x3A4C533288A9F892ULL,
		0xFE23E8F8827FF42EULL,
		0x8D89A7CFDBD76B4EULL,
		0x1701F8B61CF7A1DBULL,
		0x347C9DF28C842442ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4E48251B396002EDULL,
		0x7851A3688A5485F1ULL,
		0x11C2E02266D04183ULL,
		0xE256B6C013D0CFB2ULL,
		0x1887D19365D10B54ULL,
		0x0AB37110EDAB9000ULL,
		0x6DF028847AAF7D22ULL,
		0x2CBAE65C016C7D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C904A3672C005DAULL,
		0xF0A346D114A90BE2ULL,
		0x2385C044CDA08306ULL,
		0xC4AD6D8027A19F64ULL,
		0x310FA326CBA216A9ULL,
		0x1566E221DB572000ULL,
		0xDBE05108F55EFA44ULL,
		0x5975CCB802D8FA82ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A99ED40A99DDDE4ULL,
		0x34DB9A4A2EA5C0A5ULL,
		0xB8C669B3011156DCULL,
		0xBBC6B77165626D1BULL,
		0x988A624F41E39784ULL,
		0xCAE53BE31F192894ULL,
		0x6141401B4FB6A215ULL,
		0x388B92120CB6AC88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1533DA81533BBBC8ULL,
		0x69B734945D4B814AULL,
		0x718CD3660222ADB8ULL,
		0x778D6EE2CAC4DA37ULL,
		0x3114C49E83C72F09ULL,
		0x95CA77C63E325129ULL,
		0xC28280369F6D442BULL,
		0x71172424196D5910ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7016C7818D4648C9ULL,
		0x8F4E18B37B30B4C3ULL,
		0x237056367FC151B2ULL,
		0xA283BF620C4F5EE6ULL,
		0x03ED40707C7505FDULL,
		0xFBE69F4CCCC5C8C3ULL,
		0xCE6C527ADAF1149CULL,
		0x0929BA52676523C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02D8F031A8C9192ULL,
		0x1E9C3166F6616986ULL,
		0x46E0AC6CFF82A365ULL,
		0x45077EC4189EBDCCULL,
		0x07DA80E0F8EA0BFBULL,
		0xF7CD3E99998B9186ULL,
		0x9CD8A4F5B5E22939ULL,
		0x125374A4CECA4789ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9B9733684D50EAEEULL,
		0xE967CB0753F1DDD6ULL,
		0xB9C59AD28DBF5182ULL,
		0xD8BC985CB2F36C0CULL,
		0x8E99B3AE62C49B26ULL,
		0x35F04C9FA3E4A48FULL,
		0x94255129E408A457ULL,
		0x2BDBB9F12DBACF40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x372E66D09AA1D5DCULL,
		0xD2CF960EA7E3BBADULL,
		0x738B35A51B7EA305ULL,
		0xB17930B965E6D819ULL,
		0x1D33675CC589364DULL,
		0x6BE0993F47C9491FULL,
		0x284AA253C81148AEULL,
		0x57B773E25B759E81ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x06C58FD233424D4BULL,
		0x7967B244216E8907ULL,
		0x9FA591AD19BA212CULL,
		0x7CBC2797A6CBC435ULL,
		0x9AC043D6684EB83CULL,
		0xEF9E7BAA203995A0ULL,
		0x83ECCDB8E0489D2DULL,
		0x25194C9CBA504D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D8B1FA466849A96ULL,
		0xF2CF648842DD120EULL,
		0x3F4B235A33744258ULL,
		0xF9784F2F4D97886BULL,
		0x358087ACD09D7078ULL,
		0xDF3CF75440732B41ULL,
		0x07D99B71C0913A5BULL,
		0x4A32993974A09A95ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4025FB39984C4B58ULL,
		0x2734F0289D030F02ULL,
		0xD3EEE8D10A3ACD55ULL,
		0xD98BDFA8A564C850ULL,
		0x9061C5D8A8935EE7ULL,
		0xB6C16E98FF485270ULL,
		0x20038A5FD9AE191BULL,
		0x0B921620DAF93669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x804BF673309896B0ULL,
		0x4E69E0513A061E04ULL,
		0xA7DDD1A214759AAAULL,
		0xB317BF514AC990A1ULL,
		0x20C38BB15126BDCFULL,
		0x6D82DD31FE90A4E1ULL,
		0x400714BFB35C3237ULL,
		0x17242C41B5F26CD2ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC1915CA92EB8B722ULL,
		0xB060F7E073C57FF5ULL,
		0x35BCA117B955759CULL,
		0x375318A95CC1707DULL,
		0x52AE4465E38326BDULL,
		0xF63F63870CF6F2C1ULL,
		0x345B9CE5C0893B66ULL,
		0x37631B8A89CE8E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8322B9525D716E44ULL,
		0x60C1EFC0E78AFFEBULL,
		0x6B79422F72AAEB39ULL,
		0x6EA63152B982E0FAULL,
		0xA55C88CBC7064D7AULL,
		0xEC7EC70E19EDE582ULL,
		0x68B739CB811276CDULL,
		0x6EC63715139D1CD2ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD79BD40B86C34DF4ULL,
		0xCC817A5CF00D381FULL,
		0xCCD5D15D5644BAF8ULL,
		0xC30D884E2FA74EE6ULL,
		0xBC3880E3CD1E6BC5ULL,
		0xE89AEDFAF499EFF9ULL,
		0xFA53AA2F2EDDBDD7ULL,
		0x3C15BC0F4B701BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF37A8170D869BE8ULL,
		0x9902F4B9E01A703FULL,
		0x99ABA2BAAC8975F1ULL,
		0x861B109C5F4E9DCDULL,
		0x787101C79A3CD78BULL,
		0xD135DBF5E933DFF3ULL,
		0xF4A7545E5DBB7BAFULL,
		0x782B781E96E037E3ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19FE256E32DF1303ULL,
		0x8F239B46A3BA2A74ULL,
		0x92522271787FDC94ULL,
		0x628DF91E007285FFULL,
		0x63C012292681672CULL,
		0x53E42137D1E9474FULL,
		0x7CD596B88E94529DULL,
		0x330B539D34696035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33FC4ADC65BE2606ULL,
		0x1E47368D477454E8ULL,
		0x24A444E2F0FFB929ULL,
		0xC51BF23C00E50BFFULL,
		0xC78024524D02CE58ULL,
		0xA7C8426FA3D28E9EULL,
		0xF9AB2D711D28A53AULL,
		0x6616A73A68D2C06AULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD8ACD3FA82F2A9D5ULL,
		0x9E310974AF087A53ULL,
		0xAC3C8FB5A93C1C98ULL,
		0x85278DC7D89948BFULL,
		0x7A88F81832D2178CULL,
		0x3B887ADCFA83C07AULL,
		0xAA98475C26CC6807ULL,
		0x255E309661195BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB159A7F505E553AAULL,
		0x3C6212E95E10F4A7ULL,
		0x58791F6B52783931ULL,
		0x0A4F1B8FB132917FULL,
		0xF511F03065A42F19ULL,
		0x7710F5B9F50780F4ULL,
		0x55308EB84D98D00EULL,
		0x4ABC612CC232B7D7ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x17A739B5D7EA80A7ULL,
		0x499703C49116BE16ULL,
		0xA35B904860118B4FULL,
		0x3A5CB39E49D8D11FULL,
		0x072A14D0B75D447BULL,
		0x40E7A8983A8D678FULL,
		0xD624B88EFEC12E32ULL,
		0x1C46B899FE9D73E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4E736BAFD5014EULL,
		0x932E0789222D7C2CULL,
		0x46B72090C023169EULL,
		0x74B9673C93B1A23FULL,
		0x0E5429A16EBA88F6ULL,
		0x81CF5130751ACF1EULL,
		0xAC49711DFD825C64ULL,
		0x388D7133FD3AE7C1ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20A585A5451BB123ULL,
		0x06099A59FCD590D5ULL,
		0x9158ED6DA8BD734FULL,
		0xE3F6D61AED1E6128ULL,
		0xCE98039A60DB778DULL,
		0xA576A518DC6F966BULL,
		0x05D1A92754A12DAAULL,
		0x15D7A59283B982E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x414B0B4A8A376246ULL,
		0x0C1334B3F9AB21AAULL,
		0x22B1DADB517AE69EULL,
		0xC7EDAC35DA3CC251ULL,
		0x9D300734C1B6EF1BULL,
		0x4AED4A31B8DF2CD7ULL,
		0x0BA3524EA9425B55ULL,
		0x2BAF4B25077305C8ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x291DD0825193F087ULL,
		0x533E5B3EF8F9FE72ULL,
		0x3AC8A19286FAFFB5ULL,
		0xC6516E708977030EULL,
		0x9571B9C696188BA5ULL,
		0xD5DC6F0D743A34BAULL,
		0x72726EA1245C77C9ULL,
		0x2BCC9FA49CDA7B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x523BA104A327E10EULL,
		0xA67CB67DF1F3FCE4ULL,
		0x759143250DF5FF6AULL,
		0x8CA2DCE112EE061CULL,
		0x2AE3738D2C31174BULL,
		0xABB8DE1AE8746975ULL,
		0xE4E4DD4248B8EF93ULL,
		0x57993F4939B4F640ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCA7AC3A703C258AULL,
		0x3141EAA339841CCCULL,
		0xB47E47C58585135CULL,
		0x83A978139395DB22ULL,
		0x5B6BA321121EBF83ULL,
		0x358762FBF601A6F9ULL,
		0xA66F669573FFE41CULL,
		0x10DE01E37CA99097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x794F5874E0784B14ULL,
		0x6283D54673083999ULL,
		0x68FC8F8B0B0A26B8ULL,
		0x0752F027272BB645ULL,
		0xB6D74642243D7F07ULL,
		0x6B0EC5F7EC034DF2ULL,
		0x4CDECD2AE7FFC838ULL,
		0x21BC03C6F953212FULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1DAE8BD8DE859690ULL,
		0x1193AC567341745EULL,
		0xAA985A2C0483CC75ULL,
		0x543457FE39C45BF2ULL,
		0x41CC689759268012ULL,
		0xD3497A2FB8DCACA0ULL,
		0xF46071CBEC383FA6ULL,
		0x28422724AA860562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5D17B1BD0B2D20ULL,
		0x232758ACE682E8BCULL,
		0x5530B458090798EAULL,
		0xA868AFFC7388B7E5ULL,
		0x8398D12EB24D0024ULL,
		0xA692F45F71B95940ULL,
		0xE8C0E397D8707F4DULL,
		0x50844E49550C0AC5ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2B4BEAC61B04F2B5ULL,
		0x03B081564DDD827FULL,
		0xB68D3ABBA1974D0BULL,
		0xE253D221DBFF9CBDULL,
		0x9CA9ACC9F7EA8FCAULL,
		0xD0F1FC96789DE6D7ULL,
		0x265BF8B41099989EULL,
		0x0EBFFB03E2563209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5697D58C3609E56AULL,
		0x076102AC9BBB04FEULL,
		0x6D1A7577432E9A16ULL,
		0xC4A7A443B7FF397BULL,
		0x39535993EFD51F95ULL,
		0xA1E3F92CF13BCDAFULL,
		0x4CB7F1682133313DULL,
		0x1D7FF607C4AC6412ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF39AA21F5B305AEULL,
		0x11C22016C51B42BDULL,
		0x0BDB1D23C3C4A5CCULL,
		0xB81C3D13ED15853CULL,
		0x019AA55A687BD304ULL,
		0xE411C18436C1179AULL,
		0xAC554A42BC87A3BDULL,
		0x057FB3BCF20E8E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE735443EB660B5CULL,
		0x2384402D8A36857BULL,
		0x17B63A4787894B98ULL,
		0x70387A27DA2B0A78ULL,
		0x03354AB4D0F7A609ULL,
		0xC82383086D822F34ULL,
		0x58AA9485790F477BULL,
		0x0AFF6779E41D1CE1ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC4A49C667BDF2A19ULL,
		0x2DF37370127F527EULL,
		0x86C6EFE269EB4E81ULL,
		0xCB07A3876837762CULL,
		0xD154673391AA9EA5ULL,
		0xA6341FA2053590DBULL,
		0x88EC9007EF1FC6ECULL,
		0x31E032BCE5242DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x894938CCF7BE5432ULL,
		0x5BE6E6E024FEA4FDULL,
		0x0D8DDFC4D3D69D02ULL,
		0x960F470ED06EEC59ULL,
		0xA2A8CE6723553D4BULL,
		0x4C683F440A6B21B7ULL,
		0x11D9200FDE3F8DD9ULL,
		0x63C06579CA485BD5ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF5812BFF483E1F0ULL,
		0x0121DB863F7955BDULL,
		0xAF0DE9282C9106D2ULL,
		0xAC9D71334A767AE4ULL,
		0x358DB8748FFC1EFAULL,
		0x1B023319BB8F6B88ULL,
		0x2A68988BBFD92929ULL,
		0x291BF805AB0BAD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEB0257FE907C3E0ULL,
		0x0243B70C7EF2AB7BULL,
		0x5E1BD25059220DA4ULL,
		0x593AE26694ECF5C9ULL,
		0x6B1B70E91FF83DF5ULL,
		0x36046633771ED710ULL,
		0x54D131177FB25252ULL,
		0x5237F00B56175A7AULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x888A6BBB031267B8ULL,
		0xC751F8FE7F587584ULL,
		0x2B14A994A74FDFADULL,
		0x8A532734EAFBF3F4ULL,
		0x1520DF0F0EF60EECULL,
		0xF098F48DF55E805FULL,
		0x700739F62F4EEE8CULL,
		0x30A57A6B37BD9D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1114D7760624CF70ULL,
		0x8EA3F1FCFEB0EB09ULL,
		0x562953294E9FBF5BULL,
		0x14A64E69D5F7E7E8ULL,
		0x2A41BE1E1DEC1DD9ULL,
		0xE131E91BEABD00BEULL,
		0xE00E73EC5E9DDD19ULL,
		0x614AF4D66F7B3A62ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x994FBB6E660932A7ULL,
		0x6B8439716976865CULL,
		0x5413C6EA7F686833ULL,
		0xFDBCEBC051A9F1D2ULL,
		0x1A3015C0F1194571ULL,
		0xC925B1A4A2CA9D07ULL,
		0x8DDD219A3163BAACULL,
		0x1E5A86607474A4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329F76DCCC12654EULL,
		0xD70872E2D2ED0CB9ULL,
		0xA8278DD4FED0D066ULL,
		0xFB79D780A353E3A4ULL,
		0x34602B81E2328AE3ULL,
		0x924B634945953A0EULL,
		0x1BBA433462C77559ULL,
		0x3CB50CC0E8E949C5ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE7A5800E11C45732ULL,
		0x4D920040E9142BB5ULL,
		0x4C216BBE2ED60EE2ULL,
		0xE04D539BEC2B0FFBULL,
		0xBFAB552DFA44446BULL,
		0x617F2E5A445B2EFEULL,
		0x7AC63EB1D11939DAULL,
		0x2D043216ACAD1C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4B001C2388AE64ULL,
		0x9B240081D228576BULL,
		0x9842D77C5DAC1DC4ULL,
		0xC09AA737D8561FF6ULL,
		0x7F56AA5BF48888D7ULL,
		0xC2FE5CB488B65DFDULL,
		0xF58C7D63A23273B4ULL,
		0x5A08642D595A3876ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x32B374D03916FBB0ULL,
		0x1018C32B219CEFBAULL,
		0x81CEDA076DCD37C5ULL,
		0xDAA8FF4A58178234ULL,
		0xD8049DF0E85755B7ULL,
		0x5FAC4D823AAE2569ULL,
		0x14F72B6FEE6A62F6ULL,
		0x3813E0A81869EE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6566E9A0722DF760ULL,
		0x203186564339DF74ULL,
		0x039DB40EDB9A6F8AULL,
		0xB551FE94B02F0469ULL,
		0xB0093BE1D0AEAB6FULL,
		0xBF589B04755C4AD3ULL,
		0x29EE56DFDCD4C5ECULL,
		0x7027C15030D3DCF0ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x67CE35BB71F3D8C7ULL,
		0x357073B6443776DEULL,
		0x6ADFF915E102FD0EULL,
		0x40D065348AF04489ULL,
		0x26E48D8D66AA634AULL,
		0x99B5FF1A09C834EEULL,
		0x8F2801E2FF1618A5ULL,
		0x2ADFB0F3B0999505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9C6B76E3E7B18EULL,
		0x6AE0E76C886EEDBCULL,
		0xD5BFF22BC205FA1CULL,
		0x81A0CA6915E08912ULL,
		0x4DC91B1ACD54C694ULL,
		0x336BFE34139069DCULL,
		0x1E5003C5FE2C314BULL,
		0x55BF61E761332A0BULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9A2817DC09ABB87BULL,
		0xE27653E6C4D55C49ULL,
		0x50A6B0216FC599ABULL,
		0x589E0CA8DBC13052ULL,
		0xA0899E2AFA3D9777ULL,
		0xAA5FFB648A44651AULL,
		0x37407FDAF6B0A143ULL,
		0x2FDE9DB663CCA2C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34502FB8135770F6ULL,
		0xC4ECA7CD89AAB893ULL,
		0xA14D6042DF8B3357ULL,
		0xB13C1951B78260A4ULL,
		0x41133C55F47B2EEEULL,
		0x54BFF6C91488CA35ULL,
		0x6E80FFB5ED614287ULL,
		0x5FBD3B6CC799458CULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x51F699AB6C75E204ULL,
		0xD15EDFE9789B0FD9ULL,
		0x411200B6463EDF0CULL,
		0x8F1A0ADF292BF4B0ULL,
		0xC60695426587BB75ULL,
		0xEC3A8D2B0AD30E89ULL,
		0x95C79421D8BAF39CULL,
		0x0B653B048B189AF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3ED3356D8EBC408ULL,
		0xA2BDBFD2F1361FB2ULL,
		0x8224016C8C7DBE19ULL,
		0x1E3415BE5257E960ULL,
		0x8C0D2A84CB0F76EBULL,
		0xD8751A5615A61D13ULL,
		0x2B8F2843B175E739ULL,
		0x16CA7609163135E7ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0FAA50F6F3605254ULL,
		0x9FCE1D3BBE03E411ULL,
		0x8D30726BCE80F91CULL,
		0x011F430F951EEA49ULL,
		0xEE16E337802F0901ULL,
		0x13460DD2011F1FA3ULL,
		0xF40279050499F189ULL,
		0x028ACF4AE8137045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F54A1EDE6C0A4A8ULL,
		0x3F9C3A777C07C822ULL,
		0x1A60E4D79D01F239ULL,
		0x023E861F2A3DD493ULL,
		0xDC2DC66F005E1202ULL,
		0x268C1BA4023E3F47ULL,
		0xE804F20A0933E312ULL,
		0x05159E95D026E08BULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x827503AEEEB33C36ULL,
		0x30457070B1A86322ULL,
		0xF3E9E7FE9A03DB42ULL,
		0x0C3675EC8214FAE6ULL,
		0x477A85F16EAFE496ULL,
		0xF92EDD341227437DULL,
		0x0308B0CF684995F0ULL,
		0x33624B4C8A251404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04EA075DDD66786CULL,
		0x608AE0E16350C645ULL,
		0xE7D3CFFD3407B684ULL,
		0x186CEBD90429F5CDULL,
		0x8EF50BE2DD5FC92CULL,
		0xF25DBA68244E86FAULL,
		0x0611619ED0932BE1ULL,
		0x66C49699144A2808ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0F7D7BAC0CFFF192ULL,
		0x73F4B98357F25599ULL,
		0x02D6D81F77D24DCBULL,
		0x9A9589299DDB7389ULL,
		0xC1C2CC0124791994ULL,
		0xF0E7A65FBBDB8FC5ULL,
		0x77B4A567D20F99CDULL,
		0x3C852763DF8139D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EFAF75819FFE324ULL,
		0xE7E97306AFE4AB32ULL,
		0x05ADB03EEFA49B96ULL,
		0x352B12533BB6E712ULL,
		0x8385980248F23329ULL,
		0xE1CF4CBF77B71F8BULL,
		0xEF694ACFA41F339BULL,
		0x790A4EC7BF0273A6ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEB48F1B3A283175CULL,
		0x073A6EB4E53BEE4AULL,
		0x53EEDBA126A89916ULL,
		0xA2F52495301E9F8AULL,
		0x4B41B900210CED7FULL,
		0xC751713BBE27B7A8ULL,
		0x544602930E57439EULL,
		0x2F4DDB1C72EB1D5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD691E36745062EB8ULL,
		0x0E74DD69CA77DC95ULL,
		0xA7DDB7424D51322CULL,
		0x45EA492A603D3F14ULL,
		0x968372004219DAFFULL,
		0x8EA2E2777C4F6F50ULL,
		0xA88C05261CAE873DULL,
		0x5E9BB638E5D63AB8ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC9888720DC545BA9ULL,
		0xE57454042277F236ULL,
		0xA2953C223B026564ULL,
		0xFC595D955CB77C1FULL,
		0xC3FB07D90D42E724ULL,
		0xD985F3CFE2A681A7ULL,
		0x9A197052F8E61D62ULL,
		0x1A09334C57AEFBE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93110E41B8A8B752ULL,
		0xCAE8A80844EFE46DULL,
		0x452A78447604CAC9ULL,
		0xF8B2BB2AB96EF83FULL,
		0x87F60FB21A85CE49ULL,
		0xB30BE79FC54D034FULL,
		0x3432E0A5F1CC3AC5ULL,
		0x34126698AF5DF7D3ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB8373067A1DBB8AAULL,
		0x92C12025F8853052ULL,
		0x88B7589552A87F07ULL,
		0x3DBFA473EEDEB2D7ULL,
		0x0BADCA574BA68293ULL,
		0xDAA6F7FC238A540FULL,
		0xB681A615A8F00CA8ULL,
		0x0AB4611EF5468C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x706E60CF43B77154ULL,
		0x2582404BF10A60A5ULL,
		0x116EB12AA550FE0FULL,
		0x7B7F48E7DDBD65AFULL,
		0x175B94AE974D0526ULL,
		0xB54DEFF84714A81EULL,
		0x6D034C2B51E01951ULL,
		0x1568C23DEA8D185DULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C3AD4C1FAAF16A0ULL,
		0x6F8AE450DACAC9B6ULL,
		0xF6D7D0E6E53FEB30ULL,
		0xB61C55002FA7EE72ULL,
		0xD135888526B921C7ULL,
		0x2C375059D41C5FC5ULL,
		0x1B8C0F80CEA6FF44ULL,
		0x35187EEDFF6F9E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF875A983F55E2D40ULL,
		0xDF15C8A1B595936CULL,
		0xEDAFA1CDCA7FD660ULL,
		0x6C38AA005F4FDCE5ULL,
		0xA26B110A4D72438FULL,
		0x586EA0B3A838BF8BULL,
		0x37181F019D4DFE88ULL,
		0x6A30FDDBFEDF3C14ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x03AAC02845202646ULL,
		0xFFCAE82F135EA644ULL,
		0x8F1E05C70367666AULL,
		0x263E6F71A723BC13ULL,
		0x28EC65CCD3DFB83BULL,
		0x75D7498BCB3DA05DULL,
		0x58001285D9A08D2FULL,
		0x1B4706B3FE9A676FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x075580508A404C8CULL,
		0xFF95D05E26BD4C88ULL,
		0x1E3C0B8E06CECCD5ULL,
		0x4C7CDEE34E477827ULL,
		0x51D8CB99A7BF7076ULL,
		0xEBAE9317967B40BAULL,
		0xB000250BB3411A5EULL,
		0x368E0D67FD34CEDEULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x99A85D03293EA49FULL,
		0x733A0F2ADF0AC95DULL,
		0xFEE1B991D07EE92FULL,
		0x2F15FEB9867FC1DDULL,
		0xF936CEB630E34B4BULL,
		0x9E3E4099AE4600FAULL,
		0x28C3F29327B7968DULL,
		0x04AE2A238AD7E965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3350BA06527D493EULL,
		0xE6741E55BE1592BBULL,
		0xFDC37323A0FDD25EULL,
		0x5E2BFD730CFF83BBULL,
		0xF26D9D6C61C69696ULL,
		0x3C7C81335C8C01F5ULL,
		0x5187E5264F6F2D1BULL,
		0x095C544715AFD2CAULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x739D4F864EECAA83ULL,
		0x7D60A8AA1D160854ULL,
		0x9E4E5626D873D8DAULL,
		0xBB017871ED335DFBULL,
		0x346176782D55EAA6ULL,
		0xAD65DC3F11258DCBULL,
		0x89B6A43B8AAD0DB4ULL,
		0x286869765CFB92EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE73A9F0C9DD95506ULL,
		0xFAC151543A2C10A8ULL,
		0x3C9CAC4DB0E7B1B4ULL,
		0x7602F0E3DA66BBF7ULL,
		0x68C2ECF05AABD54DULL,
		0x5ACBB87E224B1B96ULL,
		0x136D4877155A1B69ULL,
		0x50D0D2ECB9F725DFULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x42171FEC18E6C566ULL,
		0x0674531C291576F5ULL,
		0xB818824A29709BCBULL,
		0xE0AF23C0D27B2532ULL,
		0x05270555BFDD24F8ULL,
		0xC47541D6E7BE9079ULL,
		0x1A53E41A9B38A226ULL,
		0x00AEBFA3C4CDF4A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842E3FD831CD8ACCULL,
		0x0CE8A638522AEDEAULL,
		0x7031049452E13796ULL,
		0xC15E4781A4F64A65ULL,
		0x0A4E0AAB7FBA49F1ULL,
		0x88EA83ADCF7D20F2ULL,
		0x34A7C8353671444DULL,
		0x015D7F47899BE950ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0CB096EB69E31557ULL,
		0xBEF212FAF729CE2AULL,
		0x09B9DC1FA37EB66DULL,
		0x33FFB6B7EBD09C2CULL,
		0xDB1A7F2ED358AE05ULL,
		0x29D9D14994CBB4FAULL,
		0x34A757A4F954E1F7ULL,
		0x33E0A595E37B4BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19612DD6D3C62AAEULL,
		0x7DE425F5EE539C54ULL,
		0x1373B83F46FD6CDBULL,
		0x67FF6D6FD7A13858ULL,
		0xB634FE5DA6B15C0AULL,
		0x53B3A293299769F5ULL,
		0x694EAF49F2A9C3EEULL,
		0x67C14B2BC6F69742ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x499789DF4A4AE00AULL,
		0x4298B62CEBC94CF5ULL,
		0xC1C87EA0D9424DC8ULL,
		0x247BBF21BE5B6785ULL,
		0x61BBCCE287281C1EULL,
		0xD1E408F8821E8BEAULL,
		0x7356C38F118814BEULL,
		0x2ACBEF4FFB170BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x932F13BE9495C014ULL,
		0x85316C59D79299EAULL,
		0x8390FD41B2849B90ULL,
		0x48F77E437CB6CF0BULL,
		0xC37799C50E50383CULL,
		0xA3C811F1043D17D4ULL,
		0xE6AD871E2310297DULL,
		0x5597DE9FF62E17B4ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6F587E18E3D384B3ULL,
		0xA2C5053AB175F6E6ULL,
		0x5C0832DEE174066BULL,
		0xDA49AC48405D5C8AULL,
		0x4583B7E6940267E2ULL,
		0x36605E08DF711F52ULL,
		0xA5335F7C93CAE5CDULL,
		0x184919BE54970965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB0FC31C7A70966ULL,
		0x458A0A7562EBEDCCULL,
		0xB81065BDC2E80CD7ULL,
		0xB493589080BAB914ULL,
		0x8B076FCD2804CFC5ULL,
		0x6CC0BC11BEE23EA4ULL,
		0x4A66BEF92795CB9AULL,
		0x3092337CA92E12CBULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x53EEDD0171C82351ULL,
		0xC853069D70C3B8B0ULL,
		0xCA72F3EC622908D7ULL,
		0x43E464BB5A20D5C9ULL,
		0x454BC83CA263B780ULL,
		0x6FFFC3409B23B5ADULL,
		0x4350C4EB6A638B86ULL,
		0x11C0D97A9926F2E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DDBA02E39046A2ULL,
		0x90A60D3AE1877160ULL,
		0x94E5E7D8C45211AFULL,
		0x87C8C976B441AB93ULL,
		0x8A97907944C76F00ULL,
		0xDFFF868136476B5AULL,
		0x86A189D6D4C7170CULL,
		0x2381B2F5324DE5C4ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
}