#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0x9839077CB3B27CB3ULL,
		0xBF4F74B6DC57C185ULL,
		0xA31BCC9247B65D3AULL,
		0x4AD021C834A24A36ULL,
		0x62ADE10F5AB7383BULL,
		0xB5CA9324704C92ACULL,
		0x7253AF1432E67F62ULL,
		0x4E8DC87D509A116AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE1790364B71F671CULL,
		0x84613580812018F8ULL,
		0xC12608C4F1905F7EULL,
		0x78D031844C0D2874ULL,
		0x42E2A723CC970E7CULL,
		0x95918DF5858E72C2ULL,
		0xD1009BE6707FDAC3ULL,
		0xF30CD7F38F4D1677ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xB6C00417FC931597ULL,
		0x3AEE3F365B37A88CULL,
		0xE1F5C3CD5625FDBCULL,
		0xD1FFF043E89521C1ULL,
		0x1FCB39EB8E2029BEULL,
		0x2039052EEABE1FEAULL,
		0xA153132DC266A49FULL,
		0x5B80F089C14CFAF2ULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8BBA4D6A57AFD40ULL,
		0x4D8477046FB5EF22ULL,
		0x1A15ECBF81A94B50ULL,
		0x4182E6B681997046ULL,
		0x19496306EE9A20F8ULL,
		0xCE3E4886D1551948ULL,
		0xC855869F511954BEULL,
		0x3664A8982EACDAEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0E768F65590637ULL,
		0xFC66668DA4D13094ULL,
		0x39B3EC2BB41E03DDULL,
		0x0B43E5A4DBE0263AULL,
		0xA9FA132F324BFAEFULL,
		0x32E54602BD8F7559ULL,
		0x2A988EFB4035BE73ULL,
		0x18E98A09C701304FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DAD2E474021F709ULL,
		0x511E1076CAE4BE8EULL,
		0xE0620093CD8B4772ULL,
		0x363F0111A5B94A0BULL,
		0x6F4F4FD7BC4E2609ULL,
		0x9B59028413C5A3EEULL,
		0x9DBCF7A410E3964BULL,
		0x1D7B1E8E67ABAAA0ULL
	}};
	sign = 0;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x198840F65650F19CULL,
		0x25BCCB8513EB4667ULL,
		0x7174993DAD179529ULL,
		0xB6D19D3C90C0761DULL,
		0x10007DB3DCCBD2D7ULL,
		0xE25EFF328FEB9322ULL,
		0xF4E26B851E4FA074ULL,
		0xC9877B9C6B7110E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33906AC6736AF7FCULL,
		0xA9CC5ED5C1062259ULL,
		0x43BD40C5B579D491ULL,
		0x3AC5D1BE5CFD9788ULL,
		0xED84674F5555BB3DULL,
		0x110459ECEA30552DULL,
		0xB537E567A6C6EBACULL,
		0x9DFBEB90FAAA85C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5F7D62FE2E5F9A0ULL,
		0x7BF06CAF52E5240DULL,
		0x2DB75877F79DC097ULL,
		0x7C0BCB7E33C2DE95ULL,
		0x227C16648776179AULL,
		0xD15AA545A5BB3DF4ULL,
		0x3FAA861D7788B4C8ULL,
		0x2B8B900B70C68B1DULL
	}};
	sign = 0;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BE4E8EDF7EA4BE4ULL,
		0x051EB46AAE665EA9ULL,
		0x32918AF5D9AD97BBULL,
		0x8E016DAE2BE39CC8ULL,
		0x2CB0632935FCD9CFULL,
		0xA44918B8609F53C6ULL,
		0x654CF895FF5120E5ULL,
		0x88B078E7B8ABB32FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD845248E8FA8431EULL,
		0xA03EB6D8386A09BAULL,
		0xFE57217027ADDCF3ULL,
		0xA6846DEDB30C19BEULL,
		0x66A5EB7644D1A0BAULL,
		0x111F850162AABD02ULL,
		0xA5E0FEDE4E443301ULL,
		0x87F0F141E0253F5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC39FC45F684208C6ULL,
		0x64DFFD9275FC54EEULL,
		0x343A6985B1FFBAC7ULL,
		0xE77CFFC078D78309ULL,
		0xC60A77B2F12B3914ULL,
		0x932993B6FDF496C3ULL,
		0xBF6BF9B7B10CEDE4ULL,
		0x00BF87A5D88673CFULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE43B4C18816471DULL,
		0xEBF96B538A3764ECULL,
		0x83E27C366DFC6906ULL,
		0xBEF8EF41D3BADA4DULL,
		0x6FDC683FC3929788ULL,
		0x3113B4A0128F0F7BULL,
		0xF7F3FEA3184E7D8BULL,
		0x703740A7546470F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F24A9CD0EA2432ULL,
		0xE3A2BCF1EB5394CBULL,
		0x8B09A1CD27B32663ULL,
		0xA1FF376207BA5C26ULL,
		0x8DE397B6FFF4A4FCULL,
		0xD1C417266ECFAEA4ULL,
		0x1B52B9AC9CE7BAA4ULL,
		0x928599B141B4498DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4516A24B72C22EBULL,
		0x0856AE619EE3D021ULL,
		0xF8D8DA69464942A3ULL,
		0x1CF9B7DFCC007E26ULL,
		0xE1F8D088C39DF28CULL,
		0x5F4F9D79A3BF60D6ULL,
		0xDCA144F67B66C2E6ULL,
		0xDDB1A6F612B02766ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73E1EFEA99856C85ULL,
		0x972B82180BFE6B0CULL,
		0x8135C66B81903ED3ULL,
		0xB67B9BBA04048410ULL,
		0xA36B61D7B661DF39ULL,
		0x82B96928A64EC9CBULL,
		0xD0CACA69E0185C81ULL,
		0x5ED55EFD804A4D5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB44FA942CFBEF85ULL,
		0xC5B8D4224F5B3385ULL,
		0x51227850BEA4944BULL,
		0xC6B99BF9D8614624ULL,
		0x9B59266706DFE81AULL,
		0xE5B1D63D8643FA20ULL,
		0x6F6E0FF0CAC7018CULL,
		0xB86692D0354E06DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA89CF5566C897D00ULL,
		0xD172ADF5BCA33786ULL,
		0x30134E1AC2EBAA87ULL,
		0xEFC1FFC02BA33DECULL,
		0x08123B70AF81F71EULL,
		0x9D0792EB200ACFABULL,
		0x615CBA7915515AF4ULL,
		0xA66ECC2D4AFC4681ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD07D1298B56A70AFULL,
		0x6262C399CEC2EBA1ULL,
		0x3B88A758991ECA3CULL,
		0xD59F8D9BD2943201ULL,
		0x6BFDDCA66D28DA83ULL,
		0x6E5590182F4A57BBULL,
		0xB0E3B61190B12C35ULL,
		0x54219E52938DCF9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54AF2CF5B6EBCD13ULL,
		0x4466B9DC33D3228CULL,
		0x568005729F287297ULL,
		0xDC9A64D0FED1BE8CULL,
		0x9C2645D3E22A3AFAULL,
		0x386542008C9AC4ACULL,
		0xFB663CCDDE32830AULL,
		0x3010C01015146293ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BCDE5A2FE7EA39CULL,
		0x1DFC09BD9AEFC915ULL,
		0xE508A1E5F9F657A5ULL,
		0xF90528CAD3C27374ULL,
		0xCFD796D28AFE9F88ULL,
		0x35F04E17A2AF930EULL,
		0xB57D7943B27EA92BULL,
		0x2410DE427E796D0BULL
	}};
	sign = 0;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D66EF0990593F9EULL,
		0x84035337338C062AULL,
		0xCF32D7FFF8CBEDAFULL,
		0x6DD1E3F1EF41202CULL,
		0xAC389BE421C9A67AULL,
		0x9D7D79DDF83CA2ACULL,
		0x4AD99382F4DB4F0BULL,
		0x758A8DA67A71B4BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FEAA3C04062A08ULL,
		0x1F7E708AE3CA2D12ULL,
		0x23DCA10D4A8EEF78ULL,
		0x557575D6C202597EULL,
		0xE149A3234952B6A3ULL,
		0x3AA8EC44EDAAD359ULL,
		0x74774AA0ADE2DCCEULL,
		0x4BEEA74607591201ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA66844CD8C531596ULL,
		0x6484E2AC4FC1D917ULL,
		0xAB5636F2AE3CFE37ULL,
		0x185C6E1B2D3EC6AEULL,
		0xCAEEF8C0D876EFD7ULL,
		0x62D48D990A91CF52ULL,
		0xD66248E246F8723DULL,
		0x299BE6607318A2B8ULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x639AC5BDA8F71E8BULL,
		0xC9203AED60A8BFC0ULL,
		0xBD41ABA6147C6414ULL,
		0x27E2AC140BBA3FEAULL,
		0xB99E445C5AC47980ULL,
		0xA8C256E1CC59A20AULL,
		0x4ADFE9168ABCBA9FULL,
		0xF515EAD89D3538DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA809132317E1EF1DULL,
		0xDD248D4972A410C6ULL,
		0x3A6283E01D482AC7ULL,
		0x40C54472EC10D3B5ULL,
		0xE0FAB3B592A8ACF7ULL,
		0x9321667AF303FCF6ULL,
		0x53264CAE85BDB976ULL,
		0xDE2D98FD84B04389ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB91B29A91152F6EULL,
		0xEBFBADA3EE04AEF9ULL,
		0x82DF27C5F734394CULL,
		0xE71D67A11FA96C35ULL,
		0xD8A390A6C81BCC88ULL,
		0x15A0F066D955A513ULL,
		0xF7B99C6804FF0129ULL,
		0x16E851DB1884F551ULL
	}};
	sign = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC36D19531EDEC5ULL,
		0x4D81261B2D442AA2ULL,
		0xFD17EE3442977F7AULL,
		0x1269B8D741509F4CULL,
		0x62862588E218C0E6ULL,
		0x54CA2B57B9268348ULL,
		0x6683E500BD7B8B05ULL,
		0xCDF21F705907E7A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408C2E9D9E087A8AULL,
		0x99FE77894DAB24CBULL,
		0xBE635B1135A52580ULL,
		0xD6999FC89E64A447ULL,
		0x4E4086D597ED3638ULL,
		0x661B5216E9E0D9C0ULL,
		0x2D98D7135C50719DULL,
		0x557F8F909F8B4D5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B373E7BB516643BULL,
		0xB382AE91DF9905D7ULL,
		0x3EB493230CF259F9ULL,
		0x3BD0190EA2EBFB05ULL,
		0x14459EB34A2B8AADULL,
		0xEEAED940CF45A988ULL,
		0x38EB0DED612B1967ULL,
		0x78728FDFB97C9A4CULL
	}};
	sign = 0;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D06688AFBF7F81CULL,
		0x881014B7ADD71FCDULL,
		0x2FD69BAE74C3A510ULL,
		0x7CA917F61D6485DAULL,
		0xFB2968930897FF1AULL,
		0xC49ADE76060CAFF4ULL,
		0xB2285BA9E396E98CULL,
		0xF62BB5588A70FAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A25D0ED9652037ULL,
		0xC7526D3EAC508612ULL,
		0xACFCD285B97CB2ABULL,
		0x0B8B1B925C0BA8E1ULL,
		0xC6A60612B45D88B7ULL,
		0x1876222FC1B6BF6BULL,
		0xACEFD8C2FC691BBAULL,
		0xF240003CF98C4331ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA640B7C2292D7E5ULL,
		0xC0BDA779018699BAULL,
		0x82D9C928BB46F264ULL,
		0x711DFC63C158DCF8ULL,
		0x34836280543A7663ULL,
		0xAC24BC464455F089ULL,
		0x053882E6E72DCDD2ULL,
		0x03EBB51B90E4B7C0ULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AD0141C2833E4D6ULL,
		0x96982AF9ED6140F6ULL,
		0xC16872ACB35E5EB8ULL,
		0x5F24F184CD314A76ULL,
		0x3F04C077E61EF486ULL,
		0x375C02F1DF970217ULL,
		0x1CBE420C1B9BC9FEULL,
		0x3EAB11C098CE5193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A66993F72CFC8ADULL,
		0xA5ABF496583BEC13ULL,
		0xA5A84873A0127687ULL,
		0x6C64AA46219C458FULL,
		0x43D543507B8D25E9ULL,
		0x0811A30FBD6B472CULL,
		0x144B8D11EEEF98EFULL,
		0xDA9CDC4CFA659D85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0697ADCB5641C29ULL,
		0xF0EC3663952554E2ULL,
		0x1BC02A39134BE830ULL,
		0xF2C0473EAB9504E7ULL,
		0xFB2F7D276A91CE9CULL,
		0x2F4A5FE2222BBAEAULL,
		0x0872B4FA2CAC310FULL,
		0x640E35739E68B40EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C249E9565A0DCF8ULL,
		0x2EAE114F63FE77BEULL,
		0x89C7F9E18C364C17ULL,
		0x2D05D38AD0EB4DF0ULL,
		0xC3198048E6294CEAULL,
		0x2DF38C543B79DE64ULL,
		0x27024CDA60AB7420ULL,
		0xE47A320026638D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A590F1683F3C66FULL,
		0xF62E206A86A3174EULL,
		0x2F750C4518B3BEB4ULL,
		0x2CB9D233A4AC72B1ULL,
		0x4235E60C320831D6ULL,
		0xF734DDC086CBCCF3ULL,
		0x7DCB4CBD5742B91DULL,
		0x6BCD229006BEB66EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1CB8F7EE1AD1689ULL,
		0x387FF0E4DD5B606FULL,
		0x5A52ED9C73828D62ULL,
		0x004C01572C3EDB3FULL,
		0x80E39A3CB4211B14ULL,
		0x36BEAE93B4AE1171ULL,
		0xA937001D0968BB02ULL,
		0x78AD0F701FA4D72AULL
	}};
	sign = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC2F4FBE3417AE5AULL,
		0x254C15B6A5B28743ULL,
		0x535BF91F1564A667ULL,
		0x626307D592F23F59ULL,
		0x4DA710B9B70E2EFFULL,
		0x3F4CB3BCC140A846ULL,
		0xF71203651FE4C328ULL,
		0xE3FC62A5EA561819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF313D36FF7B752ULL,
		0x54F9DB312094CBE9ULL,
		0xED54336BAD6C51FFULL,
		0x3AE5C5184E972F81ULL,
		0x7F1F680096E587E0ULL,
		0xADEC52A423AE032CULL,
		0x6577BF29262FD295ULL,
		0xE018004844213C83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE3C3BEAC41FF708ULL,
		0xD0523A85851DBB59ULL,
		0x6607C5B367F85467ULL,
		0x277D42BD445B0FD7ULL,
		0xCE87A8B92028A71FULL,
		0x916061189D92A519ULL,
		0x919A443BF9B4F092ULL,
		0x03E4625DA634DB96ULL
	}};
	sign = 0;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49C35DAF3AA1AF2DULL,
		0x2BB02422B238FD63ULL,
		0x8E66C2F31D2D3876ULL,
		0xDC59E81892BE7AD2ULL,
		0x3FC5E132900227B6ULL,
		0xC4195BCED5C18390ULL,
		0xA813A41C3D840E3DULL,
		0x8CB6EF5290B6CFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B3B94FCAE978A8ULL,
		0x6F8C172805F202F4ULL,
		0x481CBBA03125E9B2ULL,
		0xFBB2FB473DA61FF5ULL,
		0xD6E7C0B594203C5EULL,
		0x29352D9C0A48E1E2ULL,
		0xCC05D8D710B931F9ULL,
		0x8A25B64EA3240581ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x810FA45F6FB83685ULL,
		0xBC240CFAAC46FA6EULL,
		0x464A0752EC074EC3ULL,
		0xE0A6ECD155185ADDULL,
		0x68DE207CFBE1EB57ULL,
		0x9AE42E32CB78A1ADULL,
		0xDC0DCB452CCADC44ULL,
		0x02913903ED92CA61ULL
	}};
	sign = 0;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B5B71B51CB6E28AULL,
		0x00E91EAC3098D8D5ULL,
		0xE07A32A36DC1564CULL,
		0xEFBED1C7CF76FDCAULL,
		0xA4B015DCDDF4A464ULL,
		0xDF4E52CE34FAB9DCULL,
		0x97142B812401FB29ULL,
		0xA7B3D1C22394C7EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06EE5A09ED67962ULL,
		0x31EB64B0C75F96E8ULL,
		0xEEBCADBC35E16A64ULL,
		0x475F1F5C764A97F2ULL,
		0xF18DC48EB48CF34FULL,
		0xEF91B74C0653509CULL,
		0xBAB051FD6545D5CCULL,
		0x054E5FACF553FE2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AEC8C147DE06928ULL,
		0xCEFDB9FB693941ECULL,
		0xF1BD84E737DFEBE7ULL,
		0xA85FB26B592C65D7ULL,
		0xB322514E2967B115ULL,
		0xEFBC9B822EA7693FULL,
		0xDC63D983BEBC255CULL,
		0xA26572152E40C9C0ULL
	}};
	sign = 0;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x419504807B11EF8CULL,
		0x5E0D556728551E4EULL,
		0x0C9EAA5B79E16415ULL,
		0xD94D420CB2A2D924ULL,
		0xAD0283347169AA10ULL,
		0xF95C3441C108CEFBULL,
		0xF8163362C1DB4CD2ULL,
		0x9AC2BDBE6BEDAB46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6739422DAA3D05ULL,
		0xF7346AECF4FB33D0ULL,
		0xFD6D456B587E866EULL,
		0xBD418AEBA7DA5472ULL,
		0x638C3A6A8E358234ULL,
		0x4F743E46312C7C73ULL,
		0xD7E768A2B65928A1ULL,
		0x1F3D70FC435BAC0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x472DCB3E4D67B287ULL,
		0x66D8EA7A3359EA7DULL,
		0x0F3164F02162DDA6ULL,
		0x1C0BB7210AC884B1ULL,
		0x497648C9E33427DCULL,
		0xA9E7F5FB8FDC5288ULL,
		0x202ECAC00B822431ULL,
		0x7B854CC22891FF38ULL
	}};
	sign = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C39825D19FB0F99ULL,
		0x57A182C3B286722CULL,
		0x356AA790993EE355ULL,
		0xCC5741D59B66ACD7ULL,
		0x7DE42DEF1D0C74ADULL,
		0x6BDC8C9CAD17994AULL,
		0x0D2734CD69E3C559ULL,
		0xD811F43C9118B47BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E277BA72592486ULL,
		0xD2A2DA7C7E836AC2ULL,
		0x4258771C2DD1DFFEULL,
		0xF7CF81D6128E2B01ULL,
		0x4E80961C80A0B59EULL,
		0xEC1C3B636CC018CBULL,
		0xB36FE3741556A01DULL,
		0xD8473F9B64C8BFF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05570AA2A7A1EB13ULL,
		0x84FEA8473403076AULL,
		0xF31230746B6D0356ULL,
		0xD487BFFF88D881D5ULL,
		0x2F6397D29C6BBF0EULL,
		0x7FC051394057807FULL,
		0x59B75159548D253BULL,
		0xFFCAB4A12C4FF486ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4816CB595AE5A95CULL,
		0x6037CD686D6CE614ULL,
		0x2F7D5009D2EA80C2ULL,
		0x9D10DB3C5C1FB728ULL,
		0x1EDDB7D918865474ULL,
		0x77CC4FA4D33C2B7AULL,
		0x4BCFDF3ACB175C62ULL,
		0xBDFE10902E8342EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5377511481AB1432ULL,
		0xDD81FB765826C2FAULL,
		0xB80821F0685BF72DULL,
		0x587EE2CBE62AE797ULL,
		0x5DA1F06129AB2742ULL,
		0x7253B42188B692BAULL,
		0x571F68351A40AE26ULL,
		0xA603463DB88134A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF49F7A44D93A952AULL,
		0x82B5D1F215462319ULL,
		0x77752E196A8E8994ULL,
		0x4491F87075F4CF90ULL,
		0xC13BC777EEDB2D32ULL,
		0x05789B834A8598BFULL,
		0xF4B07705B0D6AE3CULL,
		0x17FACA5276020E4BULL
	}};
	sign = 0;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC21AE3EBF63A4719ULL,
		0xF8732CB04044FD9FULL,
		0x96F2292DC6DE50DAULL,
		0x6F94A0AEF02F084CULL,
		0xF92E194C77E59999ULL,
		0x06D982B9328EB7F3ULL,
		0x1FF45498F6BCEA06ULL,
		0x5A28B226D3424B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51C44F384D529A77ULL,
		0x50401461EBC93057ULL,
		0x6F274B206B69E870ULL,
		0x6F1711965ED49BA3ULL,
		0x9BCD37F670288E40ULL,
		0xA118AD76A1BBBBD8ULL,
		0x410FAEA4158C4A22ULL,
		0xBBACE6C2BF3D57ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x705694B3A8E7ACA2ULL,
		0xA833184E547BCD48ULL,
		0x27CADE0D5B74686AULL,
		0x007D8F18915A6CA9ULL,
		0x5D60E15607BD0B59ULL,
		0x65C0D54290D2FC1BULL,
		0xDEE4A5F4E1309FE3ULL,
		0x9E7BCB641404F373ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x191081DD75319F9EULL,
		0x338BDAB0A8C9BC1DULL,
		0x63E356AC3D88A798ULL,
		0x12B14D7E0A8DB0D7ULL,
		0x3785779461793FD3ULL,
		0x13BCD1BDC93A2842ULL,
		0x29DF61B35A7C2B1CULL,
		0x3433731B426B4024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDDCFDC17D9CA2BULL,
		0xEFEABB0168A89E4BULL,
		0x72407F4CE31034BFULL,
		0xCE71C45E4E6A4637ULL,
		0xA7BD334C7B722401ULL,
		0x4BD2F99820789E7BULL,
		0x09C13015916DA959ULL,
		0x110EFDE4CBEE79E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD32B2015D57D573ULL,
		0x43A11FAF40211DD1ULL,
		0xF1A2D75F5A7872D8ULL,
		0x443F891FBC236A9FULL,
		0x8FC84447E6071BD1ULL,
		0xC7E9D825A8C189C6ULL,
		0x201E319DC90E81C2ULL,
		0x23247536767CC640ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDEC2F693C699248ULL,
		0x71509E3C1413A1C9ULL,
		0x51B0FD60BB6474ACULL,
		0x05ADF828B0337931ULL,
		0xE7381367D39A682DULL,
		0x0FE81FBA54556386ULL,
		0xC328472D1D2B4BAEULL,
		0xA50B8F53E5846C39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF661A7115E6D4A80ULL,
		0xE75E60BA28B74AEEULL,
		0xC89331FAB5B669F7ULL,
		0x154E9E53FBF4CA72ULL,
		0x79CFE28391F5288AULL,
		0x0059463A019B3A16ULL,
		0xEFBE510285B42736ULL,
		0xC0FF39FBDED63C93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD78A8857DDFC47C8ULL,
		0x89F23D81EB5C56DAULL,
		0x891DCB6605AE0AB4ULL,
		0xF05F59D4B43EAEBEULL,
		0x6D6830E441A53FA2ULL,
		0x0F8ED98052BA2970ULL,
		0xD369F62A97772478ULL,
		0xE40C555806AE2FA5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0323208CCB95E2A2ULL,
		0xB259641685A2A67CULL,
		0x2734C5ECBCD5ECC3ULL,
		0xD041B61804774485ULL,
		0x6FCB7F3C7D7CE73CULL,
		0x4C32C45B3C9857D1ULL,
		0x2A5D9B04974E20FFULL,
		0xAABE3340B3E7435AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65AC75B45CD97B78ULL,
		0x7D8B3014F11A22F7ULL,
		0xFA9D8BC9298DFDF9ULL,
		0xBE130EC01E2F149FULL,
		0x1420A79121EF8B2AULL,
		0x02A5E8547E0BE15CULL,
		0xFBB5C0277062E596ULL,
		0x9E2333261F2C638FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D76AAD86EBC672AULL,
		0x34CE340194888384ULL,
		0x2C973A239347EECAULL,
		0x122EA757E6482FE5ULL,
		0x5BAAD7AB5B8D5C12ULL,
		0x498CDC06BE8C7675ULL,
		0x2EA7DADD26EB3B69ULL,
		0x0C9B001A94BADFCAULL
	}};
	sign = 0;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDD69BDBEC681D8DULL,
		0x1AF359787101CD5DULL,
		0x2B59AC3A36158F52ULL,
		0xB0D0EF1E91565597ULL,
		0x80F83A2F7B995B35ULL,
		0xDD77B55FFE2BDAF6ULL,
		0x9A5F0E058BB388CBULL,
		0xBB4424F9172EBF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE1EC7CAD8393EFULL,
		0x1F5834C52698A677ULL,
		0xAE6B8FAC1FE2CA8DULL,
		0x5A168C42098AFDB5ULL,
		0xD323B8A03EA33C7CULL,
		0xC72B1CF6B45B6DDFULL,
		0xAD761110B3909A02ULL,
		0xF13BE434328DA7EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DF4AF5F3EE4899EULL,
		0xFB9B24B34A6926E6ULL,
		0x7CEE1C8E1632C4C4ULL,
		0x56BA62DC87CB57E1ULL,
		0xADD4818F3CF61EB9ULL,
		0x164C986949D06D16ULL,
		0xECE8FCF4D822EEC9ULL,
		0xCA0840C4E4A1179CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD29AAFF8D5BE7244ULL,
		0xCC5E39BE57C7D1C7ULL,
		0x5DF11715545BC14BULL,
		0xEE6906094A5EBA3BULL,
		0x97FC10BAB0426D3DULL,
		0xF2F8C4DE13E01253ULL,
		0xE1EFDE84C2EB0190ULL,
		0xAF0A6891B02FF5A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE611C180623C474BULL,
		0xDF69D818D9C78669ULL,
		0x652A9FA9DD099BD3ULL,
		0x546EE5C86DA9F2E5ULL,
		0xBB8AB0250FF974FBULL,
		0xFEDD998291F85D18ULL,
		0x8E3E47539E943CBDULL,
		0xE668B7066A64EE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC88EE7873822AF9ULL,
		0xECF461A57E004B5DULL,
		0xF8C6776B77522577ULL,
		0x99FA2040DCB4C755ULL,
		0xDC716095A048F842ULL,
		0xF41B2B5B81E7B53AULL,
		0x53B197312456C4D2ULL,
		0xC8A1B18B45CB0748ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53B916C164715698ULL,
		0xB5E5B7ED89A20844ULL,
		0x74DE802F848E1F3AULL,
		0x281603EB461C2409ULL,
		0x9227D0375A62141FULL,
		0xC77097575CE668A9ULL,
		0x90B68B15FBB2AC57ULL,
		0x6C1506182C7D176CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D3E9F8D60FBF80ULL,
		0x9EC2591551FAF318ULL,
		0x58CA3DDAB0ED51AFULL,
		0x35DFD0E8E2D115DCULL,
		0xC5922C4485D2F9EAULL,
		0x27ED849F0A5F72C5ULL,
		0x0CD0CE546FF5CCE9ULL,
		0xA632AC6788BACEFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CE52CC88E619718ULL,
		0x17235ED837A7152BULL,
		0x1C144254D3A0CD8BULL,
		0xF2363302634B0E2DULL,
		0xCC95A3F2D48F1A34ULL,
		0x9F8312B85286F5E3ULL,
		0x83E5BCC18BBCDF6EULL,
		0xC5E259B0A3C2486DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31EE9DC64EB78730ULL,
		0xB834DE3D84BB0BB1ULL,
		0x749FA97CCBB10821ULL,
		0xFD474304044C928DULL,
		0x633DEA84A49AF513ULL,
		0xFCB215C60E37EFC3ULL,
		0xA5FE010DE98FCC27ULL,
		0x2035E729B3711990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3194501A64EC9DULL,
		0xBC35DFE9FC7BDA20ULL,
		0x0CC92C205426C5D0ULL,
		0xE1A71DC7FDB3C21FULL,
		0x4A1F0D49D0F4D168ULL,
		0x03C006E40B54520EULL,
		0xC7E07EDD721B5550ULL,
		0xFA1D04023DDB266DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82BD097634529A93ULL,
		0xFBFEFE53883F3190ULL,
		0x67D67D5C778A4250ULL,
		0x1BA0253C0698D06EULL,
		0x191EDD3AD3A623ABULL,
		0xF8F20EE202E39DB5ULL,
		0xDE1D8230777476D7ULL,
		0x2618E3277595F322ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60681288CEBA8248ULL,
		0x09377FFBD396B226ULL,
		0x6D27C41911377EE0ULL,
		0x67732BD4FBD68D6BULL,
		0xA7BEC34294EE0FDEULL,
		0xCD4D0285B033F860ULL,
		0x5E6404F7419459C7ULL,
		0xC5F2BB24E0592F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DF8A1FCA2F45914ULL,
		0x73A783713917A809ULL,
		0xBE6121324928249AULL,
		0x5CEB95D09B828DEDULL,
		0x61FC1515B5495753ULL,
		0x0095AFA98FA6FE03ULL,
		0x1E957B8BBC488021ULL,
		0x898E4353514D51B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x226F708C2BC62934ULL,
		0x958FFC8A9A7F0A1DULL,
		0xAEC6A2E6C80F5A45ULL,
		0x0A8796046053FF7DULL,
		0x45C2AE2CDFA4B88BULL,
		0xCCB752DC208CFA5DULL,
		0x3FCE896B854BD9A6ULL,
		0x3C6477D18F0BDDE2ULL
	}};
	sign = 0;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79E76A9172DFDA02ULL,
		0x5FEAD9228B215326ULL,
		0x91922DF868731CB2ULL,
		0xFE0F1498DA722E15ULL,
		0x1D47BFF7C707DDC8ULL,
		0x967A911972C6BD62ULL,
		0x9834688C12683BC0ULL,
		0xDCC9CB1E7C0E5C31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD5C71DB9EE6F61ULL,
		0xE24E52EEDE08A2A7ULL,
		0xBA396DC1C9D9E94EULL,
		0xE91FCFA4C0C65373ULL,
		0x8FDDE1B8144A7018ULL,
		0x9ABCCCB516276DB2ULL,
		0xB64643DB87040B61ULL,
		0x403DAD99BE2B7EA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D11A373B8F16AA1ULL,
		0x7D9C8633AD18B07FULL,
		0xD758C0369E993363ULL,
		0x14EF44F419ABDAA1ULL,
		0x8D69DE3FB2BD6DB0ULL,
		0xFBBDC4645C9F4FAFULL,
		0xE1EE24B08B64305EULL,
		0x9C8C1D84BDE2DD90ULL
	}};
	sign = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86ABF91C968F7D91ULL,
		0x78FA9704F1E560C6ULL,
		0xE0C58B4A3D354044ULL,
		0xA0D4E7AB67E14886ULL,
		0x4D8B4B26BE2DD848ULL,
		0x74FB0310C2EA737AULL,
		0x877C157D20283FBEULL,
		0xCBB219B96F4E1023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB8F2115426E7BFULL,
		0xBB12969A30DA0240ULL,
		0x007F8A666AB30A9EULL,
		0xD621514D9BE8B8E2ULL,
		0x9B565F3A2692F6EFULL,
		0x92136268577FC27AULL,
		0x89875C8089E306F9ULL,
		0xBE0691F1646E010FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6F3070B426895D2ULL,
		0xBDE8006AC10B5E85ULL,
		0xE04600E3D28235A5ULL,
		0xCAB3965DCBF88FA4ULL,
		0xB234EBEC979AE158ULL,
		0xE2E7A0A86B6AB0FFULL,
		0xFDF4B8FC964538C4ULL,
		0x0DAB87C80AE00F13ULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74676E5E1F0FAC5AULL,
		0x42569031DBF7E1EFULL,
		0x9659A6F358717BA6ULL,
		0x852B194DCC27693CULL,
		0xAFF98976B2EEDD4AULL,
		0xCD9DCCE41FB00F16ULL,
		0x8E2479959C844DC5ULL,
		0xD96C5F9196FB45A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6362A387DA073D47ULL,
		0x72E5A4C1585F6E50ULL,
		0x84C1ABB5B538CE31ULL,
		0xDA47FD241E74A3A1ULL,
		0x6B22D62F11A6AA04ULL,
		0x79475B40F1F3E8A8ULL,
		0xC79422FC122317F8ULL,
		0x76959185A82B45CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1104CAD645086F13ULL,
		0xCF70EB708398739FULL,
		0x1197FB3DA338AD74ULL,
		0xAAE31C29ADB2C59BULL,
		0x44D6B347A1483345ULL,
		0x545671A32DBC266EULL,
		0xC69056998A6135CDULL,
		0x62D6CE0BEECFFFD8ULL
	}};
	sign = 0;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0037730D7F940DFBULL,
		0x78D2A3D70B61495CULL,
		0xEE23A14A43DD0A2CULL,
		0x3E40D3810A112542ULL,
		0x173C04D8B3B5195FULL,
		0xC80F22CD3D8E57FCULL,
		0xAA687DF6F4B439E0ULL,
		0xA8A0C883A47B6982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DCD6C70B4EAE80BULL,
		0xE16EC1DB66EE6E9AULL,
		0xBFCF86C7ACE38FBDULL,
		0x980568203826C827ULL,
		0xA5510406E36892B7ULL,
		0x9BE13231CBA09CE6ULL,
		0x52798FB81BDFFE3DULL,
		0xBF2E1613FC27D933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x626A069CCAA925F0ULL,
		0x9763E1FBA472DAC1ULL,
		0x2E541A8296F97A6EULL,
		0xA63B6B60D1EA5D1BULL,
		0x71EB00D1D04C86A7ULL,
		0x2C2DF09B71EDBB15ULL,
		0x57EEEE3ED8D43BA3ULL,
		0xE972B26FA853904FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x835BA3AC9B22A8D4ULL,
		0xB0B69BE5D9423B35ULL,
		0xFC9A5C47223FED6CULL,
		0xC41A91FC519E073DULL,
		0x5C4C71345AD470ADULL,
		0x314849F3B532A0ADULL,
		0xAA395EBE6BA4C339ULL,
		0x7DD3FCE9DA5BE1A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4574FB1C11C2265ULL,
		0x9A4F65C634980709ULL,
		0xB1289F9E6DE46991ULL,
		0x09E733732BF75FF7ULL,
		0x571E71243F320485ULL,
		0x6BAB6115079D6EC6ULL,
		0xB7CD6DE7D92EE932ULL,
		0x53CD1C70994D929AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF0453FADA06866FULL,
		0x1667361FA4AA342BULL,
		0x4B71BCA8B45B83DBULL,
		0xBA335E8925A6A746ULL,
		0x052E00101BA26C28ULL,
		0xC59CE8DEAD9531E7ULL,
		0xF26BF0D69275DA06ULL,
		0x2A06E079410E4F0AULL
	}};
	sign = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A6E0BE59F5FA669ULL,
		0x7CB54AAB34B29B49ULL,
		0x51EC7CBF960BBDA0ULL,
		0x16F7DA1C175C5877ULL,
		0x15E7178D6AE944C2ULL,
		0xFEE59ECA5CC6024BULL,
		0x6ADAF5B47EB4F695ULL,
		0x8CD644F3F66ACF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC17434A77FE0C5A5ULL,
		0x3DE517A3A19EE1A4ULL,
		0xE8A3CD68706D5EFBULL,
		0x96454C5AF26A6279ULL,
		0x57430BD34779D96DULL,
		0x203BB8F5858981A8ULL,
		0x22C45C0DE2273102ULL,
		0xD639DDD19C747AF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8F9D73E1F7EE0C4ULL,
		0x3ED033079313B9A4ULL,
		0x6948AF57259E5EA5ULL,
		0x80B28DC124F1F5FDULL,
		0xBEA40BBA236F6B54ULL,
		0xDEA9E5D4D73C80A2ULL,
		0x481699A69C8DC593ULL,
		0xB69C672259F654A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A9A6E794843E044ULL,
		0x767C0244682EE362ULL,
		0x6367661D02B2C264ULL,
		0x08FFF4F0D33E636CULL,
		0xA25163FBD27A8501ULL,
		0xAAD7CF7BC0C5C591ULL,
		0x7E3C580E63F3723AULL,
		0xA41E5BB61716EFB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74417C2C1F01DDDFULL,
		0xB003B6377C6EEAC1ULL,
		0xE6D4087B4F6AB546ULL,
		0x53EE0FE7E35D0F12ULL,
		0xC727F8357B073213ULL,
		0x04F67F211FC9D2D6ULL,
		0xD5801BC41CE2C939ULL,
		0xEFDCAE6F7120931AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2658F24D29420265ULL,
		0xC6784C0CEBBFF8A1ULL,
		0x7C935DA1B3480D1DULL,
		0xB511E508EFE15459ULL,
		0xDB296BC6577352EDULL,
		0xA5E1505AA0FBF2BAULL,
		0xA8BC3C4A4710A901ULL,
		0xB441AD46A5F65C95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C1FF8BAF4E1B242ULL,
		0xB9ADCB19B90E1EDFULL,
		0xADA607B7B35AE2BEULL,
		0x97998037BFA766B4ULL,
		0x445C3453D4D00CD7ULL,
		0xE6B236AB9BDDE3B8ULL,
		0xDB0DFE667519EE08ULL,
		0xDCD8A0C8092A8472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF070C1C3E1D7E5C6ULL,
		0xFB8A2EC70079B109ULL,
		0x164F5E39F3A22C37ULL,
		0xDA9AF372C8ADD7B9ULL,
		0x96C3E0A71388DBDEULL,
		0x1193337501FEF517ULL,
		0xF14B14BE5D05AA7DULL,
		0xE89FE7396136FE50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BAF36F71309CC7CULL,
		0xBE239C52B8946DD5ULL,
		0x9756A97DBFB8B686ULL,
		0xBCFE8CC4F6F98EFBULL,
		0xAD9853ACC14730F8ULL,
		0xD51F033699DEEEA0ULL,
		0xE9C2E9A81814438BULL,
		0xF438B98EA7F38621ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB23A161A9F064BEFULL,
		0x6704358BF0301703ULL,
		0x2534DF79B00B45ACULL,
		0x822BF31F7189DE0CULL,
		0x67637CBA4B2BB0B5ULL,
		0x13541C4DEC00A693ULL,
		0xDB464A3435215A28ULL,
		0x053EEBC8B8BE3211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B29D2751F8B4260ULL,
		0x284DDEA87F8D42AAULL,
		0xEC8A71D389404B03ULL,
		0x38C38B3C0A993398ULL,
		0x7D05ACD7F7F08B4EULL,
		0x89568F87FDBF285FULL,
		0x64517EA69CE3715CULL,
		0x2BC1B679AB2F813BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x271043A57F7B098FULL,
		0x3EB656E370A2D459ULL,
		0x38AA6DA626CAFAA9ULL,
		0x496867E366F0AA73ULL,
		0xEA5DCFE2533B2567ULL,
		0x89FD8CC5EE417E33ULL,
		0x76F4CB8D983DE8CBULL,
		0xD97D354F0D8EB0D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBFFC0DAB6B1AD85ULL,
		0xDAA757F594D8D92CULL,
		0x2A42A2D36A2B3A88ULL,
		0xD4EBAA92DD9595DAULL,
		0x69B4C82CFE934656ULL,
		0x767A3B827A2C3FBEULL,
		0x2F8D61FAC39D3C78ULL,
		0x15FDE929FAD3F03BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB1A5DF2907BCBAULL,
		0xDC41AFA3EE4914E3ULL,
		0xC03664D4F02C8A76ULL,
		0x5A613CC450CC1B3EULL,
		0x7D5A2CB9675987ADULL,
		0xC049F5A5EEECECE5ULL,
		0x5E3116BEB15F5614ULL,
		0x1572980080532332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4E1AFB8DA9F0CBULL,
		0xFE65A851A68FC449ULL,
		0x6A0C3DFE79FEB011ULL,
		0x7A8A6DCE8CC97A9BULL,
		0xEC5A9B739739BEA9ULL,
		0xB63045DC8B3F52D8ULL,
		0xD15C4B3C123DE663ULL,
		0x008B51297A80CD08ULL
	}};
	sign = 0;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBEC2B82EC000FF4ULL,
		0xDBC06BFAB1BD968DULL,
		0x2AD30B7EA34520A8ULL,
		0xC11D2141C760C351ULL,
		0x57876FAC874CFD9CULL,
		0x0D5D9A778AE627B2ULL,
		0xCC7B33C8985DE579ULL,
		0xFEC9D6BD09263D50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478D9371CA53A047ULL,
		0x730C9004912866B7ULL,
		0x61B711E6511A5D4DULL,
		0x36A6A65575DEC992ULL,
		0xB950349BD21E3AB9ULL,
		0xBA2EA772EC10D562ULL,
		0x11B7C9DB83A25D48ULL,
		0x301B0DD4D1738E8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x845E981121AC6FADULL,
		0x68B3DBF620952FD6ULL,
		0xC91BF998522AC35BULL,
		0x8A767AEC5181F9BEULL,
		0x9E373B10B52EC2E3ULL,
		0x532EF3049ED5524FULL,
		0xBAC369ED14BB8830ULL,
		0xCEAEC8E837B2AEC6ULL
	}};
	sign = 0;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88E84812AF0E3848ULL,
		0x75D642BCCF123664ULL,
		0x244F47FDB8781D50ULL,
		0x1743B99689E32459ULL,
		0xCB015088C465BBBAULL,
		0xEA100B7C72B2B2CEULL,
		0xC261CC81509F61FAULL,
		0xF1F7C50DFDB43698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994E13B751BD67D3ULL,
		0xCD8E49BCBEE2338CULL,
		0x34F3C3298E31F302ULL,
		0x8CEE561C38719D20ULL,
		0xF576B118FCE50C97ULL,
		0x7E6E4AD37B4D11F0ULL,
		0xB34DC62DCBC547B9ULL,
		0x2AD56762EC75DA29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF9A345B5D50D075ULL,
		0xA847F900103002D7ULL,
		0xEF5B84D42A462A4DULL,
		0x8A55637A51718738ULL,
		0xD58A9F6FC780AF22ULL,
		0x6BA1C0A8F765A0DDULL,
		0x0F14065384DA1A41ULL,
		0xC7225DAB113E5C6FULL
	}};
	sign = 0;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFBE2C1FA1D6317DULL,
		0xE68982E19163A52FULL,
		0xDAA1161280634D88ULL,
		0x6F158BC92DCDD594ULL,
		0x195129866AC722ADULL,
		0x9435FD7495A5D67EULL,
		0x226988E6811692C3ULL,
		0xDBE645E8662E58A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E23B5A9A62C313ULL,
		0x92C23BDE11C1EFCBULL,
		0xB095F771AF00CFF5ULL,
		0x2BCDA3FF4F59876DULL,
		0xBBA31ACBF982017DULL,
		0xC04767D08CBB54C5ULL,
		0x0F5FDDB1D0AE481BULL,
		0x10C012BF809DB2DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5DBF0C507736E6AULL,
		0x53C747037FA1B564ULL,
		0x2A0B1EA0D1627D93ULL,
		0x4347E7C9DE744E27ULL,
		0x5DAE0EBA71452130ULL,
		0xD3EE95A408EA81B8ULL,
		0x1309AB34B0684AA7ULL,
		0xCB263328E590A5C5ULL
	}};
	sign = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05D7EC3F9BF6BF45ULL,
		0xAAE30B68B48245C0ULL,
		0x711A4BE17BB17715ULL,
		0x022759FA8C793145ULL,
		0xACE228EAF1915591ULL,
		0xE4636A23B75DA447ULL,
		0x1D65BEEAAEA299B8ULL,
		0xE3CF5E9F1E8CC2C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36AC025BF24E96AULL,
		0xFC2E796FD48F169BULL,
		0x48F9212875F13210ULL,
		0xC929056E339C829DULL,
		0x8AF9F189C6D0839DULL,
		0xFEBE8DA27385CCDFULL,
		0xB8C00405CBD2A248ULL,
		0x34DD649110DDFA55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x526D2C19DCD1D5DBULL,
		0xAEB491F8DFF32F24ULL,
		0x28212AB905C04504ULL,
		0x38FE548C58DCAEA8ULL,
		0x21E837612AC0D1F3ULL,
		0xE5A4DC8143D7D768ULL,
		0x64A5BAE4E2CFF76FULL,
		0xAEF1FA0E0DAEC870ULL
	}};
	sign = 0;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA29C71A418BEDE6DULL,
		0xB4FCE841CC49B9F8ULL,
		0x1194F87397385D44ULL,
		0x5A196D06462D355BULL,
		0x8665A22BB8B257FEULL,
		0x28BDFBC22D4392F6ULL,
		0x0752E7B93ACCE412ULL,
		0xB1DF1CFB42C56928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A10D03B48A27213ULL,
		0xA590207C109D9872ULL,
		0xBF32D6BA64CD0E9AULL,
		0xA61ACF707E0DF3FAULL,
		0x80056A2DFBB29947ULL,
		0x9DA20487DF5EE6CBULL,
		0x4AD38ABC298DAAF4ULL,
		0xAF989E14DB330CC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x688BA168D01C6C5AULL,
		0x0F6CC7C5BBAC2186ULL,
		0x526221B9326B4EAAULL,
		0xB3FE9D95C81F4160ULL,
		0x066037FDBCFFBEB6ULL,
		0x8B1BF73A4DE4AC2BULL,
		0xBC7F5CFD113F391DULL,
		0x02467EE667925C5EULL
	}};
	sign = 0;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9EB1E86972F46ACULL,
		0x47CFB36E1967A60EULL,
		0xA9BDFE02417D2019ULL,
		0xE57869532A53AF34ULL,
		0x4A8BB5A13C90D26DULL,
		0x7C250ACC71A6C12BULL,
		0x28BAC6D398DCBA7AULL,
		0xD5A9FC164DA02E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x283F2CE3A67B981DULL,
		0xBE03B56CA2BBCF3DULL,
		0x29AEFF3DBEC96779ULL,
		0xB2E80C3F741713B7ULL,
		0xBC96C8C7166D2488ULL,
		0x17DAB618828DC19FULL,
		0x066292FD21B0800CULL,
		0x05DE09F11C882AD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91ABF1A2F0B3AE8FULL,
		0x89CBFE0176ABD6D1ULL,
		0x800EFEC482B3B89FULL,
		0x32905D13B63C9B7DULL,
		0x8DF4ECDA2623ADE5ULL,
		0x644A54B3EF18FF8BULL,
		0x225833D6772C3A6EULL,
		0xCFCBF22531180334ULL
	}};
	sign = 0;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5FF9BCAF6FD7246ULL,
		0xBBA4A98189A8CCCBULL,
		0xF6C0A1E485AA80FEULL,
		0xC1D6CAB5DDDBEFCAULL,
		0x3232CB00D4DB169FULL,
		0xAE48CEA570B07DDEULL,
		0x181E6D5294992540ULL,
		0x3E1110903FC69EEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A160555F99F29E0ULL,
		0x60DE9580718FCD36ULL,
		0xCBA9B3953678BD21ULL,
		0xA7634A6FB3B1C928ULL,
		0xB886AFAD3D775912ULL,
		0x094CD9B58A0E8E13ULL,
		0x9A13966AA230D5B6ULL,
		0xD8AAA9A8D35C1AAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBE99674FD5E4866ULL,
		0x5AC614011818FF95ULL,
		0x2B16EE4F4F31C3DDULL,
		0x1A7380462A2A26A2ULL,
		0x79AC1B539763BD8DULL,
		0xA4FBF4EFE6A1EFCAULL,
		0x7E0AD6E7F2684F8AULL,
		0x656666E76C6A843BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2C0C0ECD07E1B42ULL,
		0x74C6274607A8AAA4ULL,
		0xF6DF49E1F9AC9FAFULL,
		0x4FFC870032F8FABBULL,
		0x3B0C85AAD707A7D2ULL,
		0xEB1C9D4B2AC08404ULL,
		0x71B2AE06FEDD7B4AULL,
		0xEB8B3682A184AB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED03419F4E9EC3A6ULL,
		0x0337CB71BDEFB26CULL,
		0x315B62E485A1985EULL,
		0x96F02FED77BFCF0BULL,
		0x9DA9C1613ED61A92ULL,
		0x7368F8C6DE05B188ULL,
		0xBC3EDF8639691C2CULL,
		0xC2A3390A2E90E986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05BD7F4D81DF579CULL,
		0x718E5BD449B8F838ULL,
		0xC583E6FD740B0751ULL,
		0xB90C5712BB392BB0ULL,
		0x9D62C44998318D3FULL,
		0x77B3A4844CBAD27BULL,
		0xB573CE80C5745F1EULL,
		0x28E7FD7872F3C1EDULL
	}};
	sign = 0;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA2CFE0BFA3849F6ULL,
		0x4D897CC51197118CULL,
		0x8625A65033CAB5D3ULL,
		0xF727096D4163618FULL,
		0xEEA2D46D78B3AEA5ULL,
		0x548F4EEB3A316189ULL,
		0x6E1E90E1F56DC488ULL,
		0x3B848F0635AA75D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B758394DB41BF4ULL,
		0xEE0229631B832CCBULL,
		0x2FDC2B8C6DF44078ULL,
		0x80EDFC871F20315AULL,
		0xB9D14E7E50287340ULL,
		0xFE45406E49358A01ULL,
		0xD5D7259D5C9A1E1DULL,
		0x9C18F793C63135E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB075A5D2AC842E02ULL,
		0x5F875361F613E4C1ULL,
		0x56497AC3C5D6755AULL,
		0x76390CE622433035ULL,
		0x34D185EF288B3B65ULL,
		0x564A0E7CF0FBD788ULL,
		0x98476B4498D3A66AULL,
		0x9F6B97726F793FF0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x345F2E059C746F6BULL,
		0xE9E9D953A698EFBDULL,
		0x7419A8B77C637E74ULL,
		0x69523FCD452C53FDULL,
		0xC7DCF96553156A4AULL,
		0x7102CA4C5644335BULL,
		0x4063397E35D74079ULL,
		0x55739C892B66AE38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC487A054E3A1186ULL,
		0x2DA24434960AD0B6ULL,
		0x3E5AE829139C540BULL,
		0x5529273BC41BDF25ULL,
		0xAF696E010C7AF8D0ULL,
		0x82F8548E96AE026DULL,
		0x05681BA88D14E52FULL,
		0xD21AF9F2A41089D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7816B4004E3A5DE5ULL,
		0xBC47951F108E1F06ULL,
		0x35BEC08E68C72A69ULL,
		0x14291891811074D8ULL,
		0x18738B64469A717AULL,
		0xEE0A75BDBF9630EEULL,
		0x3AFB1DD5A8C25B49ULL,
		0x8358A29687562465ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB33748AC9E0717F3ULL,
		0xDB2C0EEF58FFDD87ULL,
		0xCFA6EF619D1DCF23ULL,
		0xA2D3EE01BDBCAC8EULL,
		0x9EACAD2D7C959865ULL,
		0x68214EAD6890E793ULL,
		0x9F984E63761B39F1ULL,
		0x0BACC52BFA2AD6FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71097AB89FFF5F97ULL,
		0x10BC05486D5C7526ULL,
		0x36BD0E61B57464DFULL,
		0x4BBF96A261948907ULL,
		0x2C41D48A8D307831ULL,
		0x146E14A1619FA9D4ULL,
		0x900B588D863FC069ULL,
		0x509B050838F8DCD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x422DCDF3FE07B85CULL,
		0xCA7009A6EBA36861ULL,
		0x98E9E0FFE7A96A44ULL,
		0x5714575F5C282387ULL,
		0x726AD8A2EF652034ULL,
		0x53B33A0C06F13DBFULL,
		0x0F8CF5D5EFDB7988ULL,
		0xBB11C023C131FA21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD777D1043DDCC134ULL,
		0x6B2346131324F189ULL,
		0x939BE500878A54D4ULL,
		0x72936B4B1FD561A9ULL,
		0xE09C6B2CA9C4B350ULL,
		0x4E742D06A2261C36ULL,
		0x49FB82D23C83FEEBULL,
		0xF65A93F24B8F757FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74551ECC5EA839A4ULL,
		0x626B77B5536D4D05ULL,
		0x6401050F0905640CULL,
		0xF2B9DAF6AEDE9F6CULL,
		0xE9ABEEEE63D610C7ULL,
		0x77D3B62DD211B83AULL,
		0x59A6523B2897BD4EULL,
		0xF8756AE97CE9ADF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6322B237DF348790ULL,
		0x08B7CE5DBFB7A484ULL,
		0x2F9ADFF17E84F0C8ULL,
		0x7FD9905470F6C23DULL,
		0xF6F07C3E45EEA288ULL,
		0xD6A076D8D01463FBULL,
		0xF055309713EC419CULL,
		0xFDE52908CEA5C785ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D4871FD7102796EULL,
		0x80419A4101C475BFULL,
		0x70EF363B7A88EA5CULL,
		0x8A1D7CB7DE7B3D99ULL,
		0x8A2F5841696064CFULL,
		0x1B050E30FA5FA852ULL,
		0x42110A2677C20276ULL,
		0xE753A916FBD23068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83AC0C0C933911B3ULL,
		0x0CF32B12C802FD4DULL,
		0xAD55FBEC00F4DB30ULL,
		0x22F063671A9A034BULL,
		0x93B8D69AB9FA6B2AULL,
		0x34163F307481510BULL,
		0x851D4535FC2C7F16ULL,
		0x1D6181E00CD2C94FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC99C65F0DDC967BBULL,
		0x734E6F2E39C17871ULL,
		0xC3993A4F79940F2CULL,
		0x672D1950C3E13A4DULL,
		0xF67681A6AF65F9A5ULL,
		0xE6EECF0085DE5746ULL,
		0xBCF3C4F07B95835FULL,
		0xC9F22736EEFF6718ULL
	}};
	sign = 0;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80775E3F9451A679ULL,
		0x929A6D14777CDCD0ULL,
		0x434A94E400BF3B00ULL,
		0x1ABA1E0521A40051ULL,
		0xCAFF69CD132E5AB6ULL,
		0x3669379F7D99AACBULL,
		0x56578BFA2C6D4884ULL,
		0x25389E6F8669AC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x166B3E3AD8C01511ULL,
		0x4950AFE2EE4DDA2AULL,
		0xB384A0997A4C85FAULL,
		0xEB91681E6F902FE7ULL,
		0x6C353530ACCEB09FULL,
		0xE0A3768FB560F136ULL,
		0x43C73B38B58E1AF7ULL,
		0xC5FECDD4B6A79788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A0C2004BB919168ULL,
		0x4949BD31892F02A6ULL,
		0x8FC5F44A8672B506ULL,
		0x2F28B5E6B213D069ULL,
		0x5ECA349C665FAA16ULL,
		0x55C5C10FC838B995ULL,
		0x129050C176DF2D8CULL,
		0x5F39D09ACFC214B9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x094B00FC9F910F58ULL,
		0xB6AC038238004568ULL,
		0x0A1C9685A6DE2C48ULL,
		0x8EA7F789346A3A21ULL,
		0x49343B981CA059CFULL,
		0x823EA1602041A999ULL,
		0x1CF196E59F68DCF0ULL,
		0x13AFED4944903229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89FB0650834ADB87ULL,
		0xF8E6FFE00C2F1161ULL,
		0x7AFC1031ED4191A4ULL,
		0xB8CB2438BCDE431BULL,
		0xD98F67F37015C6CDULL,
		0x4225E87B18F6A015ULL,
		0x931E0F85033ED1C5ULL,
		0xF421A259C4EA9745ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F4FFAAC1C4633D1ULL,
		0xBDC503A22BD13406ULL,
		0x8F208653B99C9AA3ULL,
		0xD5DCD350778BF705ULL,
		0x6FA4D3A4AC8A9301ULL,
		0x4018B8E5074B0983ULL,
		0x89D387609C2A0B2BULL,
		0x1F8E4AEF7FA59AE3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E1218CE54F8DB4AULL,
		0x9F2EC9C32FB86FE8ULL,
		0xB3580E8EFCC54411ULL,
		0xC7206070F3D9B774ULL,
		0xEA607EE380C1DD61ULL,
		0xC2DD917276FEEDA6ULL,
		0xC9792B6E29E5E2E2ULL,
		0x2B6ECA6B6FFC81D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61741C2113B6BCEULL,
		0xFFF2B3486BDCC03DULL,
		0xD1E47D4390302573ULL,
		0x159B9625C4331C01ULL,
		0xC24A94D0EA2813CFULL,
		0x4AA52449E54F6688ULL,
		0x9219F4B0E5FF3AF5ULL,
		0x4775D02965FE5398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77FAD70C43BD6F7CULL,
		0x9F3C167AC3DBAFAAULL,
		0xE173914B6C951E9DULL,
		0xB184CA4B2FA69B72ULL,
		0x2815EA129699C992ULL,
		0x78386D2891AF871EULL,
		0x375F36BD43E6A7EDULL,
		0xE3F8FA4209FE2E40ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEC239B9FC7D0720ULL,
		0xF65403AD83EE10B5ULL,
		0x8C80FAD0254C4326ULL,
		0x9716E6403791A643ULL,
		0x126E30F6FA0D12CCULL,
		0xE659D510A2B6373AULL,
		0x3B25EE63F227CA49ULL,
		0xF7C9EBC364F8E1FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3CB7814916C68EAULL,
		0x9F2D5AF7BAD10958ULL,
		0x7656394F396478A1ULL,
		0x5C9E03FA1662CC6CULL,
		0x679C64A391EA552EULL,
		0xC78F620A47A345DAULL,
		0x91974CBF386B739AULL,
		0x8F2147BBC1C1723FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAF6C1A56B109E36ULL,
		0x5726A8B5C91D075CULL,
		0x162AC180EBE7CA85ULL,
		0x3A78E246212ED9D7ULL,
		0xAAD1CC536822BD9EULL,
		0x1ECA73065B12F15FULL,
		0xA98EA1A4B9BC56AFULL,
		0x68A8A407A3376FBEULL
	}};
	sign = 0;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E510A080D0F329EULL,
		0x3E33225197D91C99ULL,
		0x2F7A8366356D7926ULL,
		0x9E79382D247BF399ULL,
		0x656C6D47E22A6349ULL,
		0xC7A7F07E3C11E330ULL,
		0x783960BE5C25E5B0ULL,
		0x98D4E89C510E3EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E6187AF1D3A5681ULL,
		0xAF198EF987F335D0ULL,
		0xCCE1A5FE70AE1CCBULL,
		0xE98B4A56F7349020ULL,
		0x584558335D432BE6ULL,
		0x2BB0A2217DB46625ULL,
		0x029867C35151ECFCULL,
		0x9185D28FA6B599DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFEF8258EFD4DC1DULL,
		0x8F1993580FE5E6C8ULL,
		0x6298DD67C4BF5C5AULL,
		0xB4EDEDD62D476378ULL,
		0x0D27151484E73762ULL,
		0x9BF74E5CBE5D7D0BULL,
		0x75A0F8FB0AD3F8B4ULL,
		0x074F160CAA58A4C3ULL
	}};
	sign = 0;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E3C138C9CCAAE22ULL,
		0xA0AD73486A763867ULL,
		0x3F2D2F94941B2DAEULL,
		0xF22E3E647C7C150BULL,
		0x4086B1E5EEDB9352ULL,
		0xD5B3CB36EA71BA53ULL,
		0xC527AC0E6AD096E6ULL,
		0x1E7CCB495596F5FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF952EF44C3882B9ULL,
		0x2175B6D26D9C50ADULL,
		0xE1EABD3B8A1190F5ULL,
		0x55AAB35E941338B6ULL,
		0x464A0DDAF164AC7FULL,
		0x29E0548C6E9E3EB8ULL,
		0xFFAB55D3236B4D12ULL,
		0x2ED07B627D525726ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEA6E49850922B69ULL,
		0x7F37BC75FCD9E7B9ULL,
		0x5D4272590A099CB9ULL,
		0x9C838B05E868DC54ULL,
		0xFA3CA40AFD76E6D3ULL,
		0xABD376AA7BD37B9AULL,
		0xC57C563B476549D4ULL,
		0xEFAC4FE6D8449ED3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8244ACE3AD089EC9ULL,
		0xB7B6FBF4D51BA12BULL,
		0xE426FF4821EF54F8ULL,
		0xABC5F8BBFB7604A2ULL,
		0xB9E7CF18D3348BB3ULL,
		0x0F9225DB62FB3CDCULL,
		0x322087170173B68FULL,
		0xED60D6EDE91B2919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB556C6382466B60EULL,
		0xA512710CE8E1C4FFULL,
		0x8A35418DBB3DF24DULL,
		0x70AE4D888934C360ULL,
		0xEB315D64151D5998ULL,
		0xA73201E6527CFBD4ULL,
		0x5D842086FD7078C3ULL,
		0x2B5E422ADF8E45D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCEDE6AB88A1E8BBULL,
		0x12A48AE7EC39DC2BULL,
		0x59F1BDBA66B162ABULL,
		0x3B17AB3372414142ULL,
		0xCEB671B4BE17321BULL,
		0x686023F5107E4107ULL,
		0xD49C669004033DCBULL,
		0xC20294C3098CE340ULL
	}};
	sign = 0;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF7BC59B8D1077B6ULL,
		0x0E1EC4AF4033145EULL,
		0x6C957C51BBD1419AULL,
		0x94E8C1C37C567E59ULL,
		0xFA488D50D581ADF1ULL,
		0xBB5D267A82B4F5F3ULL,
		0xEA68B29562EBC893ULL,
		0x0B0A085828071124ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDCF09315E39B4F5ULL,
		0xCB228C876461F19DULL,
		0xB82464E0633068D2ULL,
		0x1A34507555126751ULL,
		0x2FB4A51603142D99ULL,
		0x263C7D8D933AC781ULL,
		0xCD0263DDBFB40ED5ULL,
		0x8FEA15F97AEEF0A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1ACBC6A2ED6C2C1ULL,
		0x42FC3827DBD122C0ULL,
		0xB471177158A0D8C7ULL,
		0x7AB4714E27441707ULL,
		0xCA93E83AD26D8058ULL,
		0x9520A8ECEF7A2E72ULL,
		0x1D664EB7A337B9BEULL,
		0x7B1FF25EAD182080ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA5997ADE8D9720DULL,
		0x655F2D655E5116D9ULL,
		0x298210DF6A0A0F2FULL,
		0x30DDF99F5F126ABEULL,
		0x87012CE356832389ULL,
		0xE5CD5879A7975228ULL,
		0x45D1D82EB94A1A31ULL,
		0x3809B9AC21236A8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34DC93414B90F2C5ULL,
		0x4642ED44819164A7ULL,
		0x449AF5FFC3487D68ULL,
		0x41AD239189452A8EULL,
		0xF1F619532BBD3241ULL,
		0x91D85334A9FFF009ULL,
		0xE5FE02CA2D0152A7ULL,
		0x494024160252A5AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x857D046C9D487F48ULL,
		0x1F1C4020DCBFB232ULL,
		0xE4E71ADFA6C191C7ULL,
		0xEF30D60DD5CD402FULL,
		0x950B13902AC5F147ULL,
		0x53F50544FD97621EULL,
		0x5FD3D5648C48C78AULL,
		0xEEC995961ED0C4DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB45C3275C5B09F76ULL,
		0x25CA4D15858BE804ULL,
		0xB3C75B2334F06395ULL,
		0x289B0BC8F5EB46F4ULL,
		0x927C4C28D8CE73F3ULL,
		0x4A9F08A7622467D8ULL,
		0x9473F5B1A7349B05ULL,
		0xF917234B734362DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB61FBBD0EA68858FULL,
		0x72424EE558AB3272ULL,
		0x32BC6B88686B044EULL,
		0xB3501158C42F6DC6ULL,
		0x811C78CB69692609ULL,
		0xF1DD483A84667707ULL,
		0xADB7BA0DE6BE0DF4ULL,
		0xF9355656854468CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE3C76A4DB4819E7ULL,
		0xB387FE302CE0B591ULL,
		0x810AEF9ACC855F46ULL,
		0x754AFA7031BBD92EULL,
		0x115FD35D6F654DE9ULL,
		0x58C1C06CDDBDF0D1ULL,
		0xE6BC3BA3C0768D10ULL,
		0xFFE1CCF4EDFEFA0CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F927196D97B8DD7ULL,
		0xB08EDAAAE4F3C2FAULL,
		0x2FD9B54CEA6C39D0ULL,
		0xDF140CE4B8C1C29AULL,
		0x5C2E5933ED9966CDULL,
		0x58715F0D9A6F4811ULL,
		0x28AAF20C698EC31DULL,
		0x9C15782DFECBDB2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB019FC7ADA299A61ULL,
		0x129A54D2795D2210ULL,
		0x326458543DE9ED5EULL,
		0x84D31FA51F03A73CULL,
		0xDF8F8E0D9438AC8DULL,
		0x149E0963AED99EDDULL,
		0x9BF78A4327943ED7ULL,
		0x3F61BBCCD7D9DF59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F78751BFF51F376ULL,
		0x9DF485D86B96A0E9ULL,
		0xFD755CF8AC824C72ULL,
		0x5A40ED3F99BE1B5DULL,
		0x7C9ECB265960BA40ULL,
		0x43D355A9EB95A933ULL,
		0x8CB367C941FA8446ULL,
		0x5CB3BC6126F1FBD4ULL
	}};
	sign = 0;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83B899CBB057F319ULL,
		0x27DE2EF74178E1E8ULL,
		0xFBF9CDED08A0EBC6ULL,
		0xB77C42B7916C9234ULL,
		0x57F617BD06FCF058ULL,
		0x6FA195A0A3497F56ULL,
		0xDA1366F256AFADB3ULL,
		0x5CECF8B81AA0340FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A48DD9A2579D290ULL,
		0x525A19B38921EDA6ULL,
		0x7C42B1EC9E01BD88ULL,
		0x90CC3A3718ACAA52ULL,
		0x4F8A5567F9C3CEBEULL,
		0xB689BB3BACB880B8ULL,
		0x81F8CBC93C18EF53ULL,
		0xD03B81EE01C4C44BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x396FBC318ADE2089ULL,
		0xD5841543B856F442ULL,
		0x7FB71C006A9F2E3DULL,
		0x26B0088078BFE7E2ULL,
		0x086BC2550D39219AULL,
		0xB917DA64F690FE9EULL,
		0x581A9B291A96BE5FULL,
		0x8CB176CA18DB6FC4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F3410B478A10672ULL,
		0x1DD43AC0561F171FULL,
		0x448B9801DD1E146FULL,
		0x6279E47F096F9D73ULL,
		0x4307A74BB839D069ULL,
		0x0BBE23721A12241CULL,
		0x1743EF66BF06BEF7ULL,
		0x6E986C482F30051CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C7437702CA94A6ULL,
		0xCCEF420F6D8ECC01ULL,
		0xED6964876DD25D4FULL,
		0xB343927C298B2CC4ULL,
		0x32B8882C23ED5A35ULL,
		0x3361054DECE38257ULL,
		0x058108323ACA5210ULL,
		0xAA4DA5582D704A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x386CCD3D75D671CCULL,
		0x50E4F8B0E8904B1EULL,
		0x5722337A6F4BB71FULL,
		0xAF365202DFE470AEULL,
		0x104F1F1F944C7633ULL,
		0xD85D1E242D2EA1C5ULL,
		0x11C2E734843C6CE6ULL,
		0xC44AC6F001BFBAB1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0A730F8BF83E778ULL,
		0x41E62524B87855D3ULL,
		0xD25DF651727AF8DAULL,
		0xF19DFA03A66DD6D0ULL,
		0x22E7408E76632F56ULL,
		0x42C5489BEBBF299FULL,
		0xA6D4F3E2DBA8E335ULL,
		0x224C09E752151DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323BCEBF8B7FC26EULL,
		0x153E4EF37F4B07D5ULL,
		0x79B4BAE8777B8C51ULL,
		0x2BD5EEF7F03EE6B1ULL,
		0xE7D467CB7E894156ULL,
		0x0ED9351E01AEB647ULL,
		0x5B14080D1600239DULL,
		0x3100D6D6A1E24B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E6B62393404250AULL,
		0x2CA7D631392D4DFEULL,
		0x58A93B68FAFF6C89ULL,
		0xC5C80B0BB62EF01FULL,
		0x3B12D8C2F7D9EE00ULL,
		0x33EC137DEA107357ULL,
		0x4BC0EBD5C5A8BF98ULL,
		0xF14B3310B032D2D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9113E7D91656E58ULL,
		0xDA30262C8F42E3F3ULL,
		0x4EF212D576AFA57EULL,
		0x916B286724EF2A32ULL,
		0xE9FB6D3F47BE7017ULL,
		0xEBE7E39A9EFE6101ULL,
		0x0F8CAF2C6CCFD0F5ULL,
		0x2EE3BC2DADFECF83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C6CCE8A8CE1363EULL,
		0x86F1635EFA2A1F4AULL,
		0x8EB2F34B90D181DAULL,
		0xC0E998205797CDB1ULL,
		0xB50989955079AD1CULL,
		0x0BFC878A99D1AD68ULL,
		0xBE8E293C0ACF6532ULL,
		0x70D7E84804BF6C1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACA46FF30484381AULL,
		0x533EC2CD9518C4A9ULL,
		0xC03F1F89E5DE23A4ULL,
		0xD0819046CD575C80ULL,
		0x34F1E3A9F744C2FAULL,
		0xDFEB5C10052CB399ULL,
		0x50FE85F062006BC3ULL,
		0xBE0BD3E5A93F6364ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DFD4CB52FD93608ULL,
		0xC2B7E11DA0030FB2ULL,
		0xF322D7057BEB8B3CULL,
		0xB1465AD9CAB11089ULL,
		0x0E3C769AC2A54FDAULL,
		0xDA1068F0BC8838B5ULL,
		0x4E86F35E2552B403ULL,
		0x3B2703112DDC0777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9994D6255CADDE31ULL,
		0xE8A7E6F761D5360FULL,
		0x9AF5BBECB2DC2459ULL,
		0xDF2E11BFE3D847E7ULL,
		0xA61702BF09A57330ULL,
		0xD0C5EB19AE957259ULL,
		0x815B6559A204C09CULL,
		0x099C5A84D0E6D2D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE468768FD32B57D7ULL,
		0xDA0FFA263E2DD9A2ULL,
		0x582D1B18C90F66E2ULL,
		0xD2184919E6D8C8A2ULL,
		0x682573DBB8FFDCA9ULL,
		0x094A7DD70DF2C65BULL,
		0xCD2B8E04834DF367ULL,
		0x318AA88C5CF534A5ULL
	}};
	sign = 0;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31E29ED8D99F4299ULL,
		0x3CC865175F998647ULL,
		0xBE64392E6E33EFB8ULL,
		0xBC9198A3B1DD1821ULL,
		0x77DAD15263904C52ULL,
		0x00343E78DF64D566ULL,
		0xE2610262272185CFULL,
		0xAFFB1D8FA6BADD5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52253617E0FFB7ABULL,
		0x8A42A5FE641DC452ULL,
		0x3B7533351646DD82ULL,
		0xFB09B33689294B6CULL,
		0x61AFA2F42BB10908ULL,
		0xEE267D688779BF40ULL,
		0x1452EE7B1B7CFE98ULL,
		0xAEDBBBD9219CBA83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFBD68C0F89F8AEEULL,
		0xB285BF18FB7BC1F4ULL,
		0x82EF05F957ED1235ULL,
		0xC187E56D28B3CCB5ULL,
		0x162B2E5E37DF4349ULL,
		0x120DC11057EB1626ULL,
		0xCE0E13E70BA48736ULL,
		0x011F61B6851E22DAULL
	}};
	sign = 0;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F7BB470A8C0E1E4ULL,
		0x493C38CEA6A5ED88ULL,
		0xB959C5A1D4227254ULL,
		0x52F34709657FC9F9ULL,
		0x71CA64C13728ED74ULL,
		0xB1D02DE531D75309ULL,
		0xE6D5F2C562473C67ULL,
		0x479D4A3113F58CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC069FE262F1AC085ULL,
		0xA139F3BEDFE50735ULL,
		0x0E354CADAF8AB7A4ULL,
		0xE3AE2B564E2AA1C9ULL,
		0x14F5B25ECCFDFBFEULL,
		0x2DA92ACCEA871FBDULL,
		0x192CB0A7BCE37780ULL,
		0x7C1CEBFB7E105DF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF11B64A79A6215FULL,
		0xA802450FC6C0E652ULL,
		0xAB2478F42497BAAFULL,
		0x6F451BB317552830ULL,
		0x5CD4B2626A2AF175ULL,
		0x842703184750334CULL,
		0xCDA9421DA563C4E7ULL,
		0xCB805E3595E52F09ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F97F96C356EA100ULL,
		0x1A4B8EB1D800890AULL,
		0x2A4C60C1F3EB2A18ULL,
		0x6985FB164BB6D2C1ULL,
		0x2C3356BCF532D054ULL,
		0x8CD0A4EFAA13C440ULL,
		0x23E2439424F93DD7ULL,
		0x91F7E77208B61B1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C2362C8DF598A7EULL,
		0x23E74181F76DEE79ULL,
		0xCB588CB2E8B56025ULL,
		0xF3CE9C70BDD55401ULL,
		0x969D86B57CB73C34ULL,
		0x1F464C15FBF76D88ULL,
		0x697946CFBBF0CDA8ULL,
		0x2E0ED9618BF84C86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x137496A356151682ULL,
		0xF6644D2FE0929A91ULL,
		0x5EF3D40F0B35C9F2ULL,
		0x75B75EA58DE17EBFULL,
		0x9595D007787B941FULL,
		0x6D8A58D9AE1C56B7ULL,
		0xBA68FCC46908702FULL,
		0x63E90E107CBDCE98ULL
	}};
	sign = 0;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD96EE487EEDA0AFBULL,
		0x6167D98C8C810B57ULL,
		0x22FB5190E5150F69ULL,
		0xD3E9B531BADA722EULL,
		0xE16529A4596AFB43ULL,
		0xACB5054DC9782FACULL,
		0x2A02A4AC92DD3D84ULL,
		0x0E172A45C412FFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36EF022C5BA24BCFULL,
		0x6D4E7B1040332FBBULL,
		0xC6CD3B84EB18EAD2ULL,
		0x3DCA5B3769C7BA99ULL,
		0x6C46AE21A4C087D4ULL,
		0x7B397D464FFBC459ULL,
		0x87910AA6FEFF9883ULL,
		0x28B22F5E795AE15AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA27FE25B9337BF2CULL,
		0xF4195E7C4C4DDB9CULL,
		0x5C2E160BF9FC2496ULL,
		0x961F59FA5112B794ULL,
		0x751E7B82B4AA736FULL,
		0x317B8807797C6B53ULL,
		0xA2719A0593DDA501ULL,
		0xE564FAE74AB81E6AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ED53F579B910F2FULL,
		0xC70819E75F2D7E12ULL,
		0x7F778B986EDC9413ULL,
		0xBD193A9D01D5759CULL,
		0xF0AEB4D7AD5053CCULL,
		0x698E832EB8A89394ULL,
		0xBC56C93526A6843AULL,
		0xCC575F947BE83045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE909227E3884A62ULL,
		0x4C6A79DD70082222ULL,
		0x58A27972725D9427ULL,
		0xCEC741C4C3D59959ULL,
		0x7389839111963403ULL,
		0x9F474C30D60BC8B7ULL,
		0x30601FBB3E3F1854ULL,
		0x0A9DF9196FCCB10AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9044AD2FB808C4CDULL,
		0x7A9DA009EF255BEFULL,
		0x26D51225FC7EFFECULL,
		0xEE51F8D83DFFDC43ULL,
		0x7D2531469BBA1FC8ULL,
		0xCA4736FDE29CCADDULL,
		0x8BF6A979E8676BE5ULL,
		0xC1B9667B0C1B7F3BULL
	}};
	sign = 0;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2935F8AB3CB75F3BULL,
		0x984551230D78382DULL,
		0x18BEF91ACD83CCD7ULL,
		0x05A764D8509F8102ULL,
		0xC8AB9F7E7F060729ULL,
		0x32D9454B723FD04BULL,
		0x2B76229C3C29C823ULL,
		0x0D8CB29F3CC96DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x207BDF611145F9BBULL,
		0xDA91D632445904CEULL,
		0x9A0B774A2A5B1362ULL,
		0x8F08D98DFCD2EC43ULL,
		0x26448D89B2CEE2A9ULL,
		0x5BDD5F783C19F3F7ULL,
		0x06CB3B34E0BB5C61ULL,
		0x69F8AA3F4DC7DA5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08BA194A2B716580ULL,
		0xBDB37AF0C91F335FULL,
		0x7EB381D0A328B974ULL,
		0x769E8B4A53CC94BEULL,
		0xA26711F4CC37247FULL,
		0xD6FBE5D33625DC54ULL,
		0x24AAE7675B6E6BC1ULL,
		0xA394085FEF01935DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5684F03CD74EBCAFULL,
		0x740388C8B42E6765ULL,
		0x6A81CAD4705927C1ULL,
		0x6DE4EB5DDE1D8A1FULL,
		0x87E8F8F2BE7853BBULL,
		0x16A29B9E7BB31E5DULL,
		0xD68C1E871345945FULL,
		0x78A4C7E880A7E3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067DD171C7E2210AULL,
		0x3A930A8D1F031904ULL,
		0xBFC948D2F0D2DC8CULL,
		0x0C81AC2946B5EDF1ULL,
		0x3CF3EF6FC1538E73ULL,
		0x49A17D18CDD6178BULL,
		0x7374DC088B5A0470ULL,
		0x3C84CD24AF0533B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50071ECB0F6C9BA5ULL,
		0x39707E3B952B4E61ULL,
		0xAAB882017F864B35ULL,
		0x61633F3497679C2DULL,
		0x4AF50982FD24C548ULL,
		0xCD011E85ADDD06D2ULL,
		0x6317427E87EB8FEEULL,
		0x3C1FFAC3D1A2AFF6ULL
	}};
	sign = 0;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EBF17B10FC20C45ULL,
		0x5301674205827F54ULL,
		0x53B049FE8C3D9742ULL,
		0xBACC626488225703ULL,
		0x40D082FBC3269C95ULL,
		0xBC90701BB1E66A4AULL,
		0x32CD7EEBBCFF6376ULL,
		0x17034469ED7F5E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x259ACDABD3E93087ULL,
		0xFE44377B38D22EA2ULL,
		0x2FFB2A28F991A1EFULL,
		0xB0365C76E4107D73ULL,
		0x34894A57B941F9FFULL,
		0x0FB7F5153F07273EULL,
		0xC18B7604909D0DE0ULL,
		0x38188F66315625A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49244A053BD8DBBEULL,
		0x54BD2FC6CCB050B2ULL,
		0x23B51FD592ABF552ULL,
		0x0A9605EDA411D990ULL,
		0x0C4738A409E4A296ULL,
		0xACD87B0672DF430CULL,
		0x714208E72C625596ULL,
		0xDEEAB503BC2938F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7BC7E54E8ACE5FULL,
		0xF7B81B03ECB5C154ULL,
		0xD0AB2AF4A7524499ULL,
		0x8FE30236616487C2ULL,
		0x92204DC3532950ACULL,
		0xBD1DCEE4EDBFF8B5ULL,
		0xE5A1A22C3A18E98EULL,
		0x998C021D07C417DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2232AD77DB99DB57ULL,
		0xB1A54B7E2D8185C7ULL,
		0x35D43DB32135B6D7ULL,
		0xA3EB8C8704CFC274ULL,
		0xC8CC849EE17883D5ULL,
		0xA6FBB3D6271E249EULL,
		0x8A917237D89D3E27ULL,
		0x6EBA460D0447A615ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B491A6D72F0F308ULL,
		0x4612CF85BF343B8DULL,
		0x9AD6ED41861C8DC2ULL,
		0xEBF775AF5C94C54EULL,
		0xC953C92471B0CCD6ULL,
		0x16221B0EC6A1D416ULL,
		0x5B102FF4617BAB67ULL,
		0x2AD1BC10037C71C9ULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27B41EFE1EF05B98ULL,
		0x0CC59F5B27ED2380ULL,
		0xE5FF642C35D2D91DULL,
		0xA4A7AB11FA3BE8B7ULL,
		0xEEBB5984D1EB400CULL,
		0x5F27283598CD0077ULL,
		0x5D64C1240D68C7B6ULL,
		0xCF3D1D238FDDA9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x531D2BCA3AAE1F7EULL,
		0x9B5435FCA017710FULL,
		0xE39E1EF3F907C1A8ULL,
		0x98D7AB4B46EA742EULL,
		0xA6F70D3130033A94ULL,
		0xC255096C074D4AC6ULL,
		0x5A386CDD435D6683ULL,
		0xAFAB27BC10E17466ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD496F333E4423C1AULL,
		0x7171695E87D5B270ULL,
		0x026145383CCB1774ULL,
		0x0BCFFFC6B3517489ULL,
		0x47C44C53A1E80578ULL,
		0x9CD21EC9917FB5B1ULL,
		0x032C5446CA0B6132ULL,
		0x1F91F5677EFC3561ULL
	}};
	sign = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8DBAAEDEAEEBF95ULL,
		0xF306C34D5C8A2CADULL,
		0x88A5C6C1656C3A07ULL,
		0x1A7B5E54BEC08E74ULL,
		0x4A119C30C2D46706ULL,
		0xEE3865D1702D541CULL,
		0x40ECCD5DFEC66C7FULL,
		0xA0AEF2A822A51FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAECF73DB4D16770BULL,
		0xA4199A16BDA82D3EULL,
		0xE41EB25F35B8EC43ULL,
		0x2E49C6C70AB9D998ULL,
		0xD0E8ABFD1FB924B8ULL,
		0xD2155A356547C002ULL,
		0x3F6B3CAFB59628DBULL,
		0x8C00FC086A4258D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA0C37129DD8488AULL,
		0x4EED29369EE1FF6EULL,
		0xA48714622FB34DC4ULL,
		0xEC31978DB406B4DBULL,
		0x7928F033A31B424DULL,
		0x1C230B9C0AE59419ULL,
		0x018190AE493043A4ULL,
		0x14ADF69FB862C722ULL
	}};
	sign = 0;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6793F909A215122ULL,
		0xF75C29930BD04961ULL,
		0x93BE8435B362EC47ULL,
		0x76C604F23EA9E5BAULL,
		0x413EB08883742A6CULL,
		0x1E8623A5F357138FULL,
		0x76AF2793D79A9014ULL,
		0xAA1BFA81B2AB8E26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD1D42DA393ABD0ULL,
		0xA524185F59AB393BULL,
		0x17C88CA6322178DDULL,
		0x2A13E429AE04D392ULL,
		0x893AB20D7C709E17ULL,
		0x5BEB046D6CE64C00ULL,
		0x7CACB7357F1F3099ULL,
		0x3B489410428D1C5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A76B62F68DA552ULL,
		0x52381133B2251026ULL,
		0x7BF5F78F8141736AULL,
		0x4CB220C890A51228ULL,
		0xB803FE7B07038C55ULL,
		0xC29B1F388670C78EULL,
		0xFA02705E587B5F7AULL,
		0x6ED36671701E71C9ULL
	}};
	sign = 0;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA37C308772615D80ULL,
		0xD5E2FA7A82AC4536ULL,
		0x86B58B710EEC9771ULL,
		0xC7267BA936704A9AULL,
		0x089767BB2413786FULL,
		0x3A62360A578CCE3AULL,
		0x706D1B8B96FBD870ULL,
		0x2A084B6FBAA7B8BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96024A9CB124DB4ULL,
		0xD507F7BFD3A89EE5ULL,
		0xBCD833E088743A0BULL,
		0x7994557149B2DEC4ULL,
		0xF9C6A6EE8D4A4B01ULL,
		0x8DDB51415452B712ULL,
		0x31E5BA04C373809BULL,
		0xD027BFC57E0A4C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA1C0BDDA74F0FCCULL,
		0x00DB02BAAF03A650ULL,
		0xC9DD579086785D66ULL,
		0x4D922637ECBD6BD5ULL,
		0x0ED0C0CC96C92D6EULL,
		0xAC86E4C9033A1727ULL,
		0x3E876186D38857D4ULL,
		0x59E08BAA3C9D6C7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64165604E8A62B0DULL,
		0x7CF40C6BDA5492AEULL,
		0xA11D08460C046986ULL,
		0x2D2C4F3C3D0F3004ULL,
		0xE6647FC7EF24E6FBULL,
		0xF16CBBDA15037E02ULL,
		0xCE6E52257C93569CULL,
		0x977228D6317602A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F828544A5992FFBULL,
		0x0C8C62B4287BA8DBULL,
		0x67B60CB5A750DFAEULL,
		0x9EFBF45ABD0B5EBBULL,
		0x6EFFA56F3CD79640ULL,
		0x76F447ECB92094C0ULL,
		0xAB3ED97F8DC263F9ULL,
		0x489B2F7C48264FA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE493D0C0430CFB12ULL,
		0x7067A9B7B1D8E9D2ULL,
		0x3966FB9064B389D8ULL,
		0x8E305AE18003D149ULL,
		0x7764DA58B24D50BAULL,
		0x7A7873ED5BE2E942ULL,
		0x232F78A5EED0F2A3ULL,
		0x4ED6F959E94FB302ULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D677D83B245197AULL,
		0x23982A08ED54CC6AULL,
		0x65015F431723E7B9ULL,
		0x4FFC76FA18C6EEBBULL,
		0xAC3EFC71CBACCA8EULL,
		0xFFA0C4ADC497BF99ULL,
		0x86519B30FA6B82C3ULL,
		0x0767E316C59A641AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35867DFF5C2A5080ULL,
		0x31F2057645FBD61EULL,
		0x261D4BE6B6027404ULL,
		0x73217739C4E85664ULL,
		0x45959FD0A317CD7AULL,
		0x6327C22371536E42ULL,
		0x2E3E33E3C755C31BULL,
		0xC0FD50D69F93E61DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47E0FF84561AC8FAULL,
		0xF1A62492A758F64CULL,
		0x3EE4135C612173B4ULL,
		0xDCDAFFC053DE9857ULL,
		0x66A95CA12894FD13ULL,
		0x9C79028A53445157ULL,
		0x5813674D3315BFA8ULL,
		0x466A924026067DFDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B85B163C2955147ULL,
		0x7937DBFD9E391C75ULL,
		0x23D598F0895279D8ULL,
		0x887A86B4EBD5121AULL,
		0xCA6F9D4BB1D710A9ULL,
		0x639FCCA287A3CF2AULL,
		0x93B65CE3698B4B32ULL,
		0xF09996CA5D0F8159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E047925CB026DDULL,
		0x599EA242FD4148B4ULL,
		0x5E941E96E58530CBULL,
		0x2E4A73FBD38BB5C5ULL,
		0xECED187910185ACCULL,
		0x1D16B9D51A91F757ULL,
		0x6FB805DFE43D8230ULL,
		0x35CA9F31C8493F44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94A569D165E52A6AULL,
		0x1F9939BAA0F7D3C0ULL,
		0xC5417A59A3CD490DULL,
		0x5A3012B918495C54ULL,
		0xDD8284D2A1BEB5DDULL,
		0x468912CD6D11D7D2ULL,
		0x23FE5703854DC902ULL,
		0xBACEF79894C64215ULL
	}};
	sign = 0;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0978966BBF863ED8ULL,
		0x29D5598C9FCF5A83ULL,
		0x514651B02B37E770ULL,
		0x7C45539FE36087ADULL,
		0x4626B78E1064EEC2ULL,
		0xE5FB9E90DA38753CULL,
		0x2A3061933DA26822ULL,
		0x142701A9254BA18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DAFE60A29B6AF3ULL,
		0xBBB589531F5346D6ULL,
		0x28D409132172E7B2ULL,
		0x45C7467FBEABC6B1ULL,
		0x5EB1A780CCB549ABULL,
		0xF682341B3CE726D2ULL,
		0xF99F7904036DA9F5ULL,
		0xA3E177FD16E9B4B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA59D980B1CEAD3E5ULL,
		0x6E1FD039807C13ACULL,
		0x2872489D09C4FFBDULL,
		0x367E0D2024B4C0FCULL,
		0xE775100D43AFA517ULL,
		0xEF796A759D514E69ULL,
		0x3090E88F3A34BE2CULL,
		0x704589AC0E61ECDAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x440819D6EF1E5985ULL,
		0xCE05EAE18293642CULL,
		0x615263048D08F09BULL,
		0x930795E75103CC04ULL,
		0x30BEFFFD7810D873ULL,
		0xBC5E9BA3522FFF15ULL,
		0xC2103DFA7CA9AEFAULL,
		0x0CE900FD73F70A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E44776A47A5E24ULL,
		0x1A597EBBA711065EULL,
		0x1547F6C1F6261D15ULL,
		0x8A545A0DC4ACFC2CULL,
		0x572BC023BC6B7FA2ULL,
		0xAD8A491E89CFAE1EULL,
		0xE535AF60BAF22395ULL,
		0x3B38153A537E31ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE023D2604AA3FB61ULL,
		0xB3AC6C25DB825DCDULL,
		0x4C0A6C4296E2D386ULL,
		0x08B33BD98C56CFD8ULL,
		0xD9933FD9BBA558D1ULL,
		0x0ED45284C86050F6ULL,
		0xDCDA8E99C1B78B65ULL,
		0xD1B0EBC32078D8BCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B78D132454302ADULL,
		0xB510F199551053BDULL,
		0x4233777A1DF17CC1ULL,
		0xE63C65118F46E718ULL,
		0xC46E5B859D7F402EULL,
		0x87340DB5880504B8ULL,
		0x8F86D6630A94A4EDULL,
		0x9A9EB563E448DA68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C991AE7031FF51ULL,
		0xB2BF14F8165B8400ULL,
		0x887560574E443D27ULL,
		0x6135AF61A72F0399ULL,
		0xC2258691154C0684ULL,
		0x61B16745269B0078ULL,
		0xEC026A396EACE657ULL,
		0x9EA87DB0FDCEDF08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36AF3F83D511035CULL,
		0x0251DCA13EB4CFBDULL,
		0xB9BE1722CFAD3F9AULL,
		0x8506B5AFE817E37EULL,
		0x0248D4F4883339AAULL,
		0x2582A670616A0440ULL,
		0xA3846C299BE7BE96ULL,
		0xFBF637B2E679FB5FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA321AF8A2756C9EBULL,
		0x98EB8F9C82D46198ULL,
		0x62D1F3A828A77DD0ULL,
		0xC0ADBD44BDF8EE46ULL,
		0x4A15847D06E7A731ULL,
		0x6A363AA84A76FF69ULL,
		0x29779AF0EFF39D25ULL,
		0xC04E9F6B8E49FAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27631F5FAC0C4DC3ULL,
		0xA6BEA1C547F0990AULL,
		0x2294F8489FA0FECBULL,
		0xC14EFAD7B10674BCULL,
		0xC0C2554E68299CC7ULL,
		0x5BA199787F91768AULL,
		0x87DBE549B01FC02CULL,
		0xAD0CEC874AB2C7E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BBE902A7B4A7C28ULL,
		0xF22CEDD73AE3C88EULL,
		0x403CFB5F89067F04ULL,
		0xFF5EC26D0CF2798AULL,
		0x89532F2E9EBE0A69ULL,
		0x0E94A12FCAE588DEULL,
		0xA19BB5A73FD3DCF9ULL,
		0x1341B2E443973314ULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x722BD4A1FC1DE8FCULL,
		0x19FC8ADB147041AEULL,
		0xDD0CBB22A609553EULL,
		0x997A6162BE678735ULL,
		0x4273105D309A21E1ULL,
		0x586E5383D58F4A24ULL,
		0x2C43C5693039936EULL,
		0x296B86417DF86908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B933306EA0AF96BULL,
		0x341D7D345751D897ULL,
		0x090D615590791681ULL,
		0x4D1E6DAB2DD75B31ULL,
		0x4E7F90D8C2AD156AULL,
		0x4C01258E1EA8458FULL,
		0xA0B95725F1A33B00ULL,
		0xA5A57C817B559CEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE698A19B1212EF91ULL,
		0xE5DF0DA6BD1E6916ULL,
		0xD3FF59CD15903EBCULL,
		0x4C5BF3B790902C04ULL,
		0xF3F37F846DED0C77ULL,
		0x0C6D2DF5B6E70494ULL,
		0x8B8A6E433E96586EULL,
		0x83C609C002A2CC18ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25EDFDB089353BE3ULL,
		0x52F4ABBC3501A1E2ULL,
		0x342E469CF2F864BDULL,
		0x2F471D80A2E24EC8ULL,
		0x47082EC69A03C3F2ULL,
		0xBDEC820B5FCE5EECULL,
		0xA3C29AF708266248ULL,
		0x4BBD19123F3C66BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD67B069710255E0ULL,
		0xAF27DFB2A127F31EULL,
		0xB69183D2E0FE6908ULL,
		0x08B2BC6D4ECA428AULL,
		0x9462842413AA8453ULL,
		0x8CDC91F56492B0B1ULL,
		0x2951ED12BEFFDDBCULL,
		0x7C7C8E4C4F354960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68864D471832E603ULL,
		0xA3CCCC0993D9AEC3ULL,
		0x7D9CC2CA11F9FBB4ULL,
		0x2694611354180C3DULL,
		0xB2A5AAA286593F9FULL,
		0x310FF015FB3BAE3AULL,
		0x7A70ADE44926848CULL,
		0xCF408AC5F0071D5DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53655471BF8DDB6FULL,
		0x1B4A1F7DB890B671ULL,
		0x62C4C3F0ED0ACAF2ULL,
		0xE30243C9F58F7D1BULL,
		0x7DA3E37D81F72571ULL,
		0x7085D11EC1ED157AULL,
		0x8049E5EC2DE50EA1ULL,
		0xEB77026BC1C7608CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE100865E5841D01ULL,
		0x263BAA690120CA47ULL,
		0xC8159AE4314E8F6EULL,
		0x5B01D8EF61B5E924ULL,
		0xA4D60F227E941661ULL,
		0x57BF7E3504852331ULL,
		0x8F9D707D0DD8AB6BULL,
		0xF827C2652EAF51DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75554C0BDA09BE6EULL,
		0xF50E7514B76FEC29ULL,
		0x9AAF290CBBBC3B83ULL,
		0x88006ADA93D993F6ULL,
		0xD8CDD45B03630F10ULL,
		0x18C652E9BD67F248ULL,
		0xF0AC756F200C6336ULL,
		0xF34F400693180EB0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE928304E5020C832ULL,
		0x9C375B3E80A5B28BULL,
		0x69BC8F6BC6D6D812ULL,
		0x80DB76B0FFB17777ULL,
		0x0CDBCB19E65EBFA7ULL,
		0xEF219AC414664D1AULL,
		0x4E2E6EBF1E3BB1E1ULL,
		0x7E976983D166DD8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517C89637DB70DCAULL,
		0x8B799B103EB0365EULL,
		0x151673BA07D01C00ULL,
		0x956B07B15A556F06ULL,
		0xDAA8ECEE0B1C789FULL,
		0xD3B7992B5CBB7DC6ULL,
		0xCF7C00ABF1B52218ULL,
		0x04166422C8138DBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97ABA6EAD269BA68ULL,
		0x10BDC02E41F57C2DULL,
		0x54A61BB1BF06BC12ULL,
		0xEB706EFFA55C0871ULL,
		0x3232DE2BDB424707ULL,
		0x1B6A0198B7AACF53ULL,
		0x7EB26E132C868FC9ULL,
		0x7A81056109534FCEULL
	}};
	sign = 0;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F70748F269F5EC5ULL,
		0xAEB174FFD62F4E2DULL,
		0x32F520AAE01886B6ULL,
		0xC00AE2682AE357A2ULL,
		0x43A15B7675E0D551ULL,
		0xDDEB2E20EE166713ULL,
		0xA6CF8B11B2794B14ULL,
		0x73270092D05710FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE828D04A95C3293ULL,
		0xD7FB2596150824D5ULL,
		0xD6786C9FD71C7892ULL,
		0x901F30EF35368BF8ULL,
		0xB33836AB2E2AAEF9ULL,
		0xA9C82457A907AB67ULL,
		0x3244E430AC9D0FE7ULL,
		0xB98D7076E1C6AABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60EDE78A7D432C32ULL,
		0xD6B64F69C1272957ULL,
		0x5C7CB40B08FC0E23ULL,
		0x2FEBB178F5ACCBA9ULL,
		0x906924CB47B62658ULL,
		0x342309C9450EBBABULL,
		0x748AA6E105DC3B2DULL,
		0xB999901BEE906644ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E6EFC0418ED0669ULL,
		0x034E379DE2AA23DCULL,
		0x019452E7414AEA13ULL,
		0x8168386AA2FFB885ULL,
		0xAECBD80AF9AACAD9ULL,
		0xC47400C2F8A187B1ULL,
		0x37D273D2F0673F0DULL,
		0xDA9C8951A7F86DE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59131CC00AD1C0B8ULL,
		0xAF7A00A82598F50FULL,
		0x424B2BC84BB46F4BULL,
		0x20E4E494F7E3A1F4ULL,
		0xCA5A94DC2BB36422ULL,
		0x1EBFEDBFD314143BULL,
		0xF89E62F77BFF213CULL,
		0x47A1D8EDCD6EA59BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x455BDF440E1B45B1ULL,
		0x53D436F5BD112ECDULL,
		0xBF49271EF5967AC7ULL,
		0x608353D5AB1C1690ULL,
		0xE471432ECDF766B7ULL,
		0xA5B41303258D7375ULL,
		0x3F3410DB74681DD1ULL,
		0x92FAB063DA89C84AULL
	}};
	sign = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADF47564F575BD93ULL,
		0x82B3BCCEFEEE1ABCULL,
		0x8E265CC32E4AA209ULL,
		0x2B625EBB769103C6ULL,
		0x1FEEE93CBE440064ULL,
		0x4FB38FB7EBFC8961ULL,
		0x696DB2DED2250212ULL,
		0xCDB5DF2E5FCAA2DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA988145BA570EF37ULL,
		0x54BC4DC0F9399D3EULL,
		0xC2B63757817A8999ULL,
		0x430B5F8623AFB32AULL,
		0xAC317C28772A60C9ULL,
		0x8343E530ED49B389ULL,
		0x40084F87A1273552ULL,
		0x02F653E877907AE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x046C61095004CE5CULL,
		0x2DF76F0E05B47D7EULL,
		0xCB70256BACD01870ULL,
		0xE856FF3552E1509BULL,
		0x73BD6D1447199F9AULL,
		0xCC6FAA86FEB2D5D7ULL,
		0x2965635730FDCCBFULL,
		0xCABF8B45E83A27FCULL
	}};
	sign = 0;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x182EE68F1A8FB13AULL,
		0x8808AFB5E7C31788ULL,
		0xC4AABF2A852B0C0AULL,
		0x356706BB69BC477FULL,
		0xCE94C7FF07DA8624ULL,
		0x302031A5A6BA7CA7ULL,
		0xED830D9DFA6F84E9ULL,
		0xC57C48C82C4A563AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1884B12B8BB5C740ULL,
		0x27BF58A9C396B6C8ULL,
		0x82ADE6E57D39B443ULL,
		0x25BC8043D61DA4D3ULL,
		0x4D5B0336F0571B66ULL,
		0xA4993F637EC8D94FULL,
		0xC91B52B4291BC0EAULL,
		0x0DE66BC0068A3893ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFAA35638ED9E9FAULL,
		0x6049570C242C60BFULL,
		0x41FCD84507F157C7ULL,
		0x0FAA8677939EA2ACULL,
		0x8139C4C817836ABEULL,
		0x8B86F24227F1A358ULL,
		0x2467BAE9D153C3FEULL,
		0xB795DD0825C01DA7ULL
	}};
	sign = 0;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8049B9F2446C602DULL,
		0x00F1E25F3CA559C3ULL,
		0x5C872BE0F876E335ULL,
		0xAA0E6F8510B45452ULL,
		0x54FB11A2A0D6E4FDULL,
		0x0AD8B68D6298DBC3ULL,
		0x5AD318608234B300ULL,
		0xC24D77C0D7DC2BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x010B15842BD302F3ULL,
		0x22431344D0BDE967ULL,
		0xB709E4801BC996E2ULL,
		0xF6491E5779D02713ULL,
		0xEF323D9F981C31E4ULL,
		0x4C17C8CA5496499AULL,
		0xF1525CD9B0FDDB7DULL,
		0x5C05B8A87A710228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F3EA46E18995D3AULL,
		0xDEAECF1A6BE7705CULL,
		0xA57D4760DCAD4C52ULL,
		0xB3C5512D96E42D3EULL,
		0x65C8D40308BAB318ULL,
		0xBEC0EDC30E029228ULL,
		0x6980BB86D136D782ULL,
		0x6647BF185D6B29B6ULL
	}};
	sign = 0;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5673767DE9C423F1ULL,
		0x5803907185C6D1F6ULL,
		0xE740F64F2B275C6BULL,
		0xD321AE7BEAC6B821ULL,
		0x68B94FD539066646ULL,
		0x9DD3591B2506B2F4ULL,
		0xB25F7170C7F9C402ULL,
		0x92E4FF3FD408BEDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FEC3CCE377FCC7ULL,
		0xD9A883EDB97F082FULL,
		0x3E59E47BA6D50969ULL,
		0xD9C7071C8D73C917ULL,
		0xCDEC43F93C024DBBULL,
		0xBF1E7E64F252E854ULL,
		0xBD92D35BAEDB3A92ULL,
		0xFB8AB55879ADCD79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC74B2B1064C272AULL,
		0x7E5B0C83CC47C9C6ULL,
		0xA8E711D384525301ULL,
		0xF95AA75F5D52EF0AULL,
		0x9ACD0BDBFD04188AULL,
		0xDEB4DAB632B3CA9FULL,
		0xF4CC9E15191E896FULL,
		0x975A49E75A5AF165ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC7671479768C274ULL,
		0x4D4A03F7840F40E7ULL,
		0x4E19F476881EECE6ULL,
		0xA94707DDD8AB0CBAULL,
		0x9B6323636C839007ULL,
		0xF2FF0099A5FFE4A1ULL,
		0xE9C66210E3FB142BULL,
		0x84DC9144E18C63A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B1B1B17359E565ULL,
		0x4D4CB13262AFA0E6ULL,
		0x42450D22B2E00020ULL,
		0xC24C247F70570CF3ULL,
		0xD0308EB266402ECCULL,
		0x6C929A4CD7A90403ULL,
		0x20E047DF12E69AA8ULL,
		0x04D993D9ACC49A7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18C4BF96240EDD0FULL,
		0xFFFD52C5215FA001ULL,
		0x0BD4E753D53EECC5ULL,
		0xE6FAE35E6853FFC7ULL,
		0xCB3294B10643613AULL,
		0x866C664CCE56E09DULL,
		0xC8E61A31D1147983ULL,
		0x8002FD6B34C7C925ULL
	}};
	sign = 0;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1506C07CB2D4F1AULL,
		0x551D1806BBC116DCULL,
		0x5D4B343D2DB36995ULL,
		0xEF50A5214FBC67E3ULL,
		0x7E1C0541440790BEULL,
		0x9537FA02D585BEC9ULL,
		0xAAA838CA4A0FDDDBULL,
		0x92C272FFB78A9C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x793C4D2A687FA091ULL,
		0xA67A4BBF78242553ULL,
		0x50F682E0EEC7797BULL,
		0xCE4A6BFB146DFD0AULL,
		0x0F79698EC2416B97ULL,
		0xEF03C49D7E4FE6FBULL,
		0x0F3EB96B6A3AE723ULL,
		0x8415B334D1FD43ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48141EDD62ADAE89ULL,
		0xAEA2CC47439CF189ULL,
		0x0C54B15C3EEBF019ULL,
		0x210639263B4E6AD9ULL,
		0x6EA29BB281C62527ULL,
		0xA63435655735D7CEULL,
		0x9B697F5EDFD4F6B7ULL,
		0x0EACBFCAE58D5824ULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8661C79427DAF86FULL,
		0x8C902AFD215C5FF4ULL,
		0xC0F1651E75E22845ULL,
		0x78B631CC770C9F4EULL,
		0x6AA00F5878B80523ULL,
		0x0EE21EE88F40AF3BULL,
		0xEF14FBFCA40C3CC5ULL,
		0xA1B56AEB91FCA146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A61E6C715325B2ULL,
		0x7A3F3D49E73C0F5BULL,
		0x9BC434FBF81A518BULL,
		0xB4C7A7C71C36E6C9ULL,
		0xB427896D01B3D8D0ULL,
		0xB5548B4741CD2A17ULL,
		0x86491AD15788EEF7ULL,
		0x7816A7C8E5C49564ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3BBA927B687D2BDULL,
		0x1250EDB33A205098ULL,
		0x252D30227DC7D6BAULL,
		0xC3EE8A055AD5B885ULL,
		0xB67885EB77042C52ULL,
		0x598D93A14D738523ULL,
		0x68CBE12B4C834DCDULL,
		0x299EC322AC380BE2ULL
	}};
	sign = 0;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x654D9AF816C43D33ULL,
		0x5F3625F7EC92872AULL,
		0x05D7C0CE72A31C1DULL,
		0xF001F12877471141ULL,
		0x301B6F20C550703FULL,
		0x9782FF58268991E0ULL,
		0x94CB24739D62090EULL,
		0x51F83599F7A7BED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470DB2B285320C24ULL,
		0x40D2CE6E339F1D1AULL,
		0xD207167DB1D744C4ULL,
		0xB68FC1169C432C3DULL,
		0xD07B65812C543AD0ULL,
		0x623E5AA90BF84158ULL,
		0x7211E3E1589D6018ULL,
		0x164D8E84AAB6DAA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E3FE8459192310FULL,
		0x1E635789B8F36A10ULL,
		0x33D0AA50C0CBD759ULL,
		0x39723011DB03E503ULL,
		0x5FA0099F98FC356FULL,
		0x3544A4AF1A915087ULL,
		0x22B9409244C4A8F6ULL,
		0x3BAAA7154CF0E433ULL
	}};
	sign = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8342292DA8B9BD2DULL,
		0xA625D3D2AACD3DE3ULL,
		0x1E759A836CBFB792ULL,
		0xB87DBC40EA318BCAULL,
		0xE3570C0708F8936DULL,
		0x723153B90D3EDD58ULL,
		0xC4E7D88CE49F1D02ULL,
		0xC2DA97FCBAF16E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69AF533761864094ULL,
		0x03287CE822F42ABBULL,
		0xF51F36DD1A5F58DFULL,
		0x5EF2C2962E5A2005ULL,
		0x100E52B6FD9B8F89ULL,
		0x3A0ED558F74DBAD4ULL,
		0x12AB0DDA65C4E1DFULL,
		0x316F824F48CEE800ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1992D5F647337C99ULL,
		0xA2FD56EA87D91328ULL,
		0x295663A652605EB3ULL,
		0x598AF9AABBD76BC4ULL,
		0xD348B9500B5D03E4ULL,
		0x38227E6015F12284ULL,
		0xB23CCAB27EDA3B23ULL,
		0x916B15AD7222866CULL
	}};
	sign = 0;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x480BE9C13BA480C7ULL,
		0x41DC8D141007CAA3ULL,
		0x0B0E28334F5DE26EULL,
		0x3818CCCBAFC918ACULL,
		0xBBA0DAAEA72E0162ULL,
		0x3BBF7278FC1B0148ULL,
		0x3BF31EB266313E48ULL,
		0x05F42365C8CDFFE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA5F3B90E526A1AULL,
		0xE9485C82520C7325ULL,
		0xA8A500D2E88F801CULL,
		0x04ADF096B39565BFULL,
		0x4837B37A23746615ULL,
		0xB31D5801216D81E9ULL,
		0x82B5BC3E846D7707ULL,
		0x83AA968BAB2B8E1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B65F6082D5216ADULL,
		0x58943091BDFB577EULL,
		0x6269276066CE6251ULL,
		0x336ADC34FC33B2ECULL,
		0x7369273483B99B4DULL,
		0x88A21A77DAAD7F5FULL,
		0xB93D6273E1C3C740ULL,
		0x82498CDA1DA271CCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF9712199C7A1158ULL,
		0xF529FFF40315C47AULL,
		0xE67559570BCFFC48ULL,
		0x831EEAA626A6B096ULL,
		0x135F4A7285313FC5ULL,
		0x41D3E56422110F63ULL,
		0x698DEC9A97217E0BULL,
		0xA7A6FDB4D1B75189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA76F64D0D646FD4ULL,
		0xCAEFCB0DF34B86ADULL,
		0x70D2122FB8C99E29ULL,
		0x3C27A46739CA2AE6ULL,
		0x4DAB696E7B5D2D1AULL,
		0xCEDD08AD4E7D55A8ULL,
		0x8E14590FFA3CC07BULL,
		0x2FADB89BED9C6FAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45201BCC8F15A184ULL,
		0x2A3A34E60FCA3DCDULL,
		0x75A3472753065E1FULL,
		0x46F7463EECDC85B0ULL,
		0xC5B3E10409D412ABULL,
		0x72F6DCB6D393B9BAULL,
		0xDB79938A9CE4BD8FULL,
		0x77F94518E41AE1DAULL
	}};
	sign = 0;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5453354B7F138DFCULL,
		0xCC5934BF463ADA2BULL,
		0x943A43A94B51C146ULL,
		0x038F4A5E2BD1D754ULL,
		0xBF683F75CA1C67C3ULL,
		0x7DF72FC7E81F3BB5ULL,
		0x7F94BC4217573771ULL,
		0x10682938D65C794BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46307571177B5F49ULL,
		0xC79638C86CDC0523ULL,
		0x07031EE058D2845BULL,
		0xDFDBD496B93D87E1ULL,
		0xAC71A4E6C302E8F5ULL,
		0x672A6DB27E47D408ULL,
		0x786ED786C2AC451DULL,
		0x234CC76526DB6575ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E22BFDA67982EB3ULL,
		0x04C2FBF6D95ED508ULL,
		0x8D3724C8F27F3CEBULL,
		0x23B375C772944F73ULL,
		0x12F69A8F07197ECDULL,
		0x16CCC21569D767ADULL,
		0x0725E4BB54AAF254ULL,
		0xED1B61D3AF8113D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x433404CA680C61E3ULL,
		0x9EE7B5FA9B511DD0ULL,
		0x560F794F77A52556ULL,
		0x74EFFEA04DA68CBEULL,
		0xE406BC627475E17EULL,
		0x965EA7D6638251C1ULL,
		0x6986DD3445069A12ULL,
		0x27CE7E7DB2AA0F21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E1DC1C9750A495ULL,
		0x1E985A940DFB3D2BULL,
		0xFB73FC53626BFB71ULL,
		0x652CA8C5EF57E683ULL,
		0xFB4E1871917790B5ULL,
		0xCCAB7A488A5F96E5ULL,
		0x9719689BE5DC4778ULL,
		0x458B3AE6FC82CBC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB25228ADD0BBBD4EULL,
		0x804F5B668D55E0A4ULL,
		0x5A9B7CFC153929E5ULL,
		0x0FC355DA5E4EA63AULL,
		0xE8B8A3F0E2FE50C9ULL,
		0xC9B32D8DD922BADBULL,
		0xD26D74985F2A5299ULL,
		0xE2434396B627435FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45CDCA52A4F1CC52ULL,
		0x9D68D292643F02C2ULL,
		0x8CF790E9973AA2F4ULL,
		0x5AF7F1A6442B89D8ULL,
		0x80089AF1FBDAD1A2ULL,
		0x7D5DDA8F667095B5ULL,
		0x2B67481C800F0F25ULL,
		0x725EBE6CCDF2E987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA08808C6EB3D56ULL,
		0xAA70802457CFED6EULL,
		0xC9032CCB741A59B3ULL,
		0xE923C7AF2B8892F3ULL,
		0xC63A1E290CCA5451ULL,
		0x4C128941AC5CE72DULL,
		0xC5FBF8E8143FAF5EULL,
		0x0F1DC1664F808276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x362D4249DE068EFCULL,
		0xF2F8526E0C6F1554ULL,
		0xC3F4641E23204940ULL,
		0x71D429F718A2F6E4ULL,
		0xB9CE7CC8EF107D50ULL,
		0x314B514DBA13AE87ULL,
		0x656B4F346BCF5FC7ULL,
		0x6340FD067E726710ULL
	}};
	sign = 0;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5999F95B45EF0F00ULL,
		0x6F0A6A86C5CBC92FULL,
		0x4F7FC3BA98965185ULL,
		0x20DDCA22FE120BC8ULL,
		0x9285F52AD919479EULL,
		0xD201AE5F77E7BF5FULL,
		0x71D09CE2980D9A60ULL,
		0x2883C121D7E7E8FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x327D7171A8F21491ULL,
		0x839BD406B827E567ULL,
		0x18E5EDB5C37A26EDULL,
		0x4C22D580CAED5389ULL,
		0xACF4B416E61F90B0ULL,
		0x4350F4385A5FF09AULL,
		0x1CAFF9FD1B632F84ULL,
		0xC7BE0B0082586F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x271C87E99CFCFA6FULL,
		0xEB6E96800DA3E3C8ULL,
		0x3699D604D51C2A97ULL,
		0xD4BAF4A23324B83FULL,
		0xE5914113F2F9B6EDULL,
		0x8EB0BA271D87CEC4ULL,
		0x5520A2E57CAA6ADCULL,
		0x60C5B621558F79B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86CA49D71E0C7B7EULL,
		0xB90BFC1A29A592CAULL,
		0x52A3B22DE7FA2FF1ULL,
		0x72EEFC1AE5CEAC48ULL,
		0x596863DFD3766114ULL,
		0x5E6F5F09BF4BD46CULL,
		0x91008B08691159FCULL,
		0xCDC7195B777B6E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F8E32593B756F3CULL,
		0x451888226D94F938ULL,
		0x82AFBE914C7892EBULL,
		0x10BA4CA9082323EEULL,
		0xF1BCE53C5669C54AULL,
		0x015D465457DF4B82ULL,
		0x378CEA936B67D313ULL,
		0x9406D79F7FDDA0BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x573C177DE2970C42ULL,
		0x73F373F7BC109992ULL,
		0xCFF3F39C9B819D06ULL,
		0x6234AF71DDAB8859ULL,
		0x67AB7EA37D0C9BCAULL,
		0x5D1218B5676C88E9ULL,
		0x5973A074FDA986E9ULL,
		0x39C041BBF79DCDC4ULL
	}};
	sign = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC3589F9F61EA60EULL,
		0x15B6A79D92B3228BULL,
		0xAC62B817C49CD39DULL,
		0x4C2C9750BA3F7D3BULL,
		0xE6879FF7C6B02D97ULL,
		0xC76ABD7472291F2AULL,
		0x4D45496EA09DC465ULL,
		0x26C099A0688854CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6750E09672F3DDB9ULL,
		0xD3E260651521B589ULL,
		0x553D072D6D52EC46ULL,
		0xF2931CCA79C4F262ULL,
		0x87F3B92E54BC274AULL,
		0x95077C371E1C67BCULL,
		0x3B01A659AD282CEEULL,
		0xEB5FEC58D18FF236ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74E4A963832AC855ULL,
		0x41D447387D916D02ULL,
		0x5725B0EA5749E756ULL,
		0x59997A86407A8AD9ULL,
		0x5E93E6C971F4064CULL,
		0x3263413D540CB76EULL,
		0x1243A314F3759777ULL,
		0x3B60AD4796F86294ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x030DC46CDB24A9C4ULL,
		0xCE32A37918DAC879ULL,
		0xD249082463E117BBULL,
		0x27C00B2E84E3BF7AULL,
		0x8C51175F288DC382ULL,
		0xB3FC800C9A1E4B85ULL,
		0x86416023BB73F18AULL,
		0x7FB6B71F02867BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1043B5A782719B0CULL,
		0xE47E26CA89B82D5AULL,
		0x06EC51C997C49FA3ULL,
		0x3A8C27A571129447ULL,
		0x0A2E2DD4776DD38FULL,
		0x1D01E7C8AC1C5844ULL,
		0xDA212F43571C9612ULL,
		0xD83620D27E989E51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2CA0EC558B30EB8ULL,
		0xE9B47CAE8F229B1EULL,
		0xCB5CB65ACC1C7817ULL,
		0xED33E38913D12B33ULL,
		0x8222E98AB11FEFF2ULL,
		0x96FA9843EE01F341ULL,
		0xAC2030E064575B78ULL,
		0xA780964C83EDDD59ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F75161FB553FAC5ULL,
		0xE892FBF6A547DF5CULL,
		0x8D2CA6F460FAA1E8ULL,
		0x442F39A96079788AULL,
		0x5CBB439DC6BD637AULL,
		0xF1FD1E12B8E79F9FULL,
		0xACABA674385062ABULL,
		0xFCF24C78373EB73FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB459E4B8877CAA77ULL,
		0x4CEBD184DF9185A8ULL,
		0xD3D83B36FF0587B4ULL,
		0x6CD3FFC2962C2CBEULL,
		0x03F4E49629E28084ULL,
		0x722BD57CA31B53C0ULL,
		0x92381C52FE4B86FBULL,
		0x38624EE1FA33688FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB1B31672DD7504EULL,
		0x9BA72A71C5B659B3ULL,
		0xB9546BBD61F51A34ULL,
		0xD75B39E6CA4D4BCBULL,
		0x58C65F079CDAE2F5ULL,
		0x7FD1489615CC4BDFULL,
		0x1A738A213A04DBB0ULL,
		0xC48FFD963D0B4EB0ULL
	}};
	sign = 0;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE23D123845547C8AULL,
		0xA5B505DEC33EB742ULL,
		0xB203D88214D7D81FULL,
		0x6297A6FDD18ED936ULL,
		0xCEC654D05E5DEDB7ULL,
		0xED6808189D99E0BCULL,
		0x4CA52168D2EFABB0ULL,
		0xF3E5464DC0A537AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6046D4904E51869ULL,
		0xE8BBAB6255E2610EULL,
		0xC16E4CF69ABF64E7ULL,
		0xDD6E9E0A87E96E39ULL,
		0xF0F4DD24A2578CB9ULL,
		0xA00903678E0B68E1ULL,
		0x24C47B1D45F3E2DCULL,
		0x38042BFB7A1B9105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC38A4EF406F6421ULL,
		0xBCF95A7C6D5C5633ULL,
		0xF0958B8B7A187337ULL,
		0x852908F349A56AFCULL,
		0xDDD177ABBC0660FDULL,
		0x4D5F04B10F8E77DAULL,
		0x27E0A64B8CFBC8D4ULL,
		0xBBE11A524689A6A5ULL
	}};
	sign = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE23A41D74FC36DF1ULL,
		0xC38FD0AE1A39CDF4ULL,
		0xBFFD6CDB22FD79AAULL,
		0x516DCD203DE1D95BULL,
		0x3EC147CFEEFE6AF9ULL,
		0x8A9F27BEE1DE459CULL,
		0xE1A9C6C17FA81ED2ULL,
		0x37C4BD5B95A3BC5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E955A629666E357ULL,
		0x5963095DFB824249ULL,
		0x6F905CB8D4C82C9BULL,
		0xDB2B4516E4AEBBABULL,
		0x33CA0B6EBE355FABULL,
		0x211B9E9C378772D9ULL,
		0x98E38C962756A04CULL,
		0xBBF43F3A94D3C67AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3A4E774B95C8A9AULL,
		0x6A2CC7501EB78BABULL,
		0x506D10224E354D0FULL,
		0x7642880959331DB0ULL,
		0x0AF73C6130C90B4DULL,
		0x69838922AA56D2C3ULL,
		0x48C63A2B58517E86ULL,
		0x7BD07E2100CFF5E0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD66D1B1267D9CB65ULL,
		0x91488EEFA11B13C4ULL,
		0x81E8458D82BE3D35ULL,
		0xD561AD816268B101ULL,
		0xE4FCA6044DCD866FULL,
		0x8D1F9EC984178C3BULL,
		0x5D34C533CA7BBAA5ULL,
		0xEDF9274F0D44A192ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB42A569A479C831ULL,
		0xB17B34676E931954ULL,
		0xD4A73EF1B0030A87ULL,
		0x700C891DE54DAEB0ULL,
		0x7D1FB3CEF725710BULL,
		0xD10C95F25432A559ULL,
		0x62BBF9B770B5E425ULL,
		0x65C640A74B322149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB2A75A8C3600334ULL,
		0xDFCD5A883287FA6FULL,
		0xAD41069BD2BB32ADULL,
		0x655524637D1B0250ULL,
		0x67DCF23556A81564ULL,
		0xBC1308D72FE4E6E2ULL,
		0xFA78CB7C59C5D67FULL,
		0x8832E6A7C2128048ULL
	}};
	sign = 0;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADA30F541A4CD66FULL,
		0x3F5B6A6AC1BF2723ULL,
		0x1A892E3B9CA32E25ULL,
		0x5494501B1E91C017ULL,
		0xB6E54E541179407BULL,
		0xD0EF1F9AC1A1B9A7ULL,
		0xBBD3A359C2E7A173ULL,
		0x8156DA6471F01E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4DEEAA1361E9E36ULL,
		0x5199231F57ED15E0ULL,
		0x5F6B90CFAE79302BULL,
		0x4C38873801518DE0ULL,
		0x9EB0C3991B876EE6ULL,
		0x80987708240F123AULL,
		0x3F43944296600BF8ULL,
		0x22B7F2A384FBBE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8C424B2E42E3839ULL,
		0xEDC2474B69D21142ULL,
		0xBB1D9D6BEE29FDF9ULL,
		0x085BC8E31D403236ULL,
		0x18348ABAF5F1D195ULL,
		0x5056A8929D92A76DULL,
		0x7C900F172C87957BULL,
		0x5E9EE7C0ECF45FFCULL
	}};
	sign = 0;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE71D6A4B7A5EA80ULL,
		0xE7490735C09BD9BBULL,
		0xEA772C16F7022F82ULL,
		0x1B61C9FF0DCC4075ULL,
		0x19960FB193FCAF31ULL,
		0x9DC32F90705BF85CULL,
		0x3983A0C966A1EC21ULL,
		0x1660F38D887187EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B97F3D7CA076BAULL,
		0xC4F95A42FC5B7B5DULL,
		0xE2CA313B9CCF84C0ULL,
		0x78E8457BD465430BULL,
		0x6863B02D43FF19C9ULL,
		0x20E6B976D12F83B6ULL,
		0xB87FE6CD810579AAULL,
		0x2DD2BCC9C2150D0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18B857673B0573C6ULL,
		0x224FACF2C4405E5EULL,
		0x07ACFADB5A32AAC2ULL,
		0xA27984833966FD6AULL,
		0xB1325F844FFD9567ULL,
		0x7CDC76199F2C74A5ULL,
		0x8103B9FBE59C7277ULL,
		0xE88E36C3C65C7AE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x256B226960EE014CULL,
		0x32F574B59CC998CDULL,
		0x2D0074FC044907A4ULL,
		0x1F5B9372252DAAC8ULL,
		0x181F58F160065468ULL,
		0x0BD77555FE2925E0ULL,
		0xC0C281DDA35262ACULL,
		0x424CF024844E881EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436DFEC79530AB5FULL,
		0x511402E9BF2A71D8ULL,
		0x727728AF4F374A0DULL,
		0xC50A060F5CD15ADBULL,
		0x2CC22EE7659975F7ULL,
		0x5143BCE1CBF4859CULL,
		0x799A9C15D5720B33ULL,
		0xD46F9F405BA9EC85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1FD23A1CBBD55EDULL,
		0xE1E171CBDD9F26F4ULL,
		0xBA894C4CB511BD96ULL,
		0x5A518D62C85C4FECULL,
		0xEB5D2A09FA6CDE70ULL,
		0xBA93B8743234A043ULL,
		0x4727E5C7CDE05778ULL,
		0x6DDD50E428A49B99ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD532AC7A321B4B8ULL,
		0x9ED861C287832E6FULL,
		0x5BC8EDFE05148BE0ULL,
		0xDC0E97DF7BAA1E05ULL,
		0x7CECDB1B4F863776ULL,
		0x23ACB8E10301A28CULL,
		0x95F2BE9AC5BF118EULL,
		0xAABEAFD54E5C01EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E77173598358C1CULL,
		0x4210ECF23A03F821ULL,
		0xF21ECECDCAEECC4DULL,
		0x634ACC61FC856766ULL,
		0x9FCE7073262BA5FBULL,
		0xB80A0AD4D62C8BD5ULL,
		0x1DD152AE5ECD6ACDULL,
		0x19868F32590F8A3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EDC13920AEC289CULL,
		0x5CC774D04D7F364EULL,
		0x69AA1F303A25BF93ULL,
		0x78C3CB7D7F24B69EULL,
		0xDD1E6AA8295A917BULL,
		0x6BA2AE0C2CD516B6ULL,
		0x78216BEC66F1A6C0ULL,
		0x913820A2F54C77ACULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC079601F757DC62ULL,
		0x2D75C54D081377D7ULL,
		0x563346AA8700D7BBULL,
		0x168119D4099E0366ULL,
		0x276360BF6FB924DEULL,
		0x0EB6E14719CE3AEBULL,
		0x0BD3632D822F7FC2ULL,
		0xAD605DDB5877FDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC290BDE9E0DC562AULL,
		0xA911BE0E92B24B85ULL,
		0x126007EFBEAC0637ULL,
		0x97573FE89C16CD94ULL,
		0xA7506FFFA5BAADD0ULL,
		0x3B21A84F9421CD05ULL,
		0xEBB20899400101F9ULL,
		0x9B7F4E82D20B839DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE976D818167B8638ULL,
		0x8464073E75612C51ULL,
		0x43D33EBAC854D183ULL,
		0x7F29D9EB6D8735D2ULL,
		0x8012F0BFC9FE770DULL,
		0xD39538F785AC6DE5ULL,
		0x20215A94422E7DC8ULL,
		0x11E10F58866C7A12ULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB796CE35EE91D27ULL,
		0x8B96E4FC109B5A71ULL,
		0xDC1CC5E2E51B3928ULL,
		0x6D61F6A62CC8C52CULL,
		0x08749C6D5EAA6CC8ULL,
		0x206A1ACAB5A3DC80ULL,
		0x2E7C0FF3B2E2E235ULL,
		0x351372744F5963CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x015E938408A7A53CULL,
		0xC121F8D1B5B85429ULL,
		0xA8FBDFB494C0FFF8ULL,
		0xEAC01F70DB20D522ULL,
		0x70D6D47E9FC7CE44ULL,
		0xFB7C20E2133CBDC9ULL,
		0xF0DBD7666D26A54FULL,
		0xA7B56407490152F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA1AD95F564177EBULL,
		0xCA74EC2A5AE30648ULL,
		0x3320E62E505A392FULL,
		0x82A1D73551A7F00AULL,
		0x979DC7EEBEE29E83ULL,
		0x24EDF9E8A2671EB6ULL,
		0x3DA0388D45BC3CE5ULL,
		0x8D5E0E6D065810D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62773E196F3C9586ULL,
		0xE364556E5FA5E5F6ULL,
		0xDBD05C7F5D14D881ULL,
		0xABBAF6C3E15E65B6ULL,
		0xEABF31774C5A50FBULL,
		0x1CF312BE592F62F6ULL,
		0xD2091D2C7CB88DE4ULL,
		0xEE5D287241076FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03856DF3267CA389ULL,
		0xC554B1AFCDF2CC75ULL,
		0xB4AD36BDEC7389DDULL,
		0x44A1FEF2626E7084ULL,
		0xA51CE54A1B0E66B8ULL,
		0xCE9B48CF9DB3DCB0ULL,
		0x7785EA9001B8E009ULL,
		0x31E0747E376D6C2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EF1D02648BFF1FDULL,
		0x1E0FA3BE91B31981ULL,
		0x272325C170A14EA4ULL,
		0x6718F7D17EEFF532ULL,
		0x45A24C2D314BEA43ULL,
		0x4E57C9EEBB7B8646ULL,
		0x5A83329C7AFFADDAULL,
		0xBC7CB3F4099A0396ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75C2A1EFB0EF176AULL,
		0x23F428DEC5466FEFULL,
		0x9DB4154552086C4AULL,
		0x62A4C3899518F564ULL,
		0xD2EE8E18A1F078D7ULL,
		0xAFCD149172E4072DULL,
		0x7E76A4F0196E7A76ULL,
		0xA2846681ED1DA6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42FD0DB7DAF7B38ULL,
		0xAA2F4AA7C210D323ULL,
		0xEB410B94378C5290ULL,
		0x805461ED4CB47924ULL,
		0xAE387C09067F2898ULL,
		0x41FA5011BAFAD149ULL,
		0x55EA10F86A621991ULL,
		0x89E93B1C3171D155ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8192D114333F9C32ULL,
		0x79C4DE3703359CCBULL,
		0xB27309B11A7C19B9ULL,
		0xE250619C48647C3FULL,
		0x24B6120F9B71503EULL,
		0x6DD2C47FB7E935E4ULL,
		0x288C93F7AF0C60E5ULL,
		0x189B2B65BBABD58AULL
	}};
	sign = 0;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97368F724C6907A9ULL,
		0xF0BD078B0598BF7AULL,
		0x50CBCAE51A59152AULL,
		0x54121AA9242E6E92ULL,
		0xADB7E6B06FA66429ULL,
		0x6AEDD30F874137FAULL,
		0xCEA5EDC7D1FE206EULL,
		0x5A8426346B319794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0687032447F1A59ULL,
		0xE94CDE886BFBF236ULL,
		0x62260F5B77557515ULL,
		0x44D8C967F816282EULL,
		0xA90965400080DD77ULL,
		0xC5ED881FC8EFDDA7ULL,
		0xD9B947B428E0B81EULL,
		0x5D47E6319598CA38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6CE1F4007E9ED50ULL,
		0x07702902999CCD43ULL,
		0xEEA5BB89A303A015ULL,
		0x0F3951412C184663ULL,
		0x04AE81706F2586B2ULL,
		0xA5004AEFBE515A53ULL,
		0xF4ECA613A91D684FULL,
		0xFD3C4002D598CD5BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2741F185E5AF07AULL,
		0x557E7CDFA98AF009ULL,
		0x7D0C1DEB79F72797ULL,
		0xF6677A75833F243EULL,
		0x299808692DF11AF4ULL,
		0x12AACAD1FD5A8DCEULL,
		0x3EBEB36415BF7A17ULL,
		0xF17E33D756A9BD18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E54836D8967942ULL,
		0x0B12C80152C70DE7ULL,
		0x9BA1B7986BC1738AULL,
		0x0FF0498469206CA0ULL,
		0x5A92179BD51BEE4CULL,
		0xADEC7683D19D724AULL,
		0xED41DD34193BE03AULL,
		0x66EA17353E45FD67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB8ED6E185C47738ULL,
		0x4A6BB4DE56C3E221ULL,
		0xE16A66530E35B40DULL,
		0xE67730F11A1EB79DULL,
		0xCF05F0CD58D52CA8ULL,
		0x64BE544E2BBD1B83ULL,
		0x517CD62FFC8399DCULL,
		0x8A941CA21863BFB0ULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x305C895BB8D95957ULL,
		0x1D53E75854EA0831ULL,
		0xDCD783918BA40AB4ULL,
		0x49377A9CAE8881D8ULL,
		0x51F60762EB97FA38ULL,
		0xCEBCDCB6B91EA7E3ULL,
		0x39D8CE0A8F673417ULL,
		0x0E295D157EDA5B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF7F344C6FA1D097ULL,
		0x344CA81F15028ADEULL,
		0x87C82FBA0D99A324ULL,
		0x96BCF9F3818F4B58ULL,
		0x2718EA9C5DCB71C8ULL,
		0x3078AB35A5E06B27ULL,
		0x2A0BC561ED5B09BDULL,
		0xCF9C24A6797EA27DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70DD550F493788C0ULL,
		0xE9073F393FE77D52ULL,
		0x550F53D77E0A678FULL,
		0xB27A80A92CF93680ULL,
		0x2ADD1CC68DCC886FULL,
		0x9E443181133E3CBCULL,
		0x0FCD08A8A20C2A5AULL,
		0x3E8D386F055BB901ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9774F2FA513416EULL,
		0x4BEFDC567E373ACBULL,
		0xDEE12A2320FBEFF2ULL,
		0xEBAD9FE142A8ACC0ULL,
		0x9CCE4CAFB652F5E8ULL,
		0xE518E71E7B3B7ED8ULL,
		0xB4C4E9ABCACE0FD6ULL,
		0x47912819C82039F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A2C7225930ED4BULL,
		0x7FA8F76E6A7C05BEULL,
		0xAA3A4E816E86479EULL,
		0x4F9B23DF385A5E16ULL,
		0x6C34094FBD7A842CULL,
		0x6FC679BE5C8F00F8ULL,
		0x27EEBB7D1DED249BULL,
		0x9CDB20D99EC204F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6D4880D4BE25423ULL,
		0xCC46E4E813BB350CULL,
		0x34A6DBA1B275A853ULL,
		0x9C127C020A4E4EAAULL,
		0x309A435FF8D871BCULL,
		0x75526D601EAC7DE0ULL,
		0x8CD62E2EACE0EB3BULL,
		0xAAB60740295E34FBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B74CCBCFB701E97ULL,
		0xEB8017A4E6A546CDULL,
		0x602E6F0CD49F2E95ULL,
		0x38EBB70F529044B0ULL,
		0x4B4E0E8B81832099ULL,
		0xA19492A9DBC09078ULL,
		0x8DB9A12EC4EC65A0ULL,
		0x864C19696EC1D89EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5564C961605D9D6ULL,
		0x6A8B9770F62ABF96ULL,
		0xB7A372F2348E4CF2ULL,
		0xB95C5B725B597316ULL,
		0xC6DD974B06E95AFBULL,
		0x34F4FC1D6B866AA1ULL,
		0x758B9D8366EB031CULL,
		0x3D3B8CB14255933DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x961E8026E56A44C1ULL,
		0x80F48033F07A8736ULL,
		0xA88AFC1AA010E1A3ULL,
		0x7F8F5B9CF736D199ULL,
		0x847077407A99C59DULL,
		0x6C9F968C703A25D6ULL,
		0x182E03AB5E016284ULL,
		0x49108CB82C6C4561ULL
	}};
	sign = 0;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1779D44FDAE2ADB5ULL,
		0x1D9A41DC9085A930ULL,
		0xD7D2FBD11C593746ULL,
		0xA82C39A7525589E8ULL,
		0x7CA905F89D6055BAULL,
		0xBEBC2D6E285455F9ULL,
		0xED643549824D04F3ULL,
		0x8CAA692DA4A2B52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4103D1AEE04F055ULL,
		0xB0E10EBACF8D9837ULL,
		0xCFD7DD6F26454CC4ULL,
		0xCD75A341D1A91734ULL,
		0x15D551F38403FC3DULL,
		0x27AD5A789D507210ULL,
		0x21DDECDFBA6EB700ULL,
		0xDC6856BFF740DFF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23699734ECDDBD60ULL,
		0x6CB93321C0F810F8ULL,
		0x07FB1E61F613EA81ULL,
		0xDAB6966580AC72B4ULL,
		0x66D3B405195C597CULL,
		0x970ED2F58B03E3E9ULL,
		0xCB864869C7DE4DF3ULL,
		0xB042126DAD61D534ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BFDA32BA757F285ULL,
		0x5425C418F733BF8DULL,
		0xCD5DEA69501C3929ULL,
		0x01D88D85997C8FCBULL,
		0xFACD2705290C15CBULL,
		0x39CAE142EC6FC449ULL,
		0x7D1107F3EBF7851BULL,
		0x97CF771834240DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5042B77BFA97F10ULL,
		0x8B9A649D5B180DDCULL,
		0xDF8B0BE4AEE3A0FAULL,
		0xF94F18F9B6B2796FULL,
		0x05F6C83C7A39852FULL,
		0x72318FA09FE42CB8ULL,
		0x7EF44806A7FB4729ULL,
		0x78DB71BE6AFF3229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56F977B3E7AE7375ULL,
		0xC88B5F7B9C1BB1B0ULL,
		0xEDD2DE84A138982EULL,
		0x0889748BE2CA165BULL,
		0xF4D65EC8AED2909BULL,
		0xC79951A24C8B9791ULL,
		0xFE1CBFED43FC3DF1ULL,
		0x1EF40559C924DB7BULL
	}};
	sign = 0;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA83568D78D9166B4ULL,
		0xD3ED69E111714790ULL,
		0xBCE3F5E5A38B63ADULL,
		0xADD0CAE23D2FB4A5ULL,
		0xB9F7D5CC700BA0BAULL,
		0x79257523ED0D31E3ULL,
		0x82402B81C05AF4A7ULL,
		0x415C7E879A1BF19DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33B7BD04C673D16ULL,
		0xA94ADD363A9EFF12ULL,
		0xC7E24C7A84B3721BULL,
		0x1F3ED32517A15DE2ULL,
		0x89BC8517088FB368ULL,
		0x40D7F6FDAC375B2AULL,
		0xC3E6BE1DED24322DULL,
		0x74D3578F63921C6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4F9ED07412A299EULL,
		0x2AA28CAAD6D2487DULL,
		0xF501A96B1ED7F192ULL,
		0x8E91F7BD258E56C2ULL,
		0x303B50B5677BED52ULL,
		0x384D7E2640D5D6B9ULL,
		0xBE596D63D336C27AULL,
		0xCC8926F83689D531ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB979092689410B94ULL,
		0x27E70F6F68FF2780ULL,
		0xC08383915A3583A1ULL,
		0xDB0EA21EB3D28A8FULL,
		0xD1F619C67E9657F8ULL,
		0xDAF9568B24BDD7B8ULL,
		0xEC14D71576B336CDULL,
		0x40620C4F69B03D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BFBA5BAF58DACFULL,
		0xF307D5B3815D600FULL,
		0x8EA739153114834BULL,
		0xCEDDAFDD0168D4FAULL,
		0x343739C11F42DD50ULL,
		0xB7018CC6F393EAF4ULL,
		0x04A78405C14F4D45ULL,
		0x234F360F74A605C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77B94ECAD9E830C5ULL,
		0x34DF39BBE7A1C771ULL,
		0x31DC4A7C29210055ULL,
		0x0C30F241B269B595ULL,
		0x9DBEE0055F537AA8ULL,
		0x23F7C9C43129ECC4ULL,
		0xE76D530FB563E988ULL,
		0x1D12D63FF50A37A0ULL
	}};
	sign = 0;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CFE0B3BE2F413F4ULL,
		0xEF16FD807F1E88EEULL,
		0x2C6CE1318F50918EULL,
		0x7EB939AC79C50BDCULL,
		0x9047531ACA8992CAULL,
		0x35E65C74BC28AB29ULL,
		0x8D4EF8BF311AFA06ULL,
		0x9D9B7AA1DC5D633AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x732734753A4B8602ULL,
		0x51DA02C307D84B46ULL,
		0x8F926FAB3F0F298BULL,
		0x69A81642CB03D2F8ULL,
		0x82922DAA6E705962ULL,
		0x851B0B60CDF0DCA5ULL,
		0xB6403A9F6309D944ULL,
		0xBAA14EA4A3CAFF0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9D6D6C6A8A88DF2ULL,
		0x9D3CFABD77463DA7ULL,
		0x9CDA718650416803ULL,
		0x15112369AEC138E3ULL,
		0x0DB525705C193968ULL,
		0xB0CB5113EE37CE84ULL,
		0xD70EBE1FCE1120C1ULL,
		0xE2FA2BFD3892642DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x329A53D95630234CULL,
		0xE95516EBAE290740ULL,
		0x6167891665AA0AB6ULL,
		0x66B04FF33F48D8D8ULL,
		0x58628CA7A2B953FBULL,
		0x8E77EB6D5E639836ULL,
		0xAE3C3EF724FB4B3CULL,
		0x95E120DD6D144977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6157EEEE94D876A8ULL,
		0xEB99ABAC853240AFULL,
		0xB70E22EF0EB44E55ULL,
		0x84D227CC191636EDULL,
		0x2929141C97ADB7F0ULL,
		0x70268AEFB4C7A24FULL,
		0xE1FABB4D9CDB41CBULL,
		0xA2B8921976B308F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD14264EAC157ACA4ULL,
		0xFDBB6B3F28F6C690ULL,
		0xAA59662756F5BC60ULL,
		0xE1DE28272632A1EAULL,
		0x2F39788B0B0B9C0AULL,
		0x1E51607DA99BF5E7ULL,
		0xCC4183A988200971ULL,
		0xF3288EC3F6614084ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FA0489E78C1AD2AULL,
		0x3F90BD2CEA6F4861ULL,
		0xC5D40869DE99182BULL,
		0xE76FB488F5EB1F31ULL,
		0xC2ABD89DBBBC5AA5ULL,
		0x187C2FAB2F61AE75ULL,
		0x44F0EF36B9207395ULL,
		0x95CF2496510F22ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE297212D16E518E7ULL,
		0x78C727A0E64CDEB7ULL,
		0xD93E1B4A9AA3022EULL,
		0x3833C48F709CFEEAULL,
		0x7D5D3AF960777AF8ULL,
		0x4942F1747D81B7D5ULL,
		0x8A2F622CFDB71607ULL,
		0x48600D26006E752AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D09277161DC9443ULL,
		0xC6C9958C042269A9ULL,
		0xEC95ED1F43F615FCULL,
		0xAF3BEFF9854E2046ULL,
		0x454E9DA45B44DFADULL,
		0xCF393E36B1DFF6A0ULL,
		0xBAC18D09BB695D8DULL,
		0x4D6F177050A0AD82ULL
	}};
	sign = 0;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9F7091813B45B0EULL,
		0xECF160AB0A74B3D7ULL,
		0x4BADE1694C716447ULL,
		0x8D5986C57FE31ED9ULL,
		0xA1CC54D2BA306ABAULL,
		0xC5524C86DF314677ULL,
		0xA40C0C62FC4959C0ULL,
		0x19286C978A8B09ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E7FC7A59F773B8ULL,
		0x9B4DF4A67C6DD3AFULL,
		0x90A53AB7FD5C6185ULL,
		0xFA7F9AE4E0AD41B3ULL,
		0x10E3108AFDA3A018ULL,
		0xD84351A9F2B1C589ULL,
		0x83B32ED8ED01659BULL,
		0xAF50E206A4B024F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA70F0C9DB9BCE756ULL,
		0x51A36C048E06E028ULL,
		0xBB08A6B14F1502C2ULL,
		0x92D9EBE09F35DD25ULL,
		0x90E94447BC8CCAA1ULL,
		0xED0EFADCEC7F80EEULL,
		0x2058DD8A0F47F424ULL,
		0x69D78A90E5DAE4B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86A551649FD28BFCULL,
		0xB06BAF3A5C039E1BULL,
		0xEEC2D331383AE35EULL,
		0xC32CD4FEFFC46649ULL,
		0x45663E735A44E2BCULL,
		0xBE63116C2352AC40ULL,
		0x8899D73A80A33C3EULL,
		0x19C01DA43A31226BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0F95106EED2F1CULL,
		0xBBF8D0DF41A7FE86ULL,
		0x72C696AAADAB6782ULL,
		0x856AB46C86AE8482ULL,
		0xBD7B3B615B6BB827ULL,
		0x6706BB5C4504E43BULL,
		0x18EFEDF5FA81231EULL,
		0x6E15169BF2DD0749ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2895BC5430E55CE0ULL,
		0xF472DE5B1A5B9F95ULL,
		0x7BFC3C868A8F7BDBULL,
		0x3DC220927915E1C7ULL,
		0x87EB0311FED92A95ULL,
		0x575C560FDE4DC804ULL,
		0x6FA9E94486221920ULL,
		0xABAB070847541B22ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x182BD05CD2759128ULL,
		0x80A8B91ABEFFB728ULL,
		0x416AACA1F45D3C1DULL,
		0xE2E614B7AA6EC82EULL,
		0x29E59267F6F87501ULL,
		0x70FE533908FF3BB1ULL,
		0xD2BAFAF9B5597E57ULL,
		0x6473DADC7C7B40D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17AEC1BE8907E359ULL,
		0x6679AECA3ABA8B0DULL,
		0xDAAADEA8F6E45621ULL,
		0xF89D7A9B29474D12ULL,
		0x57088DEEC63BF355ULL,
		0xBBF017878288ACCDULL,
		0x2D83BA3054095340ULL,
		0xAF08D3EEFB6CC62EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x007D0E9E496DADCFULL,
		0x1A2F0A5084452C1BULL,
		0x66BFCDF8FD78E5FCULL,
		0xEA489A1C81277B1BULL,
		0xD2DD047930BC81ABULL,
		0xB50E3BB186768EE3ULL,
		0xA53740C961502B16ULL,
		0xB56B06ED810E7AA2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB603DA1F89F0D785ULL,
		0x0266BEEF7C33E345ULL,
		0xCCFE936394866BFCULL,
		0x8E9E5CF33809BB44ULL,
		0xE13401D07EC4E7C0ULL,
		0xF0A7974BE9615C27ULL,
		0x3B0AD622267AFA48ULL,
		0x4A5A51A57CCC4F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x494DDB742E2AAC53ULL,
		0x052362E590E6DB66ULL,
		0xD895C3F4DA7F7CB8ULL,
		0x9159AD89C9D79D74ULL,
		0xF8A6058CC0423296ULL,
		0xE7D73C9131D90CA0ULL,
		0xE43B5388B8FD2B16ULL,
		0x46B9ABBFC1567F9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CB5FEAB5BC62B32ULL,
		0xFD435C09EB4D07DFULL,
		0xF468CF6EBA06EF43ULL,
		0xFD44AF696E321DCFULL,
		0xE88DFC43BE82B529ULL,
		0x08D05ABAB7884F86ULL,
		0x56CF82996D7DCF32ULL,
		0x03A0A5E5BB75CFD3ULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC77D76E0C9D480BFULL,
		0x80957AA2BCA7CB50ULL,
		0x0114332D199B7A19ULL,
		0xF4CF35FF89B5913FULL,
		0xEBFEFA143C8CEEDCULL,
		0x91A550BDFF68CB5BULL,
		0x4047FF349D94A15DULL,
		0x1E4971DC474114FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BDFDC315A629863ULL,
		0x410F0164F463F2DAULL,
		0x55C33D4F9A306E02ULL,
		0x9D1FB177E9BA72EDULL,
		0x8EC5963411861B16ULL,
		0x67923D1CF3290D8AULL,
		0x65186A52F332FFBDULL,
		0x7270BE991E9B0B51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B9D9AAF6F71E85CULL,
		0x3F86793DC843D876ULL,
		0xAB50F5DD7F6B0C17ULL,
		0x57AF84879FFB1E51ULL,
		0x5D3963E02B06D3C6ULL,
		0x2A1313A10C3FBDD1ULL,
		0xDB2F94E1AA61A1A0ULL,
		0xABD8B34328A609A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x485D888AE7B4E682ULL,
		0xFCCD81DE66B04CE5ULL,
		0x9A66D66F5B27D3F3ULL,
		0xD6D69FF3BC0D615DULL,
		0xA42236486E790B7DULL,
		0xE056C88A308EAD6BULL,
		0x4419C63A81B11B7BULL,
		0x5C5F2271B2CF3A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43C62BBD6BE9295ULL,
		0xD25171E81C2479B7ULL,
		0xCB2F259894C5E60FULL,
		0xEFB7DBEAACEFFD27ULL,
		0xF93CB9F9BFEFD13BULL,
		0x4A3E2C38E85BD6AFULL,
		0x3EEF5E073C56EC14ULL,
		0x978A139492B6B7B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x642125CF10F653EDULL,
		0x2A7C0FF64A8BD32DULL,
		0xCF37B0D6C661EDE4ULL,
		0xE71EC4090F1D6435ULL,
		0xAAE57C4EAE893A41ULL,
		0x96189C514832D6BBULL,
		0x052A6833455A2F67ULL,
		0xC4D50EDD20188286ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8477FECE64F1BD4FULL,
		0x72E7B3CA8C46E55BULL,
		0xAC009D7CE7819ADDULL,
		0x3B45F8E8FF8E0E46ULL,
		0xDFB59D48C0714E46ULL,
		0xD19EDC97B6A8650DULL,
		0x03FA68A974DAA7B0ULL,
		0xAD5E4A2BCFDF27C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ADCF7CFF2D69930ULL,
		0xFBC32FCA5B6D2FEFULL,
		0xBEB8A81BE44D318FULL,
		0x25B4D8370738C886ULL,
		0xD3466B9FFA8B4636ULL,
		0x19D4A68F599F1BD5ULL,
		0xF8193C7F494AC643ULL,
		0x683360C6F48D245EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x299B06FE721B241FULL,
		0x7724840030D9B56CULL,
		0xED47F5610334694DULL,
		0x159120B1F85545BFULL,
		0x0C6F31A8C5E60810ULL,
		0xB7CA36085D094938ULL,
		0x0BE12C2A2B8FE16DULL,
		0x452AE964DB520361ULL
	}};
	sign = 0;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F3F5EED90B6E662ULL,
		0x34340197C5E69751ULL,
		0x312CA84500C93BBCULL,
		0x0B02559190FF2354ULL,
		0x134927C8BCC0B6B1ULL,
		0xFA991B54A46D957FULL,
		0xDB3C1CF9A9C93492ULL,
		0xE4860C233EE5A758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CFFAB778CCF8B84ULL,
		0x35E68C629B45B8DEULL,
		0x46C6AA89A55D2B3FULL,
		0x28251B3BFD7876F4ULL,
		0x0CD22C70D37E4CA6ULL,
		0xC2C081884799E90EULL,
		0x5398AA26505D235BULL,
		0xF1F5B685E82440BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x123FB37603E75ADEULL,
		0xFE4D75352AA0DE73ULL,
		0xEA65FDBB5B6C107CULL,
		0xE2DD3A559386AC5FULL,
		0x0676FB57E9426A0AULL,
		0x37D899CC5CD3AC71ULL,
		0x87A372D3596C1137ULL,
		0xF290559D56C1669EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D5003A0199D2E47ULL,
		0x8AC5DF90B135567BULL,
		0x9E475816F0D5E6D8ULL,
		0x0515F77E23BE06EEULL,
		0xD8A32817B38BF62BULL,
		0x2CCA7AC553F97579ULL,
		0xA37E7B2DF0490A1CULL,
		0xDA0720618FE768F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41E44158C1D59D0ULL,
		0x4D7316C77742878DULL,
		0x9F9C5730CE264D07ULL,
		0x9C6B8336FA621A4FULL,
		0x7797C5801FC47864ULL,
		0xDABDAEA712D9CA7DULL,
		0xF10E31E0C971BD8FULL,
		0x680959CFC69421B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8931BF8A8D7FD477ULL,
		0x3D52C8C939F2CEEDULL,
		0xFEAB00E622AF99D1ULL,
		0x68AA7447295BEC9EULL,
		0x610B629793C77DC6ULL,
		0x520CCC1E411FAAFCULL,
		0xB270494D26D74C8CULL,
		0x71FDC691C953473EULL
	}};
	sign = 0;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6379FA0B237BCD5EULL,
		0x03CB4D7A5890BA51ULL,
		0xB5D863DCFFD77D1BULL,
		0xD4BD4C690B46A2DDULL,
		0x2C3EB6A573691837ULL,
		0x28D0ACB1F3A99751ULL,
		0x0090FD51E7EB9E9FULL,
		0x0F3D933E016849DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD84BD2D04E221B30ULL,
		0x8BC2C28699FCC1F0ULL,
		0x55070C16B0541B12ULL,
		0x49BA8CD87AC3DC85ULL,
		0x015B6AC7868CA5EEULL,
		0xAB791262E6ED6ECBULL,
		0x224D96983A463ECAULL,
		0x5BB6C8D0C00476BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B2E273AD559B22EULL,
		0x78088AF3BE93F860ULL,
		0x60D157C64F836208ULL,
		0x8B02BF909082C658ULL,
		0x2AE34BDDECDC7249ULL,
		0x7D579A4F0CBC2886ULL,
		0xDE4366B9ADA55FD4ULL,
		0xB386CA6D4163D31EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0732DB7654D26D6DULL,
		0x895C170F75982385ULL,
		0xC33A15DAABEDCA40ULL,
		0xE58FE86328901A35ULL,
		0xA1BC89C66E0E9EF2ULL,
		0x3116A0C82FD24FF5ULL,
		0x8F3C1321A7747A38ULL,
		0x50B68E2704E604F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26169AFAB4FACEAEULL,
		0x89D6074A7A3EB3AAULL,
		0x494F7EF0065B02BCULL,
		0x0FE138E15E95E60DULL,
		0x2C9711AF55C26526ULL,
		0x6D29AB77C37C1765ULL,
		0x6DB762C630807148ULL,
		0x6F0E02A948AF03B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE11C407B9FD79EBFULL,
		0xFF860FC4FB596FDAULL,
		0x79EA96EAA592C783ULL,
		0xD5AEAF81C9FA3428ULL,
		0x75257817184C39CCULL,
		0xC3ECF5506C563890ULL,
		0x2184B05B76F408EFULL,
		0xE1A88B7DBC37013AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CEDE26CD0359087ULL,
		0xE9508B41366EE2C8ULL,
		0x9E8D3E9333368D7CULL,
		0xF4C0487654532E86ULL,
		0x9D164B3A384624D8ULL,
		0x534A1CDD07ED09D0ULL,
		0x40D084D635D8B55EULL,
		0x757CBB8288B65987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E9F2976974848CEULL,
		0xC0D35F96701DF8A2ULL,
		0x8D3EC187389E4FEBULL,
		0x035DD4659E525220ULL,
		0xC94A0995EBE208EBULL,
		0x5B1BF2755AC6ECE7ULL,
		0x59A75A7786314529ULL,
		0x645F018D5F5DC69BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE4EB8F638ED47B9ULL,
		0x287D2BAAC650EA25ULL,
		0x114E7D0BFA983D91ULL,
		0xF1627410B600DC66ULL,
		0xD3CC41A44C641BEDULL,
		0xF82E2A67AD261CE8ULL,
		0xE7292A5EAFA77034ULL,
		0x111DB9F5295892EBULL
	}};
	sign = 0;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE02370F134D4CB49ULL,
		0x504FBFD4BEE33FD4ULL,
		0x7D3C88E61DCDA3AAULL,
		0x0BCECF60CB62DFE7ULL,
		0x9A5640EB7F15014DULL,
		0x646878631F03485FULL,
		0xB3BC2473466FD6EBULL,
		0xA4ECEBA385064DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58BBA2634326BE34ULL,
		0x3409F359AFE9C408ULL,
		0x70A6042076E1DD17ULL,
		0xCE1DF1488AE9D259ULL,
		0x7B714B7FEA05943BULL,
		0x1556A4EC6BC9EBD5ULL,
		0xC73E473D598092DEULL,
		0x255BFABD1BA03C9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8767CE8DF1AE0D15ULL,
		0x1C45CC7B0EF97BCCULL,
		0x0C9684C5A6EBC693ULL,
		0x3DB0DE1840790D8EULL,
		0x1EE4F56B950F6D11ULL,
		0x4F11D376B3395C8AULL,
		0xEC7DDD35ECEF440DULL,
		0x7F90F0E669661144ULL
	}};
	sign = 0;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC16703AEC3AA64D9ULL,
		0xD8DE45AE8782A657ULL,
		0x05DF031282CDF9E4ULL,
		0x1327242A3EE7B88DULL,
		0x65A08626F18301DFULL,
		0xBA8858F58BE739C9ULL,
		0xF8AFDAD113537425ULL,
		0x0BCF01DDF90C7A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02613086C88C2ED7ULL,
		0x49043D9A48FF2AC2ULL,
		0x0553DCE3DD0D7724ULL,
		0x05F1662414690E19ULL,
		0x17F9679F1D36B4EAULL,
		0x11340FE312E7EE7BULL,
		0x6B2BEB67C0363B91ULL,
		0x256D9CFEF254F893ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF05D327FB1E3602ULL,
		0x8FDA08143E837B95ULL,
		0x008B262EA5C082C0ULL,
		0x0D35BE062A7EAA74ULL,
		0x4DA71E87D44C4CF5ULL,
		0xA954491278FF4B4EULL,
		0x8D83EF69531D3894ULL,
		0xE66164DF06B781D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85D0A44D6E43CE3BULL,
		0xFE2568E70CADB355ULL,
		0x10479898D3AE3303ULL,
		0x704877454063A757ULL,
		0xDD8090A265E27CDFULL,
		0xBACA1598173BD209ULL,
		0xE77AE138E0D8A978ULL,
		0xFBB223AD02C927CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B745ADA3BD56467ULL,
		0x23C17420AA2EF584ULL,
		0xB20916FA7E1143E2ULL,
		0x85CED147D943A200ULL,
		0xDBC4D20BA0AB228AULL,
		0x5F58D4FE99720F12ULL,
		0x47E7B31540738BD9ULL,
		0x5122408A8CD7442CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA5C4973326E69D4ULL,
		0xDA63F4C6627EBDD0ULL,
		0x5E3E819E559CEF21ULL,
		0xEA79A5FD67200556ULL,
		0x01BBBE96C5375A54ULL,
		0x5B7140997DC9C2F7ULL,
		0x9F932E23A0651D9FULL,
		0xAA8FE32275F1E3A1ULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58F6591439D05EBBULL,
		0xD3960DD7B976535EULL,
		0xD22837705BDC810BULL,
		0xEAFD9D7EF50D47DEULL,
		0xD2F37E2738BD7E14ULL,
		0x958D775171FE2920ULL,
		0x33D16EF44954A751ULL,
		0xAF4D2D768255F8FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527F8C8DB6596491ULL,
		0x012EF90ACA0182ABULL,
		0xFB57CB752AD3E63EULL,
		0x6AEA755A7A714429ULL,
		0x14FC1E2A9E810D6AULL,
		0x030792A4BF1A16B0ULL,
		0x4F488F1E65346669ULL,
		0x75F18E63D9C440DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0676CC868376FA2AULL,
		0xD26714CCEF74D0B3ULL,
		0xD6D06BFB31089ACDULL,
		0x801328247A9C03B4ULL,
		0xBDF75FFC9A3C70AAULL,
		0x9285E4ACB2E41270ULL,
		0xE488DFD5E42040E8ULL,
		0x395B9F12A891B823ULL
	}};
	sign = 0;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30B97D5B65E11988ULL,
		0xE00D2ECD9FEB1947ULL,
		0x8E24CDACF39D7E6CULL,
		0x196BDCBD3FCF94CEULL,
		0xA23B678AC3ED007EULL,
		0xBD19D0A0E35CD092ULL,
		0xEA8F50E488CC140FULL,
		0xDD14208DC45FE8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C8A7AEFBF917C0ULL,
		0x667189C09F80303AULL,
		0x7FA8EEBA8307B996ULL,
		0x5038EB3DBADE5D40ULL,
		0x1A387B2337ECCFE9ULL,
		0xCEB9DCC331C8DB02ULL,
		0xCEC2E79686E88A94ULL,
		0xDC6A3240F2D02E62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDF0D5AC69E801C8ULL,
		0x799BA50D006AE90CULL,
		0x0E7BDEF27095C4D6ULL,
		0xC932F17F84F1378EULL,
		0x8802EC678C003094ULL,
		0xEE5FF3DDB193F590ULL,
		0x1BCC694E01E3897AULL,
		0x00A9EE4CD18FBA53ULL
	}};
	sign = 0;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA59B03AC66116CDULL,
		0x89DDD90A09690F34ULL,
		0x0DA5C1961838CB53ULL,
		0xC5B8CD2AC315DEC0ULL,
		0xFC760CA0182FB151ULL,
		0xC754E0AE10569CCFULL,
		0x43F2428249CDD99DULL,
		0x20C3A5FC355F10DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0580A24EEAB6583CULL,
		0x430D5AF4D7F4C161ULL,
		0xBA7D7DF66C54310DULL,
		0x6408D2C2DD5CD9CEULL,
		0xADE8A1CC67B135D0ULL,
		0x3BF80A60AEC31D98ULL,
		0xA6AA2B89578D59D5ULL,
		0x8D811247FF6F913DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4D90DEBDBAABE91ULL,
		0x46D07E1531744DD3ULL,
		0x5328439FABE49A46ULL,
		0x61AFFA67E5B904F1ULL,
		0x4E8D6AD3B07E7B81ULL,
		0x8B5CD64D61937F37ULL,
		0x9D4816F8F2407FC8ULL,
		0x934293B435EF7F9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8C64393B95F7528ULL,
		0xBE41D1E6F3A2BDA7ULL,
		0x1CC20D7EB8764895ULL,
		0x400BA937E285B6C8ULL,
		0xB7DF8C5A3FC95920ULL,
		0x5F01467EEF95E919ULL,
		0x5179C35A5F1756E3ULL,
		0xCA4BC2FEE1CEB5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD65D50E80C819A2ULL,
		0xBCB841FD073B1B3EULL,
		0xD930730CE1725703ULL,
		0x3518662FB10D24C1ULL,
		0x9C741C76738427F2ULL,
		0x61D284801FCB7FD3ULL,
		0x1A2F8B6321484C10ULL,
		0x300CB38982CAC8FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B606E8538975B86ULL,
		0x01898FE9EC67A269ULL,
		0x43919A71D703F192ULL,
		0x0AF3430831789206ULL,
		0x1B6B6FE3CC45312EULL,
		0xFD2EC1FECFCA6946ULL,
		0x374A37F73DCF0AD2ULL,
		0x9A3F0F755F03ECB4ULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FD521621F56A70FULL,
		0x9FEB870CF49AFD34ULL,
		0x04B47167662726B2ULL,
		0xC0D0E996771B86C9ULL,
		0x963AC4E22BE36606ULL,
		0x589311D0BB490E9AULL,
		0x36B014EB5AB0D941ULL,
		0x9D50425C32172FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC382FC58DEF459ULL,
		0x8452408463E3326BULL,
		0xA6882E806EBAE3EBULL,
		0xBBA4C1DD647EA404ULL,
		0x4E05177FFE7A1187ULL,
		0x444D384063CD451CULL,
		0xC457347572F8F6A4ULL,
		0x3E5DBDC2276A5D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3119E65C677B2B6ULL,
		0x1B99468890B7CAC8ULL,
		0x5E2C42E6F76C42C7ULL,
		0x052C27B9129CE2C4ULL,
		0x4835AD622D69547FULL,
		0x1445D990577BC97EULL,
		0x7258E075E7B7E29DULL,
		0x5EF2849A0AACD2DEULL
	}};
	sign = 0;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0607269C97BD76ULL,
		0xD9F5ACEE61D03FE5ULL,
		0xDCFA6845DC4AAE2AULL,
		0x6D2D84ED371590A1ULL,
		0x7E9C3D410F52A768ULL,
		0xF1E26F23F825343FULL,
		0xD906AA94DF69F7C7ULL,
		0x801806F3ACF99849ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F3F81AF9C473ADULL,
		0x1FB0ECF919CD5984ULL,
		0x3EACA2C368925E3AULL,
		0x3C061C300D20A680ULL,
		0x4F5D6F9E582A94A8ULL,
		0x663FF4EAE3E82891ULL,
		0x620BA8BA6C80C6CFULL,
		0x82B66DEB4E7CB592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B120F0BA2D349C9ULL,
		0xBA44BFF54802E661ULL,
		0x9E4DC58273B84FF0ULL,
		0x312768BD29F4EA21ULL,
		0x2F3ECDA2B72812C0ULL,
		0x8BA27A39143D0BAEULL,
		0x76FB01DA72E930F8ULL,
		0xFD6199085E7CE2B7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABCBD50A11E0305CULL,
		0x703C57D0892C35F7ULL,
		0x5DD5489651D225C9ULL,
		0xBC9CE2F1B6E2A884ULL,
		0x949DB4559B2F1D9DULL,
		0xAADDAC4F9D4E180AULL,
		0xB5BDCF9E18A3F0C4ULL,
		0xDE70EC0190100968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF71D92875923B29ULL,
		0xC9244D97245FC187ULL,
		0xDE1341D8AF0F1179ULL,
		0x1712703D0F71688BULL,
		0x0A50BECA7394EF12ULL,
		0x9E0FE4E35F6281EFULL,
		0xA13B0A2EEB7E8CCEULL,
		0xF24C03DA91E976B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC59FBE19C4DF533ULL,
		0xA7180A3964CC746FULL,
		0x7FC206BDA2C3144FULL,
		0xA58A72B4A7713FF8ULL,
		0x8A4CF58B279A2E8BULL,
		0x0CCDC76C3DEB961BULL,
		0x1482C56F2D2563F6ULL,
		0xEC24E826FE2692B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x654A745AAF0A0B0DULL,
		0x0313D48E2EA40488ULL,
		0xC4159F6790CECAD2ULL,
		0x751D7F16536277FDULL,
		0x783A1B64011893E3ULL,
		0xC8E9F1A0BFCC3D06ULL,
		0x185752702096CE16ULL,
		0x402F56FA22A5FAC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAEE3CB54505CD4EULL,
		0x8D328D2CBC996B38ULL,
		0xF26407919E322FF9ULL,
		0x6D0862F9CA697438ULL,
		0x4B8CC6A9887D5B78ULL,
		0x3B79287F0ECC342BULL,
		0xF1F6ED6C42F35FD9ULL,
		0xC3AD486344E6CE05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA5C37A56A043DBFULL,
		0x75E14761720A994FULL,
		0xD1B197D5F29C9AD8ULL,
		0x08151C1C88F903C4ULL,
		0x2CAD54BA789B386BULL,
		0x8D70C921B10008DBULL,
		0x26606503DDA36E3DULL,
		0x7C820E96DDBF2CBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAC79B3D7512D992ULL,
		0x328A55C81CD16CBDULL,
		0x3925527DB9E7F1A4ULL,
		0xD34D569B44EE96DAULL,
		0xEB5E1401704B73ECULL,
		0x6F8BC1B3EB96EEF9ULL,
		0xC4835A4BDFC5EC36ULL,
		0xAA767544117302F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3037CE9A6F74BFC5ULL,
		0x23FBA23FA5B2476EULL,
		0xFA36A47E464AEF3AULL,
		0x3F14BBADE932CA3FULL,
		0x27EDD545E81066A8ULL,
		0xB90AA34CE7509CC4ULL,
		0x9BBFEEC36E2F2DBDULL,
		0x6317E856FA5BAE15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A8FCCA3059E19CDULL,
		0x0E8EB388771F254FULL,
		0x3EEEADFF739D026AULL,
		0x94389AED5BBBCC9AULL,
		0xC3703EBB883B0D44ULL,
		0xB6811E6704465235ULL,
		0x28C36B887196BE78ULL,
		0x475E8CED171754DDULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BBC52114B71C550ULL,
		0xCB1A105465AB282AULL,
		0x44D9ED9022F0FE86ULL,
		0xFA2481AF82F61CD8ULL,
		0x5A8930071B518AE0ULL,
		0xE385470AD9523125ULL,
		0xFE6BE9B270EF530CULL,
		0xC774EC44A25D89AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8798B3C0A0D3B244ULL,
		0x37D9C17A59AE7D91ULL,
		0x2A3A99F4DF7ED10AULL,
		0x6F977405F88D30B7ULL,
		0x27B3E7D13D79D6DEULL,
		0xCE36E7FAF2695F9CULL,
		0x48927B47BAD1029CULL,
		0x923E77A45C8905C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84239E50AA9E130CULL,
		0x93404EDA0BFCAA98ULL,
		0x1A9F539B43722D7CULL,
		0x8A8D0DA98A68EC21ULL,
		0x32D54835DDD7B402ULL,
		0x154E5F0FE6E8D189ULL,
		0xB5D96E6AB61E5070ULL,
		0x353674A045D483E8ULL
	}};
	sign = 0;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA1A92BF70935EDDULL,
		0xEDD7195CB3233718ULL,
		0x99F79C75DC1A6484ULL,
		0xC99C4EC6EEE4C145ULL,
		0x8C3E577AAD96DA39ULL,
		0xCC427402C76C4F3CULL,
		0xFCE4144258057272ULL,
		0xF913919B54014205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15822E516F9C77CAULL,
		0x60A2482FB951A008ULL,
		0xC35D7BB5FC48877BULL,
		0x4114D4B7EB3E8340ULL,
		0x15B5F53516764986ULL,
		0xFEA5AD309F5104C5ULL,
		0x2DF1D486A2D1C77DULL,
		0xCB35B044EB7F1EDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA498646E00F6E713ULL,
		0x8D34D12CF9D19710ULL,
		0xD69A20BFDFD1DD09ULL,
		0x88877A0F03A63E04ULL,
		0x76886245972090B3ULL,
		0xCD9CC6D2281B4A77ULL,
		0xCEF23FBBB533AAF4ULL,
		0x2DDDE15668822329ULL
	}};
	sign = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD77B0C0C2BE27EE5ULL,
		0x16D8D16BC0B69EF3ULL,
		0xF3A31D17968C15AEULL,
		0xD4C59340F545A18AULL,
		0x6D226A1E02CC0EDEULL,
		0x49EA30CC88669746ULL,
		0x2C18DAB01FBD8EB6ULL,
		0xF0957666EE60B189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D3800F1F6225C7ULL,
		0x4A5ED9F7143C42CAULL,
		0x174CD4359A34C4C6ULL,
		0x13D8F033C3C8DBC3ULL,
		0x60636231E8F73D5BULL,
		0xDB3B7AEE4A0BC686ULL,
		0xBEBDBE709343EDFCULL,
		0x3A503D1519CE7521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22A78BFD0C80591EULL,
		0xCC79F774AC7A5C29ULL,
		0xDC5648E1FC5750E7ULL,
		0xC0ECA30D317CC5C7ULL,
		0x0CBF07EC19D4D183ULL,
		0x6EAEB5DE3E5AD0C0ULL,
		0x6D5B1C3F8C79A0B9ULL,
		0xB6453951D4923C67ULL
	}};
	sign = 0;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03246F9976170F88ULL,
		0x2CAEDD05D252A28CULL,
		0x95999BEB91CB1189ULL,
		0x4EEC5FB6AEAB7520ULL,
		0x96DB7CA62B18131FULL,
		0xE9E2812B09FE5C0CULL,
		0x3CDEE1D102424D16ULL,
		0x613A910A7A9961C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A3F28D160E7F65ULL,
		0x1CBDBEC553CF719FULL,
		0xCA804A1700231A6DULL,
		0x87524DA77DC1F6F1ULL,
		0xE032B98E942A2ABDULL,
		0xC7D0FC98A4018A43ULL,
		0xFB0F3F27630631F1ULL,
		0x5666B594681B915AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72807D0C60089023ULL,
		0x0FF11E407E8330ECULL,
		0xCB1951D491A7F71CULL,
		0xC79A120F30E97E2EULL,
		0xB6A8C31796EDE861ULL,
		0x2211849265FCD1C8ULL,
		0x41CFA2A99F3C1B25ULL,
		0x0AD3DB76127DD06DULL
	}};
	sign = 0;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13FD0FD51C4D1A6BULL,
		0x791034A73D74515FULL,
		0x0867C747A370FA8FULL,
		0xE20773B6193F43CFULL,
		0xE5DC4BEEFEB5B53CULL,
		0x54D1BD4BAE77FF06ULL,
		0x7F002C91626712B3ULL,
		0xBB9E5ACB35E87B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD6F694D6E83C832ULL,
		0xD0908A9E93A0ECF8ULL,
		0x07C24D2FAB601EB0ULL,
		0xE50D4D86ADB66CD9ULL,
		0x72743B9EB7D66DFCULL,
		0x34D85433F5E4CFCBULL,
		0x2CE4F98E393FB1EBULL,
		0xDCD1A979009D177FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x568DA687ADC95239ULL,
		0xA87FAA08A9D36466ULL,
		0x00A57A17F810DBDEULL,
		0xFCFA262F6B88D6F6ULL,
		0x7368105046DF473FULL,
		0x1FF96917B8932F3BULL,
		0x521B3303292760C8ULL,
		0xDECCB152354B63A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DD1B2F29FD6C774ULL,
		0x887178908DC7A4CAULL,
		0xD760F6A363168CA6ULL,
		0xE72E7105B2199A17ULL,
		0xF79F7C331D06182BULL,
		0x08EFBD73960123C6ULL,
		0x9FF31B1782F11F5AULL,
		0x70EE072DB69DAC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x359C2DF25D0802FAULL,
		0x7430E8D7081ADF12ULL,
		0x5652A88BE7F67879ULL,
		0xFC1EDCC34E451571ULL,
		0x5D0053A29ABA0532ULL,
		0x1C69DB861697FE51ULL,
		0x9AC89646A0F408C9ULL,
		0xE40A63AF2A5FB4FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE835850042CEC47AULL,
		0x14408FB985ACC5B7ULL,
		0x810E4E177B20142DULL,
		0xEB0F944263D484A6ULL,
		0x9A9F2890824C12F8ULL,
		0xEC85E1ED7F692575ULL,
		0x052A84D0E1FD1690ULL,
		0x8CE3A37E8C3DF769ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x114AE4BCF29F0C80ULL,
		0xF960E6D27B9B1931ULL,
		0x61043655F29A2BBBULL,
		0x2D4C2C6C73F36913ULL,
		0x0B2CFA77BC9CDED6ULL,
		0x668EC5A0967367C3ULL,
		0x782D061ECAE03D32ULL,
		0xD110C80F8959797BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543DC581660D2CCAULL,
		0x0763A95822EB6AA9ULL,
		0x9CFA653C25E0DE3EULL,
		0xDBC3CD7C815D34FCULL,
		0xC101B9AF61728950ULL,
		0xACD6238D7EFD5B59ULL,
		0x4AE9E2FFCFDD9DB8ULL,
		0x8D9466DD3D2E1122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD0D1F3B8C91DFB6ULL,
		0xF1FD3D7A58AFAE87ULL,
		0xC409D119CCB94D7DULL,
		0x51885EEFF2963416ULL,
		0x4A2B40C85B2A5585ULL,
		0xB9B8A21317760C69ULL,
		0x2D43231EFB029F79ULL,
		0x437C61324C2B6859ULL
	}};
	sign = 0;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB445940375C4AD3ULL,
		0x830873E1C203CA0BULL,
		0x50277293713CD89CULL,
		0x0FDDC804DBF8D2B5ULL,
		0x6F6A4F14459FA1E2ULL,
		0x967012BA597557E2ULL,
		0x6452728A1F1257A7ULL,
		0x9827C249A8C3285FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA32D3CAF8538549ULL,
		0x90AEAD3E8D987ADCULL,
		0xAE678E750F069273ULL,
		0xB7CE646282E8CE3FULL,
		0x6F64220B99534ED8ULL,
		0x0B65B1A83EA72CB5ULL,
		0xBE4052C66F5AD4A5ULL,
		0x705AAF49884CB328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF11185753F08C58AULL,
		0xF259C6A3346B4F2EULL,
		0xA1BFE41E62364628ULL,
		0x580F63A259100475ULL,
		0x00062D08AC4C5309ULL,
		0x8B0A61121ACE2B2DULL,
		0xA6121FC3AFB78302ULL,
		0x27CD130020767536ULL
	}};
	sign = 0;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86AC6D7F5FE940B6ULL,
		0xE22546AE5A548E53ULL,
		0xDA90188C05D39109ULL,
		0xB04E844C8088F2ACULL,
		0xB16147F76AA097F8ULL,
		0x6A94516FD524803DULL,
		0x372CA65FD4DA93F3ULL,
		0x178BB20193A81784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670D40DD01253A40ULL,
		0xBA0A0E8DD157334FULL,
		0x6310D54B0AFC91FCULL,
		0x84F19F033AD1D602ULL,
		0xD84B4E0565799952ULL,
		0xF7F40097708A0372ULL,
		0x8D08DFCFD1B9DF82ULL,
		0xDEA8EB19F51CB280ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F9F2CA25EC40676ULL,
		0x281B382088FD5B04ULL,
		0x777F4340FAD6FF0DULL,
		0x2B5CE54945B71CAAULL,
		0xD915F9F20526FEA6ULL,
		0x72A050D8649A7CCAULL,
		0xAA23C6900320B470ULL,
		0x38E2C6E79E8B6503ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EA786948B1BB5FAULL,
		0x26B2310BE6462D7CULL,
		0x47478F0722059248ULL,
		0xE1D6186B0DA3E550ULL,
		0x126B88E9385FA698ULL,
		0x55687BF92B2CC0EDULL,
		0xCEAA303FB72EED0BULL,
		0x67D3E7F1C6C245DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C5B44B89BC4D99BULL,
		0x7492918633D6B481ULL,
		0xC7F4DC5FFF725CE3ULL,
		0xECA377392DA2552AULL,
		0xE084693337432A1EULL,
		0xDB65FDD17077BDCDULL,
		0xB83A1475328AF631ULL,
		0xEA50B7380D70319CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x624C41DBEF56DC5FULL,
		0xB21F9F85B26F78FBULL,
		0x7F52B2A722933564ULL,
		0xF532A131E0019025ULL,
		0x31E71FB6011C7C79ULL,
		0x7A027E27BAB5031FULL,
		0x16701BCA84A3F6D9ULL,
		0x7D8330B9B9521441ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x793263590FDB5AA3ULL,
		0x6ADB6A4184094DA2ULL,
		0x1CC89A4B24B13209ULL,
		0x542C8DA0DD634125ULL,
		0x92D93F1BAC37DB7DULL,
		0x60A29D533AE7BE69ULL,
		0x211181FB77B9AC88ULL,
		0x7B4CBFBB350479BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB677D9FBC9B04617ULL,
		0xD7F579E5D8A83A3EULL,
		0x58E91E11BC5C5186ULL,
		0xFEA66458F45CD214ULL,
		0xF3EBBA14F507E47BULL,
		0x753EDC339CC8EED8ULL,
		0x2C515CE2CB5DD71CULL,
		0xA5FE1045EFC8A9C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2BA895D462B148CULL,
		0x92E5F05BAB611363ULL,
		0xC3DF7C396854E082ULL,
		0x55862947E9066F10ULL,
		0x9EED8506B72FF701ULL,
		0xEB63C11F9E1ECF90ULL,
		0xF4C02518AC5BD56BULL,
		0xD54EAF75453BCFF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF4B17DC4DEF85AULL,
		0x2F79152AE65B957BULL,
		0x5373EAC4D3DEAD0DULL,
		0x784269A64350A08EULL,
		0x5DEAC6880A917A79ULL,
		0x4EA33AE2D4AA5B26ULL,
		0x1AF5C1F3F0F4E48BULL,
		0x1CA3B17ADB5432E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B2F9EC6DC63893ULL,
		0x953D57582D7E10DDULL,
		0xC7678C5E205E1053ULL,
		0x7920666BC3F67AF4ULL,
		0x20A4DFB69FD358E0ULL,
		0x112A8714DCCAC584ULL,
		0x9F9E844DD5F8969EULL,
		0x3E84691A1EF5F015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0841B7915718BFC7ULL,
		0x9A3BBDD2B8DD849EULL,
		0x8C0C5E66B3809CB9ULL,
		0xFF22033A7F5A2599ULL,
		0x3D45E6D16ABE2198ULL,
		0x3D78B3CDF7DF95A2ULL,
		0x7B573DA61AFC4DEDULL,
		0xDE1F4860BC5E42CFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCB68E51A7AFC1D2ULL,
		0x72AA45400C53953EULL,
		0x9FCA113BD039AD20ULL,
		0x430B3461190B4F97ULL,
		0xBC567B758ED84212ULL,
		0x26110AF93459CB2EULL,
		0xE71C036A6A98EDA8ULL,
		0x53DCCDFBA581154CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA626C6B325B0162ULL,
		0x29330C1A2FB8454FULL,
		0xF5B3363ABB13F2EEULL,
		0xC90DFCEAF94071E0ULL,
		0x3527A60DFC5B03DEULL,
		0xBD8845C035D8FACFULL,
		0x69D22F850DBBA67AULL,
		0xDE1322785204BAB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x025421E67554C070ULL,
		0x49773925DC9B4FEFULL,
		0xAA16DB011525BA32ULL,
		0x79FD37761FCADDB6ULL,
		0x872ED567927D3E33ULL,
		0x6888C538FE80D05FULL,
		0x7D49D3E55CDD472DULL,
		0x75C9AB83537C5A9AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9A8D7497761B53BULL,
		0xDBB317C7D7C3E786ULL,
		0x8C2B57D1A2741987ULL,
		0xB3DA75BCA066E573ULL,
		0x478D22514A388108ULL,
		0xBB92A1C7B1C52C81ULL,
		0x57806C05A23E2CABULL,
		0x451F1BFB7280E4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EE86F80E339A81ULL,
		0x66963FA8094F1CA3ULL,
		0x1C9B9A41029FC48EULL,
		0x206040B70AD91BECULL,
		0x4605041DD50B3B9FULL,
		0xFD2047572DB1E0F6ULL,
		0xE79D6EAF771BEBE2ULL,
		0x1E180448B0DD10F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1BA5051692E1ABAULL,
		0x751CD81FCE74CAE2ULL,
		0x6F8FBD909FD454F9ULL,
		0x937A3505958DC987ULL,
		0x01881E33752D4569ULL,
		0xBE725A7084134B8BULL,
		0x6FE2FD562B2240C8ULL,
		0x270717B2C1A3D3C8ULL
	}};
	sign = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x270DA6D2A2A3C74FULL,
		0x5FB5C7CFEC218850ULL,
		0x8CFF7D751BC41FC0ULL,
		0xE0A085B2E98624B6ULL,
		0x6108BD1095D0F3D2ULL,
		0x61FC4F120E346E4DULL,
		0x5AAA3331DBE7DCC3ULL,
		0x566D2115332404AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027A667893D7D5E0ULL,
		0x649E512755071CFAULL,
		0x52EEE1468E38EE6DULL,
		0xF487F2253B1356C9ULL,
		0xF2D3875C14CB8968ULL,
		0xE48FBA50DDAD5549ULL,
		0x846DCA345B675268ULL,
		0xBD535DD95242002CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2493405A0ECBF16FULL,
		0xFB1776A8971A6B56ULL,
		0x3A109C2E8D8B3152ULL,
		0xEC18938DAE72CDEDULL,
		0x6E3535B481056A69ULL,
		0x7D6C94C130871903ULL,
		0xD63C68FD80808A5AULL,
		0x9919C33BE0E2047DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2533C26BFB0FB5CULL,
		0xF91F2469C8DFD5A0ULL,
		0xA90A5D80B1A82BAFULL,
		0x58EF6043F957AFA1ULL,
		0x4A15373C9B786240ULL,
		0x9BA2DA355CA18A57ULL,
		0x9D748DC6525D70C1ULL,
		0x566F4AB76687BE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7FB8C5148E14716ULL,
		0x9BA61C7C7B3760A7ULL,
		0x986963FB9F29F8E0ULL,
		0x04C0ED2DBEC7A9EDULL,
		0x3C138A60F3B80CDBULL,
		0x0BE847B815C4E623ULL,
		0x928B9F8992D8D2C2ULL,
		0x68EB7771E5DD0A27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA57AFD576CFB446ULL,
		0x5D7907ED4DA874F8ULL,
		0x10A0F985127E32CFULL,
		0x542E73163A9005B4ULL,
		0x0E01ACDBA7C05565ULL,
		0x8FBA927D46DCA434ULL,
		0x0AE8EE3CBF849DFFULL,
		0xED83D34580AAB3DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x858D5C9FC997F012ULL,
		0x688FAA90EE57F7ECULL,
		0xAB51C9944A4C6C53ULL,
		0x64573F4425BA8158ULL,
		0xA307FE0CDF74F226ULL,
		0x9CDB6DC7A26A8776ULL,
		0x962B9DEA2ACA52DDULL,
		0x194800C9967FE956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CFED4C5D55E6077ULL,
		0x661F663A082D5968ULL,
		0xA3954A46BEC3972FULL,
		0xEEBD45F206939E6DULL,
		0xEE0CDB64A0DE51ACULL,
		0x440421F0B3D19F99ULL,
		0xA0E31317BD46937BULL,
		0x3345016DC042D396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x388E87D9F4398F9BULL,
		0x02704456E62A9E84ULL,
		0x07BC7F4D8B88D524ULL,
		0x7599F9521F26E2EBULL,
		0xB4FB22A83E96A079ULL,
		0x58D74BD6EE98E7DCULL,
		0xF5488AD26D83BF62ULL,
		0xE602FF5BD63D15BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75463A90B8120B4CULL,
		0x41AAF8E2EFADFC28ULL,
		0x5A616F1A47A6C2D2ULL,
		0x3E2E1095C6EE27F0ULL,
		0xA02F38ADC98FE4B5ULL,
		0x02348FB5269B28BDULL,
		0x2F3B227A42C4822CULL,
		0xF3D58C3496091A54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x004C1B38392EF170ULL,
		0x954D3E18E1356380ULL,
		0x1B985220EC80D5BEULL,
		0x4AD16CB746E80D83ULL,
		0x5C00397009345053ULL,
		0x4A375127AF9EF55BULL,
		0x6724C51C3649180EULL,
		0xFABC14A35A9D68E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74FA1F587EE319DCULL,
		0xAC5DBACA0E7898A8ULL,
		0x3EC91CF95B25ED13ULL,
		0xF35CA3DE80061A6DULL,
		0x442EFF3DC05B9461ULL,
		0xB7FD3E8D76FC3362ULL,
		0xC8165D5E0C7B6A1DULL,
		0xF91977913B6BB170ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4D91C8E9378ACE6ULL,
		0x4258E0811E52A4D7ULL,
		0x930703FDB8C4DD75ULL,
		0x8F3CAA0F8B149965ULL,
		0x2E0AC4142EC58F0CULL,
		0xFEF44CDB97411C3FULL,
		0x116E48C9C0BDED15ULL,
		0xFE2F659FE65F8C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD06DAF56C92BCE5ULL,
		0xCCAAAA66C1AB2744ULL,
		0x9816F37EC6A8A3B9ULL,
		0x100303728014267FULL,
		0xA2800DA708A8480FULL,
		0xCE6AF0AD1543A41BULL,
		0x178A5D83B02736E3ULL,
		0x46F9311BFDA7C79BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7D2419926E5F001ULL,
		0x75AE361A5CA77D92ULL,
		0xFAF0107EF21C39BBULL,
		0x7F39A69D0B0072E5ULL,
		0x8B8AB66D261D46FDULL,
		0x30895C2E81FD7823ULL,
		0xF9E3EB461096B632ULL,
		0xB7363483E8B7C4FDULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB612FB880586737ULL,
		0xE49753016CF3B8A7ULL,
		0x10B103B615F43CF1ULL,
		0xA41AB77E2908119CULL,
		0xAA10A090A3E408A6ULL,
		0xF402CA3F03FAF613ULL,
		0xF723E6389EA54B96ULL,
		0xF82943C21E46F865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D4E8791030FE17ULL,
		0xD6C09A90D4320C80ULL,
		0xC0C78CAB0DDA5F1FULL,
		0x239C1FD706DDC4BBULL,
		0xAD751B1544DE8073ULL,
		0xDC7C14C56322E41DULL,
		0xDACA7DD7333591D4ULL,
		0xC27444B1AF246BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x778C473F70276920ULL,
		0x0DD6B87098C1AC27ULL,
		0x4FE9770B0819DDD2ULL,
		0x807E97A7222A4CE0ULL,
		0xFC9B857B5F058833ULL,
		0x1786B579A0D811F5ULL,
		0x1C5968616B6FB9C2ULL,
		0x35B4FF106F228C7EULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD35D0036C7F6E7DULL,
		0xF7D42675A96B2DA9ULL,
		0xBBB25ED0A559DD48ULL,
		0x335D64440AD2EC6FULL,
		0x4994FA45C7559F50ULL,
		0x4D521EC671BBC796ULL,
		0xFF275A02D0064BC2ULL,
		0x17C3BCE83ADA1589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16AF045A823B2B37ULL,
		0x3E490A97ED6C88B3ULL,
		0x97A5AE2E70BF7E28ULL,
		0x24E9E0BD76FDD8EBULL,
		0xFB1C012E75965231ULL,
		0x92D271D9DE0ACD6DULL,
		0x8F2FD7DAF7B69445ULL,
		0xDDDEDE0589F90D07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC686CBA8EA444346ULL,
		0xB98B1BDDBBFEA4F6ULL,
		0x240CB0A2349A5F20ULL,
		0x0E73838693D51384ULL,
		0x4E78F91751BF4D1FULL,
		0xBA7FACEC93B0FA28ULL,
		0x6FF78227D84FB77CULL,
		0x39E4DEE2B0E10882ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB652C37D44CA3FA2ULL,
		0x702242D28617FEC1ULL,
		0x9EE25CAEAEF9799EULL,
		0x2DAEC5DE08E459ABULL,
		0x1C32EC13921196E2ULL,
		0xB4A25C2A0BFE7269ULL,
		0xA45BF6173721EEAEULL,
		0xC393C5909466B370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A04AA4A87632A6ULL,
		0x2A17179F3C8B91CBULL,
		0xE6E3EAAECA4E994AULL,
		0xA8D20CE8DBC09188ULL,
		0xCFDD449550AA8CFCULL,
		0xF223003E9A87D57EULL,
		0xC334E6EEBA05457BULL,
		0x8B0352BE808F36B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35B278D89C540CFCULL,
		0x460B2B33498C6CF6ULL,
		0xB7FE71FFE4AAE054ULL,
		0x84DCB8F52D23C822ULL,
		0x4C55A77E416709E5ULL,
		0xC27F5BEB71769CEAULL,
		0xE1270F287D1CA932ULL,
		0x389072D213D77CBEULL
	}};
	sign = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37656BC718658222ULL,
		0xDC557709B4CE620EULL,
		0xBC8A0424C6B4206CULL,
		0x808D289CDA7592D8ULL,
		0xCCE349CEEB260D16ULL,
		0x7062F5101A7F0BBEULL,
		0x4D0D365C6F0EA355ULL,
		0x11581D0F92355499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x249534C0506F0861ULL,
		0x9F77618796C91809ULL,
		0xE888CB8D5FA3AD08ULL,
		0x8E14714AC54CD9C9ULL,
		0x086942F6B092814DULL,
		0x3DEDAD443B501EE9ULL,
		0x6044C83D4C280DD4ULL,
		0x5F34E54AAE41AE39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12D03706C7F679C1ULL,
		0x3CDE15821E054A05ULL,
		0xD401389767107364ULL,
		0xF278B7521528B90EULL,
		0xC47A06D83A938BC8ULL,
		0x327547CBDF2EECD5ULL,
		0xECC86E1F22E69581ULL,
		0xB22337C4E3F3A65FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x123C09201E4B5EABULL,
		0xC01D460215E7CC47ULL,
		0xA9AD529251258D67ULL,
		0x4D21F2DA14776A1EULL,
		0xAD5DD749D50F230BULL,
		0x78E65613A98C3384ULL,
		0x445FFB1C99AEDC1DULL,
		0xDDE2BDAB2F513063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E9FF0EF2A977FD0ULL,
		0x488A1AEBCC3DED6CULL,
		0xD9857A8B1CAFA2B7ULL,
		0xED08979CE3DB8F10ULL,
		0x7FEBBBF735D08792ULL,
		0xC227C487AA356866ULL,
		0x50E75CB2CB0F6A85ULL,
		0x105CE03D035A0331ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC39C1830F3B3DEDBULL,
		0x77932B1649A9DEDAULL,
		0xD027D8073475EAB0ULL,
		0x60195B3D309BDB0DULL,
		0x2D721B529F3E9B78ULL,
		0xB6BE918BFF56CB1EULL,
		0xF3789E69CE9F7197ULL,
		0xCD85DD6E2BF72D31ULL
	}};
	sign = 0;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4337FCBC51E79AAULL,
		0x463DE3BA85535F35ULL,
		0xE24464C168580E78ULL,
		0x58C5C54E761D5E2DULL,
		0xA3506B461A030C43ULL,
		0x6B8B7AE63BD68960ULL,
		0xCCD1CD83939F9593ULL,
		0xAE281C5E88F88629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB9772C0B8A9015ULL,
		0x7BC246739F51CE1AULL,
		0xE235BC48829026F2ULL,
		0x355E61B5693114E0ULL,
		0xC1A1BEF2776549BCULL,
		0x57A874CE3B04FF66ULL,
		0x355EB74097138D01ULL,
		0x136EA2D200870B80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x597A089FB993E995ULL,
		0xCA7B9D46E601911BULL,
		0x000EA878E5C7E785ULL,
		0x236763990CEC494DULL,
		0xE1AEAC53A29DC287ULL,
		0x13E3061800D189F9ULL,
		0x97731642FC8C0892ULL,
		0x9AB9798C88717AA9ULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13B0846BA0CFE1ECULL,
		0x1122CDB261F81C5FULL,
		0x764005A34998C9D8ULL,
		0xF2B36E6FA1490DEEULL,
		0x22D833ECC978DADAULL,
		0xBB8287272D989CA1ULL,
		0x2B4200002773A330ULL,
		0xC8BC8B8F34D58F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3775BF8080A0767ULL,
		0x88DD3E716A42D908ULL,
		0x37342C9D6D142DB2ULL,
		0xBDFA99D5E059DF05ULL,
		0x44E083ADD487B104ULL,
		0xB735D5E4F3A6755AULL,
		0x0D73B3885C819B6DULL,
		0x19A6232E308081F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3039287398C5DA85ULL,
		0x88458F40F7B54356ULL,
		0x3F0BD905DC849C25ULL,
		0x34B8D499C0EF2EE9ULL,
		0xDDF7B03EF4F129D6ULL,
		0x044CB14239F22746ULL,
		0x1DCE4C77CAF207C3ULL,
		0xAF16686104550D1AULL
	}};
	sign = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA016453E474A553DULL,
		0x064EA9D8B2452D3DULL,
		0x14AAF16DD95BD7FEULL,
		0xEC73DE5F896201F3ULL,
		0xCB17B2E874ED52DFULL,
		0xADEE388AC9505139ULL,
		0x16F7C4248B4561A7ULL,
		0xDC85ECD5EC7357B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF02E4F828BFA057ULL,
		0xE1FAB4CCB572C48CULL,
		0xBEAE54C2AFBC9DE7ULL,
		0x329489CE2B701CC5ULL,
		0x6085E57BEA9B9DDBULL,
		0xED086FBE2A7A9AF4ULL,
		0x68925E065F2CA285ULL,
		0xC134D0F3C1D7F18FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD11360461E8AB4E6ULL,
		0x2453F50BFCD268B0ULL,
		0x55FC9CAB299F3A16ULL,
		0xB9DF54915DF1E52DULL,
		0x6A91CD6C8A51B504ULL,
		0xC0E5C8CC9ED5B645ULL,
		0xAE65661E2C18BF21ULL,
		0x1B511BE22A9B6626ULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9863212872A498CULL,
		0xE6B7BDDFEE9C6E41ULL,
		0x370C7C32AC9F679FULL,
		0x4FCCA7E29C855C29ULL,
		0xBB04149492E9E9A6ULL,
		0xE18958D7C5DBFC1DULL,
		0x45E1EEDDB3E3AFF3ULL,
		0xAC7C7B330682205DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE73C8A5A74566BB4ULL,
		0xDF67C91EBE92006FULL,
		0x96F60BDBCB7AF972ULL,
		0xD45690F3890693E2ULL,
		0x3B42CC3E75666A89ULL,
		0x67EDC1C4F8C182D2ULL,
		0xB49F97FFDC9D3804ULL,
		0xB8363AE16FDFCDABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE249A7B812D3DDD8ULL,
		0x074FF4C1300A6DD1ULL,
		0xA0167056E1246E2DULL,
		0x7B7616EF137EC846ULL,
		0x7FC148561D837F1CULL,
		0x799B9712CD1A794BULL,
		0x914256DDD74677EFULL,
		0xF446405196A252B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D01267D7169D40DULL,
		0xB8C439C0F5953099ULL,
		0x32AFC77D9D163BE2ULL,
		0xB5FB6B11D2B24DE0ULL,
		0xE5B0EC1F43972771ULL,
		0x5ACE2823231E8047ULL,
		0xB1AC9F97AC3A6A5EULL,
		0x13016138643FDFDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517B44483122B9DEULL,
		0x9CE137EEF7BE0841ULL,
		0x23EE690E114B417CULL,
		0x99A25836FEA6E275ULL,
		0x20BA168C8ABFDE09ULL,
		0xBA2233775B140F88ULL,
		0xB867DEB01C2534E1ULL,
		0xD29D786834F63A80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B85E23540471A2FULL,
		0x1BE301D1FDD72858ULL,
		0x0EC15E6F8BCAFA66ULL,
		0x1C5912DAD40B6B6BULL,
		0xC4F6D592B8D74968ULL,
		0xA0ABF4ABC80A70BFULL,
		0xF944C0E79015357CULL,
		0x4063E8D02F49A55CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BC355589B65EBE4ULL,
		0xCA11EAE0E6982709ULL,
		0x4352B501904A8914ULL,
		0xFCECCC9DF982FC34ULL,
		0x45DA11DBFD9C7868ULL,
		0x072A9AD54C0DBE38ULL,
		0x5AF732FC50284F01ULL,
		0x7DF3AB491DCE14E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1913E800CC134DD1ULL,
		0xEF2CD3630A576B3EULL,
		0x7FF5A4382C58D146ULL,
		0x9A0C785B5CB4C0ABULL,
		0x99A3229AC3CF05CAULL,
		0xAD270713692EA3B0ULL,
		0xE7AE0F6B52310836ULL,
		0x4523DC220AF47D7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2AF6D57CF529E13ULL,
		0xDAE5177DDC40BBCAULL,
		0xC35D10C963F1B7CDULL,
		0x62E054429CCE3B88ULL,
		0xAC36EF4139CD729EULL,
		0x5A0393C1E2DF1A87ULL,
		0x73492390FDF746CAULL,
		0x38CFCF2712D99764ULL
	}};
	sign = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D854C8BC011D6D2ULL,
		0xDE5355A533D05C7FULL,
		0x3F3C04F990855012ULL,
		0x26CFE5C92B67D82DULL,
		0xDCCE910CDD89B56CULL,
		0x3C6E6E3F090BDE6EULL,
		0xCE154EB985100B21ULL,
		0x28F538F4D3DF2CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFFF3BEC5A86948ULL,
		0xD431A54DF9FED39FULL,
		0x8666661EEB9022A0ULL,
		0xE347E12A8A467C03ULL,
		0xAD827FC94BB44A7EULL,
		0x657A072A5404A8B3ULL,
		0x280493BB607FDB7CULL,
		0x1A1437B288921983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x608558CCFA696D8AULL,
		0x0A21B05739D188E0ULL,
		0xB8D59EDAA4F52D72ULL,
		0x4388049EA1215C29ULL,
		0x2F4C114391D56AEDULL,
		0xD6F46714B50735BBULL,
		0xA610BAFE24902FA4ULL,
		0x0EE101424B4D133DULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B80B90FBB06046AULL,
		0x89BA77A17F18B26EULL,
		0x1FB5A981E943F394ULL,
		0x4A26FC6D63EFFE1FULL,
		0x44B5065CD24346CFULL,
		0x10EF270879B5D93DULL,
		0x48A406682AD8A538ULL,
		0x9BEE4FD37CBD40B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A6ABA2B7BA05AEULL,
		0x7B62DC71F99F5DC6ULL,
		0x04F4CC107E6BA475ULL,
		0xFDDD60F382A7E2BBULL,
		0x4ABE26560F19607AULL,
		0xBF5841B4B1DC6922ULL,
		0x9B58952E13934B21ULL,
		0x1B1680B35F755B7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5DA0D6D034BFEBCULL,
		0x0E579B2F857954A7ULL,
		0x1AC0DD716AD84F1FULL,
		0x4C499B79E1481B64ULL,
		0xF9F6E006C329E654ULL,
		0x5196E553C7D9701AULL,
		0xAD4B713A17455A16ULL,
		0x80D7CF201D47E536ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8F6DBC5CF99BA48ULL,
		0xD32BCEC9C93A02ECULL,
		0x12E19E08BC39AAEBULL,
		0xCD9093F74A29E12DULL,
		0xBC26E860B2EF6563ULL,
		0x630067CEE5157657ULL,
		0x0CECEF25CE0A9B29ULL,
		0xDB8950BF51A19F18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F56A81EC569F692ULL,
		0x5BE39AD9742A89B6ULL,
		0x118BF9CFE69EF42FULL,
		0xC2C6FB4CBDEA4F19ULL,
		0xF58F660813110584ULL,
		0xC411BE3343C98908ULL,
		0x52C8054DF0841E4FULL,
		0xF92B1FC1C60561F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79A033A70A2FC3B6ULL,
		0x774833F0550F7936ULL,
		0x0155A438D59AB6BCULL,
		0x0AC998AA8C3F9214ULL,
		0xC69782589FDE5FDFULL,
		0x9EEEA99BA14BED4EULL,
		0xBA24E9D7DD867CD9ULL,
		0xE25E30FD8B9C3D21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8606CA623CE155E4ULL,
		0x283A51FCD8EBF472ULL,
		0x0D6FDADA45A0CB20ULL,
		0x91E682B6C00DB5DFULL,
		0xF1FC8E99390AC082ULL,
		0x51D9A9800AACFE27ULL,
		0x955DC999C4C14AB9ULL,
		0x075039D8230CBE1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4FDFD52D4F7902ULL,
		0x69D4059C622723ECULL,
		0xE3C91EC0C4A759B4ULL,
		0xF51DC99C29F4BC82ULL,
		0x484842EB2A4E77D3ULL,
		0xCA966C452863DD85ULL,
		0xFDBA93F5B43C8658ULL,
		0xBB62065C4A4FFDA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB6EA8D0F91DCE2ULL,
		0xBE664C6076C4D085ULL,
		0x29A6BC1980F9716BULL,
		0x9CC8B91A9618F95CULL,
		0xA9B44BAE0EBC48AEULL,
		0x87433D3AE24920A2ULL,
		0x97A335A41084C460ULL,
		0x4BEE337BD8BCC073ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA025F4A73D464180ULL,
		0x13F387C2DF7E2628ULL,
		0x2196D0C56EF3E938ULL,
		0xBA14B090D6D8C20FULL,
		0xEF0BF95B94682456ULL,
		0x907192516CE8C71BULL,
		0xEB4FD0E6EEC648FAULL,
		0x54A805305A0E1B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A75BD63C345C71ULL,
		0x56A331AB6DAF1A99ULL,
		0xE9A4A0582DC626CCULL,
		0x17A3C98B091B8EF4ULL,
		0x8D2921968FD0D30EULL,
		0x63821DD2278F1262ULL,
		0x8A8DF0D83ABE9DCCULL,
		0x632B21B76F412579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A7E98D10111E50FULL,
		0xBD50561771CF0B8FULL,
		0x37F2306D412DC26BULL,
		0xA270E705CDBD331AULL,
		0x61E2D7C504975148ULL,
		0x2CEF747F4559B4B9ULL,
		0x60C1E00EB407AB2EULL,
		0xF17CE378EACCF600ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D01ABE09A34D80BULL,
		0xB210968FD7D5EC5AULL,
		0x4ACC1C2863920A20ULL,
		0x1640F9240E1C9271ULL,
		0x41B39940820770E5ULL,
		0x705198F360C0F937ULL,
		0x9C6BB77BC60751A7ULL,
		0x2B834202F2E61105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642DD0ECD6454593ULL,
		0xFEB15013BE829EC1ULL,
		0x181BAF7A1E742362ULL,
		0xB83A8054BD5698EBULL,
		0x359F2B0478FC85ECULL,
		0xEF8E07FB4879D578ULL,
		0xCBB9DD87969A2A7DULL,
		0xEB85BED08D7DEC64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8D3DAF3C3EF9278ULL,
		0xB35F467C19534D98ULL,
		0x32B06CAE451DE6BDULL,
		0x5E0678CF50C5F986ULL,
		0x0C146E3C090AEAF8ULL,
		0x80C390F8184723BFULL,
		0xD0B1D9F42F6D2729ULL,
		0x3FFD8332656824A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EA2F164E4D4D6E1ULL,
		0x4CCB078072BA77B6ULL,
		0xE5CC6D31D571DB65ULL,
		0x3BDBDBFD6A484898ULL,
		0x915B46F4710DD025ULL,
		0xFADD2F2D8DCAD4ECULL,
		0x10EDB94397E7044AULL,
		0x29A113C70120A5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0540A1E6BB639C70ULL,
		0x23BBA62FD7ACD59AULL,
		0xF1F06E3271DEFB3BULL,
		0x79C5CF836D6B6CB4ULL,
		0xD8B2C0AEC684FEFEULL,
		0x5837BA7344AF9126ULL,
		0x915577C57181E148ULL,
		0x33480335AD5A1A65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49624F7E29713A71ULL,
		0x290F61509B0DA21CULL,
		0xF3DBFEFF6392E02AULL,
		0xC2160C79FCDCDBE3ULL,
		0xB8A88645AA88D126ULL,
		0xA2A574BA491B43C5ULL,
		0x7F98417E26652302ULL,
		0xF659109153C68B5AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FCA4DDF6E4D9D0FULL,
		0xF8168A1C8C48C654ULL,
		0xFA25991742B78DEDULL,
		0x004258AC4EE63B00ULL,
		0x792F8EE12AA5DFEEULL,
		0x619075A4DBA3C68EULL,
		0x0EC1A4F799DC2E2BULL,
		0x5E8275D9B4AC8D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC0E0255314587B1ULL,
		0xC46494D007BC6EEDULL,
		0x4466C9293DF92561ULL,
		0xC660338B2DB5AFCCULL,
		0xA185B3C4B4AC68E7ULL,
		0x240326C703FB6C7FULL,
		0xE155CBA94B4491F8ULL,
		0x22B6C86E72657FAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83BC4B8A3D08155EULL,
		0x33B1F54C848C5766ULL,
		0xB5BECFEE04BE688CULL,
		0x39E2252121308B34ULL,
		0xD7A9DB1C75F97706ULL,
		0x3D8D4EDDD7A85A0EULL,
		0x2D6BD94E4E979C33ULL,
		0x3BCBAD6B42470D91ULL
	}};
	sign = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F86EA51EF9D62CEULL,
		0xA0B9BA05EE7DC247ULL,
		0xF3568EC0C7F84925ULL,
		0x3C1CCA91E977B0ABULL,
		0x9CBE61AE583B1E68ULL,
		0x17A2C2428FFEC140ULL,
		0x81A827C350F2173DULL,
		0x8EF4C7E3812D4F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9F183AFB8B2D5AULL,
		0xACE4ABF649A91219ULL,
		0x53640F17601D98C8ULL,
		0x3DC49171DB5E720BULL,
		0x2E5C7EFAAC4C737DULL,
		0xD90CCE2086A6BD3BULL,
		0x36E79F5F5EA9B2ABULL,
		0x07ED17F3276EA95DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FE7D216F4123574ULL,
		0xF3D50E0FA4D4B02EULL,
		0x9FF27FA967DAB05CULL,
		0xFE5839200E193EA0ULL,
		0x6E61E2B3ABEEAAEAULL,
		0x3E95F42209580405ULL,
		0x4AC08863F2486491ULL,
		0x8707AFF059BEA5C6ULL
	}};
	sign = 0;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BDF23937CB3F792ULL,
		0x396144CB4B548B33ULL,
		0x92FA62D33BD4D089ULL,
		0x59605F56E7E18463ULL,
		0xC4B07CE8ACCCECEEULL,
		0xCA43D18487DAE408ULL,
		0xE0DE5EB2C2577E47ULL,
		0x617A878D74BC847EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9567A45956075BB8ULL,
		0x2627E487FCC6E1E5ULL,
		0xE39DCFF6AD12BD91ULL,
		0x093719C79A331A24ULL,
		0x2DB9FAF195EC718FULL,
		0xE37783F5390E72BEULL,
		0x10EC28D76EECA2F5ULL,
		0x3DA031D3F75E2A6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6777F3A26AC9BDAULL,
		0x133960434E8DA94DULL,
		0xAF5C92DC8EC212F8ULL,
		0x5029458F4DAE6A3EULL,
		0x96F681F716E07B5FULL,
		0xE6CC4D8F4ECC714AULL,
		0xCFF235DB536ADB51ULL,
		0x23DA55B97D5E5A12ULL
	}};
	sign = 0;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2A3452B263BC4C9ULL,
		0xA1E0372E5016D64CULL,
		0xB03F8CA40F08A94BULL,
		0x3B6B7371C115DEB4ULL,
		0xD34C00F1FD547429ULL,
		0x7D4BED46B106D978ULL,
		0x06D9C38F97589C31ULL,
		0x558588E9DDC0A2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE423E43C1CE684C3ULL,
		0x06BC07A773AF3F0AULL,
		0xACAC8C4E19E99F77ULL,
		0x89C68A5F430BB078ULL,
		0xF7E696CDD33702B0ULL,
		0x47A7C49A119C88BDULL,
		0x3AE8AA53C5503B24ULL,
		0x63E9B330DDE2CE22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE7F60EF09554006ULL,
		0x9B242F86DC679741ULL,
		0x03930055F51F09D4ULL,
		0xB1A4E9127E0A2E3CULL,
		0xDB656A242A1D7178ULL,
		0x35A428AC9F6A50BAULL,
		0xCBF1193BD208610DULL,
		0xF19BD5B8FFDDD49CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB41FC04171C9A4AFULL,
		0x3DE74004F5300A8CULL,
		0x7925D54BCD3696A1ULL,
		0x5D719C33C02F955BULL,
		0x3F4E54459FB7C935ULL,
		0x680CD23298F20BF2ULL,
		0x85C487D065664D58ULL,
		0x768080364625027BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19799433803FA9FCULL,
		0xE44E32CF420870DFULL,
		0x95A4C7F9EAB6F958ULL,
		0x68B879BC3F157710ULL,
		0x4A29A5A126ADC628ULL,
		0x628891938320D82FULL,
		0x3788AB697D653F83ULL,
		0x0B47030FEFAF937CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AA62C0DF189FAB3ULL,
		0x59990D35B32799ADULL,
		0xE3810D51E27F9D48ULL,
		0xF4B92277811A1E4AULL,
		0xF524AEA4790A030CULL,
		0x0584409F15D133C2ULL,
		0x4E3BDC66E8010DD5ULL,
		0x6B397D2656756EFFULL
	}};
	sign = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x084BEEA6127BC41EULL,
		0xA47732EB5CDB4CAFULL,
		0x12AA5881A61CBC30ULL,
		0x19693A6ABB63AC74ULL,
		0x04A1B58093D9B31BULL,
		0xBE644512D6CB35D9ULL,
		0xAA7F94450F3F3EBCULL,
		0x173B707D509AE842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9EAB2D9DA893C9DULL,
		0xE12B1816AC132CEDULL,
		0x62E4ABD08B529E46ULL,
		0x787BA1C508F22C83ULL,
		0xED6C0C9F01C25283ULL,
		0xDE4319B1439B9229ULL,
		0x74B60A5062CD3E5CULL,
		0x0EC31ED84AB97F1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E613BCC37F28781ULL,
		0xC34C1AD4B0C81FC1ULL,
		0xAFC5ACB11ACA1DE9ULL,
		0xA0ED98A5B2717FF0ULL,
		0x1735A8E192176097ULL,
		0xE0212B61932FA3AFULL,
		0x35C989F4AC72005FULL,
		0x087851A505E16923ULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3501158ADE4E795EULL,
		0xAC89A671EBF57FA1ULL,
		0x6186D10AED024779ULL,
		0xFE5D78146E186CDBULL,
		0xB52AC6F5C5889666ULL,
		0x76C6B93D04392F82ULL,
		0xDE114D602CD2CD13ULL,
		0x464CD85F801C9E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF894C994CC0D34D8ULL,
		0x2E997FF0E90522FDULL,
		0xB25DD0FA7C748583ULL,
		0x9BAA814EE5B403D3ULL,
		0xE99A9E4B123C1388ULL,
		0x2EEE415E96994556ULL,
		0x58AEE1EDE58D3D7AULL,
		0xAC8982B10781163DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C6C4BF612414486ULL,
		0x7DF0268102F05CA3ULL,
		0xAF290010708DC1F6ULL,
		0x62B2F6C588646907ULL,
		0xCB9028AAB34C82DEULL,
		0x47D877DE6D9FEA2BULL,
		0x85626B7247458F99ULL,
		0x99C355AE789B8804ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68267B1424FE5DA7ULL,
		0xE148A8651D5B2430ULL,
		0xAAEB61AAC7D1B4FBULL,
		0xB00C223108C46D90ULL,
		0x7E3D06254CAB5779ULL,
		0x0A38C7A2178F24CDULL,
		0xD7DDDD48C3E00DD0ULL,
		0xB464946AB29F3223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14488F291758E312ULL,
		0xB5C6A6CEBEDD55B3ULL,
		0x78258ED5FAE7F27FULL,
		0x78D1B420B7CD319BULL,
		0x4338AE4CA744B8CCULL,
		0x9B115A37D0F5E644ULL,
		0x09AD83B601057FC5ULL,
		0x594F3BC13A4F1584ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53DDEBEB0DA57A95ULL,
		0x2B8201965E7DCE7DULL,
		0x32C5D2D4CCE9C27CULL,
		0x373A6E1050F73BF5ULL,
		0x3B0457D8A5669EADULL,
		0x6F276D6A46993E89ULL,
		0xCE305992C2DA8E0AULL,
		0x5B1558A978501C9FULL
	}};
	sign = 0;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74C07BCB3F6724F7ULL,
		0x8E7A7C0C7A9341C4ULL,
		0x763D731EB71090DCULL,
		0xD49D73E70B131633ULL,
		0x0ECD3415AFB400BBULL,
		0x7A40E190BAAC3F69ULL,
		0x2CE8DBECDA9A9D4DULL,
		0xD031D9F34037618DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA36B833E86567EDULL,
		0x6EA690C520BE5DDDULL,
		0x1C678B367BB49F9AULL,
		0x98DFAD43FE3D3D21ULL,
		0x1CF70B170EC92463ULL,
		0x3E247E95780000F1ULL,
		0x14EAD234ED2C3FE3ULL,
		0x77C7A4855D417FC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A89C3975701BD0AULL,
		0x1FD3EB4759D4E3E6ULL,
		0x59D5E7E83B5BF142ULL,
		0x3BBDC6A30CD5D912ULL,
		0xF1D628FEA0EADC58ULL,
		0x3C1C62FB42AC3E77ULL,
		0x17FE09B7ED6E5D6AULL,
		0x586A356DE2F5E1C4ULL
	}};
	sign = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74C66816E2DA8DCCULL,
		0x2345BB6B8E518A0CULL,
		0x0BF0B45623027C50ULL,
		0x93BB8125F0CC999CULL,
		0x53AB2C8DED51025DULL,
		0x673BD534DC56BC2CULL,
		0x1FFD5E7CE2215FDDULL,
		0xE88684199C0B4C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x560C0AE8B356A3E0ULL,
		0x47EED59E9BCD6799ULL,
		0x3709FBDB6BDDFF4FULL,
		0x0451344F5AFD85F9ULL,
		0x2AAB7D3EBA08F1F9ULL,
		0xF9E5CBC8F7CE9B63ULL,
		0x8FE212BB365A4A9BULL,
		0xB7E872ED8DCF6C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EBA5D2E2F83E9ECULL,
		0xDB56E5CCF2842273ULL,
		0xD4E6B87AB7247D00ULL,
		0x8F6A4CD695CF13A2ULL,
		0x28FFAF4F33481064ULL,
		0x6D56096BE48820C9ULL,
		0x901B4BC1ABC71541ULL,
		0x309E112C0E3BE07BULL
	}};
	sign = 0;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA262AD4F187F3679ULL,
		0x4D9A07BE04C0D128ULL,
		0xED55E90D8B1B5DF6ULL,
		0x4417F4646C122F21ULL,
		0xC6B8ECE77657E5C9ULL,
		0x7748B9FFB76544E4ULL,
		0x36C3D3EE5E95CAEBULL,
		0xD81C8B42437604F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3559BC1E463676ULL,
		0x78194F261854196CULL,
		0x12F29FB215B34833ULL,
		0xBB009C4E9588B99DULL,
		0x4016D4FF9A8F42F6ULL,
		0x7DBE5DBAD088720DULL,
		0x90D8AA4CA5BA73EDULL,
		0x9F83C7929194EAA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC42D5392FA390003ULL,
		0xD580B897EC6CB7BBULL,
		0xDA63495B756815C2ULL,
		0x89175815D6897584ULL,
		0x86A217E7DBC8A2D2ULL,
		0xF98A5C44E6DCD2D7ULL,
		0xA5EB29A1B8DB56FDULL,
		0x3898C3AFB1E11A52ULL
	}};
	sign = 0;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x265356D0EA1FE6ACULL,
		0x26228F0BA1E43E58ULL,
		0xA3E404D7E8CA6F87ULL,
		0xC2AA42951F7EB744ULL,
		0xC6B6E91B7E8AF371ULL,
		0x5F02CDA584182C1FULL,
		0x92B38AB5057A7F95ULL,
		0x376C074D34A6A7F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1995C64975857814ULL,
		0x73F1820CB02C91E6ULL,
		0x247C1D68A4CA69BCULL,
		0x5CA643D2257112D3ULL,
		0xB66DEF1348772CD2ULL,
		0x3AF38C7A8DD268A9ULL,
		0x50B57588F2C229FBULL,
		0x604C47AA82CC5ED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CBD9087749A6E98ULL,
		0xB2310CFEF1B7AC72ULL,
		0x7F67E76F440005CAULL,
		0x6603FEC2FA0DA471ULL,
		0x1048FA083613C69FULL,
		0x240F412AF645C376ULL,
		0x41FE152C12B8559AULL,
		0xD71FBFA2B1DA491EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD17660DF542D80EBULL,
		0x0B69BB72B1DB71FCULL,
		0xAF57AF4611B2647AULL,
		0x7B677DB2A257280FULL,
		0xC4AD66F3BC18189DULL,
		0xE8BF0F1FB2A3477CULL,
		0x1B449C9214515FB5ULL,
		0xD7E51B285C9016D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6495188D0242BA76ULL,
		0xF310756B3096E4CEULL,
		0x2625DA1A1AAC1F5AULL,
		0x62FF64AA71BAD68FULL,
		0x245315F49676E82BULL,
		0x84515F95B5423E50ULL,
		0x0034F650CFE622EAULL,
		0xA9DCFD40328E7EEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE1485251EAC675ULL,
		0x1859460781448D2EULL,
		0x8931D52BF706451FULL,
		0x18681908309C5180ULL,
		0xA05A50FF25A13072ULL,
		0x646DAF89FD61092CULL,
		0x1B0FA641446B3CCBULL,
		0x2E081DE82A0197E4ULL
	}};
	sign = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB853981CDDC60F45ULL,
		0x1A1A8020D474055CULL,
		0x84AFBAF7BD5C80D7ULL,
		0xB231AD75A6F414D3ULL,
		0xBE4C6A9732F7E7C2ULL,
		0x1C5F3962516741E0ULL,
		0xC30C9F15D276FF7FULL,
		0x94242BF2AE0E2F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC38AB0701505AEDBULL,
		0x7BB0599CAF689931ULL,
		0x8973F0928AFACE70ULL,
		0xD49823574D012964ULL,
		0x26528482C58CEFBFULL,
		0x1794F1EC2C0151FDULL,
		0xB566736CB84F6517ULL,
		0x434DC5A30A8B34D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4C8E7ACC8C0606AULL,
		0x9E6A2684250B6C2AULL,
		0xFB3BCA653261B266ULL,
		0xDD998A1E59F2EB6EULL,
		0x97F9E6146D6AF802ULL,
		0x04CA47762565EFE3ULL,
		0x0DA62BA91A279A68ULL,
		0x50D6664FA382FA4AULL
	}};
	sign = 0;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96F6CBF0B8B5904EULL,
		0xB908FEED383F1BC1ULL,
		0x0BF4C412B7E0967AULL,
		0x15EF89E3551A9EFAULL,
		0x792F26001F104AE8ULL,
		0x92464329EAFA1B3DULL,
		0xD4C84F84968D19F5ULL,
		0x907FB4600A569902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF265C785752AF109ULL,
		0x35457027841B45B4ULL,
		0xF198F67160B1A606ULL,
		0x60A9D149CD4AEC64ULL,
		0xCD8E194BE60167E1ULL,
		0x261411440995033FULL,
		0x2B94946D4839DF03ULL,
		0x9CB9CB4ED94F1987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA491046B438A9F45ULL,
		0x83C38EC5B423D60CULL,
		0x1A5BCDA1572EF074ULL,
		0xB545B89987CFB295ULL,
		0xABA10CB4390EE306ULL,
		0x6C3231E5E16517FDULL,
		0xA933BB174E533AF2ULL,
		0xF3C5E91131077F7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F50A2D4C45164A5ULL,
		0xEBA21702599300EFULL,
		0xE4A66EB86C091F26ULL,
		0x5698781E5686728DULL,
		0x7C3E6ECCB7309628ULL,
		0x15B7268C93E2C863ULL,
		0x787C4F6FB45B9AC6ULL,
		0xE652DF58F9351148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6D52B6B7A60547ULL,
		0x2E10FE1D69CAA6F4ULL,
		0xC63A06DB081B2838ULL,
		0x2CB3DD3B580B0A80ULL,
		0x76684072E7C8D52EULL,
		0x1693DFF16BFBE7B8ULL,
		0xFFC36FAEFF8D2167ULL,
		0x380787C1638F74F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E3501E0CAB5F5EULL,
		0xBD9118E4EFC859FBULL,
		0x1E6C67DD63EDF6EEULL,
		0x29E49AE2FE7B680DULL,
		0x05D62E59CF67C0FAULL,
		0xFF23469B27E6E0ABULL,
		0x78B8DFC0B4CE795EULL,
		0xAE4B579795A59C4EULL
	}};
	sign = 0;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC1BF5B382BBD4EULL,
		0x75A1CC55EE0FD543ULL,
		0x667923F0E5F90689ULL,
		0xD6BF2F9F9B977BF2ULL,
		0xEBFFE497887F75C0ULL,
		0x17301CAE3E5ABD2DULL,
		0xA808EF2FCB2F8D68ULL,
		0xE23C6CF249AE3E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CEC2C30AAC9CFFULL,
		0x1AAE51DCEE05DCEFULL,
		0x732ABF75C2456BAAULL,
		0x6077794ADEDB9999ULL,
		0x5134141245100251ULL,
		0xABABBCF45F50C8E9ULL,
		0x6137C4A06B3C6048ULL,
		0x9655162694FDDC03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27F2FC982D7F204FULL,
		0x5AF37A790009F854ULL,
		0xF34E647B23B39ADFULL,
		0x7647B654BCBBE258ULL,
		0x9ACBD085436F736FULL,
		0x6B845FB9DF09F444ULL,
		0x46D12A8F5FF32D1FULL,
		0x4BE756CBB4B06297ULL
	}};
	sign = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA7B58D9FDCCA2AFULL,
		0xA73B4236EEFE0320ULL,
		0x179B3F27D086D0AEULL,
		0x5FB72C20D9A9FC43ULL,
		0xB5E80196C86B8165ULL,
		0xBA6F32FFD1129F3CULL,
		0x8CEFDD12E505E4BCULL,
		0xDDCCB4FEE64A7C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DCFB64F4CC4E276ULL,
		0x4BA9CE264B6ED25BULL,
		0x9C98D86DFE3D5233ULL,
		0x8D29DF2752A1C39BULL,
		0x09898FDEAA1FE956ULL,
		0x6655C45377F6A189ULL,
		0x7AD3F60C949B11ACULL,
		0xFF5F089C679DC7C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCABA28AB107C039ULL,
		0x5B917410A38F30C5ULL,
		0x7B0266B9D2497E7BULL,
		0xD28D4CF9870838A7ULL,
		0xAC5E71B81E4B980EULL,
		0x54196EAC591BFDB3ULL,
		0x121BE706506AD310ULL,
		0xDE6DAC627EACB47EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54FA2E41B00ACA02ULL,
		0x9BD72028B233E3A8ULL,
		0x5192341AF2663F2AULL,
		0xBEF2632084463176ULL,
		0xADACF48A466C430DULL,
		0x73B6765AC0748D67ULL,
		0x9B5775D8D3486390ULL,
		0xBB88878AD56BD42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFA2DE48AFC1989ULL,
		0x6D84700155FDB930ULL,
		0xFEC77E905CB438E9ULL,
		0x7EA875DECFFC274AULL,
		0xD85933D6B039A1A8ULL,
		0xD0FF03A0C7B4895BULL,
		0x8ACD8EE34F3D53FBULL,
		0xE2EBDCA564D78BADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC500005D250EB079ULL,
		0x2E52B0275C362A77ULL,
		0x52CAB58A95B20641ULL,
		0x4049ED41B44A0A2BULL,
		0xD553C0B39632A165ULL,
		0xA2B772B9F8C0040BULL,
		0x1089E6F5840B0F94ULL,
		0xD89CAAE570944881ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0A1D7729A403AEEULL,
		0x30EC6E345C8C5AF3ULL,
		0x748F82DE9C489E7EULL,
		0x8D9F511E0CC72EE0ULL,
		0x7C262B9C375107CFULL,
		0xC27D64D92C04769CULL,
		0x1CDA18BBBD23B558ULL,
		0xA36294371C786C1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x865AD60B6F2883DFULL,
		0x372CFCC41DC582A5ULL,
		0x1E43F7675D4D75FDULL,
		0x0A0855595F098A7AULL,
		0xC892197636FDEBB0ULL,
		0x439FCC7FB31D1632ULL,
		0x15FBABC2934A9A51ULL,
		0x43C969580403A7B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A4701672B17B70FULL,
		0xF9BF71703EC6D84EULL,
		0x564B8B773EFB2880ULL,
		0x8396FBC4ADBDA466ULL,
		0xB394122600531C1FULL,
		0x7EDD985978E76069ULL,
		0x06DE6CF929D91B07ULL,
		0x5F992ADF1874C469ULL
	}};
	sign = 0;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB195FC61AA6B40A5ULL,
		0xA1FA75CCD1793484ULL,
		0x59AEFC3A18DED027ULL,
		0x73BC35C0AB7E89B0ULL,
		0x3CB384429AF1ECBBULL,
		0xA165EAF2EB44A842ULL,
		0x451898A47CE3DEC2ULL,
		0x52BA1B9844D45FE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A97C118E499C9CULL,
		0xE08FBB1439973402ULL,
		0x6D9B843F6794E53DULL,
		0x55B3B158BE64BAEBULL,
		0x6AB4895FC49CC0E9ULL,
		0x196DB947C61EF9EAULL,
		0x631278C497AEE369ULL,
		0x0AA179396C045DEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CEC80501C21A409ULL,
		0xC16ABAB897E20082ULL,
		0xEC1377FAB149EAE9ULL,
		0x1E088467ED19CEC4ULL,
		0xD1FEFAE2D6552BD2ULL,
		0x87F831AB2525AE57ULL,
		0xE2061FDFE534FB59ULL,
		0x4818A25ED8D001F2ULL
	}};
	sign = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA9469647F994E34ULL,
		0x52FA7B7A23E95964ULL,
		0x493D10EF6EA85CC9ULL,
		0x2E95859035C892DDULL,
		0x8297C1D0BEDBAAAFULL,
		0xA0E3029D2F03C3A9ULL,
		0x769C4DE7EB85F259ULL,
		0xA41BCC8F7F27263CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3844E3BC314141ULL,
		0xA7F7B780DBB1071AULL,
		0xDBADC854B291CDCEULL,
		0xB45D70DAFDAE271AULL,
		0xF162FC11BEEBB24FULL,
		0xA753311555AABDCAULL,
		0x19FD3FCD98CFEB50ULL,
		0xF6BC7BFE39670DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD5C2480C3680CF3ULL,
		0xAB02C3F948385249ULL,
		0x6D8F489ABC168EFAULL,
		0x7A3814B5381A6BC2ULL,
		0x9134C5BEFFEFF85FULL,
		0xF98FD187D95905DEULL,
		0x5C9F0E1A52B60708ULL,
		0xAD5F509145C0188BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x813C80B86A18D1C7ULL,
		0x0A5D090C0CCE8D1DULL,
		0x8C3883D1DF2DD44AULL,
		0x7FD20CAA58C3D69FULL,
		0x71298D115927FCD7ULL,
		0xF12D8A885A89EE8EULL,
		0xB6365342CFE4B805ULL,
		0xD8AD16986B9EFFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30197E87BD5B784ULL,
		0xD4BF9DCCCFE58F1EULL,
		0x37C18F07DDB2BA14ULL,
		0xDFAE656BC95731D9ULL,
		0x84BBFE390E43F31DULL,
		0x8B2FCB24E63CC6DBULL,
		0x94C51619F628AD3EULL,
		0x5D2A34B38B4B5643ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E3AE8CFEE431A43ULL,
		0x359D6B3F3CE8FDFEULL,
		0x5476F4CA017B1A35ULL,
		0xA023A73E8F6CA4C6ULL,
		0xEC6D8ED84AE409B9ULL,
		0x65FDBF63744D27B2ULL,
		0x21713D28D9BC0AC7ULL,
		0x7B82E1E4E053A98FULL
	}};
	sign = 0;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FF0AE56C4F217B1ULL,
		0x7A7BD5553D518590ULL,
		0x2EC1CCE44139639EULL,
		0x746851DA2AA18602ULL,
		0x4A0F3D79E52D1BBFULL,
		0xF7D17313B41F7407ULL,
		0xB45DB781491C5352ULL,
		0x71C46AFC7A0977CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B919CBCFA6389DFULL,
		0x203168E7AFDF703DULL,
		0xEFBE5A2912B19F14ULL,
		0x0A189AD170FA2277ULL,
		0x88C63E3064F52780ULL,
		0x7423045D065F2898ULL,
		0x39A9F16726418796ULL,
		0x2B723D2B25B4B438ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF45F1199CA8E8DD2ULL,
		0x5A4A6C6D8D721552ULL,
		0x3F0372BB2E87C48AULL,
		0x6A4FB708B9A7638AULL,
		0xC148FF498037F43FULL,
		0x83AE6EB6ADC04B6EULL,
		0x7AB3C61A22DACBBCULL,
		0x46522DD15454C394ULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E6B3E81F6B21137ULL,
		0x6502B826375A9BC2ULL,
		0x0FDC470B013AE608ULL,
		0x1B1D9000059CEA9FULL,
		0x27FD732CA3607405ULL,
		0xB4A53ABB8DCD3066ULL,
		0xC4959E9FB5645230ULL,
		0xBEB832131131ED47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A91B2FBADDADB4CULL,
		0xAE87DDFD1F97A15AULL,
		0xD5461D878650967DULL,
		0xE24F12D09A136850ULL,
		0x641476C3FD47E707ULL,
		0x4D5632FD4F69DA32ULL,
		0x369703AA65F7AA65ULL,
		0xBB80B2B5853C0A90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3D98B8648D735EBULL,
		0xB67ADA2917C2FA67ULL,
		0x3A9629837AEA4F8AULL,
		0x38CE7D2F6B89824EULL,
		0xC3E8FC68A6188CFDULL,
		0x674F07BE3E635633ULL,
		0x8DFE9AF54F6CA7CBULL,
		0x03377F5D8BF5E2B7ULL
	}};
	sign = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A3C171FA8795D7EULL,
		0x82EA693A8A4F90F6ULL,
		0x7AA5CB1291B03EE7ULL,
		0xD2E4D7FA8524ACB9ULL,
		0x7A42DE5002154A19ULL,
		0x49FC1F17F4D61BB0ULL,
		0x34819F8B87F55DABULL,
		0xE7DC5893CC5D8F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF413FE97DBA5D901ULL,
		0xA6FB00D444BA0A2FULL,
		0x2F6B3C3244D3035BULL,
		0x10513952DB456BF9ULL,
		0xD7DB97053012A073ULL,
		0x24B9CE5B095A1B64ULL,
		0x3D4E2C0FF672BC2EULL,
		0xD15FA34E764DEAA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56281887CCD3847DULL,
		0xDBEF6866459586C6ULL,
		0x4B3A8EE04CDD3B8BULL,
		0xC2939EA7A9DF40C0ULL,
		0xA267474AD202A9A6ULL,
		0x254250BCEB7C004BULL,
		0xF733737B9182A17DULL,
		0x167CB545560FA470ULL
	}};
	sign = 0;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8762121E5D938CACULL,
		0xDBBA971627FA424AULL,
		0xB5215047E43BCC6BULL,
		0x8E9825C0FB3FB35BULL,
		0x3F307B2C336C3D39ULL,
		0x7B1467DB02534EDFULL,
		0x92E987894F2FF874ULL,
		0xB9F0BA2053E005FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C835159A8DBB53CULL,
		0xF9B9053C47B3C8D8ULL,
		0xA395D2A1F2B92ABBULL,
		0xDD4B165C13F32B23ULL,
		0xFC0F7BACD227202BULL,
		0x6F0FAB58BE2D53C6ULL,
		0xFEE9AB0DBC23FDC5ULL,
		0x4AEFEE5AD1441DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEADEC0C4B4B7D770ULL,
		0xE20191D9E0467971ULL,
		0x118B7DA5F182A1AFULL,
		0xB14D0F64E74C8838ULL,
		0x4320FF7F61451D0DULL,
		0x0C04BC824425FB18ULL,
		0x93FFDC7B930BFAAFULL,
		0x6F00CBC5829BE804ULL
	}};
	sign = 0;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x177E1F69B73E3FE7ULL,
		0x754475C478E56F8CULL,
		0x9195B28BAB05D2E2ULL,
		0x7B49E50C06BD8C17ULL,
		0xC928445925609CC8ULL,
		0xB45039D187DD7F28ULL,
		0xBE2B801BC4682FDAULL,
		0xDC9B2ACB1FA3E243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A98628B54936632ULL,
		0x0770711758F6870BULL,
		0x62FBB562191E393DULL,
		0xE89E539DFB7EFBC1ULL,
		0xA4D5116F818C4D69ULL,
		0x638C315103A99B5EULL,
		0xB732E828A685E7B8ULL,
		0x632CD8FAAFB5EA87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCE5BCDE62AAD9B5ULL,
		0x6DD404AD1FEEE880ULL,
		0x2E99FD2991E799A5ULL,
		0x92AB916E0B3E9056ULL,
		0x245332E9A3D44F5EULL,
		0x50C408808433E3CAULL,
		0x06F897F31DE24822ULL,
		0x796E51D06FEDF7BCULL
	}};
	sign = 0;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB20EF17F043E786ULL,
		0xD5A98C8A2CC6B95FULL,
		0xF2191086F9CB5B2DULL,
		0xB37F795D243AFE70ULL,
		0x6C7142C210848814ULL,
		0xA6E253BC499AE1DDULL,
		0x1F957F80D38C2AD8ULL,
		0x91933FA86DAFB074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C864751E1363B5EULL,
		0x9F8382AC5FED472FULL,
		0x3109F3EAF598351EULL,
		0x04BCC9C85DE20B20ULL,
		0x9CACC3CF71AB4726ULL,
		0xC769BF8C09068571ULL,
		0xB04551F00EEE2FF3ULL,
		0x0B4430216621871CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E9AA7C60F0DAC28ULL,
		0x362609DDCCD97230ULL,
		0xC10F1C9C0433260FULL,
		0xAEC2AF94C658F350ULL,
		0xCFC47EF29ED940EEULL,
		0xDF78943040945C6BULL,
		0x6F502D90C49DFAE4ULL,
		0x864F0F87078E2957ULL
	}};
	sign = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x664637055DA959ADULL,
		0x65F24CE198EA3B19ULL,
		0xE646FAD53B0BA430ULL,
		0xBA47DE6DB929CBBCULL,
		0xEAB88D490D57A809ULL,
		0x218BA03A46A36127ULL,
		0x0836F5130400F83AULL,
		0x6E8DC4A5B7090403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD25568E53355B078ULL,
		0x795991F61B43CD46ULL,
		0x8BE2780437008E8DULL,
		0x232E6C9D7F8BE8B8ULL,
		0x05750E466CBF873CULL,
		0x24ED93D87933379AULL,
		0x5357C954D72D1073ULL,
		0xA2752C53871AE7CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93F0CE202A53A935ULL,
		0xEC98BAEB7DA66DD2ULL,
		0x5A6482D1040B15A2ULL,
		0x971971D0399DE304ULL,
		0xE5437F02A09820CDULL,
		0xFC9E0C61CD70298DULL,
		0xB4DF2BBE2CD3E7C6ULL,
		0xCC1898522FEE1C37ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86E0F39CE3D99086ULL,
		0x70E4E9DB5736D6A4ULL,
		0x9545296390628DB5ULL,
		0xE364192AC63D57CAULL,
		0xA9337978F89172C4ULL,
		0x8895F819070A7928ULL,
		0xB49622C6DC054346ULL,
		0xAFF9AC3EACEC8965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE374E688EF460FULL,
		0x802C259FB61D188BULL,
		0x1033D602F528B085ULL,
		0x56B539F5623EB9F2ULL,
		0x92E0783D0A222295ULL,
		0x72BA0DB6FC32F329ULL,
		0xF55C81BE0F29EC87ULL,
		0xD719A173D175D88AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AFD7EB65AEA4A77ULL,
		0xF0B8C43BA119BE18ULL,
		0x851153609B39DD2FULL,
		0x8CAEDF3563FE9DD8ULL,
		0x1653013BEE6F502FULL,
		0x15DBEA620AD785FFULL,
		0xBF39A108CCDB56BFULL,
		0xD8E00ACADB76B0DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB03643A7A3523ECFULL,
		0xB7360091A7033806ULL,
		0x83897AF111001AA0ULL,
		0xA2E2405941AD87B0ULL,
		0x79C28526C2E2B500ULL,
		0x21D12ECC8ABD448BULL,
		0x7576DCF4E09EBB66ULL,
		0xDEF52F6D35BD7961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3A1C2EFBFCE8A88ULL,
		0xBBD6EB44AB8156C0ULL,
		0x484010621461BA87ULL,
		0x2330E028B1F41354ULL,
		0x20ED8605E7AB1B99ULL,
		0xE65544D3FB9CC23CULL,
		0xD94CA2800D53C43AULL,
		0x1B9204466082BAA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC9480B7E383B447ULL,
		0xFB5F154CFB81E145ULL,
		0x3B496A8EFC9E6018ULL,
		0x7FB160308FB9745CULL,
		0x58D4FF20DB379967ULL,
		0x3B7BE9F88F20824FULL,
		0x9C2A3A74D34AF72BULL,
		0xC3632B26D53ABEC0ULL
	}};
	sign = 0;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA43ABB2DCC7A008CULL,
		0xA396DA741AEC22B0ULL,
		0xC59F2B7BB87A8687ULL,
		0x10DBC0AF478D1660ULL,
		0xD39225DD9FA1916AULL,
		0x543233D90FFE5FBCULL,
		0x790010E3D0EA6FDDULL,
		0xB79940AA3C7F042CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF177A83E8D97BF83ULL,
		0xD18639004097CEDBULL,
		0xA6837596CDD34809ULL,
		0x46D05EED42E7A56FULL,
		0x7FDD710A6DCB9A51ULL,
		0xDD745312707E566AULL,
		0xF437D6B9020A801AULL,
		0x83A6101609520BD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C312EF3EE24109ULL,
		0xD210A173DA5453D4ULL,
		0x1F1BB5E4EAA73E7DULL,
		0xCA0B61C204A570F1ULL,
		0x53B4B4D331D5F718ULL,
		0x76BDE0C69F800952ULL,
		0x84C83A2ACEDFEFC2ULL,
		0x33F33094332CF856ULL
	}};
	sign = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x582675C5B2C8BE6EULL,
		0xB0BA2548949BCD87ULL,
		0x32E606569C12CC25ULL,
		0xCDFA9C7583756314ULL,
		0xD997DE8695EF5B7FULL,
		0x0DD8D61621ED8110ULL,
		0x7D1D233D1D93A497ULL,
		0x9307288F8D1939A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D912C4C22A638B5ULL,
		0xA6E65EBB6225ED42ULL,
		0x1FA1F602B9BFF7E8ULL,
		0xF1BD90A548471E46ULL,
		0xB6F987295AD04015ULL,
		0xA5B9632E6CCC65E1ULL,
		0x5BC162B6F593BC59ULL,
		0x955CB17B7FCD5A97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A954979902285B9ULL,
		0x09D3C68D3275E045ULL,
		0x13441053E252D43DULL,
		0xDC3D0BD03B2E44CEULL,
		0x229E575D3B1F1B69ULL,
		0x681F72E7B5211B2FULL,
		0x215BC08627FFE83DULL,
		0xFDAA77140D4BDF12ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x673A7BF6AEE40780ULL,
		0xF1932C907612025EULL,
		0xFFBF6C41BED575C8ULL,
		0x85074E127872EAF8ULL,
		0x6833439980477EA2ULL,
		0x735F0E810CF6318AULL,
		0xB5524428CFF02AABULL,
		0xEEE316A991A10BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2482670E14A1BE39ULL,
		0x629EE0A35BB86576ULL,
		0x0D2CE8EB2D7708F8ULL,
		0x379D166F461A3B91ULL,
		0x2851BD87F914FBB8ULL,
		0xF93DFCAD51E5B473ULL,
		0x532079BE4B688B71ULL,
		0x22ADFB6505246A9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42B814E89A424947ULL,
		0x8EF44BED1A599CE8ULL,
		0xF2928356915E6CD0ULL,
		0x4D6A37A33258AF67ULL,
		0x3FE18611873282EAULL,
		0x7A2111D3BB107D17ULL,
		0x6231CA6A84879F39ULL,
		0xCC351B448C7CA137ULL
	}};
	sign = 0;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC1C40E73D2AEC51ULL,
		0x441687451930F8F1ULL,
		0x513108E354376B71ULL,
		0xA0BFDB57ED829902ULL,
		0x703C44524D90BCD9ULL,
		0xFB791CA96191958CULL,
		0x1F1493BA24D2380CULL,
		0xAF30BD55067BCF7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98224A771910559DULL,
		0xF6A5FC81A6F962E5ULL,
		0x62E1832749F1CABBULL,
		0xF1CD1F6D4AC5E3ACULL,
		0xF59CA1EB8B442A4DULL,
		0x14611C0C58F95FA1ULL,
		0xC5E8693B07163BBEULL,
		0x7F08BCE994E56958ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13F9F670241A96B4ULL,
		0x4D708AC37237960CULL,
		0xEE4F85BC0A45A0B5ULL,
		0xAEF2BBEAA2BCB555ULL,
		0x7A9FA266C24C928BULL,
		0xE718009D089835EAULL,
		0x592C2A7F1DBBFC4EULL,
		0x3028006B71966621ULL
	}};
	sign = 0;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3520C77EE339ADCULL,
		0x255A5385C1498190ULL,
		0x11E332C5A4161B8EULL,
		0x070112B176048D77ULL,
		0xCA3900EFFE161C67ULL,
		0xCA2D701DA87F146CULL,
		0xA5EAE86BAD2FBED3ULL,
		0xAF663C447B5AB6DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B9922A837C2780DULL,
		0xD3CFFBD95BBE0015ULL,
		0x63B51E2F32AD08B2ULL,
		0x26C82E805FB681A2ULL,
		0x493339E32BBAAA2DULL,
		0xCFBDC90B609AEB42ULL,
		0x0C7589ABB23F2189ULL,
		0x562E3950569D5A8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97B8E9CFB67122CFULL,
		0x518A57AC658B817BULL,
		0xAE2E1496716912DBULL,
		0xE038E431164E0BD4ULL,
		0x8105C70CD25B7239ULL,
		0xFA6FA71247E4292AULL,
		0x99755EBFFAF09D49ULL,
		0x593802F424BD5C53ULL
	}};
	sign = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB12DAA069B82BBB6ULL,
		0x73E86F544BAAC942ULL,
		0xF695ACDC7CCEC272ULL,
		0xECF9273B205B3A82ULL,
		0xAB690FA5E39E9F0BULL,
		0x51BB370290924FFDULL,
		0x1C604CA9724B42B3ULL,
		0x9EB820E943EA21A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CD1C6B114A3BFFDULL,
		0x6EA7E7CD5228D02DULL,
		0xE9EF3E8496E76218ULL,
		0x8173A1583365DF4AULL,
		0xB56A8E1A5268246DULL,
		0xF149B227590ED7C9ULL,
		0x4AA5A67F39C29A33ULL,
		0x3210B3D271CBD497ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x345BE35586DEFBB9ULL,
		0x05408786F981F915ULL,
		0x0CA66E57E5E7605AULL,
		0x6B8585E2ECF55B38ULL,
		0xF5FE818B91367A9EULL,
		0x607184DB37837833ULL,
		0xD1BAA62A3888A87FULL,
		0x6CA76D16D21E4D0BULL
	}};
	sign = 0;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x526FCAE2266FB6FFULL,
		0xBD335FB56D5E371BULL,
		0xBB4FED46ECDD9C4DULL,
		0x7847AFA225E2D957ULL,
		0x7820F808019DA894ULL,
		0xF2691438DEE7541EULL,
		0x7C4A947A6882435EULL,
		0x73F98C001D41F627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7D51B13A2524E10ULL,
		0x07C1A13D4CCA1B25ULL,
		0xCF4C8D5BFAF68B4DULL,
		0x6308D3D9930AB146ULL,
		0x74568CFBABF63785ULL,
		0x860B1FB075C89B7CULL,
		0x607D64CCCE23F330ULL,
		0x39F0A058B7271738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A9AAFCE841D68EFULL,
		0xB571BE7820941BF5ULL,
		0xEC035FEAF1E71100ULL,
		0x153EDBC892D82810ULL,
		0x03CA6B0C55A7710FULL,
		0x6C5DF488691EB8A2ULL,
		0x1BCD2FAD9A5E502EULL,
		0x3A08EBA7661ADEEFULL
	}};
	sign = 0;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x017D15351F6B78CEULL,
		0x3EB5A4E882F2EE10ULL,
		0x0576878A87598307ULL,
		0x296D700589EEAFC7ULL,
		0xB4BB7FDEFC8FB15FULL,
		0x5BC6FFF2B2922271ULL,
		0x6BFD6DAFED6F0575ULL,
		0xF18F2A12752B3A83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59BFA9B1F6F3DA1DULL,
		0x38D328932C15F159ULL,
		0xA1D1DEFD4906C74AULL,
		0x7F5F7520810B5074ULL,
		0x0C9E2E3128AE1F63ULL,
		0xAE7E36C1BAAD5D2EULL,
		0xF2ACB1FD640B4B8EULL,
		0xB94D30CC2971F141ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7BD6B8328779EB1ULL,
		0x05E27C5556DCFCB6ULL,
		0x63A4A88D3E52BBBDULL,
		0xAA0DFAE508E35F52ULL,
		0xA81D51ADD3E191FBULL,
		0xAD48C930F7E4C543ULL,
		0x7950BBB28963B9E6ULL,
		0x3841F9464BB94941ULL
	}};
	sign = 0;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x554AB8208A250960ULL,
		0xC00CE8B36A83534DULL,
		0x4E5238454055C835ULL,
		0xE0820F2F12C6D2CDULL,
		0x7DD901C94277FA42ULL,
		0xE36FD057FE6B0A1FULL,
		0x199EB5BBF086E4C2ULL,
		0x36ACA7781F21FE69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB80ED4084F2B7AFULL,
		0x97259BED37469234ULL,
		0x1E82F47C82A8639BULL,
		0x17667A92359B903EULL,
		0x056CD17851D8BD2FULL,
		0xEA14A478EE670B41ULL,
		0x5B677CF850AF869CULL,
		0xFF8838B9D824CECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C9CAE0053251B1ULL,
		0x28E74CC6333CC118ULL,
		0x2FCF43C8BDAD649AULL,
		0xC91B949CDD2B428FULL,
		0x786C3050F09F3D13ULL,
		0xF95B2BDF1003FEDEULL,
		0xBE3738C39FD75E25ULL,
		0x37246EBE46FD2F9BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAFF43E935F1D8E5ULL,
		0x40D494392787BAFAULL,
		0x84530EB67D2C5AA5ULL,
		0x882FEBCCD28EDBF1ULL,
		0x8B35AA794AA61163ULL,
		0x1A5D131CDD0CC430ULL,
		0xFEF5F4FEB22C500EULL,
		0x45D61DC2AF92FB93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x422571A262813C67ULL,
		0xD02F3E9A4EA3FFB4ULL,
		0xDA9779E3B3D30775ULL,
		0x4E23C0E25E2D66E9ULL,
		0xCBF238B4E453BB90ULL,
		0x0D662B13DE43E7B9ULL,
		0xA11842DFCE267FF4ULL,
		0x7C2BFB10CE0F6DF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98D9D246D3709C7EULL,
		0x70A5559ED8E3BB46ULL,
		0xA9BB94D2C959532FULL,
		0x3A0C2AEA74617507ULL,
		0xBF4371C4665255D3ULL,
		0x0CF6E808FEC8DC76ULL,
		0x5DDDB21EE405D01AULL,
		0xC9AA22B1E1838D9BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE69D95C07A1D3B2CULL,
		0x81C20C9E26A7E39FULL,
		0x5D2A09314126725BULL,
		0x72104EB794F66F74ULL,
		0xD234690CE08BAEC6ULL,
		0xD80E29ADFE64B49FULL,
		0x0417E7ACFCC963B2ULL,
		0x359DFB1066487659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B5FF51823BCA6C5ULL,
		0xE5377235ECD71889ULL,
		0xA5FB8CF0DBE03964ULL,
		0x56C5B445ED2C394AULL,
		0x1ECFCF67F0184CE4ULL,
		0xA450B10B555688F8ULL,
		0xE93143BDD37295D2ULL,
		0x08DE922FCC25C552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B3DA0A856609467ULL,
		0x9C8A9A6839D0CB16ULL,
		0xB72E7C40654638F6ULL,
		0x1B4A9A71A7CA3629ULL,
		0xB36499A4F07361E2ULL,
		0x33BD78A2A90E2BA7ULL,
		0x1AE6A3EF2956CDE0ULL,
		0x2CBF68E09A22B106ULL
	}};
	sign = 0;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x447F55525104912CULL,
		0x557515D168681184ULL,
		0x17394E2189F382F5ULL,
		0x994386C52F2928F2ULL,
		0x746FADE3BD8DE2D7ULL,
		0x7C55FA741487EFBAULL,
		0x9A9A333FEACE9614ULL,
		0xF20F6EDF07EED01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC5107A0C96E730ULL,
		0xE1AE2F35BF06316FULL,
		0x7E7E0099D2521BA4ULL,
		0xBF2210FF07001449ULL,
		0xEA454014E23597E6ULL,
		0x2A9538DB737901ECULL,
		0x54607239D627A57BULL,
		0xD3B1983E9A514AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7BA44D8446DA9FCULL,
		0x73C6E69BA961E014ULL,
		0x98BB4D87B7A16750ULL,
		0xDA2175C6282914A8ULL,
		0x8A2A6DCEDB584AF0ULL,
		0x51C0C198A10EEDCDULL,
		0x4639C10614A6F099ULL,
		0x1E5DD6A06D9D8578ULL
	}};
	sign = 0;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x019391D7B74A448BULL,
		0x073D4A6451D0D681ULL,
		0x090C4B8167E66B16ULL,
		0x0E92274EAA8A29A4ULL,
		0x057A7A77A0FCFF25ULL,
		0xD75EDAFE64EA7DEBULL,
		0xDDF4C9C2F1F1BFC4ULL,
		0x3EF86766C1446857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957CF474B2D5D485ULL,
		0xF4865F3816F09372ULL,
		0xA8A4D47667D7666DULL,
		0xD0C2F3DFE6BDC4AAULL,
		0x3A381A568C4E778CULL,
		0xD5C5AE2D1C87D891ULL,
		0x59CDFC71FA6A5C4FULL,
		0x371216731D2135C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C169D6304747006ULL,
		0x12B6EB2C3AE0430EULL,
		0x6067770B000F04A8ULL,
		0x3DCF336EC3CC64F9ULL,
		0xCB42602114AE8798ULL,
		0x01992CD14862A559ULL,
		0x8426CD50F7876375ULL,
		0x07E650F3A4233291ULL
	}};
	sign = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF20499A492783541ULL,
		0x1DDF08E451AF6708ULL,
		0x21E6C2A1A2621515ULL,
		0x712BD0CB82589F4CULL,
		0xD081A4162CF1D059ULL,
		0x5A789234EEA1C1A8ULL,
		0x766A1CECA89D5DC0ULL,
		0xF8D1DAAEAC7AAC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03846C05D90AD549ULL,
		0xDC79072193274D82ULL,
		0x05CAAAAF970EDC62ULL,
		0x0438D48FCCCC894DULL,
		0xE476EE356A6B732BULL,
		0x99215666DD42500DULL,
		0xD4E62F7DC35E1C60ULL,
		0xEEA474147949AA07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE802D9EB96D5FF8ULL,
		0x416601C2BE881986ULL,
		0x1C1C17F20B5338B2ULL,
		0x6CF2FC3BB58C15FFULL,
		0xEC0AB5E0C2865D2EULL,
		0xC1573BCE115F719AULL,
		0xA183ED6EE53F415FULL,
		0x0A2D669A33310268ULL
	}};
	sign = 0;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DDE6955C7271F2FULL,
		0x1AB502BA98F59479ULL,
		0xA9E426FAB8130205ULL,
		0xC52DE402D54E9A58ULL,
		0x43FB1224BB8803A2ULL,
		0xE90F4C190426A7DAULL,
		0x0F95A4ADF11D7C65ULL,
		0xF0700326A82B2539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F315261A22844AULL,
		0x3B133DB45112333FULL,
		0x185D5697B3B3B48CULL,
		0xFFAAC429CDA748E8ULL,
		0x1992CCFDA19E146EULL,
		0x7D3FE02ED5C991EEULL,
		0x5EACDE3B14926EF3ULL,
		0x369FA320C40F2EA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54EB542FAD049AE5ULL,
		0xDFA1C50647E3613AULL,
		0x9186D063045F4D78ULL,
		0xC5831FD907A75170ULL,
		0x2A68452719E9EF33ULL,
		0x6BCF6BEA2E5D15ECULL,
		0xB0E8C672DC8B0D72ULL,
		0xB9D06005E41BF696ULL
	}};
	sign = 0;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8870095377E38FF8ULL,
		0x1DF3BAE1D312D7B7ULL,
		0xCD5688FEBA3FF55AULL,
		0x055E7A3B5BAD9606ULL,
		0x66056F270D76A021ULL,
		0x421339176B32559AULL,
		0x13C98942F25EEC93ULL,
		0x07F7841CFB4A4F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33C4490E75BBD25ULL,
		0x19DA578A2B6204FBULL,
		0x94AE9CF123199C2FULL,
		0x8AD50ADE3B727AB9ULL,
		0xB88286656A42E56AULL,
		0x794094D4CB8471A8ULL,
		0xF14FBCC41EAD52FAULL,
		0x3D772DEADC665502ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE533C4C29087D2D3ULL,
		0x04196357A7B0D2BBULL,
		0x38A7EC0D9726592BULL,
		0x7A896F5D203B1B4DULL,
		0xAD82E8C1A333BAB6ULL,
		0xC8D2A4429FADE3F1ULL,
		0x2279CC7ED3B19998ULL,
		0xCA8056321EE3FA4CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECF75E93892DAF1BULL,
		0xBBA43605D1E0B085ULL,
		0x55F8BC492879E89CULL,
		0x83FD4CFE344621E7ULL,
		0xF7A1DD223593BCFDULL,
		0x9E5B227832FC17D3ULL,
		0x3B0317F9232566CDULL,
		0x291C1528DCCB07C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAA68C53DF6233DULL,
		0x6CD2D60A3C05B971ULL,
		0xCAED849526208D48ULL,
		0xC2DF9B981B81C90FULL,
		0xF685F54419824B15ULL,
		0x62B27F7C20DFCE38ULL,
		0x887AE3DE731C2880ULL,
		0x5A878DCA74C44E31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE4CF5CE4B378BDEULL,
		0x4ED15FFB95DAF714ULL,
		0x8B0B37B402595B54ULL,
		0xC11DB16618C458D7ULL,
		0x011BE7DE1C1171E7ULL,
		0x3BA8A2FC121C499BULL,
		0xB288341AB0093E4DULL,
		0xCE94875E6806B98FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF639C4822CF82AULL,
		0xF63BFD8A1B029843ULL,
		0xAE966EBEC35C5987ULL,
		0x718794BA85802A25ULL,
		0x9F988CC456593DE9ULL,
		0x4FBEAE9E2E248C0BULL,
		0x50DF083E490DE142ULL,
		0x5A0B823A4145BC18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE4900FBDC17C82ULL,
		0x010EB3FFFCAFCB2DULL,
		0xA65F5D00F5BB5838ULL,
		0x288A9BCE8F7EF1D7ULL,
		0xE8433CE4C7F770E9ULL,
		0x77CC33BB7B2F8A68ULL,
		0x6DDA173D84F16390ULL,
		0xE60FF2DE9DB40C92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD11A9B4C46B7BA8ULL,
		0xF52D498A1E52CD15ULL,
		0x083711BDCDA1014FULL,
		0x48FCF8EBF601384EULL,
		0xB7554FDF8E61CD00ULL,
		0xD7F27AE2B2F501A2ULL,
		0xE304F100C41C7DB1ULL,
		0x73FB8F5BA391AF85ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B2A23171617DCFBULL,
		0xAB4C6DD083620243ULL,
		0x015DF37E5B9FBA2DULL,
		0xBDE06FF6C7BE6606ULL,
		0x829B4CCC8D7A47B3ULL,
		0x0C3A485CC39ADCFFULL,
		0x6E6212A8C9CBC4BEULL,
		0x6AB399C683DC028CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5009E9CCA9636094ULL,
		0x9924F52C7084D89AULL,
		0x619C99E45E47AD13ULL,
		0x56B71441A36D13B5ULL,
		0xDF47984A7B7819F3ULL,
		0xC75D7A1566FE99D4ULL,
		0x35F6ABC8DCF1B064ULL,
		0x7B34A0427746428EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB20394A6CB47C67ULL,
		0x122778A412DD29A8ULL,
		0x9FC15999FD580D1AULL,
		0x67295BB524515250ULL,
		0xA353B48212022DC0ULL,
		0x44DCCE475C9C432AULL,
		0x386B66DFECDA1459ULL,
		0xEF7EF9840C95BFFEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C1C146D914E4EF8ULL,
		0x9535D61BC5596655ULL,
		0x4AA772C18760789BULL,
		0xE870304355A613B0ULL,
		0x2E85B7430E1D80DAULL,
		0xF73385A8DBEBFD33ULL,
		0x32A4CC711807F6C8ULL,
		0x3D30F1BD36F81E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92624E5BF78E77C4ULL,
		0x2666A1A526AF1C7BULL,
		0x425E45580AA38EC4ULL,
		0xCCC8622217E054A4ULL,
		0xD31F026A5C6658D3ULL,
		0xDFC0175C6C7EDADAULL,
		0x0EF1E01C6F4DD5D3ULL,
		0x247A9C38868D8810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9B9C61199BFD734ULL,
		0x6ECF34769EAA49D9ULL,
		0x08492D697CBCE9D7ULL,
		0x1BA7CE213DC5BF0CULL,
		0x5B66B4D8B1B72807ULL,
		0x17736E4C6F6D2258ULL,
		0x23B2EC54A8BA20F5ULL,
		0x18B65584B06A95FFULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2ADDCDA788E06D0ULL,
		0x68811E48354B6815ULL,
		0x1509D94A4805C1F6ULL,
		0x20779DC1AA26A3BFULL,
		0x4E7F61768D3F43A9ULL,
		0x82F74ADD1FD8C890ULL,
		0x0FA2BD68C6153969ULL,
		0xBEE42430CD46B244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53A9B79C447A5C8ULL,
		0x28A9F4F173D87016ULL,
		0xD03279AAD5144516ULL,
		0x556252FB3EE9DD89ULL,
		0x5FDFC4B5114C9676ULL,
		0xD466D191567B27E6ULL,
		0xFF32196FE121B894ULL,
		0x1E88361B67F62B3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D734160B4466108ULL,
		0x3FD72956C172F7FFULL,
		0x44D75F9F72F17CE0ULL,
		0xCB154AC66B3CC635ULL,
		0xEE9F9CC17BF2AD32ULL,
		0xAE90794BC95DA0A9ULL,
		0x1070A3F8E4F380D4ULL,
		0xA05BEE1565508706ULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A0304F0E4BB21B7ULL,
		0x05BC57C3E898DBD3ULL,
		0x9C9EF3C1CDD92868ULL,
		0x3FDCD5AFB131CEBEULL,
		0x8BD9535DBFDFF3FFULL,
		0x1E6B524D367CB8BFULL,
		0x6846923912D57885ULL,
		0x45E6BE4E4B17F2C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FDC6FA9639482B1ULL,
		0xF0D0FBC16C93442DULL,
		0xF9A25A616F5A09D2ULL,
		0xA16E13A24F56E3CCULL,
		0x7AA6A4FAB76C4198ULL,
		0x01A69042A3579AF4ULL,
		0xA52E770963ACBBCCULL,
		0x33F4DEE20F47DB31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA26954781269F06ULL,
		0x14EB5C027C0597A5ULL,
		0xA2FC99605E7F1E95ULL,
		0x9E6EC20D61DAEAF1ULL,
		0x1132AE630873B266ULL,
		0x1CC4C20A93251DCBULL,
		0xC3181B2FAF28BCB9ULL,
		0x11F1DF6C3BD0178EULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF860A93C28A92864ULL,
		0xFC66B0C261FC1EB3ULL,
		0x7DC8CCCAE6E40F26ULL,
		0xEAA0DEC3B70F7D9AULL,
		0xD5A0B0498BADD300ULL,
		0x8A8885CB8A175551ULL,
		0xCF873C5D4055D8C1ULL,
		0xEBB02AEC8D9B57DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0352D61E65E5D939ULL,
		0xE448CA966A54C454ULL,
		0xDF437042255837D7ULL,
		0xC3416BEEFD39CB0EULL,
		0xB1A0E6F977B7BD59ULL,
		0x79306063E53CBDDFULL,
		0x6BAD529983E22A0BULL,
		0x7F19373B7BD4DB7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF50DD31DC2C34F2BULL,
		0x181DE62BF7A75A5FULL,
		0x9E855C88C18BD74FULL,
		0x275F72D4B9D5B28BULL,
		0x23FFC95013F615A7ULL,
		0x11582567A4DA9772ULL,
		0x63D9E9C3BC73AEB6ULL,
		0x6C96F3B111C67C5EULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99CB404D6D99900EULL,
		0x728E6C50B41DA724ULL,
		0xD8A72F1AFDC0D2D1ULL,
		0x907B329B819039CEULL,
		0xAC45E6E83E25C9F8ULL,
		0x35CE9D1778CABBB9ULL,
		0x081B525366C83051ULL,
		0x7298F60AF230D57EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC37AF9F38D5D0D4ULL,
		0xF5150880E0471ED7ULL,
		0xA6C53F73576135E0ULL,
		0x90441CE93FD1E27BULL,
		0xE1FF8120977EE7C8ULL,
		0x83161635583BECA3ULL,
		0x43D082FF40DCDC1AULL,
		0xE1D7BEC5AF3BD7D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD9390AE34C3BF3AULL,
		0x7D7963CFD3D6884CULL,
		0x31E1EFA7A65F9CF0ULL,
		0x003715B241BE5753ULL,
		0xCA4665C7A6A6E230ULL,
		0xB2B886E2208ECF15ULL,
		0xC44ACF5425EB5436ULL,
		0x90C1374542F4FDA4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B78AF6AACFF6358ULL,
		0x65F9B2DAD69201DAULL,
		0x84B710001CCB6AE3ULL,
		0x804109E1218C4237ULL,
		0xC3741B2A0E7B4FDBULL,
		0x971A1FF3505258BDULL,
		0x4EEEAFE6A76ABF6AULL,
		0xD7B4088E4BD07861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0212A919F8E7051FULL,
		0x15939D3F1C96C3CAULL,
		0xA63F61C3A205EA42ULL,
		0x4E7A89779CFEEE88ULL,
		0xDF16512800BE9BC7ULL,
		0x87C732FC25DE502DULL,
		0x2D4EF31C93454BBDULL,
		0x65B046A3285E8375ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79660650B4185E39ULL,
		0x5066159BB9FB3E10ULL,
		0xDE77AE3C7AC580A1ULL,
		0x31C68069848D53AEULL,
		0xE45DCA020DBCB414ULL,
		0x0F52ECF72A74088FULL,
		0x219FBCCA142573ADULL,
		0x7203C1EB2371F4ECULL
	}};
	sign = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34F94D52A0A189E1ULL,
		0x504BF3B53B70F7FAULL,
		0xD5136F9F3BA769C2ULL,
		0xC8514E2C65C30AB8ULL,
		0xB76EAF3E13DF2337ULL,
		0xCF632DD420EC6786ULL,
		0xA6EC3890880374C8ULL,
		0xAC575B6B4ACA8682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F83CE3706C131EULL,
		0x93FE3447F79E1AB1ULL,
		0x639C9D8B06A48DA4ULL,
		0xF6509AE6F054AE20ULL,
		0xCD702568C1BCC2ECULL,
		0x8F79808518666E6DULL,
		0x8A3B279E5DC0A55FULL,
		0x9179B144F3F482C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE01106F303576C3ULL,
		0xBC4DBF6D43D2DD48ULL,
		0x7176D2143502DC1DULL,
		0xD200B345756E5C98ULL,
		0xE9FE89D55222604AULL,
		0x3FE9AD4F0885F918ULL,
		0x1CB110F22A42CF69ULL,
		0x1ADDAA2656D603C2ULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA6B9547CD6D3F1DULL,
		0x4FA15FBBC3429A30ULL,
		0x46D2B83CB83F8B68ULL,
		0x291501BA14D7F72EULL,
		0x86BCB0B81855570AULL,
		0x9617BFCD9C246B86ULL,
		0x284195A88CC5357AULL,
		0x3C2D0548B4E0CB4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF95BF4B76C5DA15ULL,
		0x8EB179EA46594B85ULL,
		0x7B58F591E58BD043ULL,
		0x01DC836CF18F3CF0ULL,
		0xEB99ACD92E381E70ULL,
		0xB51AF41B37569DCDULL,
		0x614B1A337F621394ULL,
		0x1033A4D5500C569EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AD5D5FC56A76508ULL,
		0xC0EFE5D17CE94EABULL,
		0xCB79C2AAD2B3BB24ULL,
		0x27387E4D2348BA3DULL,
		0x9B2303DEEA1D389AULL,
		0xE0FCCBB264CDCDB8ULL,
		0xC6F67B750D6321E5ULL,
		0x2BF9607364D474AFULL
	}};
	sign = 0;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF2FAB1FD5F97CB1ULL,
		0x907AE3E14C65C9E5ULL,
		0x6D1BCB9AC7CAFFCEULL,
		0x34D28467C1D19CA7ULL,
		0xDE49462601165A0FULL,
		0x44042CE80887CCD2ULL,
		0x1DD8859721D9BCFDULL,
		0x8ABA32BFD93ED6A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC2B92E056E1A101ULL,
		0xE05F48DEDAE47D68ULL,
		0x8E91EC3395B5CAF2ULL,
		0x27F0990009AE53BEULL,
		0x97E2F900AAB9E597ULL,
		0x1F42340D45C156DCULL,
		0x4A6641389F1A0D23ULL,
		0x5D0B0D5EA5E15910ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1304183F7F17DBB0ULL,
		0xB01B9B0271814C7DULL,
		0xDE89DF67321534DBULL,
		0x0CE1EB67B82348E8ULL,
		0x46664D25565C7478ULL,
		0x24C1F8DAC2C675F6ULL,
		0xD372445E82BFAFDAULL,
		0x2DAF2561335D7D8FULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14DE21455065E423ULL,
		0xE974BA5523AE3A09ULL,
		0x2664A7893E50C843ULL,
		0x6B9CF45C1352C854ULL,
		0x86BE6F31D948A265ULL,
		0x864539022B4657FEULL,
		0x9865DE5B16773C2FULL,
		0x43A6171CF264CB6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEBFBBAED8738456ULL,
		0xCBFC26958F321AB4ULL,
		0x0FB5AA84FC986160ULL,
		0x8C6E9533248BAEBDULL,
		0xAE230BA1A82FA758ULL,
		0x9CDEA13F72B73818ULL,
		0x90E416AA5721EFB3ULL,
		0xC68D1127A3A2B358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x461E659677F25FCDULL,
		0x1D7893BF947C1F54ULL,
		0x16AEFD0441B866E3ULL,
		0xDF2E5F28EEC71997ULL,
		0xD89B63903118FB0CULL,
		0xE96697C2B88F1FE5ULL,
		0x0781C7B0BF554C7BULL,
		0x7D1905F54EC21812ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC3ECDA880EB7364ULL,
		0x5CE2E0F671DA9A28ULL,
		0xF9B2D891136FB095ULL,
		0xD45CE3CAE687074FULL,
		0xD986A66C04BBC7B2ULL,
		0xB531C7D939D1EEBAULL,
		0x34DEE91E73857D85ULL,
		0x053B138FED616ABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A8674578B2FE63ULL,
		0xDAA2C361933DCE71ULL,
		0x573A0B226111FD73ULL,
		0x751B04FCF5931E70ULL,
		0xB268DCD96AFCE6E4ULL,
		0x6666E2241CBD3A46ULL,
		0xA462CAADF93B0FCBULL,
		0x61C1985F8C0C4E9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD396666308387501ULL,
		0x82401D94DE9CCBB6ULL,
		0xA278CD6EB25DB321ULL,
		0x5F41DECDF0F3E8DFULL,
		0x271DC99299BEE0CEULL,
		0x4ECAE5B51D14B474ULL,
		0x907C1E707A4A6DBAULL,
		0xA3797B3061551C1DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6102211629D1E421ULL,
		0x58C12ADF0E8307A8ULL,
		0x3F0C71E964E7CC41ULL,
		0x393B365778F9C337ULL,
		0x4EB80D92B1D03164ULL,
		0x50E21607A8BB802DULL,
		0x3023B327057CF957ULL,
		0xDAE4F1E51D920E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCEC6BCFE4ADFA18ULL,
		0x4F3BC8629C1B6CECULL,
		0x1CD7FC6F454FA0BFULL,
		0x6BA8B1080DAE36EDULL,
		0x04D3C87F586EE4A5ULL,
		0xEED2A6300946B059ULL,
		0xE045D34E1B1EF114ULL,
		0x67A557C7208482FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8415B5464523EA09ULL,
		0x0985627C72679ABBULL,
		0x2234757A1F982B82ULL,
		0xCD92854F6B4B8C4AULL,
		0x49E4451359614CBEULL,
		0x620F6FD79F74CFD4ULL,
		0x4FDDDFD8EA5E0842ULL,
		0x733F9A1DFD0D8B45ULL
	}};
	sign = 0;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54BE39233E27796ULL,
		0x78580DE93BC5D66EULL,
		0xA63257763484F296ULL,
		0x0AABC00E15B7DC92ULL,
		0x6D769310AFA6A6C6ULL,
		0xC42B5CFFD74E989DULL,
		0xAAAB2993074C71F4ULL,
		0x22D60BA0E994E2B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BAD388F8E3067CULL,
		0xE572F7848FCF26CCULL,
		0xEF1ABF2A28FEF7C3ULL,
		0xAA9012237FBD7808ULL,
		0x00A03AFEF097F4F4ULL,
		0x5D52216072E04CCCULL,
		0x83275410EEB32FDEULL,
		0x44118E70B20AEAAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA39110093AFF711AULL,
		0x92E51664ABF6AFA2ULL,
		0xB717984C0B85FAD2ULL,
		0x601BADEA95FA6489ULL,
		0x6CD65811BF0EB1D1ULL,
		0x66D93B9F646E4BD1ULL,
		0x2783D58218994216ULL,
		0xDEC47D303789F80FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA877D9980190F87EULL,
		0xD07B9B523FE09032ULL,
		0xB0054AE535CC07F0ULL,
		0x55EA88977D641780ULL,
		0x090E925369A4AB97ULL,
		0x04C8D7915B94F273ULL,
		0x4F9A11D5D5FA421AULL,
		0x54CDCB9D9D9AAC38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B429AD8CE40CC20ULL,
		0x4FFE437CC25E83E0ULL,
		0x6E73C2EE531AB5BEULL,
		0x4368DD6C12662768ULL,
		0xA2A992D6CDB97399ULL,
		0xB28B3C129A34EB2AULL,
		0x4D2DB441B617B3C3ULL,
		0x343A7B2D685D6F81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D353EBF33502C5EULL,
		0x807D57D57D820C52ULL,
		0x419187F6E2B15232ULL,
		0x1281AB2B6AFDF018ULL,
		0x6664FF7C9BEB37FEULL,
		0x523D9B7EC1600748ULL,
		0x026C5D941FE28E56ULL,
		0x20935070353D3CB7ULL
	}};
	sign = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BAD58B30DD20916ULL,
		0x56E7F82666103941ULL,
		0x7443F74F9C098C71ULL,
		0xF2B46152A9A54CBAULL,
		0xD9FB828BAAC675E4ULL,
		0x37154741BCD4955DULL,
		0xF6B59E48B64CA0A6ULL,
		0xBDA597D1BAE50B26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9524DE54227CB8B6ULL,
		0x275E78330CB57BECULL,
		0xA993927B0F0D8DECULL,
		0x61DA62BEAE983E4DULL,
		0xE0507F2E13515A7EULL,
		0x03E6BD96638F3455ULL,
		0x009D7B66CC7B2685ULL,
		0x94348DE9336C869BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6887A5EEB555060ULL,
		0x2F897FF3595ABD54ULL,
		0xCAB064D48CFBFE85ULL,
		0x90D9FE93FB0D0E6CULL,
		0xF9AB035D97751B66ULL,
		0x332E89AB59456107ULL,
		0xF61822E1E9D17A21ULL,
		0x297109E88778848BULL
	}};
	sign = 0;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3CEC05ACC69233FULL,
		0x7F1557732F3E6EAEULL,
		0x3E9BFD93A629351EULL,
		0xDA97C6DD34EA32ADULL,
		0xE62062155DD373EDULL,
		0xD23FDBA77CE7119AULL,
		0xA2B5F48715117438ULL,
		0xB61F8545FB1700E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EC4276E53242706ULL,
		0x5BF6CFA76CCC90ACULL,
		0xAF3BB9292342B42FULL,
		0x5934202581633427ULL,
		0xBD7FD9E88A65AA94ULL,
		0xE8B8495C8380B55CULL,
		0x3D4EE038438FB38AULL,
		0xD8EC172E09A67E4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x650A98EC7944FC39ULL,
		0x231E87CBC271DE02ULL,
		0x8F60446A82E680EFULL,
		0x8163A6B7B386FE85ULL,
		0x28A0882CD36DC959ULL,
		0xE987924AF9665C3EULL,
		0x6567144ED181C0ADULL,
		0xDD336E17F1708299ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9915ACB5CEBF63E1ULL,
		0x5AE134B62C4344F2ULL,
		0x3E963E35AD57274AULL,
		0x4328012981DBD9C2ULL,
		0x3007442C3F96C497ULL,
		0x138D9B7568B8459EULL,
		0xCFB97B0C414B4E0EULL,
		0x44506F476B844BA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0E76C714FF262AULL,
		0xD20F570803473252ULL,
		0xEF79FC14A5AB4D79ULL,
		0x5FDDD53D7A9749C6ULL,
		0x46FEE2964BBAAE2BULL,
		0x9F31C9D4EEB276F3ULL,
		0x26A97CEFD13CF4BAULL,
		0x1D58FB0DE703C9BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C0735EEB9C03DB7ULL,
		0x88D1DDAE28FC12A0ULL,
		0x4F1C422107ABD9D0ULL,
		0xE34A2BEC07448FFBULL,
		0xE9086195F3DC166BULL,
		0x745BD1A07A05CEAAULL,
		0xA90FFE1C700E5953ULL,
		0x26F77439848081E1ULL
	}};
	sign = 0;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E845329C8E79D94ULL,
		0x757CE92854131E9FULL,
		0x6CDEF617C9B6CB14ULL,
		0xE229D73E7AE9806AULL,
		0x7001E0293274C21BULL,
		0x42FB2888B93E6A33ULL,
		0xDA3C6A88673B9923ULL,
		0x4A16C2B8B5807280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB5F84192A46C35ULL,
		0xF902BEA7A89FD9E4ULL,
		0x38EE9067A3B0E287ULL,
		0xA6FDB03EC338C0E3ULL,
		0x6D46CE4D0F03D574ULL,
		0xCDCD83A1B27217DEULL,
		0x13B20AA8710A970CULL,
		0x99BFC2936060D0B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70CE5AE83643315FULL,
		0x7C7A2A80AB7344BAULL,
		0x33F065B02605E88CULL,
		0x3B2C26FFB7B0BF87ULL,
		0x02BB11DC2370ECA7ULL,
		0x752DA4E706CC5255ULL,
		0xC68A5FDFF6310216ULL,
		0xB0570025551FA1D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BA28CF6C96A089DULL,
		0xE7D93088A34C496BULL,
		0xF71B8583934F7747ULL,
		0x5E16F23E8D82FB30ULL,
		0xD2AE2B338798E1B6ULL,
		0x64898C6455DF2A4AULL,
		0xED990C139C10DA94ULL,
		0x4F178FBB9E4AB543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD50E2B1A38E012BULL,
		0x5AB83378E80ABE1FULL,
		0x557C2D01F26AF1BAULL,
		0x6CD454A6C4A2EB43ULL,
		0xF4CD5AF933DF8C51ULL,
		0xAD0213986EFC143DULL,
		0xDEF4A848026C8148ULL,
		0xED938D98F46B39ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE51AA4525DC0772ULL,
		0x8D20FD0FBB418B4BULL,
		0xA19F5881A0E4858DULL,
		0xF1429D97C8E00FEDULL,
		0xDDE0D03A53B95564ULL,
		0xB78778CBE6E3160CULL,
		0x0EA463CB99A4594BULL,
		0x61840222A9DF7B98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C92C367A80A4E3AULL,
		0xAC8478C7288181B5ULL,
		0x1D381BE6A6C5F370ULL,
		0xFC29AA6B13253B89ULL,
		0x7A38BF84225FE560ULL,
		0x8065EFD369F8D8F2ULL,
		0x3BBD2C87409F1339ULL,
		0xD61978349865C022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F700841CB78BB9BULL,
		0xEA8E8BCFDD399870ULL,
		0xBBB03CFF3271674EULL,
		0xF952A20FF58A161CULL,
		0x68DAC875EC02591DULL,
		0x7A043E74EA351271ULL,
		0x3727CD6C6D61A0ABULL,
		0x45BF09CE7E4B9FD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D22BB25DC91929FULL,
		0xC1F5ECF74B47E945ULL,
		0x6187DEE774548C21ULL,
		0x02D7085B1D9B256CULL,
		0x115DF70E365D8C43ULL,
		0x0661B15E7FC3C681ULL,
		0x04955F1AD33D728EULL,
		0x905A6E661A1A204BULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE076D594DBEC6783ULL,
		0xB0FDDE5ACA8DF4C9ULL,
		0xE3920FC90B365F26ULL,
		0x9882AE8F2E941D28ULL,
		0x8E5DCFA5C723C53AULL,
		0x5C3041F2713BB8F5ULL,
		0x580BBFC4B47624DDULL,
		0x8FC491655E831759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F651401B7F1DDDULL,
		0x45175ACEAB856E7BULL,
		0x89354D680B6BB99FULL,
		0xAEFBD67CF750D2B9ULL,
		0xF0F921FCA1638557ULL,
		0xB588D0E3408170A6ULL,
		0xCB2ADAA77EE2DA84ULL,
		0x262F9CA80CDB5602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A808454C06D49A6ULL,
		0x6BE6838C1F08864EULL,
		0x5A5CC260FFCAA587ULL,
		0xE986D81237434A6FULL,
		0x9D64ADA925C03FE2ULL,
		0xA6A7710F30BA484EULL,
		0x8CE0E51D35934A58ULL,
		0x6994F4BD51A7C156ULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA0C902CA84FF7C2ULL,
		0xC883E1E258AF5EECULL,
		0xF908DB5E005F351CULL,
		0x439EDBC6B0397FC9ULL,
		0x2D8B3DC488C3A407ULL,
		0xBFD4508784072EBAULL,
		0x889FB12F788AB146ULL,
		0xAC28FB7AC1752E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CBC130AB2A5C93DULL,
		0xB6D7559343C57F56ULL,
		0xEAFE5ACEAA3D5728ULL,
		0xD150547FB3862429ULL,
		0x3011DE36A998B725ULL,
		0x1425E9BBEE856B0BULL,
		0x253221F103D10BDAULL,
		0x0F099B3A637D4AA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D507D21F5AA2E85ULL,
		0x11AC8C4F14E9DF96ULL,
		0x0E0A808F5621DDF4ULL,
		0x724E8746FCB35BA0ULL,
		0xFD795F8DDF2AECE1ULL,
		0xABAE66CB9581C3AEULL,
		0x636D8F3E74B9A56CULL,
		0x9D1F60405DF7E3A3ULL
	}};
	sign = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73AF596F0FB1824BULL,
		0xD1DAF9182EDE48A0ULL,
		0x443128213C0830A6ULL,
		0x4142DF6CCA0C3B89ULL,
		0x7CF1D1FB03369B11ULL,
		0xBBE3A77BE42B7CEEULL,
		0xDD5938CC56FAA4CBULL,
		0x820CD1588BA0810FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D82C3314330EFDULL,
		0x56ACEDA2E3EA8315ULL,
		0xD358F66C312C3148ULL,
		0x80CC3CF983516632ULL,
		0x1F5A080A99444B2FULL,
		0x8EDFAF99C3D7F820ULL,
		0x4CF8319CEF0B27ABULL,
		0xC6DAB7B61B687DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1D72D3BFB7E734EULL,
		0x7B2E0B754AF3C58AULL,
		0x70D831B50ADBFF5EULL,
		0xC076A27346BAD556ULL,
		0x5D97C9F069F24FE1ULL,
		0x2D03F7E2205384CEULL,
		0x9061072F67EF7D20ULL,
		0xBB3219A270380367ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669E1AA3A32F9C45ULL,
		0x11314B0212C13D67ULL,
		0x82E7857B40585DAFULL,
		0xF18E186F5D16D554ULL,
		0x98CE6C86DFCFB222ULL,
		0x7789CF2967F31EC8ULL,
		0x615A452225102C99ULL,
		0xA5323FEDC4B9F2CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F0B0EC4899C41BULL,
		0xD10D29C638EB54D0ULL,
		0x73F54A2BE383A53DULL,
		0x5D027962E00C04C3ULL,
		0x97A5B5C6044D7C65ULL,
		0x99BCD69BE40C7FB2ULL,
		0x32E4499FE2E983B0ULL,
		0x11443394EE7E89D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34AD69B75A95D82AULL,
		0x4024213BD9D5E897ULL,
		0x0EF23B4F5CD4B871ULL,
		0x948B9F0C7D0AD091ULL,
		0x0128B6C0DB8235BDULL,
		0xDDCCF88D83E69F16ULL,
		0x2E75FB824226A8E8ULL,
		0x93EE0C58D63B68FEULL
	}};
	sign = 0;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56D9472ADC6CAA97ULL,
		0xC0CCD6CB10F333C5ULL,
		0xF3A08074629EFFCEULL,
		0x03ECBD49C4F7307FULL,
		0xA2F097339149B554ULL,
		0xEDA66FF08A893F27ULL,
		0xF144A3E68691B448ULL,
		0x8718E9917784CA8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D0C7F1CCB9D5B3AULL,
		0xED7F916B2F6EB27DULL,
		0xDAD120145DE0F8CBULL,
		0x15918D24D8047E5EULL,
		0xF9ABE0537933C82BULL,
		0xDC2A86E660EFB1E0ULL,
		0x88AD2963A71942FDULL,
		0x35BA52338645F732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9CCC80E10CF4F5DULL,
		0xD34D455FE1848147ULL,
		0x18CF606004BE0702ULL,
		0xEE5B3024ECF2B221ULL,
		0xA944B6E01815ED28ULL,
		0x117BE90A29998D46ULL,
		0x68977A82DF78714BULL,
		0x515E975DF13ED35DULL
	}};
	sign = 0;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0FA8B2112ABCE29ULL,
		0x5138DF285F880BF3ULL,
		0x9FEC6F5819B1F01DULL,
		0x2C826D408A6E7ED1ULL,
		0x70B3BC51DA21A4FBULL,
		0x6D2935ACAF6426A4ULL,
		0xBD120C487B7599EBULL,
		0xB9405364C2B50E85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE898C60C4636A12ULL,
		0xBE020854657CEA7BULL,
		0x755360ADB5B0886DULL,
		0x183D28CFB08EBBE9ULL,
		0xAFE38B0D39D5BB50ULL,
		0x82E9EE3119E6C7ECULL,
		0x61AA84B955E312E7ULL,
		0xF6DE0FEF476B59F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3270FEC04E486417ULL,
		0x9336D6D3FA0B2178ULL,
		0x2A990EAA640167AFULL,
		0x14454470D9DFC2E8ULL,
		0xC0D03144A04BE9ABULL,
		0xEA3F477B957D5EB7ULL,
		0x5B67878F25928703ULL,
		0xC26243757B49B491ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE696900589DEE3CULL,
		0x6A6B19E4A0D8BA96ULL,
		0x8396CF2A4575EEA8ULL,
		0x8B4B8192195F8FC1ULL,
		0x1B891098971AEA3DULL,
		0x95CEB8530AE932B6ULL,
		0x75A278F3DFA1506AULL,
		0x78628AA58122B4C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04C15F32E20F9A45ULL,
		0xCC09C47DAA8FF5F8ULL,
		0x5FBE651C9E1CD597ULL,
		0xDE1E911AB9FC9265ULL,
		0x047CD8AF650CF352ULL,
		0x3438D4F6476C85EDULL,
		0x0EA790A72073ACCAULL,
		0xA50A18636A488F86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9A809CD768E53F7ULL,
		0x9E615566F648C49EULL,
		0x23D86A0DA7591910ULL,
		0xAD2CF0775F62FD5CULL,
		0x170C37E9320DF6EAULL,
		0x6195E35CC37CACC9ULL,
		0x66FAE84CBF2DA3A0ULL,
		0xD358724216DA2540ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60B6C4E80BB62F9FULL,
		0x1483C888E7234883ULL,
		0x67A65B0A042E3DA8ULL,
		0x5BC0E92D8067F731ULL,
		0x9F04A809ADBC2FD4ULL,
		0xE419DAD2B8A8BF6BULL,
		0xD908B6F726605CDAULL,
		0x64F9E5D987A5B33BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19210386C696B240ULL,
		0x3A257F9582B3794EULL,
		0x4C2B9539A2616882ULL,
		0x2EA558005A1FB82CULL,
		0x0152C1C99A3C9C70ULL,
		0x86508357834C4EECULL,
		0x68C713000C82929BULL,
		0xE001FE694CD617B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4795C161451F7D5FULL,
		0xDA5E48F3646FCF35ULL,
		0x1B7AC5D061CCD525ULL,
		0x2D1B912D26483F05ULL,
		0x9DB1E640137F9364ULL,
		0x5DC9577B355C707FULL,
		0x7041A3F719DDCA3FULL,
		0x84F7E7703ACF9B86ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF97137949E55661ULL,
		0x775DA7403C27E747ULL,
		0x73C5299CA48CF0CEULL,
		0x672DA71C906682A5ULL,
		0xA1F0B16DD2E85693ULL,
		0xE87A655213055607ULL,
		0x2970709A8797A39AULL,
		0xA053A6A46D413965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79CDF4D32BAB4212ULL,
		0xE94F3CA5322D49B6ULL,
		0x6171E4F261A84347ULL,
		0x96E43FC572D0CA46ULL,
		0x79798488AC4E49ADULL,
		0x32CAB4E1561CFD25ULL,
		0x1E7CA5457E592105ULL,
		0x029717670853B01CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C91EA61E3A144FULL,
		0x8E0E6A9B09FA9D91ULL,
		0x125344AA42E4AD86ULL,
		0xD04967571D95B85FULL,
		0x28772CE5269A0CE5ULL,
		0xB5AFB070BCE858E2ULL,
		0x0AF3CB55093E8295ULL,
		0x9DBC8F3D64ED8949ULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCFDF8B744D7DDC8ULL,
		0xD2315EC18E287C8EULL,
		0xC556E44DD747DCA1ULL,
		0x00E98DF733DA47C5ULL,
		0xEEFAADAEA22F7CBBULL,
		0xBEC87593E31A61B7ULL,
		0xC26C54A7C77037DBULL,
		0x83CDB8E03903E3C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD43F150ECF029F80ULL,
		0xF7F228E31BBCFD53ULL,
		0xC5522C4C3C946D5EULL,
		0x486B3C1ED800656EULL,
		0x4AF895BF03BD7E5AULL,
		0x979FA12BEFDC027EULL,
		0x4D4E0A74499D47EFULL,
		0x3C2C87CC54E20036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28BEE3A875D53E48ULL,
		0xDA3F35DE726B7F3BULL,
		0x0004B8019AB36F42ULL,
		0xB87E51D85BD9E257ULL,
		0xA40217EF9E71FE60ULL,
		0x2728D467F33E5F39ULL,
		0x751E4A337DD2EFECULL,
		0x47A13113E421E392ULL
	}};
	sign = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59B1B5C1CEEF446EULL,
		0x1555FBC90C1BAFA2ULL,
		0x4285FDFC17B8309CULL,
		0xCCD7E128DB4299C3ULL,
		0xF45219F11FB3EACFULL,
		0xDBFB6AAD3D221BDAULL,
		0xB65D8C640CFDA059ULL,
		0xC84800EC94101E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467050798A8BE3B4ULL,
		0xEAC98F7ACD39A258ULL,
		0x1E2A06EDCFBB6DA2ULL,
		0x0E65D4CC470EB40AULL,
		0x3FABC6EB2E398A0FULL,
		0x4FC9128064AE5BD6ULL,
		0x4D57393427472FA9ULL,
		0x194CE549E4642A0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13416548446360BAULL,
		0x2A8C6C4E3EE20D4AULL,
		0x245BF70E47FCC2F9ULL,
		0xBE720C5C9433E5B9ULL,
		0xB4A65305F17A60C0ULL,
		0x8C32582CD873C004ULL,
		0x6906532FE5B670B0ULL,
		0xAEFB1BA2AFABF40EULL
	}};
	sign = 0;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C916C1FBA2AAD9FULL,
		0xDC5A0B6CD4528607ULL,
		0x114A9DA1BD44D4E0ULL,
		0x566CA62D044ACA9BULL,
		0xA063A517A3B4D55DULL,
		0x7F1AA1E9A9816D59ULL,
		0x019C6D0DCB22D861ULL,
		0x3BBBFF35F7B012ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B31202DE0FCAFA1ULL,
		0x01178ECAACCE6212ULL,
		0xF0FDE1EF0CF3589EULL,
		0x6DC0DB94D23C83A0ULL,
		0x84406E680F46B55EULL,
		0x75DCDAC32EACBD18ULL,
		0xD92AC6FF75FDFBD3ULL,
		0x8CEBC5233ED4DA93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91604BF1D92DFDFEULL,
		0xDB427CA2278423F4ULL,
		0x204CBBB2B0517C42ULL,
		0xE8ABCA98320E46FAULL,
		0x1C2336AF946E1FFEULL,
		0x093DC7267AD4B041ULL,
		0x2871A60E5524DC8EULL,
		0xAED03A12B8DB3817ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF37F05237A26D8FBULL,
		0x4DCC0F47A71AF0BEULL,
		0x852FD7693471103CULL,
		0x11F3D76CA18C2BCFULL,
		0x4794ADDC4ACB72FAULL,
		0x27B40D272639ACBDULL,
		0x27D96F9FF5943334ULL,
		0xDD541DA79E914EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D88C7666C2755CEULL,
		0x98EF78B067DEE265ULL,
		0x54E0F6300F35FB34ULL,
		0x8DA0765F7A742EFFULL,
		0xE89E2F6FF2700D6DULL,
		0x0B260017769685BDULL,
		0x815B24A5306D547EULL,
		0xF752FCDA415BCD43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5F63DBD0DFF832DULL,
		0xB4DC96973F3C0E59ULL,
		0x304EE139253B1507ULL,
		0x8453610D2717FCD0ULL,
		0x5EF67E6C585B658CULL,
		0x1C8E0D0FAFA326FFULL,
		0xA67E4AFAC526DEB6ULL,
		0xE60120CD5D35816DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3B958BBBB3C2751ULL,
		0x56BCE1083E46C001ULL,
		0x72D016E5F6A6CF0AULL,
		0xADDC6939020FDDEFULL,
		0x4C8160EC287AF0A6ULL,
		0x7865DA083C25DD58ULL,
		0x01A2EF2F9777A0A2ULL,
		0x42826A936F8C405BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA60BBC2E19F51F83ULL,
		0xCB75396268CE3D81ULL,
		0x7D2167BAC6907A00ULL,
		0x5D6F6AE8A4B37825ULL,
		0xF6B4C4834D5173D4ULL,
		0x368A192085B703B2ULL,
		0x4AEC84CB482F4309ULL,
		0xEB7DEE5D35F424D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DAD9C8DA14707CEULL,
		0x8B47A7A5D5788280ULL,
		0xF5AEAF2B30165509ULL,
		0x506CFE505D5C65C9ULL,
		0x55CC9C68DB297CD2ULL,
		0x41DBC0E7B66ED9A5ULL,
		0xB6B66A644F485D99ULL,
		0x57047C3639981B81ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4B7D950BD1AA486ULL,
		0x8D4BE0F7410C6090ULL,
		0x8F0F00BD38882B28ULL,
		0xE77357E30A531711ULL,
		0xEF5F57244845EAA6ULL,
		0x56F20A43955728B6ULL,
		0x3B3CCAAEAB4868FAULL,
		0xD24DC083781890A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F2D2AA0B775D97CULL,
		0x46B539021B1C73FBULL,
		0x37210E21605E1CCAULL,
		0x69A3393701D29554ULL,
		0x628E3999E19B0392ULL,
		0x63A147A9409F2953ULL,
		0x7615C46BFFE5CDB8ULL,
		0x5779CC428F8565C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x358AAEB005A4CB0AULL,
		0x4696A7F525EFEC95ULL,
		0x57EDF29BD82A0E5EULL,
		0x7DD01EAC088081BDULL,
		0x8CD11D8A66AAE714ULL,
		0xF350C29A54B7FF63ULL,
		0xC5270642AB629B41ULL,
		0x7AD3F440E8932ADCULL
	}};
	sign = 0;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FFF237016CA052CULL,
		0x5A831107E40CC747ULL,
		0xE74B666352C3E09FULL,
		0x0A12EB669BC79F52ULL,
		0xDC2C63200A381431ULL,
		0x690004D42325D327ULL,
		0x35DABDEB60225B25ULL,
		0x781925DE391924C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1D178A79EC9DC5ULL,
		0x50402A6E6AFDD1C1ULL,
		0xF1D83DD8E1AD7B4AULL,
		0xFC02885D36BB5B69ULL,
		0xA3AABDC06EF16A44ULL,
		0x4274C80D297DBA68ULL,
		0x66497C99D3C732D6ULL,
		0x49B3D8352F3B6D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1E20BE59CDD6767ULL,
		0x0A42E699790EF585ULL,
		0xF573288A71166555ULL,
		0x0E106309650C43E8ULL,
		0x3881A55F9B46A9ECULL,
		0x268B3CC6F9A818BFULL,
		0xCF9141518C5B284FULL,
		0x2E654DA909DDB782ULL
	}};
	sign = 0;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF887C0E1A458D40EULL,
		0xF059B36B4168F69DULL,
		0xB43C7433B00178EDULL,
		0x5D86647A679FA24FULL,
		0x3A4C16CF8C89E7EEULL,
		0x01AC2961EFD0907CULL,
		0xFDE976BDB738A575ULL,
		0x4C888BB38C9DE6A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B73FF109A044CF9ULL,
		0x587FBAA3F816E1EDULL,
		0xD741E04D8EEA3D2BULL,
		0x4B7AE32F29E985BFULL,
		0x1E026BD02570C210ULL,
		0xA9A98DE9B0D193ABULL,
		0x5C367974F7A5B52BULL,
		0x43E8443C9EAE3370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD13C1D10A548715ULL,
		0x97D9F8C7495214B0ULL,
		0xDCFA93E621173BC2ULL,
		0x120B814B3DB61C8FULL,
		0x1C49AAFF671925DEULL,
		0x58029B783EFEFCD1ULL,
		0xA1B2FD48BF92F049ULL,
		0x08A04776EDEFB332ULL
	}};
	sign = 0;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE57D857066387976ULL,
		0x455D3B771E6CD6EFULL,
		0x8C390BB59E61DE1BULL,
		0xAC230D69A2215A94ULL,
		0xB1B1CE5E6A040D1BULL,
		0xB74A019FE96D04AFULL,
		0xE587B4EE0A9FE529ULL,
		0x69A3B5ADEB367CA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9A6926C661DEE4ULL,
		0x708911FE85E3CAB9ULL,
		0xECD90741B84E8294ULL,
		0x104B2E76291E8192ULL,
		0x2EE989E480C34A9BULL,
		0x8D37B80410484864ULL,
		0xDF98FD7AD3EDCE49ULL,
		0x013242D09D3A20CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E31C499FD69A92ULL,
		0xD4D4297898890C36ULL,
		0x9F600473E6135B86ULL,
		0x9BD7DEF37902D901ULL,
		0x82C84479E940C280ULL,
		0x2A12499BD924BC4BULL,
		0x05EEB77336B216E0ULL,
		0x687172DD4DFC5BDFULL
	}};
	sign = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF439AC4A4EC3EE8ULL,
		0x62A5B52C3AFA5F86ULL,
		0x6EE9FD5CB5604BCCULL,
		0x25721B3E18465962ULL,
		0xAFD15275DD4C6DC5ULL,
		0xB15910869053BFCEULL,
		0x6B870689251696F0ULL,
		0xC0BBE49B24D1842CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA68401EE1AAC2A8ULL,
		0x698C70DD3E0F7B62ULL,
		0x79C14DB8A39F3052ULL,
		0x6F0BEB5B6BACF3DDULL,
		0x71C9EB1B2281C575ULL,
		0x0BC470712A278841ULL,
		0xAEF242D2599ED02BULL,
		0x91ED227C7DBE1282ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04DB5AA5C3417C40ULL,
		0xF919444EFCEAE424ULL,
		0xF528AFA411C11B79ULL,
		0xB6662FE2AC996584ULL,
		0x3E07675ABACAA84FULL,
		0xA594A015662C378DULL,
		0xBC94C3B6CB77C6C5ULL,
		0x2ECEC21EA71371A9ULL
	}};
	sign = 0;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B0AA5C7120753AULL,
		0x2AEFD8E95F05F06EULL,
		0x0587456F946CE467ULL,
		0xA362F4FFD7048651ULL,
		0xC5A19BBA39A2A1ABULL,
		0x5B35F7BC79DCC05DULL,
		0xC7A565B8DF9E62CCULL,
		0xCEE99C1E6D5E4EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3AFAA4B2E785B73ULL,
		0x3AD9E30D460BFB02ULL,
		0xA6BDD83BAB47594AULL,
		0x50F7FF7478F2D869ULL,
		0x192DE8B41DB01EFDULL,
		0xBE6EBFC316429311ULL,
		0x407B143AB3489CF9ULL,
		0x4D10862005D97FE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD01001142A819C7ULL,
		0xF015F5DC18F9F56BULL,
		0x5EC96D33E9258B1CULL,
		0x526AF58B5E11ADE7ULL,
		0xAC73B3061BF282AEULL,
		0x9CC737F9639A2D4CULL,
		0x872A517E2C55C5D2ULL,
		0x81D915FE6784CEE2ULL
	}};
	sign = 0;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA86AA48B4CB8CBCAULL,
		0xB5AD5D5E8EB4D2EFULL,
		0x195A1279E92888CDULL,
		0xA07BB8B34A94BD2AULL,
		0x14B19CCA19412729ULL,
		0xCC293365E09591A2ULL,
		0x2442E992FDBF01D5ULL,
		0xFDCE00A4361DBE8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7BF16BD1F786347ULL,
		0x6102FBFB369C3BBCULL,
		0xDCABE8BBA7BA8BCCULL,
		0x5604B0FEDA1030EBULL,
		0x69C9552F0B8A1D8AULL,
		0x6A28A1F160D306BEULL,
		0x740BB4D15653653EULL,
		0x04E712B838A26E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0AB8DCE2D406883ULL,
		0x54AA616358189732ULL,
		0x3CAE29BE416DFD01ULL,
		0x4A7707B470848C3EULL,
		0xAAE8479B0DB7099FULL,
		0x620091747FC28AE3ULL,
		0xB03734C1A76B9C97ULL,
		0xF8E6EDEBFD7B4FFBULL
	}};
	sign = 0;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE65FC2EB8A1950AULL,
		0xBCE086A23CCD6E22ULL,
		0x457555EAA24CC896ULL,
		0x85363A26EEA3E0D8ULL,
		0x07E641E0C173F6BBULL,
		0x7BE62A592527BDAFULL,
		0xACE4B2A41BF6A659ULL,
		0xDED9FC8D8D60CCDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCABAF843DBD5E41FULL,
		0x964AA7E1125BCFB1ULL,
		0x67C7FD81512EECF6ULL,
		0xD8520A2786AB239BULL,
		0x65F982E55402E04AULL,
		0x7E5B01981590A23AULL,
		0x73062D8652C3038EULL,
		0xB6CDD303C4F34250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3AB03EADCCBB0EBULL,
		0x2695DEC12A719E70ULL,
		0xDDAD5869511DDBA0ULL,
		0xACE42FFF67F8BD3CULL,
		0xA1ECBEFB6D711670ULL,
		0xFD8B28C10F971B74ULL,
		0x39DE851DC933A2CAULL,
		0x280C2989C86D8A8BULL
	}};
	sign = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58BB543BD37D0F1AULL,
		0xA20E565CA10DAD9BULL,
		0x7BC57A4661175117ULL,
		0x3B3E91DF6D00F74BULL,
		0x64B351A57ACEE6A5ULL,
		0xF32F9C001C962150ULL,
		0xCFC78926F2205172ULL,
		0x97FB485D22528049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x151EE6EAE514C95AULL,
		0xEFF6D2DFF6452527ULL,
		0x6945412E1ABE8CC3ULL,
		0xD9593696A60604F9ULL,
		0x8B586FC2EB081376ULL,
		0x0B5C34814E965D5DULL,
		0x2731004B3A98E836ULL,
		0x5831033C0045DB91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x439C6D50EE6845C0ULL,
		0xB217837CAAC88874ULL,
		0x128039184658C453ULL,
		0x61E55B48C6FAF252ULL,
		0xD95AE1E28FC6D32EULL,
		0xE7D3677ECDFFC3F2ULL,
		0xA89688DBB787693CULL,
		0x3FCA4521220CA4B8ULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x533B32814938D844ULL,
		0x1781B61FAB89FA70ULL,
		0xE55CF1F05C10772FULL,
		0x9270934A7F957A40ULL,
		0xD2ADA01B05086CE0ULL,
		0x059758AC2ECAE89AULL,
		0xF2990AC03AF8A8B8ULL,
		0x02827294D0B882CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDFC00781A8E5E3ULL,
		0xE1748C98BEEAF857ULL,
		0x9D3AFDCEBEB4AD2FULL,
		0xCCB071F7CB40797CULL,
		0x63198DC8687AD184ULL,
		0x65BEB49C3D1DD0BAULL,
		0x336A817244EF7F70ULL,
		0x09CBBE57F342CAB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF55B7279C78FF261ULL,
		0x360D2986EC9F0218ULL,
		0x4821F4219D5BC9FFULL,
		0xC5C02152B45500C4ULL,
		0x6F9412529C8D9B5BULL,
		0x9FD8A40FF1AD17E0ULL,
		0xBF2E894DF6092947ULL,
		0xF8B6B43CDD75B817ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9955D294CDFF44E9ULL,
		0xF59666846FF09720ULL,
		0xED21FBD3882D3D74ULL,
		0x8486DF18F8201541ULL,
		0x3790FFD5A44AC2F5ULL,
		0xC3CEFE344F30C112ULL,
		0x0188084E247AEBC1ULL,
		0xBA87F9E753186265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3EC5CD7AA0F9B43ULL,
		0xA202D5CD42DB5609ULL,
		0x0906D725E4167254ULL,
		0xA1B5A45A70503AF8ULL,
		0x3D2C2A292FAA0FAAULL,
		0xB68B1C5B37AC897CULL,
		0xC28F3E881DE1D5A0ULL,
		0x57060276FE88D771ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD56975BD23EFA9A6ULL,
		0x539390B72D154116ULL,
		0xE41B24ADA416CB20ULL,
		0xE2D13ABE87CFDA49ULL,
		0xFA64D5AC74A0B34AULL,
		0x0D43E1D917843795ULL,
		0x3EF8C9C606991621ULL,
		0x6381F770548F8AF3ULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE2ACDD5401BACB2ULL,
		0xE89BCA7C9611D4BBULL,
		0xA4FA962AA75C6A7FULL,
		0xD0BBE168F88934C7ULL,
		0x99B789DD0302FE55ULL,
		0xAACF63633654F872ULL,
		0x77352B803E5DF9F6ULL,
		0x123643F56225FC3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A5F1E1EDD7A2D0ULL,
		0xB50F753BF4DCE0F4ULL,
		0xE8E83AD930E785D3ULL,
		0xBC5BD9D7E41E0750ULL,
		0x8D4E862A3D49CB27ULL,
		0xDFA6FC345746E3D8ULL,
		0x47F02DBA60E4995DULL,
		0x41DFE3914EE7F36EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4784DBF3524409E2ULL,
		0x338C5540A134F3C7ULL,
		0xBC125B517674E4ACULL,
		0x14600791146B2D76ULL,
		0x0C6903B2C5B9332EULL,
		0xCB28672EDF0E149AULL,
		0x2F44FDC5DD796098ULL,
		0xD0566064133E08CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x931FB2472BC8CC1DULL,
		0xE5122D3E3C135A35ULL,
		0x9C9D9A05EE9B846FULL,
		0xBEC4BF851D6D8307ULL,
		0x9F400692CD28A2D5ULL,
		0xEF4E73FB9578E985ULL,
		0x044205F9641B3BD3ULL,
		0xC414FB5E59BF5287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3907C5B83FADEC4ULL,
		0xC81AA133A22A09FAULL,
		0x9817BA589F8C8CF2ULL,
		0x6FF566FBA32EEFDEULL,
		0xF201177C9425E379ULL,
		0xDA4780683869B4F0ULL,
		0x765BA3B7A7A48A0CULL,
		0x2F82A379DB494139ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF8F35EBA7CDED59ULL,
		0x1CF78C0A99E9503AULL,
		0x0485DFAD4F0EF77DULL,
		0x4ECF58897A3E9329ULL,
		0xAD3EEF163902BF5CULL,
		0x1506F3935D0F3494ULL,
		0x8DE66241BC76B1C7ULL,
		0x949257E47E76114DULL
	}};
	sign = 0;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2962A0BDCF0511CBULL,
		0x604BB1326C1773EFULL,
		0xC0E6CBA73214B884ULL,
		0x0BE6258802C79110ULL,
		0x7EE27FA194F1C1D4ULL,
		0xACCC0E57DD8C3326ULL,
		0xC346BB166EDBBFC1ULL,
		0xA1C6658E9D9E2935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC762B23FABABA86FULL,
		0x5CBA9348C827D555ULL,
		0xF63A75CB7E4CC737ULL,
		0x03C6BB877E4CE3CAULL,
		0x6664525C03F222ECULL,
		0x3A233856CAAAE973ULL,
		0xCE669149148593D6ULL,
		0x0928EA9CC100B52AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61FFEE7E2359695CULL,
		0x03911DE9A3EF9E99ULL,
		0xCAAC55DBB3C7F14DULL,
		0x081F6A00847AAD45ULL,
		0x187E2D4590FF9EE8ULL,
		0x72A8D60112E149B3ULL,
		0xF4E029CD5A562BEBULL,
		0x989D7AF1DC9D740AULL
	}};
	sign = 0;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D2E6166AA708B56ULL,
		0x3A7EF16BFFB59297ULL,
		0x5BE120107C01CA29ULL,
		0xEE8EC779E8958381ULL,
		0x49E795D84C097A17ULL,
		0xF13961207532BB87ULL,
		0x4431A9A78C8C06D7ULL,
		0xA40A72983FCA157AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85F07534209A127FULL,
		0x94C85F60E3C277ADULL,
		0x92E7738E323A3DA6ULL,
		0x91A57ACCB8353BD8ULL,
		0xCAA060617C896113ULL,
		0xE7EBEE73FAABD280ULL,
		0x659328FE34457CDDULL,
		0x4A7F96C8135C2759ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE73DEC3289D678D7ULL,
		0xA5B6920B1BF31AE9ULL,
		0xC8F9AC8249C78C82ULL,
		0x5CE94CAD306047A8ULL,
		0x7F473576CF801904ULL,
		0x094D72AC7A86E906ULL,
		0xDE9E80A9584689FAULL,
		0x598ADBD02C6DEE20ULL
	}};
	sign = 0;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4224ABA2C165F4BULL,
		0x23E4EB88F8E9AFC5ULL,
		0x705CE9F80A940A3CULL,
		0x52613A9919B8EEB3ULL,
		0xB7CC9D7C68815D57ULL,
		0x04BFE6B490FF9D00ULL,
		0x3FB9B7D58E58DB05ULL,
		0x187D50068DE50358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCC48FC581E3446ULL,
		0xCE8C85857EC17D14ULL,
		0x9E8DD915837B409DULL,
		0xAA8D3E9E8D300620ULL,
		0x12FCD2476B529FD0ULL,
		0xE2804C6EC1F57F1DULL,
		0x160EC6BCCDA5270DULL,
		0x8B206153EA052828ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA65601BDD3F82B05ULL,
		0x555866037A2832B0ULL,
		0xD1CF10E28718C99EULL,
		0xA7D3FBFA8C88E892ULL,
		0xA4CFCB34FD2EBD86ULL,
		0x223F9A45CF0A1DE3ULL,
		0x29AAF118C0B3B3F7ULL,
		0x8D5CEEB2A3DFDB30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80B476A6C0A79555ULL,
		0xC8E1935D0C4DBCC7ULL,
		0x3A86DC970E6889EFULL,
		0xF90CDEE8FD9E1272ULL,
		0x03775946C92B7E2DULL,
		0x3CB038FBF14F82F5ULL,
		0x2DAC850ADC0BDB8BULL,
		0x79CF49F6DFDA8E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46659A31089FEF1CULL,
		0xA51CDD567C696F93ULL,
		0x0E5DF1FEBCB4E864ULL,
		0x8160B002E71FB959ULL,
		0xD413643D836F8855ULL,
		0xBDE64CBEFDC60B7DULL,
		0xE396817B2C122576ULL,
		0x16C445B51FB70633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A4EDC75B807A639ULL,
		0x23C4B6068FE44D34ULL,
		0x2C28EA9851B3A18BULL,
		0x77AC2EE6167E5919ULL,
		0x2F63F50945BBF5D8ULL,
		0x7EC9EC3CF3897777ULL,
		0x4A16038FAFF9B614ULL,
		0x630B0441C0238847ULL
	}};
	sign = 0;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB38513FE54FE682ULL,
		0x80F347B2221CA76CULL,
		0x12086F40E1B2830CULL,
		0x7BD08E45197F04CCULL,
		0xF632415C4317ABE2ULL,
		0x86B5101CC96DC2B8ULL,
		0x0FB42769179882CDULL,
		0x849DBC41C81F2B8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2B4A3FB2717355EULL,
		0x413D671FCC6EE747ULL,
		0x5CB3EC0CDE83A81DULL,
		0x7C7C2123B4D8A8BAULL,
		0xB3A7611521FAAF46ULL,
		0xDF7600F514886EB9ULL,
		0x03EB55A72BC8A4E4ULL,
		0x599EA75522C8C5FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3883AD44BE38B124ULL,
		0x3FB5E09255ADC025ULL,
		0xB5548334032EDAEFULL,
		0xFF546D2164A65C11ULL,
		0x428AE047211CFC9BULL,
		0xA73F0F27B4E553FFULL,
		0x0BC8D1C1EBCFDDE8ULL,
		0x2AFF14ECA5566591ULL
	}};
	sign = 0;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D36279EF47A5837ULL,
		0x7E0896434E8BAB90ULL,
		0x84FC05F847FD176DULL,
		0x86DFF3EE22916AECULL,
		0x38FB999EFC3DDABFULL,
		0x2BA0B446F54209B0ULL,
		0x0BC9A9962969EE1AULL,
		0x16BC9281CE008E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31173E71CBEE87DCULL,
		0x9B5CCEE3B2391865ULL,
		0x34FFB2036A4C12FAULL,
		0x46C31C4F932F995DULL,
		0x19B7301BD71E288BULL,
		0x0A07798B47452158ULL,
		0xC5A686BC787CBD05ULL,
		0x79F6BB2FE129E24EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC1EE92D288BD05BULL,
		0xE2ABC75F9C52932AULL,
		0x4FFC53F4DDB10472ULL,
		0x401CD79E8F61D18FULL,
		0x1F446983251FB234ULL,
		0x21993ABBADFCE858ULL,
		0x462322D9B0ED3115ULL,
		0x9CC5D751ECD6ABCFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x557C8AD199FB6CA7ULL,
		0x6FA391D5050A3ABBULL,
		0x27554169AEE93DC3ULL,
		0xD4131A8DF75BDBB5ULL,
		0x4D5B13A5642B4476ULL,
		0x5CE76EA7CFEE5C47ULL,
		0x9B2642895D8DB450ULL,
		0x850C36768FB8A107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E4D77D2FBB6F17AULL,
		0x34F6A1020CBFB4AFULL,
		0x3F3D307432DA8836ULL,
		0x65F143F60DF3DFDFULL,
		0xC76728FD794628B5ULL,
		0xBA0614AC6E6334A1ULL,
		0x553EC1764C28B7CFULL,
		0x1B99825A46CA8C0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD72F12FE9E447B2DULL,
		0x3AACF0D2F84A860BULL,
		0xE81810F57C0EB58DULL,
		0x6E21D697E967FBD5ULL,
		0x85F3EAA7EAE51BC1ULL,
		0xA2E159FB618B27A5ULL,
		0x45E781131164FC80ULL,
		0x6972B41C48EE14FDULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ED20BC1549F5573ULL,
		0x8918C22BAD24CB0EULL,
		0xE2C18783C9DA4127ULL,
		0x336E5820CDD8AB70ULL,
		0xF890BB76DB65915AULL,
		0x2C2326800134F8DCULL,
		0x8D1E8C9328ABFF44ULL,
		0xA043A9A80FE87A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0134B57474C7C038ULL,
		0xCB2B6398BE6EA877ULL,
		0xED06480C41717023ULL,
		0xAA3DF4B47A71968BULL,
		0x4695798BB4F3B2E5ULL,
		0xBAF59132227999A2ULL,
		0x49557D4FC993F1E6ULL,
		0x8A2E98237411C236ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D9D564CDFD7953BULL,
		0xBDED5E92EEB62297ULL,
		0xF5BB3F778868D103ULL,
		0x8930636C536714E4ULL,
		0xB1FB41EB2671DE74ULL,
		0x712D954DDEBB5F3AULL,
		0x43C90F435F180D5DULL,
		0x161511849BD6B7E3ULL
	}};
	sign = 0;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB090B97FA73290AULL,
		0x1131B91F734FF6BAULL,
		0xE8112DDDF4BB2E54ULL,
		0xB85D3FC25B551286ULL,
		0x6156542AADD41F88ULL,
		0x323BCF48E52D5890ULL,
		0xE05B316415835084ULL,
		0x3096135D0F468FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B8908C7EF06877ULL,
		0x71A3B507588E220EULL,
		0xAF97D16C9066C486ULL,
		0xC1E8077DF858CC40ULL,
		0x9950D30CD4C67B28ULL,
		0x4BCCF11604AEDEC2ULL,
		0x9BFC69570F27A423ULL,
		0x52CE990A683650C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3507B0B7B82C093ULL,
		0x9F8E04181AC1D4ABULL,
		0x38795C71645469CDULL,
		0xF675384462FC4646ULL,
		0xC805811DD90DA45FULL,
		0xE66EDE32E07E79CDULL,
		0x445EC80D065BAC60ULL,
		0xDDC77A52A7103F0EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06DD35CD64367038ULL,
		0xE8C565771748AF92ULL,
		0x871E269AC4082877ULL,
		0xB417113ACC522194ULL,
		0x2D9779B75254161BULL,
		0x8F099054BCFD923FULL,
		0x054CA6C1C85189E7ULL,
		0xC4FF1099BD2AD332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5579D58CACEBB19FULL,
		0xE87CA45F26D9C2BFULL,
		0x36CCD3195B292C91ULL,
		0x7C92C5636092D03BULL,
		0x072653969E2124A7ULL,
		0xFA43FC9A192CE059ULL,
		0xABFF5FAD2B638E6EULL,
		0x4EA2AD72994D0176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1636040B74ABE99ULL,
		0x0048C117F06EECD2ULL,
		0x5051538168DEFBE6ULL,
		0x37844BD76BBF5159ULL,
		0x26712620B432F174ULL,
		0x94C593BAA3D0B1E6ULL,
		0x594D47149CEDFB78ULL,
		0x765C632723DDD1BBULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x596EA15253F4416BULL,
		0x5243E66F8F5B93A3ULL,
		0x9ADA5C815D10377DULL,
		0xD0F303DC954F0804ULL,
		0xBAED38158E08F052ULL,
		0x860C697454254846ULL,
		0xB7FC24D22CBC12FAULL,
		0x9B8E400A8513C794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A41E311A3FC82DULL,
		0x0802F9710A0917CCULL,
		0xE413CFBDA150690FULL,
		0xBAEA3471D1FA0497ULL,
		0xBD7FC3E5E6873748ULL,
		0x9DFC5822A06DC760ULL,
		0x5D88A1E2D6CD27F7ULL,
		0x9D0D44D01D268394ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFCA832139B4793EULL,
		0x4A40ECFE85527BD6ULL,
		0xB6C68CC3BBBFCE6EULL,
		0x1608CF6AC355036CULL,
		0xFD6D742FA781B90AULL,
		0xE8101151B3B780E5ULL,
		0x5A7382EF55EEEB02ULL,
		0xFE80FB3A67ED4400ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8300832E35167DD0ULL,
		0x9EB0AC2EA9657282ULL,
		0x932A6773FCF8892BULL,
		0xA17AF5DDF8E2A5BAULL,
		0xEA6B1C24C9CCDA45ULL,
		0xF569F45BA112A1B5ULL,
		0xF486473D43980101ULL,
		0xA4C1136B9D12B436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C4A1ED9A558660ULL,
		0x398BDA0E2081BDA6ULL,
		0xA46F15C610A634F8ULL,
		0x09074F94EFF0DE36ULL,
		0x0F44E1C869350084ULL,
		0x426A20BE5A5D711AULL,
		0xAB4CFA0877E61B24ULL,
		0xD95A7C3FEB8E6650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x793BE1409AC0F770ULL,
		0x6524D22088E3B4DCULL,
		0xEEBB51ADEC525433ULL,
		0x9873A64908F1C783ULL,
		0xDB263A5C6097D9C1ULL,
		0xB2FFD39D46B5309BULL,
		0x49394D34CBB1E5DDULL,
		0xCB66972BB1844DE6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A471A98DB3B578AULL,
		0x27B244817AAC1584ULL,
		0xB857C04DCBF25EACULL,
		0xC694AAF6094EDB3FULL,
		0x55A7E96875AA065BULL,
		0x7AE18BDD7DDB444AULL,
		0x161E7E6436D8C44DULL,
		0x843E903D2109A55EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A229B375E7AFFF2ULL,
		0x6733F4686BF8CDC3ULL,
		0x94A7D28CAE633A7BULL,
		0x13F0E0693277F0F6ULL,
		0xA1B1D5B0C3F43AB2ULL,
		0xF43F939E13116585ULL,
		0x0EEC5FBFD35E5260ULL,
		0xD06B7445920715A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0247F617CC05798ULL,
		0xC07E50190EB347C0ULL,
		0x23AFEDC11D8F2430ULL,
		0xB2A3CA8CD6D6EA49ULL,
		0xB3F613B7B1B5CBA9ULL,
		0x86A1F83F6AC9DEC4ULL,
		0x07321EA4637A71ECULL,
		0xB3D31BF78F028FBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EAC232B0220AB3DULL,
		0xC2C623F9A4ABB165ULL,
		0x5DCCC334E628D8C5ULL,
		0xBB39BA4A5E4B6799ULL,
		0x7F5F8338C1297F51ULL,
		0x56E2D81105790FAAULL,
		0xA4CC8F1B78074B92ULL,
		0x9220C7E303A365BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDA6917C1DE2765ULL,
		0xA5B1B7B90FB5F1DCULL,
		0xFEC7ECC0F31D2E54ULL,
		0x3225A7F39BBFFFA5ULL,
		0x342EE7123E4A3465ULL,
		0xFF2C707DD5BA5DB4ULL,
		0xD5812D58341A1DACULL,
		0xF98A4B52CD9B555FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51D1BA13404283D8ULL,
		0x1D146C4094F5BF88ULL,
		0x5F04D673F30BAA71ULL,
		0x89141256C28B67F3ULL,
		0x4B309C2682DF4AECULL,
		0x57B667932FBEB1F6ULL,
		0xCF4B61C343ED2DE5ULL,
		0x98967C903608105FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5493D18602677DDFULL,
		0xCF00D7C30A40FBD5ULL,
		0x527A8CC8661A2282ULL,
		0xD42B6C7E447816E3ULL,
		0xA47DB736F27B0AA0ULL,
		0x7B56AA001888DC5EULL,
		0xF843F37E98551F6DULL,
		0x213E3183D5DC1EEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DE51D3F4B59EC01ULL,
		0x4405E96808247C57ULL,
		0x5084C5085F3CC824ULL,
		0xB2E1354CCA85BD32ULL,
		0x0B3871EAE17A3A5EULL,
		0xAD85FEC5856A3FC4ULL,
		0xB9D7EE67E5B199E9ULL,
		0x99EB6D7E4CF252A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36AEB446B70D91DEULL,
		0x8AFAEE5B021C7F7EULL,
		0x01F5C7C006DD5A5EULL,
		0x214A373179F259B1ULL,
		0x9945454C1100D042ULL,
		0xCDD0AB3A931E9C9AULL,
		0x3E6C0516B2A38583ULL,
		0x8752C40588E9CC4CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3DB97562B4B5D5EULL,
		0xC418AFEFD32FB272ULL,
		0x3B557B49BA7316FFULL,
		0xBE00452073A511DAULL,
		0xB5B032430CAA7779ULL,
		0x0603B77CD421FF3FULL,
		0x2D923236BD3A737BULL,
		0x99F2C354FC2F3A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66518C16708062FCULL,
		0xB127961E08139943ULL,
		0xC87DFDA0554DD5A2ULL,
		0x7F88A12C98C6A135ULL,
		0x3C12118F694AD3CAULL,
		0xE94CF380D20E2A69ULL,
		0xBAFAB26766556E7EULL,
		0xE8EBBF54D018E3F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D8A0B3FBACAFA62ULL,
		0x12F119D1CB1C192FULL,
		0x72D77DA96525415DULL,
		0x3E77A3F3DADE70A4ULL,
		0x799E20B3A35FA3AFULL,
		0x1CB6C3FC0213D4D6ULL,
		0x72977FCF56E504FCULL,
		0xB10704002C16565BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB64580A6263024D5ULL,
		0x50A3C9959BE2352AULL,
		0xFA5C0D4889C25B4AULL,
		0xBE64E2E8C5E95B91ULL,
		0x0554742253FB98A4ULL,
		0xC976627F4E91F0EBULL,
		0xFE7334E12A2F83C4ULL,
		0x154360E8AAC0BB3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA5A74C9206190E3ULL,
		0xC5AA59B0AC11AA5BULL,
		0x7EDBB15B24B52D72ULL,
		0x38DF185FF199F17AULL,
		0xB4D06C8D4DBF4DD4ULL,
		0x2356BA1C07A6AD0DULL,
		0x3ED8DA35397E845FULL,
		0xF16BC54598F95E17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBEB0BDD05CE93F2ULL,
		0x8AF96FE4EFD08ACEULL,
		0x7B805BED650D2DD7ULL,
		0x8585CA88D44F6A17ULL,
		0x50840795063C4AD0ULL,
		0xA61FA86346EB43DDULL,
		0xBF9A5AABF0B0FF65ULL,
		0x23D79BA311C75D26ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x554A49A147125B80ULL,
		0x9B7922A06900AB7CULL,
		0xF442A713A05CACACULL,
		0xC045020806EE189FULL,
		0x5BD47C29250C3945ULL,
		0x99FC28C3BA12DDD8ULL,
		0x10A0EC871A70BFE7ULL,
		0xD526DFC6DE623974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE9A43C839BB86DULL,
		0xFDB1B81A3C3F854BULL,
		0x15F9594BB47E3FCDULL,
		0x57D9FBEED8AE7679ULL,
		0xC11EF6D4905E6976ULL,
		0xFA89F33B69BC0505ULL,
		0x5C620779BA6BBD0FULL,
		0x80ADB7FD28730AFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4960A564C376A313ULL,
		0x9DC76A862CC12631ULL,
		0xDE494DC7EBDE6CDEULL,
		0x686B06192E3FA226ULL,
		0x9AB5855494ADCFCFULL,
		0x9F7235885056D8D2ULL,
		0xB43EE50D600502D7ULL,
		0x547927C9B5EF2E76ULL
	}};
	sign = 0;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF1A8D3A8977A7B0ULL,
		0x3C2016A1E0833EC6ULL,
		0x5DBD655F418B7E74ULL,
		0xA87143732E92BE4FULL,
		0x19E9C6BCE3315589ULL,
		0xF8081ACF9BA91E8EULL,
		0xAF2392DB1ED02EA9ULL,
		0x75BAA377E24F71E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F009323920E6096ULL,
		0xE70DC3DB9D840B87ULL,
		0x8C8D94C21777E519ULL,
		0x817F1D818B5366EBULL,
		0x7D1A8821A11881F3ULL,
		0x4F9D8D043F3A6E0FULL,
		0x84B5099DF85A1372ULL,
		0xFAE54BF93F0E6E0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9019FA16F769471AULL,
		0x551252C642FF333FULL,
		0xD12FD09D2A13995AULL,
		0x26F225F1A33F5763ULL,
		0x9CCF3E9B4218D396ULL,
		0xA86A8DCB5C6EB07EULL,
		0x2A6E893D26761B37ULL,
		0x7AD5577EA34103D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x981F360C7C6C3316ULL,
		0x78CB4EBE2775B227ULL,
		0xA001F0AC8BF3C19BULL,
		0x5CD4845DBA139CEAULL,
		0xADB7C2BDB1602AFEULL,
		0x517107DFD3ACBDCDULL,
		0x9D984A264BAFCCF3ULL,
		0xD9126E3A8939326EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E815D305243698ULL,
		0xB2DF6BD249B13FCEULL,
		0xF18CBE87DD096FFBULL,
		0x371BD651D354B689ULL,
		0xA937300DA452CAFDULL,
		0xA66CCC2F8A0058EEULL,
		0xAF878C4068D1F3CBULL,
		0x140AA3B7592BC3E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC73720397747FC7EULL,
		0xC5EBE2EBDDC47258ULL,
		0xAE753224AEEA519FULL,
		0x25B8AE0BE6BEE660ULL,
		0x048092B00D0D6001ULL,
		0xAB043BB049AC64DFULL,
		0xEE10BDE5E2DDD927ULL,
		0xC507CA83300D6E89ULL
	}};
	sign = 0;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A996A579038F3EULL,
		0xD19A0FC836DF165BULL,
		0x223C0FE5AE320E6EULL,
		0x07C220FE75CA0E01ULL,
		0xAB17B62B12C5A454ULL,
		0x9026BDA94D4AFC70ULL,
		0xCE9127651BF0FF7BULL,
		0xC86F47EDD339B88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA38812C1C9D88008ULL,
		0xB4696D9505073599ULL,
		0x87E4661AD412C051ULL,
		0x2C16C85C5530C174ULL,
		0xB4E6B7D643239D60ULL,
		0xF1A6BD2DCE75BA99ULL,
		0x747A8DC9B0E3C7FDULL,
		0xEAC913740FCF0508ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x612183E3AF2B0F36ULL,
		0x1D30A23331D7E0C1ULL,
		0x9A57A9CADA1F4E1DULL,
		0xDBAB58A220994C8CULL,
		0xF630FE54CFA206F3ULL,
		0x9E80007B7ED541D6ULL,
		0x5A16999B6B0D377DULL,
		0xDDA63479C36AB384ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C62EA86A2FEDFEAULL,
		0x30FA21ECB4B871B7ULL,
		0x2F7F2D307A251C70ULL,
		0xC158980A3D769805ULL,
		0x5F483BF3FC1A9E74ULL,
		0x5E78E846A8D90D8FULL,
		0x7B5FB4EC95D79258ULL,
		0x508716FE479C52D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA7A4571BC216A76ULL,
		0x23A2237AD1E8004EULL,
		0x3E78C5A7E90DD67BULL,
		0xEDA6EFB0CAB8A8CEULL,
		0x059AEAE3FDBC6288ULL,
		0x3D0875CBDC6A99E3ULL,
		0xD88890EC9C92A4DDULL,
		0xB4B1798027B75305ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71E8A514E6DD7574ULL,
		0x0D57FE71E2D07168ULL,
		0xF1066788911745F5ULL,
		0xD3B1A85972BDEF36ULL,
		0x59AD510FFE5E3BEBULL,
		0x2170727ACC6E73ACULL,
		0xA2D723FFF944ED7BULL,
		0x9BD59D7E1FE4FFD3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29B3D3A041DF7F2BULL,
		0x2C36DC6071C405E6ULL,
		0xF6B6F0A230D2754FULL,
		0x01ECEED3ABDCC609ULL,
		0xF945CCD26E2F396BULL,
		0x6779FEBFF2BE88A1ULL,
		0x75035663F2CDFA8AULL,
		0x3DCCDCF8E0E7EBC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6289625FAFB83939ULL,
		0xD21CE7680BBB4E34ULL,
		0xDA4BDE1FE8EFCB22ULL,
		0xA813750681F9E2BCULL,
		0xD4259197F83019BEULL,
		0xF74AD70751BDE48AULL,
		0x55681636E2FE5944ULL,
		0x59FCFBC9DE85C1B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC72A7140922745F2ULL,
		0x5A19F4F86608B7B1ULL,
		0x1C6B128247E2AA2CULL,
		0x59D979CD29E2E34DULL,
		0x25203B3A75FF1FACULL,
		0x702F27B8A100A417ULL,
		0x1F9B402D0FCFA145ULL,
		0xE3CFE12F02622A0FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D8BA9D0804DC457ULL,
		0x7EDDF443DBD6389AULL,
		0x822703DD77437193ULL,
		0xB93177F8F3E868A3ULL,
		0xDB1C92639946041BULL,
		0xFAA36C026BF162E7ULL,
		0x4528D2238D406F68ULL,
		0x221E3A60399AAA0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x301347F55A46A31DULL,
		0x0F8D4BE1ACD39CCBULL,
		0xDBD5E76A143C1A31ULL,
		0xA9C5BA7D84D9D8BDULL,
		0x78E8E6DE8064849CULL,
		0x9D9487C280A1E2D8ULL,
		0x28D4BF9DD4A4929BULL,
		0x4D8CD6A7F1ECCCC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D7861DB2607213AULL,
		0x6F50A8622F029BCFULL,
		0xA6511C7363075762ULL,
		0x0F6BBD7B6F0E8FE5ULL,
		0x6233AB8518E17F7FULL,
		0x5D0EE43FEB4F800FULL,
		0x1C541285B89BDCCDULL,
		0xD49163B847ADDD47ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AECF0F576E7D411ULL,
		0xA043358362E90E0DULL,
		0x147597E7383E3225ULL,
		0x7592530AB8483872ULL,
		0x9A439BF0C03671F0ULL,
		0xAD8F49EEE9E98EBEULL,
		0x7FC32F0175ACA859ULL,
		0x0DC5E0DE18DF1C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A5E19AB05D7EF73ULL,
		0xE5190604AFB7008BULL,
		0xFC6F147BB0615C34ULL,
		0x9BFB7FBDB47A7704ULL,
		0xA6B74B8F6B1CE522ULL,
		0xFC4D451B9E52BF5BULL,
		0xF6E3199DB1D16655ULL,
		0xA06588DF57B6DA63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408ED74A710FE49EULL,
		0xBB2A2F7EB3320D82ULL,
		0x1806836B87DCD5F0ULL,
		0xD996D34D03CDC16DULL,
		0xF38C506155198CCDULL,
		0xB14204D34B96CF62ULL,
		0x88E01563C3DB4203ULL,
		0x6D6057FEC128422EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x220F8AD70F6C87A0ULL,
		0x9BDC4A278734CF01ULL,
		0x97C3985D38CA2650ULL,
		0xF918DABF33A6CE7FULL,
		0x7D87E7C792A3D023ULL,
		0x59F4BB7C2C374A2EULL,
		0xC4993009CAB7FCC1ULL,
		0xCE93AB954D80E4CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAF3E73B1A59448BULL,
		0x986ED572C6DC67F0ULL,
		0x22C1EFA7B71AF132ULL,
		0x236ACEE90F31FB19ULL,
		0x2D9CC0CFDA53C885ULL,
		0x5E35D62868742BC5ULL,
		0xE5E6018CA1119D03ULL,
		0x1DC9DD54D29119D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x371BA39BF5134315ULL,
		0x036D74B4C0586710ULL,
		0x7501A8B581AF351EULL,
		0xD5AE0BD62474D366ULL,
		0x4FEB26F7B850079EULL,
		0xFBBEE553C3C31E69ULL,
		0xDEB32E7D29A65FBDULL,
		0xB0C9CE407AEFCAF8ULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5E30D7C70E485AULL,
		0xE39976ABC7FEEA29ULL,
		0x345E507C44780741ULL,
		0x76E1DCADA6C621B1ULL,
		0xCF2BAF31733901F0ULL,
		0x817565D98844852FULL,
		0xAEC0550329137081ULL,
		0x7875752F353F24DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45DB99D526C44A1ULL,
		0xC74D4BEAF620F9C9ULL,
		0xBE3E4FAE64695EE3ULL,
		0x676407288D0387D1ULL,
		0x6547364C63A88C27ULL,
		0x43F650231DB82A3DULL,
		0x7A8E00FC5F272F63ULL,
		0x8B8F909113D94D9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A00773A74A203B9ULL,
		0x1C4C2AC0D1DDF060ULL,
		0x762000CDE00EA85EULL,
		0x0F7DD58519C299DFULL,
		0x69E478E50F9075C9ULL,
		0x3D7F15B66A8C5AF2ULL,
		0x34325406C9EC411EULL,
		0xECE5E49E2165D73DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E85E4F9FBBE7ADBULL,
		0x98FE3ABE4B4B484EULL,
		0xE20F17EDBE3425ADULL,
		0x98C5987F95EADD09ULL,
		0xEF447875A0BA479AULL,
		0x2C53FFF9F1F38375ULL,
		0x3AAB97D824E366DBULL,
		0x063C16438EA3CF5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A380174402EE2BULL,
		0x1E4160D32189D7FDULL,
		0x37F18FCD6AACFF24ULL,
		0x7A4239B2B9FD6613ULL,
		0x47DA21E3841FA852ULL,
		0x5BD49DE665559F26ULL,
		0x1D3CC8CA7F055D17ULL,
		0x467C443638FC098EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCE264E2B7BB8CB0ULL,
		0x7ABCD9EB29C17050ULL,
		0xAA1D882053872689ULL,
		0x1E835ECCDBED76F6ULL,
		0xA76A56921C9A9F48ULL,
		0xD07F62138C9DE44FULL,
		0x1D6ECF0DA5DE09C3ULL,
		0xBFBFD20D55A7C5CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5386F405D0537FBBULL,
		0x4A8F4530B4E3A989ULL,
		0xB47EC864CEA4FA7AULL,
		0xA95FFEAB6C5F4C86ULL,
		0xEE244E2C3874D317ULL,
		0xB7CEF2BD2B385F69ULL,
		0x516826879D0B91FEULL,
		0xDF4BD925D491C060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1A20D8D6E2CC77ULL,
		0x333238480EB6FF51ULL,
		0x357110286BFFD2B7ULL,
		0xC056FCEAB27EB4D2ULL,
		0x2CEC0FDB17C8976BULL,
		0xFEDAE3686AE0A763ULL,
		0x2CDE12BBEA68E656ULL,
		0xC96C75B036868E7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB86CD32CF970B344ULL,
		0x175D0CE8A62CAA37ULL,
		0x7F0DB83C62A527C3ULL,
		0xE90901C0B9E097B4ULL,
		0xC1383E5120AC3BABULL,
		0xB8F40F54C057B806ULL,
		0x248A13CBB2A2ABA7ULL,
		0x15DF63759E0B31E5ULL
	}};
	sign = 0;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x286E007EEE7849B9ULL,
		0xAA1DEC3618AD0DA7ULL,
		0x17625D809B006D90ULL,
		0xE20C7CE60D9488EBULL,
		0x3E3694FA93772074ULL,
		0x3F4BC2E983AAFA8EULL,
		0x87096F1EF1F1F59FULL,
		0x6A5293E694FEA9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73F72A76650469A6ULL,
		0x76B3E66E79AFFC16ULL,
		0x0B5C782F58B4A942ULL,
		0xBB781766DAD506AAULL,
		0xD0A8298F014C4A09ULL,
		0xAED680E45BF5A50DULL,
		0xAF2FC90F445F0D16ULL,
		0x2F2BA5E03A3DCF6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB476D6088973E013ULL,
		0x336A05C79EFD1190ULL,
		0x0C05E551424BC44EULL,
		0x2694657F32BF8241ULL,
		0x6D8E6B6B922AD66BULL,
		0x9075420527B55580ULL,
		0xD7D9A60FAD92E888ULL,
		0x3B26EE065AC0DA44ULL
	}};
	sign = 0;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76C8308DCC2BF503ULL,
		0xBBA19EC1EA53D6DAULL,
		0x8E1CF895301E41A9ULL,
		0x213D2E712B4AFC83ULL,
		0xFE2F35E63DC123B0ULL,
		0x15B66A4C2E5FCD84ULL,
		0xFBEF11CE93572E78ULL,
		0x9A7E57ADD95191F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x705600D1C96E0C0CULL,
		0x7A0FD545D81C21A1ULL,
		0xC9EF7D8C5A3A30E3ULL,
		0xFEA5590C6EE27DBBULL,
		0x974111AAE11D5707ULL,
		0xDBC1C3464EC4D234ULL,
		0x20CCDFFAA5A33CCBULL,
		0x2214B7442535D54EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06722FBC02BDE8F7ULL,
		0x4191C97C1237B539ULL,
		0xC42D7B08D5E410C6ULL,
		0x2297D564BC687EC7ULL,
		0x66EE243B5CA3CCA8ULL,
		0x39F4A705DF9AFB50ULL,
		0xDB2231D3EDB3F1ACULL,
		0x7869A069B41BBCA9ULL
	}};
	sign = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x216A96E3C62BB0ECULL,
		0xEB10FF448EF8154CULL,
		0x64590DC41F7C5EBFULL,
		0xAD195F01B0E01748ULL,
		0x95C014DFDDF3F0CAULL,
		0x0FF7816770B19619ULL,
		0xA2476B85EB262E4DULL,
		0xAEA07F38B73F877FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00DA76C493ED6D07ULL,
		0xE3B0F4C22497B57CULL,
		0x80AB3EFA51C3FC60ULL,
		0x2B2A1B3E2A2D0CA0ULL,
		0xAE009104CC16C625ULL,
		0xCE26F4511EB2ED1DULL,
		0x1C66D91175D5CF2FULL,
		0x1A57218217B66BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2090201F323E43E5ULL,
		0x07600A826A605FD0ULL,
		0xE3ADCEC9CDB8625FULL,
		0x81EF43C386B30AA7ULL,
		0xE7BF83DB11DD2AA5ULL,
		0x41D08D1651FEA8FBULL,
		0x85E0927475505F1DULL,
		0x94495DB69F891B83ULL
	}};
	sign = 0;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC367F989DC371437ULL,
		0x8E22A28BB87F110BULL,
		0xE17AC52E85C511B7ULL,
		0xFEF4F671F6AEF338ULL,
		0x34B1DA13E7140F86ULL,
		0x5E6E08C2651EFBFFULL,
		0xF63B5934BAE2F91CULL,
		0x083F01B07C0C27EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17260F838460CD3EULL,
		0xA0BBBE1D2FEF1F27ULL,
		0xA031E68ECD74B539ULL,
		0x67C8064BAB74E7BFULL,
		0xBC2DB8ED52AD240BULL,
		0xC3AC20F3BA81C607ULL,
		0xE5FF1A855D4552A4ULL,
		0x4CAD3C2C1EDA1A2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC41EA0657D646F9ULL,
		0xED66E46E888FF1E4ULL,
		0x4148DE9FB8505C7DULL,
		0x972CF0264B3A0B79ULL,
		0x788421269466EB7BULL,
		0x9AC1E7CEAA9D35F7ULL,
		0x103C3EAF5D9DA677ULL,
		0xBB91C5845D320DBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4F0005DD9030DE5ULL,
		0x69ECEE6BE881EF65ULL,
		0x4D44A1EBAE99B11EULL,
		0xFABA68CAE1722A65ULL,
		0x08FD0AD2F3EF30DCULL,
		0x045BE9B4AB18A188ULL,
		0x4F92FECF1D7ACEF0ULL,
		0x0AFB9758C12C0357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9ABCB5578D67F1EULL,
		0x3275D56CFD02D3FAULL,
		0x05AE4EDD028FDD82ULL,
		0xFA063AAE6E58455CULL,
		0xA7EF281DC5A56355ULL,
		0x5C844350A1DDACE5ULL,
		0x1A707A43B795BDCFULL,
		0xEDDCE97622D2258CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB443508602C8EC7ULL,
		0x377718FEEB7F1B6AULL,
		0x4796530EAC09D39CULL,
		0x00B42E1C7319E509ULL,
		0x610DE2B52E49CD87ULL,
		0xA7D7A664093AF4A2ULL,
		0x3522848B65E51120ULL,
		0x1D1EADE29E59DDCBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF803888EAE3FA973ULL,
		0x41EDB633F8AF482DULL,
		0xE6D03568CC7009D9ULL,
		0xA696F7CC502E2C39ULL,
		0xAB3F2D3ADD82689CULL,
		0x4A6BAC2C5199FCB3ULL,
		0xE46FC35DCECC41D7ULL,
		0x44EFB41E433500A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B02F84D04BC5F9ULL,
		0xF67EB30C00AD959AULL,
		0x38053BC7F42476B8ULL,
		0x84AA1F058E6B5989ULL,
		0x468A91154D72F73AULL,
		0x0F0589CED0492007ULL,
		0xB3877DBD0E4AAEE7ULL,
		0x03624860820A444CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6535909DDF3E37AULL,
		0x4B6F0327F801B293ULL,
		0xAECAF9A0D84B9320ULL,
		0x21ECD8C6C1C2D2B0ULL,
		0x64B49C25900F7162ULL,
		0x3B66225D8150DCACULL,
		0x30E845A0C08192F0ULL,
		0x418D6BBDC12ABC56ULL
	}};
	sign = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x130EBF11484C77D7ULL,
		0x5B7674031E10BAC6ULL,
		0xF7B66E9700EF4AC0ULL,
		0xF0182050E1180132ULL,
		0xDEA257CC46022E37ULL,
		0x81B1CB1AE1A7DCBCULL,
		0x2A69690279DF31FEULL,
		0xAC0DFF53C4C5A001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59CA54A4CAA4FE5ULL,
		0x3CDD86E5EB12A2E4ULL,
		0x3C305E453ACE91CBULL,
		0xDAE42C5CFAB9C59BULL,
		0x1EC0CAD3549E4F28ULL,
		0xA92C0DB5DFAA0ECDULL,
		0xE61E589351D53D22ULL,
		0xF41E31768DDF2175ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D7219C6FBA227F2ULL,
		0x1E98ED1D32FE17E1ULL,
		0xBB861051C620B8F5ULL,
		0x1533F3F3E65E3B97ULL,
		0xBFE18CF8F163DF0FULL,
		0xD885BD6501FDCDEFULL,
		0x444B106F2809F4DBULL,
		0xB7EFCDDD36E67E8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3164EFA501ABD440ULL,
		0x04E001B92B574DD3ULL,
		0xAEC156FB5388D0B1ULL,
		0x42B62D29126D8457ULL,
		0x58DCF2CBC2A1D125ULL,
		0x5D6A56F34FB8CBE6ULL,
		0x3F4B94ABAB954EDAULL,
		0xF17414D5978EA4DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F539AC6B05A5073ULL,
		0x09F1E94F463CD20BULL,
		0x885385FB64B3972FULL,
		0x877387300A85442FULL,
		0x3269102BCF069C1EULL,
		0x449DAE494E26D526ULL,
		0xC0E868F5AC3C9E74ULL,
		0xAFCF2E3E7701175FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x221154DE515183CDULL,
		0xFAEE1869E51A7BC8ULL,
		0x266DD0FFEED53981ULL,
		0xBB42A5F907E84028ULL,
		0x2673E29FF39B3506ULL,
		0x18CCA8AA0191F6C0ULL,
		0x7E632BB5FF58B066ULL,
		0x41A4E697208D8D7EULL
	}};
	sign = 0;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9016E48F68821A07ULL,
		0x1DE0FC98799E2E76ULL,
		0x1BD8DE1187A45AC5ULL,
		0xAE2CED9CDC7B743BULL,
		0x4E4167BDAF47974AULL,
		0x38EE7B3882F87145ULL,
		0x4E5998FC0C8E393EULL,
		0x83F264AE9022200BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8976EA4400FD4F74ULL,
		0xCAEB6B2F0AD3E25BULL,
		0x3A9D1B344394B939ULL,
		0xDEA1D62736EBDE42ULL,
		0x9EA211D01B5298C0ULL,
		0x2EF5C07AD18851E1ULL,
		0x153D3CF3AD26A77AULL,
		0x03B6C74DABA2A412ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x069FFA4B6784CA93ULL,
		0x52F591696ECA4C1BULL,
		0xE13BC2DD440FA18BULL,
		0xCF8B1775A58F95F8ULL,
		0xAF9F55ED93F4FE89ULL,
		0x09F8BABDB1701F63ULL,
		0x391C5C085F6791C4ULL,
		0x803B9D60E47F7BF9ULL
	}};
	sign = 0;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D8CEC93D90CB93BULL,
		0x1C19470270338F88ULL,
		0x8E949A88D42C2802ULL,
		0x0E689629B6C7D617ULL,
		0x8DC578A14EBAE046ULL,
		0x14558D112E0A7D3DULL,
		0x4D8EF9F28FACAA1CULL,
		0x3494FBAEAF0A96B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4CE1D7D00F0A9BULL,
		0x34F5CCB28364FD0FULL,
		0xBC7753F3D0D18790ULL,
		0x0B0AC0014F6D1B08ULL,
		0xDD07E93074FE8307ULL,
		0x80E8EB5FDF653A65ULL,
		0x58267CA8ED41323DULL,
		0xC66BAC6846E73297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80400ABC08FDAEA0ULL,
		0xE7237A4FECCE9278ULL,
		0xD21D4695035AA071ULL,
		0x035DD628675ABB0EULL,
		0xB0BD8F70D9BC5D3FULL,
		0x936CA1B14EA542D7ULL,
		0xF5687D49A26B77DEULL,
		0x6E294F4668236419ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x881CB247EBA5791CULL,
		0x0812546B6AB1E749ULL,
		0x7567A32ADC2F5360ULL,
		0x9EE3EB838CE7DF78ULL,
		0x5962293581F49564ULL,
		0x272396B416C7D3A7ULL,
		0x14D5B193D8F27A93ULL,
		0xAD8E69F8CEEE72F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324F15C28126CEF4ULL,
		0x9F1E74D91A017168ULL,
		0xE9DE5BD22E705AE3ULL,
		0x3980947FA4043B7CULL,
		0xE02BCA79EC61026DULL,
		0x640E14A09F411CB9ULL,
		0x22E0E3F7C1453D97ULL,
		0x1253D097567EC2FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55CD9C856A7EAA28ULL,
		0x68F3DF9250B075E1ULL,
		0x8B894758ADBEF87CULL,
		0x65635703E8E3A3FBULL,
		0x79365EBB959392F7ULL,
		0xC31582137786B6EDULL,
		0xF1F4CD9C17AD3CFBULL,
		0x9B3A9961786FAFFBULL
	}};
	sign = 0;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2725A207F6909F1ULL,
		0xFD30DE4A3B7F5516ULL,
		0x152DB61236E58EA0ULL,
		0x7D922B087FDC2B42ULL,
		0xB263BB231EFCE1B2ULL,
		0x9E0D8F06AFC06C36ULL,
		0x9C8CE699829AA0A9ULL,
		0x6BA0DDACA8DBF2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D9E4AF626EE0FFULL,
		0xDDE8CB6D8DEF01BDULL,
		0x658A3F3D4062BED9ULL,
		0xDE66E681C2F6A862ULL,
		0x2B8F5EFCCD8F97CCULL,
		0x77FFFD1559A3CCE2ULL,
		0xB04EC49E3B2923B8ULL,
		0xD0D85B236A2ADA54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E9875711CFA28F2ULL,
		0x1F4812DCAD905359ULL,
		0xAFA376D4F682CFC7ULL,
		0x9F2B4486BCE582DFULL,
		0x86D45C26516D49E5ULL,
		0x260D91F1561C9F54ULL,
		0xEC3E21FB47717CF1ULL,
		0x9AC882893EB11869ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECB4D446F7BE2D07ULL,
		0xFB10936D87F382B4ULL,
		0xE84ECC6CDF8E1D78ULL,
		0x624A802D7BA2C68CULL,
		0x7C9D6C297519F051ULL,
		0x6A4758D10AB73489ULL,
		0x4BE86F5B2AB5BAF6ULL,
		0x4FBC8325EF8DD34AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBB06F88DE3D502FULL,
		0xD07B50C114CA67A8ULL,
		0x3C9B04217B083A6DULL,
		0x6C142C8DD11D30C9ULL,
		0xBBD50F61E5602056ULL,
		0x723037B6933E9110ULL,
		0xE1394CAACFC17E16ULL,
		0x03F3B122DF24418AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110464BE1980DCD8ULL,
		0x2A9542AC73291B0CULL,
		0xABB3C84B6485E30BULL,
		0xF636539FAA8595C3ULL,
		0xC0C85CC78FB9CFFAULL,
		0xF817211A7778A378ULL,
		0x6AAF22B05AF43CDFULL,
		0x4BC8D203106991BFULL
	}};
	sign = 0;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F31F5EF3C632B33ULL,
		0xD697CCAD443D6980ULL,
		0x44AC7D88A0B866FAULL,
		0x7E1CFF6CC23A6818ULL,
		0x4EDFCBF17D666EA5ULL,
		0xFB1EB8041A227AF4ULL,
		0xD6D92E6FB388C179ULL,
		0xC05F29F5299F2F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C627996957AB71FULL,
		0x08560D725BFB9F1DULL,
		0x9DEAA13617024947ULL,
		0x58325D98C76279D0ULL,
		0xBD9099D57638E2DCULL,
		0xD62845995CC25949ULL,
		0x38488808FFE33E26ULL,
		0x126716082BC22DBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02CF7C58A6E87414ULL,
		0xCE41BF3AE841CA63ULL,
		0xA6C1DC5289B61DB3ULL,
		0x25EAA1D3FAD7EE47ULL,
		0x914F321C072D8BC9ULL,
		0x24F6726ABD6021AAULL,
		0x9E90A666B3A58353ULL,
		0xADF813ECFDDD0146ULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2EC61CFE93E77AAULL,
		0xD06577659B155B7CULL,
		0x5161EF5B924CBF29ULL,
		0xA4246B113CB413E3ULL,
		0xE0AEB0D6FF21D2B8ULL,
		0xEF303051933540DAULL,
		0x94855CF9E0AEEE03ULL,
		0x19F33BDEAE3AAC8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC08E5EDC8D304A3ULL,
		0x1D18B8FFC0B3D2ADULL,
		0x3A8F0B5E0F356F22ULL,
		0x6C15E8B8537C1412ULL,
		0x3A60A37430D82D69ULL,
		0x5CB4AEEBDB0D2029ULL,
		0x40E25285F5B370ACULL,
		0x62245B7142B1C29CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6E37BE2206B7307ULL,
		0xB34CBE65DA6188CEULL,
		0x16D2E3FD83175007ULL,
		0x380E8258E937FFD1ULL,
		0xA64E0D62CE49A54FULL,
		0x927B8165B82820B1ULL,
		0x53A30A73EAFB7D57ULL,
		0xB7CEE06D6B88E9F0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C8E1CC6124014C1ULL,
		0x473475B5829E3F02ULL,
		0xE57D20C31EA30A92ULL,
		0xEEAEB37CC340C218ULL,
		0x5D9909E4135365A2ULL,
		0x4A32F60E99105D57ULL,
		0x88E075842BA9C595ULL,
		0x554C51B3ED8DAF83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B346C9D2F36BFCULL,
		0x8D5A60AC60A58B5AULL,
		0x2A5A7BFBAE1C7408ULL,
		0x8515721C717B2BF7ULL,
		0x29A7C4890C9DC367ULL,
		0xDF2D82A0B0FE2E39ULL,
		0x9A517181E72833ACULL,
		0xA10F203E0E0A281DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29DAD5FC3F4CA8C5ULL,
		0xB9DA150921F8B3A8ULL,
		0xBB22A4C770869689ULL,
		0x6999416051C59621ULL,
		0x33F1455B06B5A23BULL,
		0x6B05736DE8122F1EULL,
		0xEE8F0402448191E8ULL,
		0xB43D3175DF838765ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05859578179F9358ULL,
		0x8B0EFEC1E929FC1EULL,
		0x88238DEF82894519ULL,
		0x8A343185CB483D0FULL,
		0xA2C1BFFABD589BAFULL,
		0xC2DCBD7546632DB9ULL,
		0x9CDB4E78B999748CULL,
		0x7D0A3B70DDC25BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A5527888239F39ULL,
		0xAD6E2B2C9F5B473BULL,
		0xC48DE8F5323E5137ULL,
		0xF79598176DA05F2DULL,
		0x8DBDE0EAFDBB4474ULL,
		0xD953D1073E990EA7ULL,
		0xBD45D3279111C9ACULL,
		0xBEB4D714D08C065FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CE042FF8F7BF41FULL,
		0xDDA0D39549CEB4E2ULL,
		0xC395A4FA504AF3E1ULL,
		0x929E996E5DA7DDE1ULL,
		0x1503DF0FBF9D573AULL,
		0xE988EC6E07CA1F12ULL,
		0xDF957B512887AADFULL,
		0xBE55645C0D365587ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F4883D5A058A072ULL,
		0xD8325F0C925CFD70ULL,
		0x36BC2642741C405EULL,
		0x74FA227335864836ULL,
		0x636586F146C48845ULL,
		0xB39D2D2B65FDC0ABULL,
		0xB731076E2FF20E7EULL,
		0xB6B04E1963004205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3732C988E3EE1CCULL,
		0xE6A90F4EE55B75CDULL,
		0x2B8DE8BB9C1C2528ULL,
		0x91822FC5841FBCBEULL,
		0x1CD87FC6E95D1320ULL,
		0xC9EAE43E44A7BD49ULL,
		0xDD9FC7742A07BD82ULL,
		0xDFAE2D7821B6AA61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBD5573D1219BEA6ULL,
		0xF1894FBDAD0187A2ULL,
		0x0B2E3D86D8001B35ULL,
		0xE377F2ADB1668B78ULL,
		0x468D072A5D677524ULL,
		0xE9B248ED21560362ULL,
		0xD9913FFA05EA50FBULL,
		0xD70220A1414997A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA7A9EBB3B53C72DULL,
		0xE46E1C377D3B082CULL,
		0xAE9ACD597DBE948BULL,
		0x5C5D25E4804E4F4DULL,
		0xD002FF4CA855A406ULL,
		0x948C828C5891D648ULL,
		0xAA0DF79464717D6CULL,
		0xD8485A0A319C133FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48B9D1F78C517E95ULL,
		0x51FD097BED131309ULL,
		0x32EB14BDDB02F4E4ULL,
		0xBB22AE0C55C23E19ULL,
		0x711BE78AFFA16A25ULL,
		0xA408AEBAE87AD521ULL,
		0x41D2615C7A8993DAULL,
		0xA68B29F74B8D18B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C0CCC3AF024898ULL,
		0x927112BB9027F523ULL,
		0x7BAFB89BA2BB9FA7ULL,
		0xA13A77D82A8C1134ULL,
		0x5EE717C1A8B439E0ULL,
		0xF083D3D170170127ULL,
		0x683B9637E9E7E991ULL,
		0x31BD3012E60EFA8DULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EF6881DFC06D103ULL,
		0xC9F3D6B029678B47ULL,
		0xB9E8251DC90B0E93ULL,
		0xEDF189A206ECD7ADULL,
		0x6E9CC9EE7308D0CDULL,
		0x62B17F94BD7F3946ULL,
		0xD5B7E36DB5D6E6F4ULL,
		0x53C0B478081EEE3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E81855FDDBABECULL,
		0xD63CF6CE5DA668BBULL,
		0xA75B6F0B9C9F466FULL,
		0x4A846953C6E39B5CULL,
		0xF1EC998E897F1923ULL,
		0xE2CA9D8D2BC0626CULL,
		0xA4452EC13076BFE7ULL,
		0x3C3263593AFF3DBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE0E6FC7FE2B2517ULL,
		0xF3B6DFE1CBC1228BULL,
		0x128CB6122C6BC823ULL,
		0xA36D204E40093C51ULL,
		0x7CB0305FE989B7AAULL,
		0x7FE6E20791BED6D9ULL,
		0x3172B4AC8560270CULL,
		0x178E511ECD1FB07FULL
	}};
	sign = 0;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FC17C84ECBD0107ULL,
		0x714A1E0E1B603A67ULL,
		0x3502C80061263A5FULL,
		0xA948552BDD8A6BFFULL,
		0x0CD4FE5BA54CD72BULL,
		0xB54427A4E55E2D1DULL,
		0xEE24FF456456D478ULL,
		0x38AAF5BC9AFEAAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1845C4D2A97D9F90ULL,
		0x6C9EC631EA280675ULL,
		0xC8FAF4B5478D972DULL,
		0x364F323D128D955BULL,
		0x51A99BAB6B6620E3ULL,
		0xFC384C4A2C631F5CULL,
		0x60B5180C006F9939ULL,
		0xB314D2B9085CD354ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x377BB7B2433F6177ULL,
		0x04AB57DC313833F2ULL,
		0x6C07D34B1998A332ULL,
		0x72F922EECAFCD6A3ULL,
		0xBB2B62B039E6B648ULL,
		0xB90BDB5AB8FB0DC0ULL,
		0x8D6FE73963E73B3EULL,
		0x8596230392A1D74CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA22A2DF304F6022ULL,
		0x3B25BC1381ABA698ULL,
		0x24AC67535CE4BC76ULL,
		0xAE4F82C0200EF16DULL,
		0x9450CD11F7129533ULL,
		0x991009253381D9A3ULL,
		0x17C5AF27B2474A81ULL,
		0x6B5255CF36AFDCDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9329AB784BE1BEBULL,
		0x6D77597AF2ECD690ULL,
		0xABC589C864507512ULL,
		0xD509D7F6A54AC841ULL,
		0xEE13D31367999845ULL,
		0xE86DE54F6D320D3CULL,
		0xDE0CD831324990BDULL,
		0x39FD4F08F5575F92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0F00827AB914437ULL,
		0xCDAE62988EBED007ULL,
		0x78E6DD8AF8944763ULL,
		0xD945AAC97AC4292BULL,
		0xA63CF9FE8F78FCEDULL,
		0xB0A223D5C64FCC66ULL,
		0x39B8D6F67FFDB9C3ULL,
		0x315506C641587D4CULL
	}};
	sign = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11443C0D5463505CULL,
		0xB11FCC1E3F10F6E2ULL,
		0x2D4F6A6A2365A054ULL,
		0x41182FEC148BC1E9ULL,
		0x7B18405FED6E5E85ULL,
		0xDF5A7E4499A66C1BULL,
		0x0C4D6B4814107482ULL,
		0xE97E283D78CC0CFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F354DA7C3E5D7EDULL,
		0x1368F279C83283E4ULL,
		0x65B33CDF03B86033ULL,
		0x6451B83331BC8F3AULL,
		0x73EFA347F9F01C07ULL,
		0x256DCBC9AB2BD736ULL,
		0x5983319127C98C86ULL,
		0xEA634F6DE9DF4303ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020EEE65907D786FULL,
		0x9DB6D9A476DE72FEULL,
		0xC79C2D8B1FAD4021ULL,
		0xDCC677B8E2CF32AEULL,
		0x07289D17F37E427DULL,
		0xB9ECB27AEE7A94E5ULL,
		0xB2CA39B6EC46E7FCULL,
		0xFF1AD8CF8EECC9F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17409121629F8F5EULL,
		0xD0932DE00B313821ULL,
		0x96E9DDDFD0D767EDULL,
		0x8E78233C9CCCB8ADULL,
		0x63CC3FF453FBDC23ULL,
		0x14509B1E6DEE047FULL,
		0xABA85C4736C27787ULL,
		0x522C4FBACED14835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D342971CB26E03EULL,
		0x0B795EB37C579066ULL,
		0x38764BACE4533C98ULL,
		0xA5850E438EA211EDULL,
		0xACD8AE1D49D85696ULL,
		0x3D5AAC52D6E599D3ULL,
		0xB402708F5096C9F5ULL,
		0x43B2A551B6F7799DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA0C67AF9778AF20ULL,
		0xC519CF2C8ED9A7BAULL,
		0x5E739232EC842B55ULL,
		0xE8F314F90E2AA6C0ULL,
		0xB6F391D70A23858CULL,
		0xD6F5EECB97086AABULL,
		0xF7A5EBB7E62BAD91ULL,
		0x0E79AA6917D9CE97ULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2C340114AEAAEDAULL,
		0x13B50A5919984E67ULL,
		0x478D02A83B78E082ULL,
		0xC0DBC9715D7780C3ULL,
		0xA43C8A9188BAF0B0ULL,
		0x9D667E387F23E3B4ULL,
		0x881AA14EBE229A0FULL,
		0x58EF3A8EC4537998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68ED1E5EE7E3EB3ULL,
		0x6B2DD4AAFAF94B66ULL,
		0xBB1DA78CC0B3CA4FULL,
		0x5C7A47CF28406B80ULL,
		0x97538C0E05BF3D8DULL,
		0x33BDD0E343F73CCAULL,
		0x97FBED202E149FD6ULL,
		0x4B6DD0A45624781FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC346E2B5C6C7027ULL,
		0xA88735AE1E9F0300ULL,
		0x8C6F5B1B7AC51632ULL,
		0x646181A235371542ULL,
		0x0CE8FE8382FBB323ULL,
		0x69A8AD553B2CA6EAULL,
		0xF01EB42E900DFA39ULL,
		0x0D8169EA6E2F0178ULL
	}};
	sign = 0;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0EC10AF48E05E96ULL,
		0x9FE852D22457500FULL,
		0xCF5768374B9684EAULL,
		0x27613CC668E009C3ULL,
		0xFE77FF895F12BCA0ULL,
		0x665869365EA4C19DULL,
		0xE4EA2FF8355C3BB5ULL,
		0x77763A4F3B04747BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA761EDE8D154C02BULL,
		0x57D8F1CA671E7130ULL,
		0x820F9C3D09BEB48BULL,
		0x3D734A2AD829E5ECULL,
		0xE68CF5E0CB2303FDULL,
		0xECECB972F012C1B2ULL,
		0x43ABAE049D030940ULL,
		0x2AB86D38693A63DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x298A22C6778B9E6BULL,
		0x480F6107BD38DEDFULL,
		0x4D47CBFA41D7D05FULL,
		0xE9EDF29B90B623D7ULL,
		0x17EB09A893EFB8A2ULL,
		0x796BAFC36E91FFEBULL,
		0xA13E81F398593274ULL,
		0x4CBDCD16D1CA109DULL
	}};
	sign = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC531AA44DA272AF7ULL,
		0x18CFFB8D6E247EFCULL,
		0x69140B81F5793353ULL,
		0xB2871CB7ECAACBD4ULL,
		0x86E282FD2375C882ULL,
		0x5322ECE5318D058BULL,
		0xD6C77760A40E8EC0ULL,
		0xE6FB10AA122059C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F3EBCA3908D4BCULL,
		0x36E41A83EB0F4F02ULL,
		0x1E8189149F5D3094ULL,
		0xD0DEE4F9CDDC8FF4ULL,
		0xCF9A204FDD383EEDULL,
		0xBE6F5E716B1EDCE8ULL,
		0x78258E026C68DA5AULL,
		0x554F74922DDD4F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023DBE7AA11E563BULL,
		0xE1EBE10983152FFAULL,
		0x4A92826D561C02BEULL,
		0xE1A837BE1ECE3BE0ULL,
		0xB74862AD463D8994ULL,
		0x94B38E73C66E28A2ULL,
		0x5EA1E95E37A5B465ULL,
		0x91AB9C17E4430A83ULL
	}};
	sign = 0;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x807FC697920AAB5BULL,
		0xDF16EA2CAF3B0B8BULL,
		0x60D4730412B634A7ULL,
		0x8FF5D68D7162F472ULL,
		0xBC48191829104D1CULL,
		0xA9B9272252FA38B9ULL,
		0x722E5D07F0DBFCFFULL,
		0xEC590AE1329D00BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33A51D09878775EULL,
		0x69230E58FDC7145EULL,
		0xA49CDD0A0AFAB5CEULL,
		0xDDE86B39547A5B8AULL,
		0x541A258A22D35D69ULL,
		0x26BE0BDB43F07513ULL,
		0xDA35D541CEEF214FULL,
		0x51CC8F7D8D8AB3C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD4574C6F99233FDULL,
		0x75F3DBD3B173F72CULL,
		0xBC3795FA07BB7ED9ULL,
		0xB20D6B541CE898E7ULL,
		0x682DF38E063CEFB2ULL,
		0x82FB1B470F09C3A6ULL,
		0x97F887C621ECDBB0ULL,
		0x9A8C7B63A5124CF6ULL
	}};
	sign = 0;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x647BF4A31D379269ULL,
		0x229A457921DE1F81ULL,
		0xA75A3AD8A000765EULL,
		0x04E2E07D3D2C0C96ULL,
		0xE6BAB2C1A879435AULL,
		0xA577EB73C56E2C2BULL,
		0xFE8E911D23F11127ULL,
		0x8F708B39C5D4C08DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B08C53B69057C3ULL,
		0x0BB256ECB74FC3CAULL,
		0xEFDB90C7874BB4FFULL,
		0x9A129E3FF498AC51ULL,
		0xBBBAF9622B96A57DULL,
		0xA49764F44B083574ULL,
		0x9F4913DBFEDD7361ULL,
		0x05F8261D387FAACEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1CB684F66A73AA6ULL,
		0x16E7EE8C6A8E5BB6ULL,
		0xB77EAA1118B4C15FULL,
		0x6AD0423D48936044ULL,
		0x2AFFB95F7CE29DDCULL,
		0x00E0867F7A65F6B7ULL,
		0x5F457D4125139DC6ULL,
		0x8978651C8D5515BFULL
	}};
	sign = 0;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB63D816A0E3E7736ULL,
		0x9012D19269492F6BULL,
		0xD0C05DBF240363E2ULL,
		0x48B4F9BCBA42BF68ULL,
		0x6491E3785962A419ULL,
		0x9F426AB116D0F3A5ULL,
		0xBA8B698E2726BF09ULL,
		0x0CF78E01EB26146BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121064B641632023ULL,
		0x07ADB9438A29F756ULL,
		0x7674B75CD9E74EA3ULL,
		0xFF7661CC6668F0ADULL,
		0x85BD99F8030E96CFULL,
		0x037A0D32E3F8DE2EULL,
		0xA79C847A70D4505AULL,
		0x505A3E35B35ECBC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA42D1CB3CCDB5713ULL,
		0x8865184EDF1F3815ULL,
		0x5A4BA6624A1C153FULL,
		0x493E97F053D9CEBBULL,
		0xDED4498056540D49ULL,
		0x9BC85D7E32D81576ULL,
		0x12EEE513B6526EAFULL,
		0xBC9D4FCC37C748A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F60701180AD2A7BULL,
		0x1AE2C43E53310D36ULL,
		0x6DB9C0B4A4891108ULL,
		0xAF6F4CB00C247202ULL,
		0x99E1895BC88FDAF6ULL,
		0xA1B5C29A7202877AULL,
		0xE9313639AC40DD39ULL,
		0x5A2ECF69DF99632DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAADCAC92CB345A3EULL,
		0x66686EA1D0C55E03ULL,
		0x740B5022BF017559ULL,
		0x250C5E89B4317257ULL,
		0x2123686E381419E0ULL,
		0x75F3ED120A1725ECULL,
		0xAC9D9E403A4D52ACULL,
		0xA3129026F0BBAD88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD483C37EB578D03DULL,
		0xB47A559C826BAF32ULL,
		0xF9AE7091E5879BAEULL,
		0x8A62EE2657F2FFAAULL,
		0x78BE20ED907BC116ULL,
		0x2BC1D58867EB618EULL,
		0x3C9397F971F38A8DULL,
		0xB71C3F42EEDDB5A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7F1D93F17575F7FULL,
		0x2F59F0969CB61C12ULL,
		0xB52C3CE5EF4CA0D4ULL,
		0xC57E0494A6ADDEDAULL,
		0xB3647682BA106749ULL,
		0x48FFDFD1ABE41B4BULL,
		0x796C6281A388FE7AULL,
		0x25DA59CC669AC744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C9D0F464D229F75ULL,
		0x26C0C858E1F2DF14ULL,
		0xA004FDA27644BB28ULL,
		0x875848FE9AC7A94FULL,
		0x249AFAA43D0A7E0EULL,
		0x6E0E1EC5DA56022DULL,
		0x07BC0485CD9DEC2DULL,
		0xD2B5AE6732A47D09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B54C9F8CA34C00AULL,
		0x0899283DBAC33CFEULL,
		0x15273F437907E5ACULL,
		0x3E25BB960BE6358BULL,
		0x8EC97BDE7D05E93BULL,
		0xDAF1C10BD18E191EULL,
		0x71B05DFBD5EB124CULL,
		0x5324AB6533F64A3BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81A5583239A7664CULL,
		0xE80D6D3A4C3AA397ULL,
		0xA03F079BAD72EB8BULL,
		0x8B65F9D1E945E1F4ULL,
		0x53B20838FD88914AULL,
		0x3D0EAE1D48A8AB60ULL,
		0x98E12EA476558BBAULL,
		0x74B5911AC274ED52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AFE08CB4585013BULL,
		0x882FC41FDD187919ULL,
		0xC1EC5147B3D2031CULL,
		0x05A8F270A886A6A8ULL,
		0x79383BDF2D934A79ULL,
		0x042ED77A9B3C3018ULL,
		0x455C275323CE1D1CULL,
		0x4B0645A1D8AE955AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A74F66F4226511ULL,
		0x5FDDA91A6F222A7EULL,
		0xDE52B653F9A0E86FULL,
		0x85BD076140BF3B4BULL,
		0xDA79CC59CFF546D1ULL,
		0x38DFD6A2AD6C7B47ULL,
		0x5385075152876E9EULL,
		0x29AF4B78E9C657F8ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6905FFE0A5EE5E1BULL,
		0x6EC2F5042ED7C719ULL,
		0x0D074230EEF227DBULL,
		0x438CE08E5771A8A8ULL,
		0x74D223FFA9D06CA8ULL,
		0xB77118ECF940C7C6ULL,
		0x51FD7F71B5351CCCULL,
		0x86BD2C97E12A9826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A0B58172433EB2EULL,
		0x6BEF3411984326F3ULL,
		0xAE2661AF7BB68D93ULL,
		0x2F6C636972EA2E8CULL,
		0xA594D7648FC62132ULL,
		0xFFD755422BF64FF4ULL,
		0xDAEBF394E0FEE37AULL,
		0x3E7B851C61FB4A8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEFAA7C981BA72EDULL,
		0x02D3C0F29694A025ULL,
		0x5EE0E081733B9A48ULL,
		0x14207D24E4877A1BULL,
		0xCF3D4C9B1A0A4B76ULL,
		0xB799C3AACD4A77D1ULL,
		0x77118BDCD4363951ULL,
		0x4841A77B7F2F4D99ULL
	}};
	sign = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x811495779970C6E0ULL,
		0xA874DF3A195AA142ULL,
		0x363BE9A4A39D11D1ULL,
		0xFB876B84030969B5ULL,
		0xB80BA094656888D4ULL,
		0x3E639E2017FCDDECULL,
		0xE19EF1787313D399ULL,
		0x25E7F5D8CE10B67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFEEB03A57C004CEULL,
		0xC9707C48DFD7283EULL,
		0x4B677092FC246690ULL,
		0x5D11984678248EFBULL,
		0x21BC1FB25F2A4C26ULL,
		0x8D68ECF8CEAEE860ULL,
		0x14B147FA63476E83ULL,
		0x480CFF57D1382C4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC125E53D41B0C212ULL,
		0xDF0462F139837903ULL,
		0xEAD47911A778AB40ULL,
		0x9E75D33D8AE4DAB9ULL,
		0x964F80E2063E3CAEULL,
		0xB0FAB127494DF58CULL,
		0xCCEDA97E0FCC6515ULL,
		0xDDDAF680FCD88A33ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C3BFB9AF37A9229ULL,
		0x51D53A1FE885FC52ULL,
		0x885C333C92D788FEULL,
		0xF9769023A6836CDAULL,
		0xC805E416B903E23EULL,
		0x2C31ABB2B793BB9DULL,
		0x801BB8300B974740ULL,
		0x3CFBD07ABA6755C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7D2C8D86E7B402ULL,
		0x9CA0A352A4923A09ULL,
		0x7EC4A3068BF5D578ULL,
		0xE27C3EC7ACA836AEULL,
		0xB0ACDE457F44FA8CULL,
		0x3D3035216BB1417FULL,
		0xFE162BB8D70C0768ULL,
		0x917ADA5094DE767FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EBECF0D6C92DE27ULL,
		0xB53496CD43F3C248ULL,
		0x0997903606E1B385ULL,
		0x16FA515BF9DB362CULL,
		0x175905D139BEE7B2ULL,
		0xEF0176914BE27A1EULL,
		0x82058C77348B3FD7ULL,
		0xAB80F62A2588DF49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18F4DE937088710AULL,
		0xB68F1BC6489208BCULL,
		0xFD07CC533E3C3A01ULL,
		0x5E975103241B87A0ULL,
		0xF9899A13750FD44EULL,
		0xF7E0014D46F17D44ULL,
		0xBE93DD8B784407F6ULL,
		0xEE21D07AB191C450ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98533D852B5E3E38ULL,
		0xC06B5A8D67E3350DULL,
		0xD1B06392C2F2C971ULL,
		0x6A0586E833DC0FF0ULL,
		0x1006A19552E4796CULL,
		0xB407D94C2616733BULL,
		0x23D4074E415F1511ULL,
		0xD2BCFC68741F6C71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A1A10E452A32D2ULL,
		0xF623C138E0AED3AEULL,
		0x2B5768C07B49708FULL,
		0xF491CA1AF03F77B0ULL,
		0xE982F87E222B5AE1ULL,
		0x43D8280120DB0A09ULL,
		0x9ABFD63D36E4F2E5ULL,
		0x1B64D4123D7257DFULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x950D60D19DA615D6ULL,
		0xF06DCBD54BA04FF0ULL,
		0x9A2F68A4FA9AB443ULL,
		0xDCE733219B177D98ULL,
		0x964A4FE0886C2CF0ULL,
		0x88E3A4E5F9B4F66DULL,
		0x6A70D160D65D9334ULL,
		0xC9777CC862132EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCCB509E7209DA6ULL,
		0x8D70775D2E0F5CBEULL,
		0x713D1452BA4CC609ULL,
		0x83C24CE9F3BD1B24ULL,
		0x4748B7BFDE269B46ULL,
		0x70A770BD170B481FULL,
		0x0340A95C8642CAFDULL,
		0x8B5F9068D5C1F712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC940ABC7B6857830ULL,
		0x62FD54781D90F331ULL,
		0x28F25452404DEE3AULL,
		0x5924E637A75A6274ULL,
		0x4F019820AA4591AAULL,
		0x183C3428E2A9AE4EULL,
		0x67302804501AC837ULL,
		0x3E17EC5F8C5137A1ULL
	}};
	sign = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82A11468E1D538BEULL,
		0xEC6709A1BBEF599BULL,
		0xBE5AAC14C1C0BC39ULL,
		0x3BAD6E4A10C65B5AULL,
		0x86E019DFE922A700ULL,
		0x13ED02C39EF9E8E0ULL,
		0x423C9055848ADEA4ULL,
		0x7FEE6BAB29B0A7A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE5BB1320D8F5669ULL,
		0x8096F379D4A2A6F4ULL,
		0x9F667B7313ADB1B0ULL,
		0x99ABC714D56D185CULL,
		0x96EC0509F5F564F3ULL,
		0x977371108F14B571ULL,
		0xFB79A43159F90EFCULL,
		0xF4AC0CACCAFE47BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84456336D445E255ULL,
		0x6BD01627E74CB2A6ULL,
		0x1EF430A1AE130A89ULL,
		0xA201A7353B5942FEULL,
		0xEFF414D5F32D420CULL,
		0x7C7991B30FE5336EULL,
		0x46C2EC242A91CFA7ULL,
		0x8B425EFE5EB25FE3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C9925EFC904DD95ULL,
		0xC178B8DFF8146066ULL,
		0x524F9D3171220774ULL,
		0x984A267B2B211C88ULL,
		0x5C1508A7455BE431ULL,
		0x07678A8C81F5C42AULL,
		0x6C0F5B08AEACC097ULL,
		0xF59EEB15F4909F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41ABDE3A1E16E5A3ULL,
		0x7EDB1B67AB026790ULL,
		0x8FFD93E748CF32E7ULL,
		0x644A55C6C21A4027ULL,
		0x3C7E4C7AA2FD6EB4ULL,
		0x4E8C9801D725DEE9ULL,
		0x7D2BBF1B38BCAD91ULL,
		0xEDA670E873B4D2D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AED47B5AAEDF7F2ULL,
		0x429D9D784D11F8D6ULL,
		0xC252094A2852D48DULL,
		0x33FFD0B46906DC60ULL,
		0x1F96BC2CA25E757DULL,
		0xB8DAF28AAACFE541ULL,
		0xEEE39BED75F01305ULL,
		0x07F87A2D80DBCC38ULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87425457EEB92942ULL,
		0xA2EE78753129A568ULL,
		0x6512B45DA4377A60ULL,
		0xC0873DDBA081E58AULL,
		0x2556FA4A60461B89ULL,
		0x1B0DC40E8D89BBADULL,
		0x9006C5F6F9077D93ULL,
		0x1D0B79D2C753B393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BC8AB30686C20DULL,
		0x01A51365F5E408E5ULL,
		0x0520F1D5F5DCB997ULL,
		0x6F6F1457F6A96660ULL,
		0xEFDD46E9D3B2FEC1ULL,
		0xE7E6597B80F6277FULL,
		0xC91CC2F412BECF0CULL,
		0xB612DAA3D62FC938ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8585C9A4E8326735ULL,
		0xA149650F3B459C83ULL,
		0x5FF1C287AE5AC0C9ULL,
		0x51182983A9D87F2AULL,
		0x3579B3608C931CC8ULL,
		0x33276A930C93942DULL,
		0xC6EA0302E648AE86ULL,
		0x66F89F2EF123EA5AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F78C1B07FB6967EULL,
		0xE203EFBF4B091093ULL,
		0xA71B9A9B2CC203DEULL,
		0x2019B921F26AC0AEULL,
		0x3F1C7188347ACDF6ULL,
		0x54A8B63AE18ED7ACULL,
		0x82398D77B943BB9FULL,
		0x0F24EA7FC9D07EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1274613E3C3BCF3FULL,
		0x0B71C6E41353E950ULL,
		0xDA4ADBFC07C542ECULL,
		0x7A7E006957862CA0ULL,
		0x16B679AF8A4ABE9CULL,
		0x41DCC791B9C53473ULL,
		0x447F06B9D8437469ULL,
		0x531701549C882C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D046072437AC73FULL,
		0xD69228DB37B52743ULL,
		0xCCD0BE9F24FCC0F2ULL,
		0xA59BB8B89AE4940DULL,
		0x2865F7D8AA300F59ULL,
		0x12CBEEA927C9A339ULL,
		0x3DBA86BDE1004736ULL,
		0xBC0DE92B2D48523FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA26D330F2EE1491ULL,
		0xF39BB73FA17763D1ULL,
		0xE7F91E2E6606370CULL,
		0xBF7BAE68D98CA15AULL,
		0x9799E36262A36E14ULL,
		0xEA55BC18FA845516ULL,
		0xE3EB4F39D4602CB7ULL,
		0xC254E28CD522A705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514B3E7D3B28158DULL,
		0x56285DDD6F013966ULL,
		0x3734E1E61BBD1106ULL,
		0x3E97090E5FECBB50ULL,
		0x6ED448B3F073F2E8ULL,
		0x557D35907E3E5652ULL,
		0xB3EB8AE96E49DBEAULL,
		0x3D4A4942E02043BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8DB94B3B7C5FF04ULL,
		0x9D73596232762A6BULL,
		0xB0C43C484A492606ULL,
		0x80E4A55A799FE60AULL,
		0x28C59AAE722F7B2CULL,
		0x94D886887C45FEC4ULL,
		0x2FFFC450661650CDULL,
		0x850A9949F5026348ULL
	}};
	sign = 0;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6894275D24810103ULL,
		0xE718B728E4528525ULL,
		0x77C5FA42CBE45186ULL,
		0x82F80F404B05FFB5ULL,
		0x1C0B47111E1BDEC1ULL,
		0x71CACF978404A26CULL,
		0x268D1202FFEC21C4ULL,
		0x8A9B7D71A9B40146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5FD7E3B048622DULL,
		0xB2D57A7477C45C59ULL,
		0xE98DB8D9ED520CE9ULL,
		0x3BFD6EB43B723C61ULL,
		0xE06D0D6B816C96A3ULL,
		0x373C7B1932AB117AULL,
		0xEE031131FFAB8BDAULL,
		0xFC76A48452D77BE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A344F7974389ED6ULL,
		0x34433CB46C8E28CBULL,
		0x8E384168DE92449DULL,
		0x46FAA08C0F93C353ULL,
		0x3B9E39A59CAF481EULL,
		0x3A8E547E515990F1ULL,
		0x388A00D1004095EAULL,
		0x8E24D8ED56DC8563ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E47A00BD36A5AC2ULL,
		0x2C1DFC49BF003877ULL,
		0x21A401B967F9E809ULL,
		0xEEBF17BBBE7B3131ULL,
		0x18A433E649C7297AULL,
		0x2C8DAE68EE9505F2ULL,
		0x38C99579BFEF412FULL,
		0x1ED17B89A73873ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91EEFA410F33FF7AULL,
		0x3E8D1443170CEC8BULL,
		0x8B8CF5AA6A1A9D44ULL,
		0x88F1135DD91A6801ULL,
		0x4BDA532773242497ULL,
		0x43F09FC22EC677F8ULL,
		0xC1EF6C7B79C583FDULL,
		0x16025C1BE4E822E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC58A5CAC4365B48ULL,
		0xED90E806A7F34BEBULL,
		0x96170C0EFDDF4AC4ULL,
		0x65CE045DE560C92FULL,
		0xCCC9E0BED6A304E3ULL,
		0xE89D0EA6BFCE8DF9ULL,
		0x76DA28FE4629BD31ULL,
		0x08CF1F6DC2505104ULL
	}};
	sign = 0;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE260919EA53A849ULL,
		0x8C0494F195113DACULL,
		0x872D1391DE79F081ULL,
		0xF05390CEE09C20EDULL,
		0xC7007DF0D77EE0BCULL,
		0x54B6CA2C53E3053DULL,
		0x45C286E6B1EEF2EBULL,
		0x18C9BF42504B9128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51302332FC11E713ULL,
		0xDBB710E830D13E72ULL,
		0x1DA50403CB7F10D0ULL,
		0x4C7A73AA14104BD3ULL,
		0xB099FDD568A66661ULL,
		0x943A7FA12899BE0EULL,
		0x43812DBD5CA457FAULL,
		0xCD327B315D819226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CF5E5E6EE41C136ULL,
		0xB04D8409643FFF3AULL,
		0x69880F8E12FADFB0ULL,
		0xA3D91D24CC8BD51AULL,
		0x1666801B6ED87A5BULL,
		0xC07C4A8B2B49472FULL,
		0x02415929554A9AF0ULL,
		0x4B974410F2C9FF02ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AC9891075F737A9ULL,
		0xFBF22A492305AB12ULL,
		0x12B8044CA2C6F822ULL,
		0xD043B674F5DEEC11ULL,
		0xF4D8B4E84222D8BEULL,
		0xE3C0287EF59DFD7BULL,
		0xEAD0A533D8E81414ULL,
		0xA1B805B724E7B785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB0BE0DD72B08FE3ULL,
		0x5D85EDC2C91007CBULL,
		0x59412795E3587A17ULL,
		0xA35B7FAEE4824E00ULL,
		0x0E2B91A1F6064355ULL,
		0xBB9F4D81E402773BULL,
		0x75B2A1881D57D0BFULL,
		0xA20726D6225A9346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FBDA8330346A7C6ULL,
		0x9E6C3C8659F5A346ULL,
		0xB976DCB6BF6E7E0BULL,
		0x2CE836C6115C9E10ULL,
		0xE6AD23464C1C9569ULL,
		0x2820DAFD119B8640ULL,
		0x751E03ABBB904355ULL,
		0xFFB0DEE1028D243FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC1BD4222963DD06ULL,
		0xE5F7F9609DBBE2E7ULL,
		0x702C622A75B2EEF4ULL,
		0x36747417BFC7B497ULL,
		0xC89741F1EC397A18ULL,
		0xCA848543585507D5ULL,
		0x634A3406D2DA9206ULL,
		0x5635D5CD8680EF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E41FBAC58AC4C42ULL,
		0xF44E1159DA26EE7FULL,
		0x135765E71D4710C3ULL,
		0x06F360FE67750B33ULL,
		0xEC903256DE86FB4BULL,
		0x2A2C188B81BA123CULL,
		0x941026BACF453410ULL,
		0x5CBDD87FE35D1567ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DD9D875D0B790C4ULL,
		0xF1A9E806C394F468ULL,
		0x5CD4FC43586BDE30ULL,
		0x2F8113195852A964ULL,
		0xDC070F9B0DB27ECDULL,
		0xA0586CB7D69AF598ULL,
		0xCF3A0D4C03955DF6ULL,
		0xF977FD4DA323DA02ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEB9C518E69457E0ULL,
		0x0FAA29AF6553C473ULL,
		0x67AFFB8899BC9090ULL,
		0x869F1A850F53513FULL,
		0xD70462E725D065A6ULL,
		0x6DE49D33E673AF5AULL,
		0x06A2FD0629A0CE63ULL,
		0x36E8AE69E20CF0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4460AB07F3BB8B6CULL,
		0xA9D067B4557F36EBULL,
		0x21E6D101C667213DULL,
		0xF9CC140EFFAA1F13ULL,
		0x14C2633986AAF1A3ULL,
		0xB4D60F1264CA8C7DULL,
		0x56A4307A3E62990CULL,
		0x6F2EFD4FB60871FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA591A10F2D8CC74ULL,
		0x65D9C1FB0FD48D88ULL,
		0x45C92A86D3556F52ULL,
		0x8CD306760FA9322CULL,
		0xC241FFAD9F257402ULL,
		0xB90E8E2181A922DDULL,
		0xAFFECC8BEB3E3556ULL,
		0xC7B9B11A2C047EE7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880663FC95230E77ULL,
		0xF16449D7CBD3D331ULL,
		0x03BB8770451EB9DEULL,
		0x67207D43F6396856ULL,
		0xFC74EF4CC1FF1B6DULL,
		0xEB1D86C52CE22031ULL,
		0x8BC65F0983CF20B0ULL,
		0x66AF4465E53D575AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CC6283A8693A7DULL,
		0xDDB96DF55BEC8421ULL,
		0xE9C495DB09D9B134ULL,
		0xC5FA12F4A15FAB75ULL,
		0x583B8BD83A2988B9ULL,
		0x2F73967C108D3F7AULL,
		0x1C8AF45A175BEDAAULL,
		0x753220C416A83114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x853A0178ECB9D3FAULL,
		0x13AADBE26FE74F10ULL,
		0x19F6F1953B4508AAULL,
		0xA1266A4F54D9BCE0ULL,
		0xA439637487D592B3ULL,
		0xBBA9F0491C54E0B7ULL,
		0x6F3B6AAF6C733306ULL,
		0xF17D23A1CE952646ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC41CF32B37BCC1AEULL,
		0x41A8640C63320981ULL,
		0x020467DDD99430C4ULL,
		0xEACF0B7EE761391AULL,
		0x5209C74B398D5043ULL,
		0x38ED81EA47670AD9ULL,
		0x7017EB7297A313C1ULL,
		0x1B3A486D7191AB70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC38687A95B20125ULL,
		0x0D02B4757805EC76ULL,
		0xAF2938D3B8277663ULL,
		0x62F68FEF0E15CA28ULL,
		0xC5F4779983E66EE7ULL,
		0x2D3B27B318DE2C42ULL,
		0xCA2C78AAF122D69CULL,
		0x5985C90FB0355E06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7E48AB0A20AC089ULL,
		0x34A5AF96EB2C1D0AULL,
		0x52DB2F0A216CBA61ULL,
		0x87D87B8FD94B6EF1ULL,
		0x8C154FB1B5A6E15CULL,
		0x0BB25A372E88DE96ULL,
		0xA5EB72C7A6803D25ULL,
		0xC1B47F5DC15C4D69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF09AE68465F8D56ULL,
		0x1EDBE3FB50169768ULL,
		0x612360C98B15BF4EULL,
		0x4CED8B6AC7A3BA32ULL,
		0x1DEC2F8821BECDB7ULL,
		0x68EC4B5CF27943A9ULL,
		0xE07083D233326336ULL,
		0xB9BFDDE9DA8D6E0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA910846D5D08F1ULL,
		0xB9C07224604476B9ULL,
		0x97BD68357D4633A1ULL,
		0x226B05059C059165ULL,
		0x67BB9EC5FBE2D2DBULL,
		0xDC7FED96B29318EAULL,
		0xF0A77F473B0A3B14ULL,
		0x134305F13DDD6B92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4609DE3D9028465ULL,
		0x651B71D6EFD220AFULL,
		0xC965F8940DCF8BACULL,
		0x2A8286652B9E28CCULL,
		0xB63090C225DBFADCULL,
		0x8C6C5DC63FE62ABEULL,
		0xEFC9048AF8282821ULL,
		0xA67CD7F89CB0027AULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x962B2CB8938AB991ULL,
		0xEF9F1387CFA09C79ULL,
		0x2A4F8136AA52BCD3ULL,
		0x45A2C6F0B5ACA796ULL,
		0x326F0AFA07956537ULL,
		0x12E757A411772AB6ULL,
		0x669FF0D3423093F7ULL,
		0x3E1E67EE8CA58F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3CA5AA9E580A90ULL,
		0x682C20A68CB0154FULL,
		0xAC469AED14A03BE7ULL,
		0xC4B2054D56C7A78BULL,
		0x6B60980D25260586ULL,
		0x4914B68D975946B3ULL,
		0x1DA5FA7737342839ULL,
		0x944D9C510EF546C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABEE870DF532AF01ULL,
		0x8772F2E142F08729ULL,
		0x7E08E64995B280ECULL,
		0x80F0C1A35EE5000AULL,
		0xC70E72ECE26F5FB0ULL,
		0xC9D2A1167A1DE402ULL,
		0x48F9F65C0AFC6BBDULL,
		0xA9D0CB9D7DB048D1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21D7C0CB33AC5CF5ULL,
		0xE6C9075987A01329ULL,
		0x7C227D09259E6F1FULL,
		0x165A11EDCCBDEA0AULL,
		0x04AD92899E507836ULL,
		0xA46928873357362AULL,
		0x1984538442CBE732ULL,
		0x095D7D2745B0316AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7066E3013E89D1ULL,
		0xF1A6AB7498EB18B0ULL,
		0xBBD3D2001DEE2BF1ULL,
		0x34B566ABA350D4CCULL,
		0xD38DDE43909BF728ULL,
		0xB120C0729FF6D459ULL,
		0xFA066E064B0B81A6ULL,
		0xBB6D6967B5F6B80BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB36759E8326DD324ULL,
		0xF5225BE4EEB4FA78ULL,
		0xC04EAB0907B0432DULL,
		0xE1A4AB42296D153DULL,
		0x311FB4460DB4810DULL,
		0xF3486814936061D0ULL,
		0x1F7DE57DF7C0658BULL,
		0x4DF013BF8FB9795EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE25B7C63C2C793F5ULL,
		0xCCD859ADC1A01C35ULL,
		0x406A7423ED685D9BULL,
		0xB08C8B4DD082A675ULL,
		0x0FD570FF5EDF3738ULL,
		0xA6D912403B15AD57ULL,
		0x4F5DDA5CF2350EFBULL,
		0xACA8C721602A590BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD131F036814D0484ULL,
		0x3EAA666FE9957590ULL,
		0x74B33BE74C3F8766ULL,
		0x63A6218D1D1A61B3ULL,
		0x499722BEDCAF4D9BULL,
		0xBCFC08477729541EULL,
		0xFC17E4FF57ED085BULL,
		0xD06D608EDDE29BDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11298C2D417A8F71ULL,
		0x8E2DF33DD80AA6A5ULL,
		0xCBB7383CA128D635ULL,
		0x4CE669C0B36844C1ULL,
		0xC63E4E40822FE99DULL,
		0xE9DD09F8C3EC5938ULL,
		0x5345F55D9A48069FULL,
		0xDC3B66928247BD30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A1292AB2FD2FF23ULL,
		0xA6E02836DB81A70DULL,
		0x063CB36A0F94AAC8ULL,
		0x0433B01DD807DE21ULL,
		0x656A77F1ED88B9B6ULL,
		0xD03E49485C1C0853ULL,
		0xFA1B04AD500DB132ULL,
		0x17616A0EADA2D3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FBE59365047571ULL,
		0xEA4B231E90A9F0C2ULL,
		0xD6A9F8CDC31F37D1ULL,
		0x8F43B6B23FED1DA1ULL,
		0x366B72562181EA29ULL,
		0x56EB90800D133A23ULL,
		0x1BA2BFF468F579AAULL,
		0x93B364866280B3FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1716AD17CACE89B2ULL,
		0xBC9505184AD7B64BULL,
		0x2F92BA9C4C7572F6ULL,
		0x74EFF96B981AC07FULL,
		0x2EFF059BCC06CF8CULL,
		0x7952B8C84F08CE30ULL,
		0xDE7844B8E7183788ULL,
		0x83AE05884B221FA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC056E757FF23D393ULL,
		0x46C1172912EC52B4ULL,
		0xE564B8DF3524CF82ULL,
		0x9E53ECA7C954B1AFULL,
		0x6ED55EB20ABA67B3ULL,
		0xE406147915157FE1ULL,
		0x6738D7FCC8F8A972ULL,
		0x97F93122728F004BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E6CC24BDEB35954ULL,
		0xF630A4906AD8CD1FULL,
		0xEBE870CE5E10FB63ULL,
		0xC4859DD65BD11F2AULL,
		0x37283FA1E137BE5EULL,
		0xE2D8B05DF0911CC9ULL,
		0x91CE7CB8EB9B6A87ULL,
		0xA7AA8A21D97F09F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71EA250C20707A3FULL,
		0x50907298A8138595ULL,
		0xF97C4810D713D41EULL,
		0xD9CE4ED16D839284ULL,
		0x37AD1F102982A954ULL,
		0x012D641B24846318ULL,
		0xD56A5B43DD5D3EEBULL,
		0xF04EA700990FF655ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFB514C45738D9CBULL,
		0x494B5B97F18A0BAAULL,
		0x6C8CC94B7D957C07ULL,
		0x59DB82393058BF75ULL,
		0x3ECC2996F499300CULL,
		0x26988E391C3BA589ULL,
		0xDD6000A08525120FULL,
		0x15B676A80F188DC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71619DB599E0AE26ULL,
		0xD3F7B399A7BDD210ULL,
		0xE73B4985F5CD4746ULL,
		0x5C8B84A5DDEC385EULL,
		0xE91E41C5039DE344ULL,
		0x6C604B45C79BFCE1ULL,
		0xC29AC83C8229C7CAULL,
		0x833D201E6FC7CC6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E53770EBD582BA5ULL,
		0x7553A7FE49CC399AULL,
		0x85517FC587C834C0ULL,
		0xFD4FFD93526C8716ULL,
		0x55ADE7D1F0FB4CC7ULL,
		0xBA3842F3549FA8A7ULL,
		0x1AC5386402FB4A44ULL,
		0x927956899F50C154ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x196E9DF70E0572BBULL,
		0xD362D33D617BFB9EULL,
		0xBA648FFE9FC765C7ULL,
		0xF813BB8161FB510CULL,
		0xEDA303A1E1217C10ULL,
		0xF6AF81FB18FD0508ULL,
		0xC441E16F6A1BE6C2ULL,
		0x35BF607FEBD33290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC551EE7081FF83ULL,
		0x8DDCA5069A019106ULL,
		0x3BDCFB7FE9CB4544ULL,
		0xB90281C36C7D7F3FULL,
		0xDF92466B4DC5B9FAULL,
		0x6D1C1AB321F06040ULL,
		0x00FE686B39E3DCDFULL,
		0xAFF066B9BF4C82E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EA94C089D837338ULL,
		0x45862E36C77A6A97ULL,
		0x7E87947EB5FC2083ULL,
		0x3F1139BDF57DD1CDULL,
		0x0E10BD36935BC216ULL,
		0x89936747F70CA4C8ULL,
		0xC3437904303809E3ULL,
		0x85CEF9C62C86AFADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6955D951335B69D9ULL,
		0xF258048F5E1555C5ULL,
		0xA41DB686F56E3D2CULL,
		0xFD642ADBBA8AC0E1ULL,
		0xDA9BD48259F1C52BULL,
		0x1F098A06D2BECE66ULL,
		0x8744B1EE36D93AF6ULL,
		0xD4CAD3767A11FD50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CCE41AA1506F6AULL,
		0x4E553B2CB3805D6EULL,
		0x7AB2A69AB6038069ULL,
		0xC23F6B8C3191CCB4ULL,
		0x76D7A76196008833ULL,
		0x08DE0ED88325E48EULL,
		0x2809998406BEAE41ULL,
		0x6869E2710C3F3C8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6188F536920AFA6FULL,
		0xA402C962AA94F857ULL,
		0x296B0FEC3F6ABCC3ULL,
		0x3B24BF4F88F8F42DULL,
		0x63C42D20C3F13CF8ULL,
		0x162B7B2E4F98E9D8ULL,
		0x5F3B186A301A8CB5ULL,
		0x6C60F1056DD2C0C1ULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C3A2DBAC46CBC6BULL,
		0x84520B7A32967D61ULL,
		0x509EFB83AA5A9F26ULL,
		0xDAE41C970C5A0E72ULL,
		0x0F995CABE49BA028ULL,
		0x0942A5AA7C411BAAULL,
		0x2E0116AF2D7FEC64ULL,
		0xB1410E903916C8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B7458A24432842ULL,
		0xA33349ECF12E102DULL,
		0xA869678A60D71CEDULL,
		0x9E5B5368B54CDE54ULL,
		0x8EDB2CC07516EF56ULL,
		0xD96CAB3B76CD63BDULL,
		0x226CCD9E1E00B2D5ULL,
		0x7D25953C9AFDD3DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4582E830A0299429ULL,
		0xE11EC18D41686D34ULL,
		0xA83593F949838238ULL,
		0x3C88C92E570D301DULL,
		0x80BE2FEB6F84B0D2ULL,
		0x2FD5FA6F0573B7ECULL,
		0x0B9449110F7F398EULL,
		0x341B79539E18F4E4ULL
	}};
	sign = 0;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B43D92D32D3F36BULL,
		0xA3204F4205767DB4ULL,
		0x8CF16381EF8D5021ULL,
		0xB8AE076D078F8CCAULL,
		0xDA2A295E6F7C942EULL,
		0xFB72832FAB2B9FD7ULL,
		0xE3801F16CA1BA3DFULL,
		0x92800A437AFEEBC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA56F6721472E0FULL,
		0x1572E2C4177CAD31ULL,
		0x9BF89B9EC6F9122CULL,
		0x885CF56987C2E56EULL,
		0xB2B0E70B47E12038ULL,
		0x52FC2B182C12252FULL,
		0xE89EDEDC72051232ULL,
		0x6722780B59FA7C4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B9E69C6118CC55CULL,
		0x8DAD6C7DEDF9D082ULL,
		0xF0F8C7E328943DF5ULL,
		0x305112037FCCA75BULL,
		0x27794253279B73F6ULL,
		0xA87658177F197AA8ULL,
		0xFAE1403A581691ADULL,
		0x2B5D923821046F76ULL
	}};
	sign = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E84C29936FEBFDBULL,
		0x1C2C2068E6367CF3ULL,
		0xB93DE1376EE2DD42ULL,
		0x54BDB3312F4B81C9ULL,
		0xB03860C9A8982589ULL,
		0xAB0F8162167BE061ULL,
		0x7DA4A5EEE463A07AULL,
		0x451F18A770989320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA24074D3C0992EULL,
		0x64BB3961B8BE3F0EULL,
		0xFF8395FBAEDAA0CBULL,
		0x75F18709F3DF9A4DULL,
		0x6941E5B5B2F7B05AULL,
		0x75B708B233A87C73ULL,
		0x329B48942D986473ULL,
		0xC8018E0186C68BE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE28224633E26ADULL,
		0xB770E7072D783DE4ULL,
		0xB9BA4B3BC0083C76ULL,
		0xDECC2C273B6BE77BULL,
		0x46F67B13F5A0752EULL,
		0x355878AFE2D363EEULL,
		0x4B095D5AB6CB3C07ULL,
		0x7D1D8AA5E9D20737ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB4AD9582E3A59A8ULL,
		0xD8B059A06F7E35DCULL,
		0x7E6F88C3185BE9C0ULL,
		0xB58688D69977A021ULL,
		0x2BB773FF9AC1B4C7ULL,
		0xBDCB9C77FC3F2F9EULL,
		0xA026458FFAED37EDULL,
		0x2DDBA3367FB33B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F627D2B4B5AB2E0ULL,
		0x2785176BF586839AULL,
		0x73064DFF2488A81AULL,
		0x7FBEDB04337FD380ULL,
		0xE8CC9906D1DB3565ULL,
		0x14F0D40CCA24E952ULL,
		0x8EC0F385ADA9712DULL,
		0xA3CDAB499920E8B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BE85C2CE2DFA6C8ULL,
		0xB12B423479F7B242ULL,
		0x0B693AC3F3D341A6ULL,
		0x35C7ADD265F7CCA1ULL,
		0x42EADAF8C8E67F62ULL,
		0xA8DAC86B321A464BULL,
		0x1165520A4D43C6C0ULL,
		0x8A0DF7ECE6925264ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B5CE8909CCF1C65ULL,
		0x267223B102D6568EULL,
		0x04C4281A08CCEBB7ULL,
		0xBBDF91737D23B67DULL,
		0x5E2E7FC58F425059ULL,
		0x15FF72DA8C44BD41ULL,
		0x8060DA311AA18E8DULL,
		0xC71E0BE6B3F81625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A23C1B2ACD0603ULL,
		0x57B91BFF1E3786F9ULL,
		0x8A89E5B8B0BB206EULL,
		0x319264201797B525ULL,
		0xE02B3BC46B3295D6ULL,
		0xF77B407C44728D5BULL,
		0x66CD8FE06B2A4F03ULL,
		0x2D4625DA1122D4ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81BAAC7572021662ULL,
		0xCEB907B1E49ECF95ULL,
		0x7A3A42615811CB48ULL,
		0x8A4D2D53658C0157ULL,
		0x7E034401240FBA83ULL,
		0x1E84325E47D22FE5ULL,
		0x19934A50AF773F89ULL,
		0x99D7E60CA2D54178ULL
	}};
	sign = 0;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B718CAA8D4F9DF6ULL,
		0xF163FDA55DE070A2ULL,
		0xDA9B32847DF45DE4ULL,
		0x4291A9FFEBF2C043ULL,
		0xBE97B4C38A7437C3ULL,
		0xC40741F04E6267C3ULL,
		0x1E5C97832874D93AULL,
		0xE8C0B35788B98700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D158E0834E8AF5DULL,
		0x8EA179CBB47C925CULL,
		0x71884F9E117EA6B8ULL,
		0xE7B2FA0801C38B7AULL,
		0x8686A08F57700472ULL,
		0x426F77CE8F9BA5A2ULL,
		0x46835E8B09B97DE2ULL,
		0xD55D0ADE33799ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E5BFEA25866EE99ULL,
		0x62C283D9A963DE46ULL,
		0x6912E2E66C75B72CULL,
		0x5ADEAFF7EA2F34C9ULL,
		0x3811143433043350ULL,
		0x8197CA21BEC6C221ULL,
		0xD7D938F81EBB5B58ULL,
		0x1363A879553FEC30ULL
	}};
	sign = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4A5DF1E800953D0ULL,
		0x265088F273FF7162ULL,
		0x10CC35E3194BD9BDULL,
		0x8ACA28AFB0F636D1ULL,
		0xDC4DD28D1E67AC84ULL,
		0x2B9A4AC4517AE9EFULL,
		0x529A02CE71D19922ULL,
		0x750A416440D52F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x535455851DF02DD1ULL,
		0x8C92AC9FA09C0B2DULL,
		0x1488E09FE1D0CACDULL,
		0x744255F21092A591ULL,
		0x368B359281C381E5ULL,
		0x35F9DF9568BAB715ULL,
		0xCC2FA0A9F85A72E1ULL,
		0x75EAA7E0FEFCC370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51518999621925FFULL,
		0x99BDDC52D3636635ULL,
		0xFC435543377B0EEFULL,
		0x1687D2BDA063913FULL,
		0xA5C29CFA9CA42A9FULL,
		0xF5A06B2EE8C032DAULL,
		0x866A622479772640ULL,
		0xFF1F998341D86BA9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABE34483428BA173ULL,
		0xAB3B48F7058CFFADULL,
		0x0955C366C2D22350ULL,
		0x0ADBE9F31964195FULL,
		0xCA43325DB10F4E97ULL,
		0x10869BC64AFA3190ULL,
		0x9D460C7A4A7BF4C5ULL,
		0x8A36C3D465B5D876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10CB90AF181ACBF2ULL,
		0x3CD068D9350F0BE1ULL,
		0x55E05DE28E1F7F18ULL,
		0x1BCED58B30216D70ULL,
		0xC8AC3BCF72B2332FULL,
		0x0A3967118A56D087ULL,
		0xDFE11586C54969F3ULL,
		0x6192C339DCC37A30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B17B3D42A70D581ULL,
		0x6E6AE01DD07DF3CCULL,
		0xB375658434B2A438ULL,
		0xEF0D1467E942ABEEULL,
		0x0196F68E3E5D1B67ULL,
		0x064D34B4C0A36109ULL,
		0xBD64F6F385328AD2ULL,
		0x28A4009A88F25E45ULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBF73F4622BC602CULL,
		0xD4516B996A701340ULL,
		0x29077A948406C640ULL,
		0x03EFF634B246B62CULL,
		0x8C1B95488F18703FULL,
		0x74D0FC8FBD1C3ED2ULL,
		0x56A647C1861C787AULL,
		0xAC5542137DF32584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x111985D3CF3E6987ULL,
		0x20D9AB2DD05B41B2ULL,
		0xFDDB9C3D75323EC4ULL,
		0x5EC8E5292B92DFF9ULL,
		0x93B640FEECE6DA31ULL,
		0x59DE97560F27DF7FULL,
		0x0683BDC1FA62628AULL,
		0xF86081584848F2D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCADDB972537DF6A5ULL,
		0xB377C06B9A14D18EULL,
		0x2B2BDE570ED4877CULL,
		0xA527110B86B3D632ULL,
		0xF8655449A231960DULL,
		0x1AF26539ADF45F52ULL,
		0x502289FF8BBA15F0ULL,
		0xB3F4C0BB35AA32B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA50394DD8733AB6ULL,
		0xB8E5C035F51F2040ULL,
		0xBDEE365D2BAB21CEULL,
		0xCB15CEAFD121626EULL,
		0x001B63F16AFF6EACULL,
		0x2182EEF15C09C285ULL,
		0x7ACD19DA0BC16B8BULL,
		0xE197F767EF24EEACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x540736A88B9BF077ULL,
		0x6C22BDC6379A27B5ULL,
		0x4776B01D89B51B1FULL,
		0x9E91DE800BEA3E5AULL,
		0xA2EE43817B9F0D58ULL,
		0x8E21D972818129BDULL,
		0x634DF6C01C38ABD9ULL,
		0x984EBE2B0747EED6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x664902A54CD74A3FULL,
		0x4CC3026FBD84F88BULL,
		0x7677863FA1F606AFULL,
		0x2C83F02FC5372414ULL,
		0x5D2D206FEF606154ULL,
		0x9361157EDA8898C7ULL,
		0x177F2319EF88BFB1ULL,
		0x4949393CE7DCFFD6ULL
	}};
	sign = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD33E8F251707E400ULL,
		0x15643683DAA2693AULL,
		0xF1F06AA0A555F25AULL,
		0x1E77CAC4AEB88E42ULL,
		0x7918650907BC8CC5ULL,
		0xA5D7FB68CF2BC80AULL,
		0x44F24D21DEAB43E8ULL,
		0x1140D32656E5C5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79EF8AC926D3C01ULL,
		0x8305DBBB211F6361ULL,
		0xEC8134B6DADE050DULL,
		0xA64C4B0EE5520AFFULL,
		0x5D93CF297F964662ULL,
		0x2CAC4145E081ADB8ULL,
		0xE001660CC4386B15ULL,
		0x7C76A509DB79AAE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B9F9678849AA7FFULL,
		0x925E5AC8B98305D9ULL,
		0x056F35E9CA77ED4CULL,
		0x782B7FB5C9668343ULL,
		0x1B8495DF88264662ULL,
		0x792BBA22EEAA1A52ULL,
		0x64F0E7151A72D8D3ULL,
		0x94CA2E1C7B6C1ADDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88BF26CE62DD4215ULL,
		0x1C4DC374F63A851EULL,
		0x0DF59774FDEC2351ULL,
		0x0440630C53A8FDC8ULL,
		0x27A32B7A68764D2AULL,
		0x5AA5DF024472439CULL,
		0x7904FE6A58AC8652ULL,
		0xFE9285F82ACE95C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B1F8765224F3F0ULL,
		0x25157F160EC460E9ULL,
		0x6571155FE8068CE0ULL,
		0x4A824D40AE73FF08ULL,
		0x1CCE38464A266EE3ULL,
		0x1DC1605ED8649293ULL,
		0x24B19A3A9B4C59EEULL,
		0x9B45241BF9F64FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x770D2E5810B84E25ULL,
		0xF738445EE7762435ULL,
		0xA884821515E59670ULL,
		0xB9BE15CBA534FEBFULL,
		0x0AD4F3341E4FDE46ULL,
		0x3CE47EA36C0DB109ULL,
		0x5453642FBD602C64ULL,
		0x634D61DC30D8461BULL
	}};
	sign = 0;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29BD2C32F1E88CFBULL,
		0x6BE37FB378ECF1EFULL,
		0x96F842B02FC7A479ULL,
		0x0C1B83716D3D2D8BULL,
		0xC45703585BB993AFULL,
		0x9E4C887E48941C53ULL,
		0x9BDB79D933A5F9C9ULL,
		0x23F7F655FA43C240ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D49AB5CA5E7A5FBULL,
		0x70BB9175DDCE39A1ULL,
		0x6009229311134D00ULL,
		0x91AB149558587A88ULL,
		0xDB8F3D56FA191962ULL,
		0xCE9DB9C9AA34F9AEULL,
		0x250A9E85E37DCA43ULL,
		0x78F140FFA6D7AD58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C7380D64C00E700ULL,
		0xFB27EE3D9B1EB84EULL,
		0x36EF201D1EB45778ULL,
		0x7A706EDC14E4B303ULL,
		0xE8C7C60161A07A4CULL,
		0xCFAECEB49E5F22A4ULL,
		0x76D0DB5350282F85ULL,
		0xAB06B556536C14E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD69CFC76963C345ULL,
		0x3F9B9FB8B7A4E9E7ULL,
		0x2E611C09145CE513ULL,
		0x20F77FD5D069613FULL,
		0x068C0B9DB108C0C2ULL,
		0xD14B0FFDB4BB88E7ULL,
		0x4EFB2C7D22BFC4B2ULL,
		0x1F8CD75EC401BFFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661205C5879D5DFCULL,
		0x43E3CC3C0F106E6FULL,
		0x3AF784943CED5037ULL,
		0xBAC198C7B4B5A8A1ULL,
		0x48D3D38147ADD81AULL,
		0xFF941ACBB8CE53E3ULL,
		0x10B03C9EE277A4A8ULL,
		0x030E1ED6F9C7BA5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6757CA01E1C66549ULL,
		0xFBB7D37CA8947B78ULL,
		0xF3699774D76F94DBULL,
		0x6635E70E1BB3B89DULL,
		0xBDB8381C695AE8A7ULL,
		0xD1B6F531FBED3503ULL,
		0x3E4AEFDE40482009ULL,
		0x1C7EB887CA3A059DULL
	}};
	sign = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1896D5193DCB626DULL,
		0xD4B3A3C0739B1697ULL,
		0xC9B4E299C45ADCC8ULL,
		0x64239BB4C4FCC3FDULL,
		0x0BD7CC19F97A73C0ULL,
		0x025C51DA183677BDULL,
		0x914EACE51B8E9753ULL,
		0xF3D8604FD512D0E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35745DF048B45CD1ULL,
		0x30EBFC18B837AE13ULL,
		0x3D2920B104DCD598ULL,
		0xDE59CA2A6CEA1556ULL,
		0x8EB7CD367FA768E6ULL,
		0x0B1F46D58712BDDFULL,
		0x608B525FFF7383EDULL,
		0x914A93A20C7171A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3227728F517059CULL,
		0xA3C7A7A7BB636883ULL,
		0x8C8BC1E8BF7E0730ULL,
		0x85C9D18A5812AEA7ULL,
		0x7D1FFEE379D30AD9ULL,
		0xF73D0B049123B9DDULL,
		0x30C35A851C1B1365ULL,
		0x628DCCADC8A15F3FULL
	}};
	sign = 0;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA108627F7B35A565ULL,
		0x62F6B6354A93F176ULL,
		0x1155456D09C894BAULL,
		0x3F71FCB0958F3C96ULL,
		0xD1144B8BF806557BULL,
		0xBA805C1B21E9A5E1ULL,
		0x14ACC1D897F25F75ULL,
		0x6B6381C822D951B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0CC1C0CA7E295F8ULL,
		0xDDFC1C92328637E2ULL,
		0x98A56EF086F2816AULL,
		0xB7758CD2F089C329ULL,
		0xED337A032BF06AF4ULL,
		0x74B1E082B7D2409AULL,
		0xE9D250B60DC3D9B3ULL,
		0x1195D30B9917180AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF03C4672D3530F6DULL,
		0x84FA99A3180DB993ULL,
		0x78AFD67C82D6134FULL,
		0x87FC6FDDA505796CULL,
		0xE3E0D188CC15EA86ULL,
		0x45CE7B986A176546ULL,
		0x2ADA71228A2E85C2ULL,
		0x59CDAEBC89C239ADULL
	}};
	sign = 0;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0AB3A379AB18625ULL,
		0x8ABF94FF59C075F7ULL,
		0x481F2B26CCBB0CEDULL,
		0xE6532030707FECE1ULL,
		0x3A48D1829BBDCB75ULL,
		0xBB2D1FE1363BAD51ULL,
		0xA1DBDFED95067A13ULL,
		0xB37E02E64597F6D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CE6DFBCD981A92ULL,
		0xC6010A20BE811500ULL,
		0x59CE1D513C715D81ULL,
		0xA92C0865DD366A64ULL,
		0x5F3EFBECC509AAD0ULL,
		0x9E4CFC0F3C98F00DULL,
		0x457E7E416B62161EULL,
		0x8EA7DED1E34BAA8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97DCCC3BCD196B93ULL,
		0xC4BE8ADE9B3F60F7ULL,
		0xEE510DD59049AF6BULL,
		0x3D2717CA9349827CULL,
		0xDB09D595D6B420A5ULL,
		0x1CE023D1F9A2BD43ULL,
		0x5C5D61AC29A463F5ULL,
		0x24D62414624C4C47ULL
	}};
	sign = 0;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF51A9A50A6BA076ULL,
		0x1B71A20E748BCAE1ULL,
		0x3ED0EBBD0BF4E4BBULL,
		0x4DCB716C4BE0A921ULL,
		0xFA9E1C08299D01FAULL,
		0x349023AEE142E867ULL,
		0x8C45561F16932626ULL,
		0x67F599A23D6D496EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D074AFD54998D0ULL,
		0xE2C459F9F4F715B0ULL,
		0xFA3CAD90EDD5DB4DULL,
		0x355288C20B857A19ULL,
		0x1A71D96CB2657A62ULL,
		0xA5B74A81E12245B4ULL,
		0x4AEB1A10F0D63187ULL,
		0xD628D680F07A51B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A8134F5352207A6ULL,
		0x38AD48147F94B531ULL,
		0x44943E2C1E1F096DULL,
		0x1878E8AA405B2F07ULL,
		0xE02C429B77378798ULL,
		0x8ED8D92D0020A2B3ULL,
		0x415A3C0E25BCF49EULL,
		0x91CCC3214CF2F7BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96BFD69FCCBB6A04ULL,
		0xFFEF9742E1A4FD05ULL,
		0xB38BFB2BA9513471ULL,
		0x964CEC3C839926C9ULL,
		0xCF4FE3EFCDCDDE7DULL,
		0xDAC9545F736CD674ULL,
		0x65FA5166634B1B6AULL,
		0x6EC0588E1EC14CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD4196052088162ULL,
		0x334ED651A73F7E96ULL,
		0xC06B14A30922A49BULL,
		0x2C9B21ACFCDF2325ULL,
		0x382162F1908DD032ULL,
		0x9BDD4474FE15D787ULL,
		0x39F6FB540D1159EEULL,
		0x5026D0620F82D3A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9EBBD3F7AB2E8A2ULL,
		0xCCA0C0F13A657E6EULL,
		0xF320E688A02E8FD6ULL,
		0x69B1CA8F86BA03A3ULL,
		0x972E80FE3D400E4BULL,
		0x3EEC0FEA7556FEEDULL,
		0x2C0356125639C17CULL,
		0x1E99882C0F3E790BULL
	}};
	sign = 0;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75C8E0AAE9D0569FULL,
		0xA2F4C3C131419686ULL,
		0xD4B7DBD82194AAEAULL,
		0xE316581D3A3EA685ULL,
		0x4B5922B8D7936FC9ULL,
		0x6935B17B8597BEA5ULL,
		0x7631EC3A9E9568E2ULL,
		0xEFB5D4755285AAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3E5EF4E879556BULL,
		0x1C56BD4F3715FFDAULL,
		0x226859FA9D8595BDULL,
		0xF9222F42468A806EULL,
		0xA704EB829FC6C386ULL,
		0xC6428929F0D623B7ULL,
		0x376EBC7B28DCE6D5ULL,
		0xFD07DCBD96050E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B8A81B601570134ULL,
		0x869E0671FA2B96ABULL,
		0xB24F81DD840F152DULL,
		0xE9F428DAF3B42617ULL,
		0xA454373637CCAC42ULL,
		0xA2F3285194C19AEDULL,
		0x3EC32FBF75B8820CULL,
		0xF2ADF7B7BC809C61ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0147612030FCB9EULL,
		0x13BC6B9E17F0A3AFULL,
		0x046BDD57D6ECDEA7ULL,
		0x4DA47BED655B0EF7ULL,
		0x6254F33716CBC818ULL,
		0xE4AA2F09F66B5CC2ULL,
		0x9AE50180F49B34DAULL,
		0x4B0974F023EECB2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97088D0AD65069A0ULL,
		0x1639BCF4DDEB61CBULL,
		0xA965E9264FC077E6ULL,
		0x615D5CE3C3E87C54ULL,
		0x3002E30B2C55FBD6ULL,
		0xB7838DB460B6AC63ULL,
		0x5FDB985077F1677BULL,
		0xDA86F9721F29F81CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x090BE9072CBF61FEULL,
		0xFD82AEA93A0541E4ULL,
		0x5B05F431872C66C0ULL,
		0xEC471F09A17292A2ULL,
		0x3252102BEA75CC41ULL,
		0x2D26A15595B4B05FULL,
		0x3B0969307CA9CD5FULL,
		0x70827B7E04C4D312ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09B53EFDD79C51DBULL,
		0xB6CBB5E436330455ULL,
		0x63BF55516648CC1EULL,
		0x419A155806777407ULL,
		0x9827EB1E0D202AE6ULL,
		0x6A8909ECE336EC62ULL,
		0x3B54477F3944AE00ULL,
		0x6DC71FBA11353521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED4AD2E6630BDA6ULL,
		0xA6093883E601DB01ULL,
		0x01F3B4E6284B344AULL,
		0x9A64696856D03319ULL,
		0xEA954EBF94D9E827ULL,
		0xF074DF2309C3B715ULL,
		0x26A246F994B9427FULL,
		0xCA5B7881D12A8CA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AE091CF716B9435ULL,
		0x10C27D6050312953ULL,
		0x61CBA06B3DFD97D4ULL,
		0xA735ABEFAFA740EEULL,
		0xAD929C5E784642BEULL,
		0x7A142AC9D973354CULL,
		0x14B20085A48B6B80ULL,
		0xA36BA738400AA879ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D21C46C377D1D4CULL,
		0x68704C031A51C5CAULL,
		0xFDA02367D03F8FFFULL,
		0x5C7056673DA684D2ULL,
		0x036F252250EEF3B1ULL,
		0xD3CD0D43B9470212ULL,
		0x352CE1FC5A85C7F6ULL,
		0x12365E9711B28897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7523A6CE5EC9C204ULL,
		0xE09FD3052F10C612ULL,
		0x580726358FC0592AULL,
		0xD5E761547AF22A4AULL,
		0x5D32644F0F3F6656ULL,
		0x6AC9AB9195213C85ULL,
		0x66290ED715CB137EULL,
		0x08145014B5FE14F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97FE1D9DD8B35B48ULL,
		0x87D078FDEB40FFB7ULL,
		0xA598FD32407F36D4ULL,
		0x8688F512C2B45A88ULL,
		0xA63CC0D341AF8D5AULL,
		0x690361B22425C58CULL,
		0xCF03D32544BAB478ULL,
		0x0A220E825BB473A5ULL
	}};
	sign = 0;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A8DBA18BD9D741CULL,
		0xE3D184E1552D6DE0ULL,
		0x950F09E23BF57DFFULL,
		0x1482DEAA7DB8D38BULL,
		0x46A40D33C74C3428ULL,
		0x502265713488E557ULL,
		0x36ACF70A7F05858BULL,
		0xEDA6AC104C9F8F50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC238D0E79C895313ULL,
		0xCD62DA27C443F636ULL,
		0xEDAFB8119F69E50EULL,
		0xFEFFC1EF4DE24353ULL,
		0x433216CD1B95FD29ULL,
		0xCB624418A6F52C48ULL,
		0xA302DE46ADB34752ULL,
		0xC2AD437CF751D318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8854E93121142109ULL,
		0x166EAAB990E977A9ULL,
		0xA75F51D09C8B98F1ULL,
		0x15831CBB2FD69037ULL,
		0x0371F666ABB636FEULL,
		0x84C021588D93B90FULL,
		0x93AA18C3D1523E38ULL,
		0x2AF96893554DBC37ULL
	}};
	sign = 0;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41F51F9F8E716D7BULL,
		0xE723D84DA46D772BULL,
		0x924FCE79FB6103A4ULL,
		0x221C3885ACB47F94ULL,
		0x48B5035ECBA3F3CFULL,
		0xB5B85C57770B7CC4ULL,
		0xE14A9957928CF9E5ULL,
		0x9AB7D33D6BD923F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F12964DC9A9A93ULL,
		0x43184D01D84EDEBBULL,
		0x1FD15FE67955C55FULL,
		0xEA3550D363F2D1D9ULL,
		0xED784D4BF30BEEA7ULL,
		0x4736476590ED0595ULL,
		0xC817D4EEFCE5788AULL,
		0x7EDB7AF7943BAED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA103F63AB1D6D2E8ULL,
		0xA40B8B4BCC1E986FULL,
		0x727E6E93820B3E45ULL,
		0x37E6E7B248C1ADBBULL,
		0x5B3CB612D8980527ULL,
		0x6E8214F1E61E772EULL,
		0x1932C46895A7815BULL,
		0x1BDC5845D79D7521ULL
	}};
	sign = 0;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0A1AFAF215AB71AULL,
		0x7B52DA04083274F7ULL,
		0x55AF5502F9C14CF7ULL,
		0xE390479698284308ULL,
		0x8AFDF6B21221DA56ULL,
		0xA13A1B86D6F63AF8ULL,
		0x78E43BDE1EC418D8ULL,
		0xFBBC25775D45AA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E81AF2E925A6F1CULL,
		0xE07E1BC8B916A101ULL,
		0x4C60A57EB3866E5CULL,
		0x0339C39A582B398FULL,
		0xADF405F792089774ULL,
		0x289FBC542D86097AULL,
		0x59BBDD72DAE44974ULL,
		0xCDC275CC881CB25EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x822000808F0047FEULL,
		0x9AD4BE3B4F1BD3F6ULL,
		0x094EAF84463ADE9AULL,
		0xE05683FC3FFD0979ULL,
		0xDD09F0BA801942E2ULL,
		0x789A5F32A970317DULL,
		0x1F285E6B43DFCF64ULL,
		0x2DF9AFAAD528F7DAULL
	}};
	sign = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x718C9D2305DF55BFULL,
		0x78B3D29298363C32ULL,
		0x418D972F1091C662ULL,
		0xF56FDF17FDA81DAEULL,
		0x24959B7238E3A59CULL,
		0x34496C84182D422FULL,
		0x2BB2FA8B20014C76ULL,
		0x8954E1BA23810F52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1108F4F45D91B866ULL,
		0x21A917ED1B33A141ULL,
		0x0DECBF679BF0CADEULL,
		0x3A38ED71400FFBF2ULL,
		0x24A115BA307F1910ULL,
		0x3B172D5FF335EEBDULL,
		0x4EFF5D39ACE24167ULL,
		0x8B56D5CD0F626AC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6083A82EA84D9D59ULL,
		0x570ABAA57D029AF1ULL,
		0x33A0D7C774A0FB84ULL,
		0xBB36F1A6BD9821BCULL,
		0xFFF485B808648C8CULL,
		0xF9323F2424F75371ULL,
		0xDCB39D51731F0B0EULL,
		0xFDFE0BED141EA48DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63ED4D6D0611AA63ULL,
		0xB9609BC32AC156B3ULL,
		0x3AFC4450621D9314ULL,
		0xECC052648C78AC9AULL,
		0x93139BA59C0E86BCULL,
		0x6755706FE5CDA6F8ULL,
		0xF998B9BEA67E9BCBULL,
		0x9128CC7EA8CC24FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC67E56EDD2F8DB9AULL,
		0x1F648D44771AD5F2ULL,
		0x434F067C863E246DULL,
		0xA57838F4BD88A9F6ULL,
		0x2E430AB42E810278ULL,
		0xFCFB6B0ADCF69ADDULL,
		0x6666D9E207C1DFCFULL,
		0xF363AE324DFA4629ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D6EF67F3318CEC9ULL,
		0x99FC0E7EB3A680C0ULL,
		0xF7AD3DD3DBDF6EA7ULL,
		0x4748196FCEF002A3ULL,
		0x64D090F16D8D8444ULL,
		0x6A5A056508D70C1BULL,
		0x9331DFDC9EBCBBFBULL,
		0x9DC51E4C5AD1DED5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DA50F6DA35A22FAULL,
		0xAE22EB39B396567BULL,
		0xACC8F86C84A0BCDDULL,
		0x421C20C6BC641F8BULL,
		0x032BB68B0B378CF3ULL,
		0xB1C72F56D8C51BDFULL,
		0xD51AA1895EDC3CD0ULL,
		0xA910F189E593258AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF61EDF7B5C7EE3EULL,
		0x64F1B4CD7C86EDECULL,
		0x9EC867A0B2E8F332ULL,
		0x92F0842D686E38E6ULL,
		0x18858B8F67034161ULL,
		0xCFE8E3DF843119F5ULL,
		0x79EF6DA5ABE3A516ULL,
		0x93E0AEA10EDA92C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE432175ED9234BCULL,
		0x4931366C370F688EULL,
		0x0E0090CBD1B7C9ABULL,
		0xAF2B9C9953F5E6A5ULL,
		0xEAA62AFBA4344B91ULL,
		0xE1DE4B77549401E9ULL,
		0x5B2B33E3B2F897B9ULL,
		0x153042E8D6B892CAULL
	}};
	sign = 0;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B39BBC5B209BA47ULL,
		0xEB7E3F3CD304C978ULL,
		0x6E893BE54B0AF506ULL,
		0x591569AAE09C0EE3ULL,
		0x7DDE902B830945D0ULL,
		0xF12A4D229926A6CFULL,
		0x6C98746FC4301275ULL,
		0x34967CD20E447A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990DE1F16F61D21AULL,
		0x559F99DF7CF0284BULL,
		0x73C22F9910F6A1D5ULL,
		0x53E3B57EFA959222ULL,
		0x7CEDA62D94C05963ULL,
		0xF4BAF216C3A1A88BULL,
		0x743FD03F4553BC50ULL,
		0x651472CDF28B6EF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF22BD9D442A7E82DULL,
		0x95DEA55D5614A12CULL,
		0xFAC70C4C3A145331ULL,
		0x0531B42BE6067CC0ULL,
		0x00F0E9FDEE48EC6DULL,
		0xFC6F5B0BD584FE44ULL,
		0xF858A4307EDC5624ULL,
		0xCF820A041BB90B49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x673D091B7A0C1DBBULL,
		0xB806002744773778ULL,
		0x34FBF1C94BB2581CULL,
		0x185ACD5E125559C7ULL,
		0x427BA7FEA56DD89CULL,
		0xF71631F361102A30ULL,
		0x495A38BEDA20515DULL,
		0x2296C27736B624DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2814EE3A6B5B7A47ULL,
		0x353D7FEBAEE16732ULL,
		0xAA7204E216F20F91ULL,
		0x089F86A8FEC03788ULL,
		0xFD7B66351E1DE47DULL,
		0x81687AA3CE60B494ULL,
		0x31B2EE2A9B47AD4CULL,
		0x4A12A40FCE1BD821ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F281AE10EB0A374ULL,
		0x82C8803B9595D046ULL,
		0x8A89ECE734C0488BULL,
		0x0FBB46B51395223EULL,
		0x450041C9874FF41FULL,
		0x75ADB74F92AF759BULL,
		0x17A74A943ED8A411ULL,
		0xD8841E67689A4CBDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8B07405C93BEB0CULL,
		0xEFFA3629BFFC0688ULL,
		0xE3D1A98E18807A4AULL,
		0xB137E2CD6FC0AD85ULL,
		0x48DE344B962078D1ULL,
		0x959D63D7F93A2112ULL,
		0x3E1523E8BE80B2D8ULL,
		0x5CE74736706ADCC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9937C8E14B1EC0E5ULL,
		0x987CE9274A862554ULL,
		0x057696DEFA4B9884ULL,
		0x84269DAAF17F492AULL,
		0xF1603A8F6B6BEAAEULL,
		0xD3E9540F441075ECULL,
		0x86DD1F3878C17B3BULL,
		0x5053602F31D858C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F78AB247E1D2A27ULL,
		0x577D4D027575E134ULL,
		0xDE5B12AF1E34E1C6ULL,
		0x2D1145227E41645BULL,
		0x577DF9BC2AB48E23ULL,
		0xC1B40FC8B529AB25ULL,
		0xB73804B045BF379CULL,
		0x0C93E7073E928402ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08B56F5B98D01758ULL,
		0xAED7B4122E70DCB0ULL,
		0xC6EE81C6751CC681ULL,
		0x8A6B6FA6666A58F5ULL,
		0xC6C580AB705841ACULL,
		0x7D9A1DF6772A6B46ULL,
		0x758B1C5864B1D702ULL,
		0xB4456EFF46309DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EEEA55044FDFFAULL,
		0xE9D2D5B56B9CDCD0ULL,
		0xF32B705C930A868DULL,
		0x64000DFDC4ADD108ULL,
		0x35F6A05CB6F6460DULL,
		0xD6F84506017F171CULL,
		0x1799FD832B63EB73ULL,
		0x866CC49B234CDBBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35C685069480375EULL,
		0xC504DE5CC2D3FFDFULL,
		0xD3C31169E2123FF3ULL,
		0x266B61A8A1BC87ECULL,
		0x90CEE04EB961FB9FULL,
		0xA6A1D8F075AB542AULL,
		0x5DF11ED5394DEB8EULL,
		0x2DD8AA6422E3C227ULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F793CDBA120DD34ULL,
		0x7EB2A5E20D2F4FDCULL,
		0x4CEA7F8A85D29829ULL,
		0x23C6A746F7A617ACULL,
		0x69FEA71AEBEEC564ULL,
		0xE5F0A4CB60E4A162ULL,
		0x08B058D633B3AE62ULL,
		0x28BC485F73515708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11D2BABE1544D1A8ULL,
		0x71E4655D8403C5D0ULL,
		0x6C0DF56F04407195ULL,
		0xE93D406BB8BA08BEULL,
		0x5D2F7D2BAD1B9C65ULL,
		0xB2B3C8325317AEDCULL,
		0x89A23E83D4469511ULL,
		0x859F514616CD0435ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DA6821D8BDC0B8CULL,
		0x0CCE4084892B8A0CULL,
		0xE0DC8A1B81922694ULL,
		0x3A8966DB3EEC0EEDULL,
		0x0CCF29EF3ED328FEULL,
		0x333CDC990DCCF286ULL,
		0x7F0E1A525F6D1951ULL,
		0xA31CF7195C8452D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x519CB8F43EE3B561ULL,
		0xE8B12715A34CFA13ULL,
		0xC037723835804682ULL,
		0x9990A2F9D4D4C639ULL,
		0x0B0FE78A4CE67F12ULL,
		0xC696B70B789BD1FBULL,
		0xC657CF49FDD1186BULL,
		0x62F61F3D0F644D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D65B983B138142ULL,
		0x5F0C838393566EECULL,
		0xFBE5F23E54574BB2ULL,
		0xF57C84C9DF7AC8BCULL,
		0x453205D50CA65BE1ULL,
		0x3FC23B2C374429E6ULL,
		0xADC96B95AB41554DULL,
		0x8B92A2DBB8ECF387ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BC65D5C03D0341FULL,
		0x89A4A3920FF68B27ULL,
		0xC4517FF9E128FAD0ULL,
		0xA4141E2FF559FD7CULL,
		0xC5DDE1B540402330ULL,
		0x86D47BDF4157A814ULL,
		0x188E63B4528FC31EULL,
		0xD7637C6156775A14ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x766325AEA655DC31ULL,
		0x26F6667A78B6C071ULL,
		0x77B0F837705E5576ULL,
		0xE2DF400F89E9538CULL,
		0xC55E6EF25D07C031ULL,
		0xD604461E140FA215ULL,
		0x179586EC58BF70C6ULL,
		0x8A8CD9C0C57C804FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9D8A43F445D2D9ULL,
		0x1CE7DE1E2BEB1E1FULL,
		0x147C322D05F42B82ULL,
		0xD270795908F49F57ULL,
		0xE2BEDFFDE0DA53ACULL,
		0xEFC9CD33212E78CFULL,
		0xF5E04E12892BC5A0ULL,
		0x3E18E992F35602E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6C59B6AB2100958ULL,
		0x0A0E885C4CCBA251ULL,
		0x6334C60A6A6A29F4ULL,
		0x106EC6B680F4B435ULL,
		0xE29F8EF47C2D6C85ULL,
		0xE63A78EAF2E12945ULL,
		0x21B538D9CF93AB25ULL,
		0x4C73F02DD2267D69ULL
	}};
	sign = 0;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8A8160C7CBDFC5CULL,
		0xC393DF660DDA7CFFULL,
		0x881D996A531CC0DDULL,
		0x1AD8483B37A9109EULL,
		0x44B230BDDDFC49E9ULL,
		0x01DC87CFDBA39480ULL,
		0x09B88A8DB2B6D1FEULL,
		0x4094DB2ABF502949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58D9D4BB6A9151DCULL,
		0x117D7A773F7A98C0ULL,
		0xF90E0098CB45A727ULL,
		0x4F80A3CFC038DD70ULL,
		0xCCD1DA68D2641F67ULL,
		0x59E64E22D5D9A335ULL,
		0xDE1A21BFAE01BCD8ULL,
		0x3A3AC082993D1C98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FCE4151122CAA80ULL,
		0xB21664EECE5FE43FULL,
		0x8F0F98D187D719B6ULL,
		0xCB57A46B7770332DULL,
		0x77E056550B982A81ULL,
		0xA7F639AD05C9F14AULL,
		0x2B9E68CE04B51525ULL,
		0x065A1AA826130CB0ULL
	}};
	sign = 0;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC553F603F1B44819ULL,
		0xBE4D05FE0EF1DDD9ULL,
		0xC29396BDC6C1D862ULL,
		0xB263049C04720871ULL,
		0x846B3FB6FC5A8550ULL,
		0x47675F0E92BFF258ULL,
		0xE1DE7514DD6BF9A6ULL,
		0xF0306A85237235EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5D1DD27BB1819CULL,
		0xD07F279516E71777ULL,
		0xD4EB062E9841798BULL,
		0x5B6FABF14F404C63ULL,
		0x92254026B3FF32D6ULL,
		0x480C1C25CA5DCB67ULL,
		0x20126A884F106AA3ULL,
		0x72C470956DCAF8DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88F6D8317602C67DULL,
		0xEDCDDE68F80AC662ULL,
		0xEDA8908F2E805ED6ULL,
		0x56F358AAB531BC0DULL,
		0xF245FF90485B527AULL,
		0xFF5B42E8C86226F0ULL,
		0xC1CC0A8C8E5B8F02ULL,
		0x7D6BF9EFB5A73D12ULL
	}};
	sign = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9997C767F75828B3ULL,
		0x9F66B932FDE0117BULL,
		0x9355872B79BE0B13ULL,
		0x71756B36634DA0C1ULL,
		0x322F9B36C160DE57ULL,
		0xD0C2ECBC99368C05ULL,
		0x9EC5B4C63C853B89ULL,
		0x581AA5CB1DF9CE72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B02EBBE4C60E0D0ULL,
		0x839DA2426CAA639BULL,
		0xE2E48E80C964E386ULL,
		0x4109320215CC1B6EULL,
		0xC926F8DC8D0CE03EULL,
		0x9C62010FE64CC862ULL,
		0x2D6C84DB5AA2506DULL,
		0xD5654FE18F3DD0F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E94DBA9AAF747E3ULL,
		0x1BC916F09135ADE0ULL,
		0xB070F8AAB059278DULL,
		0x306C39344D818552ULL,
		0x6908A25A3453FE19ULL,
		0x3460EBACB2E9C3A2ULL,
		0x71592FEAE1E2EB1CULL,
		0x82B555E98EBBFD7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CA87E195399F3DDULL,
		0xBC90276FCF960E73ULL,
		0x4A33290F0D0ECBCCULL,
		0x3B1A9AFB358EDAC1ULL,
		0xC264CBFEB6931971ULL,
		0x0EEBC5B8E3CC25D3ULL,
		0xEBF44D3FF2EABD70ULL,
		0x989978E6D9036D67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BBCED6F35C60680ULL,
		0x020EEEE48B952AF3ULL,
		0x850EF1ADA6EFFD7AULL,
		0x923ADDDD472BEB49ULL,
		0x2093D9E286D4A53BULL,
		0xB604BFCFEE12D9E1ULL,
		0x1382F240409042D9ULL,
		0xC354F264A928E56BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70EB90AA1DD3ED5DULL,
		0xBA81388B4400E380ULL,
		0xC5243761661ECE52ULL,
		0xA8DFBD1DEE62EF77ULL,
		0xA1D0F21C2FBE7435ULL,
		0x58E705E8F5B94BF2ULL,
		0xD8715AFFB25A7A96ULL,
		0xD54486822FDA87FCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA39289D88E07BF80ULL,
		0xB6023A3ED7898596ULL,
		0x062F9782E3A69F93ULL,
		0x7E379B385939235AULL,
		0x451470A7280971F7ULL,
		0xCF6570C5FEA25535ULL,
		0xC837013DD95FF028ULL,
		0xC660AC0898FA5DE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC797527905CC4A5ULL,
		0x9369FBE5E83EA1D4ULL,
		0x7FD4256803E2756DULL,
		0xF8A333FAF2E40A82ULL,
		0x8DF0667B92F94999ULL,
		0xE285EBEAB1308E4FULL,
		0xFF84444E4970E120ULL,
		0xAC3ED19A7227BFFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB71914B0FDAAFADBULL,
		0x22983E58EF4AE3C1ULL,
		0x865B721ADFC42A26ULL,
		0x8594673D665518D7ULL,
		0xB7240A2B9510285DULL,
		0xECDF84DB4D71C6E5ULL,
		0xC8B2BCEF8FEF0F07ULL,
		0x1A21DA6E26D29DEDULL
	}};
	sign = 0;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9DDCAF1278E5C85ULL,
		0x7C402EE5CC147EADULL,
		0xBD9232FB58B94470ULL,
		0x205D1474D9B550ECULL,
		0x248C59DDAD21D7F0ULL,
		0x08217C82F7485019ULL,
		0xC3DC9BDBE7D08F55ULL,
		0x9F94593A9CEBF416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A60BCDB6F679F3ULL,
		0xE792179A13830DAFULL,
		0x86D4B7D82D5D7A7DULL,
		0x46E85C581878CE23ULL,
		0x299C86ADE661EEAAULL,
		0xE21E286DCA3BAE89ULL,
		0xDDCC9CB0AF6C9190ULL,
		0x7060E4DED998FE7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5637BF237097E292ULL,
		0x94AE174BB89170FEULL,
		0x36BD7B232B5BC9F2ULL,
		0xD974B81CC13C82C9ULL,
		0xFAEFD32FC6BFE945ULL,
		0x260354152D0CA18FULL,
		0xE60FFF2B3863FDC4ULL,
		0x2F33745BC352F597ULL
	}};
	sign = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x402BDEDDE88BC686ULL,
		0xCB441BD1B9B0C60BULL,
		0x073AF86955EDB857ULL,
		0xDF7D8832CC8CDFB2ULL,
		0xC3C549E85D767E8EULL,
		0x38F486022DCBC39BULL,
		0x9D94287DA3C85CF0ULL,
		0x7F3FA85B3995A5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0FD64F17028B1DULL,
		0xF878FD9E9CCCF253ULL,
		0xE6B38732232FFA36ULL,
		0xF6A19C23B464F97BULL,
		0x8197F47526581469ULL,
		0xAAAD49DDF37AE0AEULL,
		0x8B96A19AC9657552ULL,
		0xA5F48D864D310738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261C088ED1893B69ULL,
		0xD2CB1E331CE3D3B8ULL,
		0x2087713732BDBE20ULL,
		0xE8DBEC0F1827E636ULL,
		0x422D5573371E6A24ULL,
		0x8E473C243A50E2EDULL,
		0x11FD86E2DA62E79DULL,
		0xD94B1AD4EC649EC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8911632EBB4BC085ULL,
		0x2F043CD886D91B94ULL,
		0xEAE345E4509BAD3DULL,
		0x3DDD578B3E520B3EULL,
		0x77610A5FD38B7986ULL,
		0xED652B19E9C97F9FULL,
		0x8E9792E2E16D9640ULL,
		0x6AFD595F07FF6A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2970AFD93DAFADB0ULL,
		0xE526B18FDB9C4C6AULL,
		0xAB1C9BC5FAA3E499ULL,
		0xE2EAF156CD3355E5ULL,
		0x456C0D260C971CCEULL,
		0x9DC6E6E596C7140BULL,
		0x62F1A6F1C6CDE92DULL,
		0x815479DE03A61333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FA0B3557D9C12D5ULL,
		0x49DD8B48AB3CCF2AULL,
		0x3FC6AA1E55F7C8A3ULL,
		0x5AF26634711EB559ULL,
		0x31F4FD39C6F45CB7ULL,
		0x4F9E443453026B94ULL,
		0x2BA5EBF11A9FAD13ULL,
		0xE9A8DF8104595739ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD607864B0FF91422ULL,
		0xAA64F3E84C527772ULL,
		0x62341E734FE57C27ULL,
		0xDF72DB356297472EULL,
		0xE475C927FE2287DBULL,
		0x89CBA264ABCFD4EAULL,
		0xE57D5FC3A2B0DDB5ULL,
		0x7D6DDF01DE8ABB95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209712ABA3CFEF93ULL,
		0x67B7EB57571D1526ULL,
		0xE0AB58E5749D42DFULL,
		0x19168331687EBFE5ULL,
		0xE637C59551B4EC3FULL,
		0x7B10A25004DD00B0ULL,
		0xAB5AA09B37A9F73FULL,
		0xCA48DBF9C2EC5751ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB570739F6C29248FULL,
		0x42AD0890F535624CULL,
		0x8188C58DDB483948ULL,
		0xC65C5803FA188748ULL,
		0xFE3E0392AC6D9B9CULL,
		0x0EBB0014A6F2D439ULL,
		0x3A22BF286B06E676ULL,
		0xB32503081B9E6444ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x237D289B11019B0BULL,
		0x6E2622F2D989CB24ULL,
		0xD4C918FA115172ACULL,
		0xBE78CBD0E6CF13F2ULL,
		0x49CD5AE5B2426DE2ULL,
		0x1F2987639E51624FULL,
		0x299B090BD0D2D64EULL,
		0x26CAA77E2386DE33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x523DFD5CCD23B09FULL,
		0xDC59347DA48C5131ULL,
		0x3ED0822E15ED7AA3ULL,
		0x4419A9420504B68BULL,
		0x08C3B73FC344AF4AULL,
		0xC1594C90A340DFDBULL,
		0x3D6FC4BAB289728DULL,
		0x679F1D6A9C06EC68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD13F2B3E43DDEA6CULL,
		0x91CCEE7534FD79F2ULL,
		0x95F896CBFB63F808ULL,
		0x7A5F228EE1CA5D67ULL,
		0x4109A3A5EEFDBE98ULL,
		0x5DD03AD2FB108274ULL,
		0xEC2B44511E4963C0ULL,
		0xBF2B8A13877FF1CAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF255E76133A0BDCULL,
		0x511B8DEC0E4D6261ULL,
		0xF3907D8391712261ULL,
		0xE1E81BB2C2D914C2ULL,
		0x97280750C915A30FULL,
		0x5CBAF65DA2FA9C87ULL,
		0x4AEA7E14496FBAB6ULL,
		0x7C36C7BD19632A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B60CC26967A2D0ULL,
		0x0A195D3797FAB07AULL,
		0x5425EE941BB1D1DBULL,
		0x922DED55D379BB13ULL,
		0xD08741A7293D7D51ULL,
		0xF8D123D9A269DCDDULL,
		0xB157D8165FD42496ULL,
		0x84D74D5A9F3819D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD6F51B3A9D2690CULL,
		0x470230B47652B1E7ULL,
		0x9F6A8EEF75BF5086ULL,
		0x4FBA2E5CEF5F59AFULL,
		0xC6A0C5A99FD825BEULL,
		0x63E9D2840090BFA9ULL,
		0x9992A5FDE99B961FULL,
		0xF75F7A627A2B10CBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB855D9329F646ADULL,
		0x8A7711A48FE1A147ULL,
		0x63C71B863E4BF970ULL,
		0x0AD8552083CE5718ULL,
		0xEB47F47C59189C94ULL,
		0x131968A57A48E874ULL,
		0x329A39507ECB22ADULL,
		0x1C71CD75FB048C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD6602D3C717E67ULL,
		0x539C32A691EDD5F3ULL,
		0xBF7088CEABF78DA2ULL,
		0xB901440389E0006EULL,
		0x43621CDD046605ADULL,
		0x775BC9CBD399D167ULL,
		0x5B0203343EBC110FULL,
		0x3B726DC7E6810304ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEAEFD65ED84C846ULL,
		0x36DADEFDFDF3CB54ULL,
		0xA45692B792546BCEULL,
		0x51D7111CF9EE56A9ULL,
		0xA7E5D79F54B296E6ULL,
		0x9BBD9ED9A6AF170DULL,
		0xD798361C400F119DULL,
		0xE0FF5FAE14838923ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EFDC8EBE6C85183ULL,
		0xB467A2F23B487EFFULL,
		0x401984D99C72265AULL,
		0x901D070041A3A0DCULL,
		0x73142F31828B926AULL,
		0x6C9C8CA105805C51ULL,
		0xF65F902E6E9E8736ULL,
		0x62DD74346178C2F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E83CC3223A0FE7ULL,
		0x0B65813CFD54CEF2ULL,
		0xC86BC47E182C5D85ULL,
		0x508D930014FC183FULL,
		0xFBAD425C459495A6ULL,
		0x5BFA7979CDED1E2DULL,
		0x4EA50F31A9D2E15AULL,
		0x9F09DCA19BA05339ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE158C28C48E419CULL,
		0xA90221B53DF3B00CULL,
		0x77ADC05B8445C8D5ULL,
		0x3F8F74002CA7889CULL,
		0x7766ECD53CF6FCC4ULL,
		0x10A2132737933E23ULL,
		0xA7BA80FCC4CBA5DCULL,
		0xC3D39792C5D86FB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1BD9A0CC899C3F5ULL,
		0x8668F7CA093110D6ULL,
		0xE226D2240C52AC37ULL,
		0x245C7B9B4E648BDAULL,
		0x24261169872B4166ULL,
		0xC27CCECE6D015A78ULL,
		0xB09DACEF71FB1AB6ULL,
		0x3CC236AE2354D52EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x883F23E34BA875D1ULL,
		0x3B75997813607896ULL,
		0xBDB0002595AD161CULL,
		0x3E5781021AEFF09FULL,
		0x42E1C0E0CBB9DA89ULL,
		0xAD7D500A73726385ULL,
		0x8CFF97369F170BE8ULL,
		0x5EEB31F0F5280FD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x497E76297CF14E24ULL,
		0x4AF35E51F5D09840ULL,
		0x2476D1FE76A5961BULL,
		0xE604FA9933749B3BULL,
		0xE1445088BB7166DCULL,
		0x14FF7EC3F98EF6F2ULL,
		0x239E15B8D2E40ECEULL,
		0xDDD704BD2E2CC559ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0BC6BD73D6606B0ULL,
		0xDC3E20478ED4C255ULL,
		0x29B73853CCEF78EEULL,
		0x0346E1FEB98ADAFCULL,
		0x52DCC7D2C40B4F62ULL,
		0x79A7D383615F7197ULL,
		0xD9801AD77F4168F4ULL,
		0xC295F7D617AC4E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4C1E2910ECDB5A0ULL,
		0x5B2247EF30EF1CF0ULL,
		0x3A4112671D63E3A9ULL,
		0x89B5A2B0FD3F70C9ULL,
		0xE5BED021A76943AFULL,
		0xC76EE9C5959FB69AULL,
		0xB7774909D9758556ULL,
		0xB4B29423F57C750CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBFA89462E985110ULL,
		0x811BD8585DE5A564ULL,
		0xEF7625ECAF8B9545ULL,
		0x79913F4DBC4B6A32ULL,
		0x6D1DF7B11CA20BB2ULL,
		0xB238E9BDCBBFBAFCULL,
		0x2208D1CDA5CBE39DULL,
		0x0DE363B2222FD922ULL
	}};
	sign = 0;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15405030E5E95961ULL,
		0x90AE30356E546982ULL,
		0xD16097C449EB7FF8ULL,
		0x407A4FB30E225921ULL,
		0x39208EFEAE76EE81ULL,
		0x2F0261D65E2C8311ULL,
		0x59811A2A6A787423ULL,
		0xE54658B7EE2E2D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92145F6D6BEF4215ULL,
		0x7102C7430ACD44FAULL,
		0x8DE17AEED75D4A27ULL,
		0x0640C97C04151821ULL,
		0xA4D543C0C53218C7ULL,
		0x8B08E14E4DF06609ULL,
		0x6DFF648C7B362EC8ULL,
		0x6E1416649F534337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x832BF0C379FA174CULL,
		0x1FAB68F263872487ULL,
		0x437F1CD5728E35D1ULL,
		0x3A3986370A0D4100ULL,
		0x944B4B3DE944D5BAULL,
		0xA3F98088103C1D07ULL,
		0xEB81B59DEF42455AULL,
		0x773242534EDAEA08ULL
	}};
	sign = 0;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AD8DACE2771002FULL,
		0x61E2329D8B33EC07ULL,
		0x1C28F7D41B0FA54CULL,
		0x8813D86D470B3F87ULL,
		0x9FA0F6C84A17D4D4ULL,
		0x66BC35810C20F31AULL,
		0xE1D66D58552A98AEULL,
		0xB77FE81B89B0450CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B71A6CCE5A3138EULL,
		0x45EA6E0A61E72F5BULL,
		0x5FC44B819179029CULL,
		0x1FCD4224A57D302FULL,
		0xBE97654B02037FA1ULL,
		0xBDD3956155AEAE34ULL,
		0x5A50E43842FDB44DULL,
		0x98A8DB70CE1B7278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F67340141CDECA1ULL,
		0x1BF7C493294CBCACULL,
		0xBC64AC528996A2B0ULL,
		0x68469648A18E0F57ULL,
		0xE109917D48145533ULL,
		0xA8E8A01FB67244E5ULL,
		0x87858920122CE460ULL,
		0x1ED70CAABB94D294ULL
	}};
	sign = 0;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x621CC0CF89CB533FULL,
		0x71BCFF36B77E5CC0ULL,
		0xB43BAEFD228F5263ULL,
		0x579375C10509F9B3ULL,
		0xA2ECF583B30215DEULL,
		0x840935014DEB3234ULL,
		0x8EE576C37584FC07ULL,
		0x129865677F6ABBB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C541D644FDFA51ULL,
		0x5CC5F2C9EA7000F0ULL,
		0xA93E5204BEB77611ULL,
		0x8C9F3F8C55D40DCAULL,
		0xBD3CC7651D9DAB57ULL,
		0x68809B7159206008ULL,
		0xE981F9861CB46D8CULL,
		0x378698C1681A642BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90577EF944CD58EEULL,
		0x14F70C6CCD0E5BCFULL,
		0x0AFD5CF863D7DC52ULL,
		0xCAF43634AF35EBE9ULL,
		0xE5B02E1E95646A86ULL,
		0x1B88998FF4CAD22BULL,
		0xA5637D3D58D08E7BULL,
		0xDB11CCA617505784ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D82F9686207DAF4ULL,
		0x9326CE8AA6791FD1ULL,
		0x07A6A4675E249358ULL,
		0xF3BAD668E009E739ULL,
		0x0531497C14F20847ULL,
		0xF4874D7D108C7CDBULL,
		0xADAE0B1A9B4D8484ULL,
		0x94E08BF56DB2CF99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07F2591966481F4ULL,
		0x164BFD507FF1B3B6ULL,
		0x257C3DAC54525021ULL,
		0xBEC83F55C5C25224ULL,
		0x2E02BF9D2F64CA59ULL,
		0x2C81A4A0BE7639D1ULL,
		0x70943065160F7D0BULL,
		0x0F0B4FCFC477E071ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D03D3D6CBA35900ULL,
		0x7CDAD13A26876C1AULL,
		0xE22A66BB09D24337ULL,
		0x34F297131A479514ULL,
		0xD72E89DEE58D3DEEULL,
		0xC805A8DC52164309ULL,
		0x3D19DAB5853E0779ULL,
		0x85D53C25A93AEF28ULL
	}};
	sign = 0;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43426C0F46DFB191ULL,
		0x215D68D9AB7D19DEULL,
		0xC658578E071848C2ULL,
		0xEE6EBED9246CF152ULL,
		0xE60A453D80BA93D8ULL,
		0x1949EAA64D7E0E31ULL,
		0xE6AD7782D22BB302ULL,
		0xD93BF2EFEBADDB67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B27B3E2DE4281BAULL,
		0x59C07F94EADEC175ULL,
		0xF118CB1287D5B1FAULL,
		0xD22AA086D03291EFULL,
		0x3E85DB955496B7C9ULL,
		0xEC21B5A2B27F8460ULL,
		0xEBFFC4EE18ACF364ULL,
		0x9E1BC05DCAD35974ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE81AB82C689D2FD7ULL,
		0xC79CE944C09E5868ULL,
		0xD53F8C7B7F4296C7ULL,
		0x1C441E52543A5F62ULL,
		0xA78469A82C23DC0FULL,
		0x2D2835039AFE89D1ULL,
		0xFAADB294B97EBF9DULL,
		0x3B20329220DA81F2ULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D67ADCE4B473B06ULL,
		0x466657315CA55B5EULL,
		0xE1C5D49D00437097ULL,
		0xFA802CB55246665FULL,
		0xF8F05D9E6671529FULL,
		0xFD07C0417FFEA0D7ULL,
		0x0D671F833028E67FULL,
		0x1E3C267D734551CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1390DA243CD91995ULL,
		0x65112B5FCC6073B9ULL,
		0xD15DE0A69C5D04FEULL,
		0xBA6B514EFBCF3C54ULL,
		0x1E65070683A97CBCULL,
		0x8114C71507133DF8ULL,
		0x678AC1ABA4537274ULL,
		0x37766701165555C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9D6D3AA0E6E2171ULL,
		0xE1552BD19044E7A4ULL,
		0x1067F3F663E66B98ULL,
		0x4014DB6656772A0BULL,
		0xDA8B5697E2C7D5E3ULL,
		0x7BF2F92C78EB62DFULL,
		0xA5DC5DD78BD5740BULL,
		0xE6C5BF7C5CEFFC0AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70A29650E567C03BULL,
		0xC538D3AA9624EA86ULL,
		0xDA0AB47B5ED3598FULL,
		0xBC1516CD0A6B83C7ULL,
		0xD23595A2AEDCA21EULL,
		0xD6C80EA1DD940D90ULL,
		0xD0FCB0A1B1E33A12ULL,
		0xBAFC2A69CAD6C04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A99BBEB68BB8698ULL,
		0x9A9FC70A04EC91FDULL,
		0x9F2FEF89F9364593ULL,
		0x8F2744B683D8B2A4ULL,
		0x8E99FC4D57D38F9DULL,
		0xDB843B8949C80AA0ULL,
		0x7D58292DD1A1695DULL,
		0x8C4D99FC9AEAF602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2608DA657CAC39A3ULL,
		0x2A990CA091385889ULL,
		0x3ADAC4F1659D13FCULL,
		0x2CEDD2168692D123ULL,
		0x439B995557091281ULL,
		0xFB43D31893CC02F0ULL,
		0x53A48773E041D0B4ULL,
		0x2EAE906D2FEBCA4BULL
	}};
	sign = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0009102309E9685ULL,
		0xC799B99BA07D5902ULL,
		0x8D3AAE5E7E063DBDULL,
		0x4BD7B6C0B222B9B6ULL,
		0x368FA6FB0DFB15A1ULL,
		0x8F9ED4D9909E4D41ULL,
		0x5B09C2CD371B7FF9ULL,
		0xC6471538A4090701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51240C4AA9364B7ULL,
		0xD02CDC2BF75468D6ULL,
		0x895DB20672706F3CULL,
		0xD8B1C6F6D7AD5CFFULL,
		0x47F94E4A72279425ULL,
		0x939F3D09395AF072ULL,
		0x50BAA508A64F0807ULL,
		0x8D734AE14A6E4E77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AEE503D860B31CEULL,
		0xF76CDD6FA928F02CULL,
		0x03DCFC580B95CE80ULL,
		0x7325EFC9DA755CB7ULL,
		0xEE9658B09BD3817BULL,
		0xFBFF97D057435CCEULL,
		0x0A4F1DC490CC77F1ULL,
		0x38D3CA57599AB88AULL
	}};
	sign = 0;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x264939B38E2349BBULL,
		0x5301325A7FF05CEEULL,
		0x1FEBE1F92C0173C6ULL,
		0x9834E6455B113448ULL,
		0x5C34A4739C3F9BFBULL,
		0xA162DA379D788590ULL,
		0xED96C4A7E0766F24ULL,
		0xD09B57826C958F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6599BCC19BA4EDDULL,
		0x709C39FC651C6F95ULL,
		0x6776F1752249968FULL,
		0xDED524846F74ABB7ULL,
		0xAA0CD6B4E4B1F864ULL,
		0xA44188CEA0F55C2DULL,
		0x6A2CC9FF75008236ULL,
		0x159FFD4C456A54CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FEF9DE77468FADEULL,
		0xE264F85E1AD3ED58ULL,
		0xB874F08409B7DD36ULL,
		0xB95FC1C0EB9C8890ULL,
		0xB227CDBEB78DA396ULL,
		0xFD215168FC832962ULL,
		0x8369FAA86B75ECEDULL,
		0xBAFB5A36272B3A8CULL
	}};
	sign = 0;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF55B24F14FDA986ULL,
		0x0E10D80ACBEC98B7ULL,
		0xD45873D414D9C570ULL,
		0x782F4ED132131DB4ULL,
		0xAB7E76A6D282F410ULL,
		0x8E10EB6D22262480ULL,
		0x151CA9300ACA7ED4ULL,
		0x5D9A85332216B1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4AD42C274A856BULL,
		0xF3F46B3C3402FC32ULL,
		0x0F928A88C574DABCULL,
		0x2629826A68269C49ULL,
		0x1802789A898A9A9FULL,
		0xD8E21C5142E593D7ULL,
		0xCA7B3101E5F1CDC0ULL,
		0xF781B9AF5CAA699DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050ADE22EDB3241BULL,
		0x1A1C6CCE97E99C85ULL,
		0xC4C5E94B4F64EAB3ULL,
		0x5205CC66C9EC816BULL,
		0x937BFE0C48F85971ULL,
		0xB52ECF1BDF4090A9ULL,
		0x4AA1782E24D8B113ULL,
		0x6618CB83C56C4827ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD00B80A704E542EULL,
		0xA06ECF32FA1F7451ULL,
		0x92F58EE5F6D1ADCAULL,
		0xF1FFCAFE37AF6C90ULL,
		0xC0EF00C3C83AE165ULL,
		0x68A1AFFF22D2078EULL,
		0x96E9E807499D5F76ULL,
		0x248B7C27A563C1AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE209A184BAFB292DULL,
		0xC5B10A974D40E91DULL,
		0x6F3E10C4F2AEC17FULL,
		0x8C1F061B9EFE59CBULL,
		0x4FB58C8D170F3CB5ULL,
		0x8C470D5989528E25ULL,
		0x1DEBA17979513C8CULL,
		0xBD96D08A921CE084ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAF71685B5532B01ULL,
		0xDABDC49BACDE8B33ULL,
		0x23B77E210422EC4AULL,
		0x65E0C4E298B112C5ULL,
		0x71397436B12BA4B0ULL,
		0xDC5AA2A5997F7969ULL,
		0x78FE468DD04C22E9ULL,
		0x66F4AB9D1346E12AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBB600784F8D338CULL,
		0x97DD61EF453F5C82ULL,
		0x82A8B45368C49C21ULL,
		0xBC5B352DA74DD958ULL,
		0x946FAF6AD32FBCDBULL,
		0x444861A1C86D5B62ULL,
		0x65E3932CB5ABB8E3ULL,
		0x70F68C1735607A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778B69FF997D9043ULL,
		0x1CF1095B5C3A792AULL,
		0x3207DD960AC14D35ULL,
		0x6D14A1B1249E24F4ULL,
		0x677092C09256CC8BULL,
		0x07C185984507C824ULL,
		0xC97E6BA924A0A136ULL,
		0xD6B7054F247F5E45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x642A9678B60FA349ULL,
		0x7AEC5893E904E358ULL,
		0x50A0D6BD5E034EECULL,
		0x4F46937C82AFB464ULL,
		0x2CFF1CAA40D8F050ULL,
		0x3C86DC098365933EULL,
		0x9C652783910B17ADULL,
		0x9A3F86C810E11C12ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B186A329D932ACULL,
		0x21B0E0E3B45BBF2EULL,
		0x318CFB00B1819AF6ULL,
		0xC57D43A475079356ULL,
		0x33D18A6764FB13E5ULL,
		0xECCF6CB683EE3724ULL,
		0xF84E291FA52471C4ULL,
		0xDCE123A38AD7B1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D22B8ACAA2B4A7CULL,
		0x52DB15335FB7F3AEULL,
		0xE44643FC4068256CULL,
		0xE6BA72AE9C327B23ULL,
		0xDF193B64538CE1C6ULL,
		0x154A928150FC7B29ULL,
		0x6FA14C0F34F69BECULL,
		0xA29B1D3F4D49D5E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE38ECDF67FADE830ULL,
		0xCED5CBB054A3CB7FULL,
		0x4D46B70471197589ULL,
		0xDEC2D0F5D8D51832ULL,
		0x54B84F03116E321EULL,
		0xD784DA3532F1BBFAULL,
		0x88ACDD10702DD5D8ULL,
		0x3A4606643D8DDBCAULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0FBF05F603A6C80ULL,
		0x320F261DB4F64775ULL,
		0x80CFC141030E2B1CULL,
		0xD8E0C5E32416F45BULL,
		0x51FB81698E388E32ULL,
		0x0880B6EA188244A2ULL,
		0x8C8252A0A7B429EDULL,
		0x1311ADCBAD19C969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DF683EF2CDCDBC2ULL,
		0xF73F2605AE394F25ULL,
		0x9B86C60E385894F6ULL,
		0x3254DE3BF84D6950ULL,
		0x4D1BA2709131B88CULL,
		0x00D922AB55B3BA07ULL,
		0x6F5889A44952E000ULL,
		0xC9FDFB6174EDA37CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3056C70335D90BEULL,
		0x3AD0001806BCF850ULL,
		0xE548FB32CAB59625ULL,
		0xA68BE7A72BC98B0AULL,
		0x04DFDEF8FD06D5A6ULL,
		0x07A7943EC2CE8A9BULL,
		0x1D29C8FC5E6149EDULL,
		0x4913B26A382C25EDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C6536614E8750BAULL,
		0x77D199F39F316456ULL,
		0xEE30B4BD77A147EEULL,
		0x7AEA378BDA29A69CULL,
		0xC8EABC4132A23AFFULL,
		0xC2FCA0B7808FDEBCULL,
		0x25377DDFD4AA23C2ULL,
		0x65DFFD08AAF85E86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504BF6684CEE3A2BULL,
		0xB73ECD82581896FAULL,
		0xBEA220D80C0CE2B9ULL,
		0x7C9AF4A383E0A93CULL,
		0x1F641891A522599DULL,
		0x5713505EBA9F074DULL,
		0xF400448780F0B516ULL,
		0x1976FBCD2F0A5274ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC193FF90199168FULL,
		0xC092CC714718CD5BULL,
		0x2F8E93E56B946534ULL,
		0xFE4F42E85648FD60ULL,
		0xA986A3AF8D7FE161ULL,
		0x6BE95058C5F0D76FULL,
		0x3137395853B96EACULL,
		0x4C69013B7BEE0C11ULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x250A7E6C1E80BF11ULL,
		0x8B091BE313DE5B9BULL,
		0xFC4FEAA71FDB5A10ULL,
		0x06CA877B7350AB21ULL,
		0x8E44CAFE22D6E0BCULL,
		0x4285CD24887F35E1ULL,
		0x18FB9EBE07777842ULL,
		0x10BC94379A558E44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BFB88607081B39ULL,
		0xD45FBE55EF34ADB5ULL,
		0x689CDA896A6F44BAULL,
		0x1793EA10C7955A75ULL,
		0xC419C39F054607EFULL,
		0x5B94F9AB8213BD44ULL,
		0x0D7736793D23414DULL,
		0x087C59145EC4BE52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504AC5E61778A3D8ULL,
		0xB6A95D8D24A9ADE5ULL,
		0x93B3101DB56C1555ULL,
		0xEF369D6AABBB50ACULL,
		0xCA2B075F1D90D8CCULL,
		0xE6F0D379066B789CULL,
		0x0B846844CA5436F4ULL,
		0x08403B233B90CFF2ULL
	}};
	sign = 0;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x319CD1377C446CA0ULL,
		0x73FB162885D62F77ULL,
		0xEFCE507D201E47DDULL,
		0x935FCBCB43DA4E99ULL,
		0x31C7AFC11EE5B370ULL,
		0xDFE6D019442F8E9FULL,
		0x08559A4E06DDFF7DULL,
		0x0837B37ABC6DB2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B3B53A3A551248ULL,
		0xEB2D3218286B077AULL,
		0xB4D9FC17C50B0453ULL,
		0x6B3ECD03EE344946ULL,
		0x9DE0E3E0FBBA0631ULL,
		0xD6DC120B9BA95200ULL,
		0xA40ACEFB8CA3C72EULL,
		0xE3E362F9F3F6A015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCE91BFD41EF5A58ULL,
		0x88CDE4105D6B27FCULL,
		0x3AF454655B134389ULL,
		0x2820FEC755A60553ULL,
		0x93E6CBE0232BAD3FULL,
		0x090ABE0DA8863C9EULL,
		0x644ACB527A3A384FULL,
		0x24545080C87712A9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25C6939CA1B4F887ULL,
		0xDD3B333427ADC05FULL,
		0x046B054CD5138975ULL,
		0x4953D08B93CFBDC2ULL,
		0x6116BA15D9C3FAFAULL,
		0xFE28C0F6E7F9B97CULL,
		0x4B36735FF68BA716ULL,
		0x0F8DE2DB904F14B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A1092F67A4D3CDFULL,
		0x7DBFF2E49714FAA1ULL,
		0x0E975040A21618DCULL,
		0xC60D80484FB63050ULL,
		0x9962B4B04F38D9BCULL,
		0x644293025198AF5BULL,
		0xA3A6B6A5F37C8692ULL,
		0x9D5E8F9B0046825FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BB600A62767BBA8ULL,
		0x5F7B404F9098C5BEULL,
		0xF5D3B50C32FD7099ULL,
		0x8346504344198D71ULL,
		0xC7B405658A8B213DULL,
		0x99E62DF496610A20ULL,
		0xA78FBCBA030F2084ULL,
		0x722F534090089255ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19F7EDD99BD2AC48ULL,
		0x5A9907FBBBBA86DAULL,
		0xBD6E45CD2574582CULL,
		0x18734DFFCA31B41FULL,
		0x80ED4E1590739980ULL,
		0xD33F0389F67D3A07ULL,
		0x2D9C7E918AA8529FULL,
		0x40B2D911426A36C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810A5FB22D0E0BA2ULL,
		0x87BD67593669C614ULL,
		0x71ADF8C96D9DFBE5ULL,
		0xC5C10C8CB7B33ADCULL,
		0x1C043B7B3448CCF7ULL,
		0xFB70F1197E053B00ULL,
		0xDA754E13AC406EDEULL,
		0x3CB258FBE578F706ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98ED8E276EC4A0A6ULL,
		0xD2DBA0A28550C0C5ULL,
		0x4BC04D03B7D65C46ULL,
		0x52B24173127E7943ULL,
		0x64E9129A5C2ACC88ULL,
		0xD7CE12707877FF07ULL,
		0x5327307DDE67E3C0ULL,
		0x040080155CF13FBEULL
	}};
	sign = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E77092BED91144BULL,
		0xCD6330F3B57889A6ULL,
		0x68274E7286FE308BULL,
		0x1FA5EC4CFF6F027AULL,
		0x034D1A7A8A372580ULL,
		0x3239BF10653D023BULL,
		0x0B89D09D7FCF1E0AULL,
		0x9E9CEBE7D8655CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B8B3E0E06988EFULL,
		0x4BA37116527B0F8AULL,
		0xA2833CBEEA87BD8BULL,
		0xCB71F56DC05D5704ULL,
		0x5FE7F052D61CF7F8ULL,
		0xF88FF11894738BDEULL,
		0xFB034A73C50C7E0DULL,
		0x2075DE725408CBA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DBE554B0D278B5CULL,
		0x81BFBFDD62FD7A1BULL,
		0xC5A411B39C767300ULL,
		0x5433F6DF3F11AB75ULL,
		0xA3652A27B41A2D87ULL,
		0x39A9CDF7D0C9765CULL,
		0x10868629BAC29FFCULL,
		0x7E270D75845C9138ULL
	}};
	sign = 0;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x022F555BC38122F3ULL,
		0x852543762DF033A4ULL,
		0xAC685189E9FBEE1DULL,
		0x27EAA369D5B397CDULL,
		0x24E3B39C029249ECULL,
		0xC2A5711E00F22668ULL,
		0x3F4432AB57F263D2ULL,
		0x596ACE63FF3F00FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC5F77281D833CAULL,
		0xDF9A77146043BD2DULL,
		0x8E27E1401E3817BAULL,
		0x3C6897DB6394C65BULL,
		0xE6211242646ED964ULL,
		0x4637B2BF76DE05C7ULL,
		0xE37BFC059D79D5BEULL,
		0x687044BB20E7B946ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23695DE941A8EF29ULL,
		0xA58ACC61CDAC7676ULL,
		0x1E407049CBC3D662ULL,
		0xEB820B8E721ED172ULL,
		0x3EC2A1599E237087ULL,
		0x7C6DBE5E8A1420A0ULL,
		0x5BC836A5BA788E14ULL,
		0xF0FA89A8DE5747B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC74189CF465B82A5ULL,
		0xC04BD0E8CA9E9801ULL,
		0xB189BF4009990D26ULL,
		0xCB2ABF1C3FD5A990ULL,
		0x97099DBB7E980C60ULL,
		0x5088CC8CC32B34F8ULL,
		0xB6F0DB15BCC3F11DULL,
		0xF1C6E37F86494EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B8A2F953794D01AULL,
		0x1103B03093BA1034ULL,
		0xE1158DC8F09A4365ULL,
		0x43D57D09BCE9836CULL,
		0x6C4386BA8EEA0E56ULL,
		0x289953C04059841BULL,
		0xEE558D8388D51E09ULL,
		0x43FD29E2FC671A23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABB75A3A0EC6B28BULL,
		0xAF4820B836E487CDULL,
		0xD074317718FEC9C1ULL,
		0x8755421282EC2623ULL,
		0x2AC61700EFADFE0AULL,
		0x27EF78CC82D1B0DDULL,
		0xC89B4D9233EED314ULL,
		0xADC9B99C89E234DAULL
	}};
	sign = 0;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A315F0C1B04591CULL,
		0xA27451F2831853AAULL,
		0xFA5B6065A45752DEULL,
		0x65A44BDE203B62F3ULL,
		0xCDD8AFA3013C7C27ULL,
		0xD829365AE6295EE2ULL,
		0x62F91916EA529EC1ULL,
		0x154675FDB8EEF12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C380538B38AC566ULL,
		0x331E401409C5D788ULL,
		0x6B560FF0152A6EEDULL,
		0xE257C9802649D613ULL,
		0xCAFD5953858D9C9CULL,
		0x5D95F5307D4D5D89ULL,
		0x7A5FF46DEBC53159ULL,
		0xE4201C7B11EFAD13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDF959D3677993B6ULL,
		0x6F5611DE79527C21ULL,
		0x8F0550758F2CE3F1ULL,
		0x834C825DF9F18CE0ULL,
		0x02DB564F7BAEDF8AULL,
		0x7A93412A68DC0159ULL,
		0xE89924A8FE8D6D68ULL,
		0x31265982A6FF441AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31566313222C07A1ULL,
		0xF2E800D1AC0469A2ULL,
		0x3B3DB12E5CD11994ULL,
		0x82A46FB3D861F834ULL,
		0xB8F7BF3D4BEDD372ULL,
		0x5C483F9F7C0547DDULL,
		0xF432C66777106D1DULL,
		0x02C4F2A18AE0421EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14C36154790BADB6ULL,
		0xB0558003C6F8110EULL,
		0xC5E0A535A0146256ULL,
		0x0F1CC7E4996DE9E0ULL,
		0x3748282E71BC2B98ULL,
		0x9BA068BA8E02EA7FULL,
		0x7EE92FDFFFBC7423ULL,
		0xC4F553E7BED1E218ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C9301BEA92059EBULL,
		0x429280CDE50C5894ULL,
		0x755D0BF8BCBCB73EULL,
		0x7387A7CF3EF40E53ULL,
		0x81AF970EDA31A7DAULL,
		0xC0A7D6E4EE025D5EULL,
		0x754996877753F8F9ULL,
		0x3DCF9EB9CC0E6006ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48C456F1D9F6BE98ULL,
		0xF02F0526C2B7F217ULL,
		0x397CCDDA2F77BF9AULL,
		0x575614DBF187731DULL,
		0x4D3F43C18814C149ULL,
		0x5B6B047EAD19064CULL,
		0x09A5924220D0A465ULL,
		0x31C757EE10F95C6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA65282C9834293C9ULL,
		0xDA0A7804BA1EC4EBULL,
		0x28D6DDB6D766BF94ULL,
		0xCAF312EDFE7D2B17ULL,
		0xCBEB06D30C870995ULL,
		0x840BA30A3CA3D42AULL,
		0xCB6D6AE92CB8F662ULL,
		0xD5E7D9EC66BF2A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA271D42856B42ACFULL,
		0x16248D2208992D2BULL,
		0x10A5F02358110006ULL,
		0x8C6301EDF30A4806ULL,
		0x81543CEE7B8DB7B3ULL,
		0xD75F617470753221ULL,
		0x3E382758F417AE02ULL,
		0x5BDF7E01AA3A31E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAD94DA1A16CE977ULL,
		0x4F438591581DD64FULL,
		0xF923CBA652DADC63ULL,
		0x45682EC9CE9C3D59ULL,
		0x79A0DEAC0EAE39FBULL,
		0x2BC042DCAFCD47B8ULL,
		0x305B97E6AB8A18A8ULL,
		0x5CE1C33CE1B4DA0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC131F1C67FCE07CULL,
		0x3C3E517A5CB84328ULL,
		0x8AE95CDAF38B1E2EULL,
		0xDBF9DAE8AE8581F3ULL,
		0xB5C9EF318859AAAAULL,
		0x8BE6A5E0AB6CBB27ULL,
		0x49EA7387702747BCULL,
		0x49C2B4652B73F2F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEC62E85397008FBULL,
		0x13053416FB659326ULL,
		0x6E3A6ECB5F4FBE35ULL,
		0x696E53E12016BB66ULL,
		0xC3D6EF7A86548F50ULL,
		0x9FD99CFC04608C90ULL,
		0xE671245F3B62D0EBULL,
		0x131F0ED7B640E719ULL
	}};
	sign = 0;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A57AD2ED90AEB2AULL,
		0xF4ED5A7B996CC81AULL,
		0xD46F1903A18D133DULL,
		0x0F3232C504A219B5ULL,
		0x6E6ACB9BFBA608EEULL,
		0xD5E0F1AFA7FA49A6ULL,
		0x7DCC405BA8BD177BULL,
		0xF152587CF3544BFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6256AF99607C0928ULL,
		0x57EFB910B76F18E5ULL,
		0x2C8F17286914424AULL,
		0xDD00FB8C77FD815BULL,
		0x425ECFFE66FD5944ULL,
		0xAECBA85BB043DDBEULL,
		0x0D2D1A481D95FE40ULL,
		0x478BDD65AB93AA82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0800FD95788EE202ULL,
		0x9CFDA16AE1FDAF35ULL,
		0xA7E001DB3878D0F3ULL,
		0x323137388CA4985AULL,
		0x2C0BFB9D94A8AFA9ULL,
		0x27154953F7B66BE8ULL,
		0x709F26138B27193BULL,
		0xA9C67B1747C0A17AULL
	}};
	sign = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08EA96DBCC281179ULL,
		0x06914267EEC64487ULL,
		0xC4A62D321DB5AED5ULL,
		0x037339E916A67E32ULL,
		0x46A5C51AC02C5D0BULL,
		0xBC009382D5DE6A93ULL,
		0xC4F1D5572257A322ULL,
		0x4925FDBEBCAB9703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80CB970F670B0B6ULL,
		0x10BB9A71D1098EFFULL,
		0xEA65FAAB1BD815F4ULL,
		0x80B0D362CFB80338ULL,
		0xEE7185C50650C762ULL,
		0x32D18B172D38D378ULL,
		0xF07606DBB6280921ULL,
		0xACCD2403F84C90BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30DDDD6AD5B760C3ULL,
		0xF5D5A7F61DBCB587ULL,
		0xDA40328701DD98E0ULL,
		0x82C2668646EE7AF9ULL,
		0x58343F55B9DB95A8ULL,
		0x892F086BA8A5971AULL,
		0xD47BCE7B6C2F9A01ULL,
		0x9C58D9BAC45F0648ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B9A6139FBA4EAD6ULL,
		0x7FD7B3C1E052209EULL,
		0x93D31BAE51EF2579ULL,
		0x06F9BE5A5835132FULL,
		0x1824CB2D38E0CEC1ULL,
		0xD5E8E1CE3E5F272EULL,
		0x553356B4DB22BA0BULL,
		0x39B30A5DC5AD3D10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF49C166D549B948BULL,
		0x091EFB52D48DE66AULL,
		0xEC37CB4FABC61067ULL,
		0x23C8EEA01967FB8DULL,
		0x6460830A83B35254ULL,
		0xC85C38487458D997ULL,
		0x89676FBD60B2EE7DULL,
		0x1DF6715DB67EDD5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36FE4ACCA709564BULL,
		0x76B8B86F0BC43A33ULL,
		0xA79B505EA6291512ULL,
		0xE330CFBA3ECD17A1ULL,
		0xB3C44822B52D7C6CULL,
		0x0D8CA985CA064D96ULL,
		0xCBCBE6F77A6FCB8EULL,
		0x1BBC99000F2E5FB5ULL
	}};
	sign = 0;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C920607B328174AULL,
		0x4FA46184FFA0A81CULL,
		0xFAA31EE41DCC920CULL,
		0x4A8AFD1E4C72D783ULL,
		0x85B706EEFEB47A93ULL,
		0x28C1A10661D8B2FCULL,
		0xFB14BE7FF39FB174ULL,
		0x2B65729B900702FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D064CBF9684E465ULL,
		0x6910F33669D9710EULL,
		0xDA49FA5F866CE281ULL,
		0x3040A38BECEE59A1ULL,
		0xC7EEA567CF9D82BEULL,
		0x51456B66A64A57ACULL,
		0x84A47F413396CC97ULL,
		0xACC332D809CEEEADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F8BB9481CA332E5ULL,
		0xE6936E4E95C7370EULL,
		0x20592484975FAF8AULL,
		0x1A4A59925F847DE2ULL,
		0xBDC861872F16F7D5ULL,
		0xD77C359FBB8E5B4FULL,
		0x76703F3EC008E4DCULL,
		0x7EA23FC386381452ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BF332BBD0A78699ULL,
		0x3DFC0BBF0A093385ULL,
		0xE3EC5862651B1345ULL,
		0x4D0E09911C6AECFFULL,
		0x77E16CE58A5ADF8EULL,
		0x307168F99105EC7FULL,
		0x9CF4E869A8F248FDULL,
		0xAA1826E159CFCD80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9537C1D8044C570ULL,
		0x60DA3983B3A1ADBDULL,
		0xB39121984893207CULL,
		0x37B252FEC031E88EULL,
		0x24C2DB3EEFF68381ULL,
		0x1AE9BBC9CFD31607ULL,
		0x8435463B5A16E353ULL,
		0x17B84565CDA4E8E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x129FB69E5062C129ULL,
		0xDD21D23B566785C7ULL,
		0x305B36CA1C87F2C8ULL,
		0x155BB6925C390471ULL,
		0x531E91A69A645C0DULL,
		0x1587AD2FC132D678ULL,
		0x18BFA22E4EDB65AAULL,
		0x925FE17B8C2AE499ULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7C81B05A43E536DULL,
		0x6DA5750E2B4903B2ULL,
		0x5E81427A1EB51B6FULL,
		0xEDA3FEA010BA5D79ULL,
		0xEBAFE06578E3DD33ULL,
		0xEAB45D27F5013333ULL,
		0x2F6D0CB5EFF8EF42ULL,
		0xCCDDE2C29B5F41CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EF517FD4B46581ULL,
		0x394096CB57D3EEA5ULL,
		0x4662193FB36351BDULL,
		0x29F5119D16573BE7ULL,
		0x6BF88510CDEDF638ULL,
		0x23B1FA17B3B23376ULL,
		0xCE71405CFDD29492ULL,
		0x01D7A58BD180EDACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91D8C985CF89EDECULL,
		0x3464DE42D375150DULL,
		0x181F293A6B51C9B2ULL,
		0xC3AEED02FA632192ULL,
		0x7FB75B54AAF5E6FBULL,
		0xC7026310414EFFBDULL,
		0x60FBCC58F2265AB0ULL,
		0xCB063D36C9DE541EULL
	}};
	sign = 0;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62133C0E17F2A875ULL,
		0x0B8251BEA0BCD071ULL,
		0xC6CFF62CA9497173ULL,
		0x7EAA11E4F11B1ACEULL,
		0x8AB55E5887D57ACAULL,
		0xA7CE99C29F96D216ULL,
		0xDF6C95CAA2011A77ULL,
		0xA8E1D6FCC529A7EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A55C9D0371B9F0FULL,
		0x290366A5D81152CFULL,
		0x45D3BB14E117612DULL,
		0x4A880BB0DF8591F0ULL,
		0xDCB349F650E1C513ULL,
		0x1A838E1CB2767F27ULL,
		0x9A16BAE7E7B77627ULL,
		0x45CBEAB4AA1518DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27BD723DE0D70966ULL,
		0xE27EEB18C8AB7DA2ULL,
		0x80FC3B17C8321045ULL,
		0x34220634119588DEULL,
		0xAE02146236F3B5B7ULL,
		0x8D4B0BA5ED2052EEULL,
		0x4555DAE2BA49A450ULL,
		0x6315EC481B148F0FULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71175EFE6758CDABULL,
		0x74A360790FA75899ULL,
		0x48022720A545F75DULL,
		0x760FD8BDBD8E08F4ULL,
		0x4881A5C8DA078F82ULL,
		0x652D962F3CEC7F75ULL,
		0x376856283B355E3CULL,
		0x07A52CB9546170C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5374E60DCF0AAA8ULL,
		0xB26044651EC3805BULL,
		0xDC16CFB0707880CAULL,
		0xCE0F902EEB933B9EULL,
		0x02F2B3DEA89B9899ULL,
		0xED8F9DA5D2C96533ULL,
		0x16B41756A7BEBD06ULL,
		0x876488741EC14BA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBE0109D8A682303ULL,
		0xC2431C13F0E3D83DULL,
		0x6BEB577034CD7692ULL,
		0xA800488ED1FACD55ULL,
		0x458EF1EA316BF6E8ULL,
		0x779DF8896A231A42ULL,
		0x20B43ED19376A135ULL,
		0x8040A44535A0251AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA61D01D65C6336EFULL,
		0x1AF5EDDA742245A0ULL,
		0x78B281B140A20A38ULL,
		0x4B919676ADD0897CULL,
		0x7A1B8968F0167FBAULL,
		0xCBA388B475893753ULL,
		0x63B406526D4167A9ULL,
		0x4C8E3DC532AA7FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD7E82A69AD8C17ULL,
		0x3CE18028A7B332CBULL,
		0xB433444213AE0C42ULL,
		0xF986AC6E22C11082ULL,
		0x237ACE7770B30420ULL,
		0xFC1400FCF97EB7DAULL,
		0xE21C2099DD09B012ULL,
		0xD75DD58838ABC585ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B4519ABF2B5AAD8ULL,
		0xDE146DB1CC6F12D5ULL,
		0xC47F3D6F2CF3FDF5ULL,
		0x520AEA088B0F78F9ULL,
		0x56A0BAF17F637B99ULL,
		0xCF8F87B77C0A7F79ULL,
		0x8197E5B89037B796ULL,
		0x7530683CF9FEBA23ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81F2D9E955347456ULL,
		0xF28EBA8538089413ULL,
		0x6DBED22D2502FE01ULL,
		0x93B13B31159923A8ULL,
		0xE2AE8369FECBFDE4ULL,
		0xB7F26B4724DF45BDULL,
		0xB77709555989DD9DULL,
		0x64AB35380A0B4E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x938C2F19495CBE4EULL,
		0x297AD89E33266D5AULL,
		0x413C00B8820F8AC7ULL,
		0x1C2322F3690E51D8ULL,
		0xC9E765675D405ACAULL,
		0x2F0063D4BBB3C34EULL,
		0xB2EA9AA0C3A3875EULL,
		0xF0B75152152D7F26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE66AAD00BD7B608ULL,
		0xC913E1E704E226B8ULL,
		0x2C82D174A2F3733AULL,
		0x778E183DAC8AD1D0ULL,
		0x18C71E02A18BA31AULL,
		0x88F20772692B826FULL,
		0x048C6EB495E6563FULL,
		0x73F3E3E5F4DDCF14ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BC10885024E49B5ULL,
		0x41AE006A0A993166ULL,
		0x4AC2ACE120DE99C4ULL,
		0x4C695A83AC2D96C9ULL,
		0xFC51AC3767577FD5ULL,
		0x6414AFB88FD9B294ULL,
		0x6B26137EB4262536ULL,
		0x559A1D49E425CA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1DE9753E474ED91ULL,
		0xF3B30F700E34E572ULL,
		0xAE17356C2D690646ULL,
		0x40D0C0A2ECF3F3A8ULL,
		0x5D42950B6D6692BCULL,
		0x614F495005FC5913ULL,
		0xE194F7887306095DULL,
		0xA626BC94A8BFE984ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9E271311DD95C24ULL,
		0x4DFAF0F9FC644BF3ULL,
		0x9CAB7774F375937DULL,
		0x0B9899E0BF39A320ULL,
		0x9F0F172BF9F0ED19ULL,
		0x02C5666889DD5981ULL,
		0x89911BF641201BD9ULL,
		0xAF7360B53B65E0B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40E01F1D4BC01821ULL,
		0x7BAF557E03597A72ULL,
		0x917F49C6E109F8B7ULL,
		0x2366AE2AEEB2B749ULL,
		0x9C91FC1F62CD095EULL,
		0x5C485325A8C1716BULL,
		0x37504004970EDFB1ULL,
		0xDB13E91287DAF53CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71224BE8501392CBULL,
		0xB9F29FE512D62075ULL,
		0x84FD67E3419C97ACULL,
		0x12AA5875D311E840ULL,
		0x9F331882FEBC8C44ULL,
		0x08387A613BEC9BCAULL,
		0xFB333DD0E9F67A41ULL,
		0xD131D9AA4A1FA62AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFBDD334FBAC8556ULL,
		0xC1BCB598F08359FCULL,
		0x0C81E1E39F6D610AULL,
		0x10BC55B51BA0CF09ULL,
		0xFD5EE39C64107D1AULL,
		0x540FD8C46CD4D5A0ULL,
		0x3C1D0233AD186570ULL,
		0x09E20F683DBB4F11ULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E4C9D13A11E0C89ULL,
		0x632767236D94007CULL,
		0xD21CFA7FFCC1165FULL,
		0x421FE0BE93E57C29ULL,
		0x7298D7F16D52997AULL,
		0x57A285842D00F82AULL,
		0x0F8B7EBD67618BD8ULL,
		0xF76B17311C181EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06FF08DF743E6FF3ULL,
		0xDCD9F749F713F06DULL,
		0x86CE0C72B5A726D9ULL,
		0x2C7641F7A61ED8C7ULL,
		0x72512715C0E6BD8AULL,
		0x2239C438B12B5EACULL,
		0x3575426F89C6BC29ULL,
		0xB77C964A885A7384ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x574D94342CDF9C96ULL,
		0x864D6FD97680100FULL,
		0x4B4EEE0D4719EF85ULL,
		0x15A99EC6EDC6A362ULL,
		0x0047B0DBAC6BDBF0ULL,
		0x3568C14B7BD5997EULL,
		0xDA163C4DDD9ACFAFULL,
		0x3FEE80E693BDAB22ULL
	}};
	sign = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F32028A8C7E66B8ULL,
		0x8059068A3B74B215ULL,
		0x6DD634623297A7A0ULL,
		0x66BDCB38E0B111A3ULL,
		0x446F053BAD7B829DULL,
		0x6097E074350B8851ULL,
		0x3698BF0579C8D41EULL,
		0xF90A7435BB954C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297061D9CB489B62ULL,
		0x090E427BC8A98778ULL,
		0x2848B7C9371FF30BULL,
		0x665BE113733821A2ULL,
		0xB7EE5889A0A6A352ULL,
		0xCC5E05E24EAFE7A2ULL,
		0x2137A8AEF05700F2ULL,
		0x426E3B8F080F1FAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25C1A0B0C135CB56ULL,
		0x774AC40E72CB2A9DULL,
		0x458D7C98FB77B495ULL,
		0x0061EA256D78F001ULL,
		0x8C80ACB20CD4DF4BULL,
		0x9439DA91E65BA0AEULL,
		0x156116568971D32BULL,
		0xB69C38A6B3862C79ULL
	}};
	sign = 0;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6381956092B39D26ULL,
		0x2C41DA77DA7504EBULL,
		0xBD2236E77A9CAD38ULL,
		0x9997A596279D2896ULL,
		0xDA6701368F60F39DULL,
		0xC6BB49DD78F84619ULL,
		0x5E6AC2AB5E7F8393ULL,
		0x68E4EF91006EA9ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDF52276F6284AFEULL,
		0x8DA9BC17F444DCBCULL,
		0xD610581D9F9BC1DAULL,
		0x89D2138AAE22701EULL,
		0x48CA9DD117A41D20ULL,
		0xCCCE92936400FF7AULL,
		0x35F6B24ABE0D3ABCULL,
		0xA9BC58F072979464ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x758C72E99C8B5228ULL,
		0x9E981E5FE630282EULL,
		0xE711DEC9DB00EB5DULL,
		0x0FC5920B797AB877ULL,
		0x919C636577BCD67DULL,
		0xF9ECB74A14F7469FULL,
		0x28741060A07248D6ULL,
		0xBF2896A08DD71588ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A77B92FB8A655A9ULL,
		0x15E46BEF89494DC7ULL,
		0x3F3194CFA89699F2ULL,
		0xDDFB97D170A7E9F9ULL,
		0xDCCD7E7D90DEC8B6ULL,
		0xAF7BFB7FB0BE7DCEULL,
		0xCDE9121F2EC3979CULL,
		0x7763CEC62FD59D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403703B8458EC11CULL,
		0x887C594686689F42ULL,
		0x0F8665B17A0C63A5ULL,
		0x3ABDF57B8D4E88D8ULL,
		0x24CDFAB5D9D80412ULL,
		0x532F6BADD99E3040ULL,
		0xFD31694AB73603B0ULL,
		0x2B4F9841EE16152AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA40B5777317948DULL,
		0x8D6812A902E0AE84ULL,
		0x2FAB2F1E2E8A364CULL,
		0xA33DA255E3596121ULL,
		0xB7FF83C7B706C4A4ULL,
		0x5C4C8FD1D7204D8EULL,
		0xD0B7A8D4778D93ECULL,
		0x4C14368441BF8803ULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CCAA7686A450E14ULL,
		0x8CCDEB72B8B32993ULL,
		0x1E36321C85C0BB37ULL,
		0xAC1C8A302A08116EULL,
		0x7753AEF7C37CE022ULL,
		0xD28CCE68D4C93BCCULL,
		0x9982E65E72D0BBC2ULL,
		0xD34A65719F29DA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7963F74B0F5068ULL,
		0x1A99D0A6B11AF3E8ULL,
		0x1D2D88CE028759A2ULL,
		0xAB7EF556E5E95DFEULL,
		0xDA23E47D54785820ULL,
		0xA7F4484BBC241FF4ULL,
		0xE4A2CD59071453AEULL,
		0x352CCB4E5DC1D725ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x215143711F35BDACULL,
		0x72341ACC079835ABULL,
		0x0108A94E83396195ULL,
		0x009D94D9441EB370ULL,
		0x9D2FCA7A6F048802ULL,
		0x2A98861D18A51BD7ULL,
		0xB4E019056BBC6814ULL,
		0x9E1D9A234168031BULL
	}};
	sign = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF86D782EC085F840ULL,
		0x4C0A4BCDF2F28248ULL,
		0xB571B581A6087C91ULL,
		0x6D6DCC93A9DFA5EEULL,
		0xFD646EEDB253FD3BULL,
		0x37A23F0EE4789667ULL,
		0x9C2DECF6953C171EULL,
		0xD256619854022650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F2DF460D6642E4EULL,
		0xA03617620216FD7CULL,
		0x71FFD577B4EE77D4ULL,
		0xD95A1BEC92468343ULL,
		0xEAAAF17272F65EDAULL,
		0x54AF2BEFEBD44A31ULL,
		0xBC193A4BE3778F1AULL,
		0x0F132B94485BAB1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x793F83CDEA21C9F2ULL,
		0xABD4346BF0DB84CCULL,
		0x4371E009F11A04BCULL,
		0x9413B0A7179922ABULL,
		0x12B97D7B3F5D9E60ULL,
		0xE2F3131EF8A44C36ULL,
		0xE014B2AAB1C48803ULL,
		0xC34336040BA67B35ULL
	}};
	sign = 0;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE9C4D73BE9515EFULL,
		0x035FAB2988C0B1EEULL,
		0x7C57CFF5DDC4C61CULL,
		0xF7F555520842EDEDULL,
		0xF98ECACE6B12C509ULL,
		0xBE35C48FA6CB4E45ULL,
		0xB456A75F3D7174FEULL,
		0x9D1E21EAEC248C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5EC199543EC5229ULL,
		0xE0E9CFDF620A3C34ULL,
		0xEAEF248452E51527ULL,
		0xBAD2751E7420F798ULL,
		0x7D229060CEBBF159ULL,
		0xEAB180E24551609DULL,
		0xA28921AA90177FFAULL,
		0x665A65ABDEE6719DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8B033DE7AA8C3C6ULL,
		0x2275DB4A26B675B9ULL,
		0x9168AB718ADFB0F4ULL,
		0x3D22E0339421F654ULL,
		0x7C6C3A6D9C56D3B0ULL,
		0xD38443AD6179EDA8ULL,
		0x11CD85B4AD59F503ULL,
		0x36C3BC3F0D3E1A97ULL
	}};
	sign = 0;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3412922A4EB684BDULL,
		0xF1FD6D9E13A9FB76ULL,
		0x062F0E72182A2BBAULL,
		0xC4652461C3ACBC8AULL,
		0xAE4E46BDC6902EBDULL,
		0xCD6184A5B150FBA1ULL,
		0xB04A2AEF9B4F5573ULL,
		0x8FC9520FE9FEDC59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C13808C6AFB25B5ULL,
		0x392061D290923826ULL,
		0x5F7A06303546963DULL,
		0x7932FA760E4F6E61ULL,
		0x0AE8029FF15B59D7ULL,
		0x08209158A244C099ULL,
		0xA0810912AFAD77FEULL,
		0x4CADE828AB9F090CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07FF119DE3BB5F08ULL,
		0xB8DD0BCB8317C350ULL,
		0xA6B50841E2E3957DULL,
		0x4B3229EBB55D4E28ULL,
		0xA366441DD534D4E6ULL,
		0xC540F34D0F0C3B08ULL,
		0x0FC921DCEBA1DD75ULL,
		0x431B69E73E5FD34DULL
	}};
	sign = 0;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B747A98060A0E5ULL,
		0x6FBF538F19417370ULL,
		0x3C0681D218A7B9AAULL,
		0x610ADAB3E6DA484CULL,
		0x8559998E59C4FBDBULL,
		0x5B922AF5E2CFA6D9ULL,
		0xEA2B662A66A3E1C9ULL,
		0xA7171B19BA1EE41CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6212955C6F20466ULL,
		0xB88C3F4F1232BFDAULL,
		0x14931C320AF543F5ULL,
		0x578C48E609BF66C4ULL,
		0x59E3A8AF0C4E5851ULL,
		0x194A1532A301AE84ULL,
		0x9A4826CF52FEAB38ULL,
		0xF9050CB3360C4404ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B961E53B96E9C7FULL,
		0xB7331440070EB395ULL,
		0x277365A00DB275B4ULL,
		0x097E91CDDD1AE188ULL,
		0x2B75F0DF4D76A38AULL,
		0x424815C33FCDF855ULL,
		0x4FE33F5B13A53691ULL,
		0xAE120E668412A018ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x061B1978E74FA249ULL,
		0xD18811A0C4CCE0C8ULL,
		0x154BCF866D50AF04ULL,
		0xA1F9C51ADF60CE98ULL,
		0x1EE9921920BB2FA4ULL,
		0x8D14E9951828DBA1ULL,
		0xC9D435465A38D88BULL,
		0x4B5F144D22D3BB5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C22437351C77426ULL,
		0xDD884D5E0BA02C5AULL,
		0x7F1E347B54D2C712ULL,
		0x24604651D759D910ULL,
		0xBAABED2016AE92E9ULL,
		0x1D609C79B32B5A6EULL,
		0x8D887FE535688A0CULL,
		0xA1C1B4D92A14D034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9F8D60595882E23ULL,
		0xF3FFC442B92CB46DULL,
		0x962D9B0B187DE7F1ULL,
		0x7D997EC90806F587ULL,
		0x643DA4F90A0C9CBBULL,
		0x6FB44D1B64FD8132ULL,
		0x3C4BB56124D04E7FULL,
		0xA99D5F73F8BEEB2BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA6EF2F7966D0AC0ULL,
		0x9B2DB0C9D79C5EB2ULL,
		0xCFEA02CC9F9478F6ULL,
		0x1C7CF4DDFAEBE2CCULL,
		0x62045A185C67C593ULL,
		0x0AB4740D9A1D638EULL,
		0x848FCCA9DC4274E5ULL,
		0xCE6DD277128F325BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148F704BF9E7AA04ULL,
		0x3315EBC5BE2729A8ULL,
		0xCD133F5ABCEFBDA8ULL,
		0xB50B3F7B87BE4068ULL,
		0x0D67085E70BDA97EULL,
		0xAA4E4FB7D7BA5621ULL,
		0xFFFF426E738456F3ULL,
		0x6BE2F02EC0CFE3F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5DF82AB9C8560BCULL,
		0x6817C5041975350AULL,
		0x02D6C371E2A4BB4EULL,
		0x6771B562732DA264ULL,
		0x549D51B9EBAA1C14ULL,
		0x60662455C2630D6DULL,
		0x84908A3B68BE1DF1ULL,
		0x628AE24851BF4E66ULL
	}};
	sign = 0;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8ECE928565519ECULL,
		0x7398F827942E4AE9ULL,
		0x562807F8CFF56C81ULL,
		0xFEA5DC4B7EA3C4E4ULL,
		0x35F2240F7B5C4408ULL,
		0xC7439D941466A33CULL,
		0xBB7EB687168454FFULL,
		0x3F80888796C8FEC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CE3D2B94EA27A75ULL,
		0xFE58D8FC428C7360ULL,
		0x8EBCD0B34C249765ULL,
		0xE91C59C8E6E8D653ULL,
		0x828378F24BD840BDULL,
		0x2A26B3DE1BE8A708ULL,
		0x281D8BC3BE6ECFC4ULL,
		0xA416719E3FAB51AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC09166F07B29F77ULL,
		0x75401F2B51A1D789ULL,
		0xC76B374583D0D51BULL,
		0x1589828297BAEE90ULL,
		0xB36EAB1D2F84034BULL,
		0x9D1CE9B5F87DFC33ULL,
		0x93612AC35815853BULL,
		0x9B6A16E9571DAD15ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BB85D8518B7177ULL,
		0x21484D1FD57B7B88ULL,
		0x91A8565FB73D650DULL,
		0x425404B81C9AE1A9ULL,
		0xD045A0F85E7E328CULL,
		0x040A0A8FEFF89B06ULL,
		0x61E9BB4482238F27ULL,
		0xAF6EE972BB063CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA4C0C99B3B36C1ULL,
		0x874484E7B2CFF74DULL,
		0x7584B9F3879EC168ULL,
		0x6D77C0F701F078BEULL,
		0x6590054FC1E335B7ULL,
		0xD40730383AFFA509ULL,
		0x70714F1FBBC2EA56ULL,
		0xF7935E3C754B4365ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD816C50EB6503AB6ULL,
		0x9A03C83822AB843AULL,
		0x1C239C6C2F9EA3A4ULL,
		0xD4DC43C11AAA68EBULL,
		0x6AB59BA89C9AFCD4ULL,
		0x3002DA57B4F8F5FDULL,
		0xF1786C24C660A4D0ULL,
		0xB7DB8B3645BAF93CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC8BDA8FCC7D8350ULL,
		0x7C3837FF17FD6522ULL,
		0x512D042C3E4678D6ULL,
		0x50527718C500BA07ULL,
		0xE565BDE9596F2585ULL,
		0xCCB715DA2579844CULL,
		0x640863136C9E266AULL,
		0x9E024AA61E0B43FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91922FBFA230C54AULL,
		0xCEDD61FC210A72C0ULL,
		0xBFA86D515CC14098ULL,
		0x88DF36BF6BE82EF1ULL,
		0x9C37EBA4971D4D8BULL,
		0xCDDE753BF48912D0ULL,
		0x0B4A4502CFA0C988ULL,
		0x9612A75F5755B5B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AF9AAD02A4CBE06ULL,
		0xAD5AD602F6F2F262ULL,
		0x918496DAE185383DULL,
		0xC773405959188B15ULL,
		0x492DD244C251D7F9ULL,
		0xFED8A09E30F0717CULL,
		0x58BE1E109CFD5CE1ULL,
		0x07EFA346C6B58E4FULL
	}};
	sign = 0;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x779EF966528A8F48ULL,
		0x7D38A9A34BF714BBULL,
		0x89C0FFEDC151624AULL,
		0x5132B9A98968EEFBULL,
		0xE87BF3222C908F30ULL,
		0x5CA9DF565DB3EB4AULL,
		0xE417625F9538CB98ULL,
		0x61CE3CAD64D0F7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E2CD95C4C35B86DULL,
		0x3F62DED5C4168A10ULL,
		0x77B857E7649AC03EULL,
		0x32BF2B8234D2CDB1ULL,
		0x6AFF8BA334BD6A7CULL,
		0x23F5D9449D188887ULL,
		0x7F50313052AD90BEULL,
		0x5E55B503D363B069ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0972200A0654D6DBULL,
		0x3DD5CACD87E08AABULL,
		0x1208A8065CB6A20CULL,
		0x1E738E275496214AULL,
		0x7D7C677EF7D324B4ULL,
		0x38B40611C09B62C3ULL,
		0x64C7312F428B3ADAULL,
		0x037887A9916D477AULL
	}};
	sign = 0;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1A141FFB204022CULL,
		0x49D43CAB05AAD357ULL,
		0x0544A84CCFB4C47AULL,
		0x11276F55B039FCF8ULL,
		0xC1197C75B3087669ULL,
		0xD0938BBA7A83EBFBULL,
		0x6AF0275D5067B97CULL,
		0x92E8C4A973233D4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A5CEE67D33E384ULL,
		0xDDBADEF572917742ULL,
		0xA36517C29060EB02ULL,
		0x160B28D5758F3F8FULL,
		0x786DC3E8A8D8541EULL,
		0xECD0C24A086D4279ULL,
		0x3803044C05C16871ULL,
		0x6E057238AFFE166CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0FB731934D01EA8ULL,
		0x6C195DB593195C15ULL,
		0x61DF908A3F53D977ULL,
		0xFB1C46803AAABD68ULL,
		0x48ABB88D0A30224AULL,
		0xE3C2C9707216A982ULL,
		0x32ED23114AA6510AULL,
		0x24E35270C32526E3ULL
	}};
	sign = 0;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x840E8CD7C0FCD2EDULL,
		0x05AD43AC1453B46EULL,
		0x06E250DA924E0C03ULL,
		0xA91DC658512D8C07ULL,
		0x8554DD972FF17F75ULL,
		0xE61B89A4D64A4E03ULL,
		0x9E39837BD2377DE8ULL,
		0xB071631DE6D7368AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E9D4D9B4BA1397ULL,
		0x8B719C2233F140F5ULL,
		0xAC82723C7A90AFB7ULL,
		0x1DD5F4B1D6E84061ULL,
		0x2C4BB4583E930979ULL,
		0x2AAAF09E54FAA0A3ULL,
		0x7088E0DA69A86BA4ULL,
		0x72673CCA986CFAFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A24B7FE0C42BF56ULL,
		0x7A3BA789E0627379ULL,
		0x5A5FDE9E17BD5C4BULL,
		0x8B47D1A67A454BA5ULL,
		0x5909293EF15E75FCULL,
		0xBB709906814FAD60ULL,
		0x2DB0A2A1688F1244ULL,
		0x3E0A26534E6A3B90ULL
	}};
	sign = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C73B9A47B383B34ULL,
		0xEB5604E529F4CFB4ULL,
		0xB872F10D239DD930ULL,
		0xF9CDF664A4D87109ULL,
		0x08F84019B1532624ULL,
		0xFDFC8EE7EE742C1CULL,
		0x0388C19D1A02CEDDULL,
		0x79B6308BC7208C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D641D08A6EFBB02ULL,
		0xBED37AB991BD388AULL,
		0x586BBE5A1ACFCDFAULL,
		0xFC43CBCA611F1FCBULL,
		0xC0A514D683438D9FULL,
		0x6B718652DD047366ULL,
		0xA15A0A8F32849BF4ULL,
		0x17B704B9805868E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF0F9C9BD4488032ULL,
		0x2C828A2B98379729ULL,
		0x600732B308CE0B36ULL,
		0xFD8A2A9A43B9513EULL,
		0x48532B432E0F9884ULL,
		0x928B0895116FB8B5ULL,
		0x622EB70DE77E32E9ULL,
		0x61FF2BD246C82331ULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0780BC9877B37EEFULL,
		0x34EEC2CC5511D615ULL,
		0x0F477830C8DAB758ULL,
		0x97C5673FC7BD98E5ULL,
		0xB746C3ABA37D4F40ULL,
		0xCCFDD3672BCA2151ULL,
		0xE4E9360A90B4E6A1ULL,
		0xFC4A7F640E7A555DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D897DB528A3761ULL,
		0xF43BA9E9187FB4BBULL,
		0x90C9CD8A7DE23C75ULL,
		0xA9FCAAECD4B048B6ULL,
		0x2459EADBF29A4EE7ULL,
		0xEE3EDD34817D4C0BULL,
		0xC1C5CB665892C9D7ULL,
		0x4FA621112A6029A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0A824BD2529478EULL,
		0x40B318E33C922159ULL,
		0x7E7DAAA64AF87AE2ULL,
		0xEDC8BC52F30D502EULL,
		0x92ECD8CFB0E30058ULL,
		0xDEBEF632AA4CD546ULL,
		0x23236AA438221CC9ULL,
		0xACA45E52E41A2BB9ULL
	}};
	sign = 0;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF77841FBCEB324F1ULL,
		0x8F0D55F3AFF4BAA3ULL,
		0x3FF08E68CEE00520ULL,
		0x3E2B467DDC7D9CB4ULL,
		0x3050CC43026D69C0ULL,
		0xD48FE867900335DAULL,
		0x907657F30E5953F1ULL,
		0xFEC266B10FD1870AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D2419B36421EA7ULL,
		0xA99F02567B171B19ULL,
		0x9984B0BEDEA48335ULL,
		0x58416B414078B43DULL,
		0x2208517575AFA992ULL,
		0x9EE43E3FCF0FB95FULL,
		0xFD46053E5492C260ULL,
		0x3BE71B68AF50A358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EA600609871064AULL,
		0xE56E539D34DD9F8AULL,
		0xA66BDDA9F03B81EAULL,
		0xE5E9DB3C9C04E876ULL,
		0x0E487ACD8CBDC02DULL,
		0x35ABAA27C0F37C7BULL,
		0x933052B4B9C69191ULL,
		0xC2DB4B486080E3B1ULL
	}};
	sign = 0;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56C7305B4B849D52ULL,
		0x621841111292BA83ULL,
		0x354A452F194EA55EULL,
		0x3AF373E20B76E290ULL,
		0x65EBC787832FED2CULL,
		0x442A79F886098955ULL,
		0xD7B8F4B51F816849ULL,
		0x25CF8A64FD06013CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE3CD0DFA9500966ULL,
		0x53C04DF4931BFFAEULL,
		0x13A67E25E3319415ULL,
		0xEDBEE8E6FED68175ULL,
		0xEB067DCA348818C0ULL,
		0x23C21C8A2C32D7ECULL,
		0x16BD7FF759338B74ULL,
		0xFF852810AE9C7510ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988A5F7BA23493ECULL,
		0x0E57F31C7F76BAD4ULL,
		0x21A3C709361D1149ULL,
		0x4D348AFB0CA0611BULL,
		0x7AE549BD4EA7D46BULL,
		0x20685D6E59D6B168ULL,
		0xC0FB74BDC64DDCD5ULL,
		0x264A62544E698C2CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5651B15A2C11BE2ULL,
		0x0C8656AD0401AFC7ULL,
		0x2AF79E0485FCCFD3ULL,
		0x3CF4645E93866F0EULL,
		0xCC08F0AE897C4CB2ULL,
		0xD05037B30C277D9FULL,
		0x9489CAD92B200B45ULL,
		0xA6BB7B3DC119A8B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0308729E0CDC5A9ULL,
		0x4B36A5A29B8F934EULL,
		0xCE53B130BAC97C3BULL,
		0x290B8A38CA657EADULL,
		0x317A1C4188F56F6AULL,
		0xF5B44471042CA6DFULL,
		0xFFE89900A16EBF9FULL,
		0xD9ACD4C4AB8FE98EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53493EBC1F35639ULL,
		0xC14FB10A68721C78ULL,
		0x5CA3ECD3CB335397ULL,
		0x13E8DA25C920F060ULL,
		0x9A8ED46D0086DD48ULL,
		0xDA9BF34207FAD6C0ULL,
		0x94A131D889B14BA5ULL,
		0xCD0EA6791589BF21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDC7531F846F36F3ULL,
		0xA67CF92C30BE1C47ULL,
		0xF754A7A34A08D8D0ULL,
		0xA5DB178C6AC05111ULL,
		0x134DBB9848EBA416ULL,
		0xB2C4440CDED06478ULL,
		0xE5DDCD45DF829CC1ULL,
		0xE296C8004E30909DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB8C0A3D817BCBDULL,
		0x1CBDF7CC3CE228A9ULL,
		0x91D11433F8475D9FULL,
		0xC69D88BD4411F441ULL,
		0x866873C66258D2AAULL,
		0xEF1282FAA9B13262ULL,
		0xAD5C61D1EE880FA3ULL,
		0x8574C8EA8803A238ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F0E927BAC577A36ULL,
		0x89BF015FF3DBF39EULL,
		0x6583936F51C17B31ULL,
		0xDF3D8ECF26AE5CD0ULL,
		0x8CE547D1E692D16BULL,
		0xC3B1C112351F3215ULL,
		0x38816B73F0FA8D1DULL,
		0x5D21FF15C62CEE65ULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x504397A62BB5C43BULL,
		0xB93E6EC7B7A2D8F4ULL,
		0xFD369B3250519EE8ULL,
		0x9234D9667EF4D590ULL,
		0x46A4767FE9C5F350ULL,
		0x71F5428A48C6CD54ULL,
		0x4435A142A99D7C26ULL,
		0xDAA32186B06871F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6BD2FA14BAE176ULL,
		0xD3BEA3FC46AA5F82ULL,
		0x5CCE2FCC8B56A6FEULL,
		0xBDA43E0DCC9565C9ULL,
		0x4C6C0976AFDBC3BBULL,
		0x4D01CEEF4B5E59FFULL,
		0xC9ABECBB357FDF8AULL,
		0x4CD7CB6E8B686DB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D7C4AC16FAE2C5ULL,
		0xE57FCACB70F87972ULL,
		0xA0686B65C4FAF7E9ULL,
		0xD4909B58B25F6FC7ULL,
		0xFA386D0939EA2F94ULL,
		0x24F3739AFD687354ULL,
		0x7A89B487741D9C9CULL,
		0x8DCB56182500043AULL
	}};
	sign = 0;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x222AD23C103C2223ULL,
		0x08B9EB956B13D197ULL,
		0x412946C1DE71CAEFULL,
		0x2BFEB0374F7B026AULL,
		0x68EF473A1BF62DD6ULL,
		0x9406EBCDD352A198ULL,
		0x0EB9C145D292E5B2ULL,
		0x206A1C374ADC3424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07510B3878BB510BULL,
		0x7D3016F5A9D7EC7DULL,
		0xE0DCA75ECBD3E18BULL,
		0x4CA8AC3D3065C2F0ULL,
		0x5F82EED9D5F4D8E7ULL,
		0x705E49798DFC221FULL,
		0x57891C6D9B3B6FC6ULL,
		0x71D1D30A64D3CE7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AD9C7039780D118ULL,
		0x8B89D49FC13BE51AULL,
		0x604C9F63129DE963ULL,
		0xDF5603FA1F153F79ULL,
		0x096C5860460154EEULL,
		0x23A8A25445567F79ULL,
		0xB730A4D8375775ECULL,
		0xAE98492CE60865A7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985A9910CD0179C5ULL,
		0x72374B39E67F5EBCULL,
		0xBFEECBC3D8C52FCDULL,
		0x3E609205882A42E9ULL,
		0xA17E883752947EA8ULL,
		0x0F983B132921E6E4ULL,
		0x374CBBF63AC4CE64ULL,
		0xF223A6E8366DB8A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34F527F89882538ULL,
		0x98410425A4AD146BULL,
		0xACC9B328917B6E43ULL,
		0x9C6FEFF9D4B21C5CULL,
		0x4BB754052297920BULL,
		0x2FDF79AEF00BDCD9ULL,
		0x27C58632E7908F8CULL,
		0xA408E3183410E1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB50B46914379548DULL,
		0xD9F6471441D24A50ULL,
		0x1325189B4749C189ULL,
		0xA1F0A20BB378268DULL,
		0x55C734322FFCEC9CULL,
		0xDFB8C16439160A0BULL,
		0x0F8735C353343ED7ULL,
		0x4E1AC3D0025CD6F9ULL
	}};
	sign = 0;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF07E66FFB42EE30ULL,
		0x85B4D37FF75C78D4ULL,
		0xDEEAF7AC6D4710E2ULL,
		0x6768D3F91811E028ULL,
		0x37729B9A99547D1CULL,
		0x9F0E6BEEB78F7DFAULL,
		0x4676FF1C7989CFF8ULL,
		0x88A67DC615BA1E3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8023430D40395B0ULL,
		0x45E9789543936C1CULL,
		0x12FB7F12AAF45FE7ULL,
		0xDDFAE82E8B3E090BULL,
		0xDC5A70C6A770C014ULL,
		0x47A074C1E363167EULL,
		0x8C9606630F179145ULL,
		0x63AAE5A256A23CD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1705B23F273F5880ULL,
		0x3FCB5AEAB3C90CB8ULL,
		0xCBEF7899C252B0FBULL,
		0x896DEBCA8CD3D71DULL,
		0x5B182AD3F1E3BD07ULL,
		0x576DF72CD42C677BULL,
		0xB9E0F8B96A723EB3ULL,
		0x24FB9823BF17E163ULL
	}};
	sign = 0;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E4454D55BDD895CULL,
		0x6C8480248D19659AULL,
		0x59C4B766D283603DULL,
		0xA5CCADB7437D37D5ULL,
		0xD36EA09220276926ULL,
		0x02F6461056C77547ULL,
		0xE326592B19E7049DULL,
		0x6C23FCD65E1EE234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA721306C6E5DD767ULL,
		0x615E712DB41DC769ULL,
		0x959ABA73006679A9ULL,
		0xCE0E5446E9D91E4AULL,
		0x545B7C63ED837C89ULL,
		0x5273C50E49E9FBBBULL,
		0x8E7C4BBB1DB9C635ULL,
		0xDBB6C5B85A6B7BC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77232468ED7FB1F5ULL,
		0x0B260EF6D8FB9E30ULL,
		0xC429FCF3D21CE694ULL,
		0xD7BE597059A4198AULL,
		0x7F13242E32A3EC9CULL,
		0xB08281020CDD798CULL,
		0x54AA0D6FFC2D3E67ULL,
		0x906D371E03B3666DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}