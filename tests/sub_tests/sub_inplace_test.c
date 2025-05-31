#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0x51AD763F24CC5698ULL,
		0x882A0A4E5A72F792ULL,
		0xB4BA25E36874E401ULL,
		0x3DB080FD2A086216ULL,
		0xA53CB5AB1A892726ULL,
		0xC7FB8A234CE38917ULL,
		0x67431D62D720A7C0ULL,
		0x1648D3895361B3D3ULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0x7778B9FBE29BD592ULL,
		0xC842709AFAF0F950ULL,
		0xA977DF756A37B36EULL,
		0x513196BE5C839453ULL,
		0x2A2161C811E2FB85ULL,
		0x52D69377D0558FDBULL,
		0xF89CCF83C709E3F6ULL,
		0x2ED911B70C723746ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xDA34BC4342308106ULL,
		0xBFE799B35F81FE41ULL,
		0x0B42466DFE3D3092ULL,
		0xEC7EEA3ECD84CDC3ULL,
		0x7B1B53E308A62BA0ULL,
		0x7524F6AB7C8DF93CULL,
		0x6EA64DDF1016C3CAULL,
		0xE76FC1D246EF7C8CULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1DAA589EF8FBE3DBULL,
		0x6A0AF125EAB6A1BCULL,
		0x781E9F9BFEB03370ULL,
		0x16AFB1BFEDCD77BAULL,
		0x83D224640D21EB99ULL,
		0xBF79EFC377CD7C56ULL,
		0x08F08C8F77ED5DFFULL,
		0x4BB6FD33E3A09C4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86CB94B2786F5031ULL,
		0xA3D8D7927DA0EB62ULL,
		0x7261B3CC8FC7A655ULL,
		0x000514624E7E4853ULL,
		0xD2E5B67B6A6FA8A9ULL,
		0x9F1D279831F4BC20ULL,
		0xE6C6FC1828116B78ULL,
		0xBFB6EF02EF08716BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96DEC3EC808C93AAULL,
		0xC63219936D15B659ULL,
		0x05BCEBCF6EE88D1AULL,
		0x16AA9D5D9F4F2F67ULL,
		0xB0EC6DE8A2B242F0ULL,
		0x205CC82B45D8C035ULL,
		0x222990774FDBF287ULL,
		0x8C000E30F4982AE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2FFDDF381FA56C9FULL,
		0x8707C72D9D6BBDEBULL,
		0x00EBFD7B41221A67ULL,
		0xA834331D674F381FULL,
		0xA6C9807DCF63D559ULL,
		0xFDA633BD4D98C312ULL,
		0x21B5773373E478B5ULL,
		0xB97943E537F235F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x716A2B2F939CE350ULL,
		0x66064B2B118225E3ULL,
		0xF3B49B330905DDDCULL,
		0x74FBA14476E35D73ULL,
		0xCC827C094DD2A0B4ULL,
		0xD91632B94E45AC4CULL,
		0xB6F8DD448E5C6AA6ULL,
		0xCA24150D3A713C83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE93B4088C08894FULL,
		0x21017C028BE99807ULL,
		0x0D376248381C3C8BULL,
		0x333891D8F06BDAABULL,
		0xDA470474819134A5ULL,
		0x24900103FF5316C5ULL,
		0x6ABC99EEE5880E0FULL,
		0xEF552ED7FD80F975ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDF53703DBC0FBDBBULL,
		0x85362FFC9991521EULL,
		0x4286431B7AC4E44FULL,
		0x5E079339F9E01D00ULL,
		0xA6FDBE5C4E527DB3ULL,
		0x534803E0DD0B7C07ULL,
		0xD347AEE6D28EFC00ULL,
		0x914F31B5F636059EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A32422E3F1CE3B7ULL,
		0xA9B7E1161CEC906CULL,
		0x07D656927A5E7EF4ULL,
		0x17DB4EB1EE31ED11ULL,
		0x21621610DDA09276ULL,
		0x875814473CD25747ULL,
		0x2BA4C176D819B56DULL,
		0x4EAC760EA7DD826BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5212E0F7CF2DA04ULL,
		0xDB7E4EE67CA4C1B2ULL,
		0x3AAFEC890066655AULL,
		0x462C44880BAE2FEFULL,
		0x859BA84B70B1EB3DULL,
		0xCBEFEF99A03924C0ULL,
		0xA7A2ED6FFA754692ULL,
		0x42A2BBA74E588333ULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8169D363B1562707ULL,
		0x931A50A02B3062B5ULL,
		0xE8E1A7CF281FE109ULL,
		0xB7476076C6E5BA21ULL,
		0x160FE5998F419E64ULL,
		0x47326C0638453B99ULL,
		0x933058D84A147907ULL,
		0xBAA558EDF0EBE7A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEF86AAC424A52F0ULL,
		0x486B741E9444ECF1ULL,
		0x8FCB98B6F996D950ULL,
		0x60FC0B8285C14F65ULL,
		0xBD54DCBC4C99AAF5ULL,
		0xEA0E5BED3F0ABD77ULL,
		0x66BD456BA53FBE22ULL,
		0x993E09E94C50B0C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC27168B76F0BD417ULL,
		0x4AAEDC8196EB75C3ULL,
		0x59160F182E8907B9ULL,
		0x564B54F441246ABCULL,
		0x58BB08DD42A7F36FULL,
		0x5D241018F93A7E21ULL,
		0x2C73136CA4D4BAE4ULL,
		0x21674F04A49B36DCULL
	}};
	sign = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBCFCBE6DB6F36E4DULL,
		0x1A9B2C2DC067F1C1ULL,
		0x101F6A471A16214CULL,
		0x7E32DF5197E79354ULL,
		0x818BCBC3EDC0C476ULL,
		0x4A4A89B51CF815FCULL,
		0xA2222904FEBBFF2CULL,
		0xD966B1753CE307CCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DDAA3571D0F657ULL,
		0x5601989368AF6845ULL,
		0x1E8C8470466E4D83ULL,
		0x7587794CB61EB28CULL,
		0x6790A39C92438286ULL,
		0x77C89E04486EB86FULL,
		0x048A22090649CF8DULL,
		0x307E436AF3BCA52BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x591F1438452277F6ULL,
		0xC499939A57B8897CULL,
		0xF192E5D6D3A7D3C8ULL,
		0x08AB6604E1C8E0C7ULL,
		0x19FB28275B7D41F0ULL,
		0xD281EBB0D4895D8DULL,
		0x9D9806FBF8722F9EULL,
		0xA8E86E0A492662A1ULL
	}};
	sign = 0;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8BA14E459C46E706ULL,
		0x05A8E9BC952D949FULL,
		0x0455837E0435E009ULL,
		0x1797B798B5AD9033ULL,
		0xD071B5136A936E11ULL,
		0xC6787EC5D8EB3996ULL,
		0xFF9569D98DDF7901ULL,
		0xE2706B4E7CB42E26ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1253C3BBC1FE4EULL,
		0x275B100B9A388071ULL,
		0xBC8C6BD78C6F7D4AULL,
		0xDC824786AF8C6927ULL,
		0x3BD01133E33D9E67ULL,
		0xD94E80208C976045ULL,
		0x4AA0E78E34C99FB3ULL,
		0x584F264BDE7062ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F8EFA81E084E8B8ULL,
		0xDE4DD9B0FAF5142EULL,
		0x47C917A677C662BEULL,
		0x3B1570120621270BULL,
		0x94A1A3DF8755CFA9ULL,
		0xED29FEA54C53D951ULL,
		0xB4F4824B5915D94DULL,
		0x8A2145029E43CB7AULL
	}};
	sign = 0;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB14F06E05224F50AULL,
		0xBEC65F7B09E92D69ULL,
		0xAD48BE06F6E7F7E2ULL,
		0xC741F5E00260161AULL,
		0x6E7DCDDF9475F596ULL,
		0xB13D12D2552251EDULL,
		0x25120392C09042C3ULL,
		0xB74D03E66FEC2682ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2CCE620172DB49ULL,
		0x0249B99D1D7381ECULL,
		0x0817A1D9389A6E3CULL,
		0xDC5F7B543190CAC1ULL,
		0x77BF101C652A3DC7ULL,
		0x6DEFB85A8AB7F41DULL,
		0x83072295EE94E8A7ULL,
		0xAE9FC99AA4F3F13DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3522387E50B219C1ULL,
		0xBC7CA5DDEC75AB7DULL,
		0xA5311C2DBE4D89A6ULL,
		0xEAE27A8BD0CF4B59ULL,
		0xF6BEBDC32F4BB7CEULL,
		0x434D5A77CA6A5DCFULL,
		0xA20AE0FCD1FB5A1CULL,
		0x08AD3A4BCAF83544ULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF8DC3B54A85DD56DULL,
		0x9E903C1C0763FB41ULL,
		0x3F861FC8A3AF8374ULL,
		0xAF48DB22ED1F42BCULL,
		0x59C3F9A88240C726ULL,
		0x2260FBE3F4C4B256ULL,
		0xD71AD0687269DE6FULL,
		0xEE7C42768311155DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x956CD43ACF7CE893ULL,
		0x42B6AC8D8ED429CCULL,
		0x7AFCA0D88132C7A5ULL,
		0x53A4479BF3DEBAC9ULL,
		0xF4D312E7E931070FULL,
		0x8976D6F9750D05E7ULL,
		0x175DC1B68EC89E0AULL,
		0x3AC4A2433E3578FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x636F6719D8E0ECDAULL,
		0x5BD98F8E788FD175ULL,
		0xC4897EF0227CBBCFULL,
		0x5BA49386F94087F2ULL,
		0x64F0E6C0990FC017ULL,
		0x98EA24EA7FB7AC6EULL,
		0xBFBD0EB1E3A14064ULL,
		0xB3B7A03344DB9C5FULL
	}};
	sign = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60BF42C3C5F2064AULL,
		0x3C78CFDACE8BBB95ULL,
		0xCDD86CB49A239BC0ULL,
		0xA6F13C7AB078EF7DULL,
		0x33C5702EF9A9E1FEULL,
		0x2D4B327D7E745A2BULL,
		0xC043D2861EA1A708ULL,
		0xAFF631502E80161EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BEBABBC9667F4DFULL,
		0x9426B16C120EB469ULL,
		0xA0C02BCA2E87B060ULL,
		0xBBABFB85D0624840ULL,
		0x2E824F273A2F3008ULL,
		0x8E6F6C9544A85AC3ULL,
		0x2690B265C03A1355ULL,
		0x131851EEB56605ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D397072F8A116BULL,
		0xA8521E6EBC7D072CULL,
		0x2D1840EA6B9BEB5FULL,
		0xEB4540F4E016A73DULL,
		0x05432107BF7AB1F5ULL,
		0x9EDBC5E839CBFF68ULL,
		0x99B320205E6793B2ULL,
		0x9CDDDF61791A1071ULL
	}};
	sign = 0;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD31938E2513C3E19ULL,
		0xEA15B61935FBC319ULL,
		0x03B76EC01DCAF181ULL,
		0x8C7FC8514407CE0EULL,
		0x3B4D0478A7FAFC12ULL,
		0xAFF8D8EB19149847ULL,
		0xA9FF002A3BE082B6ULL,
		0xD23868B1F8B35893ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C1A66F6EA54BC32ULL,
		0x1E6BE52451374966ULL,
		0x3BA15D70938FB2B8ULL,
		0x4F9173F4353292AAULL,
		0x082C25072438B8C8ULL,
		0x7697AC6A045D792EULL,
		0x5BC0D36D59769E6CULL,
		0x552212FA283BF311ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36FED1EB66E781E7ULL,
		0xCBA9D0F4E4C479B3ULL,
		0xC816114F8A3B3EC9ULL,
		0x3CEE545D0ED53B63ULL,
		0x3320DF7183C2434AULL,
		0x39612C8114B71F19ULL,
		0x4E3E2CBCE269E44AULL,
		0x7D1655B7D0776582ULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9900FA2BCDC8F7ACULL,
		0x497940B096CA2C3AULL,
		0x3D6595455BB34742ULL,
		0x53C31FB4D4CD9E32ULL,
		0x545FAC6879732C2BULL,
		0xFFC1C0B1FC307E21ULL,
		0x8BC74416E49110D6ULL,
		0xE2920327109EA397ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9AEC3B008CD83DULL,
		0x5E173D8852BA275AULL,
		0x9A1FA4CCEC8C7615ULL,
		0x66091067775978C8ULL,
		0x56040AD6BEE091DAULL,
		0x0F8D202843105983ULL,
		0x8C10D88B3368E4BCULL,
		0xDF9562A146717333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B660DF0CD3C1F6FULL,
		0xEB620328441004E0ULL,
		0xA345F0786F26D12CULL,
		0xEDBA0F4D5D742569ULL,
		0xFE5BA191BA929A50ULL,
		0xF034A089B920249DULL,
		0xFFB66B8BB1282C1AULL,
		0x02FCA085CA2D3063ULL
	}};
	sign = 0;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82274A5BAF6CF19AULL,
		0xFE251BDC5D25E0C7ULL,
		0xEF768693CA2FC10FULL,
		0x46B7979919BC7CE0ULL,
		0xEC42351E5B4860B0ULL,
		0x8EFD81D808DCA387ULL,
		0x2EDFA036925F1761ULL,
		0xED954BAE61A6402CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C42A865AB467A7ULL,
		0x3AB064A6FCD87288ULL,
		0x8478A097BC27178BULL,
		0xC18BAC0EE9538411ULL,
		0x5EDFD31A879C5C31ULL,
		0xD6536D702F9401B0ULL,
		0xC08AE4E8868A4B43ULL,
		0x62DE86A57200F93DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38631FD554B889F3ULL,
		0xC374B735604D6E3FULL,
		0x6AFDE5FC0E08A984ULL,
		0x852BEB8A3068F8CFULL,
		0x8D626203D3AC047EULL,
		0xB8AA1467D948A1D7ULL,
		0x6E54BB4E0BD4CC1DULL,
		0x8AB6C508EFA546EEULL
	}};
	sign = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF7B6D12BE46F51BAULL,
		0x582A01A4127B4FFCULL,
		0x5C28B40AC1888C26ULL,
		0xEB02BBC5957B116BULL,
		0xD4CF61F6E1B43324ULL,
		0x0BD53BDF46FFD2B7ULL,
		0xDDFF1F6573D83808ULL,
		0xCBFAFEF040ABD99BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA0DF4A19E4A48CBULL,
		0xF025CA41CF94E067ULL,
		0xA0BEEF9C05A9FE49ULL,
		0xF862130B9D859911ULL,
		0xA7C6A7AFAFB9208CULL,
		0x38A749206AF25897ULL,
		0x6140221563722B27ULL,
		0xDE2321F1CEB75F2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDA8DC8A462508EFULL,
		0x6804376242E66F94ULL,
		0xBB69C46EBBDE8DDCULL,
		0xF2A0A8B9F7F57859ULL,
		0x2D08BA4731FB1297ULL,
		0xD32DF2BEDC0D7A20ULL,
		0x7CBEFD5010660CE0ULL,
		0xEDD7DCFE71F47A6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3568A4718B067B94ULL,
		0x3E8135B9E84078D7ULL,
		0x27E7456C382B0AC2ULL,
		0x00139FDACD64EA59ULL,
		0x17947CBE17F49A68ULL,
		0xB54BC35269D2CAF5ULL,
		0x110EFCC01B1EA7A8ULL,
		0x79105840603D1EBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA64ED828ED95C1DULL,
		0x1B5553C57A0CED63ULL,
		0x1CD5F9D8889B61FCULL,
		0x43EA2DC3F97EF5CAULL,
		0x5EA80EBE48420240ULL,
		0xE811C23C6E79349FULL,
		0x5C9DACA5B28AB112ULL,
		0xDAAAFC5CE3A901C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B03B6EEFC2D1F77ULL,
		0x232BE1F46E338B73ULL,
		0x0B114B93AF8FA8C6ULL,
		0xBC297216D3E5F48FULL,
		0xB8EC6DFFCFB29827ULL,
		0xCD3A0115FB599655ULL,
		0xB471501A6893F695ULL,
		0x9E655BE37C941CFBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1046CC88C897B6C4ULL,
		0x3CC216E43D5D8F3CULL,
		0x07846B5A12053AF6ULL,
		0xBB62227963E4CA41ULL,
		0x3842F658765EA448ULL,
		0x1A353806C40DFB7DULL,
		0x6AE6D734C80390F2ULL,
		0x8A87330A5A54A85BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x973FC6B292473E28ULL,
		0x7DCFC54CE2385921ULL,
		0x5A18D341DFFC57B2ULL,
		0x75C26A6DFD62F1F8ULL,
		0x5123047BF514F034ULL,
		0x6F528B658E8345BAULL,
		0x981D68D9518C08D5ULL,
		0x60E1E1E426C506C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x790705D63650789CULL,
		0xBEF251975B25361AULL,
		0xAD6B98183208E343ULL,
		0x459FB80B6681D848ULL,
		0xE71FF1DC8149B414ULL,
		0xAAE2ACA1358AB5C2ULL,
		0xD2C96E5B7677881CULL,
		0x29A55126338FA193ULL
	}};
	sign = 0;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B05AAFD6CC0ED68ULL,
		0x915BDFC72B64C20CULL,
		0x43EF647A20A49488ULL,
		0x21203A20DC89E900ULL,
		0x834DC94D105C6D62ULL,
		0xE2A7247164F3178DULL,
		0xF31E0C949E711397ULL,
		0xB4BEB7EF8B889C82ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6231F60CF73CCCFDULL,
		0xD91D3C9BCA3A3939ULL,
		0x0D5E014C985139C7ULL,
		0xFA69BFD85924DC0CULL,
		0xCFB952DDDA85503FULL,
		0xBE1A453D11E1B91EULL,
		0x09B99E632C50F5A2ULL,
		0x5DEB160799C0936AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38D3B4F07584206BULL,
		0xB83EA32B612A88D3ULL,
		0x3691632D88535AC0ULL,
		0x26B67A4883650CF4ULL,
		0xB394766F35D71D22ULL,
		0x248CDF3453115E6EULL,
		0xE9646E3172201DF5ULL,
		0x56D3A1E7F1C80918ULL
	}};
	sign = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6F266BCBC0B50C9BULL,
		0xEB4F7BA4FA8F791EULL,
		0x4CEA9A1C267069B6ULL,
		0x925256E9A66AEEAAULL,
		0x982CA9E19C0F3877ULL,
		0x588C8F3A2BF5AD87ULL,
		0x1108A85D066B4EA9ULL,
		0x70E453F946749263ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF248C40FB7D2C7DFULL,
		0x501AB3391F39C4E3ULL,
		0xF647CFB51528992DULL,
		0xEF40FB0D5459FB59ULL,
		0x54574B83F2BB54D8ULL,
		0xDCC0182DF0A7D4C2ULL,
		0xFEBAB30E30725DEFULL,
		0xCD851749A30B6DDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CDDA7BC08E244BCULL,
		0x9B34C86BDB55B43AULL,
		0x56A2CA671147D089ULL,
		0xA3115BDC5210F350ULL,
		0x43D55E5DA953E39EULL,
		0x7BCC770C3B4DD8C5ULL,
		0x124DF54ED5F8F0B9ULL,
		0xA35F3CAFA3692487ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC5CB104B37683C2AULL,
		0x8B103AED0A64B92CULL,
		0xC4F69DC2861E6C71ULL,
		0xD91D2769E7EF18F5ULL,
		0x3ED9250704FF3AE4ULL,
		0x9681416978559AD1ULL,
		0xD5039A602781969CULL,
		0x447ED7BE55A8C5C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64A3FD646C3AB3C5ULL,
		0xE6B405A9C6AC7CB4ULL,
		0xAAC1D754C6AB889FULL,
		0xD042AABF8D3C2AE9ULL,
		0xD1EC71333E20A72FULL,
		0x495F53CE9C14BB68ULL,
		0x4BFE96BD151D7991ULL,
		0xE69D5E9A7BC027EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x612712E6CB2D8865ULL,
		0xA45C354343B83C78ULL,
		0x1A34C66DBF72E3D1ULL,
		0x08DA7CAA5AB2EE0CULL,
		0x6CECB3D3C6DE93B5ULL,
		0x4D21ED9ADC40DF68ULL,
		0x890503A312641D0BULL,
		0x5DE17923D9E89DDDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6AEA6384ADB49823ULL,
		0x9CD522CB8D5D1BCBULL,
		0xF32BEAF4EE91EFF2ULL,
		0x5C8D833523F142A8ULL,
		0xA08FBBE49AFA00DAULL,
		0x25E367C2BF2A7497ULL,
		0xF0A1C068002DB1E9ULL,
		0x334358335B7FBFE6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BF1BAF7931C2B6CULL,
		0x23B903EA1094A485ULL,
		0xA0F374C8B3A5D471ULL,
		0x35CD117A2DF1B7B7ULL,
		0x214E87888CFDD5C4ULL,
		0x2B243E1B00F914FCULL,
		0x3F5CB6C7E98A5016ULL,
		0x72E7188B9E1330ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EF8A88D1A986CB7ULL,
		0x791C1EE17CC87746ULL,
		0x5238762C3AEC1B81ULL,
		0x26C071BAF5FF8AF1ULL,
		0x7F41345C0DFC2B16ULL,
		0xFABF29A7BE315F9BULL,
		0xB14509A016A361D2ULL,
		0xC05C3FA7BD6C8F39ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF471C257670FB65BULL,
		0x1D213691971FBA10ULL,
		0x2A5129C671229753ULL,
		0x3BEE900192711B82ULL,
		0xA09D653C46B58244ULL,
		0x920DCBD06BB9A88AULL,
		0xAB953209FD17AF1BULL,
		0xB036BF4177345CEEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x514EF42A7E8D6543ULL,
		0x7F2D43FCEDB31E38ULL,
		0x26486C34080038A5ULL,
		0xFAB8F4ECF0DF1575ULL,
		0x65CD8BD827EBE801ULL,
		0x2DC17459E2F3D0E1ULL,
		0x7BECF24A66F8DC79ULL,
		0x1E9F9BC97ABB5BC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA322CE2CE8825118ULL,
		0x9DF3F294A96C9BD8ULL,
		0x0408BD9269225EADULL,
		0x41359B14A192060DULL,
		0x3ACFD9641EC99A42ULL,
		0x644C577688C5D7A9ULL,
		0x2FA83FBF961ED2A2ULL,
		0x91972377FC790126ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B1F1CC1241A7C8AULL,
		0xEF7CC9582CFC3BF4ULL,
		0xC84BF97ABF77045CULL,
		0xEE673F814D444EF0ULL,
		0x01ABB40487C59C85ULL,
		0xF6E14F93B95FD12FULL,
		0x20FB20E26CF09DBAULL,
		0x9E04BB9C60498FA5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0EFD69253EDF26ULL,
		0xA89B795A8685789AULL,
		0xAB1238C2652C91F9ULL,
		0xC92557DAD5D6FDA4ULL,
		0x078FBF4C2DFA70B4ULL,
		0x0F3EE5F0E78E37B0ULL,
		0x1484C22BC1BA161CULL,
		0x5819A5AD4AD31091ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40101F57FEDB9D64ULL,
		0x46E14FFDA676C359ULL,
		0x1D39C0B85A4A7263ULL,
		0x2541E7A6776D514CULL,
		0xFA1BF4B859CB2BD1ULL,
		0xE7A269A2D1D1997EULL,
		0x0C765EB6AB36879EULL,
		0x45EB15EF15767F14ULL
	}};
	sign = 0;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53807DCAD0B5E955ULL,
		0x5395EFC313DE1A9DULL,
		0xA14BCDD5655622EAULL,
		0x927C33085251CFFDULL,
		0xE5C96164574730BEULL,
		0x2DE92F34B1C3CAE6ULL,
		0xC06846ABF6728129ULL,
		0xB80FBCE438899722ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C028034060F368ULL,
		0x46FD9EB02625C673ULL,
		0x115BFD0C6E0F68EAULL,
		0x0D81A8B73CC7EE1BULL,
		0xEC6C215998B1A593ULL,
		0x26167D2C96B5C0E0ULL,
		0xBD46718250E03199ULL,
		0xE6AB9A6D8C0C40C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C055C79054F5EDULL,
		0x0C985112EDB85429ULL,
		0x8FEFD0C8F746BA00ULL,
		0x84FA8A511589E1E2ULL,
		0xF95D400ABE958B2BULL,
		0x07D2B2081B0E0A05ULL,
		0x0321D529A5924F90ULL,
		0xD1642276AC7D5661ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x57CE24EE42E650B6ULL,
		0x1427FBA08DD443D4ULL,
		0xDD691181F127E206ULL,
		0x651992E88BEAD841ULL,
		0xF3B1277E09DC69D2ULL,
		0xABBF2FA6B23F9526ULL,
		0xA09543130B5F1E0FULL,
		0x78147B2728C86D78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E16B5999E86822EULL,
		0x665F89EBEFE2828BULL,
		0xB4C952003D0E72F8ULL,
		0xCA714BDCF44DD8DCULL,
		0xAB361A4C5EA5E13FULL,
		0x53ED27243F12C0E3ULL,
		0xE5C4D911E1A9B71AULL,
		0xFF322D823459CD8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49B76F54A45FCE88ULL,
		0xADC871B49DF1C149ULL,
		0x289FBF81B4196F0DULL,
		0x9AA8470B979CFF65ULL,
		0x487B0D31AB368892ULL,
		0x57D20882732CD443ULL,
		0xBAD06A0129B566F5ULL,
		0x78E24DA4F46E9FE8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1377787ECC0E1C4EULL,
		0xBB4CD9F609D86440ULL,
		0x49FF12C1DD60CBF8ULL,
		0x89ED1F31C58BE1C2ULL,
		0x616A8B70D8CF4BE8ULL,
		0xDABE4E6417841EABULL,
		0xAEC0A8246351085CULL,
		0xDB39510CECE0DC72ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCC32022CE8D56DCULL,
		0x4E79BA1199D42979ULL,
		0xE2DCFCC552429E64ULL,
		0x08B3A048E496EB34ULL,
		0x1255D33BE187A29CULL,
		0x31B17192C3010107ULL,
		0x1DF683A54A60F881ULL,
		0xBD6FF630F845CED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36B4585BFD80C572ULL,
		0x6CD31FE470043AC6ULL,
		0x672215FC8B1E2D94ULL,
		0x81397EE8E0F4F68DULL,
		0x4F14B834F747A94CULL,
		0xA90CDCD154831DA4ULL,
		0x90CA247F18F00FDBULL,
		0x1DC95ADBF49B0D9FULL
	}};
	sign = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x858DC4CD0A0467C0ULL,
		0xD7C92E0E81FBA61FULL,
		0xF099A8D633C938E2ULL,
		0x2F4D45E7D5C56347ULL,
		0xD17F5D6BCB8F0A69ULL,
		0x792B32178CAC0E7EULL,
		0x7D90A6422BDB8C5BULL,
		0x6A47C0269EAECCD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52B4BCACA477EC62ULL,
		0x97193C8FC7E5B6B3ULL,
		0xC5CB238838F91387ULL,
		0xFD5F317895552866ULL,
		0xFB6D0CE233885041ULL,
		0x7418051A61A700E2ULL,
		0x32893DC33C3BEC58ULL,
		0x5FB8AEE7C0032CF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32D90820658C7B5EULL,
		0x40AFF17EBA15EF6CULL,
		0x2ACE854DFAD0255BULL,
		0x31EE146F40703AE1ULL,
		0xD61250899806BA27ULL,
		0x05132CFD2B050D9BULL,
		0x4B07687EEF9FA003ULL,
		0x0A8F113EDEAB9FE1ULL
	}};
	sign = 0;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE5994EC20293660CULL,
		0x1F92FA8B5B9FA874ULL,
		0x6F2DE67C851E924AULL,
		0x3988F42944E2D05CULL,
		0x9E22946C41A89877ULL,
		0x3E0935AF65D6EA9AULL,
		0x0891EAA83DAEAFBFULL,
		0x8067A1FA61D72FAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1842892922E06D61ULL,
		0x1D1E0C487AC042B6ULL,
		0x53D49F94CDEF4593ULL,
		0x5150D100FABA0EFBULL,
		0x85D9B6AF206A7A87ULL,
		0x68CCCC7BC8EB6174ULL,
		0xF88E9D546C38A43EULL,
		0x720BAB75500A4FC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD56C598DFB2F8ABULL,
		0x0274EE42E0DF65BEULL,
		0x1B5946E7B72F4CB7ULL,
		0xE83823284A28C161ULL,
		0x1848DDBD213E1DEFULL,
		0xD53C69339CEB8926ULL,
		0x10034D53D1760B80ULL,
		0x0E5BF68511CCDFE6ULL
	}};
	sign = 0;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD43ECD7EC1FD4CD2ULL,
		0xE696A2B0F52F5177ULL,
		0x8DCED6B6387880F2ULL,
		0x981EBE1AC75B43A7ULL,
		0xEA31178351FF385DULL,
		0xC28F8A4BF0A11B02ULL,
		0x40FDBB526A9BC397ULL,
		0x4C472072E578DF1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6813A22B6AAB7837ULL,
		0x680225A60948F0C2ULL,
		0xC0552035B48A3846ULL,
		0xB16508A7FC85276EULL,
		0x0E51C1ECC2B803ADULL,
		0xFE5DF71F0CE4CC06ULL,
		0x9E5F1146D9166AF0ULL,
		0x2C7DF27EEDC520ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C2B2B535751D49BULL,
		0x7E947D0AEBE660B5ULL,
		0xCD79B68083EE48ACULL,
		0xE6B9B572CAD61C38ULL,
		0xDBDF55968F4734AFULL,
		0xC431932CE3BC4EFCULL,
		0xA29EAA0B918558A6ULL,
		0x1FC92DF3F7B3BE2DULL
	}};
	sign = 0;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1E50AEC75672F9DDULL,
		0x47134FFC49F10D4BULL,
		0xF96995477E8DBA1FULL,
		0x6CBDDECF3DF288C2ULL,
		0xA5F9D18DD5C43D30ULL,
		0x56204F69335D5B9DULL,
		0x2F9EE6AF032D6ED5ULL,
		0x0A5B0742114AC9C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80FB5E521B0FBA69ULL,
		0x741290801E31CAF3ULL,
		0xF6D17DFECA177F07ULL,
		0x7AFF1CC7559ABD79ULL,
		0x1F898068238FB14AULL,
		0x062D57581BC4437CULL,
		0x06B96CA23D63653CULL,
		0x9BE76CE1DD66D570ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D5550753B633F74ULL,
		0xD300BF7C2BBF4257ULL,
		0x02981748B4763B17ULL,
		0xF1BEC207E857CB49ULL,
		0x86705125B2348BE5ULL,
		0x4FF2F81117991821ULL,
		0x28E57A0CC5CA0999ULL,
		0x6E739A6033E3F459ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAF939C7D489A5A0FULL,
		0x0BEB876B612C0DDBULL,
		0x3B713A9A2A9C1EF0ULL,
		0x1E3C76F8CB3E8FD7ULL,
		0xA6A85A3EF2F3FAB8ULL,
		0x68118F4FB698DC36ULL,
		0x15501FF1FB1CBE38ULL,
		0xE034515A177D4305ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x150897F896780974ULL,
		0xE4CE68B31E12762DULL,
		0xB3CD6D4EDF90B1C1ULL,
		0x067B6101273122E4ULL,
		0x08B079CECD9747AAULL,
		0x1D22D3503050BB09ULL,
		0x63194314569B7AC7ULL,
		0x1814BC7EDF4540A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A8B0484B222509BULL,
		0x271D1EB8431997AEULL,
		0x87A3CD4B4B0B6D2EULL,
		0x17C115F7A40D6CF2ULL,
		0x9DF7E070255CB30EULL,
		0x4AEEBBFF8648212DULL,
		0xB236DCDDA4814371ULL,
		0xC81F94DB3838025DULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD55D90C0A770FEBEULL,
		0x7B4A7479725B638EULL,
		0x6E964D7715AD2CF3ULL,
		0xA9FD081AE9F370DDULL,
		0x3E55B03BB77E5982ULL,
		0x0B4ED467EC9B39AFULL,
		0xD8C516D793D3CDA1ULL,
		0x74FE56080B4DBD8AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF88E925747F20DCULL,
		0xA8299B9B83C9D527ULL,
		0x4521C8B2C1834E72ULL,
		0x176ADC9AF63D7951ULL,
		0xC7CB48A2558E1E67ULL,
		0x1993188B682C39E2ULL,
		0xF656182307BB4E95ULL,
		0xCC0F00B5A3D19363ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5D4A79B32F1DDE2ULL,
		0xD320D8DDEE918E66ULL,
		0x297484C45429DE80ULL,
		0x92922B7FF3B5F78CULL,
		0x768A679961F03B1BULL,
		0xF1BBBBDC846EFFCCULL,
		0xE26EFEB48C187F0BULL,
		0xA8EF5552677C2A26ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x532665E317AEE765ULL,
		0x32889DBD5DAAB162ULL,
		0x21B64C1DAA1F7288ULL,
		0xD77A8ECF4FF4EC23ULL,
		0xDD40B293CAAA487FULL,
		0x8008306A784BE27DULL,
		0xD55243C037A6778DULL,
		0x065A99374A6D91F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56ACBDEFA9352830ULL,
		0xBC8407D5DDA9228BULL,
		0xE6EEDF799C9B3F13ULL,
		0x87295DC66C8F7CB6ULL,
		0xCFE4DD30443ED3FAULL,
		0x095D7CD15AB45C3AULL,
		0xA95106F12FB049C2ULL,
		0x996AB4460503D41BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC79A7F36E79BF35ULL,
		0x760495E780018ED6ULL,
		0x3AC76CA40D843374ULL,
		0x50513108E3656F6CULL,
		0x0D5BD563866B7485ULL,
		0x76AAB3991D978643ULL,
		0x2C013CCF07F62DCBULL,
		0x6CEFE4F14569BDD7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0ED96D62BF7BAABDULL,
		0x8EEDFA3BC2F2091BULL,
		0xDC768A571A2636EAULL,
		0xD2684BE1C330294FULL,
		0x8818445A35F0A7D3ULL,
		0x37EFCD08635816D9ULL,
		0x1CB915E54265F601ULL,
		0xC15E0AEA9EAA407EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4929D90288FE67ULL,
		0x3B0F51D74F347E64ULL,
		0x51C524611688BC23ULL,
		0x25396113B8B6C3EFULL,
		0x2E05727F8C825FB1ULL,
		0x8D19501A41F7CA47ULL,
		0x58F373660C5CA1A3ULL,
		0x690F6FB053166B5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10904389BCF2AC56ULL,
		0x53DEA86473BD8AB6ULL,
		0x8AB165F6039D7AC7ULL,
		0xAD2EEACE0A796560ULL,
		0x5A12D1DAA96E4822ULL,
		0xAAD67CEE21604C92ULL,
		0xC3C5A27F3609545DULL,
		0x584E9B3A4B93D51FULL
	}};
	sign = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFA1EFE7F656A10E3ULL,
		0xBF2DDE32F5926F49ULL,
		0x29ECA29992127C39ULL,
		0x81179B30E6EA63D5ULL,
		0x3253C4256321B7D0ULL,
		0xE96A2233AFC4C737ULL,
		0x34E09D1F830E6A0CULL,
		0x80AAD9146413411CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7311CEF1D4C034A0ULL,
		0x9BD2240013313C63ULL,
		0x7E406F1659063A72ULL,
		0x621A64E4E5C08810ULL,
		0xE65CB48BA950E958ULL,
		0x378B834104473345ULL,
		0xD1161D9BBF1B11D7ULL,
		0x552E5D6E405DE45DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x870D2F8D90A9DC43ULL,
		0x235BBA32E26132E6ULL,
		0xABAC3383390C41C7ULL,
		0x1EFD364C0129DBC4ULL,
		0x4BF70F99B9D0CE78ULL,
		0xB1DE9EF2AB7D93F1ULL,
		0x63CA7F83C3F35835ULL,
		0x2B7C7BA623B55CBEULL
	}};
	sign = 0;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x309B835E21D0A64EULL,
		0xD2C34839A42AA53CULL,
		0xB90762F78B473C96ULL,
		0x7E42581DC1620CD8ULL,
		0x31E25C803F0A66C4ULL,
		0xFD2C31B10CBFBE67ULL,
		0x2B27D9B6BC25BF47ULL,
		0x155806572415EB16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3AE265A9B48EDB3ULL,
		0xA1FEE8198506BE81ULL,
		0xAEBE9C635C3043F7ULL,
		0x68620653F6190C30ULL,
		0xBB6B1B635AC66AB5ULL,
		0xCCF2388F19826852ULL,
		0x5C0263910AB1E752ULL,
		0xD39BE94F8BF62A60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CED5D038687B89BULL,
		0x30C460201F23E6BAULL,
		0x0A48C6942F16F89FULL,
		0x15E051C9CB4900A8ULL,
		0x7677411CE443FC0FULL,
		0x3039F921F33D5614ULL,
		0xCF257625B173D7F5ULL,
		0x41BC1D07981FC0B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1A05EE29DFA4818ULL,
		0x3B85E3C6ADE2C78FULL,
		0xDA5DB3B9D90DAC33ULL,
		0xF821814CD47F35E9ULL,
		0xA567196AEDB3E1E1ULL,
		0xE97511C7A3077C70ULL,
		0xD870BB6DE0905238ULL,
		0x4EEEC7C02CC00D76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEFBB0A5DA4E476ULL,
		0x25C02683FD608304ULL,
		0x5990E9C3822B31AFULL,
		0x9EA9F69B258285D0ULL,
		0x264D2A9434A70965ULL,
		0x33E70F95D21A8C92ULL,
		0xA7BDFE1BDF4549FBULL,
		0xFF89619FC4E01A8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2B0A3D8405563A2ULL,
		0x15C5BD42B082448BULL,
		0x80CCC9F656E27A84ULL,
		0x59778AB1AEFCB019ULL,
		0x7F19EED6B90CD87CULL,
		0xB58E0231D0ECEFDEULL,
		0x30B2BD52014B083DULL,
		0x4F65662067DFF2EBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB10B53397EABA5E6ULL,
		0xEDD4A8756A56E0E3ULL,
		0x959D649579E88C2EULL,
		0x33245B187620DD71ULL,
		0xF6A50782187E3B49ULL,
		0x410B51D4B158B1F5ULL,
		0xB98B14B6E64FA541ULL,
		0x81311368397166E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4887BA657D133D60ULL,
		0xB087ED177A56AAB9ULL,
		0x510C9F3B069E9E0EULL,
		0xC78FB0352E625E66ULL,
		0xBC385E5246816F68ULL,
		0xD3FB5E214D035B13ULL,
		0x3F3F84AD4C431B3DULL,
		0xF907D9BC67ED4F4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x688398D401986886ULL,
		0x3D4CBB5DF000362AULL,
		0x4490C55A7349EE20ULL,
		0x6B94AAE347BE7F0BULL,
		0x3A6CA92FD1FCCBE0ULL,
		0x6D0FF3B3645556E2ULL,
		0x7A4B90099A0C8A03ULL,
		0x882939ABD184179FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B6F3C32402232D4ULL,
		0xE69F9936657B4833ULL,
		0xA48B4594D958B69AULL,
		0x41B04506E968F096ULL,
		0xECE548646ACD13E3ULL,
		0xAF24FEE403158527ULL,
		0xF20D2D8FD092E5DAULL,
		0x6C5B96BBE78C7543ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2070A7DF41B4CC57ULL,
		0x5D9F71DFF564523AULL,
		0xF460CC83183C9B77ULL,
		0x241ABE3926EE793DULL,
		0x8306977DD16B74B8ULL,
		0x56FE594C5D126C20ULL,
		0xFA2F88FA787F2D96ULL,
		0x59F3C8EB94A3859EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFE9452FE6D667DULL,
		0x890027567016F5F9ULL,
		0xB02A7911C11C1B23ULL,
		0x1D9586CDC27A7758ULL,
		0x69DEB0E699619F2BULL,
		0x5826A597A6031907ULL,
		0xF7DDA4955813B844ULL,
		0x1267CDD052E8EFA4ULL
	}};
	sign = 0;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x75C8E5AA55BED3FFULL,
		0xD94465058BC9DB0FULL,
		0xAF47E08A49D231E5ULL,
		0x50DBC4E3DA62E110ULL,
		0x4CCD9B9B19CFE5EEULL,
		0xC24BC1ACF9FEB4ABULL,
		0x076A50B1D9C0345BULL,
		0x83155286F7D4260AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x796BF1344CF814B5ULL,
		0x0608FC54604D7FCDULL,
		0x8746841A7EC4516AULL,
		0x7BF8D9B0D1A7D316ULL,
		0x899D1D1C8B605C39ULL,
		0xC9EF85B673A92E72ULL,
		0xF22A1B889E11F224ULL,
		0xADCBF300729B05D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC5CF47608C6BF4AULL,
		0xD33B68B12B7C5B41ULL,
		0x28015C6FCB0DE07BULL,
		0xD4E2EB3308BB0DFAULL,
		0xC3307E7E8E6F89B4ULL,
		0xF85C3BF686558638ULL,
		0x154035293BAE4236ULL,
		0xD5495F8685392031ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xECC64373444C163AULL,
		0x6BAF47C41522869FULL,
		0x1640F2927B983601ULL,
		0x329B0E31BB8E8C6EULL,
		0x4B3CB1ADA5178722ULL,
		0xA83D7DD368119EDFULL,
		0x335E34456D9865B2ULL,
		0x887C774B25CF9250ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x557D3DE93E74477AULL,
		0x9CE7F8B1BEE2D9A9ULL,
		0xBE439836A3B22EC7ULL,
		0x8DDA0B4351B1EDCCULL,
		0xCB431F20B0CDDE6EULL,
		0xBAEC8F855859FD22ULL,
		0x37B24ACE22F4C435ULL,
		0xF5301A88FBAB5510ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9749058A05D7CEC0ULL,
		0xCEC74F12563FACF6ULL,
		0x57FD5A5BD7E60739ULL,
		0xA4C102EE69DC9EA1ULL,
		0x7FF9928CF449A8B3ULL,
		0xED50EE4E0FB7A1BCULL,
		0xFBABE9774AA3A17CULL,
		0x934C5CC22A243D3FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x834A98E3F6F81498ULL,
		0x46DED955C2DEC69FULL,
		0x7F3789C1515B8FFDULL,
		0x0CA422E0A39C79F6ULL,
		0xAFA365A0E3DD84C9ULL,
		0x549B5C54816299B0ULL,
		0xAE483C6751BBA6C7ULL,
		0x8235E4CD17511F43ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89AB7D264A6038DULL,
		0xA7D9FDE650DA40C2ULL,
		0x85A97F55FF8E5062ULL,
		0xE8C395B9C0F2618DULL,
		0x98D934EAB97C9D6EULL,
		0xDB719713D422D8BFULL,
		0xEEB15AAA4C01EA3BULL,
		0x49BBAA42FDB6DA80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAAFE1119252110BULL,
		0x9F04DB6F720485DCULL,
		0xF98E0A6B51CD3F9AULL,
		0x23E08D26E2AA1868ULL,
		0x16CA30B62A60E75AULL,
		0x7929C540AD3FC0F1ULL,
		0xBF96E1BD05B9BC8BULL,
		0x387A3A8A199A44C2ULL
	}};
	sign = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB4591901FACEC971ULL,
		0x4510D7A738FEB2A4ULL,
		0x5457E90BE7D3BE0FULL,
		0x93C7A29A5D2D9DCBULL,
		0x3E7B00F75B9C598FULL,
		0x191B60F999A7EA72ULL,
		0xBB4F3BC98FD8500BULL,
		0x95DED2CCAE68B475ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF238C92846226BABULL,
		0x860CBAFDFA765CC6ULL,
		0xFA93E1D9F34D4428ULL,
		0x4542AEDCF13A676AULL,
		0x3435EA705F0D0984ULL,
		0x2E702482D7407F75ULL,
		0x9E7B1065BDFCF897ULL,
		0xB02A3105CF34E8CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2204FD9B4AC5DC6ULL,
		0xBF041CA93E8855DDULL,
		0x59C40731F48679E6ULL,
		0x4E84F3BD6BF33660ULL,
		0x0A451686FC8F500BULL,
		0xEAAB3C76C2676AFDULL,
		0x1CD42B63D1DB5773ULL,
		0xE5B4A1C6DF33CBA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF5A2AE88D92BA76BULL,
		0x62E26363F90990E5ULL,
		0xE7E6B8525BF3DC5BULL,
		0x20101E6B309DB462ULL,
		0xD593633DF429A585ULL,
		0xD1746109279284B4ULL,
		0x78FEDEA6A3322356ULL,
		0x052A6A912CE1A081ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F8DC8FC4D02E3FFULL,
		0xFADC134FF3F8CAD8ULL,
		0xE44BF4D30FA0EDBDULL,
		0x3EF6620AE31FBB63ULL,
		0xB988E30FD53623A3ULL,
		0x00216B61DB79C042ULL,
		0x9FB9299670C71264ULL,
		0xECC7561CF4BD4452ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6614E58C8C28C36CULL,
		0x680650140510C60DULL,
		0x039AC37F4C52EE9DULL,
		0xE119BC604D7DF8FFULL,
		0x1C0A802E1EF381E1ULL,
		0xD152F5A74C18C472ULL,
		0xD945B510326B10F2ULL,
		0x1863147438245C2EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A78C01DE81BB3FCULL,
		0xF74D20CBAE9475AFULL,
		0x9CBEAB3742399CECULL,
		0x6568808C6FFE645FULL,
		0x1A42C83ADBAE6F19ULL,
		0x391B7DE186286F3DULL,
		0x00FFACD93DE88828ULL,
		0x27DBF3C2B5537465ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D57A03268C29675ULL,
		0x303EAD3277B63C1BULL,
		0x6084B9142A8D0F38ULL,
		0x190773C541331F5FULL,
		0x347DD08D68CE4517ULL,
		0xB419FB8A15BD7D55ULL,
		0x6094A61A8D4576C7ULL,
		0x67D70BEE62986451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED211FEB7F591D87ULL,
		0xC70E739936DE3993ULL,
		0x3C39F22317AC8DB4ULL,
		0x4C610CC72ECB4500ULL,
		0xE5C4F7AD72E02A02ULL,
		0x85018257706AF1E7ULL,
		0xA06B06BEB0A31160ULL,
		0xC004E7D452BB1013ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5A0406B6DB05A7E3ULL,
		0x1E0B886DB4705FE6ULL,
		0x7803D76CDBE2B7E1ULL,
		0x488B9799E06750BAULL,
		0xFE893C4D5DE8F99BULL,
		0x7B4493843B0F98D6ULL,
		0x6C7F561CAC822E11ULL,
		0x1A0F40D4A0E6BC28ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC9982262154797ULL,
		0xB8C3B94B951F8D5DULL,
		0x624C04223ABF825DULL,
		0x640138BDC826FEABULL,
		0x44AF0247B6482593ULL,
		0x7B98415BD8102255ULL,
		0x9F24A0D9AA3A5D68ULL,
		0x86A18D5EF1029028ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A3A6E9478F0604CULL,
		0x6547CF221F50D288ULL,
		0x15B7D34AA1233583ULL,
		0xE48A5EDC1840520FULL,
		0xB9DA3A05A7A0D407ULL,
		0xFFAC522862FF7681ULL,
		0xCD5AB5430247D0A8ULL,
		0x936DB375AFE42BFFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x31A6EAB35B4FD4E2ULL,
		0xEDE43F75BE650DEAULL,
		0xCBA2F405DAD97B93ULL,
		0xADFBFB3788A70AE3ULL,
		0xC3CCBEB70AE57CBEULL,
		0x33274B7F56471903ULL,
		0xC649093E490EAF52ULL,
		0xA9B6665B05ADCC91ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA4A3BADE5186FB6ULL,
		0xD859DC12BC3F5A3BULL,
		0xD612BEA11C358E31ULL,
		0xDE27181C0AA6B29AULL,
		0x29021841C25960E6ULL,
		0x3ABDC06D2EEF78A3ULL,
		0x59303FB201D6EA48ULL,
		0x06C267F5988BDC97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x775CAF057637652CULL,
		0x158A63630225B3AEULL,
		0xF5903564BEA3ED62ULL,
		0xCFD4E31B7E005848ULL,
		0x9ACAA675488C1BD7ULL,
		0xF8698B122757A060ULL,
		0x6D18C98C4737C509ULL,
		0xA2F3FE656D21EFFAULL
	}};
	sign = 0;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC8A004D5342AD49DULL,
		0x301B885BC49F8D12ULL,
		0x507D6FEBC181A09BULL,
		0x8A8FE303D3AD8B27ULL,
		0x0CB58CCE4537ACAAULL,
		0x80B2489A305AA0ECULL,
		0x173129FEEA1960D6ULL,
		0x125DCD55E5F5E89AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A58FBE28DEF5B91ULL,
		0xD0CCD7EB5F886A7CULL,
		0xDDCB441B1C94D178ULL,
		0x9787BD5BD35F8211ULL,
		0xC6A9131F23004821ULL,
		0xF0264E8CBF0FE282ULL,
		0xD24368CFE4996D69ULL,
		0x9A145E036D1F5B08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E4708F2A63B790CULL,
		0x5F4EB07065172296ULL,
		0x72B22BD0A4ECCF22ULL,
		0xF30825A8004E0915ULL,
		0x460C79AF22376488ULL,
		0x908BFA0D714ABE69ULL,
		0x44EDC12F057FF36CULL,
		0x78496F5278D68D91ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA10B1EF04B48A027ULL,
		0x023C7A1B78C24FA7ULL,
		0x33C7473E4CFFFE57ULL,
		0x26C83E115E19709BULL,
		0x7E1E91804BBCAC96ULL,
		0xB77667B01E1F3743ULL,
		0x52AF65CD9DB73344ULL,
		0x45BF30EF9A183E4DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA69031FA881C8F5ULL,
		0x5B6A66E989BD907AULL,
		0xAFFE5154F68EDDD0ULL,
		0x77E193508618BA2FULL,
		0x0F9B7C3BC6038F06ULL,
		0xDB2AE23DF07673EDULL,
		0xEC51F4AEC23BD1BFULL,
		0xDE5C3879B2E17A9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6A21BD0A2C6D732ULL,
		0xA6D21331EF04BF2CULL,
		0x83C8F5E956712086ULL,
		0xAEE6AAC0D800B66BULL,
		0x6E83154485B91D8FULL,
		0xDC4B85722DA8C356ULL,
		0x665D711EDB7B6184ULL,
		0x6762F875E736C3AFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4AC16C226857DD25ULL,
		0x3B2F3F48C221AF66ULL,
		0x1EC4CAE5FCFE6EC4ULL,
		0x3709CBE4987CA889ULL,
		0x5A612AD79654AF87ULL,
		0x06BEE2F5DBA50F2BULL,
		0x39BC9B207DA332CEULL,
		0x7F17606C5376D36EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x935D00B9150A8FD4ULL,
		0x66AE892ACE3897F4ULL,
		0xCAD09F2A835E8B9BULL,
		0x341242B402C80BFEULL,
		0xFEEDAD1E7D7D49A1ULL,
		0x3CC64CC924ADD98BULL,
		0xC49AEC6EFBBEDD80ULL,
		0x48253E5DE82D547EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7646B69534D4D51ULL,
		0xD480B61DF3E91771ULL,
		0x53F42BBB799FE328ULL,
		0x02F7893095B49C8AULL,
		0x5B737DB918D765E6ULL,
		0xC9F8962CB6F7359FULL,
		0x7521AEB181E4554DULL,
		0x36F2220E6B497EEFULL
	}};
	sign = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE98D91F73B3489A2ULL,
		0x8E450DAB77E54836ULL,
		0xFE0499FB64E6B20EULL,
		0xFFC15EF006B51AB0ULL,
		0x558093EB86D4E56FULL,
		0x2EE65CC63F3577AEULL,
		0x51FAAA5C4F799CEEULL,
		0x226DE5799A001229ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5A6EE38182A2BBULL,
		0x7AE21ECB64754F53ULL,
		0x14BB5E18CFB51252ULL,
		0x529AF59D7B3B9B44ULL,
		0x42FA121EECA595F6ULL,
		0xC5EF73362ED42058ULL,
		0x13768CE41293603AULL,
		0x6E1ADBF2A20EDEF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE332313B9B1E6E7ULL,
		0x1362EEE0136FF8E2ULL,
		0xE9493BE295319FBCULL,
		0xAD2669528B797F6CULL,
		0x128681CC9A2F4F79ULL,
		0x68F6E99010615756ULL,
		0x3E841D783CE63CB3ULL,
		0xB4530986F7F13331ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF9D33DEA282C7ED0ULL,
		0x6B9BFDDC82DFD112ULL,
		0xA770357072A65257ULL,
		0xB4EA3093914205E8ULL,
		0x6BC82CE6DCC55381ULL,
		0x62BD9A200BD5D8DDULL,
		0xBE8FF91F089CB3D6ULL,
		0x06690346DC7665A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x94262F3C15B4D99EULL,
		0xE8063B83A37D2AEDULL,
		0x1B9CF83780189D59ULL,
		0x72F0E4449AA26B14ULL,
		0x41620DF518F36061ULL,
		0x5D19B91956037030ULL,
		0x88B3E3E28271E344ULL,
		0xEB5D0676B4BEBFB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65AD0EAE1277A532ULL,
		0x8395C258DF62A625ULL,
		0x8BD33D38F28DB4FDULL,
		0x41F94C4EF69F9AD4ULL,
		0x2A661EF1C3D1F320ULL,
		0x05A3E106B5D268ADULL,
		0x35DC153C862AD092ULL,
		0x1B0BFCD027B7A5F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF26C92DCF77E138BULL,
		0x90DF144FA9A21109ULL,
		0x2F828F90FEB36C7AULL,
		0xF260C1BB3B13EB64ULL,
		0x75D580140EEBADF2ULL,
		0x5969D02CEAD9F487ULL,
		0xBAF5F38CE102A4BDULL,
		0x0BC7BDB1DAC322A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C74DA1F40A30A08ULL,
		0x90418EBA57E40A27ULL,
		0xF9720F0EE6108071ULL,
		0xAA04FAE44B2E1384ULL,
		0xD54E0A7F375D3748ULL,
		0x897EFD129EB52FE0ULL,
		0x097F85AD13938E2DULL,
		0x90FAE8B352905B07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85F7B8BDB6DB0983ULL,
		0x009D859551BE06E2ULL,
		0x3610808218A2EC09ULL,
		0x485BC6D6EFE5D7DFULL,
		0xA0877594D78E76AAULL,
		0xCFEAD31A4C24C4A6ULL,
		0xB1766DDFCD6F168FULL,
		0x7ACCD4FE8832C79BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x47351678FD5803A3ULL,
		0x539E1F1F572686FCULL,
		0x82F404AFBEDF802CULL,
		0x6FB9B98A2B7F8FBDULL,
		0x6FAAD2BDBBCF2961ULL,
		0xC7DE33AA5C622BFFULL,
		0x2CADA9FD72FEA19FULL,
		0x9915D3C8225CA918ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07A2CFB0B55B34CULL,
		0xD43197AB123CEC05ULL,
		0xBB169A4F1471A99BULL,
		0xBD14E0BCBE6D6565ULL,
		0x77903F7DDEA55494ULL,
		0xF6BA8C30CA97FC0DULL,
		0x76EF13E6E7034A12ULL,
		0x49829C95FC8815B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76BAE97DF2025057ULL,
		0x7F6C877444E99AF6ULL,
		0xC7DD6A60AA6DD690ULL,
		0xB2A4D8CD6D122A57ULL,
		0xF81A933FDD29D4CCULL,
		0xD123A77991CA2FF1ULL,
		0xB5BE96168BFB578CULL,
		0x4F93373225D49361ULL
	}};
	sign = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x37E7B7928C021BEDULL,
		0x507FF751C79E6BD8ULL,
		0x78C877FEE9E11546ULL,
		0xCE8756956C536CB1ULL,
		0x7E94F90AD2744CE7ULL,
		0x952C23E4BA1FF5FFULL,
		0x2A9399B253C9FA7EULL,
		0x22970968FEA65A4DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE907C919B454416ULL,
		0x68000940A1865FA7ULL,
		0xCA14A412E6344722ULL,
		0x065D778060CB4C25ULL,
		0x4A3DFFA41E9660B0ULL,
		0xB773B49A326FAFDCULL,
		0x4CF6DEFC93484751ULL,
		0xBE80B356C89A2163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69573B00F0BCD7D7ULL,
		0xE87FEE1126180C30ULL,
		0xAEB3D3EC03ACCE23ULL,
		0xC829DF150B88208BULL,
		0x3456F966B3DDEC37ULL,
		0xDDB86F4A87B04623ULL,
		0xDD9CBAB5C081B32CULL,
		0x64165612360C38E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x550E6AECCDADB965ULL,
		0xEA24BEC1798DCA1FULL,
		0xC52C40CE785AD70BULL,
		0x2F0FD9A99248B5AAULL,
		0xB599A4AB3D494748ULL,
		0x1136E002E55747EFULL,
		0xDC4B06D85CABA725ULL,
		0x329976BC86BE181FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3E643FDD80828AULL,
		0x72BEFA0BA21E9654ULL,
		0xA87F25F199B955B5ULL,
		0x7C53C628FAC61569ULL,
		0x502F29BA6291D6D6ULL,
		0x96CB7E73D6B29F00ULL,
		0x44C899282002986CULL,
		0xEA1312B374B19F26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7D006ACF02D36DBULL,
		0x7765C4B5D76F33CAULL,
		0x1CAD1ADCDEA18156ULL,
		0xB2BC13809782A041ULL,
		0x656A7AF0DAB77071ULL,
		0x7A6B618F0EA4A8EFULL,
		0x97826DB03CA90EB8ULL,
		0x48866409120C78F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98763B166BA0074AULL,
		0x7144EFFA2DDA4FA1ULL,
		0x817ED5E9B1CDB1BBULL,
		0x2A24C8543EC86FA0ULL,
		0x844923C736BB30B9ULL,
		0xB0A411AE6EECD062ULL,
		0x90B344F75E256875ULL,
		0x38C23AF9E1754979ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A28F2051FF424DULL,
		0x0D4C00A6C44A9272ULL,
		0x3C34D74B48603F46ULL,
		0x3DAEEF0C5608FAABULL,
		0xF92E331638D0167FULL,
		0x7E1366DA8AE57D0BULL,
		0xE12251F2F59F07A8ULL,
		0xCBBE49929057B77FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7D3ABF619A0C4FDULL,
		0x63F8EF53698FBD2EULL,
		0x4549FE9E696D7275ULL,
		0xEC75D947E8BF74F5ULL,
		0x8B1AF0B0FDEB1A39ULL,
		0x3290AAD3E4075356ULL,
		0xAF90F304688660CDULL,
		0x6D03F167511D91F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7330F4E61EE5CA9AULL,
		0x716E49E92593882BULL,
		0x5F31157C10BA634FULL,
		0x41843432AEC865AAULL,
		0xFFFAB40A5305DF15ULL,
		0x0CF9BFFB42CBD11DULL,
		0xA36822E89C62E9EBULL,
		0x864A5F85B2F0D57DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73CD4907DEF2C6DULL,
		0x663FEA324CA62AC3ULL,
		0x3455DA7462F8D350ULL,
		0x42D5E1A2E3624A9EULL,
		0xFB76D46F86CCB66BULL,
		0x55BE7B860BB63549ULL,
		0x5D3832F35BFDDDD9ULL,
		0x1BA8D5A01349C909ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABF42055A0F69E2DULL,
		0x0B2E5FB6D8ED5D67ULL,
		0x2ADB3B07ADC18FFFULL,
		0xFEAE528FCB661B0CULL,
		0x0483DF9ACC3928A9ULL,
		0xB73B447537159BD4ULL,
		0x462FEFF540650C11ULL,
		0x6AA189E59FA70C74ULL
	}};
	sign = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x80614C5BE204B799ULL,
		0x7783AECEB4E6A758ULL,
		0x4C49FB740020EAD2ULL,
		0xC2FBE6B12EF40F91ULL,
		0x30CF9C7062F1E787ULL,
		0xB6C545CC056B264AULL,
		0xA3CEDA4929FC0E5AULL,
		0x9D5004A49B9B4EE2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE985C96A28F241A5ULL,
		0x616E44697D49B46DULL,
		0x7DCC168556F45BACULL,
		0x4AF5CE25246920FBULL,
		0x105DEC88C67FF652ULL,
		0x274B465A04B79983ULL,
		0x428E252C291F479FULL,
		0xFDF26AE8714CEEA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96DB82F1B91275F4ULL,
		0x16156A65379CF2EAULL,
		0xCE7DE4EEA92C8F26ULL,
		0x7806188C0A8AEE95ULL,
		0x2071AFE79C71F135ULL,
		0x8F79FF7200B38CC7ULL,
		0x6140B51D00DCC6BBULL,
		0x9F5D99BC2A4E603EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB4F579CE10FD6BC6ULL,
		0x936A39230B16350FULL,
		0xCF035397EF9042CFULL,
		0xAE395F68FCCDE825ULL,
		0x2364857C8A1A458BULL,
		0x9B74DF0C8C8181ECULL,
		0x81C4EA36E200F6E0ULL,
		0x733CEBE6C6720753ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA973A9C4A44E301ULL,
		0x9693E77E49D36A63ULL,
		0x90AA6BF2B7B302A6ULL,
		0x32605B9E1DE12959ULL,
		0xA06AFFF879842602ULL,
		0x06B631586EA0C06AULL,
		0x843759587C80CD8CULL,
		0x16D2B2CE58C2639EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA5E3F31C6B888C5ULL,
		0xFCD651A4C142CAABULL,
		0x3E58E7A537DD4028ULL,
		0x7BD903CADEECBECCULL,
		0x82F9858410961F89ULL,
		0x94BEADB41DE0C181ULL,
		0xFD8D90DE65802954ULL,
		0x5C6A39186DAFA3B4ULL
	}};
	sign = 0;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x854D31B85329FFAAULL,
		0x95C6E718579483E5ULL,
		0x56FC125A30C5B9D7ULL,
		0x64947AD0B47BCAF5ULL,
		0xEC6406E1BC7C34BCULL,
		0x452085D7F63D57BDULL,
		0x4759E44CC6AB93ECULL,
		0x74C9FD0177E0A80EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x331C0B15CA29354DULL,
		0x813214C0182F7A3EULL,
		0x0A697391A948F8B1ULL,
		0xF8F04124E24BDA91ULL,
		0xA4D192778ECAF555ULL,
		0x29F0B855D210D60DULL,
		0xC4507737360EACE9ULL,
		0xC5EB66FAAE90681AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x523126A28900CA5DULL,
		0x1494D2583F6509A7ULL,
		0x4C929EC8877CC126ULL,
		0x6BA439ABD22FF064ULL,
		0x4792746A2DB13F66ULL,
		0x1B2FCD82242C81B0ULL,
		0x83096D15909CE703ULL,
		0xAEDE9606C9503FF3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0C483EFC52A0F046ULL,
		0xA3E0B2DCE2C58D05ULL,
		0xEBCCD11D657C21EBULL,
		0xCC6B29FC0C9477EFULL,
		0x11029DB7FB99EB44ULL,
		0x8E12CBA338E93F60ULL,
		0x6655E95B71950BC9ULL,
		0xDB6ED33601CD0683ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA917152C2AE22665ULL,
		0xBFF7074ECA4748EDULL,
		0x9D02B5C66D44AFEBULL,
		0x4C77C74FFF13D771ULL,
		0x7BF68827D32488E3ULL,
		0x96D8F354C125F8C1ULL,
		0x8F1096B45BC9E09DULL,
		0xAD935D363BDF75E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x633129D027BEC9E1ULL,
		0xE3E9AB8E187E4417ULL,
		0x4ECA1B56F83771FFULL,
		0x7FF362AC0D80A07EULL,
		0x950C159028756261ULL,
		0xF739D84E77C3469EULL,
		0xD74552A715CB2B2BULL,
		0x2DDB75FFC5ED909DULL
	}};
	sign = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3652A7125340296ULL,
		0x617532EE2E76521DULL,
		0xC81457A256E0F8E9ULL,
		0x9F8F501DD88159E7ULL,
		0xEAD3879E51843E53ULL,
		0x99BF7D818278A0FBULL,
		0x8A60A4EBE5D7A2CCULL,
		0x2C11CE92E9F0B174ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DEE3511A49DFC54ULL,
		0x23A25191771E0EF0ULL,
		0x3E635C29F69A938AULL,
		0x8971494991702546ULL,
		0xF836D23465A55CA2ULL,
		0x05F6AE4287635207ULL,
		0xE8C40901065B8D62ULL,
		0x495EF7A4CE3FDC2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD576F55F80960642ULL,
		0x3DD2E15CB758432DULL,
		0x89B0FB786046655FULL,
		0x161E06D4471134A1ULL,
		0xF29CB569EBDEE1B1ULL,
		0x93C8CF3EFB154EF3ULL,
		0xA19C9BEADF7C156AULL,
		0xE2B2D6EE1BB0D549ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x79AB3BBA7A6106CDULL,
		0xBF5F701F0ADC9535ULL,
		0x535B2D9A91C18FDBULL,
		0xFD38453852C09C00ULL,
		0x88799C42E199D226ULL,
		0x2AD8508218360924ULL,
		0xA5B5234A3B044261ULL,
		0x90F6E3BCD3D303ECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF29C14FCDD306DULL,
		0x83167D0F746AE35FULL,
		0xB7800C1915C4353CULL,
		0x4D596E712E30E45BULL,
		0x28F41AC61D484588ULL,
		0x24DFD31C0FDA1382ULL,
		0xCD557976C7150622ULL,
		0xE2D2A050A449A056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19B89FA57D83D660ULL,
		0x3C48F30F9671B1D6ULL,
		0x9BDB21817BFD5A9FULL,
		0xAFDED6C7248FB7A4ULL,
		0x5F85817CC4518C9EULL,
		0x05F87D66085BF5A2ULL,
		0xD85FA9D373EF3C3FULL,
		0xAE24436C2F896395ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE4EE12639878F7D7ULL,
		0x7FCF14DD4783820AULL,
		0x22D46AB350D8148FULL,
		0x8646206268D3410DULL,
		0x43D73B3909DE5FC7ULL,
		0x24C20DAFE41E025BULL,
		0x0C673444C0CFC918ULL,
		0x50885AC02BCE1BFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBACC2D737A8F74AULL,
		0x67A20E320B1B37AFULL,
		0xE26FBDE03B198366ULL,
		0xD916929B71B661CDULL,
		0x47CF58B6767012CAULL,
		0x4A8E3EEA7FDF0843ULL,
		0x0A715B70511CEDFDULL,
		0xE436CC6BFFEB12B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9414F8C60D0008DULL,
		0x182D06AB3C684A5AULL,
		0x4064ACD315BE9129ULL,
		0xAD2F8DC6F71CDF3FULL,
		0xFC07E282936E4CFCULL,
		0xDA33CEC5643EFA17ULL,
		0x01F5D8D46FB2DB1AULL,
		0x6C518E542BE3094AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2EBFC3B020C08265ULL,
		0x218D7D82783D7A38ULL,
		0x9637E13DB5614303ULL,
		0x72890771B8AE409BULL,
		0x7077F310449729F5ULL,
		0xEB9A52E7E59758BDULL,
		0x85D79D18187191D7ULL,
		0x07F7C88020CA8BB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F5C180434E70CDULL,
		0x5E0A46800534F4F2ULL,
		0xE8E035E283C5A9CCULL,
		0x63521D4FFA3BBAD8ULL,
		0x332B52AB82017F54ULL,
		0x8C4EDE16CC1CF48DULL,
		0xAD2F299887DDA977ULL,
		0x6D2894A359D0A72EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CCA022FDD721198ULL,
		0xC383370273088546ULL,
		0xAD57AB5B319B9936ULL,
		0x0F36EA21BE7285C2ULL,
		0x3D4CA064C295AAA1ULL,
		0x5F4B74D1197A6430ULL,
		0xD8A8737F9093E860ULL,
		0x9ACF33DCC6F9E485ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6C630DC2A7E584FULL,
		0x0557327B1AE5A72FULL,
		0xFB26A893384F7632ULL,
		0xB83736577841042AULL,
		0x3FB1F03FA38DB4BDULL,
		0x79C9F468BD2D8C4CULL,
		0x37C48A6EBB83CA3AULL,
		0x615D2A75D89CCD94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8ADEB7B6B1E1D5ULL,
		0x75C0385D581BC308ULL,
		0xD11EE2B68811378EULL,
		0xDB7C4BEF48C38D73ULL,
		0xF98DAFF696252029ULL,
		0x29095E407FD65128ULL,
		0x5F9CA85F5C238F3AULL,
		0x170286D00F45720CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A3B522473CC767AULL,
		0x8F96FA1DC2C9E427ULL,
		0x2A07C5DCB03E3EA3ULL,
		0xDCBAEA682F7D76B7ULL,
		0x462440490D689493ULL,
		0x50C096283D573B23ULL,
		0xD827E20F5F603B00ULL,
		0x4A5AA3A5C9575B87ULL
	}};
	sign = 0;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x996108B9C7B9BB48ULL,
		0xBBD14EB30EB8B138ULL,
		0x7BEA62194828C315ULL,
		0xAB7DA709C9D310C0ULL,
		0x515E655C6F8D801CULL,
		0x2DEE5E76573E4E38ULL,
		0x64E437A5371D7E99ULL,
		0x1D9D3452424199CCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1EB3DCEB5B7BA67ULL,
		0x89EC8B087FF8E787ULL,
		0x70B9639CD704C634ULL,
		0xCDA082F702A9B27EULL,
		0x826ABEB2339D1B2FULL,
		0x7E1EBE7DD25F82B0ULL,
		0xF9E9151F7E5745E5ULL,
		0xA45B6C564E008420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD775CAEB120200E1ULL,
		0x31E4C3AA8EBFC9B0ULL,
		0x0B30FE7C7123FCE1ULL,
		0xDDDD2412C7295E42ULL,
		0xCEF3A6AA3BF064ECULL,
		0xAFCF9FF884DECB87ULL,
		0x6AFB2285B8C638B3ULL,
		0x7941C7FBF44115ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFE45D4436479C30ULL,
		0x809C5D79A09A6B7FULL,
		0xA95C4F3E044D0968ULL,
		0x5DA6D11E249DA91EULL,
		0xB69ED7DC3029D803ULL,
		0x5EB78B9EA9234715ULL,
		0xA1909B6C6DFBDC9DULL,
		0x9E9D4ADAF6D07EADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8E87A4A0C4967FULL,
		0x12F68914BB19132AULL,
		0x78B9D3D0084A0ED1ULL,
		0xF408C831340ACF22ULL,
		0x24B30DF89CFECF17ULL,
		0x120E47FA3BDCFF88ULL,
		0xA7D51B2DB1CE5487ULL,
		0x409B8682FE76CBA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0355D59F958305B1ULL,
		0x6DA5D464E5815855ULL,
		0x30A27B6DFC02FA97ULL,
		0x699E08ECF092D9FCULL,
		0x91EBC9E3932B08EBULL,
		0x4CA943A46D46478DULL,
		0xF9BB803EBC2D8816ULL,
		0x5E01C457F859B30AULL
	}};
	sign = 0;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1FA73246AC60C096ULL,
		0xD7303AB1CF440D83ULL,
		0x15110862C6CDC11DULL,
		0x343B76A05EDA76DDULL,
		0x7748670C4EF46341ULL,
		0x222DFF8779403452ULL,
		0xE06132074AB3446BULL,
		0xACA35FAF01350DC0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x96E480DF06B93717ULL,
		0x14863D40367D5394ULL,
		0x115BFFAF62886575ULL,
		0xAFB4D32C4ACD6E03ULL,
		0x5AA09343C1EB204EULL,
		0x753FD31CB4CF1059ULL,
		0xD74B54198F219860ULL,
		0xD956EF0CDE1DC380ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88C2B167A5A7897FULL,
		0xC2A9FD7198C6B9EEULL,
		0x03B508B364455BA8ULL,
		0x8486A374140D08DAULL,
		0x1CA7D3C88D0942F2ULL,
		0xACEE2C6AC47123F9ULL,
		0x0915DDEDBB91AC0AULL,
		0xD34C70A223174A40ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CCB937951EC2211ULL,
		0x65DEDC3D28FBD334ULL,
		0x3E0EEF0DF8B62EAFULL,
		0x4E43AFDD17699306ULL,
		0x6281DCA676960DB9ULL,
		0x59A2BEAE954ECF43ULL,
		0x6742844D2EEB08F3ULL,
		0xAD6E4956C76816D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B2672FFAA9D0C2ULL,
		0xCC6126BD5AC76E2DULL,
		0x9177A6C476EE644CULL,
		0xE68A97B7FBC925ACULL,
		0xAEE82179E2F6D207ULL,
		0x68025C626E46A631ULL,
		0x8CCBC21589A92186ULL,
		0xFD0EAF546AD674F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79192C495742514FULL,
		0x997DB57FCE346506ULL,
		0xAC97484981C7CA62ULL,
		0x67B918251BA06D59ULL,
		0xB399BB2C939F3BB1ULL,
		0xF1A0624C27082911ULL,
		0xDA76C237A541E76CULL,
		0xB05F9A025C91A1E3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C24F69D87D9438FULL,
		0xBA0BD42499B60B81ULL,
		0x6A7DC2ABEB2E5AFBULL,
		0x9F2CA11C6A268492ULL,
		0x15E155D0A2CE0D23ULL,
		0xF7EAF5A6E8B5D931ULL,
		0x124386CB94D04AD6ULL,
		0xABFFD1FE5B4E845CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE8D435B19BD8298ULL,
		0x5E83E42276F4022AULL,
		0x02857A5124C1AB34ULL,
		0xAEC66135CD6FE799ULL,
		0xF9635DE99E28C148ULL,
		0x26E1809901488F7EULL,
		0x78E5524DC2042E55ULL,
		0x4E50BA77F9CF9D9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD97B3426E1BC0F7ULL,
		0x5B87F00222C20956ULL,
		0x67F8485AC66CAFC7ULL,
		0xF0663FE69CB69CF9ULL,
		0x1C7DF7E704A54BDAULL,
		0xD109750DE76D49B2ULL,
		0x995E347DD2CC1C81ULL,
		0x5DAF1786617EE6C1ULL
	}};
	sign = 0;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x87F1A391A7A4854DULL,
		0x9E5879301CDBDACCULL,
		0x49ECD2625855476AULL,
		0xE5A0CFBC9331D516ULL,
		0xBEE7F46F071393E2ULL,
		0xAF43136D6102C83CULL,
		0x1132DFCC1B1C56B3ULL,
		0x63F28C0D3174035AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x527B668B1760772FULL,
		0xF1E7CF6A1586B5E0ULL,
		0x53FCAE38F15C3A6AULL,
		0x7BDE708369F7834DULL,
		0x15E9869F26D21705ULL,
		0x45D45831DC2006FDULL,
		0x49EC11BF4AB77D6EULL,
		0x94ECE47EAED56D36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35763D0690440E1EULL,
		0xAC70A9C6075524ECULL,
		0xF5F0242966F90CFFULL,
		0x69C25F39293A51C8ULL,
		0xA8FE6DCFE0417CDDULL,
		0x696EBB3B84E2C13FULL,
		0xC746CE0CD064D945ULL,
		0xCF05A78E829E9623ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F8CC27C8EB9344FULL,
		0x690D9F1099797124ULL,
		0xE02BD42AAB0A8023ULL,
		0xD18F45D54C54CECEULL,
		0x9A88F3CC5BC295A6ULL,
		0x4E7797E3C228C0D6ULL,
		0x1E5E94DAE7CEA107ULL,
		0x53B620487A107BEDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9CE1CBC35287F7ULL,
		0xFA0628E79104630DULL,
		0x2814F8D05C52422EULL,
		0x227D3DA82F1ED170ULL,
		0xD6EDCE0D2405A567ULL,
		0x9B5D2078C58B46C5ULL,
		0x9DB3F70A0C211E96ULL,
		0xBE6FC24380E3A59CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34EFE0B0CB66AC58ULL,
		0x6F07762908750E17ULL,
		0xB816DB5A4EB83DF4ULL,
		0xAF12082D1D35FD5EULL,
		0xC39B25BF37BCF03FULL,
		0xB31A776AFC9D7A10ULL,
		0x80AA9DD0DBAD8270ULL,
		0x95465E04F92CD650ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x02F8EE498DD3D616ULL,
		0xC74F58AB4902C8F0ULL,
		0xBC18125B6D2E7B21ULL,
		0xC279620233B2F260ULL,
		0x67159B12639EFA51ULL,
		0x62C627064F2F033EULL,
		0xE17DCE030FB74446ULL,
		0x2837689DADF90D88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26BA77CC5B079B03ULL,
		0x13A2476560AF793AULL,
		0x7D6F36F74E4C67A5ULL,
		0x89F67105849379E2ULL,
		0x9573D11C6EE124E5ULL,
		0xEAA601EFEB451DE0ULL,
		0xA9B6EC920DB77520ULL,
		0x1B58AB9A439BDDD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC3E767D32CC3B13ULL,
		0xB3AD1145E8534FB5ULL,
		0x3EA8DB641EE2137CULL,
		0x3882F0FCAF1F787EULL,
		0xD1A1C9F5F4BDD56CULL,
		0x7820251663E9E55DULL,
		0x37C6E17101FFCF25ULL,
		0x0CDEBD036A5D2FB0ULL
	}};
	sign = 0;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7356159566E25765ULL,
		0x1DEF7BF72E1AC1DDULL,
		0x00D0F7C8DCB776AEULL,
		0xD2EC12309802FAC0ULL,
		0x915FF83803726264ULL,
		0x2D898E5D2F71300BULL,
		0xD21B985E849C9BD1ULL,
		0x6951BBE6A6610C70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8257816E24E6013DULL,
		0xABAFFF0820F8811FULL,
		0xD2B6E88125F4AEA1ULL,
		0x7CC0E8B80DF1FAFBULL,
		0xBE62DC1408278E94ULL,
		0x50CB3EE46CAE6452ULL,
		0x5CE0C29CAF168BBCULL,
		0x667A13BAF758A1C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0FE942741FC5628ULL,
		0x723F7CEF0D2240BDULL,
		0x2E1A0F47B6C2C80CULL,
		0x562B29788A10FFC4ULL,
		0xD2FD1C23FB4AD3D0ULL,
		0xDCBE4F78C2C2CBB8ULL,
		0x753AD5C1D5861014ULL,
		0x02D7A82BAF086AAEULL
	}};
	sign = 0;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD66C1D5D9A2407D5ULL,
		0xFA1F9626578F0AB4ULL,
		0x986A079C25599413ULL,
		0x7A68079862998B61ULL,
		0xD75142AF80115ECCULL,
		0x9F4F0EC1457A5696ULL,
		0x371463BBEF3F194CULL,
		0x9D342A92B6759A6FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0925987F9149D86ULL,
		0xC4FB993EA1F01AA2ULL,
		0x6507644697D7F882ULL,
		0x6505F47C4D87D8A0ULL,
		0x20EE08D57BAE08A1ULL,
		0xD6045E0CACCB1CD1ULL,
		0x5EAD06619C52AB66ULL,
		0x3084BECBC74A3003ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15D9C3D5A10F6A4FULL,
		0x3523FCE7B59EF012ULL,
		0x3362A3558D819B91ULL,
		0x1562131C1511B2C1ULL,
		0xB66339DA0463562BULL,
		0xC94AB0B498AF39C5ULL,
		0xD8675D5A52EC6DE5ULL,
		0x6CAF6BC6EF2B6A6BULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0DB4931FFA2F8D66ULL,
		0xA244D7C542DC7D70ULL,
		0x610C3CA3BBC13D4BULL,
		0xD1C41B1F69D14275ULL,
		0xD19C0520E1EC5465ULL,
		0x7B13A2CB9BB960DEULL,
		0xE4BC611273308754ULL,
		0xC258E51AED06AAA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB936A17A58AFD81EULL,
		0xB8F781B83B46FCCBULL,
		0x2123AE8B74E5A349ULL,
		0x93671B3AECFDE45DULL,
		0x7F67064650E06E40ULL,
		0xA711E82C4278E2BCULL,
		0x428FCD48A3C377EEULL,
		0x6B6E78BB02962B3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x547DF1A5A17FB548ULL,
		0xE94D560D079580A4ULL,
		0x3FE88E1846DB9A01ULL,
		0x3E5CFFE47CD35E18ULL,
		0x5234FEDA910BE625ULL,
		0xD401BA9F59407E22ULL,
		0xA22C93C9CF6D0F65ULL,
		0x56EA6C5FEA707F63ULL
	}};
	sign = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x549A16753CF6A216ULL,
		0x543AA176C96F80D5ULL,
		0xEAA0DBF4B62A502CULL,
		0x0C1704DA70E0F99BULL,
		0x39A675A5FF04167AULL,
		0xDBEFC187C4B4A577ULL,
		0xBFD17D1A484719BEULL,
		0x6B909EBA3DBE88F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A2290B29DAEBDDULL,
		0xD637E52F4EECBA06ULL,
		0x9178408BD15E100DULL,
		0xA0DA0DBD7569B862ULL,
		0xE4A1D8C5B534582FULL,
		0x4E8D5F18136266F4ULL,
		0xDF0F67018F75C1C6ULL,
		0x5E2A1596DFC0784CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DF7ED6A131BB639ULL,
		0x7E02BC477A82C6CFULL,
		0x59289B68E4CC401EULL,
		0x6B3CF71CFB774139ULL,
		0x55049CE049CFBE4AULL,
		0x8D62626FB1523E82ULL,
		0xE0C21618B8D157F8ULL,
		0x0D6689235DFE10ACULL
	}};
	sign = 0;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E76E4F6F3A50988ULL,
		0xA6289742F04A9555ULL,
		0x73A6AB0AE702E841ULL,
		0x64C56CBF9FA6C605ULL,
		0x4F23FF732719DAAEULL,
		0x42C51788355EFEB9ULL,
		0xF08ABF09EC7369A0ULL,
		0x3D2D27C6ED51D19DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D965362E363A6A4ULL,
		0x6A5BCB12E7B1F469ULL,
		0x84F4EFC02AB3F742ULL,
		0xC900716C6690860DULL,
		0x3220F968386F0369ULL,
		0xC366EECB0C0322FBULL,
		0x418D06ED09011FE8ULL,
		0xD1CA899235D498E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0E09194104162E4ULL,
		0x3BCCCC300898A0EBULL,
		0xEEB1BB4ABC4EF0FFULL,
		0x9BC4FB5339163FF7ULL,
		0x1D03060AEEAAD744ULL,
		0x7F5E28BD295BDBBEULL,
		0xAEFDB81CE37249B7ULL,
		0x6B629E34B77D38B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A45CB4897818404ULL,
		0x7ED2ACADB553021EULL,
		0xA6BCAF1433F03126ULL,
		0x4C291E11FD6BC185ULL,
		0xA84C86CC7BA68AE1ULL,
		0x6025936AD84F36F1ULL,
		0x0A9A6BEC7AE8C005ULL,
		0xF7403B9A5C2258B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE46FEBA880960156ULL,
		0x834473E1136D746CULL,
		0xEBB1A20C94A6077BULL,
		0xB9492C70695F6D8BULL,
		0xFEB1FC7FA1C51ED6ULL,
		0xD261AF61FA9F5643ULL,
		0x0E51CB4BB78E1FB2ULL,
		0x1BFF184F38ECF66BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95D5DFA016EB82AEULL,
		0xFB8E38CCA1E58DB1ULL,
		0xBB0B0D079F4A29AAULL,
		0x92DFF1A1940C53F9ULL,
		0xA99A8A4CD9E16C0AULL,
		0x8DC3E408DDAFE0ADULL,
		0xFC48A0A0C35AA052ULL,
		0xDB41234B2335624AULL
	}};
	sign = 0;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x225F2D0DE8AA0DB8ULL,
		0x31258FF6A9725F1DULL,
		0x0583F783A03F7B72ULL,
		0xB741CE66121F461FULL,
		0x12223E400D3F41FFULL,
		0x89130205935D25BAULL,
		0x381EE7FB46B195C3ULL,
		0x9CD4E4FA20DB9828ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x72FFA3C09CFF7237ULL,
		0xE9C6601214E3FE31ULL,
		0xD30366BB2DC90E03ULL,
		0x94579DF3861F713CULL,
		0xDD9616D1B0E49380ULL,
		0xBF849120EACABDBDULL,
		0xEB971850C83FB9B6ULL,
		0x1C0A327F24746059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF5F894D4BAA9B81ULL,
		0x475F2FE4948E60EBULL,
		0x328090C872766D6EULL,
		0x22EA30728BFFD4E2ULL,
		0x348C276E5C5AAE7FULL,
		0xC98E70E4A89267FCULL,
		0x4C87CFAA7E71DC0CULL,
		0x80CAB27AFC6737CEULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x675E65FBCB1620C6ULL,
		0xAF93EE66340FF0B3ULL,
		0xAF7970C1E04C0182ULL,
		0x421DA32108C77B3EULL,
		0x94D9C0902165A5F9ULL,
		0xB55761DE937FED42ULL,
		0x9E6A779620AE5495ULL,
		0x1E2CD15E84655F56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC25F3E3E64ED8642ULL,
		0x0644948031CBA76DULL,
		0x721928B65B717A81ULL,
		0xB895B990FEFB1FAFULL,
		0x26789FCD84A5372BULL,
		0x178F872E6CBBCCBCULL,
		0x025C752B2AEB55E5ULL,
		0x283E795BD7B7E9F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4FF27BD66289A84ULL,
		0xA94F59E602444945ULL,
		0x3D60480B84DA8701ULL,
		0x8987E99009CC5B8FULL,
		0x6E6120C29CC06ECDULL,
		0x9DC7DAB026C42086ULL,
		0x9C0E026AF5C2FEB0ULL,
		0xF5EE5802ACAD7564ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF2513BABE31C05DEULL,
		0x46D7198F8C137745ULL,
		0x1D5FEF6278807A5AULL,
		0x7691950C4967B8E2ULL,
		0x036E536F7CE3FF4AULL,
		0x16F2B94711720DC2ULL,
		0xA875F8770D262CAAULL,
		0x6484D64F9D22AE61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FBC770F4ED12E9ULL,
		0x6CC361A65318D50EULL,
		0x8980042B263685E4ULL,
		0x59095CA450A33558ULL,
		0xE6986F805FC85B5AULL,
		0x4EBC44F90A163D7EULL,
		0x773BB7E09248CA92ULL,
		0x4C84CA03772A69B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F55743AEE2EF2F5ULL,
		0xDA13B7E938FAA237ULL,
		0x93DFEB375249F475ULL,
		0x1D883867F8C48389ULL,
		0x1CD5E3EF1D1BA3F0ULL,
		0xC836744E075BD043ULL,
		0x313A40967ADD6217ULL,
		0x18000C4C25F844ABULL
	}};
	sign = 0;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9BC8109E04DBB6ABULL,
		0xD6B92893043619C3ULL,
		0x12A53FBEC67F1F90ULL,
		0x3BBE4F7FE2857553ULL,
		0x3783B33B56FF31F4ULL,
		0xA42C5548371904CCULL,
		0xA8015F1C1218357EULL,
		0x42F82E05F8F9A102ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34CAD643260C9071ULL,
		0x7EC6872035A63A55ULL,
		0x69BFF32D8D36B76BULL,
		0x8610379CC04A93F7ULL,
		0xC20DFE440E24E6C5ULL,
		0x0D073755B92805E9ULL,
		0x30CCDE5252A83F0AULL,
		0xF02683D1F3D2B1ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66FD3A5ADECF263AULL,
		0x57F2A172CE8FDF6EULL,
		0xA8E54C9139486825ULL,
		0xB5AE17E3223AE15BULL,
		0x7575B4F748DA4B2EULL,
		0x97251DF27DF0FEE2ULL,
		0x773480C9BF6FF674ULL,
		0x52D1AA340526EF57ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6A59061388F79521ULL,
		0xF2BCED1370B3164DULL,
		0xBC974A00340BA875ULL,
		0x5E0DB0CF38E02904ULL,
		0x0A3931212CB77D01ULL,
		0x806F38A95804DB55ULL,
		0x67A754D7B6D5C3D0ULL,
		0x46DC0770EBE60778ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F99353BAE2B0292ULL,
		0x41E8B0C8EF6DBADBULL,
		0x248A2102A3D55BFBULL,
		0xB16006E4F975A31BULL,
		0x3E11CFB615611FEDULL,
		0xD1A652AF9440F116ULL,
		0xA9EDAC07A7991B4DULL,
		0x8C031B67DBF43E9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ABFD0D7DACC928FULL,
		0xB0D43C4A81455B72ULL,
		0x980D28FD90364C7AULL,
		0xACADA9EA3F6A85E9ULL,
		0xCC27616B17565D13ULL,
		0xAEC8E5F9C3C3EA3EULL,
		0xBDB9A8D00F3CA882ULL,
		0xBAD8EC090FF1C8D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0634E53649DF653FULL,
		0xFA4A34FF1FDB7E3CULL,
		0x5546D63E0B6D9A88ULL,
		0x65B7F775E380F4B0ULL,
		0xBBFAFD3CBC651570ULL,
		0x3079CAA6A011F70BULL,
		0xB85EE51E5DF3C81BULL,
		0xDAFC88D02BE00849ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC740FA7F1813DDULL,
		0x8E8D65D9608CB14DULL,
		0x8FE55226B3914E52ULL,
		0x9EA59F316925ADEFULL,
		0x1F6F3D000493979CULL,
		0x15B4E4307B7E1635ULL,
		0x5704A594F5FA2F99ULL,
		0x75328BE1DE22C809ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF76DA43BCAC75162ULL,
		0x6BBCCF25BF4ECCEEULL,
		0xC561841757DC4C36ULL,
		0xC71258447A5B46C0ULL,
		0x9C8BC03CB7D17DD3ULL,
		0x1AC4E6762493E0D6ULL,
		0x615A3F8967F99882ULL,
		0x65C9FCEE4DBD4040ULL
	}};
	sign = 0;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30910C8C3858260BULL,
		0x9B1EA39959DD56A7ULL,
		0x1C851148AF772D5DULL,
		0xEC992851A14F8645ULL,
		0xCBBD3EE3712BDDE5ULL,
		0x4A1B37B6FB6DCAF4ULL,
		0x75C8EB09DF34A2A9ULL,
		0xBED4A4D3A60F8509ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F74CCC638575F41ULL,
		0x277945197ECEA79FULL,
		0xB58074C210C19C77ULL,
		0xA70D149C8AEDFA39ULL,
		0xCF4187E2A510F059ULL,
		0x157F5D8014ECE5C0ULL,
		0x26FB2496C159EA01ULL,
		0xF48741D72E285B8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x211C3FC60000C6CAULL,
		0x73A55E7FDB0EAF08ULL,
		0x67049C869EB590E6ULL,
		0x458C13B516618C0BULL,
		0xFC7BB700CC1AED8CULL,
		0x349BDA36E680E533ULL,
		0x4ECDC6731DDAB8A8ULL,
		0xCA4D62FC77E7297CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x97533A7279DF8F2BULL,
		0xA76D08E8B10E3C67ULL,
		0x27C715A0344CB3F6ULL,
		0x67F236954DD253DBULL,
		0x6F945C0237F0993CULL,
		0xFFE0A97B7E557496ULL,
		0xA6837F12C1F4A7D9ULL,
		0x125541F4C550260EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x133F9F780F2C3920ULL,
		0xE5D8BDA95F53AEE5ULL,
		0x5E46A4EDA1A38D4DULL,
		0x1896062AD938B87AULL,
		0xE7FD7CC5445F9ECAULL,
		0x9B4423CB79701C3CULL,
		0x61EC8DBBC166646BULL,
		0x964F393627240C8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84139AFA6AB3560BULL,
		0xC1944B3F51BA8D82ULL,
		0xC98070B292A926A8ULL,
		0x4F5C306A74999B60ULL,
		0x8796DF3CF390FA72ULL,
		0x649C85B004E55859ULL,
		0x4496F157008E436EULL,
		0x7C0608BE9E2C1983ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x809F13EFA91BD689ULL,
		0xE7BA958F96DB34BBULL,
		0xB7D89757DF65EA49ULL,
		0x6EA3726A80CC5CD8ULL,
		0x6162A762F9617F72ULL,
		0xDAEF2ECF646C7954ULL,
		0x9F87E0F63213DC4EULL,
		0x248F83618ECDA29DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x70EACE7063FFB816ULL,
		0x35D16F85F8A40F90ULL,
		0xF16A692BA906A066ULL,
		0xA4B7487E89418D6EULL,
		0x7CE24E219328F379ULL,
		0xA840CDF68197D233ULL,
		0x4ED9436A755E808AULL,
		0xFD125A660FB99165ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FB4457F451C1E73ULL,
		0xB1E926099E37252BULL,
		0xC66E2E2C365F49E3ULL,
		0xC9EC29EBF78ACF69ULL,
		0xE480594166388BF8ULL,
		0x32AE60D8E2D4A720ULL,
		0x50AE9D8BBCB55BC4ULL,
		0x277D28FB7F141138ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9E4A661457D1DC2ULL,
		0x289C5605D4B850A1ULL,
		0x8BB0AE82C2F127C6ULL,
		0xAEAAC34438257479ULL,
		0x28414332C541CCC4ULL,
		0x7F99D22B1848B50BULL,
		0xDE0DED362DEAC19DULL,
		0xC9C690EE911F203EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2642EF4FF9F53494ULL,
		0x9EE63473B242372DULL,
		0xE7FD93FA67FA2B2AULL,
		0x9EEDDD1AFA1012B9ULL,
		0x9EC4B24FD650938BULL,
		0x1C5DD187EA4B015AULL,
		0x1DEFA54EB0458FDAULL,
		0x81D311CFC9762D82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3A1B7114B87E92EULL,
		0x89B6219222761974ULL,
		0xA3B31A885AF6FC9BULL,
		0x0FBCE6293E1561BFULL,
		0x897C90E2EEF13939ULL,
		0x633C00A32DFDB3B0ULL,
		0xC01E47E77DA531C3ULL,
		0x47F37F1EC7A8F2BCULL
	}};
	sign = 0;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC37057AA6CED0A8ULL,
		0x7005AED7F392A9CEULL,
		0x7B41DCFF18ACB13FULL,
		0x35B4B5CAAFEEE7CDULL,
		0x960266E4283719CBULL,
		0xAFCA35D3616B2053ULL,
		0x15E9508D03EE051AULL,
		0x9BD9685C60466863ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30CDD43BB4C8A058ULL,
		0xA06B64972028E52BULL,
		0x63E576E114109A39ULL,
		0x4E564720F6843E13ULL,
		0xAF7EFD04309CA847ULL,
		0x5AB7C6DB1F1E80C1ULL,
		0x2F56937C6D1ED840ULL,
		0xB5FAF72C08E5B55CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB69313EF2063050ULL,
		0xCF9A4A40D369C4A3ULL,
		0x175C661E049C1705ULL,
		0xE75E6EA9B96AA9BAULL,
		0xE68369DFF79A7183ULL,
		0x55126EF8424C9F91ULL,
		0xE692BD1096CF2CDAULL,
		0xE5DE71305760B306ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6299CDF997746BF6ULL,
		0xE244A1D325312BDDULL,
		0xF2EEB64247E441DFULL,
		0xA0C48E5E8DC4D8F7ULL,
		0xA0DD4AB1A4F501E3ULL,
		0x138940A6D4F4E7D3ULL,
		0xA08993BEC5FE7232ULL,
		0xCBA10F3D6530101CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09133D1803C5A3EULL,
		0x50B3A54D65B96C89ULL,
		0x3419B62B88A93BAEULL,
		0x8E4E91FFFE5D9F37ULL,
		0xCB5CC2BF96BF3EB8ULL,
		0x108EBAA530212C42ULL,
		0x24DF428C8D87DBB5ULL,
		0x7EC01E4AE1DC4DA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2089A28173811B8ULL,
		0x9190FC85BF77BF53ULL,
		0xBED50016BF3B0631ULL,
		0x1275FC5E8F6739C0ULL,
		0xD58087F20E35C32BULL,
		0x02FA8601A4D3BB90ULL,
		0x7BAA51323876967DULL,
		0x4CE0F0F28353C279ULL
	}};
	sign = 0;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB67401C550F62C0ULL,
		0xBABDEAB3BCC105E4ULL,
		0x7214D09DD72BBD5BULL,
		0xA193AACD1629F8BCULL,
		0x2FBC35ACFCE8B947ULL,
		0x8E0AF2A456E7A47FULL,
		0x02F97463EDDA1907ULL,
		0x857D8940245F980AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEF60D22E7DAA2DULL,
		0xDD5713FBDACD6060ULL,
		0x73DEEBDF32D42410ULL,
		0xF304D7E5FC94F511ULL,
		0x93170659E72A9CBEULL,
		0xA1B055C18521CBCBULL,
		0x6BFFBCEE97732460ULL,
		0x60ABBCAC7494BC79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E77DF4A2691B893ULL,
		0xDD66D6B7E1F3A584ULL,
		0xFE35E4BEA457994AULL,
		0xAE8ED2E7199503AAULL,
		0x9CA52F5315BE1C88ULL,
		0xEC5A9CE2D1C5D8B3ULL,
		0x96F9B7755666F4A6ULL,
		0x24D1CC93AFCADB90ULL
	}};
	sign = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE96EC45B691C58EAULL,
		0x68BCD0E0DD52C17FULL,
		0x1077D92ED9021E77ULL,
		0x92871D86CFE61652ULL,
		0xE9F16BB2EE1B1286ULL,
		0x5FE689798596AB78ULL,
		0x16C88FCB13B3765FULL,
		0xF2FA9BF4F59C1FF1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E4D71E30E9AEE1ULL,
		0xF3F48DA8971FE4AEULL,
		0x794DF81F7C19D6E3ULL,
		0x08DC872CFAF0B4B7ULL,
		0xB8323EA5CC5B680AULL,
		0x7301A5262C234C41ULL,
		0x24EC033476D24BEAULL,
		0xC3A9EFBF4D8BF7E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F89ED3D3832AA09ULL,
		0x74C843384632DCD1ULL,
		0x9729E10F5CE84793ULL,
		0x89AA9659D4F5619AULL,
		0x31BF2D0D21BFAA7CULL,
		0xECE4E45359735F37ULL,
		0xF1DC8C969CE12A74ULL,
		0x2F50AC35A810280CULL
	}};
	sign = 0;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB1F985E0B9835A3CULL,
		0x4D30A4FE0E80CD67ULL,
		0x0CADAE0C152CA8B2ULL,
		0x5D4FBFF162052276ULL,
		0x4E0B10D1C777354AULL,
		0xDE581A63F0FF66F4ULL,
		0x96DE05BE35E5494CULL,
		0xAAE3F8B2195E9CC6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8048CD237159BA4EULL,
		0xDA2466C9CD477F69ULL,
		0x565E348575F3F788ULL,
		0x678933A32DA6C3B7ULL,
		0xC42DECDB56AA61ABULL,
		0x2C2015542BF7DAFBULL,
		0x4516B45CD7BF8F23ULL,
		0x8CA4763A102E8777ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B0B8BD48299FEEULL,
		0x730C3E3441394DFEULL,
		0xB64F79869F38B129ULL,
		0xF5C68C4E345E5EBEULL,
		0x89DD23F670CCD39EULL,
		0xB238050FC5078BF8ULL,
		0x51C751615E25BA29ULL,
		0x1E3F82780930154FULL
	}};
	sign = 0;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB6A1040554C029A8ULL,
		0x7280A65D6B90D241ULL,
		0xA61D58630CDFEFBCULL,
		0x2A72CCA9AC1F1CB8ULL,
		0x0ED66926EF56B883ULL,
		0xAEA6303A9605ED8CULL,
		0xD1FAD5D04CDB8120ULL,
		0xB98D7E1F6862B6D0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD8F17BD639A620ULL,
		0x23E4B844D592958CULL,
		0x35D165C42FCB2681ULL,
		0x94A79C812A782658ULL,
		0x96812586C66AD8C1ULL,
		0x1AA6F8D6D3C5AA65ULL,
		0x0EDCE1D0DBBB66A9ULL,
		0x8FAE746C7C65F339ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58C812897E868388ULL,
		0x4E9BEE1895FE3CB5ULL,
		0x704BF29EDD14C93BULL,
		0x95CB302881A6F660ULL,
		0x785543A028EBDFC1ULL,
		0x93FF3763C2404326ULL,
		0xC31DF3FF71201A77ULL,
		0x29DF09B2EBFCC397ULL
	}};
	sign = 0;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA4711353F2BD4628ULL,
		0xED29F4EF49E2E1D8ULL,
		0x08BCD09199BD75D6ULL,
		0xAC9F1D6185C5BA62ULL,
		0x6DFEC5D711EC411AULL,
		0xF07F2B84ECB59E7EULL,
		0x22FDCAEB18432C4EULL,
		0xB2FC0D44B5291CFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD71C3E2E60B4317ULL,
		0x8D0B7EF8E27FDC3CULL,
		0xCAFDC65A6427DA78ULL,
		0x1B81B9606208DD67ULL,
		0x54266799D885D0C2ULL,
		0x95904F6C6D389218ULL,
		0xFFDEF73DD8453318ULL,
		0xE7E7776EA2F0A983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6FF4F710CB20311ULL,
		0x601E75F66763059BULL,
		0x3DBF0A3735959B5EULL,
		0x911D640123BCDCFAULL,
		0x19D85E3D39667058ULL,
		0x5AEEDC187F7D0C66ULL,
		0x231ED3AD3FFDF936ULL,
		0xCB1495D61238737AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x810F260273CB751FULL,
		0x203A22F1519F3044ULL,
		0x8C95FDDA4A21DE9CULL,
		0xB76EF8FEB51718DFULL,
		0x935905BFAA004119ULL,
		0xA1E9EE71AF1BECB5ULL,
		0x043BA6900EF20D70ULL,
		0xE1B30A3405521B7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9107A4191FA78822ULL,
		0xA1D18D9EDCDF16F9ULL,
		0x33ED3D65FCD6E40CULL,
		0xFCA411A0E860ADD2ULL,
		0x9EEA247F363D4C43ULL,
		0x5508357C1B20BDA1ULL,
		0x3DA46D4B8C5C09D0ULL,
		0x460000B96595895CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF00781E95423ECFDULL,
		0x7E68955274C0194AULL,
		0x58A8C0744D4AFA8FULL,
		0xBACAE75DCCB66B0DULL,
		0xF46EE14073C2F4D5ULL,
		0x4CE1B8F593FB2F13ULL,
		0xC6973944829603A0ULL,
		0x9BB3097A9FBC921EULL
	}};
	sign = 0;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60B1DD826AC35493ULL,
		0xA6E6E0E5745E4E87ULL,
		0x9CECD7773DF4A01CULL,
		0x2515835A35DDFCA3ULL,
		0x7E29283131615118ULL,
		0x5447DB1B0181CD86ULL,
		0x108C0C0A2EFD16B7ULL,
		0x02B83F58E6698E67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F53DDA11F20D7B1ULL,
		0x4325D5DC897C2246ULL,
		0x89D3BD3CF1836C08ULL,
		0x73D24F7492F97792ULL,
		0x1B821EB12170F0DEULL,
		0x3F9C766F94262A14ULL,
		0xFAD754A006544091ULL,
		0x928F65478CF95B54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x115DFFE14BA27CE2ULL,
		0x63C10B08EAE22C41ULL,
		0x13191A3A4C713414ULL,
		0xB14333E5A2E48511ULL,
		0x62A709800FF06039ULL,
		0x14AB64AB6D5BA372ULL,
		0x15B4B76A28A8D626ULL,
		0x7028DA1159703312ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F8806E43DAB7401ULL,
		0x9C90550E66E1A893ULL,
		0x3AC3EA8A43AD9E5EULL,
		0x703FD34448C68AF5ULL,
		0xABC55AB5E71840F7ULL,
		0x5E2C69D762AD0BBEULL,
		0x48AFCBC572C3D35CULL,
		0x19EC8E0AB9D48942ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1666DE64BF22AD58ULL,
		0xB8788E1B2DA22F68ULL,
		0x69F91CA88EFE83E7ULL,
		0x497062E8FABA865BULL,
		0x892B11886875C051ULL,
		0xF594B6AFC982AC6DULL,
		0x3C36FD48A8970147ULL,
		0x470B2FB3A91CB284ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3921287F7E88C6A9ULL,
		0xE417C6F3393F792BULL,
		0xD0CACDE1B4AF1A76ULL,
		0x26CF705B4E0C0499ULL,
		0x229A492D7EA280A6ULL,
		0x6897B327992A5F51ULL,
		0x0C78CE7CCA2CD214ULL,
		0xD2E15E5710B7D6BEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6ED0F2659DE0F65FULL,
		0x81EC9C2E62157CBBULL,
		0xDAA9641C65B4A7D9ULL,
		0x6E7E20349CD3DD41ULL,
		0xC97235B0FD964AC5ULL,
		0x871D541265D0BA3AULL,
		0x33BFE3500197CDB1ULL,
		0xCB7FBCE44EE13F8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71D81892EF4B6D2ULL,
		0x2EE9F1E9FB64CE9BULL,
		0x4620D8EF6288F8C3ULL,
		0x382EAC771334D082ULL,
		0x42D83B330B607FC7ULL,
		0x59EB4EB9078D227DULL,
		0xD7C52916CC09DFE4ULL,
		0x4705212AF702FA0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7B370DC6EEC3F8DULL,
		0x5302AA4466B0AE1FULL,
		0x94888B2D032BAF16ULL,
		0x364F73BD899F0CBFULL,
		0x8699FA7DF235CAFEULL,
		0x2D3205595E4397BDULL,
		0x5BFABA39358DEDCDULL,
		0x847A9BB957DE4582ULL
	}};
	sign = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD70EB443C061B503ULL,
		0xACAB0951B5B7DCF0ULL,
		0x296170D784F91EB8ULL,
		0xD0361275627729B5ULL,
		0x880B42F545E5C3B7ULL,
		0x025A0B27CC094B86ULL,
		0xCAC3A3B4F700694DULL,
		0x6B7D2426B9DA6F29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF48FA6A5AA3D8FEULL,
		0xD845BEB498467C86ULL,
		0x243A9CAB3EDFEE95ULL,
		0x35E1DE7C3376B0C9ULL,
		0xFD774385E24C5D5BULL,
		0xD844D868AA3E4273ULL,
		0xC3D4CC2722F0F190ULL,
		0xF728B1269B8ED3C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17C5B9D965BDDC05ULL,
		0xD4654A9D1D71606AULL,
		0x0526D42C46193022ULL,
		0x9A5433F92F0078ECULL,
		0x8A93FF6F6399665CULL,
		0x2A1532BF21CB0912ULL,
		0x06EED78DD40F77BCULL,
		0x745473001E4B9B68ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x683D5CDED1A20916ULL,
		0xCC6171F459B50EFCULL,
		0xE3453CCC8DAEFC6AULL,
		0xCD8604F7936702D7ULL,
		0xA46588D2430043B7ULL,
		0xED48CF04B6799580ULL,
		0xF80DD130033F6382ULL,
		0x5BACCF3A0609EB49ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x718A8D4DB5801BB1ULL,
		0x104AF43272CEAF11ULL,
		0xCCBE49BE7CD50173ULL,
		0xD66CBA0DE108197EULL,
		0x2D2136C200497646ULL,
		0xC0C568DF12F3B3F5ULL,
		0xDF962BEFFF94C04DULL,
		0x30E36C0633BCE10DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6B2CF911C21ED65ULL,
		0xBC167DC1E6E65FEAULL,
		0x1686F30E10D9FAF7ULL,
		0xF7194AE9B25EE959ULL,
		0x7744521042B6CD70ULL,
		0x2C836625A385E18BULL,
		0x1877A54003AAA335ULL,
		0x2AC96333D24D0A3CULL
	}};
	sign = 0;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC83B88B047883734ULL,
		0x35CF3467B443329FULL,
		0xF7D113AF98CB6D15ULL,
		0x2A9E7AB8EF25FB60ULL,
		0x5EA404E25976E709ULL,
		0x818A18D32799A0AAULL,
		0x553456383AB88176ULL,
		0x5A027719FDFA0309ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46EA9D7E92FA69E8ULL,
		0xE06C38BC1538F422ULL,
		0x3D956011A62CDBAEULL,
		0xEAED4BDC442CCE17ULL,
		0xCAAA11ACB48009D2ULL,
		0xBF5BD20E61D7D265ULL,
		0xF669EA4CECB577EBULL,
		0x5D41179C850084A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8150EB31B48DCD4CULL,
		0x5562FBAB9F0A3E7DULL,
		0xBA3BB39DF29E9166ULL,
		0x3FB12EDCAAF92D49ULL,
		0x93F9F335A4F6DD36ULL,
		0xC22E46C4C5C1CE44ULL,
		0x5ECA6BEB4E03098AULL,
		0xFCC15F7D78F97E66ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9CF9F3C8E7377D29ULL,
		0xB6EF6918894F101DULL,
		0x534EAFD3A057E70DULL,
		0x87B66DE34A22D560ULL,
		0x07D98AA643E1229EULL,
		0x22ACF2A7E4CB3BBDULL,
		0xA62C0740231522DBULL,
		0xB4121D25E2335B74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CA23310B7DDBDCULL,
		0x3EF0ADD7FA9AE5C1ULL,
		0x08BE84809545BD7EULL,
		0x4D61B85C36238E27ULL,
		0x8A0B3B0F52D83C49ULL,
		0x0FB80118339CED32ULL,
		0x306B6F229FF0F4B4ULL,
		0xF38634EB159296E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C2FD097DBB9A14DULL,
		0x77FEBB408EB42A5CULL,
		0x4A902B530B12298FULL,
		0x3A54B58713FF4739ULL,
		0x7DCE4F96F108E655ULL,
		0x12F4F18FB12E4E8AULL,
		0x75C0981D83242E27ULL,
		0xC08BE83ACCA0C490ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E2F5BCC1207B7C6ULL,
		0x81F127CD5F12B940ULL,
		0xC302044AADA1D6A0ULL,
		0x92B6B9D970AA2D3AULL,
		0xFB0726A994BD5CCEULL,
		0xFFE2A74263754265ULL,
		0x7F9538CAEE09B41AULL,
		0x5051ED1BBF57A3C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7AB167FE1634D6CULL,
		0xCD23407127D2212DULL,
		0x4134C2DF379EA5AFULL,
		0xACC7D24E67ABFDCDULL,
		0x612698B29199E961ULL,
		0xA7C3C2C0B853A30CULL,
		0x58F3EFE4E00267ACULL,
		0xCD7D5AB85E95721EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7684454C30A46A5AULL,
		0xB4CDE75C37409812ULL,
		0x81CD416B760330F0ULL,
		0xE5EEE78B08FE2F6DULL,
		0x99E08DF70323736CULL,
		0x581EE481AB219F59ULL,
		0x26A148E60E074C6EULL,
		0x82D4926360C231ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C3526716494A534ULL,
		0x542746C85E48E1D5ULL,
		0x4D42BBF3702A4D5DULL,
		0xE50ABE396C498257ULL,
		0xEE731AACFD98D88CULL,
		0xF64C490021777EB9ULL,
		0x9F67E846003AAEDEULL,
		0xCA1EB58CE688C405ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D28F91D862DCECULL,
		0xE707FD63F10E486BULL,
		0xA22DF055278CBD3FULL,
		0xDF16EDFD838C3A5BULL,
		0x97459D2CB14250B5ULL,
		0x2996F2FB8E5FCDEBULL,
		0xA8F13E55A21949D4ULL,
		0x82F4DB23D3BE65D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x856296DF8C31C848ULL,
		0x6D1F49646D3A9969ULL,
		0xAB14CB9E489D901DULL,
		0x05F3D03BE8BD47FBULL,
		0x572D7D804C5687D7ULL,
		0xCCB556049317B0CEULL,
		0xF676A9F05E21650AULL,
		0x4729DA6912CA5E2FULL
	}};
	sign = 0;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x479CECB53BF1A9EBULL,
		0xDD1F88FBC2358C1AULL,
		0xF331C7A149C92A54ULL,
		0xAE1C079D73E15423ULL,
		0x04F43731759C7485ULL,
		0x206E8E6BAF0F832CULL,
		0x1F02F6AF10943929ULL,
		0x2F5EFCED8E91D163ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41DE8F679D7CD67ULL,
		0xCFD7D11B7910FE0FULL,
		0x2C78DDE913FBE1A0ULL,
		0xC3F7EDC03C5A3124ULL,
		0xE34BED7A087FD865ULL,
		0xA73E597C8DD61033ULL,
		0x8E155C45C069489DULL,
		0x07E9F0613FD957DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x937F03BEC219DC84ULL,
		0x0D47B7E049248E0AULL,
		0xC6B8E9B835CD48B4ULL,
		0xEA2419DD378722FFULL,
		0x21A849B76D1C9C1FULL,
		0x793034EF213972F8ULL,
		0x90ED9A69502AF08BULL,
		0x27750C8C4EB87985ULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF174AF0DDCDF873CULL,
		0x9211CD4CB746654BULL,
		0x8D7848DC833FF7B7ULL,
		0xE93922D1F3AB0FB1ULL,
		0x7749C051F6940BE6ULL,
		0x94CDEC53F657119EULL,
		0x1E9DB6A6B04AD18BULL,
		0xD499E2A5420B6122ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8FF1C674C8A1B63ULL,
		0xFE00F3A217F6C8DCULL,
		0x68D534D38A647DDFULL,
		0xDFEF985A4FD3D6A6ULL,
		0x446E90C353406D64ULL,
		0xAD6232235EA9A641ULL,
		0x12B2076568F153B7ULL,
		0x152061500CF56C82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x387592A690556BD9ULL,
		0x9410D9AA9F4F9C6FULL,
		0x24A31408F8DB79D7ULL,
		0x09498A77A3D7390BULL,
		0x32DB2F8EA3539E82ULL,
		0xE76BBA3097AD6B5DULL,
		0x0BEBAF4147597DD3ULL,
		0xBF7981553515F4A0ULL
	}};
	sign = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6000ADBC39B74159ULL,
		0x24EA182ED6A3C021ULL,
		0xACAA08E5FB675903ULL,
		0x7DFBB6B01905B1BDULL,
		0x386F10B8067A32FCULL,
		0xC1F5376610ACFCF5ULL,
		0x7B25FCF8B52F70DAULL,
		0xC5219F01B8D2DB36ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA20DE560CC14EF8ULL,
		0xD6F31DE70C64E36AULL,
		0x63CEC0CA0B4B5B2AULL,
		0xEDA80806684C6AE9ULL,
		0xF3B874DF792E1C68ULL,
		0x5289ED0FEC8446AEULL,
		0x1B9B405FA13F37B7ULL,
		0x5D9AF6FB23D40A87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85DFCF662CF5F261ULL,
		0x4DF6FA47CA3EDCB6ULL,
		0x48DB481BF01BFDD8ULL,
		0x9053AEA9B0B946D4ULL,
		0x44B69BD88D4C1693ULL,
		0x6F6B4A562428B646ULL,
		0x5F8ABC9913F03923ULL,
		0x6786A80694FED0AFULL
	}};
	sign = 0;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA8AC590C6C2C1BEULL,
		0x6BB71EE5F265FBA1ULL,
		0x80EA87A5B6DF2405ULL,
		0x05AD007CFBC6F5B6ULL,
		0xC34BF278842DA5B4ULL,
		0xE6871DFFDC38B2AAULL,
		0x52DA1F084C8D447CULL,
		0xCCDF66735489543AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB146852E25820033ULL,
		0x0EC6BA3D914259E8ULL,
		0x130E3CA57413C8FCULL,
		0xC9BEB4ECE27F52CFULL,
		0xF61FB26CB29AD311ULL,
		0xFCFE4B2B7938DC0BULL,
		0x82D66F4464F982F6ULL,
		0xF0A561B7D13BD775ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29444062A140C18BULL,
		0x5CF064A86123A1B9ULL,
		0x6DDC4B0042CB5B09ULL,
		0x3BEE4B901947A2E7ULL,
		0xCD2C400BD192D2A2ULL,
		0xE988D2D462FFD69EULL,
		0xD003AFC3E793C185ULL,
		0xDC3A04BB834D7CC4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5AD73BA6F91CBC1ULL,
		0x1658ACB02B3F7FBAULL,
		0x3F71C5C228CE6A13ULL,
		0x4DD73426D9F6E7A1ULL,
		0x177242914A471CECULL,
		0x45ADEA67572A2707ULL,
		0xA70864A7A2404ADDULL,
		0x606AC905F4B0BB5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FB26A5412492A0ULL,
		0xCBF1FEBE7D71C873ULL,
		0xF26681AC5461A15EULL,
		0xF404DB50FDB15413ULL,
		0xFA81146C5B32BF82ULL,
		0xB6A1282FBC95A532ULL,
		0x570E59D8A6DD4A5DULL,
		0x639A77F76EE63DC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13B24D152E6D3921ULL,
		0x4A66ADF1ADCDB747ULL,
		0x4D0B4415D46CC8B4ULL,
		0x59D258D5DC45938DULL,
		0x1CF12E24EF145D69ULL,
		0x8F0CC2379A9481D4ULL,
		0x4FFA0ACEFB63007FULL,
		0xFCD0510E85CA7D94ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x991FDF27703353C9ULL,
		0x4546BF0453D4A728ULL,
		0x4BF8012967EFB761ULL,
		0xB899DC543CD7E15FULL,
		0xC5F720A5EEA36E25ULL,
		0x3AB19A9354CA2A99ULL,
		0xFF1A60D0534CFBF3ULL,
		0x1EB6A023ABF994CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C16F8CC079059CBULL,
		0xC03D7CE011CB5C93ULL,
		0x5456B29047E1657DULL,
		0x91868DE06CB39D46ULL,
		0x62DF9CDECAA5395CULL,
		0x92B45C33BF316CBAULL,
		0xA17F44C50EEB2F74ULL,
		0x03A54FA1D7C908AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD08E65B68A2F9FEULL,
		0x8509422442094A94ULL,
		0xF7A14E99200E51E3ULL,
		0x27134E73D0244418ULL,
		0x631783C723FE34C9ULL,
		0xA7FD3E5F9598BDDFULL,
		0x5D9B1C0B4461CC7EULL,
		0x1B115081D4308C20ULL
	}};
	sign = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93250CCF92F50F5FULL,
		0x0D14D7AFC1B27461ULL,
		0x0DD545BEAC3D311CULL,
		0x3098B5FFE03D4D83ULL,
		0xF947A1B980F3888BULL,
		0x71B31060E9D1187CULL,
		0x33EC7C95D5C9E5CCULL,
		0x8D6622A728B7E454ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x960C7BCED55B9ECFULL,
		0x9F6512D8AC4D4E08ULL,
		0x6CFC3AE588F73B4BULL,
		0xF945D84FBBEDC3C1ULL,
		0x2609AE9F536BEC24ULL,
		0xEABDC91057158447ULL,
		0x047EA66BC2BAB817ULL,
		0xB9064D56C588F530ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD189100BD997090ULL,
		0x6DAFC4D715652658ULL,
		0xA0D90AD92345F5D0ULL,
		0x3752DDB0244F89C1ULL,
		0xD33DF31A2D879C66ULL,
		0x86F5475092BB9435ULL,
		0x2F6DD62A130F2DB4ULL,
		0xD45FD550632EEF24ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF483C606B96CF5A3ULL,
		0xEA1080A030FECF81ULL,
		0x9F21CAB0EBE846E8ULL,
		0x4483E60F6DC101ACULL,
		0x5B7C62CE7F297E4FULL,
		0x8FD8A6724E9CF0DAULL,
		0x8DB5973CF254E91CULL,
		0x0855D01C29EF170BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06D54B2980E6D989ULL,
		0x24622C8FFE865DECULL,
		0xD3F202A83AA5DFE3ULL,
		0x21222C749E4B8B26ULL,
		0x6273E3E875E5FA07ULL,
		0xC668F2225AD557C8ULL,
		0x43E29093F67FF160ULL,
		0x62B3153523E5CD74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDAE7ADD38861C1AULL,
		0xC5AE541032787195ULL,
		0xCB2FC808B1426705ULL,
		0x2361B99ACF757685ULL,
		0xF9087EE609438448ULL,
		0xC96FB44FF3C79911ULL,
		0x49D306A8FBD4F7BBULL,
		0xA5A2BAE706094997ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3C1FEA11AFD80670ULL,
		0xC67BBEA5A289596EULL,
		0xDB9E8CD70C2DDD4AULL,
		0x3A7B0CC225D8546AULL,
		0xA4C9256AC471D30DULL,
		0xBD1F55AEB3857681ULL,
		0x0257D28E31469921ULL,
		0x7BF08AAFF2EB9FD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7A57EE2069C0B5ULL,
		0x6068F5C73989A23AULL,
		0x9BF597DCC6739252ULL,
		0x6F921E522D8E4DE2ULL,
		0x206ABE68F73F8134ULL,
		0x0DAEFA707BA3AB0DULL,
		0x029F91DFE6BA9915ULL,
		0x2EDC2F7FE8EFBA34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DA592238F6E45BBULL,
		0x6612C8DE68FFB733ULL,
		0x3FA8F4FA45BA4AF8ULL,
		0xCAE8EE6FF84A0688ULL,
		0x845E6701CD3251D8ULL,
		0xAF705B3E37E1CB74ULL,
		0xFFB840AE4A8C000CULL,
		0x4D145B3009FBE5A4ULL
	}};
	sign = 0;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A8D46C4C8DA3769ULL,
		0x0C9F04A2334BAA97ULL,
		0x0BB6CCD62CF088FBULL,
		0x507D98741230AA58ULL,
		0x78696D84B58AC6ACULL,
		0x9E40F63695B66CEEULL,
		0x70A9C9ABE6DDA6B8ULL,
		0x7871AE3BA0F18DACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6352824ECAADB6B3ULL,
		0x40796B957D446CEEULL,
		0x9084EF566DAAD442ULL,
		0x4AE2EF85EAE51130ULL,
		0x3FB235269B721611ULL,
		0x8C7BC2127A34EE24ULL,
		0x04698D0BB2E7078EULL,
		0xEDB166F8A7D45D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB73AC475FE2C80B6ULL,
		0xCC25990CB6073DA8ULL,
		0x7B31DD7FBF45B4B8ULL,
		0x059AA8EE274B9927ULL,
		0x38B7385E1A18B09BULL,
		0x11C534241B817ECAULL,
		0x6C403CA033F69F2AULL,
		0x8AC04742F91D3038ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6F42F8C5D9BCA4FAULL,
		0xE1981CFDAE226060ULL,
		0x290DF61EE901343DULL,
		0x397703403258CAD3ULL,
		0x526CFA28DBA9149EULL,
		0x04608104A0643491ULL,
		0x5651A12586C9DA89ULL,
		0x44B11CEB9C04B2CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD023B90BF5C7A77ULL,
		0x37DDFE1D701378EEULL,
		0x7CA9EF78C19E2577ULL,
		0x87B10AB49B337F8FULL,
		0x89F4D75E5176FB26ULL,
		0x94E6140AE26F599DULL,
		0x519685D7BF438C6FULL,
		0x0ED2194948DD0458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9240BD351A602A83ULL,
		0xA9BA1EE03E0EE771ULL,
		0xAC6406A627630EC6ULL,
		0xB1C5F88B97254B43ULL,
		0xC87822CA8A321977ULL,
		0x6F7A6CF9BDF4DAF3ULL,
		0x04BB1B4DC7864E19ULL,
		0x35DF03A25327AE72ULL
	}};
	sign = 0;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8199E711564F5551ULL,
		0xCEC853A3D88D393EULL,
		0xFFCD7F59AFEEF28EULL,
		0x9DABCEC21919E6A0ULL,
		0x7072AF0E7F2EEDBDULL,
		0xD6EB8F0CFF3B4459ULL,
		0x530482B95E0115CEULL,
		0x4A5FB5AF5FDCE040ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB03988208D0E45ULL,
		0x48628FA23772ED56ULL,
		0xAD165441EFF106F3ULL,
		0x9EEBC3248C047826ULL,
		0x556D47A75A0AD7DCULL,
		0xE247DA60F2922592ULL,
		0xD90A820EB51D92FCULL,
		0x1147D7BA5EFEBF09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42E9AD8935C2470CULL,
		0x8665C401A11A4BE8ULL,
		0x52B72B17BFFDEB9BULL,
		0xFEC00B9D8D156E7AULL,
		0x1B056767252415E0ULL,
		0xF4A3B4AC0CA91EC7ULL,
		0x79FA00AAA8E382D1ULL,
		0x3917DDF500DE2136ULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x34B7395DE7A2454DULL,
		0x9977F8FDE59F2734ULL,
		0x019927C8E59676EEULL,
		0x9CEE7587BBDB95F9ULL,
		0xDAA5B68501022FBFULL,
		0xA6BD645AFB01F9D7ULL,
		0xE2998EE532DA8045ULL,
		0xFDD5D106DCAA006DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46AE10043F647067ULL,
		0x6B5530A0F6E02415ULL,
		0xA29265764FB89DB5ULL,
		0xAE1DD89B9CE03EC2ULL,
		0x51A5476D9F5EFAA4ULL,
		0x20E99025353D4B64ULL,
		0xFF811204EE40D0AFULL,
		0x127DDA6F9A626092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE092959A83DD4E6ULL,
		0x2E22C85CEEBF031EULL,
		0x5F06C25295DDD939ULL,
		0xEED09CEC1EFB5736ULL,
		0x89006F1761A3351AULL,
		0x85D3D435C5C4AE73ULL,
		0xE3187CE04499AF96ULL,
		0xEB57F69742479FDAULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9794A55186908499ULL,
		0xC90E8498292859A2ULL,
		0xE8D6F0968B5E17A2ULL,
		0xBB5DBAC213A69C3DULL,
		0x65114DCE079213ADULL,
		0xA3BC4FABC197351DULL,
		0x014EE5F45ACE1EE8ULL,
		0x068D7750C251BC2DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF1554BD164B1BEULL,
		0x40CB90A1E67040D6ULL,
		0x1F69671C58C7F4FBULL,
		0x344CCC82B7FA17C3ULL,
		0x50CA644A2E0487E0ULL,
		0xEFD2E80C9BC68977ULL,
		0x623DDC624B56E903ULL,
		0x0E83ACFB9E25570AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CA35005B52BD2DBULL,
		0x8842F3F642B818CCULL,
		0xC96D897A329622A7ULL,
		0x8710EE3F5BAC847AULL,
		0x1446E983D98D8BCDULL,
		0xB3E9679F25D0ABA6ULL,
		0x9F1109920F7735E4ULL,
		0xF809CA55242C6522ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD95CDA8E2EDEAA1FULL,
		0x7164AAF9572FBBCEULL,
		0x35E295CC501FECB3ULL,
		0xECEE05CDA84EEDFCULL,
		0xFB792D7C4AABA0F7ULL,
		0x4662458B57107CDEULL,
		0xF8ABEF46D047DFA0ULL,
		0xC6D5724A685FE0E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB846AD0709F1F5EULL,
		0xB693DBD4F144762EULL,
		0x516B31D9E562D48AULL,
		0x9BF7768541C39EE5ULL,
		0xDB1043FF1B1765FDULL,
		0x3864FCC8AB6CB405ULL,
		0x211479D4E01B582BULL,
		0x3C93CCF3BB370094ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DD86FBDBE3F8AC1ULL,
		0xBAD0CF2465EB45A0ULL,
		0xE47763F26ABD1828ULL,
		0x50F68F48668B4F16ULL,
		0x2068E97D2F943AFAULL,
		0x0DFD48C2ABA3C8D9ULL,
		0xD7977571F02C8775ULL,
		0x8A41A556AD28E051ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7152E888E2414CE5ULL,
		0x8BF191D91EB1AF6CULL,
		0x7D0033122E6902CDULL,
		0xF0839902F38D44DAULL,
		0xDB11C03C737C58AAULL,
		0x96B1D06979ED5C99ULL,
		0xCE116795B657FA01ULL,
		0x3C6869C8562407B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A297FEE3A952C61ULL,
		0xB350FD615F905A3DULL,
		0xCC03774C0D531580ULL,
		0x31EA575755753006ULL,
		0xE2FE2ED1A0603515ULL,
		0x9275AB8A4C6ED3FCULL,
		0x6A1E59D009623D99ULL,
		0x8610F2140F1B8E51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2729689AA7AC2084ULL,
		0xD8A09477BF21552FULL,
		0xB0FCBBC62115ED4CULL,
		0xBE9941AB9E1814D3ULL,
		0xF813916AD31C2395ULL,
		0x043C24DF2D7E889CULL,
		0x63F30DC5ACF5BC68ULL,
		0xB65777B447087965ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x554AB4EB90E6176AULL,
		0x3E7A8FDA651CE155ULL,
		0xDCFD6EBDCAC74D25ULL,
		0x1C5B7F615AA8D05CULL,
		0xE06D77C7C022AE30ULL,
		0xCFBB4FC343C9C33CULL,
		0xDFF98145FD10D2B1ULL,
		0x2470D8287DD97FB6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E00EBFE62901ADEULL,
		0xFD3818DA4C69DCE5ULL,
		0x4D4AAE5076579A8FULL,
		0xE684A373ACE6A27CULL,
		0x25F6773A6E46414EULL,
		0x3F207AC3F8106A76ULL,
		0xD016DC19C159D870ULL,
		0xA9AC5854E47D3D0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0749C8ED2E55FC8CULL,
		0x4142770018B30470ULL,
		0x8FB2C06D546FB295ULL,
		0x35D6DBEDADC22DE0ULL,
		0xBA77008D51DC6CE1ULL,
		0x909AD4FF4BB958C6ULL,
		0x0FE2A52C3BB6FA41ULL,
		0x7AC47FD3995C42ACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x617278AEB2D4C1E5ULL,
		0xBCF28D3761B92C0FULL,
		0x06FAC241FBD49777ULL,
		0xC20A37403E03BF99ULL,
		0x0A8BE14D6634FD1FULL,
		0xC1F6FEE4DA41D23FULL,
		0xA6AAC9AB1B52C0B2ULL,
		0xD6ACB3BA82F6716DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1ED80EAF8D0AB1ULL,
		0x4F8EC8A75EFA00A8ULL,
		0xA2CA10D0D9ECD527ULL,
		0x17652130AEB61EB4ULL,
		0x87302C9AF23F8DA0ULL,
		0x5664592E00019ECCULL,
		0xAA6B8892E2F8E283ULL,
		0x9BF0A790EC3A4233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7353A0A00347B734ULL,
		0x6D63C49002BF2B66ULL,
		0x6430B17121E7C250ULL,
		0xAAA5160F8F4DA0E4ULL,
		0x835BB4B273F56F7FULL,
		0x6B92A5B6DA403372ULL,
		0xFC3F41183859DE2FULL,
		0x3ABC0C2996BC2F39ULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x599A0025C6E67481ULL,
		0xF4B5EC822D50113CULL,
		0x492613CE5ED04843ULL,
		0xD4416B2641D32453ULL,
		0x739E7E8D539A08F1ULL,
		0xAF849F41A3F478CDULL,
		0xB805AB8B5212FA33ULL,
		0xE475411B4026478CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0918170DE86BF2EULL,
		0x98C2A8748FF47D65ULL,
		0x06F2899D97DB4F43ULL,
		0x8EEAC089AB845D6FULL,
		0x0916DB10583460D8ULL,
		0x0F81A1D600260F57ULL,
		0x901ADF6A2909FAB1ULL,
		0x363C2F079F273334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69087EB4E85FB553ULL,
		0x5BF3440D9D5B93D6ULL,
		0x42338A30C6F4F900ULL,
		0x4556AA9C964EC6E4ULL,
		0x6A87A37CFB65A819ULL,
		0xA002FD6BA3CE6976ULL,
		0x27EACC212908FF82ULL,
		0xAE391213A0FF1458ULL
	}};
	sign = 0;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7CE98598D4DAFB28ULL,
		0x98EEE0B95F9BDB95ULL,
		0x316F33546AEEF724ULL,
		0x688C729A1BD56C00ULL,
		0xFF436EE14D34F5DDULL,
		0xA45AE2C0C1EA3B09ULL,
		0xE2029B8A13CD36ABULL,
		0x91571EED201F88F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B681F5F09B64B4EULL,
		0xC0C3DA1D6ACD461EULL,
		0x516EBD5B4B1D979EULL,
		0x111CC66D8F8ACE53ULL,
		0xA4332808007E8282ULL,
		0x4680461C1B117FA9ULL,
		0x3424A381555A926CULL,
		0x89C0B10F61256202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1816639CB24AFDAULL,
		0xD82B069BF4CE9576ULL,
		0xE00075F91FD15F85ULL,
		0x576FAC2C8C4A9DACULL,
		0x5B1046D94CB6735BULL,
		0x5DDA9CA4A6D8BB60ULL,
		0xADDDF808BE72A43FULL,
		0x07966DDDBEFA26F2ULL
	}};
	sign = 0;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4D1DC0E10A9B91FAULL,
		0x1007D35AA7573FD2ULL,
		0x2ACB4AC3636A3B9CULL,
		0x0297C46D75CDFD3FULL,
		0xDC1B32B86AFB52C9ULL,
		0xBEDD807DE53E99C3ULL,
		0xA2A67C4D40318B66ULL,
		0xA851DA8AA5832760ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7483441DBE4702D7ULL,
		0x2847384AAB87D8F6ULL,
		0x02EE41D599B0F593ULL,
		0x9E423BF21CAFDB7EULL,
		0xAF947254559FDBA0ULL,
		0x0CBFB5C2161078A5ULL,
		0x6EF4B1A24C230EF9ULL,
		0xA681E61621C67088ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD89A7CC34C548F23ULL,
		0xE7C09B0FFBCF66DBULL,
		0x27DD08EDC9B94608ULL,
		0x6455887B591E21C1ULL,
		0x2C86C064155B7728ULL,
		0xB21DCABBCF2E211EULL,
		0x33B1CAAAF40E7C6DULL,
		0x01CFF47483BCB6D8ULL
	}};
	sign = 0;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCDEB98601651991CULL,
		0xC1BFEFE4DC6E2398ULL,
		0x24A5C44C15DA9215ULL,
		0xFC0F4324F21915B6ULL,
		0x30524BCEBB49828AULL,
		0x4EA145F0FA1EA545ULL,
		0x281D99028F8861E4ULL,
		0x869CF5C597EE47E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8967A53492121B3ULL,
		0xBBC8EAE65CBACC12ULL,
		0x754C249BCA30329AULL,
		0x2E00722A14228356ULL,
		0x8ADAE5CC0FB6A1FFULL,
		0x9DA17B910D51B461ULL,
		0x2762784EC1314D66ULL,
		0xE4C65AB1DACE2306ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5551E0CCD307769ULL,
		0x05F704FE7FB35785ULL,
		0xAF599FB04BAA5F7BULL,
		0xCE0ED0FADDF6925FULL,
		0xA5776602AB92E08BULL,
		0xB0FFCA5FECCCF0E3ULL,
		0x00BB20B3CE57147DULL,
		0xA1D69B13BD2024DEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8694CBA4A4322EEULL,
		0x25D578B5BFAB9999ULL,
		0x3EFBA383FF8C5E2AULL,
		0x6DB1EEA31A2CF518ULL,
		0x1023D67F97D201FEULL,
		0x1A5DB11E494BD7AFULL,
		0x0BD488E755604CBCULL,
		0xA058534C95E9E531ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B545879FA846E2ULL,
		0xF99B21B28933C69AULL,
		0x300F80F0590EB861ULL,
		0x1900DF0BEE44DA26ULL,
		0xF5E7E6B9F866B380ULL,
		0x06FC17944064CC9BULL,
		0x573E31A4D3F39F84ULL,
		0xB07563B5E7149839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02B40732AA9ADC0CULL,
		0x2C3A57033677D2FFULL,
		0x0EEC2293A67DA5C8ULL,
		0x54B10F972BE81AF2ULL,
		0x1A3BEFC59F6B4E7EULL,
		0x1361998A08E70B13ULL,
		0xB4965742816CAD38ULL,
		0xEFE2EF96AED54CF7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC38B3AE0B9D59114ULL,
		0x3BFC7E1990771F02ULL,
		0x50B54D1720997965ULL,
		0x00C298F60965C19CULL,
		0x068A427FE4A72AD7ULL,
		0x20D3FEA1172E97FFULL,
		0x2A2F915159B8220AULL,
		0x206EF1F5D68E82C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35C4AA478131F97ULL,
		0x45F8FE5D163FC9A8ULL,
		0x5817C41457C70D00ULL,
		0xF074D430A80FEAFEULL,
		0x16DA84D56F72F438ULL,
		0x7A674420C3FEC3E2ULL,
		0xF4E3C37BCB711369ULL,
		0xFFCB8EE02CF07378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE02EF03C41C2717DULL,
		0xF6037FBC7A375559ULL,
		0xF89D8902C8D26C64ULL,
		0x104DC4C56155D69DULL,
		0xEFAFBDAA7534369EULL,
		0xA66CBA80532FD41CULL,
		0x354BCDD58E470EA0ULL,
		0x20A36315A99E0F48ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFBACB8A94190B29CULL,
		0x7012EFBEC12EB4D5ULL,
		0xEB2EC6D59C61A179ULL,
		0x8C395AE2AF431BFAULL,
		0xE23E685D2F896C7BULL,
		0xC1321DAB2D33CF8DULL,
		0x86291F54F4C2DC12ULL,
		0x7067F9944DBD8E3EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x718E9454A208B97AULL,
		0xAB332D1ADC2F0639ULL,
		0x476BE9791B186C2DULL,
		0xC9043A9B47BE2F12ULL,
		0xAA3948826885DEAFULL,
		0xF7A3B35733DF1A88ULL,
		0x0CDB4EE271F5AE69ULL,
		0xB17BF3B49B798D67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A1E24549F87F922ULL,
		0xC4DFC2A3E4FFAE9CULL,
		0xA3C2DD5C8149354BULL,
		0xC33520476784ECE8ULL,
		0x38051FDAC7038DCBULL,
		0xC98E6A53F954B505ULL,
		0x794DD07282CD2DA8ULL,
		0xBEEC05DFB24400D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B6DD3D6756D55BEULL,
		0x81B80B1D480AF990ULL,
		0x14E9C4E764AFC8A3ULL,
		0xBD3A7D4AFA6B2EFCULL,
		0x2616C199A4F9D2CDULL,
		0xEC8B559B907C63E6ULL,
		0x7A1F8519805005FAULL,
		0x0385D66E2DDB9D3BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FE982704343D590ULL,
		0xCACE13F59420DAB2ULL,
		0x69544A42909CFF9FULL,
		0xDA6D85B5081F51A6ULL,
		0x7CFB2CFDAD5CC1CBULL,
		0xA7959AEF88279375ULL,
		0x45DBD554E82E17A0ULL,
		0xEF225AB761CFC73AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B8451663229802EULL,
		0xB6E9F727B3EA1EDEULL,
		0xAB957AA4D412C903ULL,
		0xE2CCF795F24BDD55ULL,
		0xA91B949BF79D1101ULL,
		0x44F5BAAC0854D070ULL,
		0x3443AFC49821EE5AULL,
		0x14637BB6CC0BD601ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2545CBE1421FF58DULL,
		0xEA6E25BE469EC9EFULL,
		0x291B7C286AEBE475ULL,
		0x2D0BF26B50A6F16DULL,
		0x7990099931C950FAULL,
		0x84785ADB318FD0C5ULL,
		0x3F52720EB04EA6D1ULL,
		0x8CEAD5D7798B54B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA59F051B2FC49BULL,
		0x73146F6F17E3BE1BULL,
		0x2E853A2B1A5940E6ULL,
		0x1AB87275E1FC954CULL,
		0x24763D1B37DCBABFULL,
		0xB5D35024B0E9CDD2ULL,
		0x3360A70DDD420D75ULL,
		0x153047E744828FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6A02CDC26F030F2ULL,
		0x7759B64F2EBB0BD3ULL,
		0xFA9641FD5092A38FULL,
		0x12537FF56EAA5C20ULL,
		0x5519CC7DF9EC963BULL,
		0xCEA50AB680A602F3ULL,
		0x0BF1CB00D30C995BULL,
		0x77BA8DF03508C4DEULL
	}};
	sign = 0;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7470B2789EF6DC32ULL,
		0xE9B11115CF8B22DFULL,
		0x5D722F48CAFE3A7AULL,
		0x877A79EE8913EA01ULL,
		0x34A2309AFC4DDFD8ULL,
		0x0E13B04C96A7ECBDULL,
		0xFE42E9D3E21A45CDULL,
		0x063938EEC7BD89E0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B7908710554E2BAULL,
		0x6073EA3AC705BF4BULL,
		0x9B7CBF46AB75F7B1ULL,
		0xF5AC3BDC126877A6ULL,
		0x27E8B5D68C84F063ULL,
		0xC8073F37BDE84365ULL,
		0x1F95D3B5EA53AEE8ULL,
		0xCC4CC3752D3BC34AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08F7AA0799A1F978ULL,
		0x893D26DB08856394ULL,
		0xC1F570021F8842C9ULL,
		0x91CE3E1276AB725AULL,
		0x0CB97AC46FC8EF74ULL,
		0x460C7114D8BFA958ULL,
		0xDEAD161DF7C696E4ULL,
		0x39EC75799A81C696ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03BB6F72B9C27D1EULL,
		0x94B119C3A2A2C4B0ULL,
		0x891915C57D290480ULL,
		0x411490D27C147A9CULL,
		0xBB418452DEEB682FULL,
		0x97D8D53341367427ULL,
		0x9C985D235DB9C408ULL,
		0x163830E75BF762C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8FAB643C285EF1EULL,
		0x098FF4F2377A1B3EULL,
		0x82B599FB7CA31483ULL,
		0xB23E28FEB41BC2AEULL,
		0x009C3731F215D902ULL,
		0x333CD5D351696CA3ULL,
		0xB33D2D325696785FULL,
		0xA44392367DE0B252ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AC0B92EF73C8E00ULL,
		0x8B2124D16B28A971ULL,
		0x06637BCA0085EFFDULL,
		0x8ED667D3C7F8B7EEULL,
		0xBAA54D20ECD58F2CULL,
		0x649BFF5FEFCD0784ULL,
		0xE95B2FF107234BA9ULL,
		0x71F49EB0DE16B06EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE4868DC2EC82F632ULL,
		0xB2BBE60DF888A0A7ULL,
		0x23F36B0B4C4C69C8ULL,
		0x8F0B9E6494949272ULL,
		0xEF26B84E37D08C2CULL,
		0x88E12B20FEA2AEA8ULL,
		0xFB0614757DB6FA1BULL,
		0xEABB2F404DA26F2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA852B7AB96D8BB6EULL,
		0xE337E3BB4DF07EABULL,
		0x5E36A139B21C8F03ULL,
		0x36DF2FAFE820135BULL,
		0xC3D32A4E4767E6B3ULL,
		0xA9FBE3F3368244ACULL,
		0xB426EBAE2E54D304ULL,
		0xFB7DD777E7582D97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C33D61755AA3AC4ULL,
		0xCF840252AA9821FCULL,
		0xC5BCC9D19A2FDAC4ULL,
		0x582C6EB4AC747F16ULL,
		0x2B538DFFF068A579ULL,
		0xDEE5472DC82069FCULL,
		0x46DF28C74F622716ULL,
		0xEF3D57C8664A4194ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x226AF6DA66010F83ULL,
		0xFA9ECF4E59DBD8ABULL,
		0xA224CFF7EFA3DD43ULL,
		0xD7539AA324BD6D2CULL,
		0x2D1CECC8BD2F6420ULL,
		0xE85C60BFB56DC1C4ULL,
		0x69193A856702AB0DULL,
		0x6D77BFD8E91DDCECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFD76259AE19FB6EULL,
		0x79DCDB578B0ECF65ULL,
		0x606DC8860CD2F992ULL,
		0xFDAD4321E3AF4B1CULL,
		0x82FACD01265513C4ULL,
		0x49336D0FEC41F6AFULL,
		0xABD23ABB7574CB02ULL,
		0xD6768E9B1F7317B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42939480B7E71415ULL,
		0x80C1F3F6CECD0945ULL,
		0x41B70771E2D0E3B1ULL,
		0xD9A65781410E2210ULL,
		0xAA221FC796DA505BULL,
		0x9F28F3AFC92BCB14ULL,
		0xBD46FFC9F18DE00BULL,
		0x9701313DC9AAC53BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E81232123BAE4BFULL,
		0x36AC855D07B347EAULL,
		0x336FCC16AD2306C1ULL,
		0x0891B16A62A23CDDULL,
		0xCB5296AC1DBD6F0FULL,
		0x36DE2C7A5219551BULL,
		0x720474D24F120830ULL,
		0x343F0E76CBD67B6EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x31AC2AD3DBFE8E19ULL,
		0x0BAE215F96C9D226ULL,
		0xC7AE69D7F2AC9B82ULL,
		0x51E1E1E5B1E12FF0ULL,
		0x36CC604C28103BB1ULL,
		0xBE2EB1BC8AFA0497ULL,
		0x07CCA8A6659A45C2ULL,
		0x2BB73FEFF3B0ACE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCD4F84D47BC56A6ULL,
		0x2AFE63FD70E975C3ULL,
		0x6BC1623EBA766B3FULL,
		0xB6AFCF84B0C10CECULL,
		0x9486365FF5AD335DULL,
		0x78AF7ABDC71F5084ULL,
		0x6A37CC2BE977C26DULL,
		0x0887CE86D825CE8BULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x842ACF25DF65331AULL,
		0x5AC72DB92E59A94FULL,
		0x92936A02C1C2AF14ULL,
		0x3D7919E6A883BDDDULL,
		0xCE2A7D708B220B97ULL,
		0x452927AFC5A65FEBULL,
		0xE60288B5AAE50D57ULL,
		0xD0B2FB55032C6843ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF039CC9E5F041AULL,
		0x7371BE6635CE9451ULL,
		0x45649789A958C64DULL,
		0x625A2F03405DDE1BULL,
		0x44509C0922230713ULL,
		0x637217E478AACFA6ULL,
		0xA90151207F12C25DULL,
		0x1542E681E1AF2CD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD73A955941062F00ULL,
		0xE7556F52F88B14FDULL,
		0x4D2ED2791869E8C6ULL,
		0xDB1EEAE36825DFC2ULL,
		0x89D9E16768FF0483ULL,
		0xE1B70FCB4CFB9045ULL,
		0x3D0137952BD24AF9ULL,
		0xBB7014D3217D3B6BULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0AD9F478841C740ULL,
		0xBABC0A40B51C5DF8ULL,
		0x7F6B228538984D75ULL,
		0x73DB9C497BC3F014ULL,
		0xCB09348C7E7D9884ULL,
		0x5A3A9724616EF48EULL,
		0xF5E5595E849FCDECULL,
		0xCBB980F865CFC1DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAFBBBDC6EA2E4CULL,
		0x7BA70DE37D489AEFULL,
		0x058A55FFED5403EAULL,
		0x02267FDE3F0B8BDAULL,
		0x8AB52ADAF549ED89ULL,
		0xA769270AF94D4441ULL,
		0xAA97DFFD67929C54ULL,
		0xF1062ED150534032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93FDE389C15798F4ULL,
		0x3F14FC5D37D3C309ULL,
		0x79E0CC854B44498BULL,
		0x71B51C6B3CB8643AULL,
		0x405409B18933AAFBULL,
		0xB2D170196821B04DULL,
		0x4B4D79611D0D3197ULL,
		0xDAB35227157C81A9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0FF050B20939708AULL,
		0x651635EAD8C593A2ULL,
		0x6CEDC80C88BA8A02ULL,
		0xBBE9DBA310414E1CULL,
		0xE9655DBAB1219748ULL,
		0x2B56A60170CBFC63ULL,
		0x08A26850091C437DULL,
		0x113FFE7E3E870842ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x59FF4A1017669CF4ULL,
		0xD1A8F3A73FF8864CULL,
		0x63CD06252C28CE45ULL,
		0x59C6D46776DA7581ULL,
		0x77F6F7300F6F8877ULL,
		0xA62A74025CEDBA2EULL,
		0x6E388607EA7BDDB3ULL,
		0x18B7E77A42571A4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F106A1F1D2D396ULL,
		0x936D424398CD0D55ULL,
		0x0920C1E75C91BBBCULL,
		0x6223073B9966D89BULL,
		0x716E668AA1B20ED1ULL,
		0x852C31FF13DE4235ULL,
		0x9A69E2481EA065C9ULL,
		0xF8881703FC2FEDF7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD25A5B777505F3EAULL,
		0x37DEE0F35D6617ECULL,
		0x7A4414E4B823F2B2ULL,
		0xA19D89225450B864ULL,
		0xB965E73A5830E671ULL,
		0xFDF82F4B44CEE6A6ULL,
		0x8DE31150891C09E7ULL,
		0xE01E8608CA431AD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8998FB9AA32E9B1BULL,
		0x65D6C949293BBB4CULL,
		0x6AFC87ED3C79966BULL,
		0xE483A4DEB8F28C1FULL,
		0xECBE4CE0713BA2BFULL,
		0x57150EB1CF60A0FFULL,
		0x3DADF7F2D8B303EEULL,
		0xAA9A5AE17DAE36A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48C15FDCD1D758CFULL,
		0xD20817AA342A5CA0ULL,
		0x0F478CF77BAA5C46ULL,
		0xBD19E4439B5E2C45ULL,
		0xCCA79A59E6F543B1ULL,
		0xA6E32099756E45A6ULL,
		0x5035195DB06905F9ULL,
		0x35842B274C94E430ULL
	}};
	sign = 0;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x65830E753CD5BA3EULL,
		0xDFD2A8A2187D1EBAULL,
		0x2CD7751BBFC18512ULL,
		0xE6907BD05DA7A423ULL,
		0x32C08D5E095CBA0AULL,
		0x9E0F5BC8154437FBULL,
		0xDD890128260D2E43ULL,
		0x42EAD764BAE5E637ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x45F11A061B5B209BULL,
		0xB9F751AD69327E67ULL,
		0xA1D26CA6EE654F50ULL,
		0x30D52C31825D5DC9ULL,
		0xE0C63FBCBEAA3129ULL,
		0xBAA8763A41BA517AULL,
		0x0E5D167334B9929DULL,
		0xDCD62B8D7D0E64CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F91F46F217A99A3ULL,
		0x25DB56F4AF4AA053ULL,
		0x8B050874D15C35C2ULL,
		0xB5BB4F9EDB4A4659ULL,
		0x51FA4DA14AB288E1ULL,
		0xE366E58DD389E680ULL,
		0xCF2BEAB4F1539BA5ULL,
		0x6614ABD73DD78168ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44779E1EE9B1CD4FULL,
		0x145DE2F3DE9637E6ULL,
		0x188B637A24C5F3C0ULL,
		0xC6D2B3014993BCF0ULL,
		0x3EAE95CEF0645D05ULL,
		0x36E3D3C428168EE9ULL,
		0xBBF793BCD91ED585ULL,
		0x5A7A1F8664128F53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7BFDA70B79BE38DULL,
		0x7A0EBC50B774284FULL,
		0x333652B8CEAD2704ULL,
		0x22C0D9DD14AB6291ULL,
		0xCFDEB1510D7AFA76ULL,
		0xF81C8B8409E0D92BULL,
		0x6BEBBDC7D437AFBEULL,
		0x75635BC9F152FE94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CB7C3AE3215E9C2ULL,
		0x9A4F26A327220F96ULL,
		0xE55510C15618CCBBULL,
		0xA411D92434E85A5EULL,
		0x6ECFE47DE2E9628FULL,
		0x3EC748401E35B5BDULL,
		0x500BD5F504E725C6ULL,
		0xE516C3BC72BF90BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB738E3A74C225DA4ULL,
		0xF7E869B107BCECCBULL,
		0x0287C9A9C0D5A1ADULL,
		0xC40C32A01B3D9360ULL,
		0x77E1BEEB0B4BDBF5ULL,
		0x4D659F8007346E18ULL,
		0x0727D76A0B73575BULL,
		0xA180511B096FC79BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF59C9FF5B565A6ULL,
		0x935EAF3E6B885A5AULL,
		0x8B147D6B2A5F0721ULL,
		0xA1AD0D43CE41FD71ULL,
		0xD0559BAD9E8BBB46ULL,
		0x09656B89849C1198ULL,
		0x0139FADE6E256773ULL,
		0x938B341783A4DACBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77434707566CF7FEULL,
		0x6489BA729C349271ULL,
		0x77734C3E96769A8CULL,
		0x225F255C4CFB95EEULL,
		0xA78C233D6CC020AFULL,
		0x440033F682985C7FULL,
		0x05EDDC8B9D4DEFE8ULL,
		0x0DF51D0385CAECD0ULL
	}};
	sign = 0;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55ED2262275BFD01ULL,
		0x28406D76BFE213E5ULL,
		0x7C9D522F1637FF22ULL,
		0x3BE700DA02315211ULL,
		0xD5086749A403A624ULL,
		0x6CF4E836038385CFULL,
		0xE67EDAF80D223AF6ULL,
		0x440DAA43BAB42C37ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4356D29ED95AD279ULL,
		0xA7BC9F085ACA93EFULL,
		0x378EA0AEF711B34CULL,
		0xA97D8AF60025A59EULL,
		0x96CC4FB02603B546ULL,
		0xD4C67AD6E4F17C85ULL,
		0x957EA69AA23D63A9ULL,
		0x54F20F86EE17E972ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12964FC34E012A88ULL,
		0x8083CE6E65177FF6ULL,
		0x450EB1801F264BD5ULL,
		0x926975E4020BAC73ULL,
		0x3E3C17997DFFF0DDULL,
		0x982E6D5F1E92094AULL,
		0x5100345D6AE4D74CULL,
		0xEF1B9ABCCC9C42C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x971E38F6E1CF82CDULL,
		0x6FC4CA9ED5B57B51ULL,
		0x65E4B2ACE39C27F5ULL,
		0x221B683F6C57294BULL,
		0x4DC1AB447408958CULL,
		0xD95DB6BDA30D6A4AULL,
		0xE633F565199BA5AEULL,
		0x373ADA08AC3D20FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0873B416BFEEFD5ULL,
		0xB2F7003A702BD450ULL,
		0x55DD9D1B34D62E51ULL,
		0xA4D6D3A69B6BA203ULL,
		0x3EDEB6CE624F1B63ULL,
		0xE0DCC86F386ACE61ULL,
		0x3A776040851554B9ULL,
		0x746E5D96FB5742B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA696FDB575D092F8ULL,
		0xBCCDCA646589A700ULL,
		0x10071591AEC5F9A3ULL,
		0x7D449498D0EB8748ULL,
		0x0EE2F47611B97A28ULL,
		0xF880EE4E6AA29BE9ULL,
		0xABBC9524948650F4ULL,
		0xC2CC7C71B0E5DE4AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF42E9CFAC309F821ULL,
		0x6A6C6DD4D2409443ULL,
		0x1931F570EEF3D15FULL,
		0x8085DD849A745E67ULL,
		0x2CDCF7E178E3277BULL,
		0xD374AC818190B248ULL,
		0xC69E432502393A26ULL,
		0x45670095E09DC533ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B39239D08BEF107ULL,
		0x8A98DB2F34F53FECULL,
		0xD9B282D7E2A24AD0ULL,
		0x009E02A4C4295DE0ULL,
		0x537D161F8FA63C8DULL,
		0x666B128DC277BC46ULL,
		0x19717BACE07A935AULL,
		0x5EB78004D05000B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98F5795DBA4B071AULL,
		0xDFD392A59D4B5457ULL,
		0x3F7F72990C51868EULL,
		0x7FE7DADFD64B0086ULL,
		0xD95FE1C1E93CEAEEULL,
		0x6D0999F3BF18F601ULL,
		0xAD2CC77821BEA6CCULL,
		0xE6AF8091104DC482ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3A9416D837801C9CULL,
		0xAFF74F8E9BC53D4CULL,
		0xA98EC2842E046B90ULL,
		0xE39EE6D10534F02CULL,
		0x5CBF21D740AA52F6ULL,
		0x45676898B0BBAEBEULL,
		0xB9C62153ACBD1DF0ULL,
		0xDB536FCDAC7721B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0530040E157B67BEULL,
		0x39B5A095AE81945CULL,
		0x6E07CF686803F6A8ULL,
		0x8A409AD390F35CAAULL,
		0x72C8FA8B800CC9FFULL,
		0x5BEEAB38D2E08205ULL,
		0x03CF90E58677EF3FULL,
		0x165EF45CCA76F9D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x356412CA2204B4DEULL,
		0x7641AEF8ED43A8F0ULL,
		0x3B86F31BC60074E8ULL,
		0x595E4BFD74419382ULL,
		0xE9F6274BC09D88F7ULL,
		0xE978BD5FDDDB2CB8ULL,
		0xB5F6906E26452EB0ULL,
		0xC4F47B70E20027DEULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6252FE888D47DE31ULL,
		0x5D9832559F939DBBULL,
		0x06E7E42226BB06BAULL,
		0x41646100965432DCULL,
		0x96F58A391F42418FULL,
		0xFA568E1BCC15D06DULL,
		0x842F3E83B5CCB635ULL,
		0xED4EA4A661992D6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0385606EF375E26ULL,
		0xCF53EEE92BB80D24ULL,
		0xDDCC1684D10691FDULL,
		0xD09DB7625DC8AD54ULL,
		0xD85CB96921B6851FULL,
		0xD4A4C6F21D38BD30ULL,
		0x8D52D8A831ADA109ULL,
		0x263E7789809D1E78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB21AA8819E10800BULL,
		0x8E44436C73DB9096ULL,
		0x291BCD9D55B474BCULL,
		0x70C6A99E388B8587ULL,
		0xBE98D0CFFD8BBC6FULL,
		0x25B1C729AEDD133CULL,
		0xF6DC65DB841F152CULL,
		0xC7102D1CE0FC0EF4ULL
	}};
	sign = 0;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFED59020706D6024ULL,
		0x9ED0286B09253DD3ULL,
		0x5279C3AA3C107496ULL,
		0xAE51C7EB2BA9DDE3ULL,
		0x08A11A43568EC0FDULL,
		0xEF245396135B99B5ULL,
		0x8FAC3E9B3BFB9238ULL,
		0x7F9B4116AA03B6C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD1AC6ADBF5D933ULL,
		0xDFD3A41279F07E1DULL,
		0xAA176BEDAA49B9EAULL,
		0xE98F8FF5700A96D3ULL,
		0x5C36DA430915E877ULL,
		0x2A2B98D5A4AC9613ULL,
		0xC2B4119801062AA8ULL,
		0xE7B9C4B47F8740E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5103E3B5947786F1ULL,
		0xBEFC84588F34BFB6ULL,
		0xA86257BC91C6BAABULL,
		0xC4C237F5BB9F470FULL,
		0xAC6A40004D78D885ULL,
		0xC4F8BAC06EAF03A1ULL,
		0xCCF82D033AF56790ULL,
		0x97E17C622A7C75DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x550CC4DECB4735A9ULL,
		0x256246281952D4AFULL,
		0xE00B34B602D7C317ULL,
		0xB1E338E71E28169FULL,
		0x3D8B1F73268DDCC3ULL,
		0xFC216D733DAE95CDULL,
		0xE4EE1C43EB63A613ULL,
		0xD084D3A331AE1884ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D054FEC44890AD9ULL,
		0x901B926A18BBCCCEULL,
		0xB66A4E80F8A90FFFULL,
		0x580640BA7F7900E3ULL,
		0x544D1C218CF12A2CULL,
		0xB2E910F616A24C22ULL,
		0xF5F69DA8C58D01FFULL,
		0x3A0687532216D62AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC80774F286BE2AD0ULL,
		0x9546B3BE009707E0ULL,
		0x29A0E6350A2EB317ULL,
		0x59DCF82C9EAF15BCULL,
		0xE93E0351999CB297ULL,
		0x49385C7D270C49AAULL,
		0xEEF77E9B25D6A414ULL,
		0x967E4C500F974259ULL
	}};
	sign = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xED9F4474F1782998ULL,
		0x9AF4B81BF8FEAAD6ULL,
		0x8BFDF1F242480A87ULL,
		0xC366149B26604053ULL,
		0x6F4DC1BA0BF8813CULL,
		0x6DA675564090F4AFULL,
		0x7B5CE884AFB7794CULL,
		0xB9822BD9611CC2D9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x827B1293EB6DD70EULL,
		0x728EEDAE50C3468CULL,
		0x47E041C73460D659ULL,
		0x21F0B318E197AE9AULL,
		0x435EC1831629DA9EULL,
		0xE3CCCA502773D5D8ULL,
		0xCA5C8AE927053823ULL,
		0xA8599C4ECA4F6C8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B2431E1060A528AULL,
		0x2865CA6DA83B644AULL,
		0x441DB02B0DE7342EULL,
		0xA175618244C891B9ULL,
		0x2BEF0036F5CEA69EULL,
		0x89D9AB06191D1ED7ULL,
		0xB1005D9B88B24128ULL,
		0x11288F8A96CD564BULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9CC712035D3CC154ULL,
		0x19460B59D6A50AC9ULL,
		0x0F0BEC2939A61BD4ULL,
		0xDEAE11984277CF69ULL,
		0x8073D4C4E83BC6CDULL,
		0xE013B2FD584068FBULL,
		0x18B474EF1B3F40D3ULL,
		0xD234323B869515B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4D8BE7CF412DF7ULL,
		0x6D1813099396A1DDULL,
		0xE41D87D1486BCE7BULL,
		0x6C1CD2E901386942ULL,
		0xAD2885263BB8A60AULL,
		0xF6EA8E7945BC5797ULL,
		0xE1939A48AD918E5FULL,
		0xBD972DCF324F4B76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF79861B8DFB935DULL,
		0xAC2DF850430E68EBULL,
		0x2AEE6457F13A4D58ULL,
		0x72913EAF413F6626ULL,
		0xD34B4F9EAC8320C3ULL,
		0xE929248412841163ULL,
		0x3720DAA66DADB273ULL,
		0x149D046C5445CA3EULL
	}};
	sign = 0;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E5A44870DB710CEULL,
		0xF125ECF67F3DA04AULL,
		0xE0CF07342B8CF770ULL,
		0x3AA8574A02709CE2ULL,
		0xE6FEE179763AB0B9ULL,
		0xF24E4FAD54BB144CULL,
		0x05028D790F6F22B3ULL,
		0xBD11E2ACFCBE3360ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37456B8EE1150876ULL,
		0x39EED4FEA37701C9ULL,
		0xA155E1A600AA0C0BULL,
		0x125E4203B2C6626BULL,
		0x9DD0431E1FE0B340ULL,
		0x0088307D76E8DFB5ULL,
		0xB364AEE3B241160AULL,
		0x1F970284D25019BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF714D8F82CA20858ULL,
		0xB73717F7DBC69E80ULL,
		0x3F79258E2AE2EB65ULL,
		0x284A15464FAA3A77ULL,
		0x492E9E5B5659FD79ULL,
		0xF1C61F2FDDD23497ULL,
		0x519DDE955D2E0CA9ULL,
		0x9D7AE0282A6E19A2ULL
	}};
	sign = 0;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x81DF77F9AF97550AULL,
		0xEF08CF356F4CE908ULL,
		0xCC8B48F6B485964FULL,
		0x53D0029952833096ULL,
		0x147944B0340E9170ULL,
		0x839E0A3381F85BCEULL,
		0x9B079E31C17D6C34ULL,
		0x6772518B7F4C2F8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C05EF8729496A50ULL,
		0xE97AA32B848C588EULL,
		0xD900CE34E05F136AULL,
		0x8F5E120ADD7CE695ULL,
		0x9712AEDD12D0E25AULL,
		0x2004A9DB57DB7DA8ULL,
		0x2A3647A5142C6393ULL,
		0xA0ECE3A45A4BAD1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25D98872864DEABAULL,
		0x058E2C09EAC0907AULL,
		0xF38A7AC1D42682E5ULL,
		0xC471F08E75064A00ULL,
		0x7D6695D3213DAF15ULL,
		0x639960582A1CDE25ULL,
		0x70D1568CAD5108A1ULL,
		0xC6856DE725008275ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA732FDD55C8D44E3ULL,
		0x287276E6751F1355ULL,
		0x4BB94C8A3AEED0E0ULL,
		0x571876F3488B4CFDULL,
		0x9423995E3D4DD1D7ULL,
		0x299512D5523FAAB7ULL,
		0xE0BA9F395CC58152ULL,
		0x35BFD4416B86B66CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x72918B2CB0DA72F7ULL,
		0x3B9368C2A84FCC1DULL,
		0xE0E3C5C18D897D05ULL,
		0x315DD0922C7A5E04ULL,
		0x51F94BD697569F57ULL,
		0xB988D3EA97CC3259ULL,
		0x0F2DD9B873109353ULL,
		0x201615DD9EB8FCC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34A172A8ABB2D1ECULL,
		0xECDF0E23CCCF4738ULL,
		0x6AD586C8AD6553DAULL,
		0x25BAA6611C10EEF8ULL,
		0x422A4D87A5F73280ULL,
		0x700C3EEABA73785EULL,
		0xD18CC580E9B4EDFEULL,
		0x15A9BE63CCCDB9ACULL
	}};
	sign = 0;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x71F4BCE8F52F2CA2ULL,
		0x9B94B44762C3CF25ULL,
		0x70E5C267B6027642ULL,
		0xD6351B8535A26870ULL,
		0xF34CD08EBE609393ULL,
		0xE7E8EBF6F1B9B2CAULL,
		0xD36D153681E7CCB1ULL,
		0xE3BEE3C15137A613ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B4AC88555A56F1ULL,
		0x06B7F8D12D7A882AULL,
		0xD234C252A37B2113ULL,
		0x490FE054445B25ACULL,
		0x1E3B9A9E07EC5B6EULL,
		0xFA1E3EC29D3210E8ULL,
		0x6E10B0F83B152318ULL,
		0x5A1739A37ED49616ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF4010609FD4D5B1ULL,
		0x94DCBB76354946FAULL,
		0x9EB100151287552FULL,
		0x8D253B30F14742C3ULL,
		0xD51135F0B6743825ULL,
		0xEDCAAD345487A1E2ULL,
		0x655C643E46D2A998ULL,
		0x89A7AA1DD2630FFDULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD3826FF59EF033F1ULL,
		0xED1ABBBA17550552ULL,
		0x7E472B6CFCAA99DFULL,
		0x5FB7C20B8075E4AEULL,
		0xB963E3C24E83E993ULL,
		0x030D2A6630D45336ULL,
		0x589D0A18A2860849ULL,
		0xB7E0C2D2BE838D3AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35509A51A91A36AULL,
		0x9A1EBD5C1DBBEB5BULL,
		0x884EF3C87AF04C37ULL,
		0xB7E3BB60D4AC9B91ULL,
		0x9F515BC35CA7E694ULL,
		0x73F32600FE5C9430ULL,
		0x09585AC165FE8B9EULL,
		0x71908BCA9D58C791ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302D6650845E9087ULL,
		0x52FBFE5DF99919F7ULL,
		0xF5F837A481BA4DA8ULL,
		0xA7D406AAABC9491CULL,
		0x1A1287FEF1DC02FEULL,
		0x8F1A04653277BF06ULL,
		0x4F44AF573C877CAAULL,
		0x46503708212AC5A9ULL
	}};
	sign = 0;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8128243225765243ULL,
		0x4CB5177465155992ULL,
		0x66DF4B522CEF5B26ULL,
		0x9D2F14BAEB28EE07ULL,
		0x1490F56682F04A4AULL,
		0x723264DF67735BBFULL,
		0x12FF96EE8EB25769ULL,
		0x95952AEF7E0E89BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAD9EF5AD6A7067ULL,
		0x5D0C72C9EE7DF4F8ULL,
		0xD8F0C0861168B20CULL,
		0xFD45ACD94C566CF4ULL,
		0x195E54C07ABD70E8ULL,
		0x64F3AA35CC5B3E51ULL,
		0xC3D837C3690E3762ULL,
		0x639AD99B73F53F06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x647A853C780BE1DCULL,
		0xEFA8A4AA7697649AULL,
		0x8DEE8ACC1B86A919ULL,
		0x9FE967E19ED28112ULL,
		0xFB32A0A60832D961ULL,
		0x0D3EBAA99B181D6DULL,
		0x4F275F2B25A42007ULL,
		0x31FA51540A194AB6ULL
	}};
	sign = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x887A811093FFDE3FULL,
		0x8AD63280EF94BF1BULL,
		0x9C90D4D6DDC96DE2ULL,
		0x211D6465C8C78EFBULL,
		0xEAA983DDE163B395ULL,
		0xB4A74B3C6D1973B1ULL,
		0xB28CC2E73DF22069ULL,
		0x507078DC653AC395ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1314E886C4232C7AULL,
		0xD596E99FA36019ECULL,
		0x0C908CA406E7403EULL,
		0x09C14E26607864FAULL,
		0x26558B5A285AFDF8ULL,
		0x430CC5F786F5CD09ULL,
		0xF51EFE9DC8C6D800ULL,
		0x710D41D94F1EDEC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75659889CFDCB1C5ULL,
		0xB53F48E14C34A52FULL,
		0x90004832D6E22DA3ULL,
		0x175C163F684F2A01ULL,
		0xC453F883B908B59DULL,
		0x719A8544E623A6A8ULL,
		0xBD6DC449752B4869ULL,
		0xDF633703161BE4D1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8E3AFC6A4D50A086ULL,
		0x54236218375EBF2AULL,
		0xF9B4F83921425D68ULL,
		0xB808C5E079BB7DAEULL,
		0x11B1B841766948BAULL,
		0xD204A69E81B27C7FULL,
		0xA318B9CA09A9F7E9ULL,
		0xAB7DB1F2C95D9DC3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x72AB95F769C1ADCAULL,
		0x83302847AF17FC06ULL,
		0x6F4CBBE2ECF5EBF5ULL,
		0x2DA4BB6F12BBE211ULL,
		0xF014430A936CD45FULL,
		0xC541B341C89BFA57ULL,
		0xC046E290725CF358ULL,
		0xAC75B3E15838303EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B8F6672E38EF2BCULL,
		0xD0F339D08846C324ULL,
		0x8A683C56344C7172ULL,
		0x8A640A7166FF9B9DULL,
		0x219D7536E2FC745BULL,
		0x0CC2F35CB9168227ULL,
		0xE2D1D739974D0491ULL,
		0xFF07FE1171256D84ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x439EF252ADDA7071ULL,
		0x70021D82895D3997ULL,
		0xCD3D2ABB8FDA6291ULL,
		0xC0AD518D94F49581ULL,
		0x46C3500CE6D6D5AEULL,
		0x618BD2418DA23D4DULL,
		0x96D402C3FC668D45ULL,
		0xF75A27A554D4C8F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE348ED263351C62CULL,
		0x293D8B751C5DC5B2ULL,
		0x7FD2941321DC165DULL,
		0x8CE7A883F4093D24ULL,
		0xED7944AB4CEC9F3DULL,
		0x63002A06DA98F545ULL,
		0x17B8C61286C4D101ULL,
		0x93039DAD7DBFFE39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6056052C7A88AA45ULL,
		0x46C4920D6CFF73E4ULL,
		0x4D6A96A86DFE4C34ULL,
		0x33C5A909A0EB585DULL,
		0x594A0B6199EA3671ULL,
		0xFE8BA83AB3094807ULL,
		0x7F1B3CB175A1BC43ULL,
		0x645689F7D714CABBULL
	}};
	sign = 0;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6285C560973CD4E8ULL,
		0xA9B2FA3B8C27AD3FULL,
		0x14BEF420E426FF6AULL,
		0xD6E1DF7754337800ULL,
		0xDF82A51FED8F0DD4ULL,
		0x7B0FD497D6564CA1ULL,
		0xB61EC2DFDA633410ULL,
		0xF87FA62ABF074530ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFC5DE9A704D1A2ULL,
		0xF0A4CE24070BC209ULL,
		0x579870FFFCF7D978ULL,
		0x91582A2B68FD3508ULL,
		0x3348EE2B256741E9ULL,
		0x1E89836A98E128D1ULL,
		0xECF3BE7697BA99D7ULL,
		0xF827D872DB0E8B36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3896776F0380346ULL,
		0xB90E2C17851BEB35ULL,
		0xBD268320E72F25F1ULL,
		0x4589B54BEB3642F7ULL,
		0xAC39B6F4C827CBEBULL,
		0x5C86512D3D7523D0ULL,
		0xC92B046942A89A39ULL,
		0x0057CDB7E3F8B9F9ULL
	}};
	sign = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x92CF26C853208AC3ULL,
		0x7C6830E140331060ULL,
		0x1EF92F1B9515C387ULL,
		0xA2DC8407274A41E4ULL,
		0xEF894B654F4EA318ULL,
		0xCA140C735E3E2C26ULL,
		0xD2861ADDF8DE0B22ULL,
		0x7A08C8A872885B94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC66768078FDFC2ULL,
		0x6D0D793A2F506F80ULL,
		0x2D57242FB57792B5ULL,
		0xAC46790777099E26ULL,
		0x98F46C9957673F8AULL,
		0x7F82342A5115FF17ULL,
		0xEC8BFC02CCE5A65AULL,
		0x9A51509E46A54905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA608BF604B90AB01ULL,
		0x0F5AB7A710E2A0DFULL,
		0xF1A20AEBDF9E30D2ULL,
		0xF6960AFFB040A3BDULL,
		0x5694DECBF7E7638DULL,
		0x4A91D8490D282D0FULL,
		0xE5FA1EDB2BF864C8ULL,
		0xDFB7780A2BE3128EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E0CB5CE4353EA4DULL,
		0xF56ACE53DE805A35ULL,
		0x28029D8CEFF6470EULL,
		0xFC70760A4F339E6DULL,
		0xB9AED10D45F4E508ULL,
		0xD559F63FCB27991CULL,
		0x880A89BA62C210C1ULL,
		0x21290D34151DDB76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD9C23BF38C4204ULL,
		0xF386076FE86BC447ULL,
		0xC1C285A373A83D30ULL,
		0xD6AF02E7C4AF16ECULL,
		0x43121F7A31810CA1ULL,
		0x196D834BD3155AA8ULL,
		0x28F3AD6A9845717BULL,
		0x006E75A6FA30CB5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE32F3924FC7A849ULL,
		0x01E4C6E3F61495EDULL,
		0x664017E97C4E09DEULL,
		0x25C173228A848780ULL,
		0x769CB1931473D867ULL,
		0xBBEC72F3F8123E74ULL,
		0x5F16DC4FCA7C9F46ULL,
		0x20BA978D1AED101CULL
	}};
	sign = 0;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x832CE5E85E9B9481ULL,
		0xF20BFA672000082DULL,
		0x1BBB455C36E5D4F7ULL,
		0x327CA17AC2084D52ULL,
		0x38F9860EF2999BF6ULL,
		0x5CC86F7311EA8EEEULL,
		0x60C5096B5A1444E9ULL,
		0x98FB7B03A423A514ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FFD0C21DB6CA832ULL,
		0xCDC985FE44E254D5ULL,
		0x8EB6397EEF081682ULL,
		0x645C96698FC224A1ULL,
		0x8DB71C9A264E618BULL,
		0xE193E377C9D0F8D2ULL,
		0x38BD6DABC966AC46ULL,
		0xD3E9284F68F950D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x532FD9C6832EEC4FULL,
		0x24427468DB1DB358ULL,
		0x8D050BDD47DDBE75ULL,
		0xCE200B11324628B0ULL,
		0xAB426974CC4B3A6AULL,
		0x7B348BFB4819961BULL,
		0x28079BBF90AD98A2ULL,
		0xC51252B43B2A5443ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6344E17728F20B6ULL,
		0xF532E2B0345325A4ULL,
		0x4DE21973FB6FCB48ULL,
		0x0C06DA6A197917EAULL,
		0x623A76E93E1E4D15ULL,
		0xE2F5B7D259604F78ULL,
		0xB78F834FEFA8952CULL,
		0x4D3F69E46B74FF5CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFF09BAA4D9F60CULL,
		0xB6BAF1DDC64FD3AAULL,
		0x6E4DFF1EFD9F6BDEULL,
		0x9180A4C04E3978A6ULL,
		0x122E486EC8E4CF8CULL,
		0x28617359DDC09786ULL,
		0xA9EBBED30C74CEC3ULL,
		0x16D366F5F0B4F49CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8635445CCDB52AAAULL,
		0x3E77F0D26E0351FAULL,
		0xDF941A54FDD05F6AULL,
		0x7A8635A9CB3F9F43ULL,
		0x500C2E7A75397D88ULL,
		0xBA9444787B9FB7F2ULL,
		0x0DA3C47CE333C669ULL,
		0x366C02EE7AC00AC0ULL
	}};
	sign = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA4955685BCE8708ULL,
		0x73D37172BCC199D6ULL,
		0x985FD86875A930BAULL,
		0xC2436C5638E6C081ULL,
		0x6151F8C3CBF4ABF5ULL,
		0x5D0758F9713DF98CULL,
		0x89734B6A3D24ABA6ULL,
		0x2FB858DD57647AAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x426357E363132A8FULL,
		0xA1848818D1720461ULL,
		0x9E2D8BAC7593F77DULL,
		0xAC99ED0187866586ULL,
		0x46815EAB72BADF14ULL,
		0x75E1F1DFDA56FF54ULL,
		0xEF98DC9B83B1B027ULL,
		0xE7373C375B698671ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7E5FD84F8BB5C79ULL,
		0xD24EE959EB4F9575ULL,
		0xFA324CBC0015393CULL,
		0x15A97F54B1605AFAULL,
		0x1AD09A185939CCE1ULL,
		0xE725671996E6FA38ULL,
		0x99DA6ECEB972FB7EULL,
		0x48811CA5FBFAF438ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8803A21C3ED73579ULL,
		0x835B914617E4CB92ULL,
		0x78D25167308A76E5ULL,
		0x4D709D4B09E26651ULL,
		0xA0900D6EDA7C3554ULL,
		0xE4FD8E5C8EAB6F21ULL,
		0x8ABB96648C7AB715ULL,
		0x3380F82A90D005DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD300DC043B1A510ULL,
		0x443782BC12554CC9ULL,
		0xC63EADA790D68212ULL,
		0x74663C1C44ED8EB7ULL,
		0xBCC14C2E33D833E4ULL,
		0xA25D8E3BE83AB05BULL,
		0xFEA4F723383EF60BULL,
		0xA0EA8BA4D56394E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAD3945BFB259069ULL,
		0x3F240E8A058F7EC8ULL,
		0xB293A3BF9FB3F4D3ULL,
		0xD90A612EC4F4D799ULL,
		0xE3CEC140A6A4016FULL,
		0x42A00020A670BEC5ULL,
		0x8C169F41543BC10AULL,
		0x92966C85BB6C70F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x074FE8F5CCA2A392ULL,
		0x85A390BA14330C12ULL,
		0x973B2F99491E3732ULL,
		0x0245EA229C379D58ULL,
		0x15DCAEAE39C91D13ULL,
		0x8039CEC4F696FECCULL,
		0x61995A99695A203AULL,
		0xBDD32709843A943EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E5FFBC7A85DC77ULL,
		0x91AF55598758C25BULL,
		0xD0954F6DCD46DE5DULL,
		0xD08160D597278D02ULL,
		0x24F142D8355E114FULL,
		0x9E1CB1920A934C6DULL,
		0x1ADF1BE9C9244B45ULL,
		0x370FB58E251C4B87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3069E939521CC71BULL,
		0xF3F43B608CDA49B6ULL,
		0xC6A5E02B7BD758D4ULL,
		0x31C4894D05101055ULL,
		0xF0EB6BD6046B0BC3ULL,
		0xE21D1D32EC03B25EULL,
		0x46BA3EAFA035D4F4ULL,
		0x86C3717B5F1E48B7ULL
	}};
	sign = 0;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1ED967335BDDF9E2ULL,
		0xDD5964F7778339ADULL,
		0x31073BBA1EB1A593ULL,
		0xE06B1E50569F1DC1ULL,
		0x4CF91F4D4691F118ULL,
		0x0D2ADB862BA3297EULL,
		0xB079A4692868EAFEULL,
		0xA8136472ADC125EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE8FEF1DE87C294ULL,
		0x8F2300EA09BE67DFULL,
		0xC01A20778D11F7DBULL,
		0x5ED3993D27E9BC6BULL,
		0x9A11D7E52F4C2494ULL,
		0x01048B02075A491FULL,
		0xE6D49A28E23E3DC2ULL,
		0x4D44259816E760EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23F068417D56374EULL,
		0x4E36640D6DC4D1CDULL,
		0x70ED1B42919FADB8ULL,
		0x819785132EB56155ULL,
		0xB2E747681745CC84ULL,
		0x0C2650842448E05EULL,
		0xC9A50A40462AAD3CULL,
		0x5ACF3EDA96D9C4FFULL
	}};
	sign = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7D69C3A83027736FULL,
		0x88DE1007E52883CFULL,
		0x308EB7094EB1A83EULL,
		0xA942296054B1E297ULL,
		0x5B31746F1C8F784CULL,
		0x1991C729A851C7DAULL,
		0xA9DF2B2D89EF9CA2ULL,
		0x64A78BDCACCEF23FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D2F5FC033AA826ULL,
		0x5DF22E05580055FAULL,
		0x4940ABBE2619AE37ULL,
		0xB8F8340CA992FB7AULL,
		0x3CF50F4FD0774FA2ULL,
		0x6883BCEF80BF1B16ULL,
		0xDD5BC733F2B7EFBBULL,
		0xD42111F85F9D6965ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9896CDAC2CECCB49ULL,
		0x2AEBE2028D282DD4ULL,
		0xE74E0B4B2897FA07ULL,
		0xF049F553AB1EE71CULL,
		0x1E3C651F4C1828A9ULL,
		0xB10E0A3A2792ACC4ULL,
		0xCC8363F99737ACE6ULL,
		0x908679E44D3188D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5357EF9FD2D5BDF0ULL,
		0xCB9BB2F8F8B97E74ULL,
		0x6410B9E6E37D1717ULL,
		0x7A2AAAB66D4EC0C1ULL,
		0x906593FCF793E529ULL,
		0xB7BAE1AAD35E455AULL,
		0x8BEB8795039150C2ULL,
		0xED27A8346E6C1F46ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D21E09F28F98DE5ULL,
		0x1E6B7633663CA12DULL,
		0x9BBD30BD59D63AA1ULL,
		0xFBEA28E13BB7EC91ULL,
		0x0D57DC35DF95A59CULL,
		0xAFEE5E1E0F312DE4ULL,
		0x7854E354CF886649ULL,
		0x0827FD86511951A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6360F00A9DC300BULL,
		0xAD303CC5927CDD46ULL,
		0xC853892989A6DC76ULL,
		0x7E4081D53196D42FULL,
		0x830DB7C717FE3F8CULL,
		0x07CC838CC42D1776ULL,
		0x1396A4403408EA79ULL,
		0xE4FFAAAE1D52CDA5ULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x87C5BA94A55ACC3DULL,
		0x73400E959B855656ULL,
		0x0841EC04FAC8FD11ULL,
		0xBB83AD2FADB8F2D8ULL,
		0x216C59287ECDEA44ULL,
		0x51D73A6375803CADULL,
		0xF0C5CE8C517BE2EDULL,
		0x0707DCF9BC398FD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x301951634781750BULL,
		0xE16FB61FFAEE23ABULL,
		0xE3C345520E1DD128ULL,
		0xAB6E0C9B4243FE95ULL,
		0x8974CDE4D518189CULL,
		0x998F986A40F0B0F6ULL,
		0x0EFC7B2E0D3BAFD3ULL,
		0xE81792136A80A743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57AC69315DD95732ULL,
		0x91D05875A09732ABULL,
		0x247EA6B2ECAB2BE8ULL,
		0x1015A0946B74F442ULL,
		0x97F78B43A9B5D1A8ULL,
		0xB847A1F9348F8BB6ULL,
		0xE1C9535E44403319ULL,
		0x1EF04AE651B8E895ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA35E40B94DA25A02ULL,
		0xE6E195F4E14EBFA1ULL,
		0xEE37950EEF61E051ULL,
		0xEB885DC52846FF70ULL,
		0xD3D45BE2B160F3EBULL,
		0xB35177D91E8AAA40ULL,
		0x8A15AFCB7D4F4419ULL,
		0xC0DD9871BC2640BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97B21C5FF1D1CE47ULL,
		0x4F1DAF28D7F0B17BULL,
		0xC1576F8E463B358EULL,
		0x81A9D1784E9A3A4CULL,
		0x99A86458AB449814ULL,
		0x81A81021AA6D4CE4ULL,
		0x0C8148AE20B6A424ULL,
		0x86668E72A252B46DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BAC24595BD08BBBULL,
		0x97C3E6CC095E0E26ULL,
		0x2CE02580A926AAC3ULL,
		0x69DE8C4CD9ACC524ULL,
		0x3A2BF78A061C5BD7ULL,
		0x31A967B7741D5D5CULL,
		0x7D94671D5C989FF5ULL,
		0x3A7709FF19D38C51ULL
	}};
	sign = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7F28A8AF1F5F9E27ULL,
		0x2750A5EBE4278660ULL,
		0x9C9A52098EEC011BULL,
		0x8B64F09683E66E4BULL,
		0x64741E615C934AEAULL,
		0xAA2CFE02BDB6BFBEULL,
		0x0113ADB13B60FA6BULL,
		0x0C4547AE8D40EEDFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FB351C6C7DB057FULL,
		0x3352E44951855433ULL,
		0x771023149C35FB2EULL,
		0x2B0B0769DCB8E6D2ULL,
		0x69226B96C0203A07ULL,
		0x9C360B32FC3CA345ULL,
		0x844467EB0FC97C13ULL,
		0x9CFD62619AE6714BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F7556E8578498A8ULL,
		0xF3FDC1A292A2322DULL,
		0x258A2EF4F2B605ECULL,
		0x6059E92CA72D8779ULL,
		0xFB51B2CA9C7310E3ULL,
		0x0DF6F2CFC17A1C78ULL,
		0x7CCF45C62B977E58ULL,
		0x6F47E54CF25A7D93ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03EC68B679CDB9ABULL,
		0x77BC58F3AE91FCCDULL,
		0x3FEAB039EE08BC0BULL,
		0x18DF0B480056B845ULL,
		0xD48828ECC11F65D1ULL,
		0x69FB1FF80A4C0C0BULL,
		0x6FBED497BC645937ULL,
		0xFD333E463D6EEACBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7066FDE3FDD73540ULL,
		0xD25DB87B2E54ABDFULL,
		0xE8A9E27755F48D0FULL,
		0xB1E110AD2D223C40ULL,
		0xD7900727047D2D53ULL,
		0xCC32D22937B31042ULL,
		0xB099426B4DE8FB41ULL,
		0x8FAA2CC8AF9E82E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93856AD27BF6846BULL,
		0xA55EA078803D50EDULL,
		0x5740CDC298142EFBULL,
		0x66FDFA9AD3347C04ULL,
		0xFCF821C5BCA2387DULL,
		0x9DC84DCED298FBC8ULL,
		0xBF25922C6E7B5DF5ULL,
		0x6D89117D8DD067E3ULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB066B58304E60596ULL,
		0x4B420109FB594AFFULL,
		0xC28B6F321AB58F4CULL,
		0x1E7F103E0334BC20ULL,
		0x41F204094D7F6A26ULL,
		0x4579759BA1BA7B13ULL,
		0x4DC9840E9F2A0232ULL,
		0x5F0C9F28BE24005BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5036AF393FE999B1ULL,
		0xCA754AE6FACA13E1ULL,
		0xB13332DAACA98E1AULL,
		0x279100C93418EB9CULL,
		0x5A903AC49C225FD8ULL,
		0x6AAC1ECE720C9AE3ULL,
		0x7CB8117888DA2E3FULL,
		0x2A939A7EBEB443ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60300649C4FC6BE5ULL,
		0x80CCB623008F371EULL,
		0x11583C576E0C0131ULL,
		0xF6EE0F74CF1BD084ULL,
		0xE761C944B15D0A4DULL,
		0xDACD56CD2FADE02FULL,
		0xD1117296164FD3F2ULL,
		0x347904A9FF6FBCAFULL
	}};
	sign = 0;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x332D22A757DD0F05ULL,
		0x9469C19E3335BD08ULL,
		0xF7B9E0DB8A55A9BAULL,
		0xA5AC141AD46CAEEFULL,
		0x77D8C867954B67BAULL,
		0x409A1199648BA3D6ULL,
		0x8F58D66CCCC83F4BULL,
		0x6E0DBD73296E03A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCE4CC92C94CF31ULL,
		0xC467C5F0B6599A39ULL,
		0xC526491F32411068ULL,
		0x7E2B2C9D2BB9584FULL,
		0xE6F694511D631FCDULL,
		0xCF8EEFDFC7B168DDULL,
		0x8663B6454D17A05CULL,
		0x45FFC5196B0E6F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x355ED5DE2B483FD4ULL,
		0xD001FBAD7CDC22CEULL,
		0x329397BC58149951ULL,
		0x2780E77DA8B356A0ULL,
		0x90E2341677E847EDULL,
		0x710B21B99CDA3AF8ULL,
		0x08F520277FB09EEEULL,
		0x280DF859BE5F947CULL
	}};
	sign = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCEB7CDFC84BB97AAULL,
		0x9EC09ABFB12C5A46ULL,
		0x61398A2FA40DF589ULL,
		0x00992D99C42C02BEULL,
		0x0CACD6AA81EC8577ULL,
		0xA5C17DACAA91B902ULL,
		0x3CFD8C79B8B159EDULL,
		0x05657C1628520C1DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD9965CA3759B40ULL,
		0xA5531D5ABBA2421DULL,
		0x46DEBDBCBACE9F4EULL,
		0xFE6D249627257511ULL,
		0x6AA8F21F9F5EC6D3ULL,
		0x771135BC6C0AB49FULL,
		0xFD1776EE39F2D89AULL,
		0x5434F7FB73F41887ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEDE379FE145FC6AULL,
		0xF96D7D64F58A1829ULL,
		0x1A5ACC72E93F563AULL,
		0x022C09039D068DADULL,
		0xA203E48AE28DBEA3ULL,
		0x2EB047F03E870462ULL,
		0x3FE6158B7EBE8153ULL,
		0xB130841AB45DF395ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xED42C596E9B676C2ULL,
		0xC9200F4723422693ULL,
		0x990DA86B2B57EDE8ULL,
		0xEE7FA17EEEFB7078ULL,
		0x1653045A4B00A293ULL,
		0xF4B8EEFE8F1F4540ULL,
		0x97901B316840F72AULL,
		0xD8C25989366D07BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3283F31A9F8800ULL,
		0xA8A517B17569756AULL,
		0x7E8977ECEAB09633ULL,
		0x0C07562AD6CFB7EDULL,
		0x8101E817310FBC3FULL,
		0x0511B5F90A41E901ULL,
		0x9480BB4ACDCC47B8ULL,
		0x320AAC2A41634AE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF1041A3CF16EEC2ULL,
		0x207AF795ADD8B129ULL,
		0x1A84307E40A757B5ULL,
		0xE2784B54182BB88BULL,
		0x95511C4319F0E654ULL,
		0xEFA7390584DD5C3EULL,
		0x030F5FE69A74AF72ULL,
		0xA6B7AD5EF509BCD9ULL
	}};
	sign = 0;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F288372C35D5FBCULL,
		0xCA0E7C7CDEE513B2ULL,
		0x1B0308A133747880ULL,
		0xDF7CABD5BFDBFFAEULL,
		0xED52F704EDB47754ULL,
		0x6D0E90A832EE9636ULL,
		0x15A00DA1499AB4C6ULL,
		0xF72FA29B5A63E863ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC04540746FD2FD53ULL,
		0x26BD7524767E3D7BULL,
		0xFFED99B31F9BF25BULL,
		0xAD1199DF703E4447ULL,
		0x8B2E7ABB755B1632ULL,
		0x83CD3372DA0EE2F2ULL,
		0x4FC709FFC98686B6ULL,
		0xA75EC12F53BF10B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EE342FE538A6269ULL,
		0xA35107586866D636ULL,
		0x1B156EEE13D88625ULL,
		0x326B11F64F9DBB66ULL,
		0x62247C4978596122ULL,
		0xE9415D3558DFB344ULL,
		0xC5D903A180142E0FULL,
		0x4FD0E16C06A4D7ABULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCA071F5D4C3DBB63ULL,
		0xA08D73B1DE821544ULL,
		0x1091945FD37F003FULL,
		0xB26653288B7461D5ULL,
		0x45BCC0E9A8BDE775ULL,
		0x9BF0096E61A7ED0BULL,
		0x1E2141A8957A654EULL,
		0x10829F563C44C12CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D06D0D56A005A0ULL,
		0xB6860F80D41F3A85ULL,
		0xC1FF59B66DE4DC41ULL,
		0x01C541BE92B56321ULL,
		0x329A5D8708AD8578ULL,
		0x07D274319C76084DULL,
		0x732DEE9AFF719175ULL,
		0x9EA49F18B24A6338ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE336B24FF59DB5C3ULL,
		0xEA0764310A62DABEULL,
		0x4E923AA9659A23FDULL,
		0xB0A11169F8BEFEB3ULL,
		0x13226362A01061FDULL,
		0x941D953CC531E4BEULL,
		0xAAF3530D9608D3D9ULL,
		0x71DE003D89FA5DF3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1C499E045369892ULL,
		0xB87BFB7B06E81CD1ULL,
		0x1793BF362481AA50ULL,
		0x69F2E9559EDD9B69ULL,
		0xE435F53D5F2C7113ULL,
		0x5E15F06257E47DE3ULL,
		0x6C3D90C1967D93C1ULL,
		0x815BAF74D5145E0FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x478652B2F9839F7EULL,
		0x58DA3EBA6E2E0345ULL,
		0x40D8EBA56961042DULL,
		0x7023C3000B3AEF29ULL,
		0x40A172C3B81A0521ULL,
		0xD215F5F8F66D98BAULL,
		0xA91BF4B02D0B005DULL,
		0x48CA09F3F3E302E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA3E472D4BB2F914ULL,
		0x5FA1BCC098BA198CULL,
		0xD6BAD390BB20A623ULL,
		0xF9CF265593A2AC3FULL,
		0xA3948279A7126BF1ULL,
		0x8BFFFA696176E529ULL,
		0xC3219C1169729363ULL,
		0x3891A580E1315B2CULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7938FC3736ECD30ULL,
		0x32D9B93D4D926001ULL,
		0x6AE7ACB30EDC414DULL,
		0x1E5D1E56409CC958ULL,
		0xF9BD0CF4D7F50032ULL,
		0x57924AE15972523CULL,
		0xC278B9C11DF94069ULL,
		0xAA0172620764C7CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3AAE72787A8698EULL,
		0x0BE029946A98687FULL,
		0xFCE85881C5989242ULL,
		0xB5C90FEA37407A19ULL,
		0x87E57260BA69F814ULL,
		0xAD3963A8F668ED9EULL,
		0x1825962EE8291F0EULL,
		0xAE6670A47CC10DC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13E8A89BEBC663A2ULL,
		0x26F98FA8E2F9F782ULL,
		0x6DFF54314943AF0BULL,
		0x68940E6C095C4F3EULL,
		0x71D79A941D8B081DULL,
		0xAA58E7386309649EULL,
		0xAA53239235D0215AULL,
		0xFB9B01BD8AA3BA09ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDDE3F581C73BC9F7ULL,
		0xF9CCB76841667AC5ULL,
		0xCA48F4BFD60FD70FULL,
		0x94E49E1A9920D8F3ULL,
		0x9950243ABD12E503ULL,
		0x9E98DAC8608BAC1AULL,
		0xCC8435623E38DF94ULL,
		0xBB1899F5E841B8B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x006E64F04924BEBEULL,
		0x5060BB4CFE1B8B88ULL,
		0x1ED055C1B172AF6AULL,
		0x9635E9F53F86EF7DULL,
		0x621B2EB7E5F84FDBULL,
		0xB9EC500D0ABD5A86ULL,
		0x318CB29BA0AA7B90ULL,
		0xBF053FC59C749BFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD7590917E170B39ULL,
		0xA96BFC1B434AEF3DULL,
		0xAB789EFE249D27A5ULL,
		0xFEAEB4255999E976ULL,
		0x3734F582D71A9527ULL,
		0xE4AC8ABB55CE5194ULL,
		0x9AF782C69D8E6403ULL,
		0xFC135A304BCD1CB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x428DB819C798CF10ULL,
		0xFEC02F28C344B64EULL,
		0x94BD7BFFDD1FEF59ULL,
		0xBE60C0887E871FB7ULL,
		0x6A9944E89A0A5E98ULL,
		0x020663ABC934065BULL,
		0x6C4235E7E546FB8DULL,
		0x030DB6768E20B6B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3663E9628528BC38ULL,
		0x689F4B52BBF051B9ULL,
		0x08C8F0D23C868D3DULL,
		0x2C16B67C210676E5ULL,
		0xB8EBF0C356B49964ULL,
		0x97858F52B548FD83ULL,
		0xD96907F707C6105FULL,
		0xB53487072A1EB2EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C29CEB7427012D8ULL,
		0x9620E3D607546495ULL,
		0x8BF48B2DA099621CULL,
		0x924A0A0C5D80A8D2ULL,
		0xB1AD54254355C534ULL,
		0x6A80D45913EB08D7ULL,
		0x92D92DF0DD80EB2DULL,
		0x4DD92F6F640203C4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00D8311235EA9BACULL,
		0x09D19F97BE5D7454ULL,
		0x85DFC18E2A270B9CULL,
		0xCB590DFF759A3FF3ULL,
		0xFB4241B6CA0F7BEEULL,
		0xD1985C908FDC4685ULL,
		0x9B7C55842C2DD172ULL,
		0x4A078694C540C9B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6AB387D034CFD6ULL,
		0xF9BE4922B3F3FF8DULL,
		0x7E106DE083022E9FULL,
		0xD7711D2F67F593E7ULL,
		0xADFFDAEDCB81188BULL,
		0x62CAC20B8901D41AULL,
		0x9B965089AF1BDC3DULL,
		0xA59E2F1BA10E0352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x346D7D8A65B5CBD6ULL,
		0x101356750A6974C6ULL,
		0x07CF53ADA724DCFCULL,
		0xF3E7F0D00DA4AC0CULL,
		0x4D4266C8FE8E6362ULL,
		0x6ECD9A8506DA726BULL,
		0xFFE604FA7D11F535ULL,
		0xA46957792432C661ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x035EEB4021BE710AULL,
		0x10C71189E39D1DD7ULL,
		0x671F4643550206A5ULL,
		0x11D62B218DAC1C56ULL,
		0x827180AE10A92B0DULL,
		0x1787E193024B66CEULL,
		0x35822AB2574A9D47ULL,
		0x0688169610AEBB8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC822D8B5FAFC8B65ULL,
		0x165F5983BFBDC99FULL,
		0x3CD2C7BA4607D10FULL,
		0x79671A14BFC9AAE0ULL,
		0x8F4AB727900583E5ULL,
		0x13750B8F2F477EAFULL,
		0xF4BFFFC67497F9EAULL,
		0x0116B5303B2C717DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B3C128A26C1E5A5ULL,
		0xFA67B80623DF5437ULL,
		0x2A4C7E890EFA3595ULL,
		0x986F110CCDE27176ULL,
		0xF326C98680A3A727ULL,
		0x0412D603D303E81EULL,
		0x40C22AEBE2B2A35DULL,
		0x05716165D5824A11ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x959DC4F09E092C87ULL,
		0xC325AF2352550874ULL,
		0x3E443C996BC80FC3ULL,
		0x9E5E197BC2F0DC14ULL,
		0xF8181F6307559815ULL,
		0x89A347FD80CAE480ULL,
		0xC29601EE7314166CULL,
		0xAE2C2C1841CCD287ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB88B9630B5E30F13ULL,
		0xEE1A0218B689820DULL,
		0xC90C753BCCB7A0A9ULL,
		0xFD36F0626FE46F34ULL,
		0xC30E564DC24A36EBULL,
		0xC890FC054FD30F5DULL,
		0x88F18FE34B466F42ULL,
		0x1500E97A709B0611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD122EBFE8261D74ULL,
		0xD50BAD0A9BCB8666ULL,
		0x7537C75D9F106F19ULL,
		0xA1272919530C6CDFULL,
		0x3509C915450B6129ULL,
		0xC1124BF830F7D523ULL,
		0x39A4720B27CDA729ULL,
		0x992B429DD131CC76ULL
	}};
	sign = 0;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x23A6CCD2C13192F8ULL,
		0x46E377E8F3F55D5DULL,
		0x818776CBA3CA6C52ULL,
		0x3FEB1FA053980687ULL,
		0x87C2A90A542CFA60ULL,
		0xBE3DEFF84102D608ULL,
		0x81DD7A0F43C51D06ULL,
		0x8422A42C4000298AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x801CC20671589028ULL,
		0x638D00B4E22777FAULL,
		0xAB2A85190EBC80A0ULL,
		0x90EDFC390668B1C7ULL,
		0xD1CE8BBAA7306BCEULL,
		0xBF63CFD33B5D9570ULL,
		0xC5B1B9CB1615660AULL,
		0x380C6968FBCB2BB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA38A0ACC4FD902D0ULL,
		0xE356773411CDE562ULL,
		0xD65CF1B2950DEBB1ULL,
		0xAEFD23674D2F54BFULL,
		0xB5F41D4FACFC8E91ULL,
		0xFEDA202505A54097ULL,
		0xBC2BC0442DAFB6FBULL,
		0x4C163AC34434FDD4ULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0818B4287D674282ULL,
		0x1E6E49E86A32B4F8ULL,
		0x68AE444199FF6066ULL,
		0x5D10A5A13BE3BAEAULL,
		0xE95512F6974EDA29ULL,
		0x1B539F10FBD5E593ULL,
		0x7ED6C414D1B9C787ULL,
		0xB63F0A33132120FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x626C6A24CC211772ULL,
		0x6FB361254A218FE5ULL,
		0x1466ABC0096D6C2EULL,
		0xCE5DB8DC7F5063A6ULL,
		0x58C1CD362B4C3A93ULL,
		0xEBF84DE34B30923FULL,
		0xF7EC2F98B7E9D514ULL,
		0xEB865D814F803AB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5AC4A03B1462B10ULL,
		0xAEBAE8C320112512ULL,
		0x544798819091F437ULL,
		0x8EB2ECC4BC935744ULL,
		0x909345C06C029F95ULL,
		0x2F5B512DB0A55354ULL,
		0x86EA947C19CFF272ULL,
		0xCAB8ACB1C3A0E64AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x958D434078E83836ULL,
		0x93F02AE6207C76FFULL,
		0x8C08A5A0DF716A8CULL,
		0xC966F0E013E5A22FULL,
		0x2A2DBE6DA0515989ULL,
		0xBDA6873B0E350E55ULL,
		0x207E4714F9C7E7B6ULL,
		0x0D75D932CBCFA4D3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF60C830DC26488ULL,
		0x7A8F4E0C9CA1A879ULL,
		0x0D80B6354B79843FULL,
		0x85DED033F0680369ULL,
		0xF0679D23272A0FC6ULL,
		0x2B065EB4601946F5ULL,
		0x3E6367137AF309DAULL,
		0x801AD909F34E3570ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA69736BD6B25D3AEULL,
		0x1960DCD983DACE85ULL,
		0x7E87EF6B93F7E64DULL,
		0x438820AC237D9EC6ULL,
		0x39C6214A792749C3ULL,
		0x92A02886AE1BC75FULL,
		0xE21AE0017ED4DDDCULL,
		0x8D5B0028D8816F62ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1385F28956837CAAULL,
		0x82CF3ED25511D362ULL,
		0x555990C23419A6A4ULL,
		0x47EDAB888668E76BULL,
		0x1BAF661829116F08ULL,
		0xFE8741FCFF152F91ULL,
		0x37A9EA84F7D95BB0ULL,
		0x83D24B5482754775ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91538E11F8363D4DULL,
		0x048231D6E45E4884ULL,
		0x8E735E292725EFFBULL,
		0x976884DF5B8DC88CULL,
		0x9F91773131F2799EULL,
		0xC5C9409EE92A9EBCULL,
		0xBD3B50CDAE1DB710ULL,
		0x354AC92561887772ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x823264775E4D3F5DULL,
		0x7E4D0CFB70B38ADDULL,
		0xC6E632990CF3B6A9ULL,
		0xB08526A92ADB1EDEULL,
		0x7C1DEEE6F71EF569ULL,
		0x38BE015E15EA90D4ULL,
		0x7A6E99B749BBA4A0ULL,
		0x4E87822F20ECD002ULL
	}};
	sign = 0;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3F30216E17C1B10DULL,
		0x987722CBFB66866DULL,
		0xEDEA0CCC5D8DDD6AULL,
		0x8613BDFA33792D34ULL,
		0xE2E994D09B57EBB5ULL,
		0xD7E60AD03442CF95ULL,
		0x547B22505D61AC79ULL,
		0xF18383A871697B99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E16AA8BC46ABF1ULL,
		0x5A7AD4153B473452ULL,
		0x9C792AFF8771275FULL,
		0x43A0C1D0F66D1231ULL,
		0xE4E2EF8BCAB0CB3FULL,
		0x76FA94058277626AULL,
		0xBBFAFFA3E26697F8ULL,
		0xBBC996448A0282EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684EB6C55B7B051CULL,
		0x3DFC4EB6C01F521AULL,
		0x5170E1CCD61CB60BULL,
		0x4272FC293D0C1B03ULL,
		0xFE06A544D0A72076ULL,
		0x60EB76CAB1CB6D2AULL,
		0x988022AC7AFB1481ULL,
		0x35B9ED63E766F8A9ULL
	}};
	sign = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD298AB1E260A0F32ULL,
		0xBFCE904722A07FDAULL,
		0x9E53C21329E8CA85ULL,
		0xB5411A720B3F0C2BULL,
		0x844795C0CCF4F49FULL,
		0x2077C08AD212200FULL,
		0xB4D41C10583FA9C0ULL,
		0xCBB01D95CF3BF5DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8059D90F8DE0D485ULL,
		0xFEF889E0C94B42E8ULL,
		0x6F38B5967215F919ULL,
		0x3BFAD4725B7064FEULL,
		0x414663466AEDAD52ULL,
		0x78F15E06EB63DDD6ULL,
		0x4C7470ABB9B4546DULL,
		0xE07CA1C3CC2CFC5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x523ED20E98293AADULL,
		0xC0D6066659553CF2ULL,
		0x2F1B0C7CB7D2D16BULL,
		0x794645FFAFCEA72DULL,
		0x4301327A6207474DULL,
		0xA7866283E6AE4239ULL,
		0x685FAB649E8B5552ULL,
		0xEB337BD2030EF97EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06F1EBE67C48D186ULL,
		0xEA9561191FB498A7ULL,
		0x2F4C4CB63BEE3602ULL,
		0x3AFD9CA8DEF2237CULL,
		0xE9D2318B83EC1A52ULL,
		0x915830027C71ED6BULL,
		0x473014B7F6579A96ULL,
		0x0911D633912BDB87ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37605D7885E4ED36ULL,
		0xF82C55991CBE8859ULL,
		0xDC8F0AF33E607C42ULL,
		0xB111AA75FC1A1041ULL,
		0xFC2BCA7037607DDAULL,
		0xC4F48CF13324B58DULL,
		0x62BF676F22502DEDULL,
		0x4DC2950680CB67EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF918E6DF663E450ULL,
		0xF2690B8002F6104DULL,
		0x52BD41C2FD8DB9BFULL,
		0x89EBF232E2D8133AULL,
		0xEDA6671B4C8B9C77ULL,
		0xCC63A311494D37DDULL,
		0xE470AD48D4076CA8ULL,
		0xBB4F412D10607397ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x46BFBCB830D26438ULL,
		0x3949327E09E3BBF6ULL,
		0x9A2AC5AEEAC85442ULL,
		0x687D56D773389748ULL,
		0x63B651BC55529887ULL,
		0xF84C2275393BF02FULL,
		0x38942AA74E4E5C8BULL,
		0x5EC27EF70C37EADEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E9BBB8EE7DF38F0ULL,
		0xB99EDB07941F7361ULL,
		0x9E998D664EE77262ULL,
		0xDDB12D17914D5EFCULL,
		0x25BA59491C455303ULL,
		0xE5DD94408745B4CCULL,
		0x7E8B2931AF26825DULL,
		0x1762015D21EED241ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1824012948F32B48ULL,
		0x7FAA577675C44895ULL,
		0xFB9138489BE0E1DFULL,
		0x8ACC29BFE1EB384BULL,
		0x3DFBF873390D4583ULL,
		0x126E8E34B1F63B63ULL,
		0xBA0901759F27DA2EULL,
		0x47607D99EA49189CULL
	}};
	sign = 0;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1396E5703B2DD16ULL,
		0x94E61FD7B4387D18ULL,
		0xBDD6201180CB6AFEULL,
		0xD6E9FAA971397B3FULL,
		0xAF3D5F0586D18561ULL,
		0xA7EEBE84D5FF31CDULL,
		0x572C5897797E7D1BULL,
		0xF1E2E09A4CC2AC0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xED29D071CD2B2383ULL,
		0x1F65ED66FDB3F2DEULL,
		0x951AECB1E65F6F11ULL,
		0xC92D9AF1AB0F5E5CULL,
		0xE0DE315FF728B993ULL,
		0xD124EFA985983543ULL,
		0x0A81A11703499EBEULL,
		0x70C9AD1B709E7114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040F9DE53687B993ULL,
		0x75803270B6848A3AULL,
		0x28BB335F9A6BFBEDULL,
		0x0DBC5FB7C62A1CE3ULL,
		0xCE5F2DA58FA8CBCEULL,
		0xD6C9CEDB5066FC89ULL,
		0x4CAAB7807634DE5CULL,
		0x8119337EDC243AFAULL
	}};
	sign = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA979FD7CD35884E0ULL,
		0x7F95E91ED8791FB0ULL,
		0x36C8F93E938FE14CULL,
		0x85F098E723423F45ULL,
		0x23F869EF4CDC39C6ULL,
		0x20692B748C7FBCD3ULL,
		0xD114F2690DC38ECAULL,
		0xB4780E07A86E1BFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF52359C07F8BCB43ULL,
		0x34C4F41743BEB5C7ULL,
		0xAAA0A4D39DCD0A10ULL,
		0x141A2A47473A9451ULL,
		0xF816B3F5AF586FE4ULL,
		0xBF7413CC6B112321ULL,
		0x51AA328094175B5CULL,
		0x99E02AC43FD1201DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB456A3BC53CCB99DULL,
		0x4AD0F50794BA69E8ULL,
		0x8C28546AF5C2D73CULL,
		0x71D66E9FDC07AAF3ULL,
		0x2BE1B5F99D83C9E2ULL,
		0x60F517A8216E99B1ULL,
		0x7F6ABFE879AC336DULL,
		0x1A97E343689CFBDEULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x86E49002A58D3817ULL,
		0x0703EE0C6D76189EULL,
		0x5C0CD0C3800DA685ULL,
		0x683374904A931BD9ULL,
		0x7856696C8EBE77D0ULL,
		0x251093E41E606AF5ULL,
		0x0912B30C631AFAC9ULL,
		0x09A27E120085D361ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB157F9785DB64916ULL,
		0x6181144E57B591BBULL,
		0x4E904B52534001E5ULL,
		0x84F9CD503A5E70E4ULL,
		0x8379B2B7B7642244ULL,
		0xB730F637A2BA41D7ULL,
		0x52C553FA33F49D45ULL,
		0x3DB23C21AA6F1596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD58C968A47D6EF01ULL,
		0xA582D9BE15C086E2ULL,
		0x0D7C85712CCDA49FULL,
		0xE339A7401034AAF5ULL,
		0xF4DCB6B4D75A558BULL,
		0x6DDF9DAC7BA6291DULL,
		0xB64D5F122F265D83ULL,
		0xCBF041F05616BDCAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B0660A35C18E9F7ULL,
		0x31990F0595F18AC7ULL,
		0xA07479C4AC7913D1ULL,
		0x1EAB111193BBFDB5ULL,
		0x3945AC8A4A7CC058ULL,
		0x2E59895D9842A6A7ULL,
		0x951971EF12C1245DULL,
		0x04CBA26C6D50B948ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3606977902C7D411ULL,
		0x1649230287AB576BULL,
		0x207A86506B426474ULL,
		0xD0C655D6BDF79E6EULL,
		0xB74EA048E171E9B7ULL,
		0xFE0E3751DBB141D4ULL,
		0x67E5C419F9EA43D9ULL,
		0x0E3EA4EAABC36639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64FFC92A595115E6ULL,
		0x1B4FEC030E46335CULL,
		0x7FF9F3744136AF5DULL,
		0x4DE4BB3AD5C45F47ULL,
		0x81F70C41690AD6A0ULL,
		0x304B520BBC9164D2ULL,
		0x2D33ADD518D6E083ULL,
		0xF68CFD81C18D530FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x96F7629365393B46ULL,
		0x0E53FFF1558D41CCULL,
		0x354C6DAE01DD7B6BULL,
		0x7E55BD4ABDC2B4AAULL,
		0x778A50AE4B0162DEULL,
		0xF94E26E53A868768ULL,
		0xC142BEC7946289E8ULL,
		0xFFF444540FBC4E29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8A660A9DA5D58DULL,
		0xFB8C44A6392CB2C0ULL,
		0xFFE571E5DA4E2663ULL,
		0xE7300E7527A9AE60ULL,
		0xFFD47D5A77838CE9ULL,
		0x0921AE47B3A95C55ULL,
		0x4E2444EB8803E570ULL,
		0xAE98C4A94DBEDC44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A6CFC88C79365B9ULL,
		0x12C7BB4B1C608F0CULL,
		0x3566FBC8278F5507ULL,
		0x9725AED596190649ULL,
		0x77B5D353D37DD5F4ULL,
		0xF02C789D86DD2B12ULL,
		0x731E79DC0C5EA478ULL,
		0x515B7FAAC1FD71E5ULL
	}};
	sign = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x26C0FB00EAE4D92FULL,
		0xE97893F9383D77DCULL,
		0x8165456919CBD521ULL,
		0x4E3057261EA126D9ULL,
		0x98FC882F4864FCC9ULL,
		0xB5BEF789954DFFF3ULL,
		0x99464FAB7490C420ULL,
		0x0FA7419658975FD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DFC7509C6971344ULL,
		0x5CEEC68983AABBD1ULL,
		0xC197AE6C666C47F7ULL,
		0x4D6C7EEF5F20A0FAULL,
		0x20A4C817BA3D8ED2ULL,
		0x59D9A03FA95BE2A5ULL,
		0xCD7538D91BF717A1ULL,
		0xC608FC801C962E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8C485F7244DC5EBULL,
		0x8C89CD6FB492BC0AULL,
		0xBFCD96FCB35F8D2AULL,
		0x00C3D836BF8085DEULL,
		0x7857C0178E276DF7ULL,
		0x5BE55749EBF21D4EULL,
		0xCBD116D25899AC7FULL,
		0x499E45163C0131B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x76BB775FA2FB6FD8ULL,
		0xFA3F4E113E39C54EULL,
		0xDFEC30983920090BULL,
		0x26BDAD986A9193C4ULL,
		0xB6AA1A67977BFE3FULL,
		0x0F475D80B382FDDBULL,
		0x492F59D3104A79D9ULL,
		0x317D931BB66FA46AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DB40FB9316E00ACULL,
		0xFCCE3B3BADC5B732ULL,
		0xA846DAA3CE9EC9D9ULL,
		0x4D8526593509183AULL,
		0xECA4979AB7EF4AC5ULL,
		0x902D1C949A11CE81ULL,
		0x8BF3AABA743FAB80ULL,
		0x25643E3F2EB2448BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE90767A6718D6F2CULL,
		0xFD7112D590740E1BULL,
		0x37A555F46A813F31ULL,
		0xD938873F35887B8AULL,
		0xCA0582CCDF8CB379ULL,
		0x7F1A40EC19712F59ULL,
		0xBD3BAF189C0ACE58ULL,
		0x0C1954DC87BD5FDEULL
	}};
	sign = 0;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1302057D90DBED59ULL,
		0xD57131F40C7D0530ULL,
		0xDBE9E6EBB45C6B74ULL,
		0x5299B93178550B8EULL,
		0xE365DBFCBAD843C3ULL,
		0xC9FF06BE8A48CF3AULL,
		0xA5409EDB66ED0E0DULL,
		0xDFFD1640BF6531A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55BA3996AD3C9ECEULL,
		0x0EC42FBE4BBEE241ULL,
		0x413558746D516B07ULL,
		0x0F13B8866F63C2EFULL,
		0xC6D85AA2829A82BFULL,
		0xDB06E6F6B2FEFD10ULL,
		0x61A50BD213100717ULL,
		0x522C4D970DAF0E91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD47CBE6E39F4E8BULL,
		0xC6AD0235C0BE22EEULL,
		0x9AB48E77470B006DULL,
		0x438600AB08F1489FULL,
		0x1C8D815A383DC104ULL,
		0xEEF81FC7D749D22AULL,
		0x439B930953DD06F5ULL,
		0x8DD0C8A9B1B62313ULL
	}};
	sign = 0;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30FAFAA6C47C5C55ULL,
		0x8FBED7D7C39C817DULL,
		0x00593FEAFB15A897ULL,
		0x1B4840104A28C68DULL,
		0xDD65A9AD762B1A3AULL,
		0xEFC67057ACEB9E71ULL,
		0x644517A05AFA7370ULL,
		0xD9EBC52B850E92C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F32CF0D95EE678CULL,
		0x7392F8C619DAB35EULL,
		0x61DEA9559BCF7B0EULL,
		0x4549E1C791E5FFC2ULL,
		0xDD1709AAB6D2C5FCULL,
		0xA060BD56BFB10956ULL,
		0x622DB15553ECD466ULL,
		0x27CC8BCE65551F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21C82B992E8DF4C9ULL,
		0x1C2BDF11A9C1CE1FULL,
		0x9E7A96955F462D89ULL,
		0xD5FE5E48B842C6CAULL,
		0x004EA002BF58543DULL,
		0x4F65B300ED3A951BULL,
		0x0217664B070D9F0AULL,
		0xB21F395D1FB9737AULL
	}};
	sign = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x088CB8328C85958CULL,
		0xEEDB182DAB21B9DBULL,
		0x89E2E036E9FDABF6ULL,
		0x279F2294A9D54D00ULL,
		0x9F6FC10BB13F77C6ULL,
		0x78E7ED7B4DC01CF0ULL,
		0xE271243921045D0EULL,
		0x054EA6AEBD52ABCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4F1B4BF46ABC59ULL,
		0x4B961C2C237D9279ULL,
		0x3874F895E6732273ULL,
		0x3247E7F7DBE5787DULL,
		0x84712C08295B5B70ULL,
		0x5D4659C65ECE1564ULL,
		0x54764AB615D3253DULL,
		0x28DEB5E25479887FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE3D9CE6981AD933ULL,
		0xA344FC0187A42761ULL,
		0x516DE7A1038A8983ULL,
		0xF5573A9CCDEFD483ULL,
		0x1AFE950387E41C55ULL,
		0x1BA193B4EEF2078CULL,
		0x8DFAD9830B3137D1ULL,
		0xDC6FF0CC68D9234BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE28DE896C0D4DA29ULL,
		0x014DEA2C70028447ULL,
		0x00EEFCC02F33DD20ULL,
		0x2DF54C0991B39469ULL,
		0x1C52EC3955C3C6DAULL,
		0xF0EE0D5B695FDFC5ULL,
		0x2DB3D9808B82790FULL,
		0x3ADECA9837F87D86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C503738768AFC00ULL,
		0x073FB3B71C03132BULL,
		0x064EFC0F2DBB1D5BULL,
		0x7C6D0816A442FCBFULL,
		0xAB56D51F46F8234BULL,
		0xF54634E73AA298C5ULL,
		0x605A33544A4A2225ULL,
		0x30CBD8649C7468C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD63DB15E4A49DE29ULL,
		0xFA0E367553FF711CULL,
		0xFAA000B10178BFC4ULL,
		0xB18843F2ED7097A9ULL,
		0x70FC171A0ECBA38EULL,
		0xFBA7D8742EBD46FFULL,
		0xCD59A62C413856E9ULL,
		0x0A12F2339B8414BFULL
	}};
	sign = 0;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF6533A030ED9D396ULL,
		0x8E647C1A87C4FFDBULL,
		0x4AD9B8764C652B8BULL,
		0xFF6C7BBB8323D2FAULL,
		0x1E891A6CA0B58F5EULL,
		0xD65C3F808937CFC2ULL,
		0x031429D715B5CB0EULL,
		0xD670B07F952F9229ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD66A64FFEEA2AB9ULL,
		0x58E0EE8CA08E21EBULL,
		0x246F51A9F63E0E3BULL,
		0x05321EC9452222E9ULL,
		0x5E98C3084E45F039ULL,
		0xFA0674B319DC397CULL,
		0xA9D3268EF624CE1AULL,
		0xEAC0A67FA9998DFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28EC93B30FEFA8DDULL,
		0x35838D8DE736DDF0ULL,
		0x266A66CC56271D50ULL,
		0xFA3A5CF23E01B011ULL,
		0xBFF05764526F9F25ULL,
		0xDC55CACD6F5B9645ULL,
		0x594103481F90FCF3ULL,
		0xEBB009FFEB96042DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x806B3448AB95F98EULL,
		0x75540BCDD10162A4ULL,
		0x2C3C1FB27C0C3BD3ULL,
		0x9E0BD550E5747C7BULL,
		0x654CBC31CC005994ULL,
		0x2F1F151018699275ULL,
		0xD47114DFD7F88334ULL,
		0x73D53FDCA3676C03ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92BEF228D62B0EE7ULL,
		0x8EE4861434C981FDULL,
		0xBC28BFF1ECE6B3B3ULL,
		0x629A90FEA66FB81BULL,
		0x4EB910AFBF5F2D4FULL,
		0xF5F93C9711C9016DULL,
		0x68CE4DDA2B5DEF79ULL,
		0xBCA3B0C982ECBD65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDAC421FD56AEAA7ULL,
		0xE66F85B99C37E0A6ULL,
		0x70135FC08F25881FULL,
		0x3B7144523F04C45FULL,
		0x1693AB820CA12C45ULL,
		0x3925D87906A09108ULL,
		0x6BA2C705AC9A93BAULL,
		0xB7318F13207AAE9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5B5ABA61EA9EDF8ULL,
		0x1ED51FE04DFCA610ULL,
		0x02C7E8C87F06361CULL,
		0x0319DAEC98F4368FULL,
		0x934DF10A50FFBF5FULL,
		0x2453C24BFC44C5E8ULL,
		0x775CAC04160403BDULL,
		0xC9A088ECC91407A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE4697160361D0DULL,
		0x37C0FBAF6AC38679ULL,
		0x676A6372A57FBB13ULL,
		0xDD14E5FCB27E90C2ULL,
		0x4D2DF4DFD096F22DULL,
		0xB1DFF66A6F2FBB13ULL,
		0x92C9DAEE65C627CEULL,
		0x437AE9ADE16B017BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AD14234BE73D0EBULL,
		0xE7142430E3391F97ULL,
		0x9B5D8555D9867B08ULL,
		0x2604F4EFE675A5CCULL,
		0x461FFC2A8068CD31ULL,
		0x7273CBE18D150AD5ULL,
		0xE492D115B03DDBEEULL,
		0x86259F3EE7A90628ULL
	}};
	sign = 0;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCFDCCF3838DA0526ULL,
		0x45F0DE6A9ED2B145ULL,
		0x7F80AFFF8F60D8C6ULL,
		0xA4486D7708B0FA6FULL,
		0x3FB07C87E5A9A02FULL,
		0x41FF7A70A2004724ULL,
		0x93058578A4AE7E8BULL,
		0x8FE91500B11905C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8794D50BFCB26B93ULL,
		0xCA6A3A4AFE9F7C21ULL,
		0xEC0161DF1B0B8DF0ULL,
		0x48C081C503D3184BULL,
		0x5DE453644B1EF647ULL,
		0xC5B8E49D65D72859ULL,
		0xC1E42A226C7DDA3CULL,
		0x828372D35FDA4F58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4847FA2C3C279993ULL,
		0x7B86A41FA0333524ULL,
		0x937F4E2074554AD5ULL,
		0x5B87EBB204DDE223ULL,
		0xE1CC29239A8AA9E8ULL,
		0x7C4695D33C291ECAULL,
		0xD1215B563830A44EULL,
		0x0D65A22D513EB667ULL
	}};
	sign = 0;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7AEBBA008228021AULL,
		0x8E9AB175B80787AFULL,
		0x31396B230C74061FULL,
		0x930CF0E0BA3BEB74ULL,
		0x16F76B0847A4933FULL,
		0x49FD0B0DCE85B495ULL,
		0x9FAE34611495B199ULL,
		0x28807D997F8E0BBEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B525BC20AF394BULL,
		0xEC02BCB31E254333ULL,
		0xA1167518D53A8FD4ULL,
		0x78D6FD78C0EBD2EEULL,
		0x61CA768204C07EA7ULL,
		0x1FC78F2069BF4867ULL,
		0x8FE2332ABC7C0E9EULL,
		0x0657BB78AA3B1024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB23694446178C8CFULL,
		0xA297F4C299E2447BULL,
		0x9022F60A3739764AULL,
		0x1A35F367F9501885ULL,
		0xB52CF48642E41498ULL,
		0x2A357BED64C66C2DULL,
		0x0FCC01365819A2FBULL,
		0x2228C220D552FB9AULL
	}};
	sign = 0;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x761486162C434946ULL,
		0x31CAEC17E7B60F1CULL,
		0x07F2B8F3EB925E45ULL,
		0xDB6C4A12383F0908ULL,
		0xCB8C3C6413D0746AULL,
		0x882183387A243DE7ULL,
		0x35A7BE576D3FE071ULL,
		0x5A22B9D692C3F360ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E56C432FF2B00B3ULL,
		0xC55418E088A16246ULL,
		0x7E593B42D3285F58ULL,
		0x77490D6C17E10D69ULL,
		0x25044D408144CDB8ULL,
		0x4E1019CC74A317C5ULL,
		0x29E6EEA423027406ULL,
		0x9EA1F41658883349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7BDC1E32D184893ULL,
		0x6C76D3375F14ACD5ULL,
		0x89997DB11869FEECULL,
		0x64233CA6205DFB9EULL,
		0xA687EF23928BA6B2ULL,
		0x3A11696C05812622ULL,
		0x0BC0CFB34A3D6C6BULL,
		0xBB80C5C03A3BC017ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAD3022F0C0E32216ULL,
		0xA94C82C87E503BA7ULL,
		0x2F7577422BA84CBAULL,
		0x82DAA0A772A46FD9ULL,
		0x336CDB900980A2D0ULL,
		0xED940086AE461531ULL,
		0x7326CB30C30D87B5ULL,
		0x5A36DA61D158E991ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD78161ECB5086CULL,
		0x6ED3FA2A68B31EDDULL,
		0xFDC2113BB2FF4261ULL,
		0xE3673BF84D3C4DFCULL,
		0x1C1716515E40B233ULL,
		0xC023B1BCD053E97AULL,
		0x6833F78E5F05433FULL,
		0xFF4C8DCA55341E49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF58A18ED42E19AAULL,
		0x3A78889E159D1CC9ULL,
		0x31B3660678A90A59ULL,
		0x9F7364AF256821DCULL,
		0x1755C53EAB3FF09CULL,
		0x2D704EC9DDF22BB7ULL,
		0x0AF2D3A264084476ULL,
		0x5AEA4C977C24CB48ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x825BA03FAFCA00E0ULL,
		0xA48DB46E60BB9D31ULL,
		0x5E1AAFCFEAAAD7D5ULL,
		0x2712DC9EAC4F4E81ULL,
		0x02052A5841301CB1ULL,
		0x8481E8AF009ABEE9ULL,
		0xCE70FDF4CB74E0F3ULL,
		0x0547FA34D6C7B454ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x419ACF0A4CBC8976ULL,
		0x663FD2BD90D736C0ULL,
		0xAE4906197CCAB2B6ULL,
		0xB3590D4B096BB9C3ULL,
		0x0E15F7542F320396ULL,
		0xC8F4B219275701E3ULL,
		0x038E4A88253D3A69ULL,
		0x32121E548A3BF896ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40C0D135630D776AULL,
		0x3E4DE1B0CFE46671ULL,
		0xAFD1A9B66DE0251FULL,
		0x73B9CF53A2E394BDULL,
		0xF3EF330411FE191AULL,
		0xBB8D3695D943BD05ULL,
		0xCAE2B36CA637A689ULL,
		0xD335DBE04C8BBBBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x784F0B3DB53EF1A1ULL,
		0x4485F32E81B79E12ULL,
		0x46DCF3C45835E73FULL,
		0x49E54D6951D2B311ULL,
		0x52EBFE5296B7E58AULL,
		0x610C431D2C0D97C3ULL,
		0xCD68C6A884ED1BD0ULL,
		0x3CEFAB8C9A98EE3AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B2E639A417E6999ULL,
		0x767267DE82CAF225ULL,
		0x44CE874D72D69480ULL,
		0x9314BE2C7A61ED35ULL,
		0x8F6C1C825549DA05ULL,
		0x1AE6B1CA4990AC43ULL,
		0x8D4F345322AFAD4DULL,
		0x906059926E5D99C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D20A7A373C08808ULL,
		0xCE138B4FFEECABEDULL,
		0x020E6C76E55F52BEULL,
		0xB6D08F3CD770C5DCULL,
		0xC37FE1D0416E0B84ULL,
		0x46259152E27CEB7FULL,
		0x40199255623D6E83ULL,
		0xAC8F51FA2C3B5474ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9F321FB2034C6B9ULL,
		0x786F7E8AEE4E5CEDULL,
		0x168E0F434A706025ULL,
		0xF739B736251DE9CFULL,
		0x66B6FF048F2A9707ULL,
		0xCB704F8A4789DE38ULL,
		0xBAC58E11EE487250ULL,
		0x9D52A1BA230F7348ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3CC210C3F0FC848ULL,
		0x4D20BD5FF0366134ULL,
		0xE9502D5E088902ACULL,
		0x8137BB391D76E90FULL,
		0xE345EF239E9A09C6ULL,
		0x0C36BA1186FEEE78ULL,
		0xDCA0F700379E8065ULL,
		0x989BFA8992FF8B6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE62700EEE124FE71ULL,
		0x2B4EC12AFE17FBB8ULL,
		0x2D3DE1E541E75D79ULL,
		0x7601FBFD07A700BFULL,
		0x83710FE0F0908D41ULL,
		0xBF399578C08AEFBFULL,
		0xDE249711B6A9F1EBULL,
		0x04B6A730900FE7D9ULL
	}};
	sign = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C1C38B25B6FAF8AULL,
		0x7CF12F14F16BF03AULL,
		0x8882B3DE92F2A38EULL,
		0x600F18CD286FA2EDULL,
		0xB28CC41B7F1D9520ULL,
		0xBE2C3DA21973AD38ULL,
		0x9BC286E0F802B3D7ULL,
		0x1F6585C3F7AFA9F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D589DBC4A451C4ULL,
		0x157A666BACE39B24ULL,
		0x7741A7A8F80D0C44ULL,
		0xFA0E770770D486ABULL,
		0x5077961DB2AE3188ULL,
		0x1FED66F50B52F471ULL,
		0x1EA58F25FAC57208ULL,
		0x5968C4842920284FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB46AED696CB5DC6ULL,
		0x6776C8A944885515ULL,
		0x11410C359AE5974AULL,
		0x6600A1C5B79B1C42ULL,
		0x62152DFDCC6F6397ULL,
		0x9E3ED6AD0E20B8C7ULL,
		0x7D1CF7BAFD3D41CFULL,
		0xC5FCC13FCE8F81A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFF65B0DC7DEE86F6ULL,
		0x5995532F4A971A08ULL,
		0x9B7959C056CCA0F2ULL,
		0xF0E97BB6CC954E41ULL,
		0x9DE8AA7CEFB5ADF4ULL,
		0xB84A8818DC5D0740ULL,
		0x58B6BA9613DDB927ULL,
		0x4518138BCE229755ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9938A90E49F53A46ULL,
		0xB6F89179A6837221ULL,
		0x2916D6925E2CA9FFULL,
		0x53CA038232BB0C80ULL,
		0x769867A005674CE0ULL,
		0xB41E0EEF1E25E028ULL,
		0x7AADCDE4A87EE6FBULL,
		0x689FF9F6D6D0EC03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x662D07CE33F94CB0ULL,
		0xA29CC1B5A413A7E7ULL,
		0x7262832DF89FF6F2ULL,
		0x9D1F783499DA41C1ULL,
		0x275042DCEA4E6114ULL,
		0x042C7929BE372718ULL,
		0xDE08ECB16B5ED22CULL,
		0xDC781994F751AB51ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x655E98FD8B774373ULL,
		0xFADEBFFA01470DF4ULL,
		0x44B99B96F8C2F304ULL,
		0x18ED07E6D4CF692CULL,
		0x2EF3FB27FD938466ULL,
		0x14D703BAFC9D7307ULL,
		0xB777B8973EE34286ULL,
		0x54AB7F1050184A8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE745BDAE69AB5C6ULL,
		0x50D2D3C3A63794E8ULL,
		0xC0019C4AEC5A20C6ULL,
		0xEFF5EDE042AC28F8ULL,
		0x8DB7EA11C198B65DULL,
		0x707C4EC7F586D94DULL,
		0x9D167ACB826A2610ULL,
		0x564E7C6EC8D84DEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6EA3D22A4DC8DADULL,
		0xAA0BEC365B0F790BULL,
		0x84B7FF4C0C68D23EULL,
		0x28F71A0692234033ULL,
		0xA13C11163BFACE08ULL,
		0xA45AB4F3071699B9ULL,
		0x1A613DCBBC791C75ULL,
		0xFE5D02A1873FFCA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x63C3B657523B8AC7ULL,
		0xE0701E4AF764E205ULL,
		0xA84B682D55DDBEC5ULL,
		0xCD4E088EE5F8C679ULL,
		0x260DCF6CBC71AE5DULL,
		0x353D1247CA394558ULL,
		0xFD7B0EAB2D26AF33ULL,
		0x8D32807100B32D88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11AFE4CCBE4AAD33ULL,
		0x4EBCBD8783C1F10FULL,
		0x3D68321AFAE6AF7CULL,
		0xFE5CC768F434030FULL,
		0xEF0F75692D9A7625ULL,
		0x69AC4703F3736B0EULL,
		0xD0BF30BB1BCD8A93ULL,
		0x6FEEC635A5A2E16AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5213D18A93F0DD94ULL,
		0x91B360C373A2F0F6ULL,
		0x6AE336125AF70F49ULL,
		0xCEF14125F1C4C36AULL,
		0x36FE5A038ED73837ULL,
		0xCB90CB43D6C5DA49ULL,
		0x2CBBDDF01159249FULL,
		0x1D43BA3B5B104C1EULL
	}};
	sign = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x341F275ED49AF01FULL,
		0x57E708DD60F7AE7DULL,
		0x254F9B55E52A56A7ULL,
		0x4D16CE1D4283037EULL,
		0x233C95E49A3DF359ULL,
		0x0ED107AEDECE098DULL,
		0x6746DEC03E1314D6ULL,
		0x084FFF476E68215DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46D145310C04B118ULL,
		0x06EB3DCB0C22B0EBULL,
		0xF42A66065734B1D0ULL,
		0x0CED1B0F0083E180ULL,
		0xDDD15DF9C0BD5702ULL,
		0x13E56286C6E35E04ULL,
		0x56EE85358F2C16D6ULL,
		0xB7650544EC61259EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED4DE22DC8963F07ULL,
		0x50FBCB1254D4FD91ULL,
		0x3125354F8DF5A4D7ULL,
		0x4029B30E41FF21FDULL,
		0x456B37EAD9809C57ULL,
		0xFAEBA52817EAAB88ULL,
		0x1058598AAEE6FDFFULL,
		0x50EAFA028206FBBFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF83CCFBF576B7CDBULL,
		0xF919575EA46AEC87ULL,
		0x7637754EF3A07D1FULL,
		0xD388EE868C4B1781ULL,
		0x45F1635B165F6834ULL,
		0x306916BA240B1AD4ULL,
		0x4C97C1B68AF91DF5ULL,
		0x5AFC646AF860F23CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F740767544A53DULL,
		0x921846B191672ABAULL,
		0xE013F1D7C0F69524ULL,
		0x36221B0E1CEE3B3BULL,
		0xFDD807461E5D093BULL,
		0x874208DC4CDCD6B7ULL,
		0x37A2D4F88813D311ULL,
		0x8D399C28E1EA875FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F458F48E226D79EULL,
		0x670110AD1303C1CDULL,
		0x9623837732A9E7FBULL,
		0x9D66D3786F5CDC45ULL,
		0x48195C14F8025EF9ULL,
		0xA9270DDDD72E441CULL,
		0x14F4ECBE02E54AE3ULL,
		0xCDC2C84216766ADDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3FD4093AB12C1137ULL,
		0x12D846EBB0CEB337ULL,
		0xC08F034FAC6FB4C0ULL,
		0xB81EFCBBE29B005FULL,
		0x342419DF5CFD6D55ULL,
		0x3CC6EED5F7C0279AULL,
		0x7EA82A0D24082AB6ULL,
		0x2F2C242C6FE6DA68ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x460A830DFD3CC0A3ULL,
		0x0FE91BD80239F07CULL,
		0xFBD4FD466D403118ULL,
		0x3FB735F21EECBA4DULL,
		0x3AFB4A8937623DE1ULL,
		0xC4065C06BEA02DC6ULL,
		0xC3361302154159BAULL,
		0x9C0B4372C667056DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9C9862CB3EF5094ULL,
		0x02EF2B13AE94C2BAULL,
		0xC4BA06093F2F83A8ULL,
		0x7867C6C9C3AE4611ULL,
		0xF928CF56259B2F74ULL,
		0x78C092CF391FF9D3ULL,
		0xBB72170B0EC6D0FBULL,
		0x9320E0B9A97FD4FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5F2D7FC7E834594CULL,
		0x2F3741223FAAA9D4ULL,
		0x8ECF4ECE5984F08CULL,
		0xCD29D05C7ED707DEULL,
		0x945CE7758D75E15DULL,
		0xB86914BAB5C9E3D2ULL,
		0x0202F924F2C57566ULL,
		0xE6416651FBFF4088ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8D4C22D91B2FD34ULL,
		0x6AC52791BF73AD82ULL,
		0x9D0459A7234200D0ULL,
		0xFBBF346524638354ULL,
		0x4D993B71E97A474EULL,
		0x22F29BB1DF1A022AULL,
		0xD226A5E3A0642D0BULL,
		0x7A0062584550ABADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA658BD9A56815C18ULL,
		0xC47219908036FC51ULL,
		0xF1CAF5273642EFBBULL,
		0xD16A9BF75A738489ULL,
		0x46C3AC03A3FB9A0EULL,
		0x95767908D6AFE1A8ULL,
		0x2FDC53415261485BULL,
		0x6C4103F9B6AE94DAULL
	}};
	sign = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x805A338B24A3A601ULL,
		0xE23475371F9E1754ULL,
		0x09D159D23957DA14ULL,
		0xDA27B792E245D1E8ULL,
		0xD48089A6EE4E8707ULL,
		0x30CC3A4E08B5672AULL,
		0xF3CC6F1DC629DB99ULL,
		0xF888F3FC4EAABF0AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D8F74882429C38ULL,
		0xE97215587C46006AULL,
		0x5A746117CC91DED9ULL,
		0x810D1F6277888AD6ULL,
		0x37D08B93F30B298AULL,
		0x56CAF97566AA9B23ULL,
		0x3E52194093575BECULL,
		0x456C10A7E9985259ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6813C42A26109C9ULL,
		0xF8C25FDEA35816E9ULL,
		0xAF5CF8BA6CC5FB3AULL,
		0x591A98306ABD4711ULL,
		0x9CAFFE12FB435D7DULL,
		0xDA0140D8A20ACC07ULL,
		0xB57A55DD32D27FACULL,
		0xB31CE35465126CB1ULL
	}};
	sign = 0;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x279EA7CCDF1B22D6ULL,
		0xA3A03A552FAC2D06ULL,
		0x5C28ECF1E76976F7ULL,
		0x650C0504F4F956B5ULL,
		0x3EB0F48C1C4F5787ULL,
		0xAACC5163BC2692C6ULL,
		0x49D12D79AD149EFFULL,
		0x4128682D3CD8235BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16883CBC502C9203ULL,
		0x7249FD7225E30C43ULL,
		0xFD5277A8E29D7CC9ULL,
		0xE3E35918D8EB1EB4ULL,
		0x55734F41733E4FE2ULL,
		0x55204C826A1B3919ULL,
		0xD8F9512398E46A05ULL,
		0x49C77EBACB93AF44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11166B108EEE90D3ULL,
		0x31563CE309C920C3ULL,
		0x5ED6754904CBFA2EULL,
		0x8128ABEC1C0E3800ULL,
		0xE93DA54AA91107A4ULL,
		0x55AC04E1520B59ACULL,
		0x70D7DC56143034FAULL,
		0xF760E97271447416ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x632D13F3F4D7BAF9ULL,
		0x6E06245B1FAEEA05ULL,
		0x6D5595195B85EDD6ULL,
		0x8CF7115BEBD58768ULL,
		0xEAD36FBFFAD9EA17ULL,
		0x6A37A6C51E04C08CULL,
		0xA3F0C9A48085897AULL,
		0x3A1BEEC0CE16732AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA855C3E5D156D50ULL,
		0xEFE74A7973A49098ULL,
		0x28BD658A179CE25EULL,
		0x53C1957FB9EA98F2ULL,
		0xE379F52B0431E334ULL,
		0x473E076949ABA577ULL,
		0x3824CF361FC05C32ULL,
		0x96434D06AA568E29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88A7B7B597C24DA9ULL,
		0x7E1ED9E1AC0A596CULL,
		0x44982F8F43E90B77ULL,
		0x39357BDC31EAEE76ULL,
		0x07597A94F6A806E3ULL,
		0x22F99F5BD4591B15ULL,
		0x6BCBFA6E60C52D48ULL,
		0xA3D8A1BA23BFE501ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF58522C49C394919ULL,
		0x9DAC53DE38021D11ULL,
		0x52500A1433477235ULL,
		0xFA31F42DD09BAC67ULL,
		0x3F3AFB5F5A9CB028ULL,
		0x33DA4277A45DF9B2ULL,
		0x8A78F28693741F0BULL,
		0x1EAE281993956206ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EEF060B6849D7EFULL,
		0x7AB73853A1A5B91EULL,
		0x032497F3B8836790ULL,
		0xCBE11B556F82174DULL,
		0x6DB79BF1390F3EAAULL,
		0x4FBA7ADD8AB47FBFULL,
		0x134929DEBFAC9C06ULL,
		0x9ABF5132AC2E3136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76961CB933EF712AULL,
		0x22F51B8A965C63F3ULL,
		0x4F2B72207AC40AA5ULL,
		0x2E50D8D86119951AULL,
		0xD1835F6E218D717EULL,
		0xE41FC79A19A979F2ULL,
		0x772FC8A7D3C78304ULL,
		0x83EED6E6E76730D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1382C442722104ABULL,
		0xA7EA4D9429E06C0AULL,
		0x107D7FA52FBC3A42ULL,
		0x8B5B002591872865ULL,
		0x11DF01C183330B8CULL,
		0xAB5355E8325FCBF4ULL,
		0x15B337238EAABBA3ULL,
		0x27127707CAADFD3BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71A7F93FE2A82BEULL,
		0x1E8387C31B735602ULL,
		0x8655639740DDDAFAULL,
		0x1B111E3F8C3D5A4AULL,
		0xA6CD4B61B41470EAULL,
		0x953DBD7AE3816FE8ULL,
		0xEB230A0B4856B6B9ULL,
		0x35B7DBE7C5CABF83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C6844AE73F681EDULL,
		0x8966C5D10E6D1607ULL,
		0x8A281C0DEEDE5F48ULL,
		0x7049E1E60549CE1AULL,
		0x6B11B65FCF1E9AA2ULL,
		0x1615986D4EDE5C0BULL,
		0x2A902D18465404EAULL,
		0xF15A9B2004E33DB7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x83D38ADB0EB64C03ULL,
		0x25D8685A1B255C8EULL,
		0x77C0036B3F3464E4ULL,
		0xFCFF27ED662A9A24ULL,
		0x526E28BDEC780F3CULL,
		0x0BABF0D13696E920ULL,
		0xF059F6E2B317D4B7ULL,
		0x43B7D358D9DC9723ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3E7FC98C01E87AULL,
		0xF0D9549236AD7FE5ULL,
		0x0A7FB959D508B872ULL,
		0xAF58A03CAB90A55EULL,
		0xDC8B044EE81843AFULL,
		0x9DA23546670FF3E5ULL,
		0x716DF412FB4BC6E9ULL,
		0xA696B5FF3F7A1545ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77950B1182B46389ULL,
		0x34FF13C7E477DCA9ULL,
		0x6D404A116A2BAC71ULL,
		0x4DA687B0BA99F4C6ULL,
		0x75E3246F045FCB8DULL,
		0x6E09BB8ACF86F53AULL,
		0x7EEC02CFB7CC0DCDULL,
		0x9D211D599A6281DEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x338663811240E8D7ULL,
		0x1C7F1D93DECE5CDAULL,
		0x4B5A7082F6210E6AULL,
		0x2693954273F556F4ULL,
		0xDE9086CB531BA78AULL,
		0x06F446748C44102FULL,
		0xBA2655FCDB59C85DULL,
		0x50A63C1C7EC9E124ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B807FAF73D13910ULL,
		0x6AC3F9F8FE052932ULL,
		0xFA228BDCBF412BC6ULL,
		0x33C7193E56490696ULL,
		0x3F38CDB5D4369821ULL,
		0x58850E679383B2F2ULL,
		0x6AF7B0B979A7A261ULL,
		0x3B6FE835D793718FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1805E3D19E6FAFC7ULL,
		0xB1BB239AE0C933A8ULL,
		0x5137E4A636DFE2A3ULL,
		0xF2CC7C041DAC505DULL,
		0x9F57B9157EE50F68ULL,
		0xAE6F380CF8C05D3DULL,
		0x4F2EA54361B225FBULL,
		0x153653E6A7366F95ULL
	}};
	sign = 0;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9A5925D8D84B4A22ULL,
		0xE459C776B4850863ULL,
		0xD748A5693B43BA27ULL,
		0xCAE7C84C98EDCE5EULL,
		0x3C28AF0C70CC909CULL,
		0xBC249C7E8FB2629AULL,
		0x3B36D4F6EC7935FFULL,
		0x4906AD8CA64E4EF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D6980C11633E68ULL,
		0x8F82A860E560A40BULL,
		0xB208564173157E74ULL,
		0x2ED24F58BCA36464ULL,
		0x168E708E2FAA6705ULL,
		0x77E08E8B3D3AA017ULL,
		0x3755B07FE0D789EEULL,
		0x3C8A4CB2305ABFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70828DCCC6E80BBAULL,
		0x54D71F15CF246458ULL,
		0x25404F27C82E3BB3ULL,
		0x9C1578F3DC4A69FAULL,
		0x259A3E7E41222997ULL,
		0x44440DF35277C283ULL,
		0x03E124770BA1AC11ULL,
		0x0C7C60DA75F38F51ULL
	}};
	sign = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8165D65E141ECBD9ULL,
		0x291C48F18DC0B7C3ULL,
		0x73D3CCC9B33A7049ULL,
		0x5C9E9752E18BC30FULL,
		0x742BC1B63FAE29BAULL,
		0x073713EFCF1F5713ULL,
		0xCC201F0C276B64BBULL,
		0xC737D57E4F561549ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53E74A92F7E31FA8ULL,
		0x139689927A5DD916ULL,
		0x0A28D1F8793F4B35ULL,
		0x20B582349C3CF8C2ULL,
		0xB2F29FDCD1E928E3ULL,
		0xE86ADCE9BF673E77ULL,
		0x506E7B7F7C793A37ULL,
		0xF58C0833C9B73A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D7E8BCB1C3BAC31ULL,
		0x1585BF5F1362DEADULL,
		0x69AAFAD139FB2514ULL,
		0x3BE9151E454ECA4DULL,
		0xC13921D96DC500D7ULL,
		0x1ECC37060FB8189BULL,
		0x7BB1A38CAAF22A83ULL,
		0xD1ABCD4A859EDB2DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x76C2C163FC18BBE4ULL,
		0xDBB653AAB2B93C35ULL,
		0xF19548071E63DAA5ULL,
		0xB84D10C0E0100719ULL,
		0x68B12E2A2F4B6BB6ULL,
		0x070E0571C13B9E73ULL,
		0xF330C784F2DE7449ULL,
		0x15D9FBDA951D712EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3AB11E9389D3E4ULL,
		0x4E73DD903AAFEB63ULL,
		0xA9FC8CFC3E8728C7ULL,
		0x71B9E74D2F0B91CAULL,
		0x37FE4517AFDD5C6FULL,
		0x012D67C666873548ULL,
		0x44E0E76B3589C6EEULL,
		0xB103EFA86C1B0772ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29881045688EE800ULL,
		0x8D42761A780950D2ULL,
		0x4798BB0ADFDCB1DEULL,
		0x46932973B104754FULL,
		0x30B2E9127F6E0F47ULL,
		0x05E09DAB5AB4692BULL,
		0xAE4FE019BD54AD5BULL,
		0x64D60C32290269BCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC7712CA25935979AULL,
		0xCF72E1D8AEA06E9FULL,
		0xC6BC4761B198B035ULL,
		0xCA1B0B40B7B3D924ULL,
		0xB928C0D89C67873CULL,
		0xC48DE99604B6ECF5ULL,
		0x0E4F265EF68AD7FAULL,
		0xC36141547B1FDB4AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF8E2ABBAF7E1EFULL,
		0x28D2279C05B24F9FULL,
		0x07B495972D122F84ULL,
		0xAE9F29319F3DF84DULL,
		0x200897C2BEE7C397ULL,
		0x0BDEB3360F064147ULL,
		0x0C5E7649FBC5463DULL,
		0x06F31154CACA2176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A7849F69E3DB5ABULL,
		0xA6A0BA3CA8EE1F00ULL,
		0xBF07B1CA848680B1ULL,
		0x1B7BE20F1875E0D7ULL,
		0x99202915DD7FC3A5ULL,
		0xB8AF365FF5B0ABAEULL,
		0x01F0B014FAC591BDULL,
		0xBC6E2FFFB055B9D4ULL
	}};
	sign = 0;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7BB610F83C05EC3ULL,
		0x1F8B6B4FB3582980ULL,
		0x65A51CB26EF54553ULL,
		0x5FE4FC2D73493D4FULL,
		0xA82B102D1A93EA67ULL,
		0x2A2E078A5A78F8AAULL,
		0x9FA663222CB7668FULL,
		0x2B3CEF679F5A6A34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFAA1E4AD89858F3ULL,
		0xFD20582CBEFD1421ULL,
		0xF70C51AF4219BEE5ULL,
		0x998FE554CAE2D675ULL,
		0xB72FD83C14151F5BULL,
		0xC94DA9DE3888E2C4ULL,
		0x5EFA8EBA0F17E056ULL,
		0xA835A797B274A46CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x281142C4AB2805D0ULL,
		0x226B1322F45B155FULL,
		0x6E98CB032CDB866DULL,
		0xC65516D8A86666D9ULL,
		0xF0FB37F1067ECB0BULL,
		0x60E05DAC21F015E5ULL,
		0x40ABD4681D9F8638ULL,
		0x830747CFECE5C5C8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30898A947E8D555EULL,
		0x0D7E315B11878E31ULL,
		0x1887E1E06A557186ULL,
		0xC4B93C56BE740B73ULL,
		0xC585159474C417E3ULL,
		0xC024AE3763CF246FULL,
		0x50C0153F0C2FDA6BULL,
		0xEC63CEECFC5A91C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A3DC63814F992CULL,
		0x965FC40DD3250559ULL,
		0xDA6B762FEFD5BD3CULL,
		0x5C71A029FF849583ULL,
		0x16E327E933E0B03DULL,
		0x39770855160208A6ULL,
		0x1393A9EC1781B958ULL,
		0x38709BB3640F1B0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE5AE30FD3DBC32ULL,
		0x771E6D4D3E6288D7ULL,
		0x3E1C6BB07A7FB449ULL,
		0x68479C2CBEEF75EFULL,
		0xAEA1EDAB40E367A6ULL,
		0x86ADA5E24DCD1BC9ULL,
		0x3D2C6B52F4AE2113ULL,
		0xB3F33339984B76B7ULL
	}};
	sign = 0;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF5161F172C4C21B3ULL,
		0x47EE6ACF3CA1DCD1ULL,
		0x4252F26A5545D4D3ULL,
		0xC124E9373789959FULL,
		0x13FFF566D3D2BF6AULL,
		0x6530203B72BB3CF5ULL,
		0xD47327392530F50DULL,
		0x600B3FDED72FD7AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C9173668514934ULL,
		0xAA0724FFD3702D0FULL,
		0xE93272792BC29AE3ULL,
		0x90FD68617007FFAEULL,
		0x428278FD0E189F16ULL,
		0xAB986CD507DA43F7ULL,
		0xC1625C8664FC9428ULL,
		0x7DD7280412997034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C4D07E0C3FAD87FULL,
		0x9DE745CF6931AFC2ULL,
		0x59207FF1298339EFULL,
		0x302780D5C78195F0ULL,
		0xD17D7C69C5BA2054ULL,
		0xB997B3666AE0F8FDULL,
		0x1310CAB2C03460E4ULL,
		0xE23417DAC4966776ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA033CB95F6849C46ULL,
		0xFB47EE40554C18CFULL,
		0x178D0848C0AC2089ULL,
		0x226C06F8178E35CDULL,
		0x789F8D5412B3F8E0ULL,
		0xB20983E8ECF5DCA4ULL,
		0x636EC60AD548DA13ULL,
		0x09DEF3F264B4C3E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E648F55051C05EFULL,
		0xEB446CF191EC4854ULL,
		0x446847433A36102BULL,
		0x5115C6148E82E08EULL,
		0xC14D603D69579A21ULL,
		0x79DD3C252FD155D5ULL,
		0x82D8703DB601485EULL,
		0x45E53CFBE2534270ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01CF3C40F1689657ULL,
		0x1003814EC35FD07BULL,
		0xD324C1058676105EULL,
		0xD15640E3890B553EULL,
		0xB7522D16A95C5EBEULL,
		0x382C47C3BD2486CEULL,
		0xE09655CD1F4791B5ULL,
		0xC3F9B6F682618173ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB078FFD9365349ADULL,
		0x3C7B0D2BEC61F2D5ULL,
		0x870F7FB86EDBA311ULL,
		0x943D37E9036D23D2ULL,
		0x60D63C3185BE7E87ULL,
		0x2A62F2F969CD39FBULL,
		0xB6A3F8B47356B26AULL,
		0x801D96F3B794F5E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92123C7113B98986ULL,
		0x9B52BF7BDC4F1432ULL,
		0x1876E8BAAE36682CULL,
		0x65FB0626F23C5E1DULL,
		0xEA9CF7F57CC4EA16ULL,
		0x19B116958E06FA5CULL,
		0xCD302E4162F5AC15ULL,
		0xCCD0BE180AFA4FE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E66C3682299C027ULL,
		0xA1284DB01012DEA3ULL,
		0x6E9896FDC0A53AE4ULL,
		0x2E4231C21130C5B5ULL,
		0x7639443C08F99471ULL,
		0x10B1DC63DBC63F9EULL,
		0xE973CA7310610655ULL,
		0xB34CD8DBAC9AA601ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B6E179B1BA817C5ULL,
		0xA3280E2FDDF0751DULL,
		0xA2E775BB82D345A8ULL,
		0xBCA3FD8A09C7E62CULL,
		0x015930DC034EC0B7ULL,
		0x785FD4F431FABC52ULL,
		0x4AEFC70C871F7C06ULL,
		0x487E5B6857938058ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x882A84A45CB52DF4ULL,
		0xC62CBBB6EFDCE09EULL,
		0x8CF98D368C44F0A9ULL,
		0xC952EB23C21B5FF1ULL,
		0xB96C9D71474D2783ULL,
		0x206445ADD028BF30ULL,
		0x198C459890618179ULL,
		0x9A00A83AC1F9AE90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF34392F6BEF2E9D1ULL,
		0xDCFB5278EE13947EULL,
		0x15EDE884F68E54FEULL,
		0xF351126647AC863BULL,
		0x47EC936ABC019933ULL,
		0x57FB8F4661D1FD21ULL,
		0x31638173F6BDFA8DULL,
		0xAE7DB32D9599D1C8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E428855805357A2ULL,
		0x07FAB6E518D50C4FULL,
		0xF85D6520E6314192ULL,
		0xC512D6087805338FULL,
		0x22DDFEBFA1564E83ULL,
		0x1E54EF337131700CULL,
		0x7167121A6DD80825ULL,
		0x758461CE1BED8D34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D3EEFB2753EBF7ULL,
		0xC70665BEC3085520ULL,
		0xDEC62C373E3E32ACULL,
		0x443690788AC79E0EULL,
		0x789FD410FE4C414BULL,
		0xEC497EAFC37D3BBBULL,
		0xB1FE9F38A53DE59CULL,
		0xA65857AC52BC3E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x966E995A58FF6BABULL,
		0x40F4512655CCB72EULL,
		0x199738E9A7F30EE5ULL,
		0x80DC458FED3D9581ULL,
		0xAA3E2AAEA30A0D38ULL,
		0x320B7083ADB43450ULL,
		0xBF6872E1C89A2288ULL,
		0xCF2C0A21C9314F1FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB10D2E37BA92137DULL,
		0xA56A524D924DB0EAULL,
		0xA6E6DADD959A85D7ULL,
		0x2ED06106898FF601ULL,
		0x235831FC3A158485ULL,
		0x76CEB2CC852C9DDCULL,
		0x7AFE57F13D517554ULL,
		0x933ADDC576BFBE96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6A21A711B420E9ULL,
		0xB243287309CB8E24ULL,
		0x22D3529665DD3660ULL,
		0xBF0CB5E927C1DA9FULL,
		0xFB93C0300EC5C325ULL,
		0x1700EEB5301EAF29ULL,
		0xBF2F949F5FADF7CEULL,
		0x01EF0E0D85574578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5A30C90A8DDF294ULL,
		0xF32729DA888222C5ULL,
		0x841388472FBD4F76ULL,
		0x6FC3AB1D61CE1B62ULL,
		0x27C471CC2B4FC15FULL,
		0x5FCDC417550DEEB2ULL,
		0xBBCEC351DDA37D86ULL,
		0x914BCFB7F168791DULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCCB7BA3A89AEC963ULL,
		0x3AA64054E555625FULL,
		0x5B1548B33A608EDDULL,
		0x35761CC6675B8E17ULL,
		0x1CDF9566B7147BCFULL,
		0x692583DB62793D20ULL,
		0x47696C7A847E15DFULL,
		0x74CC7B87FD0AAB10ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67193D1C9D7AABDULL,
		0x9644468EFC1780ACULL,
		0xF9BE524ADEB7DFBCULL,
		0x6CFA33F423279857ULL,
		0x7C00B368AF7814A8ULL,
		0xCD925E68500A8549ULL,
		0xA8C55947556C677DULL,
		0x64AD068E697C0F38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6462668BFD71EA6ULL,
		0xA461F9C5E93DE1B2ULL,
		0x6156F6685BA8AF20ULL,
		0xC87BE8D24433F5BFULL,
		0xA0DEE1FE079C6726ULL,
		0x9B932573126EB7D6ULL,
		0x9EA413332F11AE61ULL,
		0x101F74F9938E9BD7ULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDF6593E5AF00A7D7ULL,
		0xD08C6074B14AEF7FULL,
		0xE340EDB3A2445186ULL,
		0x85403A76ED7AB7BAULL,
		0x5354CDACC3C3A8FDULL,
		0xCF68BED1F99A80BBULL,
		0x98381F8A4463DEEBULL,
		0xE83908C7ADBB6FE7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D0ED634E4E7E63ULL,
		0x457959E122F62B7FULL,
		0xD376D80B2C14CE75ULL,
		0x724801CBD4DA04ABULL,
		0x63482113F5C7959DULL,
		0x585969928D2AF3B5ULL,
		0xF73285F2E2E67B6BULL,
		0xCAC2FCA3584F55D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA94A68260B22974ULL,
		0x8B1306938E54C400ULL,
		0x0FCA15A8762F8311ULL,
		0x12F838AB18A0B30FULL,
		0xF00CAC98CDFC1360ULL,
		0x770F553F6C6F8D05ULL,
		0xA1059997617D6380ULL,
		0x1D760C24556C1A13ULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x35BC97A05EFEF727ULL,
		0x5B9B0CB6F0FB83BFULL,
		0xCD555E4738A22186ULL,
		0xB125A974BC1E3766ULL,
		0x9F66C3F8872C7167ULL,
		0x5FDEC0A526965BA3ULL,
		0x3CAE4E623DEE4AC6ULL,
		0x47B24C4BC3183909ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA8D6140B69C0DEULL,
		0x56B1815FCB2BA822ULL,
		0x4D09E4E3F1ED4291ULL,
		0xEBD5130A42691340ULL,
		0x8B3E366E96C9B9AEULL,
		0x0A6B22835933DF70ULL,
		0x8A23553E8D1E82CCULL,
		0x048CFCB7F629FE7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2713C18C53953649ULL,
		0x04E98B5725CFDB9DULL,
		0x804B796346B4DEF5ULL,
		0xC550966A79B52426ULL,
		0x14288D89F062B7B8ULL,
		0x55739E21CD627C33ULL,
		0xB28AF923B0CFC7FAULL,
		0x43254F93CCEE3A8DULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD3BF34731A7233D1ULL,
		0x13817F454DB6E62FULL,
		0xBD049DC83282F4BCULL,
		0x75F758C68E4575EAULL,
		0x369A452849A4F7A8ULL,
		0xCFABE42A1ACCE3CFULL,
		0x307B50C8323EF09DULL,
		0x240535754033ACEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19E4CEA02DDC670ULL,
		0xE026E65A87FEA011ULL,
		0x7DB0C02D069FE35BULL,
		0x5D390668DFCF9605ULL,
		0xCD9C65AE8D77B3F2ULL,
		0xEF9E73E2AFA413B1ULL,
		0x8CB44141960B5195ULL,
		0x28C60527A81841A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2220E78917946D61ULL,
		0x335A98EAC5B8461EULL,
		0x3F53DD9B2BE31160ULL,
		0x18BE525DAE75DFE5ULL,
		0x68FDDF79BC2D43B6ULL,
		0xE00D70476B28D01DULL,
		0xA3C70F869C339F07ULL,
		0xFB3F304D981B6B48ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0BCA2F9968663285ULL,
		0xE647E0665BE1E062ULL,
		0x060D99BD18900879ULL,
		0x4CF4F615ACFBD04DULL,
		0xC6546A887C367208ULL,
		0x2A91CA76E0B8B2D5ULL,
		0x667289EEF6FEDAB3ULL,
		0x3B5DF7C71BB53280ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A86126FF7177F3ULL,
		0x7542761FA0C59FB8ULL,
		0xDD03BE6203EDA241ULL,
		0x52C0D7E13BFADC33ULL,
		0x32DCF8B127EB48A9ULL,
		0x40AA4A3EF66C1672ULL,
		0xD5783DAC0AF3CC38ULL,
		0x3C4C6CA10E80B4FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD221CE7268F4BA92ULL,
		0x71056A46BB1C40A9ULL,
		0x2909DB5B14A26638ULL,
		0xFA341E347100F419ULL,
		0x937771D7544B295EULL,
		0xE9E78037EA4C9C63ULL,
		0x90FA4C42EC0B0E7AULL,
		0xFF118B260D347D83ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x51AD176A63864970ULL,
		0x7F269C592526AA4BULL,
		0xAEC0EC2852AFE3A6ULL,
		0x2FDFD1976E8BE94DULL,
		0x7EDDD9BD3E5FD149ULL,
		0x0BE41F790BBB04F8ULL,
		0x5C52206C45A46FC0ULL,
		0x49684F5EB8D8D81CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3C042314EA22E7ULL,
		0x87C39E0734E6DD49ULL,
		0xBF53B728AC55EB97ULL,
		0x28DDF0CC8D181A99ULL,
		0x9815E9B8AD322759ULL,
		0x4FAE58C3E298B947ULL,
		0xA421F28F6123DF4CULL,
		0x61DCB8D06807F326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x057113474E9C2689ULL,
		0xF762FE51F03FCD02ULL,
		0xEF6D34FFA659F80EULL,
		0x0701E0CAE173CEB3ULL,
		0xE6C7F004912DA9F0ULL,
		0xBC35C6B529224BB0ULL,
		0xB8302DDCE4809073ULL,
		0xE78B968E50D0E4F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1DBB85727302A064ULL,
		0x8DAFC163FD880943ULL,
		0xB7DB92D2AA7E51C1ULL,
		0x313B0D22A003BB2BULL,
		0xD864CBA1AF2A1818ULL,
		0xF1C1B3E465C07355ULL,
		0x9C7F9205A6530193ULL,
		0x4F85FB4B56FC3524ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2C50B356B30E97BULL,
		0x244319AC6629998EULL,
		0x0BACDEB0D4C5D72FULL,
		0xEDF99CCFBCD9DC26ULL,
		0x65314B75927D8A83ULL,
		0x3F3B30DF3AD13273ULL,
		0x2EAAA706500FAA2DULL,
		0x84742ACA77C4CFDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AF67A3D07D1B6E9ULL,
		0x696CA7B7975E6FB4ULL,
		0xAC2EB421D5B87A92ULL,
		0x43417052E329DF05ULL,
		0x7333802C1CAC8D94ULL,
		0xB28683052AEF40E2ULL,
		0x6DD4EAFF56435766ULL,
		0xCB11D080DF376546ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE939D9FAC4ACC718ULL,
		0xFED4867FEBA14073ULL,
		0x00E746F8D503B3FDULL,
		0x454F5BC9F33B7C5DULL,
		0xAA7672D56172CE9EULL,
		0x3AF253FB69E8430BULL,
		0x68E7703BB5076B12ULL,
		0xA5C5AFA924535A71ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x060057F38B9B5A28ULL,
		0x2824803385D2A0F0ULL,
		0xCED59427B6061618ULL,
		0xA3928F6225A88A4FULL,
		0xDC23DAAD2DC336D6ULL,
		0x1466A55F2F0AD23AULL,
		0xA7E5F3C7367DE02AULL,
		0x8253C3AAE0058EE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE339820739116CF0ULL,
		0xD6B0064C65CE9F83ULL,
		0x3211B2D11EFD9DE5ULL,
		0xA1BCCC67CD92F20DULL,
		0xCE52982833AF97C7ULL,
		0x268BAE9C3ADD70D0ULL,
		0xC1017C747E898AE8ULL,
		0x2371EBFE444DCB8EULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5825EC4E26920FAEULL,
		0x5FBE26E052FE2EDAULL,
		0x2D17E987FD8463B5ULL,
		0x4BF591149C4C6832ULL,
		0xD7519ADC6C1148F8ULL,
		0xE9FBFB1744CC3F6CULL,
		0xB3AC52E79F3B9DABULL,
		0xC3A3ADF48F1E3E4DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9780F2B993E3C7BFULL,
		0xECBFAC15814DCB08ULL,
		0x6498BE12EA9C17AEULL,
		0x48C025619A14C609ULL,
		0x0C6F60A56DE434F1ULL,
		0xF9678D0C701B80CEULL,
		0xA834DCBCF6CCC639ULL,
		0x71040FF2B61EAC9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0A4F99492AE47EFULL,
		0x72FE7ACAD1B063D1ULL,
		0xC87F2B7512E84C06ULL,
		0x03356BB30237A228ULL,
		0xCAE23A36FE2D1407ULL,
		0xF0946E0AD4B0BE9EULL,
		0x0B77762AA86ED771ULL,
		0x529F9E01D8FF91B3ULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8E60F30A99CD0E5ULL,
		0x5EB50108EBF6CF95ULL,
		0x69614E36CCDC9CC1ULL,
		0xD678903C4CFFE823ULL,
		0x075CF8E15E13AE6FULL,
		0x0408AB7A2D5B349BULL,
		0x8AD3C8CA53CA9E61ULL,
		0x652DF34EC614A87FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D289608DE190C66ULL,
		0x9860B28BA537E2C0ULL,
		0x933CC4E9A33A5FC1ULL,
		0x984E2482C8F92D64ULL,
		0xAC4BD296331860E4ULL,
		0xCADE621D8131F223ULL,
		0x332A82CBBE0BC3CEULL,
		0x78AB05A2E4131A02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BBD7927CB83C47FULL,
		0xC6544E7D46BEECD5ULL,
		0xD624894D29A23CFFULL,
		0x3E2A6BB98406BABEULL,
		0x5B11264B2AFB4D8BULL,
		0x392A495CAC294277ULL,
		0x57A945FE95BEDA92ULL,
		0xEC82EDABE2018E7DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB369B8866C12299AULL,
		0x62F8E7C063060353ULL,
		0xA00EC50CB696ABF1ULL,
		0x1B482102503FFAFBULL,
		0x943B280845CE6AC7ULL,
		0xB1634D5F1F58B0EBULL,
		0x5FD1B4FB908E2344ULL,
		0xA5E14041863DBAF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB1219DA98CA58AULL,
		0xD56F89757B929FDBULL,
		0xE530A78FE836852EULL,
		0x57150E6B34D03E04ULL,
		0xBE1A8C9CEC62B790ULL,
		0x181B22CC05FF240AULL,
		0xB4B2B6F216854587ULL,
		0x6186DF5FB507BC82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95B896E8C2858410ULL,
		0x8D895E4AE7736378ULL,
		0xBADE1D7CCE6026C2ULL,
		0xC43312971B6FBCF6ULL,
		0xD6209B6B596BB336ULL,
		0x99482A9319598CE0ULL,
		0xAB1EFE097A08DDBDULL,
		0x445A60E1D135FE6FULL
	}};
	sign = 0;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x19A083388DDF7A91ULL,
		0xD4C8EA87AC828FABULL,
		0x703565D6027C7B49ULL,
		0x0C10F2CEDA629EEDULL,
		0x90060AF8AB138D1AULL,
		0xEC680E3096041D40ULL,
		0x6D6CE9429C31C677ULL,
		0x02CF212F645869B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C3A63FA082D92BULL,
		0xEFF7306CC2BCA3E0ULL,
		0x0AD3B5FAB5169424ULL,
		0x75E18C2AD6288B66ULL,
		0xDDF19FAB82C51D40ULL,
		0x1B5299D6E14D9DC2ULL,
		0xFAB49E7CB1F7EADEULL,
		0x99171FA2C7ABA463ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8DCDCF8ED5CA166ULL,
		0xE4D1BA1AE9C5EBCAULL,
		0x6561AFDB4D65E724ULL,
		0x962F66A4043A1387ULL,
		0xB2146B4D284E6FD9ULL,
		0xD1157459B4B67F7DULL,
		0x72B84AC5EA39DB99ULL,
		0x69B8018C9CACC54CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC01EAA5D4A82BFCBULL,
		0x07F0BF9C34C50431ULL,
		0xAF593EBB05AFF815ULL,
		0x6B7DA034BE9BF524ULL,
		0x3784B0FD908A4481ULL,
		0x16006E57AA7A7C78ULL,
		0x9A8F788DE003F388ULL,
		0xCF4A200CA8A095E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC022C243ACD427DFULL,
		0x35192E9BA8C9BA7DULL,
		0xE9ADC1EC25EFBDF7ULL,
		0x66DE3D95B50E9D41ULL,
		0x09D755AD8CB434EBULL,
		0xEF08562EF5375060ULL,
		0xE7B50F2F052CAFB1ULL,
		0xEEE4888B8F12EF16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFFBE8199DAE97ECULL,
		0xD2D791008BFB49B3ULL,
		0xC5AB7CCEDFC03A1DULL,
		0x049F629F098D57E2ULL,
		0x2DAD5B5003D60F96ULL,
		0x26F81828B5432C18ULL,
		0xB2DA695EDAD743D6ULL,
		0xE0659781198DA6CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4236D02B101243C6ULL,
		0xB6779754523F2065ULL,
		0xBEBF817618ACFC64ULL,
		0x748D295F9DAA73B8ULL,
		0x365E04E6EA3E20C3ULL,
		0xFAF4FF33839777C4ULL,
		0xD547DE70C3988E93ULL,
		0x02D8C0A8762F4441ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27B89CC96130A8FFULL,
		0x30D27FC2C0EDA80BULL,
		0x71DA6D0C72296BF1ULL,
		0xE16C2F430531F586ULL,
		0x7EC79D05C6588408ULL,
		0x17C7E58D783ED8C5ULL,
		0xFA791E605B99E48DULL,
		0xFEA0B55F441C1DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A7E3361AEE19AC7ULL,
		0x85A517919151785AULL,
		0x4CE51469A6839073ULL,
		0x9320FA1C98787E32ULL,
		0xB79667E123E59CBAULL,
		0xE32D19A60B589EFEULL,
		0xDACEC01067FEAA06ULL,
		0x04380B493213268FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB312A6C22058A871ULL,
		0x85B1BB96262F4DAAULL,
		0xBD7BEDD2C827D8E7ULL,
		0x8511CDB1BBF52498ULL,
		0xF65E7C44B3296B65ULL,
		0xDDEC17BBF850AE1EULL,
		0xD05726E4A2B7A643ULL,
		0xB90C6123378DB75CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD155D1B79362FB56ULL,
		0x46229CDE3765B240ULL,
		0x04D49126C23B7DA1ULL,
		0x5373152A9BD74677ULL,
		0x5759F436A1F9EFDCULL,
		0x1ADAE9B9606BE5E0ULL,
		0xA8D55BA037029B4DULL,
		0x1E54153D9787696CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1BCD50A8CF5AD1BULL,
		0x3F8F1EB7EEC99B69ULL,
		0xB8A75CAC05EC5B46ULL,
		0x319EB887201DDE21ULL,
		0x9F04880E112F7B89ULL,
		0xC3112E0297E4C83EULL,
		0x2781CB446BB50AF6ULL,
		0x9AB84BE5A0064DF0ULL
	}};
	sign = 0;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F277BB413536EC5ULL,
		0x6F7A3B070C76167AULL,
		0xA6463BE3B115C96EULL,
		0x2E155F22D48F0C0DULL,
		0x343910363D778961ULL,
		0x2AEB4B6098C0F539ULL,
		0x1ED978D2F9DA6CB2ULL,
		0x4196245C99ECC41AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x013DA863E95EA931ULL,
		0x6F4D2D07CF030286ULL,
		0x3AE3142709C146D4ULL,
		0xC7E14B05834FD253ULL,
		0xC0C2217833ED6D84ULL,
		0x1D887275E6CC9FDBULL,
		0x827D0418668BD592ULL,
		0x6DA5AB1E16EB85DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DE9D35029F4C594ULL,
		0x002D0DFF3D7313F4ULL,
		0x6B6327BCA754829AULL,
		0x6634141D513F39BAULL,
		0x7376EEBE098A1BDCULL,
		0x0D62D8EAB1F4555DULL,
		0x9C5C74BA934E9720ULL,
		0xD3F0793E83013E3DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x21A970A7C40503C3ULL,
		0x9D3FB45DD86E20BFULL,
		0xE11B0DAE3A06451BULL,
		0xDBDF8A5216CEC8BAULL,
		0x5CFC00C4DACE85BDULL,
		0x27794261C18C01FDULL,
		0x3E37B7E543D78605ULL,
		0x87D81F7B504BB1FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E4B8338DE69DA7ULL,
		0x4A7A0BB9A498C911ULL,
		0x2771053FBA8145E3ULL,
		0xD5B3EE18BC66AF12ULL,
		0x353296499EE07F5BULL,
		0x62BA5F6538B3F10CULL,
		0x67F2B90406768A4BULL,
		0x3FE8BFD33EB1D334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EC4B874361E661CULL,
		0x52C5A8A433D557ADULL,
		0xB9AA086E7F84FF38ULL,
		0x062B9C395A6819A8ULL,
		0x27C96A7B3BEE0662ULL,
		0xC4BEE2FC88D810F1ULL,
		0xD644FEE13D60FBB9ULL,
		0x47EF5FA81199DEC7ULL
	}};
	sign = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8640C22B54713483ULL,
		0x183C314D1C8A74F4ULL,
		0x75C4CC986B375995ULL,
		0x3CA3D31DD3290F86ULL,
		0xE4D20B943C472642ULL,
		0xFFCEEEB7C5C28833ULL,
		0x8B68B659B6895D99ULL,
		0x6A42CBACEC3D31D5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x931926065EE6715DULL,
		0x7C5CFC3819E8500EULL,
		0x3EEB79C27F472C32ULL,
		0x2B70B31442578E1DULL,
		0x23C548A806F9B130ULL,
		0xA4D2D8D5BCEBBC0EULL,
		0x634AA98020ECC989ULL,
		0x4BC48B06D135F259ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3279C24F58AC326ULL,
		0x9BDF351502A224E5ULL,
		0x36D952D5EBF02D62ULL,
		0x1133200990D18169ULL,
		0xC10CC2EC354D7512ULL,
		0x5AFC15E208D6CC25ULL,
		0x281E0CD9959C9410ULL,
		0x1E7E40A61B073F7CULL
	}};
	sign = 0;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E7C1D64A12FE29BULL,
		0x381221B3A2572D1DULL,
		0xE62E4E9F2EAF37F1ULL,
		0xD0E391CB25F13E7AULL,
		0x83D754321A9DB7A7ULL,
		0xCF4CB3EDF396F7F8ULL,
		0x9EA3D3BDF90038DAULL,
		0xCF414D4EB7122B73ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75429B8ABEE7419AULL,
		0x74C3B023C12A9CD4ULL,
		0x998B479C4C9650D1ULL,
		0xD2A19D809F6EE0DAULL,
		0x70662C37A13DCB14ULL,
		0x9777A52CC7EE5F9FULL,
		0x4E31DE880F55DE25ULL,
		0x1A8B260A6A2599CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD93981D9E248A101ULL,
		0xC34E718FE12C9048ULL,
		0x4CA30702E218E71FULL,
		0xFE41F44A86825DA0ULL,
		0x137127FA795FEC92ULL,
		0x37D50EC12BA89859ULL,
		0x5071F535E9AA5AB5ULL,
		0xB4B627444CEC91A5ULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5EA1518A669CCD88ULL,
		0xBAACA4C2B4495B0DULL,
		0x0E4C9AE490AD1BE0ULL,
		0x15C03944658B37DEULL,
		0x8E75E108D31FEBC0ULL,
		0x5CE27B8015D2B765ULL,
		0x6250D5247023FCF7ULL,
		0xE5F112398830D360ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9586C9EDE23C8EDULL,
		0xE9D547FD2531F5E5ULL,
		0x8D73FDFA8960B7E1ULL,
		0x283D950671D1A6EDULL,
		0x2F47448C7C7619F2ULL,
		0x8F331E6A221A84EDULL,
		0xC55E02D3ABDE7EB6ULL,
		0x14C282E78E4B5024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6548E4EB8879049BULL,
		0xD0D75CC58F176527ULL,
		0x80D89CEA074C63FEULL,
		0xED82A43DF3B990F0ULL,
		0x5F2E9C7C56A9D1CDULL,
		0xCDAF5D15F3B83278ULL,
		0x9CF2D250C4457E40ULL,
		0xD12E8F51F9E5833BULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3204828E7A211965ULL,
		0x25E79EF3CB83D59DULL,
		0x6DEE1717A66AF66EULL,
		0xFE5787E1F86F757EULL,
		0xE6C0804EF8020BA4ULL,
		0xB54ED2C5504082A3ULL,
		0x8878064C7FFE27FCULL,
		0x176FD865441EC352ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F2342D49C47C667ULL,
		0xA6CA15038B44286DULL,
		0x8554135E3A7889C8ULL,
		0x7BE4518D87311629ULL,
		0x15E46ED449C1A6BFULL,
		0x9DB729CA4E35F799ULL,
		0x2D536F9A8FE8DC8CULL,
		0x748770FB76FB74E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2E13FB9DDD952FEULL,
		0x7F1D89F0403FAD2FULL,
		0xE89A03B96BF26CA5ULL,
		0x82733654713E5F54ULL,
		0xD0DC117AAE4064E5ULL,
		0x1797A8FB020A8B0AULL,
		0x5B2496B1F0154B70ULL,
		0xA2E86769CD234E6CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x309761F2CDE98726ULL,
		0xCF6EAD040E6320F0ULL,
		0xDD70FBBA76F10118ULL,
		0x4FC0C1213C1C3A58ULL,
		0xF4BD42F56DF59551ULL,
		0xF9BE2CA92A89EDDCULL,
		0x2BDF4B1DF9B7FB68ULL,
		0xD544EFF3C5FC873FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22722DA3ED5DA048ULL,
		0x35C0ACA921D00B75ULL,
		0xE3F0B3155DA10083ULL,
		0x3D139674C412C6C5ULL,
		0x5B4D5ED2C4CFFB70ULL,
		0xB72C50BE69FFF1E9ULL,
		0xC5134CD04D19770BULL,
		0xCA189140A26775CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E25344EE08BE6DEULL,
		0x99AE005AEC93157BULL,
		0xF98048A519500095ULL,
		0x12AD2AAC78097392ULL,
		0x996FE422A92599E1ULL,
		0x4291DBEAC089FBF3ULL,
		0x66CBFE4DAC9E845DULL,
		0x0B2C5EB323951172ULL
	}};
	sign = 0;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC8092D9F05B9F95ULL,
		0x465029392B48CEC3ULL,
		0x803EC005D3B3FB01ULL,
		0x6C5E35323FFFE619ULL,
		0x363E487674790D7CULL,
		0x8538B77772BCFC44ULL,
		0x0DC06DC1E152267EULL,
		0x837219FE42A24AB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8C7FA711D2C0828ULL,
		0x96371AACDBFA231CULL,
		0xC665972201BFF147ULL,
		0xCC0B55069FD52A75ULL,
		0xD28B3CD5E7452689ULL,
		0x0E9BCD19B62319DCULL,
		0x2980BFF0BD8F7089ULL,
		0x462BFA50B7120EA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3B89868D32F976DULL,
		0xB0190E8C4F4EABA6ULL,
		0xB9D928E3D1F409B9ULL,
		0xA052E02BA02ABBA3ULL,
		0x63B30BA08D33E6F2ULL,
		0x769CEA5DBC99E267ULL,
		0xE43FADD123C2B5F5ULL,
		0x3D461FAD8B903C17ULL
	}};
	sign = 0;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB9C59760D4032081ULL,
		0xBB5805234158FBC8ULL,
		0x145CBEC8A4534E39ULL,
		0xC6EB6EFE15E25779ULL,
		0x3A8D1ECF0FE50D35ULL,
		0x7591E4E87E93A643ULL,
		0xBCA24366C8B70DE0ULL,
		0xC6C4434685D528C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20FF721C719F1F33ULL,
		0x8BB9AE5E0E248C3FULL,
		0xA99C9E605A1282D8ULL,
		0x3C1133853CAFF9D1ULL,
		0x28E306C7DFC3A694ULL,
		0x35B9B242F020E6DCULL,
		0x4FE79AE6E2702269ULL,
		0x811AF30ED122CB0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98C625446264014EULL,
		0x2F9E56C533346F89ULL,
		0x6AC020684A40CB61ULL,
		0x8ADA3B78D9325DA7ULL,
		0x11AA1807302166A1ULL,
		0x3FD832A58E72BF67ULL,
		0x6CBAA87FE646EB77ULL,
		0x45A95037B4B25DB6ULL
	}};
	sign = 0;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A4C8CC6B3A23FFFULL,
		0x9FD3FBB69F1D06C0ULL,
		0x6671C725F5BC878CULL,
		0x500683309F700576ULL,
		0x093D74B75B4469F2ULL,
		0xD2220ED0F5FE1C09ULL,
		0x63AFAF063F8FD0F3ULL,
		0xE2F6240EDA8CBABEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17461E0A3A31AE86ULL,
		0xB587040AD8D21789ULL,
		0xE9748C9EB77D28D3ULL,
		0xC5380D0B25011F5FULL,
		0x034718D2BD626FECULL,
		0x138E5630B2272EC8ULL,
		0xD16801B2C4F7E391ULL,
		0x71AB4E3FA175B63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63066EBC79709179ULL,
		0xEA4CF7ABC64AEF37ULL,
		0x7CFD3A873E3F5EB8ULL,
		0x8ACE76257A6EE616ULL,
		0x05F65BE49DE1FA05ULL,
		0xBE93B8A043D6ED41ULL,
		0x9247AD537A97ED62ULL,
		0x714AD5CF3917047FULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE6D48FE275DFA13ULL,
		0xE64533806BE20134ULL,
		0xA823B3E665DD33BBULL,
		0xBBA131F83D2AC140ULL,
		0xACB5049B71A414AAULL,
		0x9ABD352D7C310222ULL,
		0xBD767913C80B3F8FULL,
		0xD912478CC8743EF9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB959CEF891DB146DULL,
		0x4C0F150F532E9B51ULL,
		0xCA4CEA1111041409ULL,
		0x9768DE0E01DF74D2ULL,
		0x9C12291EF0289A61ULL,
		0xD150B78537C1D35BULL,
		0xDE639838FE2A44E0ULL,
		0x1098EDCD7FFF43DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05137A059582E5A6ULL,
		0x9A361E7118B365E3ULL,
		0xDDD6C9D554D91FB2ULL,
		0x243853EA3B4B4C6DULL,
		0x10A2DB7C817B7A49ULL,
		0xC96C7DA8446F2EC7ULL,
		0xDF12E0DAC9E0FAAEULL,
		0xC87959BF4874FB1DULL
	}};
	sign = 0;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B104481BFF7CB72ULL,
		0x3C1CFAEE4B179733ULL,
		0x7E8E017D44190DC9ULL,
		0x40BCFDEAD8C3F688ULL,
		0xFF809EFF914FED31ULL,
		0xCA64EE40E1C3FF8CULL,
		0x2E59F95085BB9CADULL,
		0x75867F0EB4BF11BCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF01AE68425E94B4ULL,
		0x652F2830835EF2BEULL,
		0x18505E345A042220ULL,
		0xA711E79CE403100CULL,
		0x92BC1B87D7D2D776ULL,
		0xC7AE75A4A4183C25ULL,
		0x18BA5AB793EEDE27ULL,
		0x6AF0C31A57C5DF3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C0E96197D9936BEULL,
		0xD6EDD2BDC7B8A474ULL,
		0x663DA348EA14EBA8ULL,
		0x99AB164DF4C0E67CULL,
		0x6CC48377B97D15BAULL,
		0x02B6789C3DABC367ULL,
		0x159F9E98F1CCBE86ULL,
		0x0A95BBF45CF93281ULL
	}};
	sign = 0;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE83B687A668DE897ULL,
		0xE61BB2AEFF2924C9ULL,
		0xC3F12A1A3E3236CAULL,
		0xE7EFC415B2605C18ULL,
		0xC36C6B4252F3720BULL,
		0x1D2389761B1A2A58ULL,
		0xF50A6840B64D74F2ULL,
		0xA97F11D9E70DAF03ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x456D32357209F433ULL,
		0xEAA2C0B42EFE7A0FULL,
		0xDFF7A7D822FF4D0BULL,
		0x5DC2919197AF55A7ULL,
		0x4A9FD2E492DE8138ULL,
		0x81E770C4A2B9FF2EULL,
		0xFC40B5416BBE9A0DULL,
		0x22F877AB625648F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2CE3644F483F464ULL,
		0xFB78F1FAD02AAABAULL,
		0xE3F982421B32E9BEULL,
		0x8A2D32841AB10670ULL,
		0x78CC985DC014F0D3ULL,
		0x9B3C18B178602B2AULL,
		0xF8C9B2FF4A8EDAE4ULL,
		0x86869A2E84B7660DULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xADAC1617E5289721ULL,
		0xD7B5F775263CE348ULL,
		0xF5F79A1A68FE6972ULL,
		0x53A6AAC05F1AE6F1ULL,
		0x5C83DC1BA5AA39D3ULL,
		0x114E427302CE7E88ULL,
		0x6BAC0D126FBB132CULL,
		0xE13BA08AB2507B4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE206A35613C2361ULL,
		0x53FB70D36F3F437FULL,
		0x2818B189E5047A80ULL,
		0xBCFD69A836AC9623ULL,
		0x361C34E0CC2189FAULL,
		0xACECA0F187AE24AEULL,
		0xB5A3F683DADB9608ULL,
		0x9127A5F41B99AFD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF8BABE283EC73C0ULL,
		0x83BA86A1B6FD9FC8ULL,
		0xCDDEE89083F9EEF2ULL,
		0x96A94118286E50CEULL,
		0x2667A73AD988AFD8ULL,
		0x6461A1817B2059DAULL,
		0xB608168E94DF7D23ULL,
		0x5013FA9696B6CB79ULL
	}};
	sign = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6BF0366609E76DCCULL,
		0x6698352BBCF3173AULL,
		0xB5723260F867FE73ULL,
		0x69F23E497544F5BDULL,
		0x1899EA7E550FBDC2ULL,
		0xC75013D91BD92806ULL,
		0x687C2AF7A81108BDULL,
		0x7031EBA009DF798AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47DF22AE75CE79A5ULL,
		0x0DC25A3952790F83ULL,
		0x7162C3C06723C6CFULL,
		0xE1604CE3BBAF7622ULL,
		0x294C310DD12C80BAULL,
		0xF84C8E71FC73885BULL,
		0xD80AB2A8841A9936ULL,
		0xAADCBFA08AFAE194ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x241113B79418F427ULL,
		0x58D5DAF26A7A07B7ULL,
		0x440F6EA0914437A4ULL,
		0x8891F165B9957F9BULL,
		0xEF4DB97083E33D07ULL,
		0xCF0385671F659FAAULL,
		0x9071784F23F66F86ULL,
		0xC5552BFF7EE497F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x91B9FF1CB3741675ULL,
		0x8CE201E8F3770090ULL,
		0xDBAB5DA5AE88185BULL,
		0x6C67CF39A1A9E7C8ULL,
		0xA48894D926B5A77FULL,
		0x53F6B3A26789310AULL,
		0x9FD0063218032E03ULL,
		0x4A242D7EF1A7EBFAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE5468A45A566C73ULL,
		0xF851A062DDBF6702ULL,
		0x083D318A83046786ULL,
		0xC2D1D7CE14665485ULL,
		0x1B1029574EAE79D9ULL,
		0x1E28CFDA0BFAB923ULL,
		0x586DDD1C147954ADULL,
		0xF346EB289C636DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3659678591DAA02ULL,
		0x9490618615B7998DULL,
		0xD36E2C1B2B83B0D4ULL,
		0xA995F76B8D439343ULL,
		0x89786B81D8072DA5ULL,
		0x35CDE3C85B8E77E7ULL,
		0x476229160389D956ULL,
		0x56DD425655447E00ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x22921AC9B47F5EC7ULL,
		0x4D932483944737D1ULL,
		0x261A4EF7B653E0AFULL,
		0x92F05CE767D88CD4ULL,
		0xBC454E7A8BC63DE3ULL,
		0xAAF86B45AE4DB3A3ULL,
		0x63A3B31AE76B0B0AULL,
		0xFC34CE6850DD3E15ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EC74A676D126BDULL,
		0xB38EF89FB02C7788ULL,
		0x865DCDEBFFFBD7D3ULL,
		0x77C8206F437BFC00ULL,
		0x2EDD0F5BA50E5147ULL,
		0x6DE1DE0813D08DD3ULL,
		0x2AEBD314A34C430EULL,
		0xE37801CEDFDE194BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31A5A6233DAE380AULL,
		0x9A042BE3E41AC048ULL,
		0x9FBC810BB65808DBULL,
		0x1B283C78245C90D3ULL,
		0x8D683F1EE6B7EC9CULL,
		0x3D168D3D9A7D25D0ULL,
		0x38B7E006441EC7FCULL,
		0x18BCCC9970FF24CAULL
	}};
	sign = 0;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C606C9CDC069E45ULL,
		0xFD3337CEDE02A17BULL,
		0xB88D6D6E987F2830ULL,
		0xE661BC7EF675F854ULL,
		0xFC322ED09064621BULL,
		0xA0644B27680E4AE5ULL,
		0xF47672DA32805DBEULL,
		0x16758E38A83CF9DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9044919E53BF39AULL,
		0x0CE67FC581A39C84ULL,
		0xAD806F5A891FD48CULL,
		0x530FCDE4764C9CA1ULL,
		0x4B0370FC156A7069ULL,
		0x54DBD127DE5BCD05ULL,
		0x213C0A81A2846E22ULL,
		0x90FE0BCC2BD639E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x635C2382F6CAAAABULL,
		0xF04CB8095C5F04F6ULL,
		0x0B0CFE140F5F53A4ULL,
		0x9351EE9A80295BB3ULL,
		0xB12EBDD47AF9F1B2ULL,
		0x4B8879FF89B27DE0ULL,
		0xD33A68588FFBEF9CULL,
		0x8577826C7C66BFFBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0BAF9ED7D1516DEEULL,
		0x4930E4F73A14A315ULL,
		0x7450874E78B6ED1CULL,
		0x8860019844317E20ULL,
		0x108B42368478D39AULL,
		0x9174F9837175C9EFULL,
		0x95BAC949C5C13D90ULL,
		0x41EEC44B56E44492ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B751A708A46125ULL,
		0x258E41B7290899D0ULL,
		0x3A28B5D8C6356C63ULL,
		0xA2E9F60C98272901ULL,
		0x31D4B8B5A014D145ULL,
		0x9D523B21CED7DD8DULL,
		0x1C0617F4CFAC4CB2ULL,
		0x160B24509DA5C9DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F84D30C8AD0CC9ULL,
		0x23A2A340110C0944ULL,
		0x3A27D175B28180B9ULL,
		0xE5760B8BAC0A551FULL,
		0xDEB68980E4640254ULL,
		0xF422BE61A29DEC61ULL,
		0x79B4B154F614F0DDULL,
		0x2BE39FFAB93E7AB3ULL
	}};
	sign = 0;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x657948188758F73EULL,
		0x335332B7D89929E2ULL,
		0xAB2AA108FB250074ULL,
		0xDA8E84B423577E86ULL,
		0x080C25B71C559503ULL,
		0x1EFB2B0F3AF6305DULL,
		0xEFFD652ED4A44673ULL,
		0x4EF50EDDD6399AE4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE7F28AAD16FD39ULL,
		0x6E74BC3061F9F29DULL,
		0xD1ED4595F71DDE59ULL,
		0x127E5A7C38D957B9ULL,
		0xFCE746B19F7AA02EULL,
		0xB29A914B31535ED8ULL,
		0xEB67A429E2E81E4BULL,
		0x9A6F6303152FB6E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0891558DDA41FA05ULL,
		0xC4DE7687769F3745ULL,
		0xD93D5B730407221AULL,
		0xC8102A37EA7E26CCULL,
		0x0B24DF057CDAF4D5ULL,
		0x6C6099C409A2D184ULL,
		0x0495C104F1BC2827ULL,
		0xB485ABDAC109E401ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE71EA0848F62A1D6ULL,
		0xB3E109C1926BF5E5ULL,
		0x7A1B2D013432B8FFULL,
		0x5745ABE3E27A5A38ULL,
		0x86C34EFAD4891FA8ULL,
		0xBFCE001B99B81245ULL,
		0x6BCD68326C4B96E3ULL,
		0xA0565C7F5E76610FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDE62FA05D46EE3ULL,
		0x1BD17C97084817DFULL,
		0x3D658464178273E0ULL,
		0xCA15BC0A709FAF18ULL,
		0x1280372E509D2DDCULL,
		0x225E451D9D3E89C7ULL,
		0x4E5ABDA4923A0C94ULL,
		0xA76836C263238D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89403D8A898E32F3ULL,
		0x980F8D2A8A23DE06ULL,
		0x3CB5A89D1CB0451FULL,
		0x8D2FEFD971DAAB20ULL,
		0x744317CC83EBF1CBULL,
		0x9D6FBAFDFC79887EULL,
		0x1D72AA8DDA118A4FULL,
		0xF8EE25BCFB52D40BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2D272AEC4481AA0EULL,
		0xE1E592ADFD5E0EF0ULL,
		0x3230544F7322AEE3ULL,
		0x6E6DEF40CD617A26ULL,
		0xEE38B1BBC85001EAULL,
		0x067C4C3CB7577AC5ULL,
		0x408FF49F6AF49A99ULL,
		0xD3DB1609079C53BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE8D5252897D299ULL,
		0x7EC98EC89D679BD4ULL,
		0xA5712BAEBBB2F848ULL,
		0x3141E6778434BB1EULL,
		0x942384E9CBBBDC26ULL,
		0xE9B3CF09CDA9AB3AULL,
		0x9713236ED22F901DULL,
		0xB8C89C70D04774A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D3E55C71BE9D775ULL,
		0x631C03E55FF6731BULL,
		0x8CBF28A0B76FB69BULL,
		0x3D2C08C9492CBF07ULL,
		0x5A152CD1FC9425C4ULL,
		0x1CC87D32E9ADCF8BULL,
		0xA97CD13098C50A7BULL,
		0x1B1279983754DF19ULL
	}};
	sign = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x70843C78B129CCC9ULL,
		0x17A82B3A7C939264ULL,
		0xAF592D96B1CF8574ULL,
		0xA0A5E21785D7FA08ULL,
		0x31E69208004DFF30ULL,
		0x0187A2EA70093DDBULL,
		0x182EC8E9595672CEULL,
		0xC41AC86D1C5BB172ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x403C2558F7880799ULL,
		0x345028165555A5F0ULL,
		0x4B994DC1C6DE140CULL,
		0x2762D61F4E73D69AULL,
		0xDE0A66D0E4B87441ULL,
		0x5FCD8F054D856CCDULL,
		0x009EB561F673180CULL,
		0x7F5F04FC5F70900AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3048171FB9A1C530ULL,
		0xE3580324273DEC74ULL,
		0x63BFDFD4EAF17167ULL,
		0x79430BF83764236EULL,
		0x53DC2B371B958AEFULL,
		0xA1BA13E52283D10DULL,
		0x1790138762E35AC1ULL,
		0x44BBC370BCEB2168ULL
	}};
	sign = 0;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x602121256D10A7AEULL,
		0x450EEB284C4EA3EAULL,
		0x7C580E16F72D3790ULL,
		0x28369712747E6325ULL,
		0x44BCAA3FFC77BCB2ULL,
		0x0CFD5B9C6E506ABEULL,
		0x08B1FF3694F9369EULL,
		0xB8DB8A78409A3CC0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x01B4B4805EAB17C9ULL,
		0x75723C396C509705ULL,
		0x1C56E6C8752AB1E5ULL,
		0xA6974FCBE269FFFCULL,
		0xD526A4DF2CE5D606ULL,
		0x98C2B38BFB80CC68ULL,
		0xA2F1802D906CFF66ULL,
		0xB9F6C352549DE1FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E6C6CA50E658FE5ULL,
		0xCF9CAEEEDFFE0CE5ULL,
		0x6001274E820285AAULL,
		0x819F474692146329ULL,
		0x6F960560CF91E6ABULL,
		0x743AA81072CF9E55ULL,
		0x65C07F09048C3737ULL,
		0xFEE4C725EBFC5AC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBC323114F67D313ULL,
		0xC52D4BDAD6270714ULL,
		0xAAEC654C018D747DULL,
		0xD23AF55F4C17B443ULL,
		0x2B8AB1DE7A3E5A65ULL,
		0x4C0B4F60DC0345B5ULL,
		0xD3C6B04CB72444D7ULL,
		0xB0B1A784BE578FC9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C789D4280F2303ULL,
		0x351E002066563975ULL,
		0x6F80AEB766787DF0ULL,
		0xF3386C9EA16A959CULL,
		0x22B71B4F0220B084ULL,
		0x88D0BE8F4DF00559ULL,
		0x596665E925ECB8A7ULL,
		0x37CD33029034B60AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4FB993D2758B010ULL,
		0x900F4BBA6FD0CD9FULL,
		0x3B6BB6949B14F68DULL,
		0xDF0288C0AAAD1EA7ULL,
		0x08D3968F781DA9E0ULL,
		0xC33A90D18E13405CULL,
		0x7A604A6391378C2FULL,
		0x78E474822E22D9BFULL
	}};
	sign = 0;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5D4FB75F738D28EULL,
		0x8A9FB87F0E353E66ULL,
		0x8DA54C4B1755A02CULL,
		0xA188C5BD98D5AA34ULL,
		0xFC1EA7218199C6AAULL,
		0x26F3D903AECF53E9ULL,
		0x2A963FBBD7CBF001ULL,
		0x4E8F0524C8D92D85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98CA6BE49591FF21ULL,
		0x4C70020B2D9E85F8ULL,
		0xABCC034703D3E9C4ULL,
		0xA7ECBA0320E5E88CULL,
		0x3A1EAFB0E71049FBULL,
		0xD3F99B3539503D48ULL,
		0xC39640B418DB6A83ULL,
		0xB4E22F671D258BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D0A8F9161A6D36DULL,
		0x3E2FB673E096B86EULL,
		0xE1D949041381B668ULL,
		0xF99C0BBA77EFC1A7ULL,
		0xC1FFF7709A897CAEULL,
		0x52FA3DCE757F16A1ULL,
		0x66FFFF07BEF0857DULL,
		0x99ACD5BDABB3A1E0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBD5DA02174EA7290ULL,
		0x14E800E7D578C569ULL,
		0x98081266BA836252ULL,
		0xA93F145A74EB7688ULL,
		0x95F8162FBA19F44DULL,
		0xD747F1E83517FCA8ULL,
		0xF9DD0E34832ADCB4ULL,
		0xBCDE1825F331E557ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83B9C9CC352C866FULL,
		0x50C3A9B321F6000BULL,
		0x745AAFCFC600A4B6ULL,
		0x2DF6AD1B3E5F4321ULL,
		0xC1D7014F24460643ULL,
		0xFF19BFA36F49F724ULL,
		0xFF03910D67395B5EULL,
		0x042458898AE1CB44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39A3D6553FBDEC21ULL,
		0xC4245734B382C55EULL,
		0x23AD6296F482BD9BULL,
		0x7B48673F368C3367ULL,
		0xD42114E095D3EE0AULL,
		0xD82E3244C5CE0583ULL,
		0xFAD97D271BF18155ULL,
		0xB8B9BF9C68501A12ULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD622F45103BE6A3FULL,
		0x750D2FD939E6BC31ULL,
		0x4324F23F36F79E2AULL,
		0x3A9E60F80F7D94E4ULL,
		0xB9E6C3F59C89AD5EULL,
		0xA1A4D596E848BBF6ULL,
		0x64B865B79488A1E9ULL,
		0x74EA5A4BBC158180ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7802AD94B1863321ULL,
		0xFC7C8A5FDEDD0B67ULL,
		0x84313D81B0B7518FULL,
		0x63DC0DD81137808CULL,
		0x4082F3656E220183ULL,
		0x39FA2C6A5AD605FCULL,
		0xC17CA244229DC9C7ULL,
		0x8370DC6CECDE874FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E2046BC5238371EULL,
		0x7890A5795B09B0CAULL,
		0xBEF3B4BD86404C9AULL,
		0xD6C2531FFE461457ULL,
		0x7963D0902E67ABDAULL,
		0x67AAA92C8D72B5FAULL,
		0xA33BC37371EAD822ULL,
		0xF1797DDECF36FA30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x946E9A8C2E78E534ULL,
		0x2425ED09F1AAC92AULL,
		0x19522547CA0FBDACULL,
		0x1EF5F16D9A50C709ULL,
		0x3C761E09AAA6E9D5ULL,
		0xF2471F55A0059F05ULL,
		0xAC2C737A80A3DE1BULL,
		0x296F337DBF415BD7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DDC512422949073ULL,
		0xFE9C77E317C0D9AEULL,
		0x19AF8333FECE3E70ULL,
		0x44CD458FCBE15113ULL,
		0x33990E879F5C7710ULL,
		0x9C55B71CE2410ED2ULL,
		0x25D0F26AD775168AULL,
		0x025774865E2EE077ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF69249680BE454C1ULL,
		0x25897526D9E9EF7BULL,
		0xFFA2A213CB417F3BULL,
		0xDA28ABDDCE6F75F5ULL,
		0x08DD0F820B4A72C4ULL,
		0x55F16838BDC49033ULL,
		0x865B810FA92EC791ULL,
		0x2717BEF761127B60ULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6F14D3A7F55662D2ULL,
		0xA601DFCC01D95E41ULL,
		0x95D9D3B03DE9B1CBULL,
		0xFFD39BA930270DBBULL,
		0x6FCBA4A606B77E65ULL,
		0x36B732D8A69EDE30ULL,
		0x425613F4FA62C21DULL,
		0x7FF9F3879948CDFAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8E00A8E2113C94ULL,
		0xBCC26464DFB1BA86ULL,
		0xA3AD2A8228FE8A1FULL,
		0x1CF1E36FF2190745ULL,
		0xEABFEDF765B4BC11ULL,
		0x88817D8021D3EBBBULL,
		0xDD13A2D3B0FF9283ULL,
		0x614A810F2A730FC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF186D2FF1345263EULL,
		0xE93F7B672227A3BAULL,
		0xF22CA92E14EB27ABULL,
		0xE2E1B8393E0E0675ULL,
		0x850BB6AEA102C254ULL,
		0xAE35B55884CAF274ULL,
		0x6542712149632F99ULL,
		0x1EAF72786ED5BE32ULL
	}};
	sign = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC3399455C17B5CCFULL,
		0x6B9ABE28DFD1AED9ULL,
		0x2987DCC36BD2BA51ULL,
		0xB4D699D283220700ULL,
		0x7BCC875C8A08E546ULL,
		0x4B2F2118940D78FDULL,
		0x173CD3F73E88DE2BULL,
		0x29443F3FDE7C9640ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25B6E42A3AF10DAULL,
		0xDA537C1900CD86C9ULL,
		0xD5B57520210C8641ULL,
		0xD57725C3C9A0E1E6ULL,
		0x6B054359F2743D46ULL,
		0xE56DBF0C9EBB3BECULL,
		0x05A6BC21964B7CE7ULL,
		0x20BBB9820E574B90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20DE26131DCC4BF5ULL,
		0x9147420FDF042810ULL,
		0x53D267A34AC6340FULL,
		0xDF5F740EB9812519ULL,
		0x10C744029794A7FFULL,
		0x65C1620BF5523D11ULL,
		0x119617D5A83D6143ULL,
		0x088885BDD0254AB0ULL
	}};
	sign = 0;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F9AA249B163221DULL,
		0x3B45DC0B9522F953ULL,
		0x723A2EDCB2F9054FULL,
		0x32AC297472044075ULL,
		0x02D410EB722FD1A1ULL,
		0x1AD9DF7B51B31313ULL,
		0x903456149BF66284ULL,
		0xBD57F3D1F2A7B0D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2499443BBF461F56ULL,
		0x6A4AABF81989D517ULL,
		0xA54E11F390D3CDEBULL,
		0xA96325E4CFB56CB4ULL,
		0xF418B30FF908E299ULL,
		0x4D9BA2D387D96E70ULL,
		0x9DF91F722CEA72D9ULL,
		0x296996D70A03B731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB015E0DF21D02C7ULL,
		0xD0FB30137B99243BULL,
		0xCCEC1CE922253763ULL,
		0x8949038FA24ED3C0ULL,
		0x0EBB5DDB7926EF07ULL,
		0xCD3E3CA7C9D9A4A2ULL,
		0xF23B36A26F0BEFAAULL,
		0x93EE5CFAE8A3F99FULL
	}};
	sign = 0;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBEEFE9643506638FULL,
		0x95EA05E020BC9B99ULL,
		0x957BB1936F9E34B5ULL,
		0x8A64412E146911BBULL,
		0x1316D64D499578EFULL,
		0x13094FB649598FDEULL,
		0x68EB8719279F35E0ULL,
		0x652DB34D261F56BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6303B699A7D88A1FULL,
		0x856FB3F859C610F3ULL,
		0x44615F9511C0E3D5ULL,
		0xC4A2DC04A8194C45ULL,
		0x16D32395316BACB3ULL,
		0xCB3FF611504479B0ULL,
		0x6392809E77E4EB72ULL,
		0x3999E38DFAF76C14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BEC32CA8D2DD970ULL,
		0x107A51E7C6F68AA6ULL,
		0x511A51FE5DDD50E0ULL,
		0xC5C165296C4FC576ULL,
		0xFC43B2B81829CC3BULL,
		0x47C959A4F915162DULL,
		0x0559067AAFBA4A6DULL,
		0x2B93CFBF2B27EAA7ULL
	}};
	sign = 0;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6A141630B5BB30A1ULL,
		0x6B5004DE949EBC2EULL,
		0x7B34C33EAB856CD9ULL,
		0xCFC59EFAE17C4E40ULL,
		0xE632F495E55D6840ULL,
		0x58A9313E6A8CC49AULL,
		0x17A44D5F99647574ULL,
		0x3B66083DEB517373ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28B78BA78CCC9F4ULL,
		0x7978B886EF26CE94ULL,
		0x36C09DF96F87B05DULL,
		0x889AB659FCAFBDF2ULL,
		0xCA1A000116BF8013ULL,
		0x696A8814534F82F3ULL,
		0x1A110ACCB7D93CB8ULL,
		0x8C336677149FC2DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77889D763CEE66ADULL,
		0xF1D74C57A577ED99ULL,
		0x447425453BFDBC7BULL,
		0x472AE8A0E4CC904EULL,
		0x1C18F494CE9DE82DULL,
		0xEF3EA92A173D41A7ULL,
		0xFD934292E18B38BBULL,
		0xAF32A1C6D6B1B095ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B55DEAEEA7879BFULL,
		0x47C4F56212D8D49BULL,
		0xD71CEEE26082077CULL,
		0x8B6DF7742456D85BULL,
		0x83BD1DB7E0C592E8ULL,
		0xA9B52540AF47D076ULL,
		0x325A712E7EA44DB9ULL,
		0xFA975A7343B7C259ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CAADF80AB8D320AULL,
		0x57E64F05B0274E10ULL,
		0x2B4BB953A71C5E34ULL,
		0xF1B3A22771689E43ULL,
		0xB2C10405D8A4FDD0ULL,
		0xABF9843478DA2D76ULL,
		0x43D1ACB46B1B98E0ULL,
		0x61C208AA1018B160ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEAAFF2E3EEB47B5ULL,
		0xEFDEA65C62B1868AULL,
		0xABD1358EB965A947ULL,
		0x99BA554CB2EE3A18ULL,
		0xD0FC19B208209517ULL,
		0xFDBBA10C366DA2FFULL,
		0xEE88C47A1388B4D8ULL,
		0x98D551C9339F10F8ULL
	}};
	sign = 0;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x661FE1C0FACF3839ULL,
		0x682C738BA4370706ULL,
		0x8F349B436D517C41ULL,
		0x411963999AAEB8DFULL,
		0x3D22E67BD123911BULL,
		0x2E71F9B076404E21ULL,
		0xCB49CD6E4CB45333ULL,
		0x683029D38BE7E3C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ADAC3D1CA6B8FD4ULL,
		0x63CCDF31FF47C4C4ULL,
		0xE8D331328ACADE50ULL,
		0x0FE34932C93DA7AFULL,
		0x08E1A1CB61C5555CULL,
		0xAE55D63A145AF8DEULL,
		0x96658E4A339EA7FFULL,
		0xE89031FEE9F17ECEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B451DEF3063A865ULL,
		0x045F9459A4EF4242ULL,
		0xA6616A10E2869DF1ULL,
		0x31361A66D171112FULL,
		0x344144B06F5E3BBFULL,
		0x801C237661E55543ULL,
		0x34E43F241915AB33ULL,
		0x7F9FF7D4A1F664FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98DD69838C91F934ULL,
		0xFC9F68BF072502E4ULL,
		0xCA347A1CEB05199DULL,
		0xC96264A237CAA030ULL,
		0xF02BC5A24E865E11ULL,
		0x262E16EDDB80F94CULL,
		0x3859169676E2F2F2ULL,
		0x0E552FFBF80D59FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D85B77428475BB2ULL,
		0xC1624FD6D49A7D9EULL,
		0x620CF20421561231ULL,
		0x1B03702865ABE94DULL,
		0x7360E3A15E9EBD69ULL,
		0x0DA1CB1B5A015B85ULL,
		0xE01E13E82C7FAA64ULL,
		0x8FED4D2DE1B0EB5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B57B20F644A9D82ULL,
		0x3B3D18E8328A8546ULL,
		0x68278818C9AF076CULL,
		0xAE5EF479D21EB6E3ULL,
		0x7CCAE200EFE7A0A8ULL,
		0x188C4BD2817F9DC7ULL,
		0x583B02AE4A63488EULL,
		0x7E67E2CE165C6E9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE39CDA3321025F6ULL,
		0x8124A77D4A095DE8ULL,
		0xAD046B3C04A58B2FULL,
		0x4DABE596B4FE0CA2ULL,
		0xB3D9F2B7D5935FD8ULL,
		0x9A3AC2CBDE1F4528ULL,
		0x7C333EB90BBC7EEEULL,
		0xDED1F32961B66087ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF968AD4DEDD3FB1BULL,
		0xDECFCF1382806253ULL,
		0xE25995B3841D3E7EULL,
		0xBF31F98CB25317D9ULL,
		0x065E5440496DF41CULL,
		0xA13142AE1E15D93DULL,
		0x11895875B83B2845ULL,
		0x2A0023733EB93AA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4D12055443C2ADBULL,
		0xA254D869C788FB94ULL,
		0xCAAAD58880884CB0ULL,
		0x8E79EC0A02AAF4C8ULL,
		0xAD7B9E778C256BBBULL,
		0xF909801DC0096BEBULL,
		0x6AA9E643538156A8ULL,
		0xB4D1CFB622FD25DFULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD61085813782B4A4ULL,
		0x3F1AD6F43ED3AF72ULL,
		0x422CDE5D1F777E12ULL,
		0x6A56CA8D01E1C530ULL,
		0xDCD990DEA9C87240ULL,
		0x62FF9E795D05D4ADULL,
		0x1726D86D577A10BAULL,
		0x835237D9DBBFDE02ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3D04A6EF44E6360ULL,
		0xA7645E098FB38DD0ULL,
		0xC9EE6EE74ED66BC9ULL,
		0xB503DD5D32671471ULL,
		0xA8E3875824EA9A09ULL,
		0xE306893769B08FC8ULL,
		0x3230197699D01355ULL,
		0xE4D436E856E372BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2403B1243345144ULL,
		0x97B678EAAF2021A1ULL,
		0x783E6F75D0A11248ULL,
		0xB552ED2FCF7AB0BEULL,
		0x33F6098684DDD836ULL,
		0x7FF91541F35544E5ULL,
		0xE4F6BEF6BDA9FD64ULL,
		0x9E7E00F184DC6B44ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6BAD42EB74C94E6EULL,
		0x9C5A08DE0AC551E3ULL,
		0xCCA34D9924780EB6ULL,
		0xCEB72307022717A2ULL,
		0x1F619B3FAA3DB7CFULL,
		0xC45281EF1B35B785ULL,
		0x07C9F8E712ACF012ULL,
		0x0F58AA1FEA92B71CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C7EBF23396ADA7ULL,
		0xCB0D971305C955A8ULL,
		0xF4122355E2EF4EE1ULL,
		0x21FE5A1FF4AB7C10ULL,
		0xD50AB49DE3D2915CULL,
		0x68C820638068778BULL,
		0xA29B5ACE0892586CULL,
		0xB5FE5CF6215B3B74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4E556F94132A0C7ULL,
		0xD14C71CB04FBFC3AULL,
		0xD8912A434188BFD4ULL,
		0xACB8C8E70D7B9B91ULL,
		0x4A56E6A1C66B2673ULL,
		0x5B8A618B9ACD3FF9ULL,
		0x652E9E190A1A97A6ULL,
		0x595A4D29C9377BA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6965C61F4B532461ULL,
		0x64E23FF74FACAEB8ULL,
		0x3EBBF7B13B0E7FE1ULL,
		0x0C3A5042618E15A7ULL,
		0xF4793C45F3924C19ULL,
		0x5E11835797971BE2ULL,
		0xDE1B87105EF1813CULL,
		0xE9D828057D1373DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0480CCDD3A969F81ULL,
		0xF2324FD733143F02ULL,
		0x25C10512DA7E9B6FULL,
		0xACD2E4F7E68DA49FULL,
		0xB807961946EBE9A9ULL,
		0xCE7B2A79FBDEC499ULL,
		0x701A42039A471E01ULL,
		0xE01DE81779FDD5C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64E4F94210BC84E0ULL,
		0x72AFF0201C986FB6ULL,
		0x18FAF29E608FE471ULL,
		0x5F676B4A7B007108ULL,
		0x3C71A62CACA6626FULL,
		0x8F9658DD9BB85749ULL,
		0x6E01450CC4AA633AULL,
		0x09BA3FEE03159E15ULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5AF2D979E279A27ULL,
		0x4DB7C757F0A43826ULL,
		0x10B4BDC9319165E6ULL,
		0x83DDF8CF6E98F6AFULL,
		0xF733E1E36B854974ULL,
		0x2A9082FFF58ABE76ULL,
		0x684E99E7A55B6A92ULL,
		0x2860A8895B2E850EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACBABEFB29BA03BULL,
		0x330E7420E07D7FA1ULL,
		0x23FC2F51DB99A425ULL,
		0xB7C7181A6C547C3FULL,
		0x784058A5D7912054ULL,
		0x10642C246DB054A2ULL,
		0x5EC93389B2145BC1ULL,
		0xD08997F93F1EA578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAE381A7EB8BF9ECULL,
		0x1AA953371026B884ULL,
		0xECB88E7755F7C1C1ULL,
		0xCC16E0B502447A6FULL,
		0x7EF3893D93F4291FULL,
		0x1A2C56DB87DA69D4ULL,
		0x0985665DF3470ED1ULL,
		0x57D710901C0FDF96ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x492CA376FE0539E3ULL,
		0x89DBAFA8793D89DDULL,
		0x19605E19B4901330ULL,
		0x634E20B1044656B2ULL,
		0xD1477CF39AE5E21EULL,
		0x40A643B2D8376160ULL,
		0xF7A55833D88CD433ULL,
		0xEA6E1C70DC93F514ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D364B0534A1EB8ULL,
		0x7CA3138B9D5D517DULL,
		0xC8A6FAA1CA616236ULL,
		0x28AFAB97D620D905ULL,
		0xE9D20AC85E34D04AULL,
		0x4D89BF9F5BE7F8A2ULL,
		0xE5E4EB424A50DE23ULL,
		0xAE8CED039F46CC90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75593EC6AABB1B2BULL,
		0x0D389C1CDBE0385FULL,
		0x50B96377EA2EB0FAULL,
		0x3A9E75192E257DACULL,
		0xE775722B3CB111D4ULL,
		0xF31C84137C4F68BDULL,
		0x11C06CF18E3BF60FULL,
		0x3BE12F6D3D4D2884ULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB278DF2D82B6C848ULL,
		0x945875D8E0B85A06ULL,
		0x24F7656A1EF4B8EEULL,
		0x208F7D69BD05D26EULL,
		0x7B9D3F282FE5BB6AULL,
		0x11088C45585893B8ULL,
		0x379A2CE76E553235ULL,
		0x0D993CC92FA1DE90ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FBBF81D8E12E5B4ULL,
		0x76D4F399DC627737ULL,
		0x5770DF47C684F78FULL,
		0x6A36CF55C0EB7B1CULL,
		0x011F447A61F9372EULL,
		0x84CC2FBBD84B2302ULL,
		0x69104726E4995C08ULL,
		0x686DBAA967E37C5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2BCE70FF4A3E294ULL,
		0x1D83823F0455E2CFULL,
		0xCD868622586FC15FULL,
		0xB658AE13FC1A5751ULL,
		0x7A7DFAADCDEC843BULL,
		0x8C3C5C89800D70B6ULL,
		0xCE89E5C089BBD62CULL,
		0xA52B821FC7BE6230ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9523DE0AC7513200ULL,
		0x3AE2D93479B10FC9ULL,
		0x05F0B43C931B3CC9ULL,
		0x0A94D1A522ACB3B7ULL,
		0xC617324A7F387B8BULL,
		0x21704F0E8F859780ULL,
		0xEBE3F5DD24CE82AAULL,
		0xBD8DA18B85F24601ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5140C296EB630FULL,
		0x7CE284A2C4000CF1ULL,
		0xA04F59E9FF778692ULL,
		0x794F160514CB0BF4ULL,
		0xA6EABA5A642224F7ULL,
		0x26C38487C50AD7D4ULL,
		0xDB172B643BD8042EULL,
		0x6DD8C15F939FC486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7D29D483065CEF1ULL,
		0xBE005491B5B102D7ULL,
		0x65A15A5293A3B636ULL,
		0x9145BBA00DE1A7C2ULL,
		0x1F2C77F01B165693ULL,
		0xFAACCA86CA7ABFACULL,
		0x10CCCA78E8F67E7BULL,
		0x4FB4E02BF252817BULL
	}};
	sign = 0;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x032EA20B1A9CDC92ULL,
		0x1BD50729B8656AA1ULL,
		0x49239ADD535E0841ULL,
		0x8D259A1084F0CDF2ULL,
		0x5EDB5B394A413454ULL,
		0x7E12FCAC65E84E47ULL,
		0xB203E51352096A4BULL,
		0xAF72A4A42753BBFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6EB26D73E75B66ULL,
		0x64E9DDB01E94924FULL,
		0xB0B78E01ADD55ADDULL,
		0x611748D53D6CC2C1ULL,
		0x087DBB41B10E1D37ULL,
		0xCF1716005A0428C0ULL,
		0x0EE9EB5AC15D35D6ULL,
		0x99F2CA86783225BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5BFEF9DA6B5812CULL,
		0xB6EB297999D0D851ULL,
		0x986C0CDBA588AD63ULL,
		0x2C0E513B47840B30ULL,
		0x565D9FF79933171DULL,
		0xAEFBE6AC0BE42587ULL,
		0xA319F9B890AC3474ULL,
		0x157FDA1DAF219643ULL
	}};
	sign = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1ADF7809700160A2ULL,
		0xF1AC682CE377A901ULL,
		0xB99223A42C9BCB43ULL,
		0x0C9D57A6A7D799C7ULL,
		0x18530F8DEC1344E1ULL,
		0xA31AE58707953D74ULL,
		0x90D5C9CACAF4BD35ULL,
		0x17D5F024A06AD421ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E5636404344DD68ULL,
		0x73B7E4EDD135F500ULL,
		0x3603FE07588745D0ULL,
		0x98135D29878D86DCULL,
		0x6C9E63EFAFFDF721ULL,
		0x32D6F7B8ECEC9F2DULL,
		0x38FE5AE5D7F75B67ULL,
		0xC444E1B07C397AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C8941C92CBC833AULL,
		0x7DF4833F1241B400ULL,
		0x838E259CD4148573ULL,
		0x7489FA7D204A12EBULL,
		0xABB4AB9E3C154DBFULL,
		0x7043EDCE1AA89E46ULL,
		0x57D76EE4F2FD61CEULL,
		0x53910E742431597AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF69471A65C988CCDULL,
		0x7FE2FF1CC0779E7DULL,
		0x5EB778DE87C9A7FBULL,
		0x0ECD5F54A7556C4DULL,
		0x327D78BFD4CC1887ULL,
		0x1BE4CEB4F6DDAFB8ULL,
		0xF05E402C86B34D3AULL,
		0xAF1837DABE303C4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x71765A653AEBA427ULL,
		0x3A6231EB62F2F8CFULL,
		0xBFBEFCEFF2F58409ULL,
		0x73988DA8AC449722ULL,
		0x9DA620D7F4E8A99BULL,
		0x5D5C3C9D70403331ULL,
		0x6A3F7B22B61F85E7ULL,
		0x975264AFA407E5F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x851E174121ACE8A6ULL,
		0x4580CD315D84A5AEULL,
		0x9EF87BEE94D423F2ULL,
		0x9B34D1ABFB10D52AULL,
		0x94D757E7DFE36EEBULL,
		0xBE889217869D7C86ULL,
		0x861EC509D093C752ULL,
		0x17C5D32B1A285659ULL
	}};
	sign = 0;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE629F8FBDB87E82ULL,
		0x743725CB3BD73E8EULL,
		0x98B31E5FB5D4A325ULL,
		0xDDD1B21C3BF45D99ULL,
		0xB3679F387BFFCB22ULL,
		0x376ABA249BCF168FULL,
		0x408740820DA4E749ULL,
		0x290B2785A67F3F0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA41AED517F2135C4ULL,
		0x656946DFE85972A1ULL,
		0xB705536FF06E67A5ULL,
		0x7B6843FD5B528959ULL,
		0x10CE5D1227B6A4E9ULL,
		0xF53357FECA03E591ULL,
		0xA781AEB322F337F9ULL,
		0xC118C10AD32903C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A47B23E3E9748BEULL,
		0x0ECDDEEB537DCBEDULL,
		0xE1ADCAEFC5663B80ULL,
		0x62696E1EE0A1D43FULL,
		0xA299422654492639ULL,
		0x42376225D1CB30FEULL,
		0x990591CEEAB1AF4FULL,
		0x67F2667AD3563B4AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC033D1CFA373868BULL,
		0x8545BA6AA177FB2CULL,
		0x4BC49D0B2E75D69DULL,
		0xE66F083105CF4A44ULL,
		0x9FE90537D68BD24FULL,
		0xF192DFD4C22CCF39ULL,
		0x72D2BDB44F0BD46BULL,
		0xE5876979B02B9336ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD7BDDA8B7D9188ULL,
		0x56BD939E36E59DFCULL,
		0xD3E3F47F384F48CFULL,
		0xDBF3A1F9199E9C3EULL,
		0xB54912A0960BE81DULL,
		0xE060D75B3ADC6222ULL,
		0xAA0314BDF6786A3EULL,
		0x1719792993F51E7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x825C13F517F5F503ULL,
		0x2E8826CC6A925D30ULL,
		0x77E0A88BF6268DCEULL,
		0x0A7B6637EC30AE05ULL,
		0xEA9FF297407FEA32ULL,
		0x1132087987506D16ULL,
		0xC8CFA8F658936A2DULL,
		0xCE6DF0501C3674B7ULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x157C11E3A8646E48ULL,
		0xAACD509E571E7761ULL,
		0x99BE9949BE349811ULL,
		0x333D32F8FA1EC386ULL,
		0x81059686B45B898DULL,
		0x73D8A8D60B4C8172ULL,
		0x656FCCFEA473D33EULL,
		0x15E84FF1C05BDC8EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D682C001963A73ULL,
		0x3448039A887FC05DULL,
		0x6F4F4886346AFB40ULL,
		0xB0FE914D9FEF8EF8ULL,
		0xBB704ECCB4C02F4DULL,
		0xE48E080F5B417EAEULL,
		0xD6212FEDAB96A6DDULL,
		0xCA4C9B77F673291FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FA58F23A6CE33D5ULL,
		0x76854D03CE9EB703ULL,
		0x2A6F50C389C99CD1ULL,
		0x823EA1AB5A2F348EULL,
		0xC59547B9FF9B5A3FULL,
		0x8F4AA0C6B00B02C3ULL,
		0x8F4E9D10F8DD2C60ULL,
		0x4B9BB479C9E8B36EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69953E710B5B9C7AULL,
		0xF9EF9C80903F51C1ULL,
		0x6365D290F3A126B3ULL,
		0xDB5E813C3473E507ULL,
		0x28BCA239BDCEFD77ULL,
		0xDABF36DB14DC43ADULL,
		0x74083FFB54E88BF3ULL,
		0xFBAEB39571CF9427ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A66B0F656DEF974ULL,
		0xBF7DFF0A3A8CB486ULL,
		0xB6834708D0FA51C7ULL,
		0xD2D7183FFA3A0C46ULL,
		0x6AEA6FF115D3E883ULL,
		0x3F368DF1F14B19F7ULL,
		0x5D05C6001BFAE606ULL,
		0x77A3CBCD20A984D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2E8D7AB47CA306ULL,
		0x3A719D7655B29D3AULL,
		0xACE28B8822A6D4ECULL,
		0x088768FC3A39D8C0ULL,
		0xBDD23248A7FB14F4ULL,
		0x9B88A8E9239129B5ULL,
		0x170279FB38EDA5EDULL,
		0x840AE7C851260F50ULL
	}};
	sign = 0;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA84ED016C20E5C5ULL,
		0x92F211521638CB7FULL,
		0xC0B6223D312D088DULL,
		0x30F40DD639A8E569ULL,
		0x56E087E6DCD204F1ULL,
		0xD174BC551AE0BD47ULL,
		0xF2B41FCD9F63EEA3ULL,
		0x4AA8660D78138650ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A6ACC4ADB93CAEULL,
		0x3231E40F8898A2DBULL,
		0x606F933ED43D6F49ULL,
		0x3836B2EEC0EE97BDULL,
		0x190488873108ACA2ULL,
		0x5DB566CF654E9F49ULL,
		0x18DFD56507C8B177ULL,
		0x3AFDE454DD1528F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1DE403CBE67A917ULL,
		0x60C02D428DA028A3ULL,
		0x60468EFE5CEF9944ULL,
		0xF8BD5AE778BA4DACULL,
		0x3DDBFF5FABC9584EULL,
		0x73BF5585B5921DFEULL,
		0xD9D44A68979B3D2CULL,
		0x0FAA81B89AFE5D5EULL
	}};
	sign = 0;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC593D075E2307660ULL,
		0xBE55EBE924528282ULL,
		0x05A44599DE87317BULL,
		0xEFC68103828BD653ULL,
		0xA7478FBA407E055CULL,
		0x70296F81DF5EEEB8ULL,
		0xDD8941C7A7C66305ULL,
		0x1FC0C1A86650DFE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA2F97E6CB1B09C4ULL,
		0x65155B1B91FC726EULL,
		0x177828FDC7F324FBULL,
		0x2FE399257EC791EFULL,
		0x28FD1913EA44D6F3ULL,
		0x41BBE1B8EFD2AE0FULL,
		0xB425980C778AE2BFULL,
		0xE78C1604F6EF9414ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B64388F17156C9CULL,
		0x594090CD92561014ULL,
		0xEE2C1C9C16940C80ULL,
		0xBFE2E7DE03C44463ULL,
		0x7E4A76A656392E69ULL,
		0x2E6D8DC8EF8C40A9ULL,
		0x2963A9BB303B8046ULL,
		0x3834ABA36F614BCDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x043924A297FCE6B9ULL,
		0x6E62E74A8E873637ULL,
		0xE9F7F15131260C83ULL,
		0x3C1265F809C11D71ULL,
		0x912FFD3A0EF0F5D5ULL,
		0x21A8ED4DA7FC47B4ULL,
		0xDCB0A61004B7BB2DULL,
		0x7924D11AE6F9CD1EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F98C7917B2B434ULL,
		0x664E65C4B1246495ULL,
		0xD99D516769BF2190ULL,
		0x460FDA17F993ED38ULL,
		0xDBCF3A111CC1CC69ULL,
		0x00E7B117970E91D2ULL,
		0x541FB6FEFA9A7E8FULL,
		0xE3C11FB7D82951EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x623F9829804A3285ULL,
		0x08148185DD62D1A1ULL,
		0x105A9FE9C766EAF3ULL,
		0xF6028BE0102D3039ULL,
		0xB560C328F22F296BULL,
		0x20C13C3610EDB5E1ULL,
		0x8890EF110A1D3C9EULL,
		0x9563B1630ED07B2FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8D9CA210A426829EULL,
		0xD180F6349DF47567ULL,
		0x5ECE4071FFC04BE4ULL,
		0x18AA92E591BB5C04ULL,
		0xFBCCB63A42107087ULL,
		0xF5092C5A77A02F97ULL,
		0x3B53B0711A1B344EULL,
		0xA045F0707D5CD9C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6B245780516F24ULL,
		0x2CA6E58B8B77159FULL,
		0xEAF98121BDA11E7EULL,
		0x77830C865E3C5FF7ULL,
		0x9499B47D219AE21CULL,
		0xF835B42CBC23F155ULL,
		0xD4300CA3B74F0DFBULL,
		0x3DB705702552EC51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50317DB923D5137AULL,
		0xA4DA10A9127D5FC8ULL,
		0x73D4BF50421F2D66ULL,
		0xA127865F337EFC0CULL,
		0x673301BD20758E6AULL,
		0xFCD3782DBB7C3E42ULL,
		0x6723A3CD62CC2652ULL,
		0x628EEB005809ED72ULL
	}};
	sign = 0;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3BCA31A6FD744344ULL,
		0xEB5380B1A1DD5235ULL,
		0x33DCDB1C05F94177ULL,
		0x96E99C5DB3FBE1F8ULL,
		0xD9CCBA86EEC562FEULL,
		0x36484602BDD9C625ULL,
		0xC088EA89649AA295ULL,
		0x49D248AD989C9235ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17EA90BACE709F83ULL,
		0xB3D38E69C0306E8EULL,
		0xBAA03E2A09C778E9ULL,
		0x1A21D80A0B7297DAULL,
		0xFC6015D67DBAD5C0ULL,
		0xCBDFE1287AD01F9AULL,
		0xCBE55A99B7FDCF97ULL,
		0xCF70BD8BE682E4A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23DFA0EC2F03A3C1ULL,
		0x377FF247E1ACE3A7ULL,
		0x793C9CF1FC31C88EULL,
		0x7CC7C453A8894A1DULL,
		0xDD6CA4B0710A8D3EULL,
		0x6A6864DA4309A68AULL,
		0xF4A38FEFAC9CD2FDULL,
		0x7A618B21B219AD90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1EC1008A60CA0A44ULL,
		0x077CB6729C6B5AECULL,
		0x023B5B8767FC67D8ULL,
		0xD9EB4305AB6DABD6ULL,
		0xB21212D95FF302B8ULL,
		0x1D01C57764CFAAF5ULL,
		0xB85176B6DE8E0AAFULL,
		0xE6861B682D212218ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE30B83FEC1461EULL,
		0xFDD6E844850C9E98ULL,
		0x9F28A265DC87FA7FULL,
		0x61D0CEB7FB48891FULL,
		0xE5F3DDC0A033D0ADULL,
		0x59639ADECA507D05ULL,
		0x0D925365D46052DAULL,
		0x23E0427096B67E47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02DDF5066208C426ULL,
		0x09A5CE2E175EBC54ULL,
		0x6312B9218B746D58ULL,
		0x781A744DB02522B6ULL,
		0xCC1E3518BFBF320BULL,
		0xC39E2A989A7F2DEFULL,
		0xAABF23510A2DB7D4ULL,
		0xC2A5D8F7966AA3D1ULL
	}};
	sign = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x079A1A323EA50801ULL,
		0xEFA7847BECDADD3AULL,
		0x3A291A792052F207ULL,
		0x11283B48405CBAEBULL,
		0x8E253D0904B645D4ULL,
		0x0D3EA39BA3976F3CULL,
		0x57248191F0473733ULL,
		0x3B0EB9EDC7FA6324ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x636EB8EF2B535164ULL,
		0xA1D2AF632DA634BAULL,
		0x25D0854D4916E27BULL,
		0x17592BC67241B9D9ULL,
		0x5180AE0C7078A105ULL,
		0x10999FCD89A59F17ULL,
		0x349C025EF8BE07E7ULL,
		0x67D1F92D9E98A13EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA42B61431351B69DULL,
		0x4DD4D518BF34A87FULL,
		0x1458952BD73C0F8CULL,
		0xF9CF0F81CE1B0112ULL,
		0x3CA48EFC943DA4CEULL,
		0xFCA503CE19F1D025ULL,
		0x22887F32F7892F4BULL,
		0xD33CC0C02961C1E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF9292C5AE813EBEDULL,
		0x25148D6CD9A693EDULL,
		0x9BB904028D13DB8CULL,
		0x90C9C969B30AFD55ULL,
		0x753F4C8D97FE22C0ULL,
		0xF896E58DED11C68EULL,
		0x0A12BD2310353767ULL,
		0x4AF0989489AC07AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DBBBD53CC75EFDEULL,
		0xCBEE552A47A7B2A0ULL,
		0x42ECE7A4091C4565ULL,
		0x2E4174E84DBD834AULL,
		0x81FE393A23077789ULL,
		0x18684DBA4B727096ULL,
		0x1561110E1243A2D4ULL,
		0xFB2A8FDD350D4918ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB6D6F071B9DFC0FULL,
		0x5926384291FEE14DULL,
		0x58CC1C5E83F79626ULL,
		0x62885481654D7A0BULL,
		0xF341135374F6AB37ULL,
		0xE02E97D3A19F55F7ULL,
		0xF4B1AC14FDF19493ULL,
		0x4FC608B7549EBE95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB7F67A69CC170EA0ULL,
		0xD30E859E8CBF51E0ULL,
		0x08ACDF6A08317DACULL,
		0x0C83087AD1EEC726ULL,
		0x789F8C612A964310ULL,
		0xFF7C479D63107705ULL,
		0x2A318F764EC9BB9BULL,
		0xD50EC8E0571B8A45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CC09C8AEE1EC63ULL,
		0xFEB1D0EF6BE73A3CULL,
		0xD89276F112669C06ULL,
		0xD70CCC4EA5C58B33ULL,
		0x24A783FD7C0AF5F6ULL,
		0x82481C12F4D5DF05ULL,
		0x3FCC82AA37472207ULL,
		0x84DFC82DA51858D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD32A70A11D35223DULL,
		0xD45CB4AF20D817A3ULL,
		0x301A6878F5CAE1A5ULL,
		0x35763C2C2C293BF2ULL,
		0x53F80863AE8B4D19ULL,
		0x7D342B8A6E3A9800ULL,
		0xEA650CCC17829994ULL,
		0x502F00B2B2033173ULL
	}};
	sign = 0;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0B44BDD7AF51656ULL,
		0x6270027B0666DF86ULL,
		0xA86291D2BDB67096ULL,
		0x964516CA2BF6E153ULL,
		0x13724DBA7B7D2EA0ULL,
		0xE4E3A5F317A88301ULL,
		0x9D23C4D5A1174FE9ULL,
		0x34F52C8C7CA87F20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3ACBA4BEE844A0AULL,
		0xBA6250032B89A397ULL,
		0x3C68F19E18DC6B19ULL,
		0x49031765412368AEULL,
		0xD396E0069D4319C8ULL,
		0x29BBB43F82A08631ULL,
		0x29FB537778EE01FDULL,
		0x8FFD7E634BA77D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0791918C70CC4CULL,
		0xA80DB277DADD3BEEULL,
		0x6BF9A034A4DA057CULL,
		0x4D41FF64EAD378A5ULL,
		0x3FDB6DB3DE3A14D8ULL,
		0xBB27F1B39507FCCFULL,
		0x7328715E28294DECULL,
		0xA4F7AE29310101E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA24029A909F0CDEEULL,
		0xD07F1E5F74E561A6ULL,
		0xC068C04F6C45DE22ULL,
		0x3D83495741D5BAB6ULL,
		0x81314E82659A7BFAULL,
		0xB26F270392FEAE07ULL,
		0xE236DA5B8F5AEEC2ULL,
		0x6744936219D88977ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5018EB8124AC57DEULL,
		0x45CAA0623308CD44ULL,
		0xAC968B305348697DULL,
		0x9D881FB44C391789ULL,
		0x174166FFA15652EDULL,
		0x0215C366B87C5ABAULL,
		0xD4C75DD01F533306ULL,
		0x20FA470E7E0596FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52273E27E5447610ULL,
		0x8AB47DFD41DC9462ULL,
		0x13D2351F18FD74A5ULL,
		0x9FFB29A2F59CA32DULL,
		0x69EFE782C444290CULL,
		0xB059639CDA82534DULL,
		0x0D6F7C8B7007BBBCULL,
		0x464A4C539BD2F279ULL
	}};
	sign = 0;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x08AAEEF80CAC4EF4ULL,
		0x4C4F059DCDEE4770ULL,
		0xE073AE4DC62C6F52ULL,
		0x840BA2A3C85B43D6ULL,
		0x17C5D3365F499A2EULL,
		0xA5D88B2EAD2260A2ULL,
		0x4A4ED59AEE81142DULL,
		0x6D075418492AA503ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x106571998774831EULL,
		0x472E1013272259D7ULL,
		0x40D6837019AD4CC2ULL,
		0x1ECDAB0001A18B75ULL,
		0xF71F9FF86542D9F5ULL,
		0xCE5BF8B41A527A76ULL,
		0xD9AC79BB50A5657CULL,
		0x10A29D134C033FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8457D5E8537CBD6ULL,
		0x0520F58AA6CBED98ULL,
		0x9F9D2ADDAC7F2290ULL,
		0x653DF7A3C6B9B861ULL,
		0x20A6333DFA06C039ULL,
		0xD77C927A92CFE62BULL,
		0x70A25BDF9DDBAEB0ULL,
		0x5C64B704FD276557ULL
	}};
	sign = 0;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCD3B79BB98B54B4FULL,
		0x56157FDDEB484881ULL,
		0xE7622784BA0AEDC5ULL,
		0x1D95EF34631C3EC1ULL,
		0xBFB22D633BD6640CULL,
		0x70B6ED4C01EA0B17ULL,
		0xC63F9F7095AC08EFULL,
		0xC7E74CAFD35866FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA13F8F4350C1F8BBULL,
		0x6B0E9DEF8551F673ULL,
		0x69A8371FD66A2CA2ULL,
		0x799E715B9E725841ULL,
		0xACB9DA3DA2B60A85ULL,
		0x379A8F2A2569E60DULL,
		0xC0498ED765BB8892ULL,
		0x65F94DFAF27CABA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BFBEA7847F35294ULL,
		0xEB06E1EE65F6520EULL,
		0x7DB9F064E3A0C122ULL,
		0xA3F77DD8C4A9E680ULL,
		0x12F8532599205986ULL,
		0x391C5E21DC80250AULL,
		0x05F610992FF0805DULL,
		0x61EDFEB4E0DBBB57ULL
	}};
	sign = 0;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F33BB1AEFCA78E8ULL,
		0x1467D265C6DCB9FAULL,
		0xFDBD0E671168C798ULL,
		0x5950A9FDA01FCE94ULL,
		0x6B4C9F4FCD78AE82ULL,
		0x79AF4D5B070AFD62ULL,
		0xE0710F9EE2CC3F0AULL,
		0x452D8CB8AB9E1587ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADCE983BD3BFC80ULL,
		0xDF286041A40E5087ULL,
		0xDB3E08CC0615D751ULL,
		0x2433CAC962A435BEULL,
		0xD732DFC48F576F60ULL,
		0xCE8F7C35B97E16AFULL,
		0x2FE1311228BD1B7CULL,
		0xE802295494F8C534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0456D197328E7C68ULL,
		0x353F722422CE6973ULL,
		0x227F059B0B52F046ULL,
		0x351CDF343D7B98D6ULL,
		0x9419BF8B3E213F22ULL,
		0xAB1FD1254D8CE6B2ULL,
		0xB08FDE8CBA0F238DULL,
		0x5D2B636416A55053ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF4BCFF182C858CBBULL,
		0x6BE43EA8FE2FF61BULL,
		0xCE82FD324CF9B92DULL,
		0xFB35C8A31596559AULL,
		0x268E5AF62854249DULL,
		0xD97C77E4D89612F1ULL,
		0x7E3518D333A443C6ULL,
		0xBEACDCBD713372BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB35C438611AA120ULL,
		0xD8A909ADE780FABAULL,
		0x66297C0FE22641CDULL,
		0xF3D2D54556F3C5DEULL,
		0x62AA6048EE55ABD3ULL,
		0x6BB1F66FD407CA56ULL,
		0x108DCA414A88CC73ULL,
		0x83B156A6777C8838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39873ADFCB6AEB9BULL,
		0x933B34FB16AEFB61ULL,
		0x685981226AD3775FULL,
		0x0762F35DBEA28FBCULL,
		0xC3E3FAAD39FE78CAULL,
		0x6DCA8175048E489AULL,
		0x6DA74E91E91B7753ULL,
		0x3AFB8616F9B6EA85ULL
	}};
	sign = 0;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x40981884D3D1DAF7ULL,
		0x41ED09CDEB5A3DF1ULL,
		0xFE7CEAC0DD914970ULL,
		0x4EDAFB4F87AB8990ULL,
		0xE84363D40C1D6550ULL,
		0x8FAC7327BBC89584ULL,
		0xF99C8ADCE139539EULL,
		0x41A33CFEDD191379ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2C2C75EDFDC34EULL,
		0x6E2D8F78FDEE6F3BULL,
		0xE59BBC586F4B8BD0ULL,
		0xEF93C99C91EE84C5ULL,
		0xC238C2BB5E3603A1ULL,
		0xE1E8A89EAD6CF4A9ULL,
		0x241E44FE851C0B02ULL,
		0xBE4B410B9BB10806ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE46BEC0EE5D417A9ULL,
		0xD3BF7A54ED6BCEB5ULL,
		0x18E12E686E45BD9FULL,
		0x5F4731B2F5BD04CBULL,
		0x260AA118ADE761AEULL,
		0xADC3CA890E5BA0DBULL,
		0xD57E45DE5C1D489BULL,
		0x8357FBF341680B73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0643D99C4FBB1C15ULL,
		0x89B2BF918350274CULL,
		0x4D44C3C86255E9B2ULL,
		0x7C59822606108979ULL,
		0x44CCA01CB8100457ULL,
		0xA3002314653AB3CCULL,
		0x573448A294510E52ULL,
		0x59CE467D715EA93AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3B7C51F59EA55C6ULL,
		0x9F84F8CAFBBE6B4AULL,
		0xB536992A618778F5ULL,
		0x1600C218A7ADA725ULL,
		0x087369A3CE229863ULL,
		0x5F5682D923D1C540ULL,
		0xC88DD36D28C81B18ULL,
		0x0A25B1248FE431A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x428C147CF5D0C64FULL,
		0xEA2DC6C68791BC01ULL,
		0x980E2A9E00CE70BCULL,
		0x6658C00D5E62E253ULL,
		0x3C593678E9ED6BF4ULL,
		0x43A9A03B4168EE8CULL,
		0x8EA675356B88F33AULL,
		0x4FA89558E17A7795ULL
	}};
	sign = 0;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4FEC854BC54E6D84ULL,
		0xCD726AA01D0060CDULL,
		0xB39C2914A1FF1D8CULL,
		0xF9008D35CB3FB24DULL,
		0xC08CA9EAC125F62CULL,
		0x68863B6D1646918EULL,
		0x15661260DEA7EB39ULL,
		0x506CCF6785075827ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x412952D1A8B5EFA5ULL,
		0x7934AB3FC3BEFB43ULL,
		0xF2A5E3EF4CBB2FF3ULL,
		0xFA3640E6900B27C9ULL,
		0x5600CDDEBF5D4561ULL,
		0x3A9D818E40D3AFBBULL,
		0x3A407D302CF01EC8ULL,
		0xE9C0C3605E9BF1C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EC3327A1C987DDFULL,
		0x543DBF605941658AULL,
		0xC0F645255543ED99ULL,
		0xFECA4C4F3B348A83ULL,
		0x6A8BDC0C01C8B0CAULL,
		0x2DE8B9DED572E1D3ULL,
		0xDB259530B1B7CC71ULL,
		0x66AC0C07266B6666ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4755AC4248AB7851ULL,
		0xAFFADCC54273ADA1ULL,
		0x027C159CD0800418ULL,
		0x455173F360DE0C80ULL,
		0xA5ACF114CD484442ULL,
		0x71B30EC5D8C5E406ULL,
		0xAE643FBB35CE6FC6ULL,
		0x5720095A1E7A5D7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B43AFB775894D61ULL,
		0x32FA17906DA34CC5ULL,
		0x4D6A46C1126A7137ULL,
		0xFC64C8FB32DEDB13ULL,
		0xDBABBA3A62700F1BULL,
		0xC33CAF4EB81F1F8EULL,
		0x3E1AA24E9A37898EULL,
		0xED182CB222FC0DEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C11FC8AD3222AF0ULL,
		0x7D00C534D4D060DCULL,
		0xB511CEDBBE1592E1ULL,
		0x48ECAAF82DFF316CULL,
		0xCA0136DA6AD83526ULL,
		0xAE765F7720A6C477ULL,
		0x70499D6C9B96E637ULL,
		0x6A07DCA7FB7E4F92ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5F7E4F268C661E3EULL,
		0x79E3C8EFAA9E9BFFULL,
		0x3D72812298D0F195ULL,
		0x0134683108130BD0ULL,
		0x09872ABC77D749CCULL,
		0x21A72EECC2A394E7ULL,
		0xB12E295114874A07ULL,
		0x1B389025E559DF2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DCDF72882EA52DCULL,
		0xADB1A14DAB6734F8ULL,
		0xE6E7FBDF40E0BA3CULL,
		0x243D8DDCA38322B0ULL,
		0xB54D52B1A52A8DD9ULL,
		0x3F7660C140063B39ULL,
		0xAA58C9A232EBB419ULL,
		0x31C8B327DCB78672ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B057FE097BCB62ULL,
		0xCC3227A1FF376707ULL,
		0x568A854357F03758ULL,
		0xDCF6DA54648FE91FULL,
		0x5439D80AD2ACBBF2ULL,
		0xE230CE2B829D59ADULL,
		0x06D55FAEE19B95EDULL,
		0xE96FDCFE08A258BAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6935D049870E1C79ULL,
		0xA71803364F246685ULL,
		0x4D72A952A520EC05ULL,
		0xA3635623E6297D0EULL,
		0x3CCB7B65A96C6DB0ULL,
		0x38021F97A07D92AEULL,
		0xE170D3AE7648F06EULL,
		0x59FF0FB0F58383E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60FFD25D828B56A1ULL,
		0xF2138DEE28A5BDADULL,
		0x25DF97CB6FB53FE8ULL,
		0x1BF2AA491082E71BULL,
		0x5877FB345E65C26FULL,
		0xFA8CBF25755F2797ULL,
		0x427B7614F7CF65E9ULL,
		0x9E653E8234CCE0C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0835FDEC0482C5D8ULL,
		0xB5047548267EA8D8ULL,
		0x27931187356BAC1CULL,
		0x8770ABDAD5A695F3ULL,
		0xE45380314B06AB41ULL,
		0x3D7560722B1E6B16ULL,
		0x9EF55D997E798A84ULL,
		0xBB99D12EC0B6A325ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B0AE98019459B4DULL,
		0x79A572B044D5B6CEULL,
		0xDEA32C977CCD761CULL,
		0x3FA1CB4A4F0F3EF5ULL,
		0x332C9F40926AFFD7ULL,
		0x213E2C2903BAAEA2ULL,
		0x4A22AB4BAD3A1690ULL,
		0xEDBC912AA046F2D0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9126AB7FF871620ULL,
		0x5BE64A33E2CC5405ULL,
		0xEAEDC368E87D7C7CULL,
		0xA076122D820F177AULL,
		0xBCD82DF8D610C0F9ULL,
		0xDC3BAF0165F03ED7ULL,
		0xB973035BAFDF568BULL,
		0x8E5A04E2ED45C4BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21F87EC819BE852DULL,
		0x1DBF287C620962C8ULL,
		0xF3B5692E944FF9A0ULL,
		0x9F2BB91CCD00277AULL,
		0x76547147BC5A3EDDULL,
		0x45027D279DCA6FCAULL,
		0x90AFA7EFFD5AC004ULL,
		0x5F628C47B3012E14ULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE0C1BCB95A082B23ULL,
		0x687EE16A08C6AAD9ULL,
		0xAE269000D346CFF3ULL,
		0x47402B61826DB9E7ULL,
		0xFD0F3C38E1FE8698ULL,
		0x9E4F9CD98CD78F92ULL,
		0xB7ED7C3F30C8D84AULL,
		0x737AB24C4A1DA028ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D20C7B3AAB87627ULL,
		0xA09F3A55B75E756BULL,
		0xDD7E16E38EA343B7ULL,
		0x289C5FADFBB9F1BAULL,
		0x57FC44F7537FC5C5ULL,
		0xBC144704F6130370ULL,
		0xB8094330D21A10A1ULL,
		0x642AD8D7437F8102ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A0F505AF4FB4FCULL,
		0xC7DFA7145168356EULL,
		0xD0A8791D44A38C3BULL,
		0x1EA3CBB386B3C82CULL,
		0xA512F7418E7EC0D3ULL,
		0xE23B55D496C48C22ULL,
		0xFFE4390E5EAEC7A8ULL,
		0x0F4FD975069E1F25ULL
	}};
	sign = 0;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD3550457FEA753DFULL,
		0xB926FCB9E2DA09FEULL,
		0xCDCFD99E5970565FULL,
		0x1EF94A6D5EB25B62ULL,
		0xC4AE63B896E39C05ULL,
		0x45A07666467161FCULL,
		0xDB328F8C2C283A7BULL,
		0x997AC21DBE4C8409ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EA10B6795E0992ULL,
		0x1816C5FD474B70E7ULL,
		0x85B8D3C81A9E1529ULL,
		0x83314876B3BB76F6ULL,
		0x66B8C240D7D7DAA8ULL,
		0xFB3E5174029553BCULL,
		0xA0FBBB03D0F2EF5FULL,
		0x2F10BC68A30984E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB16AF3A185494A4DULL,
		0xA11036BC9B8E9917ULL,
		0x481705D63ED24136ULL,
		0x9BC801F6AAF6E46CULL,
		0x5DF5A177BF0BC15CULL,
		0x4A6224F243DC0E40ULL,
		0x3A36D4885B354B1BULL,
		0x6A6A05B51B42FF27ULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C9E16BB854F0FF4ULL,
		0xE694297726D6BB5FULL,
		0x94CF9CF43A5365ACULL,
		0x9BE15FDCC728A7F7ULL,
		0x7F81033CF748C98FULL,
		0xE074C2059CA5FD3AULL,
		0xA82344DC276C3C22ULL,
		0x08981F446ED69D5BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x804A4F46D5DD381AULL,
		0xAB972CF707441D72ULL,
		0xE031526670B69372ULL,
		0xA35C1AE1B4045F0CULL,
		0xC3B59B45EB33CFE4ULL,
		0x430EF0BADE445068ULL,
		0xCBDA9898A5D5A0B3ULL,
		0xD16C21B11D7E8952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC53C774AF71D7DAULL,
		0x3AFCFC801F929DECULL,
		0xB49E4A8DC99CD23AULL,
		0xF88544FB132448EAULL,
		0xBBCB67F70C14F9AAULL,
		0x9D65D14ABE61ACD1ULL,
		0xDC48AC4381969B6FULL,
		0x372BFD9351581408ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x51C42C7375F041E8ULL,
		0x638814FFB487D3E9ULL,
		0x64417BC2F98888E2ULL,
		0xF79C2C86FBD56726ULL,
		0x32C87B8DAD08E11FULL,
		0x571021B556A44584ULL,
		0xFA74B9DFCF7236AAULL,
		0xA23B74A64AFED01BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D39EAE2161E694FULL,
		0x56D1C9379C2580D2ULL,
		0x700DF6995E3B2850ULL,
		0x188D4DB26DB38A0AULL,
		0x89A10260584AECC9ULL,
		0xE899E0B055F152BDULL,
		0xC40E1D67FC15EDF9ULL,
		0x06AFBA39F052B182ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF48A41915FD1D899ULL,
		0x0CB64BC818625316ULL,
		0xF43385299B4D6092ULL,
		0xDF0EDED48E21DD1BULL,
		0xA927792D54BDF456ULL,
		0x6E76410500B2F2C6ULL,
		0x36669C77D35C48B0ULL,
		0x9B8BBA6C5AAC1E99ULL
	}};
	sign = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA56B5A16A9F3F3CULL,
		0xF610753C0F04327EULL,
		0xA2863B1D6737FE21ULL,
		0xA00D10A66B415F4FULL,
		0xD1316BEE6B0605C0ULL,
		0xFA32065189AD0A6BULL,
		0x66640FD3B8D77D14ULL,
		0xC916CDD73FC41811ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8423508BB6AAFFULL,
		0x02E1BEBA751D34B1ULL,
		0x543F26258FB7A289ULL,
		0x79C2DA2BBB2CF3CEULL,
		0x374189E58B0FED8DULL,
		0x8D7046FAFDF4BE7AULL,
		0x37F965647710A17CULL,
		0x8A8B64A0CC2C1103ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BD29250DEE8943DULL,
		0xF32EB68199E6FDCDULL,
		0x4E4714F7D7805B98ULL,
		0x264A367AB0146B81ULL,
		0x99EFE208DFF61833ULL,
		0x6CC1BF568BB84BF1ULL,
		0x2E6AAA6F41C6DB98ULL,
		0x3E8B69367398070EULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2543CCA203A7C2CAULL,
		0x36D05B1F5B141B71ULL,
		0x54545442E22EECC0ULL,
		0xB9AED1CB922EEDC7ULL,
		0x38D7BE5D8B893047ULL,
		0x4A7B421E24E2EF5AULL,
		0xD820CF1D94A11B9DULL,
		0x527FFBB851FDEDEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3252AEBCF2696F1ULL,
		0x6BB9BB3D685AFB7EULL,
		0x26F7B2D7DC8BE3A0ULL,
		0x64D681E3A0039D0EULL,
		0xFEA76E7B50715203ULL,
		0x5FA4EB02A416A911ULL,
		0x158F65EB8EACA5B6ULL,
		0x257C3321044E63CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x321EA1B634812BD9ULL,
		0xCB169FE1F2B91FF2ULL,
		0x2D5CA16B05A3091FULL,
		0x54D84FE7F22B50B9ULL,
		0x3A304FE23B17DE44ULL,
		0xEAD6571B80CC4648ULL,
		0xC291693205F475E6ULL,
		0x2D03C8974DAF8A1DULL
	}};
	sign = 0;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A09A71ACAE685C7ULL,
		0xD5B9E1FDD45FAB6DULL,
		0xBDC09C6339FED417ULL,
		0x0547200481A7A47FULL,
		0xC2C635D6D26FDFCEULL,
		0x55A1F90789280DE1ULL,
		0xFB4BED95AB6B5EF4ULL,
		0x1F22A6A38AAFB6C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x580D53444DCB3000ULL,
		0x303D83BA95EF9B8DULL,
		0xF2639930B5668186ULL,
		0xC19ED3FBA4909883ULL,
		0xD09358680C8787C1ULL,
		0x92ADDE49DCCDD3A6ULL,
		0x40FC0711D9D48035ULL,
		0x74E5105051F285A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21FC53D67D1B55C7ULL,
		0xA57C5E433E700FE0ULL,
		0xCB5D033284985291ULL,
		0x43A84C08DD170BFBULL,
		0xF232DD6EC5E8580CULL,
		0xC2F41ABDAC5A3A3AULL,
		0xBA4FE683D196DEBEULL,
		0xAA3D965338BD311EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFBE61FFC4B7737AULL,
		0x3B3D4C794B950E1CULL,
		0x6DBC36745D6118DAULL,
		0x6FC68ED654F9D0D0ULL,
		0xDC39F97E4A3DDBB7ULL,
		0x8FE536341023D5D1ULL,
		0x0FE26C36B7E7370FULL,
		0x79E11C00940180CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D18126617D138ECULL,
		0x7DF6CDAD89CF09C1ULL,
		0xD3F6A9E08B31B35DULL,
		0x0F5CA2CFD40C7CE3ULL,
		0x4BC761B09985813AULL,
		0x7565EFC9EA825BAFULL,
		0xB75AE1AB1BBDC645ULL,
		0x32ECCFEF0BF02364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72A64F99ACE63A8EULL,
		0xBD467ECBC1C6045BULL,
		0x99C58C93D22F657CULL,
		0x6069EC0680ED53ECULL,
		0x907297CDB0B85A7DULL,
		0x1A7F466A25A17A22ULL,
		0x58878A8B9C2970CAULL,
		0x46F44C1188115D68ULL
	}};
	sign = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x862D645C47C9978AULL,
		0x6978013F02F408A1ULL,
		0xD2AF8660343C9D8EULL,
		0x6CEA9F2C2095F33EULL,
		0xA322825DA92618F3ULL,
		0x5DBE003BF0A3C8CAULL,
		0x500CDD1C7877E0BEULL,
		0xF996A972724B1004ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07385439EA9DC03ULL,
		0xAFE9D25A3BA4406DULL,
		0x97C68C244967F5FDULL,
		0x21B27555AA9B60CEULL,
		0x0BC8059FEF94E6A9ULL,
		0xA223C41A7A6EE644ULL,
		0xFD2792FDE13FE065ULL,
		0xA89F65ACF23380DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5B9DF18A91FBB87ULL,
		0xB98E2EE4C74FC833ULL,
		0x3AE8FA3BEAD4A790ULL,
		0x4B3829D675FA9270ULL,
		0x975A7CBDB991324AULL,
		0xBB9A3C217634E286ULL,
		0x52E54A1E97380058ULL,
		0x50F743C580178F28ULL
	}};
	sign = 0;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9FCA535413E14D05ULL,
		0x36345B778EAC35A2ULL,
		0x8039322A774438AFULL,
		0xA0F4FF5EA3B4E2A6ULL,
		0xA5746CD8DB22A699ULL,
		0xD080D8DE9D36F378ULL,
		0x5ED1867BFF7970EAULL,
		0x67F3177D4ADBC8F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD36BC4A3F9E0C40ULL,
		0x8CAEEB6C4A137B83ULL,
		0xFD833140AF745EA7ULL,
		0x7CEBB959B37BEAA4ULL,
		0x32FDD70D2E09616FULL,
		0x9BDEA41DD430D283ULL,
		0xCE2FA0AE09F2B622ULL,
		0x15EF7A3840221B5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2939709D44340C5ULL,
		0xA985700B4498BA1EULL,
		0x82B600E9C7CFDA07ULL,
		0x24094604F038F801ULL,
		0x727695CBAD19452AULL,
		0x34A234C0C90620F5ULL,
		0x90A1E5CDF586BAC8ULL,
		0x52039D450AB9AD98ULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7FBF13B175E42591ULL,
		0x6A43069884423E6CULL,
		0x8B01B6A6420F437BULL,
		0xE25397001E4FA459ULL,
		0x76991357B2EE0769ULL,
		0x1CD7ADDF8957961BULL,
		0xA569AB2353E7ADE4ULL,
		0x63DCADC531C5B342ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C344186A43245A5ULL,
		0x24EA7493B82A11D5ULL,
		0x81FE702D0FE726D1ULL,
		0xA80FFB7AD673FE8BULL,
		0xE1BCFF59A1B6E539ULL,
		0xB19F4C69D1CE9A7AULL,
		0x5C2BC23257E9CEB3ULL,
		0x75DE82A5C8DEAFD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF38AD22AD1B1DFECULL,
		0x45589204CC182C96ULL,
		0x0903467932281CAAULL,
		0x3A439B8547DBA5CEULL,
		0x94DC13FE11372230ULL,
		0x6B386175B788FBA0ULL,
		0x493DE8F0FBFDDF30ULL,
		0xEDFE2B1F68E70371ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCEF6E3E9675F0F29ULL,
		0x1E072939484BC285ULL,
		0x900166F45B1BB233ULL,
		0x302340FEC890CA3EULL,
		0x09DFB2D92B3AB93FULL,
		0xAA9B1C87A7ADD305ULL,
		0x363E8043BC2C0015ULL,
		0xA25609B0A2BE4CD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20559F3D31C083A8ULL,
		0x4E2BBF18AFF8F204ULL,
		0x312310012E0B48BAULL,
		0xAC304865AB027675ULL,
		0xBA4D01B5426AAA13ULL,
		0x2196897CD9974B6AULL,
		0x3A4CF1E5A21E7A9DULL,
		0xDEE15B7AAD5372F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEA144AC359E8B81ULL,
		0xCFDB6A209852D081ULL,
		0x5EDE56F32D106978ULL,
		0x83F2F8991D8E53C9ULL,
		0x4F92B123E8D00F2BULL,
		0x8904930ACE16879AULL,
		0xFBF18E5E1A0D8578ULL,
		0xC374AE35F56AD9DEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x04981603D0EB61D3ULL,
		0x7AB06464652B5402ULL,
		0xC20A18CEB8661869ULL,
		0x30F2D49D36AF6398ULL,
		0x08C2411722EB4D1CULL,
		0x5F44AB157FB3C384ULL,
		0x4E8A33BA567C8F0FULL,
		0x0AB43E9018FBFD1BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x548986E4ED1EEE83ULL,
		0x0666CBE22869D12FULL,
		0xD3F6C861227601D0ULL,
		0x355F8A775E42DE7FULL,
		0x88889717D3EA873BULL,
		0x45CB968591BE7096ULL,
		0x3B50E4565E2510C6ULL,
		0x0EE380B4A48A6602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB00E8F1EE3CC7350ULL,
		0x744998823CC182D2ULL,
		0xEE13506D95F01699ULL,
		0xFB934A25D86C8518ULL,
		0x8039A9FF4F00C5E0ULL,
		0x1979148FEDF552EDULL,
		0x13394F63F8577E49ULL,
		0xFBD0BDDB74719719ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x49B69DDA2449FCECULL,
		0x1334AE7B0F2EEF0CULL,
		0x967DC63AEF210D4FULL,
		0x566CCCE5B1C41DDEULL,
		0x95C067567A6E2C9BULL,
		0x16F2CA8BFBA26ECFULL,
		0x9682A5FE05E0ABEAULL,
		0x8CC7596B923A7BEDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE833C9AB3ED131F5ULL,
		0x1188B6431FE36064ULL,
		0x34773F9C9424D90BULL,
		0xEE38B6B8BB3723E0ULL,
		0x4DD7D7136A748E62ULL,
		0xF7E47D3AAF21B8BEULL,
		0x56D3D2D7464A2AA9ULL,
		0x868CDB3D000C062FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6182D42EE578CAF7ULL,
		0x01ABF837EF4B8EA7ULL,
		0x6206869E5AFC3444ULL,
		0x6834162CF68CF9FEULL,
		0x47E890430FF99E38ULL,
		0x1F0E4D514C80B611ULL,
		0x3FAED326BF968140ULL,
		0x063A7E2E922E75BEULL
	}};
	sign = 0;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4B9CE0AB787C5A01ULL,
		0x054603054A4D18AFULL,
		0x8718CBD8BE4BCF38ULL,
		0xF22DEB75ADAEBB58ULL,
		0x4A8989DF5172C158ULL,
		0xD3866885CC5B78FEULL,
		0x4BCCFF440E0E6CD4ULL,
		0x4BBF33B2F2F6B9E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7B0FAA72D0003D6ULL,
		0x9C55097DDB60B017ULL,
		0x01171E7F4BB245F5ULL,
		0x0E1D9D2D19DC2514ULL,
		0x8BD204DB742549F9ULL,
		0x725871851B96E65BULL,
		0x224D59E637E01965ULL,
		0x1170937BB46CEF35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93EBE6044B7C562BULL,
		0x68F0F9876EEC6897ULL,
		0x8601AD5972998942ULL,
		0xE4104E4893D29644ULL,
		0xBEB78503DD4D775FULL,
		0x612DF700B0C492A2ULL,
		0x297FA55DD62E536FULL,
		0x3A4EA0373E89CAB1ULL
	}};
	sign = 0;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCFAC1EA5D2B25D5CULL,
		0x0DACDB74E91AFF2BULL,
		0xF111E57DFF931159ULL,
		0xCB6AEFC9C5A12DFCULL,
		0xAE3F4E935F4F09FEULL,
		0x9563601814962EE7ULL,
		0xCF1F2D96422AEBCFULL,
		0x8EE454E740603FC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x935A4ED7DBE964EEULL,
		0xBDEDC0CE078F81A9ULL,
		0x70B98078A415F21BULL,
		0x3F4042B5ADAFBF11ULL,
		0x05948FD65877EE37ULL,
		0x14593109CCCBCF1FULL,
		0x2EA9C6C4F325EC7CULL,
		0x312489EB9CCDE168ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C51CFCDF6C8F86EULL,
		0x4FBF1AA6E18B7D82ULL,
		0x805865055B7D1F3DULL,
		0x8C2AAD1417F16EEBULL,
		0xA8AABEBD06D71BC7ULL,
		0x810A2F0E47CA5FC8ULL,
		0xA07566D14F04FF53ULL,
		0x5DBFCAFBA3925E5CULL
	}};
	sign = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x255B5797F9EAEBF4ULL,
		0x9FF2C8DE47211A54ULL,
		0xA44A3DC9741CD2E5ULL,
		0x1A8ABC96F9466BDAULL,
		0x431B0209747AFD52ULL,
		0x7ACB39A20FFF0E55ULL,
		0x8BDA74200CEB605BULL,
		0xBF0EC2ED60A65764ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D38C9A728D0ABC7ULL,
		0x3D79FA2071482911ULL,
		0x31A594845F68C662ULL,
		0x5613E6A2A3B41CDDULL,
		0x2D44FB8510705E5BULL,
		0x68064BB6B1991807ULL,
		0x9B7FFBA40EA69E16ULL,
		0x70C95D968902F31FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8228DF0D11A402DULL,
		0x6278CEBDD5D8F142ULL,
		0x72A4A94514B40C83ULL,
		0xC476D5F455924EFDULL,
		0x15D60684640A9EF6ULL,
		0x12C4EDEB5E65F64EULL,
		0xF05A787BFE44C245ULL,
		0x4E456556D7A36444ULL
	}};
	sign = 0;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B9C67ACE530B5CDULL,
		0xCCBF5FC5000D9210ULL,
		0x6092433979A23FCCULL,
		0x08560764E119F2E7ULL,
		0x6D55344ADD52B10AULL,
		0xE451C657D677E887ULL,
		0x7D6ED333B717CAE7ULL,
		0xAD9EE027CD93662DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44EFD86FB5F8DE5ULL,
		0x3114A643E366A493ULL,
		0xB3804534F46E0317ULL,
		0x19B68D39A3A5F6FDULL,
		0xCA43289F1D56D8ECULL,
		0xD6022663C0E3AC4AULL,
		0x8A1B87C45ADD0DB1ULL,
		0x70F389FDF4838009ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD74D6A25E9D127E8ULL,
		0x9BAAB9811CA6ED7CULL,
		0xAD11FE0485343CB5ULL,
		0xEE9F7A2B3D73FBE9ULL,
		0xA3120BABBFFBD81DULL,
		0x0E4F9FF415943C3CULL,
		0xF3534B6F5C3ABD36ULL,
		0x3CAB5629D90FE623ULL
	}};
	sign = 0;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1902F42DA4AE01A2ULL,
		0x270B7937693F05A8ULL,
		0x4779095DA719CE85ULL,
		0xCF6400571A79733CULL,
		0xCC12B3372D070228ULL,
		0x530B0FBEC0A388D4ULL,
		0x4F9DC330F7021EABULL,
		0xC5A195F8AA6821BFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE07098236D67211ULL,
		0x1C7A80D8A32D7E8BULL,
		0x5C2FC0A3EDDB4C01ULL,
		0x710A96D5E92C8941ULL,
		0x56E3DA6298F53371ULL,
		0xA200F9663D6E6781ULL,
		0x132604E65609E3CCULL,
		0x13E0470BD17BD125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFBEAAB6DD78F91ULL,
		0x0A90F85EC611871CULL,
		0xEB4948B9B93E8284ULL,
		0x5E596981314CE9FAULL,
		0x752ED8D49411CEB7ULL,
		0xB10A165883352153ULL,
		0x3C77BE4AA0F83ADEULL,
		0xB1C14EECD8EC509AULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8C5B90E0C39CAC1ULL,
		0x2D9DC57F966782F7ULL,
		0x9080AED487B89EE2ULL,
		0x9EDCC370F00D57D3ULL,
		0x11A0E407531F0C6CULL,
		0x5493B33C5E1C22E1ULL,
		0x06C48FE5533775E0ULL,
		0xBAC537F89073032BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x619D5A7F417D270AULL,
		0xAC4FCBC6A4B3C0A2ULL,
		0x14784F95828F7BA8ULL,
		0x904A6BECEEE0E0DBULL,
		0xD2EA22C6BD32FBE4ULL,
		0xB82D3EBF4B9218E1ULL,
		0xEEF1BFD2EA5F5640ULL,
		0xF5DCC1754B3F33B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57285E8ECABCA3B7ULL,
		0x814DF9B8F1B3C255ULL,
		0x7C085F3F05292339ULL,
		0x0E925784012C76F8ULL,
		0x3EB6C14095EC1088ULL,
		0x9C66747D128A09FFULL,
		0x17D2D01268D81F9FULL,
		0xC4E876834533CF72ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x901DBF303D014236ULL,
		0x0642B4E8D368226FULL,
		0x315A877249B4E004ULL,
		0x5EF5587E1D8532DBULL,
		0x9D72B489A30476A9ULL,
		0xE12DE4D1106CC925ULL,
		0xCE0F2B43CC055E77ULL,
		0x90FBF05E0D72F9C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2840C89E70582489ULL,
		0x16213B08E147C23AULL,
		0x38597E6DDF472840ULL,
		0x35D260E8638A58EAULL,
		0xE28040F491DC3B7FULL,
		0xE2E31DF6B5B1D25DULL,
		0xA3C65F83B97B33D1ULL,
		0x69DBAEA6FDB93D4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67DCF691CCA91DADULL,
		0xF02179DFF2206035ULL,
		0xF90109046A6DB7C3ULL,
		0x2922F795B9FAD9F0ULL,
		0xBAF2739511283B2AULL,
		0xFE4AC6DA5ABAF6C7ULL,
		0x2A48CBC0128A2AA5ULL,
		0x272041B70FB9BC79ULL
	}};
	sign = 0;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x892CF9BDB40A024EULL,
		0x3F5DF6C7D894040EULL,
		0xFB99489F7D9668B3ULL,
		0x4C90A42988B0B8A5ULL,
		0xA277A02B9A07D8E8ULL,
		0x2E761EA19EDB5E1CULL,
		0x2E624B296F412473ULL,
		0x844AD0D6C7808A1BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE545DDFFEE34BDF4ULL,
		0x1CB7F6271B1ECE3AULL,
		0x8356150D99147C2DULL,
		0xF73325BBFCBEE4D5ULL,
		0x07E8EB50A6E08CECULL,
		0xB920E94D7311FB62ULL,
		0x622C82C21C6CA35EULL,
		0x9E8A198063C9F699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3E71BBDC5D5445AULL,
		0x22A600A0BD7535D3ULL,
		0x78433391E481EC86ULL,
		0x555D7E6D8BF1D3D0ULL,
		0x9A8EB4DAF3274BFBULL,
		0x755535542BC962BAULL,
		0xCC35C86752D48114ULL,
		0xE5C0B75663B69381ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB7A4E95683F71322ULL,
		0x011E5BD8877F3171ULL,
		0xD7863D831779506CULL,
		0x37B291C5BBD03739ULL,
		0x2028AE6B2FD16F19ULL,
		0x5B6168DF02D64493ULL,
		0x3305940C1B312F67ULL,
		0x9762009E13A533DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA1F7D0F9BF3CBFULL,
		0x85AADD773F375BDDULL,
		0xC61B49E5B71EC22FULL,
		0x2AB681DD93AC6EE7ULL,
		0x68635A7DC490FB2DULL,
		0xF9944C3DAC439544ULL,
		0x783DAA70FF59770DULL,
		0x3B80D8316D415C12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A02F1858A37D663ULL,
		0x7B737E614847D594ULL,
		0x116AF39D605A8E3CULL,
		0x0CFC0FE82823C852ULL,
		0xB7C553ED6B4073ECULL,
		0x61CD1CA15692AF4EULL,
		0xBAC7E99B1BD7B859ULL,
		0x5BE1286CA663D7C9ULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x209349522E3E5137ULL,
		0xE00007E1091E6964ULL,
		0x1D199DE954139A08ULL,
		0xCAE794F60D15D8A6ULL,
		0x95195624ED9ABFB9ULL,
		0x7AE2FFC3A989589DULL,
		0x2A96F10D1F08CF76ULL,
		0x8540943C43428E89ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x59490C0020565E59ULL,
		0xC355CE990428E478ULL,
		0x4D02144560517F6AULL,
		0x88799C664DC3A655ULL,
		0x17F77084B85771A9ULL,
		0xAD93B0F345323E0DULL,
		0xC7437641FEA90192ULL,
		0xF30434BE644353EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC74A3D520DE7F2DEULL,
		0x1CAA394804F584EBULL,
		0xD01789A3F3C21A9EULL,
		0x426DF88FBF523250ULL,
		0x7D21E5A035434E10ULL,
		0xCD4F4ED064571A90ULL,
		0x63537ACB205FCDE3ULL,
		0x923C5F7DDEFF3A9AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x05F339584119D105ULL,
		0x094217636EDB8593ULL,
		0xEDB8A6BFFF4B978CULL,
		0xF9417C9ABFB215EBULL,
		0x2E92E046AB0F9E84ULL,
		0xB8C4DA3370874203ULL,
		0xFA69F28414586F8DULL,
		0x1FB3FC5633C45033ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10263A9A170357D1ULL,
		0xE837069359192BDAULL,
		0xEF554770212989B4ULL,
		0xA38396FE4741AC06ULL,
		0x49BB7282C1DC4CDEULL,
		0xB6BEB5456C2B181EULL,
		0x160A207A5F7C141AULL,
		0xD5EA30E0294952ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5CCFEBE2A167934ULL,
		0x210B10D015C259B8ULL,
		0xFE635F4FDE220DD7ULL,
		0x55BDE59C787069E4ULL,
		0xE4D76DC3E93351A6ULL,
		0x020624EE045C29E4ULL,
		0xE45FD209B4DC5B73ULL,
		0x49C9CB760A7AFD88ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F896736B2C10A63ULL,
		0x30B43B2CF16B2DB2ULL,
		0xD6DFB1573F9378BCULL,
		0xC86C5397E320E49FULL,
		0x4BD7225DAF593A75ULL,
		0x14F3BF525B7B96ACULL,
		0x92699889B2EAE984ULL,
		0x5E03E79D94FA3EFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x99A9FEF28C8F4B38ULL,
		0xE59B33F629214051ULL,
		0x201B99CDB89B2D6CULL,
		0xDEDC1563294C687FULL,
		0xEF450287029DAC7CULL,
		0x7C0E6C914DB1560CULL,
		0x0C564C73C7AF6652ULL,
		0x78B7F01330F620E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05DF68442631BF2BULL,
		0x4B190736C849ED61ULL,
		0xB6C4178986F84B4FULL,
		0xE9903E34B9D47C20ULL,
		0x5C921FD6ACBB8DF8ULL,
		0x98E552C10DCA409FULL,
		0x86134C15EB3B8331ULL,
		0xE54BF78A64041E16ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE1C4EAB8BAF628B8ULL,
		0xD14DBE3387663DF9ULL,
		0x7C6EA9666A643772ULL,
		0x64F48908DF40384FULL,
		0x7DE956E996C5DD2AULL,
		0x524A925011C02546ULL,
		0x5B381EC7BD005871ULL,
		0x943E05802F64867CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14086540FE879EFDULL,
		0x742018551EA94771ULL,
		0xB7865F18BE1D1FD2ULL,
		0xEE301D52AA55E913ULL,
		0x4B6D75145BC5720BULL,
		0x96A194B2830E61D2ULL,
		0x349384871B67838BULL,
		0xDDB18137674E4112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDBC8577BC6E89BBULL,
		0x5D2DA5DE68BCF688ULL,
		0xC4E84A4DAC4717A0ULL,
		0x76C46BB634EA4F3BULL,
		0x327BE1D53B006B1EULL,
		0xBBA8FD9D8EB1C374ULL,
		0x26A49A40A198D4E5ULL,
		0xB68C8448C816456AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1FB10A8B07E01C4FULL,
		0x889DE3D912A3A5C2ULL,
		0xD1447E1432CE6903ULL,
		0x1D95872807577568ULL,
		0x6B92AB5077315F08ULL,
		0xD00577F57D4B8DD9ULL,
		0xBAA0975A76EF0059ULL,
		0x4A5A75956BF12785ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0FEC54646CF6F0ULL,
		0x7B466E4E21CA7CABULL,
		0x8863413E51DF1F5CULL,
		0xABBFD5EA4E26BFCBULL,
		0xA1847FD148D8E70EULL,
		0xF535D5D4F4800E16ULL,
		0x73F4954E3BE177E3ULL,
		0xE6A244FAC14AEE1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0A11E36A373255FULL,
		0x0D57758AF0D92916ULL,
		0x48E13CD5E0EF49A7ULL,
		0x71D5B13DB930B59DULL,
		0xCA0E2B7F2E5877F9ULL,
		0xDACFA22088CB7FC2ULL,
		0x46AC020C3B0D8875ULL,
		0x63B8309AAAA63967ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64401D70BE0AF59FULL,
		0x2F30BE523FB2FAA5ULL,
		0x6FDC41A16448C34EULL,
		0x0BF09FC5110AAF8EULL,
		0x6250EBB2036C0C54ULL,
		0xC7F5FE4892474155ULL,
		0xA235BACC64732A70ULL,
		0x1E8EC1BEA75C0EA7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E514A627B664DBBULL,
		0xDB442ADE6BAB299AULL,
		0x97AEB8F323586C6AULL,
		0x46AEE2E2E5A5DB12ULL,
		0xDF1F7E2E1E4A8481ULL,
		0x7A43515EDB3C6547ULL,
		0x6148F6DFF95E9893ULL,
		0xB642C1C64B7B52DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25EED30E42A4A7E4ULL,
		0x53EC9373D407D10BULL,
		0xD82D88AE40F056E3ULL,
		0xC541BCE22B64D47BULL,
		0x83316D83E52187D2ULL,
		0x4DB2ACE9B70ADC0DULL,
		0x40ECC3EC6B1491DDULL,
		0x684BFFF85BE0BBCCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFF0B04EA684CA419ULL,
		0x088E8288C23E5B4EULL,
		0xEFA101B2347893F8ULL,
		0xFAD112792B93BA8AULL,
		0xBC9904EC80217C7AULL,
		0x405AEE1D7285F97DULL,
		0x339ECCA15E19C47CULL,
		0xDE66EF0FCFCB57DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF034E4BFF82E1CBULL,
		0x4E8311C570C1B772ULL,
		0x56C0E0C5D0480719ULL,
		0x300057C8618B83FCULL,
		0xBF717B3E18EE3029ULL,
		0xAE438D1E5D90A4A8ULL,
		0xB040F45425E3B461ULL,
		0x5965B5DF4B81A3E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5007B69E68C9C24EULL,
		0xBA0B70C3517CA3DCULL,
		0x98E020EC64308CDEULL,
		0xCAD0BAB0CA08368EULL,
		0xFD2789AE67334C51ULL,
		0x921760FF14F554D4ULL,
		0x835DD84D3836101AULL,
		0x850139308449B3F4ULL
	}};
	sign = 0;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D2CD76F765F986DULL,
		0x69D24F111347A494ULL,
		0x7F5721F4152FADDDULL,
		0x44E078D7B63453D9ULL,
		0xC0DF49D91AB2B218ULL,
		0x90DBE8448CF934F6ULL,
		0xD9AAA6AF8AB0F752ULL,
		0x2052765FD44C3A48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2584523ACF5D78ULL,
		0x1F5E9EA117FD0BCFULL,
		0xC281781663FB4B9FULL,
		0x0140629656A3701FULL,
		0x1D567687433CE61DULL,
		0x7591C59EE933E22DULL,
		0xB93FDBBC73735E43ULL,
		0xF6C0E52D4321F28DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB207531D3B903AF5ULL,
		0x4A73B06FFB4A98C4ULL,
		0xBCD5A9DDB134623EULL,
		0x43A016415F90E3B9ULL,
		0xA388D351D775CBFBULL,
		0x1B4A22A5A3C552C9ULL,
		0x206ACAF3173D990FULL,
		0x29919132912A47BBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x316E8391DDDE263BULL,
		0x258025BF0DCFF9C5ULL,
		0xC67259EA17F083BCULL,
		0xD6F4C0E7D6C5BC3FULL,
		0x6CBAFE6E0CD540F7ULL,
		0xACDCB2FDF1A18F27ULL,
		0x1695BE11D3C3FD29ULL,
		0xB90263267C41B8BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x815C5F7864AB62AFULL,
		0xA22BA8EAE0C1CEEEULL,
		0xDC8091650D3FEDB3ULL,
		0x04BD4B8225DC51F9ULL,
		0x1ABD98048DF5178BULL,
		0x926BE432B4A5291CULL,
		0xB5626FD727727D3CULL,
		0x7AEDD3D538F3A588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB01224197932C38CULL,
		0x83547CD42D0E2AD6ULL,
		0xE9F1C8850AB09608ULL,
		0xD2377565B0E96A45ULL,
		0x51FD66697EE0296CULL,
		0x1A70CECB3CFC660BULL,
		0x61334E3AAC517FEDULL,
		0x3E148F51434E1331ULL
	}};
	sign = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66CD14D93E804772ULL,
		0xE4FEBF4361A09146ULL,
		0x609934F9516ADA89ULL,
		0xC87999AFA12C4193ULL,
		0xE343D2BB0031667FULL,
		0xD68D032EBADB0448ULL,
		0x86331B2775AAAD4AULL,
		0xD583772158BCF98EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B29B3E3FCE25C79ULL,
		0x2176FAC50BC68A37ULL,
		0x6735D78A5511A007ULL,
		0x26BBC6ADA3DA1359ULL,
		0x7ECBA904523D789EULL,
		0xB1AC24300ADDFF71ULL,
		0xBB6E3CCA6BE97603ULL,
		0x754A30C2FFBBE5D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBA360F5419DEAF9ULL,
		0xC387C47E55DA070EULL,
		0xF9635D6EFC593A82ULL,
		0xA1BDD301FD522E39ULL,
		0x647829B6ADF3EDE1ULL,
		0x24E0DEFEAFFD04D7ULL,
		0xCAC4DE5D09C13747ULL,
		0x6039465E590113BCULL
	}};
	sign = 0;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x04AAFB3E509EEB52ULL,
		0xD00199CDC4D47B12ULL,
		0xBD6EDCAD8EC0BD30ULL,
		0x2B84A5FCFBA96AD8ULL,
		0xA2BDB30B2FEB937DULL,
		0x77A941657CE96AE7ULL,
		0x51CF3F53BC68FDF8ULL,
		0x3FFC8A085E4BC99FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4502EA2ECF6B9CULL,
		0xB86257913787EC0DULL,
		0x7715EC8EB564E8DDULL,
		0xCE8AFD3C1BEC4090ULL,
		0xCA45F9AABEF5EDBAULL,
		0x68053C9025F7CDD8ULL,
		0x0081775C94DC79E3ULL,
		0x9E90833DAD74AAE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE765F85421CF7FB6ULL,
		0x179F423C8D4C8F04ULL,
		0x4658F01ED95BD453ULL,
		0x5CF9A8C0DFBD2A48ULL,
		0xD877B96070F5A5C2ULL,
		0x0FA404D556F19D0EULL,
		0x514DC7F7278C8415ULL,
		0xA16C06CAB0D71EBFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7920C167EEB47C22ULL,
		0x2D2A8C7800993949ULL,
		0x2B15C2DEE263632BULL,
		0x3D6729D8D8C1101BULL,
		0x38C6F21A8B74524FULL,
		0x13739C5FB7682A97ULL,
		0x1993293117B161A2ULL,
		0x3E105A9EACCC4A94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5842E5D6C4A21AB4ULL,
		0xF99D9EDBDFEB1936ULL,
		0x1625DA1A15A97E21ULL,
		0x977C5DEB078AAE7DULL,
		0xF497F406A3E9BC52ULL,
		0xDC6ECEC13709D52EULL,
		0x4C1097950C9DEFFFULL,
		0xEA973AFDA88579DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20DDDB912A12616EULL,
		0x338CED9C20AE2013ULL,
		0x14EFE8C4CCB9E509ULL,
		0xA5EACBEDD136619EULL,
		0x442EFE13E78A95FCULL,
		0x3704CD9E805E5568ULL,
		0xCD82919C0B1371A2ULL,
		0x53791FA10446D0B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8C652DF0CB4C7B69ULL,
		0xE7E89EA1C64BF65AULL,
		0x65813A94E9EC30F9ULL,
		0x85890FAB61042764ULL,
		0x0753A80707C7C577ULL,
		0x7DEBF6EF5A813456ULL,
		0x504DA63A77E084A0ULL,
		0xAD4F1378D6A00505ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6FBFA00E92A172BULL,
		0xE922765BBE8DD6AFULL,
		0x9F67ABE59D0FA951ULL,
		0xA043F8C3E539A012ULL,
		0xB93FF7286BCA1F4DULL,
		0xBCB765CE3DD0FEFCULL,
		0x12EC01D580177707ULL,
		0x37ED724FE2A09D38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956933EFE222643EULL,
		0xFEC6284607BE1FAAULL,
		0xC6198EAF4CDC87A7ULL,
		0xE54516E77BCA8751ULL,
		0x4E13B0DE9BFDA629ULL,
		0xC13491211CB03559ULL,
		0x3D61A464F7C90D98ULL,
		0x7561A128F3FF67CDULL
	}};
	sign = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC78F1B87D0C4A988ULL,
		0xB2FC9669731482E5ULL,
		0x98E05BE1844D1A44ULL,
		0x49944529DF7E0767ULL,
		0x0FD8C4A1680E6D33ULL,
		0x4E2299ACAD2F629DULL,
		0xB17601A7A257446BULL,
		0x031440768C1F14DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36265126BB12A2E7ULL,
		0x437D626FB9DB7815ULL,
		0xBFC0BCEBEFCD16B6ULL,
		0xDB93860973346050ULL,
		0xAF4E1A40A1AAFA19ULL,
		0xBC9DA2245FD51615ULL,
		0xFE4E83F2C87C18C9ULL,
		0x9F3FDA86FCA9794DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9168CA6115B206A1ULL,
		0x6F7F33F9B9390AD0ULL,
		0xD91F9EF59480038EULL,
		0x6E00BF206C49A716ULL,
		0x608AAA60C6637319ULL,
		0x9184F7884D5A4C87ULL,
		0xB3277DB4D9DB2BA1ULL,
		0x63D465EF8F759B90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA1D0C7D98F6541DEULL,
		0x91EBBF8677133F88ULL,
		0x6C35840B03CB993CULL,
		0x281A810CF531ADCAULL,
		0x89A38E8536324A23ULL,
		0x079F795013013C1EULL,
		0x9A02879C673AE201ULL,
		0xFDDA2BC578BD9DB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4AF350A3E150A7FULL,
		0xA5BC2C8CB362F7A9ULL,
		0x60A1C44969FB3064ULL,
		0x9EE2882D569DF496ULL,
		0x206D8CD2DAE3C79EULL,
		0xE5FA73903EDD6886ULL,
		0x77837C1A75C59108ULL,
		0xEA24FB8D33CAF709ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD2192CF5150375FULL,
		0xEC2F92F9C3B047DEULL,
		0x0B93BFC199D068D7ULL,
		0x8937F8DF9E93B934ULL,
		0x693601B25B4E8284ULL,
		0x21A505BFD423D398ULL,
		0x227F0B81F17550F8ULL,
		0x13B5303844F2A6ABULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0BA75B8C18EE4C09ULL,
		0x4BF6C5CA5624FF77ULL,
		0x5131F7FF8366F98EULL,
		0x9B14AE6AB65D948AULL,
		0xE30364EAA9520406ULL,
		0xF2A095CD15223428ULL,
		0xFAF8038C5D6F0E85ULL,
		0xC11B99F1E7CF0849ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB04C6157C8202CBULL,
		0x75C3AD3AC06D4B38ULL,
		0xF8E9090C10030355ULL,
		0x89CD9D53848317AAULL,
		0xA99331D9F9A60492ULL,
		0xE0780077255894F7ULL,
		0x4449EB7C83F8EC7FULL,
		0x74D1873ECE84DAA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10A295769C6C493EULL,
		0xD633188F95B7B43EULL,
		0x5848EEF37363F638ULL,
		0x1147111731DA7CDFULL,
		0x39703310AFABFF74ULL,
		0x12289555EFC99F31ULL,
		0xB6AE180FD9762206ULL,
		0x4C4A12B3194A2DA5ULL
	}};
	sign = 0;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06693F69D1B0D3EFULL,
		0x4E059616C3C0CDFDULL,
		0x412D595D7A8B364DULL,
		0xB0EC75F5ACAB2260ULL,
		0x05764CC7EEF6D415ULL,
		0x21E9CDA2FBC5E553ULL,
		0xC206224DF1C5D8E4ULL,
		0xECE2A56A6419510AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBA3E1C2E429160ULL,
		0x768FEADF9B91B750ULL,
		0x05EFAAA94627B432ULL,
		0xA31E7FF9767E1826ULL,
		0xCC9B2396FF9E3843ULL,
		0xBEF77DDE956B2094ULL,
		0xD4FAB1F4417E1A89ULL,
		0x99AA531C49F63D5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAAF014DA36E428FULL,
		0xD775AB37282F16ACULL,
		0x3B3DAEB43463821AULL,
		0x0DCDF5FC362D0A3AULL,
		0x38DB2930EF589BD2ULL,
		0x62F24FC4665AC4BEULL,
		0xED0B7059B047BE5AULL,
		0x5338524E1A2313AAULL
	}};
	sign = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF06DF6987A074C57ULL,
		0x9B93121961688A8AULL,
		0xA28942811DCA799BULL,
		0x772CCCCF8AD809FCULL,
		0x1E5FC07D27AE067EULL,
		0xD7BD626F95AB9C19ULL,
		0x0675FDD1AE1D0253ULL,
		0xBE796E9305D0B393ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CE1AA2F91E051CULL,
		0x4F7EE8D2CA6C0FE4ULL,
		0xDF4A4E738B12754AULL,
		0x6DCD19834B8484E7ULL,
		0x90F4634A5C6EDAC2ULL,
		0xE0372D1B55AB4923ULL,
		0x0EEE136A77572FBFULL,
		0x156DF3BA1AA929D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F9FDBF580E9473BULL,
		0x4C14294696FC7AA6ULL,
		0xC33EF40D92B80451ULL,
		0x095FB34C3F538514ULL,
		0x8D6B5D32CB3F2BBCULL,
		0xF7863554400052F5ULL,
		0xF787EA6736C5D293ULL,
		0xA90B7AD8EB2789B9ULL
	}};
	sign = 0;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5F318B66C6AB7B1ULL,
		0x05B3A69E2E3B1712ULL,
		0xD3001CD2983797CEULL,
		0xF9A1B73899641090ULL,
		0xF19755544A3C5208ULL,
		0x9273376CEF41CADAULL,
		0x7C7102EDC0E2B177ULL,
		0x4C386E262D6B5101ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2982CA10821C604DULL,
		0xBB7AC31BA7F7C1A1ULL,
		0xA820596287DC1BC9ULL,
		0x2FE70ECD22FECE57ULL,
		0xBBAF7FAE3C9E6E8DULL,
		0xAE8CB6578F10107AULL,
		0x6B59E1A94C89D26EULL,
		0x13698823198169D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC704EA5EA4E5764ULL,
		0x4A38E38286435571ULL,
		0x2ADFC370105B7C04ULL,
		0xC9BAA86B76654239ULL,
		0x35E7D5A60D9DE37BULL,
		0xE3E681156031BA60ULL,
		0x111721447458DF08ULL,
		0x38CEE60313E9E731ULL
	}};
	sign = 0;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6282E5579553A8D0ULL,
		0x75495B1C36E556AFULL,
		0x66112F03FCAAB532ULL,
		0xDB8679272082638AULL,
		0xE68ACCAD1B39BC48ULL,
		0xA01D5C2CE95F39B2ULL,
		0x7EEE1B25C5AFAA0EULL,
		0x655981522C379DB0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE5664538D94124ULL,
		0xDD1749EB92FA8E6CULL,
		0x2ECA92C6D0A3E248ULL,
		0x760FC43EDCA899DEULL,
		0x308831C1E3B355E1ULL,
		0x27414535F8DEE299ULL,
		0x7E58403B81FEECCCULL,
		0xA43A916335A99176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339D7F125C7A67ACULL,
		0x98321130A3EAC843ULL,
		0x37469C3D2C06D2E9ULL,
		0x6576B4E843D9C9ACULL,
		0xB6029AEB37866667ULL,
		0x78DC16F6F0805719ULL,
		0x0095DAEA43B0BD42ULL,
		0xC11EEFEEF68E0C3AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x12C08F19250E9584ULL,
		0x3B26A806D174A5CFULL,
		0xA94C07A1FB00A32FULL,
		0xD156189566E66053ULL,
		0x9C7D70473597B640ULL,
		0xE1CB091794052F0FULL,
		0x79761A3D605AED80ULL,
		0x4224395F7EFFAC64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12560057EE048369ULL,
		0x5050599831612AB2ULL,
		0x29D160D401639316ULL,
		0x412C03A462B5FBF8ULL,
		0xE53A370BCB4BACB8ULL,
		0xF3F8DF00F21E23A2ULL,
		0xE2C2F2F8120DD69FULL,
		0x6DEE69AC99823A3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x006A8EC1370A121BULL,
		0xEAD64E6EA0137B1DULL,
		0x7F7AA6CDF99D1018ULL,
		0x902A14F10430645BULL,
		0xB743393B6A4C0988ULL,
		0xEDD22A16A1E70B6CULL,
		0x96B327454E4D16E0ULL,
		0xD435CFB2E57D7225ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAE12962D102476A8ULL,
		0x9A3B2CBF36D34B32ULL,
		0x4F734FB20E495B2DULL,
		0xBC1F80DD725A88ACULL,
		0xA3A17CE4F3D6FFCCULL,
		0xC832F0482C97F4DAULL,
		0x1F9B8F048B8D35BBULL,
		0x82A1898708961CDFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB85881677CF8E0ULL,
		0x9448CF44B407973BULL,
		0x5B95967F0658F7C7ULL,
		0x62A827E87FAB4BCFULL,
		0x9B53CE1549F27E49ULL,
		0x1EFC0CCF84784A3CULL,
		0x994A1C42C8B89967ULL,
		0xEA4C2627ADC16999ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE5A3DABA8A77DC8ULL,
		0x05F25D7A82CBB3F6ULL,
		0xF3DDB93307F06366ULL,
		0x597758F4F2AF3CDCULL,
		0x084DAECFA9E48183ULL,
		0xA936E378A81FAA9EULL,
		0x865172C1C2D49C54ULL,
		0x9855635F5AD4B345ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x355C77E07951B7E2ULL,
		0xAB6BB1CD495F721BULL,
		0x34040AA0E26AF9DAULL,
		0x6DF1D5CF25A5FA34ULL,
		0x6E95580852D43E2DULL,
		0x6A39D340F0683CB5ULL,
		0xB030EAC80BFB20E7ULL,
		0x51852FFDA99BACD5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FE3B952A959BFAULL,
		0x6EDA4868F19748E2ULL,
		0x09A23B4455868BCBULL,
		0x8637DE55D484E031ULL,
		0xCEB98D76B76BFAE5ULL,
		0xA3B590872A38C64FULL,
		0xD0E1A60B461D2E7EULL,
		0x1A1E4FA8F48614CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x045E3C4B4EBC1BE8ULL,
		0x3C91696457C82939ULL,
		0x2A61CF5C8CE46E0FULL,
		0xE7B9F77951211A03ULL,
		0x9FDBCA919B684347ULL,
		0xC68442B9C62F7665ULL,
		0xDF4F44BCC5DDF268ULL,
		0x3766E054B5159805ULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0CAC5E835C15CDCAULL,
		0x3334936DDB430E7DULL,
		0xA7AB54A45F1E0C08ULL,
		0x470DB7D110FF720EULL,
		0x6637814668756465ULL,
		0xE23E944716D8C075ULL,
		0xD0D0D3B65262005AULL,
		0x5552B2DA30DAF34AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA8D3932685E41EULL,
		0xC889F60AFC76E979ULL,
		0x3810FDE71184F9B8ULL,
		0x8F01C3504AEBC1E9ULL,
		0x3384159474245648ULL,
		0xD48C11BF98AE78A6ULL,
		0x6C12297F629D286EULL,
		0xC21A156531120D66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE038AF0358FE9ACULL,
		0x6AAA9D62DECC2503ULL,
		0x6F9A56BD4D99124FULL,
		0xB80BF480C613B025ULL,
		0x32B36BB1F4510E1CULL,
		0x0DB282877E2A47CFULL,
		0x64BEAA36EFC4D7ECULL,
		0x93389D74FFC8E5E4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF030E84BAF35C245ULL,
		0x1DA56DA3C66BAC2AULL,
		0x78061F39601AFFDFULL,
		0x6A0D87BFB2EF8684ULL,
		0x5ED568E4EFF0C34EULL,
		0x688F18B2B83FDA4EULL,
		0x7DBDD83A87EBEE09ULL,
		0x23BF6975EFADD30BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5736788754C22605ULL,
		0x410D5336EE2B9081ULL,
		0xB47A3487B97F2C65ULL,
		0x4DCF437A862F2D13ULL,
		0x330E59273C8C93D8ULL,
		0xA141F076BE2887E0ULL,
		0xCF9EF55FB041474EULL,
		0xD9A3A07A41429641ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98FA6FC45A739C40ULL,
		0xDC981A6CD8401BA9ULL,
		0xC38BEAB1A69BD379ULL,
		0x1C3E44452CC05970ULL,
		0x2BC70FBDB3642F76ULL,
		0xC74D283BFA17526EULL,
		0xAE1EE2DAD7AAA6BAULL,
		0x4A1BC8FBAE6B3CC9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4BF0F837A9ABE5C0ULL,
		0xA6E39A4D5103182FULL,
		0xF21A38AE871DD3C8ULL,
		0xA7E6BD73E8DB4169ULL,
		0xEE4591D56FAA1A05ULL,
		0xF1021EA506FC8BC1ULL,
		0x4C7563559B2839FDULL,
		0x2DAED5A18EA553F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9059CEA493E939D6ULL,
		0x2DECE80B9CBF1292ULL,
		0x77D7341E208B94B6ULL,
		0xE205654F42317A6FULL,
		0x432E8484C01EA608ULL,
		0x0041218EF9B7B1D5ULL,
		0xA53C81263D992F80ULL,
		0xA3A2AE71AFEF2A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB97299315C2ABEAULL,
		0x78F6B241B444059CULL,
		0x7A43049066923F12ULL,
		0xC5E15824A6A9C6FAULL,
		0xAB170D50AF8B73FCULL,
		0xF0C0FD160D44D9ECULL,
		0xA738E22F5D8F0A7DULL,
		0x8A0C272FDEB62964ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x508BFEB395202C32ULL,
		0x842FD5CA042EE0C9ULL,
		0x34F7FE64EBC7C0FCULL,
		0x518E54BB076B1A70ULL,
		0x03C496F421C1AC06ULL,
		0xCFE1E6FBC57E8C5EULL,
		0x27B7928C31918449ULL,
		0x1054210D65F6DD15ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42D4AD408DCB6F2ULL,
		0x2E99B57FF939F5B8ULL,
		0xE3606D6933430335ULL,
		0x79F86A0D091C11DEULL,
		0x37EC58EB87D9A8BCULL,
		0xF33193F771943F61ULL,
		0x95395FC404DC65F6ULL,
		0x1EF6E762CB35A484ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C5EB3DF8C437540ULL,
		0x5596204A0AF4EB10ULL,
		0x519790FBB884BDC7ULL,
		0xD795EAADFE4F0891ULL,
		0xCBD83E0899E80349ULL,
		0xDCB0530453EA4CFCULL,
		0x927E32C82CB51E52ULL,
		0xF15D39AA9AC13890ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C590C12658E9143ULL,
		0x3E7B42A95772BC8AULL,
		0xD6D85B3F72EF1EC9ULL,
		0x634D1F9CEBEF9CD7ULL,
		0x8FDD8E6D160B6419ULL,
		0x2544C3B2A5D8D54BULL,
		0x1B2B19EFA136D92CULL,
		0x88A35B51CABC6AC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4090D9B08CCA6FULL,
		0x034B3E53F814C135ULL,
		0xC5C76795B0B80157ULL,
		0x3A614CB7E5C18F98ULL,
		0x078B9F99293C424FULL,
		0xDC3419CBC087CAE2ULL,
		0x676EBDAB94679B86ULL,
		0xB774D60AAE3D620BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2187B38B501C6D4ULL,
		0x3B3004555F5DFB54ULL,
		0x1110F3A9C2371D72ULL,
		0x28EBD2E5062E0D3FULL,
		0x8851EED3ECCF21CAULL,
		0x4910A9E6E5510A69ULL,
		0xB3BC5C440CCF3DA5ULL,
		0xD12E85471C7F08B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF8AFEC9A33B045BAULL,
		0x91349C923453A7F3ULL,
		0x0FC19DF83EFC053DULL,
		0x0BC6FDB5A7C95A9CULL,
		0xD782DBC9EBF8744CULL,
		0x30CFCD7AA0AA4FA4ULL,
		0xE7EEAB97527EB55DULL,
		0x1FAB005B18377B7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24BACF8A55B743BAULL,
		0x52178613D0EC1663ULL,
		0x85BFDBB9750438C8ULL,
		0x6893B6C5DB724512ULL,
		0x1AAE2F38D641ADB6ULL,
		0xFD8F0346D5CF9037ULL,
		0xFEA3BE533A37A690ULL,
		0x1641EF39522A5BD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3F51D0FDDF90200ULL,
		0x3F1D167E63679190ULL,
		0x8A01C23EC9F7CC75ULL,
		0xA33346EFCC571589ULL,
		0xBCD4AC9115B6C695ULL,
		0x3340CA33CADABF6DULL,
		0xE94AED4418470ECCULL,
		0x09691121C60D1FAAULL
	}};
	sign = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA6ED4D804EC87FFULL,
		0x0B3ED451227B4966ULL,
		0xF25108CFDEA59BFDULL,
		0xD37A67D60BD41EA3ULL,
		0x2E17A2F203B4F197ULL,
		0x311E8CE37C71E142ULL,
		0x1B52C6A460B676C8ULL,
		0x9313042787B54FA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32573E0174D6E54ULL,
		0x94780E48B71944B5ULL,
		0xD817E41B1F8C3432ULL,
		0xC7B862C790274519ULL,
		0x675AF6216EEF8645ULL,
		0xF317BA0B870FA4D5ULL,
		0xBB29F9041AD465FDULL,
		0x99BB8040ED99497EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x274960F7ED9F19ABULL,
		0x76C6C6086B6204B1ULL,
		0x1A3924B4BF1967CAULL,
		0x0BC2050E7BACD98AULL,
		0xC6BCACD094C56B52ULL,
		0x3E06D2D7F5623C6CULL,
		0x6028CDA045E210CAULL,
		0xF95783E69A1C0623ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF75B488780B8A949ULL,
		0x73AEC5E6BC951A8EULL,
		0xDAF515E57FD11F70ULL,
		0x0105DB4D14B6D842ULL,
		0x6F0A53A89D700606ULL,
		0x86AB91F1A8231B12ULL,
		0x1AF01BA815627B2DULL,
		0x85495797B67AD75AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C53EBA9823C7DDULL,
		0x244A05B4612BB0DDULL,
		0x0B466F60884422E5ULL,
		0x8D52C244250D8B22ULL,
		0xAE468A24D30644BEULL,
		0xEEA5D34FC1721C4DULL,
		0x892ED09C9CD2DCABULL,
		0x7A735E9BFAD07425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x649609CCE894E16CULL,
		0x4F64C0325B6969B1ULL,
		0xCFAEA684F78CFC8BULL,
		0x73B31908EFA94D20ULL,
		0xC0C3C983CA69C147ULL,
		0x9805BEA1E6B0FEC4ULL,
		0x91C14B0B788F9E81ULL,
		0x0AD5F8FBBBAA6334ULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE6C34BBD76F227A4ULL,
		0xD1A31085DE5E3A63ULL,
		0x03F65A0B21EBA27DULL,
		0x76FE18321E0C5C53ULL,
		0xA7685693F4AFB042ULL,
		0x2CB831F04D6B5342ULL,
		0x420810FCAED112EDULL,
		0xAFB4790A1348926FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x730067C4B0A57448ULL,
		0xDCD1F489253F4FB8ULL,
		0xF6BAE0772B545E2CULL,
		0xEB5DFB2E2B7C1BC7ULL,
		0x4185654BD015ADB5ULL,
		0xBB52AA834EADF228ULL,
		0x88519B680118A4F6ULL,
		0xA5462CFF96AB9C10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73C2E3F8C64CB35CULL,
		0xF4D11BFCB91EEAABULL,
		0x0D3B7993F6974450ULL,
		0x8BA01D03F290408BULL,
		0x65E2F148249A028CULL,
		0x7165876CFEBD611AULL,
		0xB9B67594ADB86DF6ULL,
		0x0A6E4C0A7C9CF65EULL
	}};
	sign = 0;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x99A8C8B4C326782EULL,
		0x595DCF3DBEF4BB66ULL,
		0x33274C4151E435ACULL,
		0x2B8A62BB9489BF37ULL,
		0x8D3B40D5D066A542ULL,
		0x1C71EDF2CDD0CF06ULL,
		0xB3274536A1ED0C41ULL,
		0x104419BAAC440E67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9AF16411A62D5AULL,
		0xD90F164DCC10506CULL,
		0xFFBC3E0E281F8A19ULL,
		0x6D18F04A7337851BULL,
		0x7C41A498DC560895ULL,
		0x3E45C728FC20FB9DULL,
		0xC91C725384F40A46ULL,
		0xE7E277CF80B72D2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C0DD750B1804AD4ULL,
		0x804EB8EFF2E46AFAULL,
		0x336B0E3329C4AB92ULL,
		0xBE71727121523A1BULL,
		0x10F99C3CF4109CACULL,
		0xDE2C26C9D1AFD369ULL,
		0xEA0AD2E31CF901FAULL,
		0x2861A1EB2B8CE13CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF9CAACF501435AE7ULL,
		0xEA4201411F30140DULL,
		0x0E140C00FA17F959ULL,
		0xDD694DE778672BEEULL,
		0x83B9C3B4F2234691ULL,
		0x7F1F4E13ADB2CDF5ULL,
		0x59FCE4C410C6210DULL,
		0x7B62063631D45792ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFE62B14D4CB6A4ULL,
		0x1F7DDB34CEA97305ULL,
		0xAB6FDDA75ACB3A27ULL,
		0x0BA3671A66E1772DULL,
		0x10E3BE4E8FAD6C25ULL,
		0xEA084AA60C5713B4ULL,
		0x7986B868954865CCULL,
		0xD93579B833A77002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DCC4A43B3F6A443ULL,
		0xCAC4260C5086A108ULL,
		0x62A42E599F4CBF32ULL,
		0xD1C5E6CD1185B4C0ULL,
		0x72D605666275DA6CULL,
		0x9517036DA15BBA41ULL,
		0xE0762C5B7B7DBB40ULL,
		0xA22C8C7DFE2CE78FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x47BD4317A3FCFC25ULL,
		0x89BD3BC2B14896BCULL,
		0x3D87EFA68523E03CULL,
		0x4DF075545E8D481EULL,
		0xDF854E15F6715478ULL,
		0x4B405C7EB7CCE302ULL,
		0xC8E3EF382B6FBE75ULL,
		0x2B97D21D656FF23AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4E129ACE27BF249ULL,
		0xE74F13BD8ABD5D8DULL,
		0x26929A13DA8C3DF3ULL,
		0xF3D71225A7158F9AULL,
		0x4BD8E4AEDE0312B8ULL,
		0x92EB409C240A66DFULL,
		0xDB94387B03B1CC8EULL,
		0x285337F779E97CEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62DC196AC18109DCULL,
		0xA26E2805268B392EULL,
		0x16F55592AA97A248ULL,
		0x5A19632EB777B884ULL,
		0x93AC6967186E41BFULL,
		0xB8551BE293C27C23ULL,
		0xED4FB6BD27BDF1E6ULL,
		0x03449A25EB86754BULL
	}};
	sign = 0;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5ED65E291AE3EBA2ULL,
		0x6BBB701BE0EADE01ULL,
		0x937DE0B44601C063ULL,
		0x6B56C4A36BF835B1ULL,
		0x166F70659338AF11ULL,
		0xBD1E07F593772AA4ULL,
		0xFBCB4CBE37D5076BULL,
		0xD6F6A77E58C51AFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6963ADA4E5BC28BAULL,
		0x46861F888FE4A343ULL,
		0x92EC078F4AECE05DULL,
		0x076AEECE499D08DFULL,
		0xEC4518C70E7D6E4DULL,
		0x4B29A8AF81631A55ULL,
		0xCB47E7DA5F8BD35EULL,
		0x981F2A2BD6105208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF572B0843527C2E8ULL,
		0x2535509351063ABDULL,
		0x0091D924FB14E006ULL,
		0x63EBD5D5225B2CD2ULL,
		0x2A2A579E84BB40C4ULL,
		0x71F45F461214104EULL,
		0x308364E3D849340DULL,
		0x3ED77D5282B4C8F5ULL
	}};
	sign = 0;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD7600A126E80B8A2ULL,
		0xDB332E1559BB5A79ULL,
		0x457FCB72C6D0A7D7ULL,
		0x6A4C095C6E64AB18ULL,
		0xAA90C595BE3F6AC5ULL,
		0xD56B2182C5C9F38BULL,
		0x6248B9DD0FBAD87CULL,
		0x6AC73DF6CD1ED4D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF91D2D60753E38BEULL,
		0x4F125F77CD7F9482ULL,
		0x44373D5B3F2BCD32ULL,
		0xC26B94889EDF2563ULL,
		0x3B04CFA82FF04297ULL,
		0x0DD67F6173D15154ULL,
		0xFB312E20E3533805ULL,
		0xC18D3A46CF2A74C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE42DCB1F9427FE4ULL,
		0x8C20CE9D8C3BC5F6ULL,
		0x01488E1787A4DAA5ULL,
		0xA7E074D3CF8585B5ULL,
		0x6F8BF5ED8E4F282DULL,
		0xC794A22151F8A237ULL,
		0x67178BBC2C67A077ULL,
		0xA93A03AFFDF46015ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC76FF5F535E8C3BCULL,
		0x5C4F017AE93855EFULL,
		0x5A3669A5A7442810ULL,
		0x287038344A7C76EAULL,
		0x26E14AB3BFCA52D1ULL,
		0x0C84768794D33133ULL,
		0x8621FBEB9946A75AULL,
		0x6F9D3B07A19AAE44ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7D86C7CEA6C14A3ULL,
		0x63F8710A49D31E81ULL,
		0x152E73B18A94FD6EULL,
		0xEE2B1AFDCD2B7A0DULL,
		0x034AEFFF8B0B97ABULL,
		0xCE8E72BBAED73F5DULL,
		0xA79E49523F587CDBULL,
		0xED23057B88346936ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF9789784B7CAF19ULL,
		0xF85690709F65376DULL,
		0x4507F5F41CAF2AA1ULL,
		0x3A451D367D50FCDDULL,
		0x23965AB434BEBB25ULL,
		0x3DF603CBE5FBF1D6ULL,
		0xDE83B29959EE2A7EULL,
		0x827A358C1966450DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E9CA01845539FBBULL,
		0x68533093105D63B2ULL,
		0x53A14268C78B22DAULL,
		0x69D33D6F4D422D6EULL,
		0x9C66DDDF59374010ULL,
		0x29DA36B9DDAF011CULL,
		0xA88DB1E3083C2870ULL,
		0xBF74640F2F02EB22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C6565AFEE09CD8EULL,
		0xF4C9F11664DE2C3EULL,
		0xDF9C2C45DA61D71FULL,
		0x3B9BA6DCDDF9A2A0ULL,
		0xC8ED2ED806891275ULL,
		0x9C710A5EDB8CB086ULL,
		0x8E3304117E074D64ULL,
		0xB82A69B35CD55E60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2373A685749D22DULL,
		0x73893F7CAB7F3773ULL,
		0x74051622ED294BBAULL,
		0x2E3796926F488ACDULL,
		0xD379AF0752AE2D9BULL,
		0x8D692C5B02225095ULL,
		0x1A5AADD18A34DB0BULL,
		0x0749FA5BD22D8CC2ULL
	}};
	sign = 0;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6497143F949B82EDULL,
		0xB7C79626022E93F2ULL,
		0x83B7DE4C336AF3BEULL,
		0x58B6E03E395AA3EBULL,
		0xC5BA39E52696DA55ULL,
		0x864FDA51A719FEADULL,
		0x6FBCF9DA402C1506ULL,
		0x953E8B9F48D79DADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A231575C45737AULL,
		0x6AFAF1F31D1E584BULL,
		0x3016FE5145DD4C45ULL,
		0x1E6F33574F89C0C5ULL,
		0x02E9C8A2A5010244ULL,
		0x12BE24642F6C0125ULL,
		0x5B0C8A32A1ED5C8AULL,
		0x66EC56B46D28B298ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82F4E2E838560F73ULL,
		0x4CCCA432E5103BA6ULL,
		0x53A0DFFAED8DA779ULL,
		0x3A47ACE6E9D0E326ULL,
		0xC2D071428195D811ULL,
		0x7391B5ED77ADFD88ULL,
		0x14B06FA79E3EB87CULL,
		0x2E5234EADBAEEB15ULL
	}};
	sign = 0;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F7FA12D09C77084ULL,
		0xC48426F8417ECCE7ULL,
		0xE3D07A960C9FD9B9ULL,
		0x4150003D34B566CBULL,
		0x23F35BD9F71A0421ULL,
		0xAD18BD51D3D84234ULL,
		0x932B0CB5FA6AA8E4ULL,
		0x11E41055A4828116ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A5CC7B348E0235EULL,
		0x1E1F03EF31E9BDCCULL,
		0x98FFF544F094CFDCULL,
		0x478430A834A472AFULL,
		0x69E2039B69AE4611ULL,
		0xE06FA879370B1812ULL,
		0x53E237A446F4573AULL,
		0xCC936EE5812BED39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA522D979C0E74D26ULL,
		0xA66523090F950F1AULL,
		0x4AD085511C0B09DDULL,
		0xF9CBCF950010F41CULL,
		0xBA11583E8D6BBE0FULL,
		0xCCA914D89CCD2A21ULL,
		0x3F48D511B37651A9ULL,
		0x4550A170235693DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x18DD7E08A7841AD6ULL,
		0xE2FCA30D56663AC7ULL,
		0x268BE55702BC63D3ULL,
		0x92C22BD7633C9B0AULL,
		0x71EB3ED625BC0D88ULL,
		0xB41F6107F88001B0ULL,
		0x008BA2AE48AE72D7ULL,
		0x0007D8BD04C6B98CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C6B17F0E32EE17ULL,
		0x07692EE43342A92AULL,
		0xD2DD12324DCB4876ULL,
		0xC64FDEC600E9C1CDULL,
		0xA0DF52B637E976DBULL,
		0x8262B0ECAC889095ULL,
		0x2603A9C4A15E5924ULL,
		0x80198442071E9D2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F16CC8999512CBFULL,
		0xDB9374292323919CULL,
		0x53AED324B4F11B5DULL,
		0xCC724D116252D93CULL,
		0xD10BEC1FEDD296ACULL,
		0x31BCB01B4BF7711AULL,
		0xDA87F8E9A75019B3ULL,
		0x7FEE547AFDA81C5CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8ED3FAA3ED13468FULL,
		0x65F293B3E4DB58BAULL,
		0x3B9CC654C81BFB45ULL,
		0x385159A8CD26D250ULL,
		0xCF69BFFCE237178AULL,
		0x7F8782CB4579DED4ULL,
		0xDECF54BD6C638B3FULL,
		0x2813297441DA7593ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC7B6AB1EB73335ULL,
		0x8D47BBEABF769ACEULL,
		0x8A173567F0F2B1AEULL,
		0xFDC06EAA6C6CC2BBULL,
		0x8636DC5D04A22BF0ULL,
		0xA9B47D5EA5EFA00BULL,
		0x39B916DD386D3E8CULL,
		0x5F01BD2A8C51AB36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD10C43F8CE5C135AULL,
		0xD8AAD7C92564BDEBULL,
		0xB18590ECD7294996ULL,
		0x3A90EAFE60BA0F94ULL,
		0x4932E39FDD94EB99ULL,
		0xD5D3056C9F8A3EC9ULL,
		0xA5163DE033F64CB2ULL,
		0xC9116C49B588CA5DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B0DE63485A06D76ULL,
		0x3DC35397696BFC62ULL,
		0x562AC4F4AF303537ULL,
		0x84C0E2B3A82833D2ULL,
		0x1D174C8B36A2A67FULL,
		0x5B51DBBAA6A0D860ULL,
		0x7B809408A1DA37F3ULL,
		0xF522721E408E4ECAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF122AC46FAAE114EULL,
		0x20A70A74657FBBFDULL,
		0xB560A713659246DFULL,
		0x690A5D2A25AC130FULL,
		0x29F71780F5C40F86ULL,
		0x93D3D6A6678838F8ULL,
		0x8405A0D1C660B352ULL,
		0xB7AF59E0CA724F8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9EB39ED8AF25C28ULL,
		0x1D1C492303EC4064ULL,
		0xA0CA1DE1499DEE58ULL,
		0x1BB68589827C20C2ULL,
		0xF320350A40DE96F9ULL,
		0xC77E05143F189F67ULL,
		0xF77AF336DB7984A0ULL,
		0x3D73183D761BFF3DULL
	}};
	sign = 0;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x92C5D6FCDBEF957BULL,
		0x050C9751E0993BB0ULL,
		0x3F91C2093BFC825DULL,
		0x9EDBA183FA28A0A7ULL,
		0x6F95E66C968FDC30ULL,
		0x45B58C61B9ABF9D1ULL,
		0xA2CE5BFC793DC751ULL,
		0xA951240A20B1B203ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C82827778BA224ULL,
		0x0F1C207160FE692CULL,
		0xE5EE28A80F5D5849ULL,
		0x40A096D4B2DB2F87ULL,
		0xD13225B4362FBF53ULL,
		0x67C0CEC2C40B1847ULL,
		0xC3567D999DF7B53DULL,
		0x84A795B2D5932B99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AFDAED56463F357ULL,
		0xF5F076E07F9AD284ULL,
		0x59A399612C9F2A13ULL,
		0x5E3B0AAF474D711FULL,
		0x9E63C0B860601CDDULL,
		0xDDF4BD9EF5A0E189ULL,
		0xDF77DE62DB461213ULL,
		0x24A98E574B1E8669ULL
	}};
	sign = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3ECE93160A636EBDULL,
		0x82894507227ECE5DULL,
		0x4CA00C75329D6B2DULL,
		0xDDEA9BCCB63AD86EULL,
		0x440F84E18058D838ULL,
		0x691D30A0C686E3F5ULL,
		0xCF020DC5CFCAA540ULL,
		0xD07D9314EF874022ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x304A39D8B3C99373ULL,
		0xAADED5B4BCFB8ECCULL,
		0xBB062BD492BAD7F4ULL,
		0x6473E269AA3D278EULL,
		0x796B600D0D4F72B3ULL,
		0x9872D89D3E0B2DF9ULL,
		0x19502F4CF38C95F0ULL,
		0x81FFECF1D0C09AB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E84593D5699DB4AULL,
		0xD7AA6F5265833F91ULL,
		0x9199E0A09FE29338ULL,
		0x7976B9630BFDB0DFULL,
		0xCAA424D473096585ULL,
		0xD0AA5803887BB5FBULL,
		0xB5B1DE78DC3E0F4FULL,
		0x4E7DA6231EC6A56BULL
	}};
	sign = 0;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8B06F3EF9250ED26ULL,
		0xE69140DD47F74821ULL,
		0x3484D3D4D98C88A8ULL,
		0x8AE449F80B7FBFF1ULL,
		0xE899C71905C24410ULL,
		0x495736CC49585F18ULL,
		0x3624F4CF874CB49DULL,
		0x08DE9E63E57E727BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9081AA93D30EC93DULL,
		0x84610D835353A416ULL,
		0x8AD772E694FC1B04ULL,
		0x2724A0F6A10D3169ULL,
		0xEFDD6EC7A439BC5EULL,
		0xFAADC01656975CD8ULL,
		0xD5702B5728EF24F1ULL,
		0xEB922C33A061C82FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA85495BBF4223E9ULL,
		0x62303359F4A3A40AULL,
		0xA9AD60EE44906DA4ULL,
		0x63BFA9016A728E87ULL,
		0xF8BC5851618887B2ULL,
		0x4EA976B5F2C1023FULL,
		0x60B4C9785E5D8FABULL,
		0x1D4C7230451CAA4BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x118B4B61011CF7D2ULL,
		0xB38D34EAAEE3FBB7ULL,
		0xB686126DA4351D8DULL,
		0xB48406F69AFDB9B1ULL,
		0x28BB592068EBABA5ULL,
		0x74E6FE517B392844ULL,
		0xA2ED9BBB3D77C709ULL,
		0x26723B80C2F58E81ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9605ADD6AE8D7DDULL,
		0x6B7BDB3072AE9461ULL,
		0xFBC3BA386F9E0DC7ULL,
		0x2891274D7D4F3599ULL,
		0x718FE4EB699C9648ULL,
		0x674165CBB5439CFDULL,
		0x09D6D5DC7A238214ULL,
		0xA1D2D058191E59BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x182AF08396341FF5ULL,
		0x481159BA3C356755ULL,
		0xBAC2583534970FC6ULL,
		0x8BF2DFA91DAE8417ULL,
		0xB72B7434FF4F155DULL,
		0x0DA59885C5F58B46ULL,
		0x9916C5DEC35444F5ULL,
		0x849F6B28A9D734C4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03CE1DE57BA9A2ADULL,
		0x212669FACADA56F5ULL,
		0xCC3E54361CC5B7E5ULL,
		0x78F7B8D23BA08E23ULL,
		0x04E5D417ADA542DCULL,
		0xB318D96F229EB092ULL,
		0x2D1B673A737EA24EULL,
		0x41C902EC6125A95DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E576FD42A5CE9FAULL,
		0x19D0FD8CF9CA7D48ULL,
		0xAEEF95EA95BA148DULL,
		0xFE6540A0F1D3AF87ULL,
		0x3EAE24F3612997B4ULL,
		0x3F9E8FBD75C64E3FULL,
		0x7A1123D41B5DD527ULL,
		0xD083B150990B3E87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD576AE11514CB8B3ULL,
		0x07556C6DD10FD9ACULL,
		0x1D4EBE4B870BA358ULL,
		0x7A92783149CCDE9CULL,
		0xC637AF244C7BAB27ULL,
		0x737A49B1ACD86252ULL,
		0xB30A43665820CD27ULL,
		0x7145519BC81A6AD5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEFD46F644A937534ULL,
		0x15F1351F7B6AFAB5ULL,
		0x575480D1F6250811ULL,
		0x2C2CA47E4FB90DBCULL,
		0xAB4C4CC17BE6FC71ULL,
		0xB5DAB69CE39448F7ULL,
		0x6CA169AE852BE242ULL,
		0xC14C9D07BEB36811ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F89F0E07EEAC1DULL,
		0x216E9D81A46F07ADULL,
		0x4CC6B155DC26BE36ULL,
		0x339110128061C16CULL,
		0x95B920C35FD7E9EBULL,
		0x3303F12B03FE6881ULL,
		0x95C6352A3E41B9CAULL,
		0x12E9918701B62835ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BDBD05642A4C917ULL,
		0xF482979DD6FBF308ULL,
		0x0A8DCF7C19FE49DAULL,
		0xF89B946BCF574C50ULL,
		0x15932BFE1C0F1285ULL,
		0x82D6C571DF95E076ULL,
		0xD6DB348446EA2878ULL,
		0xAE630B80BCFD3FDBULL
	}};
	sign = 0;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5F949B051916667AULL,
		0x0CB7724936405DE0ULL,
		0xCC42F9112210B2EBULL,
		0xAAE1E4F52F41B6F6ULL,
		0x2D98F5BF161B1C2BULL,
		0x441C82DFB5D92306ULL,
		0x4CF6C3FD1E5520F0ULL,
		0xC6253700A2A16405ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF81CFBA87603376ULL,
		0x0F370DA24A5AD6F6ULL,
		0xC457CA5FD4A16094ULL,
		0x367FECD083E6B46BULL,
		0x7C1A742738491EF4ULL,
		0xEC25345BA92145CFULL,
		0x55BEA72203BE00ADULL,
		0x82303636CD70F1BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6012CB4A91B63304ULL,
		0xFD8064A6EBE586E9ULL,
		0x07EB2EB14D6F5256ULL,
		0x7461F824AB5B028BULL,
		0xB17E8197DDD1FD37ULL,
		0x57F74E840CB7DD36ULL,
		0xF7381CDB1A972042ULL,
		0x43F500C9D5307247ULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5718D66D7C01371BULL,
		0x2AEE4A4ED64D384FULL,
		0xBDBCB53CB99133CCULL,
		0x21E824007021E3EFULL,
		0x322E22A7E30B073AULL,
		0xF2806E22DD8FC6BDULL,
		0x8E20446EDD924B53ULL,
		0x28CA3BD6B5EFDB20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD10028FAE551A35ULL,
		0x02C32F95AE8591CAULL,
		0xED85A238E46455C1ULL,
		0x9F9A40150A57214FULL,
		0x574574590E87E77FULL,
		0x4602E88C624C87D1ULL,
		0x5DFBA44993C9097CULL,
		0x39FAE467CA80A387ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A08D3DDCDAC1CE6ULL,
		0x282B1AB927C7A684ULL,
		0xD0371303D52CDE0BULL,
		0x824DE3EB65CAC29FULL,
		0xDAE8AE4ED4831FBAULL,
		0xAC7D85967B433EEBULL,
		0x3024A02549C941D7ULL,
		0xEECF576EEB6F3799ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x808B576B7B6B2217ULL,
		0x1E89AE08E6E11CA4ULL,
		0xE3324765F838FA1BULL,
		0x889BEF25F4A1B942ULL,
		0x8A3FB065A2055F51ULL,
		0x0DE3476213D6405FULL,
		0x62062D96F59C8D8FULL,
		0xD89C000EA5B4DC18ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3725EE4DB1B0A3ULL,
		0x5AD0EA92C0FADE9DULL,
		0x9DBA94EE3DFCA97EULL,
		0xB72D47DD18554908ULL,
		0xB77857D34BA6B2D1ULL,
		0x4736EAFA4ECEE065ULL,
		0x9E9A71EEB75EF354ULL,
		0x48F8615F97A73BD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6254317D2DB97174ULL,
		0xC3B8C37625E63E07ULL,
		0x4577B277BA3C509CULL,
		0xD16EA748DC4C703AULL,
		0xD2C75892565EAC7FULL,
		0xC6AC5C67C5075FF9ULL,
		0xC36BBBA83E3D9A3AULL,
		0x8FA39EAF0E0DA041ULL
	}};
	sign = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB6ED2AABE0E9F7CCULL,
		0xF292661C951B1F7DULL,
		0xABB0C13A4093B2FDULL,
		0x753975E2B93B4C07ULL,
		0x3663E5EF2F12158AULL,
		0x9A0B662DA1F9722DULL,
		0x2BE6344B627543AFULL,
		0xC8FEF99CB76D26B1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11ECADD2341B1A3ULL,
		0xA9226A0C05B48DE6ULL,
		0x63BD9FFA8B934DF4ULL,
		0x22702E1C971EE701ULL,
		0xA0F54A2F8732B065ULL,
		0xBB5F48502A70783DULL,
		0x3A151F41AC16D0B5ULL,
		0x8005FE60A4E807FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5CE5FCEBDA84629ULL,
		0x496FFC108F669196ULL,
		0x47F3213FB5006509ULL,
		0x52C947C6221C6506ULL,
		0x956E9BBFA7DF6525ULL,
		0xDEAC1DDD7788F9EFULL,
		0xF1D11509B65E72F9ULL,
		0x48F8FB3C12851EB5ULL
	}};
	sign = 0;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x65F2DB136735AA8CULL,
		0x7ACB6DC649F6881DULL,
		0xC183D3C9B00F671BULL,
		0x26B8E3B2F64F53BBULL,
		0xD2D81C5F2AC98F1BULL,
		0xC8D6A8524BB757E0ULL,
		0x9FE0853896065440ULL,
		0xDAF84CE705252410ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF964DFB8C0B617AAULL,
		0xE5B844386A8755CEULL,
		0x4B9E2903FCBE815FULL,
		0xA0D2FB72142FB65EULL,
		0x17F54102801163B3ULL,
		0x8B9EDB4EE8E02F88ULL,
		0x2E85D8237364993EULL,
		0xB3D8EDC0BD65DFAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C8DFB5AA67F92E2ULL,
		0x9513298DDF6F324EULL,
		0x75E5AAC5B350E5BBULL,
		0x85E5E840E21F9D5DULL,
		0xBAE2DB5CAAB82B67ULL,
		0x3D37CD0362D72858ULL,
		0x715AAD1522A1BB02ULL,
		0x271F5F2647BF4466ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDEB0048B9AFA57E9ULL,
		0x4996EED10503D638ULL,
		0xFB22FBD7CF2AA70FULL,
		0x910A83B64F2440F0ULL,
		0x9F1DCE035D699408ULL,
		0x3B727D7E1A58440BULL,
		0x5A202932C3A66F82ULL,
		0xE85E9587C00B9FF4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83704D29A46F0C1ULL,
		0x154495CDCA616D63ULL,
		0xFF6FF1A8B1D4592BULL,
		0x747DDED9FA004816ULL,
		0x72B4A72BC2819529ULL,
		0x413A96F99F64E68CULL,
		0xBB944BA47CF31503ULL,
		0x166E98D33F2C6DF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0678FFB900B36728ULL,
		0x345259033AA268D5ULL,
		0xFBB30A2F1D564DE4ULL,
		0x1C8CA4DC5523F8D9ULL,
		0x2C6926D79AE7FEDFULL,
		0xFA37E6847AF35D7FULL,
		0x9E8BDD8E46B35A7EULL,
		0xD1EFFCB480DF3201ULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE5A6724B5B511E9EULL,
		0xE41556A08C6B59BAULL,
		0xFDB06F69F59F3F14ULL,
		0xF10880E652BF270CULL,
		0xBBEC2B304A614A21ULL,
		0xBA748D74A650BDEBULL,
		0x77910E7235720F71ULL,
		0x3A0B4E20550722F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9982CB04B5706104ULL,
		0x07F329F3F1FB225EULL,
		0x02542159CDEE2656ULL,
		0xD29E3E8096C97435ULL,
		0x58D95C81FAFE5D9EULL,
		0xA384F6BAE225A265ULL,
		0x53DB37190BCBD2AEULL,
		0x1479A8582F628B0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C23A746A5E0BD9AULL,
		0xDC222CAC9A70375CULL,
		0xFB5C4E1027B118BEULL,
		0x1E6A4265BBF5B2D7ULL,
		0x6312CEAE4F62EC83ULL,
		0x16EF96B9C42B1B86ULL,
		0x23B5D75929A63CC3ULL,
		0x2591A5C825A497EFULL
	}};
	sign = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8F8895C1F4A5FCCULL,
		0xC999B835EAAD3325ULL,
		0x2B168FD6AB707488ULL,
		0x3EBAC27C67E050AEULL,
		0xF09233761FDB0668ULL,
		0x24B64846F93A948FULL,
		0x8485660CF5E2FEBBULL,
		0xB23FD55D395B2E57ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D29683CDE682A0CULL,
		0xC529E678FFEFADF1ULL,
		0xB63CFB702AE6A4EAULL,
		0xDA2028134002E922ULL,
		0x967BC2BE62307A6CULL,
		0xFF0007D9A671C774ULL,
		0x02F7F2821446D3D0ULL,
		0xA98BD026B366A7ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBCF211F40E235C0ULL,
		0x046FD1BCEABD8534ULL,
		0x74D994668089CF9EULL,
		0x649A9A6927DD678BULL,
		0x5A1670B7BDAA8BFBULL,
		0x25B6406D52C8CD1BULL,
		0x818D738AE19C2AEAULL,
		0x08B4053685F486ACULL
	}};
	sign = 0;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x878799C4C77CC400ULL,
		0x97FF69AEBD67D6F1ULL,
		0xD7EC87488EA48553ULL,
		0x80B0E1AF83526DF5ULL,
		0x2E415B4C13A0080AULL,
		0x11B98BA4DE9ADDFDULL,
		0xA37DDDA24A92EA06ULL,
		0xE01FC715CD290E54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66DB0F58213A78ECULL,
		0x905B3304D3E68D36ULL,
		0x5CA7B6DCFACE2D21ULL,
		0x263CA5E68DEB86DFULL,
		0xDC2452EFA725615CULL,
		0xF61F6FD612E03B63ULL,
		0x9B26CF0EC121D8D3ULL,
		0x7FABB891180B9C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20AC8A6CA6424B14ULL,
		0x07A436A9E98149BBULL,
		0x7B44D06B93D65832ULL,
		0x5A743BC8F566E716ULL,
		0x521D085C6C7AA6AEULL,
		0x1B9A1BCECBBAA299ULL,
		0x08570E9389711132ULL,
		0x60740E84B51D71EEULL
	}};
	sign = 0;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8B0B082A0DF5D915ULL,
		0xF9DBE0A254B32E9AULL,
		0x0DDB73708D35382EULL,
		0xBD24EA97550F178FULL,
		0x52F77D6162708739ULL,
		0xD95832F7D32CF96DULL,
		0x541C71C4052814D1ULL,
		0x5C5DD68C2749DEC6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E1A79E6EE6DE175ULL,
		0x0839690E42FA793BULL,
		0x7CCB3DE25B10D85FULL,
		0x0B0534BA2768C588ULL,
		0x61D15C886CCA6860ULL,
		0x95E106B6194BD7C6ULL,
		0xEFF744F97C3ACCFCULL,
		0xDDF87D87E15A153EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CF08E431F87F7A0ULL,
		0xF1A2779411B8B55FULL,
		0x9110358E32245FCFULL,
		0xB21FB5DD2DA65206ULL,
		0xF12620D8F5A61ED9ULL,
		0x43772C41B9E121A6ULL,
		0x64252CCA88ED47D5ULL,
		0x7E65590445EFC987ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x230EA3A7C58742BBULL,
		0xFEBFD5E5CF7FDA8AULL,
		0xA5224D30567687F0ULL,
		0xD30D71EE8BD7CDE0ULL,
		0xA295614D32A3B34FULL,
		0x2786E0652479644AULL,
		0xDE8AF78852886D32ULL,
		0xE475C33D2D6F601DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9963A314507F30ULL,
		0x1402D0CDE7490661ULL,
		0x4F2B8FE36F5BDF3FULL,
		0x842C55A8250FE23DULL,
		0x5668AC9412F93BFDULL,
		0x1F574E4B907271D5ULL,
		0x279C2A5805BE4672ULL,
		0xBF463325F8D399EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77754004B136C38BULL,
		0xEABD0517E836D428ULL,
		0x55F6BD4CE71AA8B1ULL,
		0x4EE11C4666C7EBA3ULL,
		0x4C2CB4B91FAA7752ULL,
		0x082F92199406F275ULL,
		0xB6EECD304CCA26C0ULL,
		0x252F9017349BC630ULL
	}};
	sign = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C9D179BD5152A86ULL,
		0x244B56D17DFE1B01ULL,
		0x4940E0423D2A8A6EULL,
		0xFA667518C3DC1420ULL,
		0xA7DB828C4D5E4DFEULL,
		0xDFAAF63A07BB6B81ULL,
		0x93A217914170F997ULL,
		0x78EA54978EFB7AFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE1E7A787F9DF3CULL,
		0x1B51B532E0C216CEULL,
		0x482F9CE1DC6B6B2BULL,
		0xE57E716CCEB58825ULL,
		0x3E4EEECAFD41CB27ULL,
		0xA2D18AD0C464B103ULL,
		0xC2239BC36CDC7A86ULL,
		0x1E1CE9653B1B3AD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FBB2FF44D1B4B4AULL,
		0x08F9A19E9D3C0433ULL,
		0x0111436060BF1F43ULL,
		0x14E803ABF5268BFBULL,
		0x698C93C1501C82D7ULL,
		0x3CD96B694356BA7EULL,
		0xD17E7BCDD4947F11ULL,
		0x5ACD6B3253E04023ULL
	}};
	sign = 0;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F2AC9702727B76FULL,
		0x7FC299A736B50C06ULL,
		0xFBA03809D8DC2328ULL,
		0x5FC5A2584E12B35DULL,
		0xA375E35C58B7D9DAULL,
		0x30ADC7BBC80B07E6ULL,
		0x4B129CC82830B618ULL,
		0x6DB6B2C0C6A0AFFFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x459594C65CFBD53FULL,
		0x69270AED2B4C12F0ULL,
		0xE04B1F050ADF0557ULL,
		0xE3D598C99DEB43AEULL,
		0xF4CF9608D8072C15ULL,
		0x33CFE7F8F7A64118ULL,
		0x4E0630A9956EE3A9ULL,
		0xCF90A2203AE32F6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD99534A9CA2BE230ULL,
		0x169B8EBA0B68F915ULL,
		0x1B551904CDFD1DD1ULL,
		0x7BF0098EB0276FAFULL,
		0xAEA64D5380B0ADC4ULL,
		0xFCDDDFC2D064C6CDULL,
		0xFD0C6C1E92C1D26EULL,
		0x9E2610A08BBD8091ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC04BABFA80E40CFFULL,
		0xB5F19362B23FD0E0ULL,
		0xAE29905159F3FDF2ULL,
		0xF28FEF22AD003F51ULL,
		0xCC3F54A106EC8200ULL,
		0xA409005E068A85E6ULL,
		0x2AF7E44A3C6D6B71ULL,
		0x7715AE2887FCCD9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA91C5078D2C5C4ULL,
		0x5643E250BBE921D1ULL,
		0x0ADC7AC1D6CEB228ULL,
		0x12E07CD51E2BC1DFULL,
		0xEBC0CC6AE41B7307ULL,
		0x8B803D872DF05B94ULL,
		0x3A0E60B8AD7F298FULL,
		0x01D57E4AAD6B67AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54A28FAA0811473BULL,
		0x5FADB111F656AF0FULL,
		0xA34D158F83254BCAULL,
		0xDFAF724D8ED47D72ULL,
		0xE07E883622D10EF9ULL,
		0x1888C2D6D89A2A51ULL,
		0xF0E983918EEE41E2ULL,
		0x75402FDDDA9165EBULL
	}};
	sign = 0;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0D9F0AD17186F83ULL,
		0xD11C715F921D20D3ULL,
		0xC15CD4018B7418DFULL,
		0x186460680A4B23F6ULL,
		0x6276B42902AC240DULL,
		0x301F01F0D5B90AECULL,
		0xF3C3D146BCA257DCULL,
		0x01CF89AB7A21816EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A45F09D9693665ULL,
		0x17D11E6E5B4A1492ULL,
		0xBCED6A88236E1143ULL,
		0xA4B1F2E89A945F05ULL,
		0xFAF4BBB5157CB498ULL,
		0xC1013579C4527675ULL,
		0x4DDFC5F7BE69F6F8ULL,
		0x20A041696D46900DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD3591A33DAF391EULL,
		0xB94B52F136D30C40ULL,
		0x046F69796806079CULL,
		0x73B26D7F6FB6C4F1ULL,
		0x6781F873ED2F6F74ULL,
		0x6F1DCC7711669476ULL,
		0xA5E40B4EFE3860E3ULL,
		0xE12F48420CDAF161ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0BC725FA3F229792ULL,
		0xBDDDF785AA991AEAULL,
		0xCA6B2DF2030E0A65ULL,
		0x7BA378E23CFE16DDULL,
		0x651C2CD29601C891ULL,
		0xC6100D2FD7138B47ULL,
		0xBFB193341CEF076BULL,
		0x486B37A87C128240ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E20BC15607C1EBULL,
		0x6629F3C4255936B8ULL,
		0xA9B204B4C8118399ULL,
		0x2828B661CBB4B556ULL,
		0xC71CE345108C3689ULL,
		0xA275AE66B2A4C385ULL,
		0x44CC427A4BDA8F7AULL,
		0xCD69D8BE2CDF024CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21E51A38E91AD5A7ULL,
		0x57B403C1853FE431ULL,
		0x20B9293D3AFC86CCULL,
		0x537AC28071496187ULL,
		0x9DFF498D85759208ULL,
		0x239A5EC9246EC7C1ULL,
		0x7AE550B9D11477F1ULL,
		0x7B015EEA4F337FF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x337A7E5BBCBFD838ULL,
		0x644225ECF3FD0909ULL,
		0x9DE00D92C3AC86EAULL,
		0x750D9888833EC744ULL,
		0xC3C3EBC2A5BE6AB8ULL,
		0xCF62DED1F7F2DF75ULL,
		0x4F7103A1548A8672ULL,
		0x6EBB30BFB4743717ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3D922256B13B946ULL,
		0x9DD0929380814DFFULL,
		0xBEE7C83B46E21D3EULL,
		0xBA3FA8525A8BE8C0ULL,
		0xB9138C9A5D4FDD84ULL,
		0x38C68C492D51C1D2ULL,
		0xA3162B4F731014F1ULL,
		0x5ABA0F66E5CAD3FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FA15C3651AC1EF2ULL,
		0xC6719359737BBB09ULL,
		0xDEF845577CCA69ABULL,
		0xBACDF03628B2DE83ULL,
		0x0AB05F28486E8D33ULL,
		0x969C5288CAA11DA3ULL,
		0xAC5AD851E17A7181ULL,
		0x14012158CEA9631BULL
	}};
	sign = 0;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x83DF797A75E98435ULL,
		0x71C06CBA518CC7EDULL,
		0xCCB5AAD493777DDDULL,
		0x23C3F54A08E50687ULL,
		0x4268BB505067AC25ULL,
		0x5B2D4262127C0E36ULL,
		0x45102F6D2C79B42BULL,
		0xAA2FBCF87FDC8365ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC25A17ADAAA04BULL,
		0xDB2FA185591A907FULL,
		0x23D967E04995D1B5ULL,
		0x6B21F2F2542FDF38ULL,
		0xB8FFB41BD7BFDF98ULL,
		0xA5C04D3BB2B86A99ULL,
		0x4DC5DB322CE5CC40ULL,
		0x34B942C5B8CECB62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB51D1F62C83EE3EAULL,
		0x9690CB34F872376DULL,
		0xA8DC42F449E1AC27ULL,
		0xB8A20257B4B5274FULL,
		0x8969073478A7CC8CULL,
		0xB56CF5265FC3A39CULL,
		0xF74A543AFF93E7EAULL,
		0x75767A32C70DB802ULL
	}};
	sign = 0;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D7538D0F13F9D90ULL,
		0x6D2844B87B37D68CULL,
		0x514C505D23CB366FULL,
		0x37E132A3CAE06BEEULL,
		0x2D7982E7890E44B4ULL,
		0xB9FCE52EED4D247FULL,
		0xEC0A1906454AA5C9ULL,
		0x3002E74ADB4F69BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AF3E190FE3CBC0ULL,
		0x3A40DBD76242F2CCULL,
		0x76C77DAF2AFD20EBULL,
		0xFD1832336F7082C0ULL,
		0x222B8F8BEA4256BAULL,
		0x086C57E8AFD683FAULL,
		0xFE8851267CE0B3EBULL,
		0xF567A6D2F2589D58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAC5FAB7E15BD1D0ULL,
		0x32E768E118F4E3BFULL,
		0xDA84D2ADF8CE1584ULL,
		0x3AC900705B6FE92DULL,
		0x0B4DF35B9ECBEDF9ULL,
		0xB1908D463D76A085ULL,
		0xED81C7DFC869F1DEULL,
		0x3A9B4077E8F6CC62ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x59444DD2B7C3A143ULL,
		0x28CB9DCB6077C892ULL,
		0x6C2F6253907777DCULL,
		0xFEC8D022F97D0BF3ULL,
		0xCC3ABA68C055FD62ULL,
		0xAC64FE0A1C09C1D7ULL,
		0xF1C1DCF1354AFA3EULL,
		0xC2E94438CCEC5F75ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE90B45643ACAFECEULL,
		0x0D80A5961A7C4E80ULL,
		0x8187AF5118891388ULL,
		0x0DEE14440EEB1031ULL,
		0x5801E9ECCE06AAF3ULL,
		0x6034E8EB015048CDULL,
		0x9E52213A0934F116ULL,
		0xD7A7D3CC00FD6830ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7039086E7CF8A275ULL,
		0x1B4AF83545FB7A11ULL,
		0xEAA7B30277EE6454ULL,
		0xF0DABBDEEA91FBC1ULL,
		0x7438D07BF24F526FULL,
		0x4C30151F1AB9790AULL,
		0x536FBBB72C160928ULL,
		0xEB41706CCBEEF745ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2DE985D6A4B2E6A9ULL,
		0x73062290C7D81EC5ULL,
		0x36109F22459227A9ULL,
		0xCFAE69960C273C70ULL,
		0x2A743DC62DAEED60ULL,
		0x48FB8124904CF1F2ULL,
		0xC4BD191218CEDCB2ULL,
		0x4C3BC7A908FAD9F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF72E51EE023FFEAULL,
		0x9420182C47484A4CULL,
		0x58356A5C3F017093ULL,
		0x53F5709A90F9D943ULL,
		0xECB6A55EA0D79B1CULL,
		0x551D4C9D135FA032ULL,
		0x35EB927FB02645A9ULL,
		0x576DE7DBFD5441C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E76A0B7C48EE6BFULL,
		0xDEE60A64808FD478ULL,
		0xDDDB34C60690B715ULL,
		0x7BB8F8FB7B2D632CULL,
		0x3DBD98678CD75244ULL,
		0xF3DE34877CED51BFULL,
		0x8ED1869268A89708ULL,
		0xF4CDDFCD0BA69836ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B5BB7D72FEE2DE5ULL,
		0x4C9BAE46C5B064C8ULL,
		0xB5CACC4BAF2D4FBCULL,
		0x346525BD3C252528ULL,
		0x07073F8456DE2125ULL,
		0x1FA401413B41806EULL,
		0x6E17D01D347E15F0ULL,
		0x85B4D6BF5ED39E46ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C38F117C99EC3DULL,
		0x4FCF81CFB2D11939ULL,
		0xAE7AF36BD010E539ULL,
		0xEDD7384C647684C6ULL,
		0x059F72125DBD7660ULL,
		0x833524371B0BAEC2ULL,
		0x1B3A931C1CBD2825ULL,
		0x69F8433BD9C8D556ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x329828C5B35441A8ULL,
		0xFCCC2C7712DF4B8FULL,
		0x074FD8DFDF1C6A82ULL,
		0x468DED70D7AEA062ULL,
		0x0167CD71F920AAC4ULL,
		0x9C6EDD0A2035D1ACULL,
		0x52DD3D0117C0EDCAULL,
		0x1BBC9383850AC8F0ULL
	}};
	sign = 0;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x10E1F0F5FF8395D8ULL,
		0xFEECD4A1C0B30EFEULL,
		0x3F2B28014315DB47ULL,
		0x6E794D244083AD10ULL,
		0xAC5C3E9E274BDFB5ULL,
		0x1D7C85CFA2DF5EE6ULL,
		0xDF1F2B9BF7C93343ULL,
		0xE9437532C06C4D40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4112092F5CA5CEULL,
		0xE5C228363784290FULL,
		0x10D36FF79B7D170DULL,
		0x6FC46182D09E433FULL,
		0x2A91C1BF8DF31116ULL,
		0xC7E0E24BE0DC2DCBULL,
		0x1058360FA68E1DB1ULL,
		0x179BED5A36D0A65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A0DEECD026F00AULL,
		0x192AAC6B892EE5EEULL,
		0x2E57B809A798C43AULL,
		0xFEB4EBA16FE569D1ULL,
		0x81CA7CDE9958CE9EULL,
		0x559BA383C203311BULL,
		0xCEC6F58C513B1591ULL,
		0xD1A787D8899BA6E2ULL
	}};
	sign = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x45D88BC1EF8D3167ULL,
		0xB877FFCB8561FB9EULL,
		0x892C9217590E1745ULL,
		0xB5B59BF83D4200ECULL,
		0xB4A92EF87851543EULL,
		0x1933544389C4C070ULL,
		0x66ACFC021F67F040ULL,
		0x3ABFE156174A3FABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08254D3336614512ULL,
		0x7C1588420DDC1995ULL,
		0x3234DE463888A965ULL,
		0xCC19605D68240AA9ULL,
		0xB54EC5BE53A1FF5EULL,
		0x75F4BF0A7C30386BULL,
		0x7740E4F332F3CF02ULL,
		0xEAA2609E69234415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DB33E8EB92BEC55ULL,
		0x3C6277897785E209ULL,
		0x56F7B3D120856DE0ULL,
		0xE99C3B9AD51DF643ULL,
		0xFF5A693A24AF54DFULL,
		0xA33E95390D948804ULL,
		0xEF6C170EEC74213DULL,
		0x501D80B7AE26FB95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAF4A1F2C562BEBF9ULL,
		0xF18F335DA1A68FC3ULL,
		0xC6B19B8154A32857ULL,
		0x770AA8D9B5CFB0D3ULL,
		0xDAA154CEE1A5CB66ULL,
		0x7C0B6944B70131A7ULL,
		0xA10D131A48FDE5FDULL,
		0xC3C9C2ACDA239A73ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46E13A96F886A512ULL,
		0xD6B6E5AE0463C431ULL,
		0x361B1B2A3E21B429ULL,
		0xA1D2ABC49FA84B17ULL,
		0xB6A116DC0A54E861ULL,
		0x0FA6BEEB4E78AAF5ULL,
		0x2562E514AF99C29FULL,
		0x16E568A107E68333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6868E4955DA546E7ULL,
		0x1AD84DAF9D42CB92ULL,
		0x909680571681742EULL,
		0xD537FD15162765BCULL,
		0x24003DF2D750E304ULL,
		0x6C64AA59688886B2ULL,
		0x7BAA2E059964235EULL,
		0xACE45A0BD23D1740ULL
	}};
	sign = 0;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA3883E8E713358A0ULL,
		0x3317177CFA061C24ULL,
		0x70CD1FF0D2B32591ULL,
		0x3F8BA3FBEC57F484ULL,
		0xEA7F7623524D6CDEULL,
		0x1D371C2CC5B140ACULL,
		0x9240F3A9FF2C21DBULL,
		0xF4A81D140F61D62DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC472060969CBFFBULL,
		0x0067A09192A4E438ULL,
		0x74F52670A0E1E681ULL,
		0x99FBAC365DDFB562ULL,
		0xE32DD628FBCED981ULL,
		0xE76A7DA6B8BDFFA7ULL,
		0x057E8BC597019BC3ULL,
		0xEC4EA5ECAF1E23ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7411E2DDA9698A5ULL,
		0x32AF76EB676137EBULL,
		0xFBD7F98031D13F10ULL,
		0xA58FF7C58E783F21ULL,
		0x07519FFA567E935CULL,
		0x35CC9E860CF34105ULL,
		0x8CC267E4682A8617ULL,
		0x085977276043B281ULL
	}};
	sign = 0;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x992F0095BB65BAA6ULL,
		0x27A5E68C94DADE33ULL,
		0xA5F5C5B87C5F2572ULL,
		0x84882B33C15F8B7DULL,
		0xD174F587D734E40EULL,
		0xB49AC836F26488E4ULL,
		0x4564A365FAA1AAB0ULL,
		0xBC30F1EFD533677CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC1AAB9494A26ABULL,
		0xA665E3CFEB5BBFBDULL,
		0x02DB3982A1E3A45EULL,
		0xB299DC43BF139B5BULL,
		0x1B63853A68971375ULL,
		0xF6B840B45BEA8CF9ULL,
		0xC36DC802D2D5D4C6ULL,
		0x3FE842A35BE56E76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A6D55DC721B93FBULL,
		0x814002BCA97F1E76ULL,
		0xA31A8C35DA7B8113ULL,
		0xD1EE4EF0024BF022ULL,
		0xB611704D6E9DD098ULL,
		0xBDE287829679FBEBULL,
		0x81F6DB6327CBD5E9ULL,
		0x7C48AF4C794DF905ULL
	}};
	sign = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9575519E7E9BF533ULL,
		0xDDA84E4F454F506FULL,
		0xE4B4F746BEAAD7B9ULL,
		0x083DE8FBF4EFDDAEULL,
		0xB38A09A66B0AE6BDULL,
		0xC28A78C03C386D3FULL,
		0xB519E19EE5E2DAFCULL,
		0x73B23C0BF31296B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x515C8E024BC5CF9EULL,
		0x0DBA7E3871D58FF3ULL,
		0x5FF4D7FAE35772C7ULL,
		0x69A35BCAF428202FULL,
		0xAB5296445238F5B1ULL,
		0xC854D5EDE17BEB5CULL,
		0xA11382E75D2D0EC6ULL,
		0xD0C49809E17B0FC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4418C39C32D62595ULL,
		0xCFEDD016D379C07CULL,
		0x84C01F4BDB5364F2ULL,
		0x9E9A8D3100C7BD7FULL,
		0x0837736218D1F10BULL,
		0xFA35A2D25ABC81E3ULL,
		0x14065EB788B5CC35ULL,
		0xA2EDA402119786F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x776C6E6949773FAFULL,
		0x3575460AD313DC84ULL,
		0x915B3F2960853C9AULL,
		0x001F10331EB7D4B9ULL,
		0x1133654042266F8AULL,
		0xC68F20F5EE715B19ULL,
		0x8670AE5910D0CA1BULL,
		0x7BBEF334391A72DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7D6A767F287926ULL,
		0x165103FE9C49DFE3ULL,
		0x38785EBCF860CFF3ULL,
		0x0023D7A7C58F6179ULL,
		0xA9A3B8E08E31EFDEULL,
		0xE8451513FFC4E391ULL,
		0x140DD6C0E8E16BECULL,
		0xCE571D2127D07C4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27EF03F2CA4EC689ULL,
		0x1F24420C36C9FCA1ULL,
		0x58E2E06C68246CA7ULL,
		0xFFFB388B59287340ULL,
		0x678FAC5FB3F47FABULL,
		0xDE4A0BE1EEAC7787ULL,
		0x7262D79827EF5E2EULL,
		0xAD67D6131149F690ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x430E866538AFB2C9ULL,
		0x2ECA174EE8694396ULL,
		0x9A716AE7EA306B29ULL,
		0x6D3368AE03A59947ULL,
		0x7AAB2E5056EEAD0EULL,
		0x0F0D159481F896A3ULL,
		0xA2F01059F13CD744ULL,
		0x8B7134496DB6A0C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE31680D0ACF18CULL,
		0x9CDEF9583F797050ULL,
		0xE25F5BFABD4C2DF6ULL,
		0x097060F4C6D23E6DULL,
		0xA3BDBC5DEEBB8C99ULL,
		0x4B917846D0845B90ULL,
		0x90B8D5F11024A787ULL,
		0x65B5196DF9E018DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x452B6FE46802C13DULL,
		0x91EB1DF6A8EFD345ULL,
		0xB8120EED2CE43D32ULL,
		0x63C307B93CD35AD9ULL,
		0xD6ED71F268332075ULL,
		0xC37B9D4DB1743B12ULL,
		0x12373A68E1182FBCULL,
		0x25BC1ADB73D687E6ULL
	}};
	sign = 0;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x681A62F57E97F85EULL,
		0xFF2F1A32B60BFE98ULL,
		0x5E8EB013E4FF45DCULL,
		0x9BB71DC37519FE01ULL,
		0xB4548D449E7B8AC5ULL,
		0x349CD48AB76E8F48ULL,
		0x6CBEABCB9D02788DULL,
		0x3118F1B7F6B08990ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEFE3F4604085AEULL,
		0xCC55700D11681482ULL,
		0x57C0DDF09E66C063ULL,
		0x499592363194FEA2ULL,
		0xFF32A39B17375E3BULL,
		0x0343CF4375DF8F8DULL,
		0x6C5934DA219C503FULL,
		0xDADAEFA0593A982FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A2A7F011E5772B0ULL,
		0x32D9AA25A4A3EA16ULL,
		0x06CDD22346988579ULL,
		0x52218B8D4384FF5FULL,
		0xB521E9A987442C8AULL,
		0x31590547418EFFBAULL,
		0x006576F17B66284EULL,
		0x563E02179D75F161ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x232AA921F6FAEE5BULL,
		0xC70798A38353DA91ULL,
		0x3DE61517968FEEA8ULL,
		0x6866E09DFB61EC76ULL,
		0x3B0E02A7FD32918DULL,
		0x16605F468AD48AD5ULL,
		0x9A8F51C59B4AE1D1ULL,
		0x47B510FC374F3464ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77197928685E6A93ULL,
		0xE6BDCDD3A2D5AC00ULL,
		0x70E69D3C61192858ULL,
		0x003AD4DD2FC39C2EULL,
		0xB38376A6D7B386C0ULL,
		0xEDFC5FC8D9823418ULL,
		0xE057FB952914A27EULL,
		0x034428E8B8615BC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC112FF98E9C83C8ULL,
		0xE049CACFE07E2E90ULL,
		0xCCFF77DB3576C64FULL,
		0x682C0BC0CB9E5047ULL,
		0x878A8C01257F0ACDULL,
		0x2863FF7DB15256BCULL,
		0xBA37563072363F52ULL,
		0x4470E8137EEDD89EULL
	}};
	sign = 0;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E8D6CF1B4E04B65ULL,
		0x9DE49865CD582A55ULL,
		0x645EBCD82B70EAFBULL,
		0x44A85D54E44F2AFDULL,
		0xABA512090FCB6C25ULL,
		0x473E367BF719D1D3ULL,
		0xC0F2511FE3F42DD5ULL,
		0x45BAFDD4BE79D854ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x41950267A2609F1CULL,
		0x7C39C45CB237D63CULL,
		0xBEAF143BA78A6AF7ULL,
		0xFF4C293E58B01F24ULL,
		0x1033F53B00943476ULL,
		0x9F37BF43916FBAF4ULL,
		0xC5F77ACEE6813DF8ULL,
		0xEA79402CECE1FFF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CF86A8A127FAC49ULL,
		0x21AAD4091B205419ULL,
		0xA5AFA89C83E68004ULL,
		0x455C34168B9F0BD8ULL,
		0x9B711CCE0F3737AEULL,
		0xA806773865AA16DFULL,
		0xFAFAD650FD72EFDCULL,
		0x5B41BDA7D197D861ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7C272D7E9D41D75EULL,
		0x8E5165AF31EF1964ULL,
		0x79F5E65BD81E3162ULL,
		0xD9D88953D0410B4AULL,
		0x8A8789FF8D51905CULL,
		0x0C3767A668136666ULL,
		0xC1E9CA3417B5DFEAULL,
		0xE62EA9F141A0B2EEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1130C156CB566A64ULL,
		0xD2B21DD460A2A047ULL,
		0xA460B08811853F8AULL,
		0x835B426A6F5BDEF8ULL,
		0x6CB550F385E0B65FULL,
		0x31690470AEEED52CULL,
		0xDBA91A9AE1DAF586ULL,
		0x6D3C56E3A15E30E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AF66C27D1EB6CFAULL,
		0xBB9F47DAD14C791DULL,
		0xD59535D3C698F1D7ULL,
		0x567D46E960E52C51ULL,
		0x1DD2390C0770D9FDULL,
		0xDACE6335B924913AULL,
		0xE640AF9935DAEA63ULL,
		0x78F2530DA0428205ULL
	}};
	sign = 0;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD257887385084D22ULL,
		0xF6056A916AE16BE5ULL,
		0xE0272DE582E06F2BULL,
		0xEBCA1E8B60FBFDF9ULL,
		0xB846957413711D7AULL,
		0xDF447F9F733ECDAEULL,
		0x313C7ED0C4E5DF3DULL,
		0x0C026D60EBD82674ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35F0B8048222D95ULL,
		0x9AB9D7128F8D06B4ULL,
		0x3BC73C4F8AEB6F5BULL,
		0x9379FC04ADBBE5BDULL,
		0xFEF4285056578A18ULL,
		0x3F54AF8BE856B86BULL,
		0xCE4E2A7AE09C6EDBULL,
		0xAADEC18F829D3906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EF87CF33CE61F8DULL,
		0x5B4B937EDB546531ULL,
		0xA45FF195F7F4FFD0ULL,
		0x58502286B340183CULL,
		0xB9526D23BD199362ULL,
		0x9FEFD0138AE81542ULL,
		0x62EE5455E4497062ULL,
		0x6123ABD1693AED6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2F330F68C0D11B42ULL,
		0xD47285604B348F1BULL,
		0xC685D6FC35035D9EULL,
		0x8C24E32EE3131566ULL,
		0x064939598D02A4B7ULL,
		0xF9CFBBFFE3F6223DULL,
		0xBD5762E45B552E3DULL,
		0x4BF597D0EFAF7306ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE599A281BDEB4DF4ULL,
		0xAD59E3B331B71781ULL,
		0x7306D735F960BF4DULL,
		0xC742B410D697A1EAULL,
		0x5D71E30B3E6FFE20ULL,
		0x4AD8C34C75A7094BULL,
		0xB2B4FD48D50612B7ULL,
		0x1F2F3217B28EF269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49996CE702E5CD4EULL,
		0x2718A1AD197D7799ULL,
		0x537EFFC63BA29E51ULL,
		0xC4E22F1E0C7B737CULL,
		0xA8D7564E4E92A696ULL,
		0xAEF6F8B36E4F18F1ULL,
		0x0AA2659B864F1B86ULL,
		0x2CC665B93D20809DULL
	}};
	sign = 0;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBF706C04668751CBULL,
		0xA0B266445A61EE56ULL,
		0xE8497166A5B52C8AULL,
		0xDC40961E2B50C006ULL,
		0x3AD986926FBA6633ULL,
		0x6A718B731363FF4FULL,
		0x2987C9B8A547ADA7ULL,
		0x8D2CA06E1EEA6D09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA6704B12ACD1C8ULL,
		0xFF8D16C4E0F9264EULL,
		0x7F7ECF8E5A287A87ULL,
		0x8AD0F10F896EBB20ULL,
		0x0ACE007EDFA6A4A8ULL,
		0x7F27CF6D26DEC90BULL,
		0x17A3D5D94927B1AFULL,
		0xA343A68E29ED4269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63C9FBB953DA8003ULL,
		0xA1254F7F7968C808ULL,
		0x68CAA1D84B8CB202ULL,
		0x516FA50EA1E204E6ULL,
		0x300B86139013C18BULL,
		0xEB49BC05EC853644ULL,
		0x11E3F3DF5C1FFBF7ULL,
		0xE9E8F9DFF4FD2AA0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C4E87A50C2A8FC6ULL,
		0xCBC695AB64CB8315ULL,
		0x4EF2097FD4A1BFD0ULL,
		0x19CFB26BAC5E233AULL,
		0x449729F0105A67B4ULL,
		0x642D2BAC4C172ACEULL,
		0x8AA586D22443A8E9ULL,
		0xD158EEB43C25FCD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38954BE41276E2BULL,
		0x3F020870EEE29530ULL,
		0x1D4F6EA0DD873120ULL,
		0x5D1CDE065D646A65ULL,
		0x7439295F63725840ULL,
		0x84C1F102C3DA7404ULL,
		0xB3E249B6C3BEBCBAULL,
		0x66D3A9F011273BB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98C532E6CB03219BULL,
		0x8CC48D3A75E8EDE4ULL,
		0x31A29ADEF71A8EB0ULL,
		0xBCB2D4654EF9B8D5ULL,
		0xD05E0090ACE80F73ULL,
		0xDF6B3AA9883CB6C9ULL,
		0xD6C33D1B6084EC2EULL,
		0x6A8544C42AFEC121ULL
	}};
	sign = 0;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEEACD5E49A6579C5ULL,
		0xF38B6F2D2D9BC913ULL,
		0xC0C4C3FA6C03DA2DULL,
		0x697CEFC1D294E63DULL,
		0xCFEE41DB34DC61D0ULL,
		0x400CFC6B2FB35218ULL,
		0xD4A9BC2D8B6938FCULL,
		0x01650DC3CB19E51DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3A2EB7845F3B70ULL,
		0x214A543F80C363D4ULL,
		0xF0524B774C074A0AULL,
		0xD7CB4BDE1E40356DULL,
		0x29D26B80C58F781CULL,
		0xD03070DFF76CE741ULL,
		0xB8A70BF629E47576ULL,
		0x4F5B0B9A94E0DB4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F72A72D16063E55ULL,
		0xD2411AEDACD8653FULL,
		0xD07278831FFC9023ULL,
		0x91B1A3E3B454B0CFULL,
		0xA61BD65A6F4CE9B3ULL,
		0x6FDC8B8B38466AD7ULL,
		0x1C02B0376184C385ULL,
		0xB20A0229363909CFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E87B2FAD59ED5BDULL,
		0xF1436D11AF4EB858ULL,
		0x155A0019A47F049CULL,
		0xDC0212576BCEC3B0ULL,
		0xB6D11E56285D292EULL,
		0x81A2979B4F6CCB1FULL,
		0xC2BB9C35A37D3AE8ULL,
		0xAEA9CD49CDD31BDBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58544FCF6C82411CULL,
		0x5708A860BCA7E8FBULL,
		0xD7B22CA1B05B8B8EULL,
		0x1522C0D18669EAB6ULL,
		0x5111FAB5DBC9620FULL,
		0xD8696F4996426B39ULL,
		0x970F73C1F97A7637ULL,
		0x02CF4AD37BF365E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF633632B691C94A1ULL,
		0x9A3AC4B0F2A6CF5CULL,
		0x3DA7D377F423790EULL,
		0xC6DF5185E564D8F9ULL,
		0x65BF23A04C93C71FULL,
		0xA9392851B92A5FE6ULL,
		0x2BAC2873AA02C4B0ULL,
		0xABDA827651DFB5FAULL
	}};
	sign = 0;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07BD58233D1BC45DULL,
		0xF787068677FDE596ULL,
		0xE32B7B62C0338813ULL,
		0x70C5AA8020E2C5F0ULL,
		0x26F8289F45509A8BULL,
		0x3BE8E12298304144ULL,
		0x0A8E44CB9B5EF602ULL,
		0xA210314514264DEBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CE0A6E7D61849FULL,
		0xF51A3F451D56C4D6ULL,
		0x74A21817A071F1DAULL,
		0xB51E2865F82C7F68ULL,
		0x0C33F9B4A5781EACULL,
		0x903CA69F642E85AAULL,
		0x56CE86143C30C51EULL,
		0x1E65826D6860C812ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DEF4DB4BFBA3FBEULL,
		0x026CC7415AA720BFULL,
		0x6E89634B1FC19639ULL,
		0xBBA7821A28B64688ULL,
		0x1AC42EEA9FD87BDEULL,
		0xABAC3A833401BB9AULL,
		0xB3BFBEB75F2E30E3ULL,
		0x83AAAED7ABC585D8ULL
	}};
	sign = 0;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA9803C1074ED42D2ULL,
		0xA0BA94D920E954C1ULL,
		0x311C67375CF5DAE1ULL,
		0xE8E071A5747AA7D2ULL,
		0x9843C29E29F20E23ULL,
		0x4CFA08D408B34DE1ULL,
		0x0D743FE7F1986C23ULL,
		0x4D15F114BC2CEFEEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A7F91F4D0CA78C2ULL,
		0x8DE299A49A0A79EFULL,
		0x3EF56D3B0B2AE2B8ULL,
		0xD3A7ABFBF8E14859ULL,
		0x3B504F6F335EA1A4ULL,
		0x2A951E309CD39AA6ULL,
		0xD5B9283460634192ULL,
		0x5493E5DD24275666ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F00AA1BA422CA10ULL,
		0x12D7FB3486DEDAD2ULL,
		0xF226F9FC51CAF829ULL,
		0x1538C5A97B995F78ULL,
		0x5CF3732EF6936C7FULL,
		0x2264EAA36BDFB33BULL,
		0x37BB17B391352A91ULL,
		0xF8820B3798059987ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1B1DB73B940A5B5ULL,
		0x2A1BCD995C697048ULL,
		0x19E7E42396A0C42DULL,
		0x1CAD0309DF41531CULL,
		0xFF48658E65A37F78ULL,
		0x51818D1EE31F08B0ULL,
		0xE053DAE8117101DBULL,
		0x3AA89200788542F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88CB63755AFC1B95ULL,
		0xB6A50E246A0302C6ULL,
		0x313EA8342322DE01ULL,
		0xC7121D44EA862C4EULL,
		0x9B5DE3D8EBB9D13AULL,
		0x73DF8789268DD1EDULL,
		0x9003C417423FDE4CULL,
		0xA0C35E4A0E8EACACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68E677FE5E448A20ULL,
		0x7376BF74F2666D82ULL,
		0xE8A93BEF737DE62BULL,
		0x559AE5C4F4BB26CDULL,
		0x63EA81B579E9AE3DULL,
		0xDDA20595BC9136C3ULL,
		0x505016D0CF31238EULL,
		0x99E533B669F69647ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44852F53F96FD1EAULL,
		0xE22587C9B0CB76C4ULL,
		0xC1DC3DA028323071ULL,
		0xA522B4F407654795ULL,
		0xCD864689E7751F9FULL,
		0xC70EC04177CFD006ULL,
		0xBF754E24568C5C9FULL,
		0x5FB450E2726878A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE76B7327FD7FBD3ULL,
		0xDA2A0096ACBBB75DULL,
		0x621B756F72CD8647ULL,
		0x6A0C3B809163E67BULL,
		0x5FBD3967407F68FDULL,
		0x0A901A84640C601BULL,
		0x259ED62F7956F574ULL,
		0x9392A65BA329C188ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x760E78217997D617ULL,
		0x07FB8733040FBF66ULL,
		0x5FC0C830B564AA2AULL,
		0x3B1679737601611AULL,
		0x6DC90D22A6F5B6A2ULL,
		0xBC7EA5BD13C36FEBULL,
		0x99D677F4DD35672BULL,
		0xCC21AA86CF3EB71FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0874C0DB0A980E80ULL,
		0x10A7C83C656F0A8DULL,
		0x17BF61BFDE65DC30ULL,
		0x3B13190F3BB3846EULL,
		0xC38FC9F2CC3A3C3EULL,
		0xF5B0D6324A616DC8ULL,
		0x073449E3969D7A54ULL,
		0x69E4F5BF4441D13BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E8FCC601460B355ULL,
		0x717C52AA41E2DE4FULL,
		0xAA5F27977E187BB2ULL,
		0x0F355DA3EC71CEE0ULL,
		0xE70B5957814017B4ULL,
		0xA47DB7C2FB1D0276ULL,
		0xC0E016391E353400ULL,
		0x39480F6075D0D0D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69E4F47AF6375B2BULL,
		0x9F2B7592238C2C3DULL,
		0x6D603A28604D607DULL,
		0x2BDDBB6B4F41B58DULL,
		0xDC84709B4AFA248AULL,
		0x51331E6F4F446B51ULL,
		0x465433AA78684654ULL,
		0x309CE65ECE710061ULL
	}};
	sign = 0;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F697C2D49C8518DULL,
		0x5A0BA2C2EA707A9CULL,
		0x1AC9308D995AF1B6ULL,
		0x4C87287C65D49F9EULL,
		0x505D9B024B9FDBD4ULL,
		0x74268E2FABCB351BULL,
		0x75EE787AB618EB22ULL,
		0x48AEFFF2BFE4912EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16481BC2F654C734ULL,
		0x127C6FC3E49CBA4FULL,
		0x5B8EC012EDDBD92DULL,
		0xCCCD5219661064A1ULL,
		0xB14F79D0E2AC5BA5ULL,
		0xB9FBA90DF53A75EAULL,
		0x4B616D5A6FD2FB57ULL,
		0xF67A91E4F9E5D852ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8921606A53738A59ULL,
		0x478F32FF05D3C04DULL,
		0xBF3A707AAB7F1889ULL,
		0x7FB9D662FFC43AFCULL,
		0x9F0E213168F3802EULL,
		0xBA2AE521B690BF30ULL,
		0x2A8D0B204645EFCAULL,
		0x52346E0DC5FEB8DCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5CBD532CB162780AULL,
		0x16842AE8161EED60ULL,
		0xA90A6646F2654C58ULL,
		0xC02D1869EE168BF6ULL,
		0xAD564A9E763BA1B0ULL,
		0x8053CFD4639792F6ULL,
		0x79E57B3A4071CBD2ULL,
		0xEF300CB808C73267ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x337E1CA7E1E6EB0AULL,
		0x2C3109F93B7EBDEEULL,
		0x21DAEFE7F56C3B74ULL,
		0xD131D02B9111519CULL,
		0x7CE61C04A8F670D2ULL,
		0xD5B97151932A08ABULL,
		0xEE7D1C4EC39B0C7BULL,
		0x8F6C298C73514C34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x293F3684CF7B8D00ULL,
		0xEA5320EEDAA02F72ULL,
		0x872F765EFCF910E3ULL,
		0xEEFB483E5D053A5AULL,
		0x30702E99CD4530DDULL,
		0xAA9A5E82D06D8A4BULL,
		0x8B685EEB7CD6BF56ULL,
		0x5FC3E32B9575E632ULL
	}};
	sign = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE440EA4E9B01DDE1ULL,
		0x0E66690B4D52E756ULL,
		0x6AFA85056D2E0344ULL,
		0x68D56A3CDF2911B5ULL,
		0x4E38A20EC18BDCCBULL,
		0x607A8B0EA4EB9077ULL,
		0x8371B8D9572C3C32ULL,
		0x658CF686CEA4866DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92825D2BC85C2126ULL,
		0x9547200BAC7A37FDULL,
		0xE3B857E7372B1CE1ULL,
		0x7FA0996FB498AA3FULL,
		0x6DB23E4405A2F5D1ULL,
		0x55E4B9153994D66CULL,
		0xB20CAB6CA200C49AULL,
		0x7C120A29B6A2585CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51BE8D22D2A5BCBBULL,
		0x791F48FFA0D8AF59ULL,
		0x87422D1E3602E662ULL,
		0xE934D0CD2A906775ULL,
		0xE08663CABBE8E6F9ULL,
		0x0A95D1F96B56BA0AULL,
		0xD1650D6CB52B7798ULL,
		0xE97AEC5D18022E10ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x335A3EE4CA4255A3ULL,
		0x871A8B53B49AE62EULL,
		0xD0FAC448E7D42F54ULL,
		0xFE0CD5BF457A0FBEULL,
		0x03A2CC140CC2544DULL,
		0xA5A7F0DC208094BCULL,
		0xA436319FBF1D7268ULL,
		0xFF1D8973DDF14385ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AACEAC1C5B5BA4DULL,
		0xC1E31D1AEC583F70ULL,
		0xEA83C09A2596F1BAULL,
		0xACD29A5CE50C97A7ULL,
		0x0587EC67A8CB3900ULL,
		0x34A2B51EE1E3CCC8ULL,
		0x9793ACA06B0B5E4BULL,
		0x296C78C215974AB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8AD5423048C9B56ULL,
		0xC5376E38C842A6BDULL,
		0xE67703AEC23D3D99ULL,
		0x513A3B62606D7816ULL,
		0xFE1ADFAC63F71B4DULL,
		0x71053BBD3E9CC7F3ULL,
		0x0CA284FF5412141DULL,
		0xD5B110B1C859F8D2ULL
	}};
	sign = 0;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D675B38F1611CB7ULL,
		0xDC5061AA2B8879A5ULL,
		0x95A61197201F27EEULL,
		0x379F8F707583C32BULL,
		0xE1A2F275E3FAE934ULL,
		0x6F7798C3F207A572ULL,
		0xAB18D46954496261ULL,
		0xCEEE9901665300EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x547CE4C0EF372CC1ULL,
		0x3A71A507F3936EF2ULL,
		0x5C715A70A28F8375ULL,
		0x267EA872A82208DBULL,
		0x426286B77828DE19ULL,
		0xF11C7C7C80D0FC6BULL,
		0x92F8ABEE00047135ULL,
		0xEADF026234D261BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8EA76780229EFF6ULL,
		0xA1DEBCA237F50AB2ULL,
		0x3934B7267D8FA479ULL,
		0x1120E6FDCD61BA50ULL,
		0x9F406BBE6BD20B1BULL,
		0x7E5B1C477136A907ULL,
		0x1820287B5444F12BULL,
		0xE40F969F31809F2FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0906912254B2D9F5ULL,
		0x0290E0685A6A5025ULL,
		0x6B582883AE5771E7ULL,
		0xC946D85737049321ULL,
		0xF15E8FE6B3BA5AD2ULL,
		0x1632CEAB57552B60ULL,
		0x16E0B73D27064F86ULL,
		0x69FFB6B80994DAECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EFD6EA99B284F06ULL,
		0x077260BFE44A2765ULL,
		0xC0426CB4CD46A349ULL,
		0xE741314D4A05AD96ULL,
		0x42239E9B898085F2ULL,
		0xEF3A406DC3C4DC54ULL,
		0xD74C9DD0212BC4F1ULL,
		0x54D0E75734C92493ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA092278B98A8AEFULL,
		0xFB1E7FA8762028BFULL,
		0xAB15BBCEE110CE9DULL,
		0xE205A709ECFEE58AULL,
		0xAF3AF14B2A39D4DFULL,
		0x26F88E3D93904F0CULL,
		0x3F94196D05DA8A94ULL,
		0x152ECF60D4CBB658ULL
	}};
	sign = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC9D1C16521E4898FULL,
		0xB159BDFF34F168BDULL,
		0x1F53AA6D45BEF26BULL,
		0x5C1D6C385A6EA427ULL,
		0x9AF6B1032B3A0774ULL,
		0x95CE529EE80FC71AULL,
		0xDDF372CB462C695AULL,
		0xCFE06A65D79B33ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2852698F2686CEULL,
		0x0FB1EC725E39E2C6ULL,
		0x193C380FF0FE0192ULL,
		0x4802941FF3E89CF9ULL,
		0x4ADA34002BB7A39DULL,
		0x7A2DBEB2ED80CE9DULL,
		0x9161938C69BA22AAULL,
		0xA114210ACC66F719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CA96EFB92BE02C1ULL,
		0xA1A7D18CD6B785F7ULL,
		0x0617725D54C0F0D9ULL,
		0x141AD8186686072EULL,
		0x501C7D02FF8263D7ULL,
		0x1BA093EBFA8EF87DULL,
		0x4C91DF3EDC7246B0ULL,
		0x2ECC495B0B343C94ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98CACFCEE36A975AULL,
		0x1017D67982B54DFFULL,
		0x18BDD7E2BE888D9DULL,
		0xE6DB15F6151B7679ULL,
		0xEEA87BD696A25385ULL,
		0x77D342EB94C7F3ABULL,
		0x00F3CD308258469AULL,
		0xC95ED83D66EBCE0CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C644E9F2B7281EULL,
		0xCD55664F0ECA61B6ULL,
		0x7CF25779E2C1D373ULL,
		0x6ECCB525BB34A60AULL,
		0xBD5C218A47BD9278ULL,
		0xBB158108842EFAB4ULL,
		0xF324D1E755C8AC56ULL,
		0x58C7D68AC200E34EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43048AE4F0B36F3CULL,
		0x42C2702A73EAEC49ULL,
		0x9BCB8068DBC6BA29ULL,
		0x780E60D059E6D06EULL,
		0x314C5A4C4EE4C10DULL,
		0xBCBDC1E31098F8F7ULL,
		0x0DCEFB492C8F9A43ULL,
		0x709701B2A4EAEABDULL
	}};
	sign = 0;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8947A18DB08D75ACULL,
		0x365549BB053A30C1ULL,
		0xFEDDA90ED10C8DC1ULL,
		0xC4E463ABC8848136ULL,
		0xA7B6E315703F8064ULL,
		0x83CF537C8CDB87C1ULL,
		0x32D78739791B20FCULL,
		0x29782AE993EE84EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CBAEA96EA826D59ULL,
		0x97E89580A12EF0B7ULL,
		0x0345C58A014B3695ULL,
		0x27303FF9CE481F1BULL,
		0x69B9AA0FB3DD3ADDULL,
		0x86B78D40F3C8ED32ULL,
		0x1D2BD0A3EA0D0531ULL,
		0xA5BA9A343AB5B0EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C8CB6F6C60B0853ULL,
		0x9E6CB43A640B400AULL,
		0xFB97E384CFC1572BULL,
		0x9DB423B1FA3C621BULL,
		0x3DFD3905BC624587ULL,
		0xFD17C63B99129A8FULL,
		0x15ABB6958F0E1BCAULL,
		0x83BD90B55938D402ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6B5D78154A07D13BULL,
		0x23C60D6015A24FA8ULL,
		0xACCEF9D1775E7A56ULL,
		0x618E8EEA630B7FF4ULL,
		0x4D78BCD7033E188BULL,
		0x077F2E419B85C60EULL,
		0xAD1083D002B5E599ULL,
		0xC603D0425EA3BD24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53699A753CCEE92DULL,
		0x21A753FEA2875733ULL,
		0x6209FA30BD7A0572ULL,
		0x89672D49FAA3A768ULL,
		0x354E626360F6FB91ULL,
		0x57AD906FA5DE0C36ULL,
		0x396FBE2D07AFCE5BULL,
		0xA3145418C62F3631ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17F3DDA00D38E80EULL,
		0x021EB961731AF875ULL,
		0x4AC4FFA0B9E474E4ULL,
		0xD82761A06867D88CULL,
		0x182A5A73A2471CF9ULL,
		0xAFD19DD1F5A7B9D8ULL,
		0x73A0C5A2FB06173DULL,
		0x22EF7C29987486F3ULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93CAA5F0851CE7D2ULL,
		0x40CF52CAF3A5D4F6ULL,
		0x2BB7EF4BE256125DULL,
		0x3EA0785D08239A7DULL,
		0x7A6982EBBA271114ULL,
		0x6923F607222CF6CAULL,
		0xB40DEE7A73E1E1B6ULL,
		0x2D1B3F156212FB96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x18156A5204A24C56ULL,
		0xEC066B120B495E1BULL,
		0x9C21A7CE519F24B7ULL,
		0xCA6B74A2A83DC323ULL,
		0x116A12B5E6C40E99ULL,
		0x73B5F0244E34E69BULL,
		0xF168F173BFD8775CULL,
		0xA3AAAB5B69925FC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BB53B9E807A9B7CULL,
		0x54C8E7B8E85C76DBULL,
		0x8F96477D90B6EDA5ULL,
		0x743503BA5FE5D759ULL,
		0x68FF7035D363027AULL,
		0xF56E05E2D3F8102FULL,
		0xC2A4FD06B4096A59ULL,
		0x897093B9F8809BCCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8EDF2D5CF377411ULL,
		0x427627343EF98074ULL,
		0x68568C664D741B54ULL,
		0xDAEBF5FAD4F393D6ULL,
		0xB461BE0DE0FFC9AEULL,
		0x4A2FBE7B331A9A4AULL,
		0xE2AF01D10240DB9CULL,
		0xC8CF3226243158BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5217B0E77F71E2ULL,
		0x9D79C92EA7765103ULL,
		0x0AB0A8A53CEFE345ULL,
		0x5242E617D2AD9475ULL,
		0xC75C0A68D40A240DULL,
		0x351A94A0CF0902BCULL,
		0xFFDE4E00FDDB92EDULL,
		0xCED230783C6DCF98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB9BDB24E7B8022FULL,
		0xA4FC5E0597832F70ULL,
		0x5DA5E3C11084380EULL,
		0x88A90FE30245FF61ULL,
		0xED05B3A50CF5A5A1ULL,
		0x151529DA6411978DULL,
		0xE2D0B3D0046548AFULL,
		0xF9FD01ADE7C38924ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x71A6D2EBEA2110F6ULL,
		0x8D7689ADFF7DBD9BULL,
		0x1FCF32D2B15F570DULL,
		0x4C4B4C2E1234F0A1ULL,
		0xC80DB21A2DCF4207ULL,
		0x9AD223E237CDD625ULL,
		0x52B63D6E37E10827ULL,
		0x872B9D234965C515ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF6BEE60B6D5D9D7ULL,
		0x20173D56FDC36B90ULL,
		0xB393AA96E658B8ECULL,
		0xC75B8E7D09817C4CULL,
		0xB27B427352B2AC51ULL,
		0xDF7F14DEACEA98DAULL,
		0xC91461CDCB041991ULL,
		0x87488CD3F269703DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x723AE48B334B371FULL,
		0x6D5F4C5701BA520AULL,
		0x6C3B883BCB069E21ULL,
		0x84EFBDB108B37454ULL,
		0x15926FA6DB1C95B5ULL,
		0xBB530F038AE33D4BULL,
		0x89A1DBA06CDCEE95ULL,
		0xFFE3104F56FC54D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0A09F3D1D1D237C2ULL,
		0xB02D61B874612D44ULL,
		0x8663956ED138842EULL,
		0x1CB63D56D42712B6ULL,
		0x4C093D3A7F17FF86ULL,
		0xAA14AC31BE71620AULL,
		0xE108A7E030405C81ULL,
		0x16B0ECD92EE8E171ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E6BDD9D22D33C27ULL,
		0xF3FB4FF81DC1860DULL,
		0xF9A302085C541D51ULL,
		0xDEC4F7C079F243C0ULL,
		0x76C23598E224E7B8ULL,
		0x6B54177E7E1F9EA1ULL,
		0xC582590A0DDE2205ULL,
		0xF7FBF06D692151C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB9E1634AEFEFB9BULL,
		0xBC3211C0569FA736ULL,
		0x8CC0936674E466DCULL,
		0x3DF145965A34CEF5ULL,
		0xD54707A19CF317CDULL,
		0x3EC094B34051C368ULL,
		0x1B864ED622623A7CULL,
		0x1EB4FC6BC5C78FB1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x476697F93EB2355CULL,
		0xD6D32DF8B1C2136EULL,
		0xE5B2F8A81980927AULL,
		0xB0CEEC7B3912FAB4ULL,
		0xC8886E090FB4EC51ULL,
		0xDC0288101B3627ADULL,
		0xFF26E4D474FFF6C2ULL,
		0x283BED4F7A26FCA6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20A0CEA36E060B6BULL,
		0x9A51CBE816460B88ULL,
		0x98AE8782FB6C73DEULL,
		0x6E26E06580A47762ULL,
		0x0634EAEE979E1572ULL,
		0x2F102030BDA1575BULL,
		0x04D7C67B248B3CCBULL,
		0xC433140BAFA80DCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26C5C955D0AC29F1ULL,
		0x3C8162109B7C07E6ULL,
		0x4D0471251E141E9CULL,
		0x42A80C15B86E8352ULL,
		0xC253831A7816D6DFULL,
		0xACF267DF5D94D052ULL,
		0xFA4F1E595074B9F7ULL,
		0x6408D943CA7EEED8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x87E4067F555EC737ULL,
		0xA16939FF5A0522B2ULL,
		0xFEF3830BAC5C12DDULL,
		0x27CCD708491A1C79ULL,
		0x528634EF764A5A77ULL,
		0x87CE09586771FB4FULL,
		0x050C197895873AC3ULL,
		0xBC5FE61925E0C50DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEC1550AC1BB7B2ULL,
		0x05601006127DB2DAULL,
		0x611779968CBD6266ULL,
		0xCE6732B151AFC49FULL,
		0xDC35386B92A53235ULL,
		0xE98FE06251288243ULL,
		0x24C7A1C35EEA404FULL,
		0x6751E957098EBEAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67F7F12EA9430F85ULL,
		0x9C0929F947876FD8ULL,
		0x9DDC09751F9EB077ULL,
		0x5965A456F76A57DAULL,
		0x7650FC83E3A52841ULL,
		0x9E3E28F61649790BULL,
		0xE04477B5369CFA73ULL,
		0x550DFCC21C52065DULL
	}};
	sign = 0;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0933EAFCE6EC4D27ULL,
		0x1D66A85A594B182FULL,
		0xADDAE2C62946F850ULL,
		0x6290801554644EC8ULL,
		0xBA2B26BCFE8D5415ULL,
		0x3F7A0E96E1E921F9ULL,
		0x305D3A8F777DBD32ULL,
		0xB116D5C3EAAAF108ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A549279143AEE9CULL,
		0x1F87D07D5C7CA5DBULL,
		0x5C0EEBF763F1A6B7ULL,
		0x913FB96BEEB9EAA8ULL,
		0xF46ED46957BACF72ULL,
		0xB6B8D848F1577733ULL,
		0x11FABBD610EAA774ULL,
		0x1F93864118A3E579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEDF5883D2B15E8BULL,
		0xFDDED7DCFCCE7253ULL,
		0x51CBF6CEC5555198ULL,
		0xD150C6A965AA6420ULL,
		0xC5BC5253A6D284A2ULL,
		0x88C1364DF091AAC5ULL,
		0x1E627EB9669315BDULL,
		0x91834F82D2070B8FULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC2727FCC57CB74E7ULL,
		0x1B15BB7484678D42ULL,
		0xDA07CC293736377BULL,
		0xF6859783FEF44B04ULL,
		0xBC819FBB807046FDULL,
		0xEF7D26AAFEA0D862ULL,
		0x0A98CAA0921AB875ULL,
		0x35C04BA68401BFBBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD0F91E3EA9EAF2EULL,
		0x56247889C0B45E97ULL,
		0x7A75253B509C2B5BULL,
		0xCDFA5546480061CDULL,
		0xA94578C764D50E4EULL,
		0x44029AFF3ABB859EULL,
		0xB80DC44B447B3E04ULL,
		0x75556B2552B96F69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE562EDE86D2CC5B9ULL,
		0xC4F142EAC3B32EAAULL,
		0x5F92A6EDE69A0C1FULL,
		0x288B423DB6F3E937ULL,
		0x133C26F41B9B38AFULL,
		0xAB7A8BABC3E552C4ULL,
		0x528B06554D9F7A71ULL,
		0xC06AE08131485051ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7239ABDA2A0D5974ULL,
		0x40D972D9C13AADF1ULL,
		0xF4A07B33D7C5D2E2ULL,
		0x453648FC66B78B0CULL,
		0x677412F218BA2719ULL,
		0x88611B10A4363B14ULL,
		0x6F63FC3C218B719AULL,
		0x3CD80EE09623C5E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x797BB3843BDC676EULL,
		0x7757E87C523BD7D1ULL,
		0xAF75B6C267119708ULL,
		0xC7EB43557B102B91ULL,
		0x96836ED615D137B5ULL,
		0x49AD251424720EFDULL,
		0xAE41D23B690AD923ULL,
		0xA0DAEFCB8F346901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8BDF855EE30F206ULL,
		0xC9818A5D6EFED61FULL,
		0x452AC47170B43BD9ULL,
		0x7D4B05A6EBA75F7BULL,
		0xD0F0A41C02E8EF63ULL,
		0x3EB3F5FC7FC42C16ULL,
		0xC1222A00B8809877ULL,
		0x9BFD1F1506EF5CE5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x67EC46EA6CD41AAAULL,
		0x0B3017A8EC5302E2ULL,
		0xFE483A28D60B3D80ULL,
		0x95C63CD9ED20F246ULL,
		0xCD03803DE0FFB814ULL,
		0x5CF486CF517A914CULL,
		0x3B36FA8D346DBE42ULL,
		0x12E7A8104AAD8EADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42DA32B36075C1E5ULL,
		0x84F8C6AC2E8E7D6AULL,
		0xFBF6E4E12B5A6DB3ULL,
		0xB179257D67CBC44FULL,
		0xB2C68529551DE4B6ULL,
		0x73283B2C98A99992ULL,
		0x3357F59EE70C05EEULL,
		0x283C544F2029DCEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x251214370C5E58C5ULL,
		0x863750FCBDC48578ULL,
		0x02515547AAB0CFCCULL,
		0xE44D175C85552DF7ULL,
		0x1A3CFB148BE1D35DULL,
		0xE9CC4BA2B8D0F7BAULL,
		0x07DF04EE4D61B853ULL,
		0xEAAB53C12A83B1BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA80F7F10DD3E7FEFULL,
		0x22DBCEEDAF69E675ULL,
		0xBA624916EA5ABCFDULL,
		0xDE3FF7E8408C70CCULL,
		0xEB19102B55AB9ED4ULL,
		0xECB976B57AB79BAFULL,
		0x08E3947BE84C1E23ULL,
		0xDABA8DDF07C7CDF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA354D9A281E08AULL,
		0x7246556B38E080A9ULL,
		0xD3A1042567EA31B6ULL,
		0xD13938DC693030B2ULL,
		0x4EC7AFC4E167B155ULL,
		0xC2C0A6AF51F086A4ULL,
		0xD12EED8FEF70D195ULL,
		0x92C910B9BEC964A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C6C2A373ABC9F65ULL,
		0xB0957982768965CCULL,
		0xE6C144F182708B46ULL,
		0x0D06BF0BD75C4019ULL,
		0x9C5160667443ED7FULL,
		0x29F8D00628C7150BULL,
		0x37B4A6EBF8DB4C8EULL,
		0x47F17D2548FE6954ULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4D2A6D1A3E2EA694ULL,
		0x545D05307DC64ED8ULL,
		0xE6F11D0795884183ULL,
		0x1008A4AF12BD0259ULL,
		0xF51DE7C7EB5C97CDULL,
		0x8E49826977C8872CULL,
		0xBAB69FBD200D46C9ULL,
		0x84555F383D7455EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE876DD9EEC15C0ULL,
		0x5D4A2A7FCB71111DULL,
		0x041074ABF513F8D2ULL,
		0x2DAC6D33A4335C34ULL,
		0x1CFD28DBF93D726FULL,
		0xF1B9910E122827A7ULL,
		0xD77DB347EE20E8E0ULL,
		0x71B94C5FC352E0DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6041F63C9F4290D4ULL,
		0xF712DAB0B2553DBAULL,
		0xE2E0A85BA07448B0ULL,
		0xE25C377B6E89A625ULL,
		0xD820BEEBF21F255DULL,
		0x9C8FF15B65A05F85ULL,
		0xE338EC7531EC5DE8ULL,
		0x129C12D87A217513ULL
	}};
	sign = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB6771D08D9FB587CULL,
		0xD384D39D4AC334D3ULL,
		0x5BE2D04ECC32434EULL,
		0xE51976900AF0519AULL,
		0x42FA52C5E7A2DFCBULL,
		0x87ABC1CB5E1D864AULL,
		0xE41A4926B7C11789ULL,
		0x186246E3A6C9B786ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3388305ABEFAF755ULL,
		0x244643FC98CA6A7FULL,
		0x81E574058DFB8127ULL,
		0x65590EE19BCE9AFAULL,
		0x11F8BFC42C4131BDULL,
		0xD0C710F304B474D6ULL,
		0x5273F1E05ED83019ULL,
		0xA08D270FB58BD470ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82EEECAE1B006127ULL,
		0xAF3E8FA0B1F8CA54ULL,
		0xD9FD5C493E36C227ULL,
		0x7FC067AE6F21B69FULL,
		0x31019301BB61AE0EULL,
		0xB6E4B0D859691174ULL,
		0x91A6574658E8E76FULL,
		0x77D51FD3F13DE316ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x997C5469467C1091ULL,
		0x0F67CBA3306A32A8ULL,
		0x7FD67FFAD813FA60ULL,
		0x3770EF8D40306AF2ULL,
		0x3A19830FA97581A7ULL,
		0x0CB0CA9E89B93E0DULL,
		0x41C5DB99E6D67168ULL,
		0x7633E19F8B6FCBD6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B04AE46766BD31ULL,
		0xCF08C2ADC85BCD4FULL,
		0x3C5F62360CE56963ULL,
		0x2BCCACDDD1852776ULL,
		0x17EB918C3E78B324ULL,
		0xDDDA2A93EAF6F6DFULL,
		0x38B19475912E6EE7ULL,
		0x01F869B620865153ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27CC0984DF155360ULL,
		0x405F08F5680E6559ULL,
		0x43771DC4CB2E90FCULL,
		0x0BA442AF6EAB437CULL,
		0x222DF1836AFCCE83ULL,
		0x2ED6A00A9EC2472EULL,
		0x0914472455A80280ULL,
		0x743B77E96AE97A83ULL
	}};
	sign = 0;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB5B762B773065B0FULL,
		0xB25BEDE8E8E52A91ULL,
		0x0692A856C6518172ULL,
		0xE5D19242163C64C1ULL,
		0x4C64E906EACFA2CCULL,
		0x3B671DA226D87A00ULL,
		0x7C32CF41C8D39107ULL,
		0x484A298418BD9270ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x005665781D7C2B61ULL,
		0xF76B19EA8B16F03CULL,
		0x832C3901FEB6B567ULL,
		0x14DC0C557E74061EULL,
		0xAD85CAB655C9EE05ULL,
		0xD408E5D375087729ULL,
		0xC7FC038256ABCA77ULL,
		0x6FCC710FF63E71D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB560FD3F558A2FAEULL,
		0xBAF0D3FE5DCE3A55ULL,
		0x83666F54C79ACC0AULL,
		0xD0F585EC97C85EA2ULL,
		0x9EDF1E509505B4C7ULL,
		0x675E37CEB1D002D6ULL,
		0xB436CBBF7227C68FULL,
		0xD87DB874227F209CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03DC9C8231241D0AULL,
		0x6695D31750242A08ULL,
		0x4C4734E5792C7B04ULL,
		0x93C621E27556FEB4ULL,
		0x994ECBE05647B043ULL,
		0xB46633FAE7CEC01AULL,
		0xD770FB556C37B1AAULL,
		0xD824728AE6614161ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EFCE41923A772C5ULL,
		0x66B240B7FDE36B73ULL,
		0xB3919BE59E5410D3ULL,
		0x8072C48DE4161CF3ULL,
		0x30B1A3B584DB9A76ULL,
		0x0E66CC39C522F418ULL,
		0x7AF87FF3B6105CA0ULL,
		0xFDFF1A141E6A596BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74DFB8690D7CAA45ULL,
		0xFFE3925F5240BE94ULL,
		0x98B598FFDAD86A30ULL,
		0x13535D549140E1C0ULL,
		0x689D282AD16C15CDULL,
		0xA5FF67C122ABCC02ULL,
		0x5C787B61B627550AULL,
		0xDA255876C7F6E7F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD518D52E879F8C1DULL,
		0xFF0869CB094557E3ULL,
		0x4FDF5AC051E79101ULL,
		0x19E95389565BB374ULL,
		0xBCFDC18F95D81E17ULL,
		0x85998C2FD87B06A3ULL,
		0xCC660142E5AE24FCULL,
		0x14DD54E7E125DCDCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83368BABFB431627ULL,
		0x8AD352DA44594981ULL,
		0xA3515F0BE29DA304ULL,
		0x871D81BD241F68B5ULL,
		0x3D6C1D2BD3B7D3CFULL,
		0x61BF0ED110C81217ULL,
		0x9B111F27120C0A9DULL,
		0x0DBBB9DAD27D7ECCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51E249828C5C75F6ULL,
		0x743516F0C4EC0E62ULL,
		0xAC8DFBB46F49EDFDULL,
		0x92CBD1CC323C4ABEULL,
		0x7F91A463C2204A47ULL,
		0x23DA7D5EC7B2F48CULL,
		0x3154E21BD3A21A5FULL,
		0x07219B0D0EA85E10ULL
	}};
	sign = 0;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x574A247DED188EC1ULL,
		0x5D04FAC050557111ULL,
		0x502F594E256A9C62ULL,
		0xB8C12C50277D6806ULL,
		0x99DBB3CFADEB5EDAULL,
		0x846CBF37C821A180ULL,
		0xCE617BB4976FE568ULL,
		0xEBE62687AE915FEBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38BB9B2022DD2A1AULL,
		0xB25DD8FCBD5EEAF8ULL,
		0x0B4865419A5666F1ULL,
		0x1007DAB805584565ULL,
		0x570725CDCDFC5ACEULL,
		0x81141A94D6B01470ULL,
		0x3F7D1DC548A8DFD0ULL,
		0x718D8196A686776CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E8E895DCA3B64A7ULL,
		0xAAA721C392F68619ULL,
		0x44E6F40C8B143570ULL,
		0xA8B95198222522A1ULL,
		0x42D48E01DFEF040CULL,
		0x0358A4A2F1718D10ULL,
		0x8EE45DEF4EC70598ULL,
		0x7A58A4F1080AE87FULL
	}};
	sign = 0;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7D1239B93FDEFE7ULL,
		0x04FDF7CAF2C6994EULL,
		0x54C0529D62E4F084ULL,
		0x60B92A13774FEEE7ULL,
		0x93593AC06A820B22ULL,
		0xA62C77C8BA4F9441ULL,
		0x526695ADD0105D30ULL,
		0x9B55300B7B70B20AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0770531C7037EDULL,
		0xE464ADAB8C8DCECFULL,
		0xC429ECD0254F1545ULL,
		0xC2983D5B3D0D796AULL,
		0xEFA8A765CCAE5100ULL,
		0x4152E3EEBD736E02ULL,
		0xA1EAFF1195627BF6ULL,
		0xC62D412548EFEA73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9C9B348778DB7FAULL,
		0x20994A1F6638CA7EULL,
		0x909665CD3D95DB3EULL,
		0x9E20ECB83A42757CULL,
		0xA3B0935A9DD3BA21ULL,
		0x64D993D9FCDC263EULL,
		0xB07B969C3AADE13AULL,
		0xD527EEE63280C796ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3AFF05F97E8257AFULL,
		0x9BCD54E7FB0253B3ULL,
		0x08089881F3A004EDULL,
		0x82C04824E5B11D98ULL,
		0x6B872B272FDBB6D8ULL,
		0x46FB7C458349198FULL,
		0x7569B683F5376FC4ULL,
		0xF0526067ED812526ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x807C6FE42580AC08ULL,
		0x30FC24F91C2E2F85ULL,
		0xD76488EEF3054E63ULL,
		0x13D8A968D9231A1FULL,
		0xDAF2C5D55F706491ULL,
		0xF3C2A97AC52BE11AULL,
		0x4B495220CB4DC1DCULL,
		0x5AC19F697E0940E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA8296155901ABA7ULL,
		0x6AD12FEEDED4242DULL,
		0x30A40F93009AB68AULL,
		0x6EE79EBC0C8E0378ULL,
		0x90946551D06B5247ULL,
		0x5338D2CABE1D3874ULL,
		0x2A20646329E9ADE7ULL,
		0x9590C0FE6F77E446ULL
	}};
	sign = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE81D7D310C36659AULL,
		0x479069CBF9DDE8DBULL,
		0x67D84F9BF1AA6AF6ULL,
		0x29EE40C25759A7F9ULL,
		0xDA5F73620615A674ULL,
		0xDE6C4DFDF52FEC77ULL,
		0x1EC9704758184012ULL,
		0x557F5E256FE9DFD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DE9A16F86FF74DULL,
		0xAA517F7105377B83ULL,
		0xA5FA3DD21E6726E8ULL,
		0x3D990CFD765A8810ULL,
		0x270EA5DB9252E57FULL,
		0x1D6B9766D8457A47ULL,
		0xDEDA1F4CB9EDAF79ULL,
		0x9F893159EC2083A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA33EE31A13C66E4DULL,
		0x9D3EEA5AF4A66D58ULL,
		0xC1DE11C9D343440DULL,
		0xEC5533C4E0FF1FE8ULL,
		0xB350CD8673C2C0F4ULL,
		0xC100B6971CEA7230ULL,
		0x3FEF50FA9E2A9099ULL,
		0xB5F62CCB83C95C28ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C4592C5BB3C4CADULL,
		0xAE8687D0C87AB0EEULL,
		0x2F792BD078D524ABULL,
		0x7312102CBF344379ULL,
		0x54F5B14C4C5BEAFBULL,
		0xF8E4344BC487AF64ULL,
		0x9121623638E14455ULL,
		0x471BEF03F1B75FF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2B5A199402B8786ULL,
		0xE205FD9270F09B9BULL,
		0x5E35B662B029BBB7ULL,
		0x86C652C171D1DADAULL,
		0xE1426CF119892EADULL,
		0x1BCBFFE3D9EFBD7BULL,
		0x811425C10AA37217ULL,
		0xF62ED5AEFF80FC4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x998FF12C7B10C527ULL,
		0xCC808A3E578A1552ULL,
		0xD143756DC8AB68F3ULL,
		0xEC4BBD6B4D62689EULL,
		0x73B3445B32D2BC4DULL,
		0xDD183467EA97F1E8ULL,
		0x100D3C752E3DD23EULL,
		0x50ED1954F23663A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x947FFB338D8D9543ULL,
		0x47F3C9CBE08C69FFULL,
		0xB26071C696F16670ULL,
		0x7C65EE21AFFA7659ULL,
		0x85BBE37F05C988B0ULL,
		0x6F5C2AE487E1D52BULL,
		0x4B89449821737962ULL,
		0x6423DFF43667F0F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C30D6E9E8FB00AULL,
		0x0D133958D8D34DE7ULL,
		0x2F1581D1CB101299ULL,
		0x0AA82044AB3F5229ULL,
		0xF2D60F41E104C115ULL,
		0x36504F95BEFA703CULL,
		0x000CA0F6B36FA413ULL,
		0xD50A0FA67011DA5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCBCEDC4EEFDE539ULL,
		0x3AE0907307B91C17ULL,
		0x834AEFF4CBE153D7ULL,
		0x71BDCDDD04BB2430ULL,
		0x92E5D43D24C4C79BULL,
		0x390BDB4EC8E764EEULL,
		0x4B7CA3A16E03D54FULL,
		0x8F19D04DC6561695ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE9B7D9624AB96A69ULL,
		0x31B6B5B596442DB0ULL,
		0x7984DD4452D4A7A4ULL,
		0x12DB82161D4E0D22ULL,
		0xCCB51CDC6E3C4EACULL,
		0x9E6485884B21092EULL,
		0xCCC9C64BF2792BD2ULL,
		0xED4907BD0BBA0DAEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x010BBED882EA8CB8ULL,
		0x72EF7AC1A13FE4B9ULL,
		0xA0CBE39423F16731ULL,
		0x4C40926DE693ECA7ULL,
		0x4A043B835157655FULL,
		0xDA5F790B7A2D7030ULL,
		0x0DA598D2B750376AULL,
		0x8768CA78B99D6E70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8AC1A89C7CEDDB1ULL,
		0xBEC73AF3F50448F7ULL,
		0xD8B8F9B02EE34072ULL,
		0xC69AEFA836BA207AULL,
		0x82B0E1591CE4E94CULL,
		0xC4050C7CD0F398FEULL,
		0xBF242D793B28F467ULL,
		0x65E03D44521C9F3EULL
	}};
	sign = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF05780434A1148E2ULL,
		0xCC3A1402E0A42923ULL,
		0x14D0EE1CA39D01DCULL,
		0xF100B472CB94DB92ULL,
		0x26E3F8B8E1577861ULL,
		0x8C0E9417DA765C07ULL,
		0x53FC9D658DD6D1A2ULL,
		0xC8EF56F1B03B9428ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36501A4B20E23257ULL,
		0xEF16A044A7EC215EULL,
		0x1F04E8B10C054594ULL,
		0x675DF648BCEDA8EDULL,
		0x1623617BE6CA5F86ULL,
		0xF3CDB2135E0AD5AEULL,
		0x73F8B31110D714E4ULL,
		0x8B320C6CFCC8A0E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA0765F8292F168BULL,
		0xDD2373BE38B807C5ULL,
		0xF5CC056B9797BC47ULL,
		0x89A2BE2A0EA732A4ULL,
		0x10C0973CFA8D18DBULL,
		0x9840E2047C6B8659ULL,
		0xE003EA547CFFBCBDULL,
		0x3DBD4A84B372F343ULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A89AA0D487CD4D9ULL,
		0x1134CAF870E709AAULL,
		0x2D0BAE8E30AEF26DULL,
		0x011C937DAFD1C0DCULL,
		0x207C4526EA0E7654ULL,
		0xC7D5838480D4DF48ULL,
		0x2B1BDF72FF7B1C78ULL,
		0x794B6828F5434EDBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D5CE149F797EB2ULL,
		0xC37B596F138BF034ULL,
		0xDE89A3E6E1FBAA3DULL,
		0x7466D954F8B53FCEULL,
		0x6893A00CE06CB913ULL,
		0x49866C355C3A9F1EULL,
		0xA9EC667479B23DAFULL,
		0x36B1424B371AE33FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42B3DBF8A9035627ULL,
		0x4DB971895D5B1976ULL,
		0x4E820AA74EB3482FULL,
		0x8CB5BA28B71C810DULL,
		0xB7E8A51A09A1BD40ULL,
		0x7E4F174F249A4029ULL,
		0x812F78FE85C8DEC9ULL,
		0x429A25DDBE286B9BULL
	}};
	sign = 0;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA3C0B8DA434C6787ULL,
		0xA3975A4653F43FD4ULL,
		0xB827EA79D47F7D23ULL,
		0x1EF277F7CB661216ULL,
		0xB3C9F43594C1978AULL,
		0xEED853F6C1428EFEULL,
		0xC3235934F377EF86ULL,
		0x365F8AD4FBBBDA87ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02DB2954FBCEE682ULL,
		0xA0E4BD8A394915F0ULL,
		0xC7F7FA26E0F5A292ULL,
		0xDF9ABB3D7B433ECEULL,
		0x39ACF410906845A0ULL,
		0x352CF9F626E68294ULL,
		0xAFFAED7A36524E37ULL,
		0x0A8AFB29B347AFB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0E58F85477D8105ULL,
		0x02B29CBC1AAB29E4ULL,
		0xF02FF052F389DA91ULL,
		0x3F57BCBA5022D347ULL,
		0x7A1D0025045951E9ULL,
		0xB9AB5A009A5C0C6AULL,
		0x13286BBABD25A14FULL,
		0x2BD48FAB48742AD7ULL
	}};
	sign = 0;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x97356172C2C95E59ULL,
		0xFFE0CE98B75E07C7ULL,
		0x3AECB0B143C376DCULL,
		0x3D94AE849066B663ULL,
		0x9335CA33A617F323ULL,
		0x1CE673C589BFA5A0ULL,
		0x039FE8B12BF47F65ULL,
		0x606BBA359D4D2F44ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x412C023785F8D821ULL,
		0xFCE961255AF52039ULL,
		0x67E4A227135D5D72ULL,
		0xC270B9FF94E3C50CULL,
		0x5A427B135B8CBB51ULL,
		0x6231199B07ABDEF5ULL,
		0xBE227F6026362F67ULL,
		0x5D3DE6C1AF7ACE89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56095F3B3CD08638ULL,
		0x02F76D735C68E78EULL,
		0xD3080E8A3066196AULL,
		0x7B23F484FB82F156ULL,
		0x38F34F204A8B37D1ULL,
		0xBAB55A2A8213C6ABULL,
		0x457D695105BE4FFDULL,
		0x032DD373EDD260BAULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8647D8183C2E50D5ULL,
		0x14AF912FA22559EFULL,
		0xAB78128D441FEAD5ULL,
		0xCA8A5455AC1DE2A8ULL,
		0x3932EC01677814A2ULL,
		0x3EE13AECCD0E0C9DULL,
		0xCA3EB8ACFB872E85ULL,
		0x5671CFB7A98BCBE7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF640123A4ED66CULL,
		0xD273F2D8EE8296D7ULL,
		0x488465C89AE5D9D0ULL,
		0x14A67A41F3C3487EULL,
		0x971F3029A596F93DULL,
		0x7183994387E866F3ULL,
		0xC24DA1596F612559ULL,
		0xBF001ACADD321049ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2751980601DF7A69ULL,
		0x423B9E56B3A2C318ULL,
		0x62F3ACC4A93A1104ULL,
		0xB5E3DA13B85A9A2AULL,
		0xA213BBD7C1E11B65ULL,
		0xCD5DA1A94525A5A9ULL,
		0x07F117538C26092BULL,
		0x9771B4ECCC59BB9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C77E3957AE02B7EULL,
		0xBCA9D3F84C1EEC6BULL,
		0xE3F6CABF2C3BBD2CULL,
		0x9D6BC02ED082D50FULL,
		0x5BB8F8957E0AA759ULL,
		0xF95480C14F1F5DC5ULL,
		0x636BEA32416D8B66ULL,
		0xCB4E4FBD19CFDD29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9188761F92DD69CDULL,
		0x7652F1C8B8A23F39ULL,
		0x78E44C5DD713471DULL,
		0x931AACC4457227FAULL,
		0x338CF604F025EF62ULL,
		0xB0B11E2922151D2FULL,
		0xC22C7C04EC57F300ULL,
		0xCEC282A47EB37C55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AEF6D75E802C1B1ULL,
		0x4656E22F937CAD31ULL,
		0x6B127E615528760FULL,
		0x0A51136A8B10AD15ULL,
		0x282C02908DE4B7F7ULL,
		0x48A362982D0A4096ULL,
		0xA13F6E2D55159866ULL,
		0xFC8BCD189B1C60D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB6FBF89A5CED997ULL,
		0xABC757106F58AC06ULL,
		0x32AB2C74D7465FF8ULL,
		0x53C42266885C3906ULL,
		0x78AA6937B6CFD8A5ULL,
		0x6739DCC0A6C6C1DEULL,
		0x4FDC1C9088A91039ULL,
		0x449137278A503A40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B76B440035D0BCFULL,
		0x0C16853710369931ULL,
		0x8D8B84268188D52CULL,
		0x6B39670EA7E21694ULL,
		0x2DBF73CADA473077ULL,
		0x8A33C46316B7DDA4ULL,
		0x8C6699327EF32A36ULL,
		0x2C7A345D6BE91679ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFF90B49A271CDC8ULL,
		0x9FB0D1D95F2212D5ULL,
		0xA51FA84E55BD8ACCULL,
		0xE88ABB57E07A2271ULL,
		0x4AEAF56CDC88A82DULL,
		0xDD06185D900EE43AULL,
		0xC375835E09B5E602ULL,
		0x181702CA1E6723C6ULL
	}};
	sign = 0;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x829A745806A2E520ULL,
		0x2CCA0356EDC9724FULL,
		0xCD21D4DE9F26E888ULL,
		0xB18E7E010EF8039EULL,
		0x550651A9C002E093ULL,
		0x2F7F7A5FD669E651ULL,
		0x783E3D524D49051EULL,
		0xEEF97EE81E41E195ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x478A02353BF5CF24ULL,
		0x942337C611184E32ULL,
		0x7852A3EB0F645ADDULL,
		0x1BA3CEE5B0F565D7ULL,
		0xEBE2248831BDFEE2ULL,
		0xD5A32769C6B7D32BULL,
		0x98492624BAB67A4EULL,
		0x5570713898974131ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B107222CAAD15FCULL,
		0x98A6CB90DCB1241DULL,
		0x54CF30F38FC28DAAULL,
		0x95EAAF1B5E029DC7ULL,
		0x69242D218E44E1B1ULL,
		0x59DC52F60FB21325ULL,
		0xDFF5172D92928ACFULL,
		0x99890DAF85AAA063ULL
	}};
	sign = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC4B96CD7720A8131ULL,
		0xDF3D1465C6A2233EULL,
		0x1E25B9178EF1F564ULL,
		0xEEAD51FBFD62E2BFULL,
		0x0BF78FE8B3366D15ULL,
		0xD294F72C6C8F2AF8ULL,
		0xDB70A4E196671257ULL,
		0x149BB2CE4C07BAAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1F929C1067307FULL,
		0xD65C468037068306ULL,
		0xF1F4C85484FFF319ULL,
		0x6E88F5D55AEF3A62ULL,
		0x733BABDC4B18D54FULL,
		0x4CB8A3081370C8C8ULL,
		0x0CB1CBB389E4D0ECULL,
		0xCC997A91EF799F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA699DA3B61A350B2ULL,
		0x08E0CDE58F9BA038ULL,
		0x2C30F0C309F2024BULL,
		0x80245C26A273A85CULL,
		0x98BBE40C681D97C6ULL,
		0x85DC5424591E622FULL,
		0xCEBED92E0C82416BULL,
		0x4802383C5C8E1B6CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8F0E939FEC83A922ULL,
		0x4268C663DCC3ACE9ULL,
		0x60FC0A142FF2904FULL,
		0x7D82F0C8948FD85EULL,
		0x70EF424511A0C2EAULL,
		0x9DFD99939FBC0016ULL,
		0x95483E8CA3AF0940ULL,
		0x588A42576299E14BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF177C1B6169714ULL,
		0x98B71FAF3E10E0B1ULL,
		0x400E6A86744C1C88ULL,
		0xB2FA92A72F630670ULL,
		0x54426155963D63D2ULL,
		0x48FDCEDCBCFD5699ULL,
		0x9E5A861DE2834EF4ULL,
		0x63AB40D6C06969A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF1D1BDE366D120EULL,
		0xA9B1A6B49EB2CC37ULL,
		0x20ED9F8DBBA673C6ULL,
		0xCA885E21652CD1EEULL,
		0x1CACE0EF7B635F17ULL,
		0x54FFCAB6E2BEA97DULL,
		0xF6EDB86EC12BBA4CULL,
		0xF4DF0180A23077A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB858D84B09588F24ULL,
		0xE048231C1124B693ULL,
		0x2A066C906BD9222CULL,
		0x72DF2FA9C9CC9F22ULL,
		0xBEA8B025CF7328FDULL,
		0x5D4AA213198CDBAAULL,
		0x51A875C2A4D6E3B5ULL,
		0xA6A1F11882B88965ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4D398424D94753ULL,
		0x75B0721DD36F5F2DULL,
		0x2D59C12B82B2DC2AULL,
		0x9FAAD82606DE39E1ULL,
		0xD09EF0A7519595A2ULL,
		0x89C3861894A1BBFAULL,
		0xA6AD568865E013FFULL,
		0x54E9528FCB5B1140ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D0B9EC6E47F47D1ULL,
		0x6A97B0FE3DB55766ULL,
		0xFCACAB64E9264602ULL,
		0xD3345783C2EE6540ULL,
		0xEE09BF7E7DDD935AULL,
		0xD3871BFA84EB1FAFULL,
		0xAAFB1F3A3EF6CFB5ULL,
		0x51B89E88B75D7824ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}