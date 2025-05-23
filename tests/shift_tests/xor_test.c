#include "../tests.h"

int32_t curve25519_key_xor_test(void) {
	printf("Key XOR Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xC2D0D074D3791322ULL,
		0x3CED0C0ECA61B422ULL,
		0x12297FD10FDC39A6ULL,
		0x1FBAF62074511728ULL,
		0x7F1B5D862AE751C9ULL,
		0xEAF6B172324B5C0AULL,
		0x5FB053A55D1FDD32ULL,
		0x6645EC97F958BF8CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x848F46A3BA9DCB6FULL,
		0x3BEB8CFDE5219E08ULL,
		0xD5EB5B7B8E2D59CCULL,
		0x5D0E6CC8C5D8633EULL,
		0x85B1E19D827FABCBULL,
		0x3C8600B744D78E2CULL,
		0xF63A8147CF6A87B4ULL,
		0xA7EA728C90710E22ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x465F96D769E4D84DULL,
		0x070680F32F402A2AULL,
		0xC7C224AA81F1606AULL,
		0x42B49AE8B1897416ULL,
		0xFAAABC1BA898FA02ULL,
		0xD670B1C5769CD226ULL,
		0xA98AD2E292755A86ULL,
		0xC1AF9E1B6929B1AEULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DF2E1D3891DAB19ULL,
		0x2784722F5D147B3AULL,
		0x568A273F4D2CFF23ULL,
		0xF010F04C1D1300DFULL,
		0x711509FA72CE685DULL,
		0xFF98D68AD7E06C3AULL,
		0x9E8538B08FBB9F10ULL,
		0xE75762C238AD8108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6247B35268940E1ULL,
		0x14383736240FA395ULL,
		0x6D1472D5E4789E29ULL,
		0x6FB30D9D5FC83231ULL,
		0xB3B9F00C090084BBULL,
		0x77CFB0839F736A33ULL,
		0x86C09E3B0F851AE2ULL,
		0xE27CB28860417C7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBD69AE6AF94EBF8ULL,
		0x33BC4519791BD8AFULL,
		0x3B9E55EAA954610AULL,
		0x9FA3FDD142DB32EEULL,
		0xC2ACF9F67BCEECE6ULL,
		0x8857660948930609ULL,
		0x1845A68B803E85F2ULL,
		0x052BD04A58ECFD73ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE26F6B884CD6D196ULL,
		0xB546074995584D72ULL,
		0x7CDBF5211BA26C05ULL,
		0x36AB85F5CD2665C1ULL,
		0x85F1E8841AE2A675ULL,
		0xFF295BBA627674F7ULL,
		0x7755B736A5D4ED42ULL,
		0xE3E1BC8A64436560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB740745B156E641FULL,
		0xEE4EDE512C22DE04ULL,
		0x90FC433425669601ULL,
		0x8D97E86960DAFF68ULL,
		0x792288F9A251D76FULL,
		0x15612246CB9F640BULL,
		0x2790F9236F3AD8C0ULL,
		0xE5D5C47114D519BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x552F1FD359B8B589ULL,
		0x5B08D918B97A9376ULL,
		0xEC27B6153EC4FA04ULL,
		0xBB3C6D9CADFC9AA9ULL,
		0xFCD3607DB8B3711AULL,
		0xEA4879FCA9E910FCULL,
		0x50C54E15CAEE3582ULL,
		0x063478FB70967CDEULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30555B8F832B4AF8ULL,
		0x116B2BE9BFAF22AAULL,
		0xC0947B941AC9F27EULL,
		0xE544F0F5AF37A32AULL,
		0x3776E1988C24F744ULL,
		0xAAE5C7562BACC59FULL,
		0x501939A848C280EAULL,
		0x818565DBE7B3963AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBB1DE3BAA5CABAEULL,
		0xE7033B5FC9520E80ULL,
		0x7B134CD5C9B76404ULL,
		0x7A6FE4F4470757A7ULL,
		0x4AFF4607B129F966ULL,
		0x62D76037A6D6EA3BULL,
		0x8C61275377F55E67ULL,
		0x91DEAC6C3CCE6F28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBE485B42977E156ULL,
		0xF66810B676FD2C2AULL,
		0xBB873741D37E967AULL,
		0x9F2B1401E830F48DULL,
		0x7D89A79F3D0D0E22ULL,
		0xC832A7618D7A2FA4ULL,
		0xDC781EFB3F37DE8DULL,
		0x105BC9B7DB7DF912ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84BEB8BFD906593CULL,
		0x828D4B583BD890CCULL,
		0x0629ED71F76AF126ULL,
		0x0884DD2EA1BB1A6BULL,
		0x4BE72979CA4BD74BULL,
		0x08E0CAA7EE321120ULL,
		0x3F4EDAFF0F10ED84ULL,
		0x0AF8F440AEA61397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF590F542EC0F3A8ULL,
		0xED22E547D329DCC8ULL,
		0xD957B0AA84394919ULL,
		0xF82D0C01B53E27F6ULL,
		0xBA4738F2CB468003ULL,
		0xC2BB0E00FA831540ULL,
		0x369B802985C760D1ULL,
		0x4AC1A18C8A2EB7E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BE7B7EBF7C6AA94ULL,
		0x6FAFAE1FE8F14C04ULL,
		0xDF7E5DDB7353B83FULL,
		0xF0A9D12F14853D9DULL,
		0xF1A0118B010D5748ULL,
		0xCA5BC4A714B10460ULL,
		0x09D55AD68AD78D55ULL,
		0x403955CC2488A471ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03F7DFB838C41ACCULL,
		0xEFF310BA74105AB3ULL,
		0xCC83EB784B973FDAULL,
		0xD2F07780709EA832ULL,
		0x235EBF9560698559ULL,
		0x4C46D516C509CD5DULL,
		0x833D027DFBD34CB2ULL,
		0xD9F0178883FA70EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19063EFCA91653A9ULL,
		0x1D48B8592F98BFD3ULL,
		0x7E66007948F14E4AULL,
		0xEB6DE69600DB5561ULL,
		0xDE5D1B71B4FDE6D7ULL,
		0xBB1B1F1BCA714B2CULL,
		0x6E71ED040BAABB9DULL,
		0x467BFC1F234228D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AF1E14491D24965ULL,
		0xF2BBA8E35B88E560ULL,
		0xB2E5EB0103667190ULL,
		0x399D91167045FD53ULL,
		0xFD03A4E4D494638EULL,
		0xF75DCA0D0F788671ULL,
		0xED4CEF79F079F72FULL,
		0x9F8BEB97A0B85836ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F0ABDE84693983DULL,
		0x4CD241C7542296ABULL,
		0x79F33AF6BC74595FULL,
		0x00765CD81129345FULL,
		0x85ABBEFEF6F619A2ULL,
		0x0D220ED545A9D11EULL,
		0x68A9EF33DBF32438ULL,
		0xCDEA3AFF050A3B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF83EA43405F80BCULL,
		0x874BAE0DE6BD7838ULL,
		0x134750A200DA2AA9ULL,
		0x2F9EFB018507FD04ULL,
		0x09A3171DC760E98FULL,
		0xBA5855476B0BFFE5ULL,
		0x642FD858450DC1F3ULL,
		0xC44D4E06ADC9A06DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x908957AB06CC1881ULL,
		0xCB99EFCAB29FEE93ULL,
		0x6AB46A54BCAE73F6ULL,
		0x2FE8A7D9942EC95BULL,
		0x8C08A9E33196F02DULL,
		0xB77A5B922EA22EFBULL,
		0x0C86376B9EFEE5CBULL,
		0x09A774F9A8C39B19ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x134300F8D50BFB4EULL,
		0x66D518E0EE2B3053ULL,
		0xE057524F5BB4F3E5ULL,
		0x1D1BD368C7077053ULL,
		0xCB2803B5347BCF6DULL,
		0x0D53A83A5B5A468DULL,
		0x8A1942A6F2B8E289ULL,
		0x4BDA1E41CCC43D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16098A441E70D562ULL,
		0x87B8A0FE2EFECA36ULL,
		0xC210EC55A651D880ULL,
		0x1ED4F45B62072D2CULL,
		0xE8E6778927F3E54AULL,
		0x7ED01BC884E5F536ULL,
		0x36620E617053A396ULL,
		0x98453A89E3C04684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x054A8ABCCB7B2E2CULL,
		0xE16DB81EC0D5FA65ULL,
		0x2247BE1AFDE52B65ULL,
		0x03CF2733A5005D7FULL,
		0x23CE743C13882A27ULL,
		0x7383B3F2DFBFB3BBULL,
		0xBC7B4CC782EB411FULL,
		0xD39F24C82F047BC8ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0315E9B8521CBF30ULL,
		0xB6940610F09596D9ULL,
		0xF88826EA46753E99ULL,
		0x2439377BBCEC8FC9ULL,
		0x36BE8DFBF2E2B91DULL,
		0xC967B369BF03D487ULL,
		0x3128D4A0AAA3D4D1ULL,
		0xB262041155357C78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5EF237DE58FF4BULL,
		0x03237AF8189F1537ULL,
		0xEF449BD95D9633BDULL,
		0x7D31C68866D4CB0EULL,
		0x6FB3E5C2C9753943ULL,
		0xD6B59E689D3AF497ULL,
		0x927DC6B8CC8C0C3EULL,
		0x440D787AEE96E4F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4B1B8F8C44407BULL,
		0xB5B77CE8E80A83EEULL,
		0x17CCBD331BE30D24ULL,
		0x5908F1F3DA3844C7ULL,
		0x590D68393B97805EULL,
		0x1FD22D0122392010ULL,
		0xA3551218662FD8EFULL,
		0xF66F7C6BBBA39888ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24A57DC7CA321D69ULL,
		0x4AC53C05E8369B58ULL,
		0x91A8AA4CBAEF1222ULL,
		0x14ADD08E0EFD5C3CULL,
		0xBF2F8B25E0CFAD7FULL,
		0xE100C2C7C071FDB8ULL,
		0xBFBFAD73EAC3B7C8ULL,
		0x63C22EDD20DB12DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C994C0BB72339EULL,
		0x1ABF8D939A484DA3ULL,
		0x6101AD571C7556F6ULL,
		0x1353B3C23B454491ULL,
		0x79027F03B11A4CADULL,
		0xC717EB5BC33C2AD5ULL,
		0xA55F3FCBC9F6835DULL,
		0x954EF6D309CCB626ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D6CE90771402EF7ULL,
		0x507AB196727ED6FBULL,
		0xF0A9071BA69A44D4ULL,
		0x07FE634C35B818ADULL,
		0xC62DF42651D5E1D2ULL,
		0x2617299C034DD76DULL,
		0x1AE092B823353495ULL,
		0xF68CD80E2917A4F9ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x099B245415C8D094ULL,
		0x977F77A22C170956ULL,
		0xB674240D309777D6ULL,
		0x9D5FEEFB222A7873ULL,
		0xD811E5FB385540D2ULL,
		0x94EF6BAA98C4EE06ULL,
		0xB5CFA39E42225563ULL,
		0x623E706132BC3AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A05B5D17A1EB68ULL,
		0x2EF64CC170859FDAULL,
		0x99C372ECAD63CF9AULL,
		0xFA2DC8A6858BF60DULL,
		0x895BC09D9CCE5230ULL,
		0x1F5681243F48B51CULL,
		0xAA547A3D00F61FA1ULL,
		0x03D9255D58E32978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x193B7F0902693BFCULL,
		0xB9893B635C92968CULL,
		0x2FB756E19DF4B84CULL,
		0x6772265DA7A18E7EULL,
		0x514A2566A49B12E2ULL,
		0x8BB9EA8EA78C5B1AULL,
		0x1F9BD9A342D44AC2ULL,
		0x61E7553C6A5F138FULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96E9694F10B7CFEEULL,
		0xBF296FA26DCF9DDAULL,
		0xF549162D44DF96FEULL,
		0x0E73D9B10C87D4D1ULL,
		0xD0FE64B3C124714EULL,
		0xDE2D06257C8E45F1ULL,
		0x166DDA62F387BF9FULL,
		0x58B658A20C2A2854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247B74DDDA7F84BDULL,
		0xA79111DBC1119A90ULL,
		0x5D5278960C79E7CEULL,
		0x81497D4BD026EB6EULL,
		0x352E821734953CB6ULL,
		0xB90164AC910B8596ULL,
		0x6796003BE7947B09ULL,
		0xA46C8D050BC51C30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2921D92CAC84B53ULL,
		0x18B87E79ACDE074AULL,
		0xA81B6EBB48A67130ULL,
		0x8F3AA4FADCA13FBFULL,
		0xE5D0E6A4F5B14DF8ULL,
		0x672C6289ED85C067ULL,
		0x71FBDA591413C496ULL,
		0xFCDAD5A707EF3464ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E381F7A34D7FCF0ULL,
		0xB1B8459E699ED516ULL,
		0xCE3A2E27D649977AULL,
		0x8261ACCBBC8A7730ULL,
		0xE10444565A924099ULL,
		0x6F8DFFACD9893605ULL,
		0x172FE44E5177EEA2ULL,
		0x70ADE5C56DA49475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB23363B1C5141BFFULL,
		0x23683447F6B8EFB7ULL,
		0x820C6C3FE73B371DULL,
		0xB592A9C087E1DC43ULL,
		0xFA22E8267906F893ULL,
		0xF71B84596E3C33E0ULL,
		0xBD806E271929C9D3ULL,
		0x37C15AE66E43A840ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C0B7CCBF1C3E70FULL,
		0x92D071D99F263AA1ULL,
		0x4C3642183172A067ULL,
		0x37F3050B3B6BAB73ULL,
		0x1B26AC702394B80AULL,
		0x98967BF5B7B505E5ULL,
		0xAAAF8A69485E2771ULL,
		0x476CBF2303E73C35ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE2B4173F84A2EFBULL,
		0x2D17C1EB642E6F4EULL,
		0x6C04B6EFE2B4F853ULL,
		0xD30D17F6B0880A77ULL,
		0x7E053B8AA7DE9095ULL,
		0x9C5755472A6E4CF9ULL,
		0x90C9FB0BE875A863ULL,
		0xA17DFABC43A8805EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77C2D452D5907CF2ULL,
		0x32F9355F7CBAF3B8ULL,
		0x111914FA390184ADULL,
		0xD86B62DAB0D10A34ULL,
		0xC533336C871E98AEULL,
		0x9A23156284FAB10FULL,
		0x5FBE2AD69C2E8F4AULL,
		0xA411ACBBD9D5A91DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99E995212DDA5209ULL,
		0x1FEEF4B418949CF6ULL,
		0x7D1DA215DBB57CFEULL,
		0x0B66752C00590043ULL,
		0xBB3608E620C0083BULL,
		0x06744025AE94FDF6ULL,
		0xCF77D1DD745B2729ULL,
		0x056C56079A7D2943ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03790D5AD3A03AF4ULL,
		0x0D4C8677447D4A6EULL,
		0xAF043FB7924B2F39ULL,
		0xE2BA8A77F3F202CDULL,
		0x6404060950FCF3F4ULL,
		0xEA27C21F4CCE08F5ULL,
		0x55E58587D6FE6AECULL,
		0xC37A981EF0E2B2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0917B3A60446FC15ULL,
		0xC9052377B038AFD0ULL,
		0xB672850FB290DCF0ULL,
		0xE594E4C55A1B7D38ULL,
		0x8E98929532F8938CULL,
		0x6F479D56355FDF2EULL,
		0xD9099BE057F0315FULL,
		0xB887609F8B95B6D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A6EBEFCD7E6C6E1ULL,
		0xC449A500F445E5BEULL,
		0x1976BAB820DBF3C9ULL,
		0x072E6EB2A9E97FF5ULL,
		0xEA9C949C62046078ULL,
		0x85605F497991D7DBULL,
		0x8CEC1E67810E5BB3ULL,
		0x7BFDF8817B770473ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF002C1A264207110ULL,
		0x4AE24284F3861F4EULL,
		0xD8850FCB32AE3019ULL,
		0x4318DA6003937325ULL,
		0x5455BC65E7CFDF9CULL,
		0x575D6460A9BE0059ULL,
		0x3E91013068B93F79ULL,
		0xCEDED8FF61FD21C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1980E431F2BAF365ULL,
		0x664A1240C1AA5BABULL,
		0xE5266CF0ACA1E34EULL,
		0x7E421DE0F186F08BULL,
		0x5F4949B8C08C293BULL,
		0x879DAF9F210D360EULL,
		0x5A77FF355C4D6571ULL,
		0x05FA9546F56D291EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9822593969A8275ULL,
		0x2CA850C4322C44E5ULL,
		0x3DA3633B9E0FD357ULL,
		0x3D5AC780F21583AEULL,
		0x0B1CF5DD2743F6A7ULL,
		0xD0C0CBFF88B33657ULL,
		0x64E6FE0534F45A08ULL,
		0xCB244DB9949008DCULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5183A43F0C17E2AEULL,
		0x36D207BE06B4946DULL,
		0xC2C04D8E437DA37BULL,
		0x9D6383B37D574712ULL,
		0x4AA6D121AB2CE06DULL,
		0x01E74C7E8C210DFFULL,
		0x1F0FC1659B690F37ULL,
		0x66073E6A723F2833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17D2522639DDB9F8ULL,
		0xEA4F99FA5ED476B0ULL,
		0x3B09E98EA20FE7D0ULL,
		0x0A06E85F1387B68BULL,
		0x5EF36241EC185AD0ULL,
		0x787C68430C4CDB42ULL,
		0x8F9CCA54E1442C65ULL,
		0xE5F5269287A7377EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4651F61935CA5B56ULL,
		0xDC9D9E445860E2DDULL,
		0xF9C9A400E17244ABULL,
		0x97656BEC6ED0F199ULL,
		0x1455B3604734BABDULL,
		0x799B243D806DD6BDULL,
		0x90930B317A2D2352ULL,
		0x83F218F8F5981F4DULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03603F71BCBDEDB7ULL,
		0x67BA2478F62E47B9ULL,
		0x8EA581247D6350B9ULL,
		0xF1B2445C701E5210ULL,
		0x2415E8D075D5298AULL,
		0x5D6814EFAD9489E9ULL,
		0xA213146178847B43ULL,
		0xDE2FEF6F090335BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA572C2341298FF90ULL,
		0x1C9895F1A3A12307ULL,
		0xD108EE82265E192BULL,
		0xC09A3EAD901B64CEULL,
		0x62771AF6B8C16CDFULL,
		0x251AA97EB1B6B02DULL,
		0xF0924C0C7673A06DULL,
		0x0252C7A958EE7F03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA612FD45AE251227ULL,
		0x7B22B189558F64BEULL,
		0x5FAD6FA65B3D4992ULL,
		0x31287AF1E00536DEULL,
		0x4662F226CD144555ULL,
		0x7872BD911C2239C4ULL,
		0x5281586D0EF7DB2EULL,
		0xDC7D28C651ED4ABCULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC0E522A0DFD39C3ULL,
		0x42B8F983FD4884EFULL,
		0xDA8D487710EED099ULL,
		0xBDA21CAD11EDBDA9ULL,
		0xC59F8FA24C4EA250ULL,
		0x0051404F823565F5ULL,
		0x88FA7514EFB0B125ULL,
		0x9E793269C91F8FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D188DE17614EB99ULL,
		0x54C43CC3F735293FULL,
		0x0CCEF1690275BF41ULL,
		0x265409F4089A7604ULL,
		0x46904FB089489F21ULL,
		0x143F583DC62C0282ULL,
		0x005DC1A1E34A88DDULL,
		0x2C9C2A9B6E2CC861ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5116DFCB7BE9D25AULL,
		0x167CC5400A7DADD0ULL,
		0xD643B91E129B6FD8ULL,
		0x9BF615591977CBADULL,
		0x830FC012C5063D71ULL,
		0x146E187244196777ULL,
		0x88A7B4B50CFA39F8ULL,
		0xB2E518F2A73347A2ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53ABACFC721D72CCULL,
		0x3D1505E8CC8CDBE2ULL,
		0xBFF82A98BFC18324ULL,
		0x732D40545E84132EULL,
		0xFF62CFC81D551CC3ULL,
		0xF0547310D842FBF5ULL,
		0xB3F0E58D38BFBB9AULL,
		0xDFF623FC398A3C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC073B1E64F9876ULL,
		0xEA7BEC05D9CE2347ULL,
		0x1C9F5D204969940AULL,
		0xDCDEC85C33EBEC49ULL,
		0xCD6042AFA319D55AULL,
		0x0D263DE1292A9AC9ULL,
		0x3FCC13F1726D0D18ULL,
		0x98F8BE0AD1D7E3A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E6BDF4D9452EABAULL,
		0xD76EE9ED1542F8A5ULL,
		0xA36777B8F6A8172EULL,
		0xAFF388086D6FFF67ULL,
		0x32028D67BE4CC999ULL,
		0xFD724EF1F168613CULL,
		0x8C3CF67C4AD2B682ULL,
		0x470E9DF6E85DDF2BULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCFB1F4E2AF84D70ULL,
		0xEB1FA6CDFCCD88E6ULL,
		0xF145A67975CB2582ULL,
		0x5B2C469F14FD67DDULL,
		0x5DC24FA062C84964ULL,
		0x2D1D24DB3FB94E90ULL,
		0xFE19E17B2B05B5A7ULL,
		0xBF03F9D8267D0BF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x786D8550777E6F38ULL,
		0xD8ABC4C195DCBBF3ULL,
		0x45DF3AEC872AF466ULL,
		0x52879DBB685C809BULL,
		0x9ADC899F5BFEC15CULL,
		0x941C7F912903A67FULL,
		0x38D63155EA67D371ULL,
		0x70206028B7D8031EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4969A1E5D862248ULL,
		0x33B4620C69113315ULL,
		0xB49A9C95F2E1D1E4ULL,
		0x09ABDB247CA1E746ULL,
		0xC71EC63F39368838ULL,
		0xB9015B4A16BAE8EFULL,
		0xC6CFD02EC16266D6ULL,
		0xCF2399F091A508E8ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7055A625E1EF1A9ULL,
		0x9FE117BFA709B961ULL,
		0xF766F1C05FDD4ABBULL,
		0x0B8F56F54E9EF4B2ULL,
		0xC2B8F1A8FD92FDE3ULL,
		0xF16437D36FF3239DULL,
		0xBFAEBED84D2E1346ULL,
		0xDDDAD4FD75F9506AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735DAF5E07165C72ULL,
		0x71BB1815065FB85BULL,
		0x6A9C477480029461ULL,
		0x84F745061EAFE772ULL,
		0xACFA6E353213E9A2ULL,
		0x6577C9B4CC1C409FULL,
		0x04E8717B3378705CULL,
		0xC049A05AF84CB364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA458F53C5908ADDBULL,
		0xEE5A0FAAA156013AULL,
		0x9DFAB6B4DFDFDEDAULL,
		0x8F7813F3503113C0ULL,
		0x6E429F9DCF811441ULL,
		0x9413FE67A3EF6302ULL,
		0xBB46CFA37E56631AULL,
		0x1D9374A78DB5E30EULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E35B43E34D3CC93ULL,
		0x4B3D617B3C6843C5ULL,
		0x9889F6EB163CAB68ULL,
		0x51D08BFB87050032ULL,
		0xD2620066B2905256ULL,
		0x63A3DE80CC72FAFCULL,
		0x64BEBD9C45C4D1A2ULL,
		0xCC6D7A9C4B84DCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B8EA7392D7E56CULL,
		0x2ED70F18A9851A30ULL,
		0xF26D5FA0E36B665AULL,
		0x0A0D44CA5C7CC456ULL,
		0xE4F01A2504A9C6B8ULL,
		0x29316EB9DC6B9A5DULL,
		0x610B84640B3EA3F2ULL,
		0xBF57716B99A4B305ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA8D5E4DA60429FFULL,
		0x65EA6E6395ED59F5ULL,
		0x6AE4A94BF557CD32ULL,
		0x5BDDCF31DB79C464ULL,
		0x36921A43B63994EEULL,
		0x4A92B039101960A1ULL,
		0x05B539F84EFA7250ULL,
		0x733A0BF7D2206FD1ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEECC1DD8E6FFED1ULL,
		0x8ED38422E59E29D0ULL,
		0x7EEE30C88611C9DAULL,
		0x2CD81B0476910610ULL,
		0xDEFD6FBF331BF7A4ULL,
		0x66BA16450875EF7EULL,
		0x1E823D9AD1CE451EULL,
		0x4265738A2669F019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BB569CCEBCED49DULL,
		0xA67010247AA00537ULL,
		0xBC0F230DA8074227ULL,
		0x8C299FBCDD6E9A75ULL,
		0xBA25A0B5CEDFFC72ULL,
		0x4035C3B29829AD5BULL,
		0x2A4716169D7AA47CULL,
		0x7E1A73BEAC451BB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD559A81165A12A4CULL,
		0x28A394069F3E2CE7ULL,
		0xC2E113C52E168BFDULL,
		0xA0F184B8ABFF9C65ULL,
		0x64D8CF0AFDC40BD6ULL,
		0x268FD5F7905C4225ULL,
		0x34C52B8C4CB4E162ULL,
		0x3C7F00348A2CEBABULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDE05A81BD584CEULL,
		0x27EE5AA801875149ULL,
		0x858087075991223BULL,
		0x1D14254D17ECA1E8ULL,
		0x3AE5AD5E4E5602E9ULL,
		0xC49ECD088A1CEC60ULL,
		0x38A54A1AB7049E5AULL,
		0xD4549200B9B26C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53764D3977DC6AB9ULL,
		0x5A8C16CA181D1AC0ULL,
		0xAACC8B5FA11AEE4BULL,
		0x518F6FF7EA6A119AULL,
		0xACF8B039CFD8375EULL,
		0xFD6E005E6350549CULL,
		0x4840771142027A7BULL,
		0x035BF8D1EDDFF6B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98A848916C09EE77ULL,
		0x7D624C62199A4B89ULL,
		0x2F4C0C58F88BCC70ULL,
		0x4C9B4ABAFD86B072ULL,
		0x961D1D67818E35B7ULL,
		0x39F0CD56E94CB8FCULL,
		0x70E53D0BF506E421ULL,
		0xD70F6AD1546D9ABBULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7980D54B1921B237ULL,
		0x66D290B34A1B3FB7ULL,
		0x13E8602CB118EBD6ULL,
		0x8D0DBF5C04B2E22EULL,
		0x7164A01A8F4F27BDULL,
		0xAC64BB21578AEB89ULL,
		0x748B9D17EFA35A61ULL,
		0x40E8CF36D8F6C0E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C6B0E4369F0118ULL,
		0x15E10D8CD873C31BULL,
		0x8B2B5E3BFC112366ULL,
		0x27DB81E58A443441ULL,
		0xF073B504B98476F1ULL,
		0x2A080F932CF59D9BULL,
		0x73F9EA257377094CULL,
		0xFB329B1F11691CEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684665AF2FBEB32FULL,
		0x73339D3F9268FCACULL,
		0x98C33E174D09C8B0ULL,
		0xAAD63EB98EF6D66FULL,
		0x8117151E36CB514CULL,
		0x866CB4B27B7F7612ULL,
		0x077277329CD4532DULL,
		0xBBDA5429C99FDC0CULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x380F38E2DB4C5574ULL,
		0x7E97616103F6B36EULL,
		0x54AC2288D5CC1B9CULL,
		0x2B812A9613849AF6ULL,
		0xE97F70CAEF231C1DULL,
		0x84402B97DD3F0278ULL,
		0xC44E89F0CA0683B1ULL,
		0x3E1E897D02E2403EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA60525974EB3FFULL,
		0xF7A5AE889789C409ULL,
		0x673E1DFBFA3DFFE3ULL,
		0x99B87DC7330739CDULL,
		0x518AE83CA2C1C281ULL,
		0x4D26A806A8945979ULL,
		0xE8C04584507CDDF8ULL,
		0x26184CFA6F2C2EF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4A93DC74C02E68BULL,
		0x8932CFE9947F7767ULL,
		0x33923F732FF1E47FULL,
		0xB23957512083A33BULL,
		0xB8F598F64DE2DE9CULL,
		0xC966839175AB5B01ULL,
		0x2C8ECC749A7A5E49ULL,
		0x1806C5876DCE6EC6ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AAF30B3CB939885ULL,
		0xAB7205D17F08837EULL,
		0xF167581A2A72958DULL,
		0xC56A07389434B970ULL,
		0x50E6BD1C0F070678ULL,
		0x8FAC183547D68BD6ULL,
		0x89464115D1C8E457ULL,
		0xC2D342801E9E573EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F20C9DF8EB474AEULL,
		0xEC4F9F7662F94375ULL,
		0xCCF6C1401C1BA029ULL,
		0x264D02E4CFA8637BULL,
		0x843637E2932D5A7AULL,
		0x980132DF7D07CF8AULL,
		0xBF965A008802D9DDULL,
		0xDD5CAF91C18F7EF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC58FF96C4527EC2BULL,
		0x473D9AA71DF1C00BULL,
		0x3D91995A366935A4ULL,
		0xE32705DC5B9CDA0BULL,
		0xD4D08AFE9C2A5C02ULL,
		0x17AD2AEA3AD1445CULL,
		0x36D01B1559CA3D8AULL,
		0x1F8FED11DF1129CFULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C1BF466C564D780ULL,
		0x9CFE323494B03D5DULL,
		0xF8A81E5D8618CB68ULL,
		0xC820AF4B0A7AAF3BULL,
		0xAF9FF15E22D3E773ULL,
		0xF4C38579AE492E6FULL,
		0x601F3A8CC2E7296CULL,
		0xE503A2B6A064EB6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C09B871702C24DULL,
		0x91CFE3C88A10AE1CULL,
		0x71534A99C475194EULL,
		0xB653D71A1CFCA0D6ULL,
		0xF7038782DB4D55BEULL,
		0xFFDC406D85B3EC9DULL,
		0x16DBE31AD92F4247ULL,
		0x910B06E10D07E1FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4DB6FE1D26615CDULL,
		0x0D31D1FC1EA09341ULL,
		0x89FB54C4426DD226ULL,
		0x7E73785116860FEDULL,
		0x589C76DCF99EB2CDULL,
		0x0B1FC5142BFAC2F2ULL,
		0x76C4D9961BC86B2BULL,
		0x7408A457AD630A91ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4F128DA67CD4F22ULL,
		0xBC06CBDAD426F896ULL,
		0xA9D8D389C85FE7A6ULL,
		0xCB49B48084EE19CDULL,
		0xDF42CAE7AE5F6E76ULL,
		0xD15C8F7CF7946AA5ULL,
		0xDBA9906046708B2CULL,
		0x7161CFF8D884F989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC4B5A42EBF3085ULL,
		0x96FDD0164F5FCE2EULL,
		0xFD2C2B2693235E14ULL,
		0xE732D1EFEB6C66E9ULL,
		0x2AEE45607538CA4AULL,
		0x8E409E3750CCF172ULL,
		0xC33192A7779CE0C8ULL,
		0x4DEC6506D9CD5F71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8359D7E49727FA7ULL,
		0x2AFB1BCC9B7936B8ULL,
		0x54F4F8AF5B7CB9B2ULL,
		0x2C7B656F6F827F24ULL,
		0xF5AC8F87DB67A43CULL,
		0x5F1C114BA7589BD7ULL,
		0x189802C731EC6BE4ULL,
		0x3C8DAAFE0149A6F8ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDA23F391254CA49ULL,
		0x8C1E3CAC7E26EAC0ULL,
		0xA2257F0077A078C0ULL,
		0xA1BE9A70937B8457ULL,
		0xD7F997E453040F5EULL,
		0x2C404FF510609E5BULL,
		0x178E27201FF75FA9ULL,
		0xCBD823F3B0A12C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE91DC7A8AC1A3B0ULL,
		0x1DB6AFEE84E9FA1DULL,
		0xADF0725209D94861ULL,
		0xC34BCCFEDF751F7AULL,
		0x2DC7BFB6C4D1347CULL,
		0x5FF1440627D9915EULL,
		0x446C0F2CCC050E81ULL,
		0x553292B6530A34B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3333E343989569F9ULL,
		0x91A89342FACF10DDULL,
		0x0FD50D527E7930A1ULL,
		0x62F5568E4C0E9B2DULL,
		0xFA3E285297D53B22ULL,
		0x73B10BF337B90F05ULL,
		0x53E2280CD3F25128ULL,
		0x9EEAB145E3AB182CULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BDAC63F4980E0C6ULL,
		0xC9ED76286785C406ULL,
		0xD17F73046A0ABFF5ULL,
		0x7AB7F6FB3FD34322ULL,
		0x956BF1EA8C2F428BULL,
		0xC922EE0B8FB79D93ULL,
		0x85DC70B0B4D1F7BCULL,
		0x2469C66A745A63FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D3746E668E7CEAULL,
		0x9DE8B940AFAEC406ULL,
		0x6B19FBC17856D42CULL,
		0x61490D48FE5D185EULL,
		0xB0606BA2C2018AA7ULL,
		0xF0BCD8384EBF7E95ULL,
		0x8C3AB88108FE28BAULL,
		0x79FE4D59667BA3ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC09B2512F0E9C2CULL,
		0x5405CF68C82B0000ULL,
		0xBA6688C5125C6BD9ULL,
		0x1BFEFBB3C18E5B7CULL,
		0x250B9A484E2EC82CULL,
		0x399E3633C108E306ULL,
		0x09E6C831BC2FDF06ULL,
		0x5D978B331221C013ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF386A0965DEB6A8ULL,
		0x09C5F0EE98C0C539ULL,
		0x33BD93C3BBA9EE9FULL,
		0x74C8480250152319ULL,
		0x32FFC24A91A7D721ULL,
		0xDD5A45FDF2D8ECEFULL,
		0x4037438E69722235ULL,
		0xA2B18C58ED4E9029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81F7098DF9B7CA2DULL,
		0xB11FA84E51A007B3ULL,
		0x7EBD198B14979EC7ULL,
		0x99143E16EDED1A1CULL,
		0xA83CD22742E60BC4ULL,
		0xAD4C723516BBF55DULL,
		0xA3AB0E5FE6AEE626ULL,
		0xFED06B6E9B710735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ECF63849C697C85ULL,
		0xB8DA58A0C960C28AULL,
		0x4D008A48AF3E7058ULL,
		0xEDDC7614BDF83905ULL,
		0x9AC3106DD341DCE5ULL,
		0x701637C8E46319B2ULL,
		0xE39C4DD18FDCC413ULL,
		0x5C61E736763F971CULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6FB62C5C5451E92ULL,
		0xA350420C016C6138ULL,
		0x7D01EA9A1F29413CULL,
		0xB1F926654A02F624ULL,
		0xC145CA1EF0B5829EULL,
		0x638E5B56ADFF3F35ULL,
		0x0CF7A1BE6B3E2286ULL,
		0xDB4E50A4E705BC59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF64579A6DC5EBD7FULL,
		0xFA89659BF30E64E2ULL,
		0x8B712526506935ADULL,
		0xDE8C00A3D17CEA12ULL,
		0x8304BCE748A98CD3ULL,
		0xD9E75268206C8A79ULL,
		0xD2230459F52D34EAULL,
		0xBCECD95ED1963E03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50BE1B63191BA3EDULL,
		0x59D92797F26205DAULL,
		0xF670CFBC4F407491ULL,
		0x6F7526C69B7E1C36ULL,
		0x424176F9B81C0E4DULL,
		0xBA69093E8D93B54CULL,
		0xDED4A5E79E13166CULL,
		0x67A289FA3693825AULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70F2C8291D8BF8E7ULL,
		0xC2E6F7F2A1D7A812ULL,
		0xBCEA6BD95A586407ULL,
		0x02609C903DBA26B3ULL,
		0x0637488CE4C0BC63ULL,
		0x9400EF61499733CDULL,
		0x3FB6A7DDC138273AULL,
		0x435925B65200A581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DBC2FE19C8D5236ULL,
		0x0F15661FDAA8B4C9ULL,
		0x0188B20992102AE6ULL,
		0x2F1D661FCC88DB94ULL,
		0x6B2F878896FA5F7BULL,
		0x7DB353FFCE0918A7ULL,
		0xE0D639604C41A7B5ULL,
		0xA51A30F7DCD4064EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED4EE7C88106AAD1ULL,
		0xCDF391ED7B7F1CDBULL,
		0xBD62D9D0C8484EE1ULL,
		0x2D7DFA8FF132FD27ULL,
		0x6D18CF04723AE318ULL,
		0xE9B3BC9E879E2B6AULL,
		0xDF609EBD8D79808FULL,
		0xE64315418ED4A3CFULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC77D1661BE5E33DULL,
		0xF6D8F395391832A0ULL,
		0xE3B17E68083C87F3ULL,
		0x7FC768DA05C4DC0BULL,
		0x1FEF0438D95EA195ULL,
		0xB53AB6717A5F8DA1ULL,
		0xCDEE8DE403B993CAULL,
		0x2A34AB4D1D0D2C5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66B93571F7B427C0ULL,
		0x59A56136EEA8A5D9ULL,
		0x00EFC40917FFCB57ULL,
		0xD5A051E82621D1CFULL,
		0xB114D45E8A17A0C5ULL,
		0xB2D2826F88F48A39ULL,
		0x5E86B84747DAB42EULL,
		0x17173E877A37AA22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDACEE417EC51C4FDULL,
		0xAF7D92A3D7B09779ULL,
		0xE35EBA611FC34CA4ULL,
		0xAA67393223E50DC4ULL,
		0xAEFBD06653490150ULL,
		0x07E8341EF2AB0798ULL,
		0x936835A3446327E4ULL,
		0x3D2395CA673A867DULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B64A1A4A1DE91B2ULL,
		0x8E2CE633949CAE70ULL,
		0x990D2A694A4CB1D3ULL,
		0xE4A17CBB3EC2AB84ULL,
		0x3271B94B0B83C9E8ULL,
		0x73678B6B0BFD7FCAULL,
		0xA5A2F0A3CC4D2374ULL,
		0xA6BDA31A8ACD4FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D22A0CB23BDD90ULL,
		0x2BB4CE773943A6BBULL,
		0xE39FE7D5339F7274ULL,
		0x51333C668F2D3333ULL,
		0x9B28DFF74833A3CBULL,
		0xBA2A93BF953C54BFULL,
		0xA7A80A9490DB3996ULL,
		0xBD3837332BDC6222ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EB68BA813E54C22ULL,
		0xA5982844ADDF08CBULL,
		0x7A92CDBC79D3C3A7ULL,
		0xB59240DDB1EF98B7ULL,
		0xA95966BC43B06A23ULL,
		0xC94D18D49EC12B75ULL,
		0x020AFA375C961AE2ULL,
		0x1B859429A1112D8DULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE1734477329213ULL,
		0x85CECAF19DED0DADULL,
		0x031CB0A3F82C6B3AULL,
		0x0E2E0B5D0026CD6EULL,
		0x3F952405C9C6DC0DULL,
		0x8FB3BACB7897F026ULL,
		0x9781C73F72288E84ULL,
		0x6EA926E948CC5808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x220A18ABFB9693BBULL,
		0xD576F68CD2A7387AULL,
		0x10D6A23245F07CC8ULL,
		0xDE0655F735C6ED50ULL,
		0xA27BFE85E52B7B0FULL,
		0xD59CB0428C2F4BCAULL,
		0xBBCD0999B0FD2EA4ULL,
		0x2B3A4940023F5107ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EEB6BEF8CA401A8ULL,
		0x50B83C7D4F4A35D7ULL,
		0x13CA1291BDDC17F2ULL,
		0xD0285EAA35E0203EULL,
		0x9DEEDA802CEDA702ULL,
		0x5A2F0A89F4B8BBECULL,
		0x2C4CCEA6C2D5A020ULL,
		0x45936FA94AF3090FULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD7B709FA13CBDA2ULL,
		0x533A99CFE1B102A6ULL,
		0x7918F13065DE715AULL,
		0x25475B1601DF7C54ULL,
		0x4A4AF2C99DB79F75ULL,
		0x2473115BFAE9E1BCULL,
		0xEC7E415D6200416BULL,
		0x9A9D7BCADFC64325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA99E52699717B59ULL,
		0x44E64253575F83F8ULL,
		0x508DF849EEF1EC5CULL,
		0x2C14FC3ED99ED69BULL,
		0x2DEF1300A68B61E4ULL,
		0x63D33549C7F7B76CULL,
		0xC1DA5C78BE21A583ULL,
		0x64CF6F4D0CD7CD62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67E295B9384DC6FBULL,
		0x17DCDB9CB6EE815EULL,
		0x299509798B2F9D06ULL,
		0x0953A728D841AACFULL,
		0x67A5E1C93B3CFE91ULL,
		0x47A024123D1E56D0ULL,
		0x2DA41D25DC21E4E8ULL,
		0xFE521487D3118E47ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x458639C0407D7EF9ULL,
		0x63D1B54A61807182ULL,
		0x2576C384E5BCE06BULL,
		0x04225AB3BED70F16ULL,
		0x90485B8F59EF3925ULL,
		0xF766D3D96BE9789EULL,
		0x99399DF47D5BDF22ULL,
		0xC76F5BD5440122B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ABAF23770591EE4ULL,
		0xFC73BE6DA84B952AULL,
		0x0EB69987A87FC6FBULL,
		0x1B9EC06E879C98C4ULL,
		0x896CFE037365D7DCULL,
		0x4D985B61B2ADC636ULL,
		0xD9957FE2A5B0F633ULL,
		0xF077166A6771AFB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F3CCBF73024601DULL,
		0x9FA20B27C9CBE4A8ULL,
		0x2BC05A034DC32690ULL,
		0x1FBC9ADD394B97D2ULL,
		0x1924A58C2A8AEEF9ULL,
		0xBAFE88B8D944BEA8ULL,
		0x40ACE216D8EB2911ULL,
		0x37184DBF23708D07ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F1B812418784887ULL,
		0x1FC6FEAD155DB038ULL,
		0x4AC6CADD6DFA8108ULL,
		0x7F99AF4817623A44ULL,
		0x927C3BE4094DE81DULL,
		0x0C9BE4283D980DB6ULL,
		0x48B6FC5AADAC9694ULL,
		0x5CC055EE7C1BBFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C94CBBF390B43FULL,
		0x1EAB7264C2EFFF2FULL,
		0x537B8F7CF0C7EF03ULL,
		0x6A795BAAE893CE96ULL,
		0x4980BD14DC5411ECULL,
		0xD2385E7879DB997AULL,
		0x3B876F0907B06CDAULL,
		0x2ACEB540F64DBDCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D2CD9FEBE8FCB8ULL,
		0x016D8CC9D7B24F17ULL,
		0x19BD45A19D3D6E0BULL,
		0x15E0F4E2FFF1F4D2ULL,
		0xDBFC86F0D519F9F1ULL,
		0xDEA3BA50444394CCULL,
		0x73319353AA1CFA4EULL,
		0x760EE0AE8A560224ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DB551A4BD125358ULL,
		0xA3AD60577572808DULL,
		0xEE1C5FCC915D5F22ULL,
		0x7DA8D6E888597B80ULL,
		0xCF0F929BCD5F35F1ULL,
		0x5A81587B16D4BCC0ULL,
		0xB551E2CE40435171ULL,
		0x571F7EE91393C3E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504B96BCEC7DD57FULL,
		0xFD4FD1BCB17518AEULL,
		0x284E4449D8E8C690ULL,
		0xC83E3F9445BE7AB2ULL,
		0xEFAC1AE42B4C9F47ULL,
		0x55D3CE51C17CA6B3ULL,
		0x3FEC6E8406BCC275ULL,
		0x8129F50AE9F693EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDFEC718516F8627ULL,
		0x5EE2B1EBC4079823ULL,
		0xC6521B8549B599B2ULL,
		0xB596E97CCDE70132ULL,
		0x20A3887FE613AAB6ULL,
		0x0F52962AD7A81A73ULL,
		0x8ABD8C4A46FF9304ULL,
		0xD6368BE3FA655005ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x379D45BD92AD3710ULL,
		0x4565AE944A47557FULL,
		0x7F063AC32B0D29E5ULL,
		0x14BBD2D213418CDEULL,
		0x269DA6F7EAD509FDULL,
		0xCCEB4C6F2B6AD2CBULL,
		0x5EA497295216059CULL,
		0xE974175C47E9DD53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2F310C9EE3F594ULL,
		0x185428DE43880769ULL,
		0xA6DF571E558F878CULL,
		0x871F9F17E1129ECBULL,
		0x3EEE8CC4EF8353D2ULL,
		0x8479E2A8E080D6DCULL,
		0x66920DA14E0C2F4CULL,
		0x73CED79C3CA474BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49B274B10C4EC284ULL,
		0x5D31864A09CF5216ULL,
		0xD9D96DDD7E82AE69ULL,
		0x93A44DC5F2531215ULL,
		0x18732A3305565A2FULL,
		0x4892AEC7CBEA0417ULL,
		0x38369A881C1A2AD0ULL,
		0x9ABAC0C07B4DA9E8ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD9F1A8EA0C3814FULL,
		0x5199C579508E8AF4ULL,
		0x07C095B06837FBBEULL,
		0x57B0000ED16F0238ULL,
		0x5FE80226FBA72D94ULL,
		0x0B41158062EEF937ULL,
		0xEA28026761B9223AULL,
		0x55D3E8CE286B72FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9E822FF2908B00ULL,
		0x613993F6DE8EE07FULL,
		0x2FC1D5D2BBF4BA3FULL,
		0x54A6EB4D693ECFD1ULL,
		0xB8E7953B633B9A86ULL,
		0xABFD8635AC9754D8ULL,
		0x533D5C8EECA99987ULL,
		0xB5FB8FB0AF35A032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF30198A152530A4FULL,
		0x30A0568F8E006A8BULL,
		0x28014062D3C34181ULL,
		0x0316EB43B851CDE9ULL,
		0xE70F971D989CB712ULL,
		0xA0BC93B5CE79ADEFULL,
		0xB9155EE98D10BBBDULL,
		0xE028677E875ED2CFULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC52E13748C2780CCULL,
		0x0E811B70E2F9CDFEULL,
		0x975A5A80399647EFULL,
		0x9EF858DB87A612A1ULL,
		0x799CE5245E8C5ECDULL,
		0x56A607213695AEF8ULL,
		0xCA2D9FA0B3BD55CFULL,
		0xC35A906EB962BFF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x825F9074D92BD9C0ULL,
		0xB98151BF12A4C9E0ULL,
		0x680627D3FF9B2824ULL,
		0xE4091A4890870C3FULL,
		0xC8E995EE04891C8DULL,
		0xFF4A8D136087EB02ULL,
		0x0E1FD1A22414E70DULL,
		0x06CA5DFF91D38FD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47718300550C590CULL,
		0xB7004ACFF05D041EULL,
		0xFF5C7D53C60D6FCBULL,
		0x7AF1429317211E9EULL,
		0xB17570CA5A054240ULL,
		0xA9EC8A32561245FAULL,
		0xC4324E0297A9B2C2ULL,
		0xC590CD9128B13022ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80E7EAF284348C24ULL,
		0xE8E9EC2F16622A25ULL,
		0xEDA73ECBF3C70841ULL,
		0x3D326F29EBBE826EULL,
		0x12F49A4DB78F4219ULL,
		0xBF378C14AAC8CB74ULL,
		0x0DF4A96A9E7DFD20ULL,
		0xC840C6A1AF2E35A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4966AECDA3D9D184ULL,
		0xB6FC7E0DA375FBD2ULL,
		0x9EEADB5E3BAF927AULL,
		0xEFC52ABB556BCB8BULL,
		0xE043FAFE34854141ULL,
		0xE82C66D5EF57C86DULL,
		0x566792CB89027E8AULL,
		0x59B80B3A1C9F802EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC981443F27ED5DA0ULL,
		0x5E159222B517D1F7ULL,
		0x734DE595C8689A3BULL,
		0xD2F74592BED549E5ULL,
		0xF2B760B3830A0358ULL,
		0x571BEAC1459F0319ULL,
		0x5B933BA1177F83AAULL,
		0x91F8CD9BB3B1B58BULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6435FF229087C4AULL,
		0x055AD60608B210EBULL,
		0x5682A7C4319C2BDCULL,
		0x8765F4CCB3A0318BULL,
		0x5A805AAD21DB7C49ULL,
		0xC98A200F4542668CULL,
		0xCFB4F2992590F16AULL,
		0x5F283ACE1B7F9761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9A7A09B4E2038EULL,
		0x6E49E7E110D2CDB5ULL,
		0xAD66E71F73C16E88ULL,
		0x5F5035AC36995A2FULL,
		0x4A1A1B3DA2E15A09ULL,
		0xD9A8BC3D6B3FB429ULL,
		0xFF56F94412C16D03ULL,
		0x2B354B9A1CFB2E6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DD925FB9DEA7FC4ULL,
		0x6B1331E71860DD5EULL,
		0xFBE440DB425D4554ULL,
		0xD835C16085396BA4ULL,
		0x109A4190833A2640ULL,
		0x10229C322E7DD2A5ULL,
		0x30E20BDD37519C69ULL,
		0x741D71540784B90BULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE7F60D0C56A2816ULL,
		0x051B20C113E9C5FFULL,
		0xB0BDB5484FCDCD6FULL,
		0x92CDD8948828F664ULL,
		0xE739FEF7D43CFFD4ULL,
		0x974C327A6AFC35BEULL,
		0x59B19775A80E56CAULL,
		0xA395277F14F14A98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39559EC1D2037347ULL,
		0xF0DFF81B26672102ULL,
		0xEA59EA90265FB42CULL,
		0xD47D400E95C16EDFULL,
		0xAE05D5C4FBBD9118ULL,
		0x5188EB313C357714ULL,
		0x7A0B70FCA76F172AULL,
		0x2DA044D8DB66EC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x972AFE1117695B51ULL,
		0xF5C4D8DA358EE4FDULL,
		0x5AE45FD869927943ULL,
		0x46B0989A1DE998BBULL,
		0x493C2B332F816ECCULL,
		0xC6C4D94B56C942AAULL,
		0x23BAE7890F6141E0ULL,
		0x8E3563A7CF97A6CCULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE55BDB4718A874D9ULL,
		0x77E91446EA6AFF3DULL,
		0x61935B48943238AAULL,
		0x98F295BFDCD87604ULL,
		0x5D89210528E0769BULL,
		0x7951A3F483B7676BULL,
		0x588253CADDE34C76ULL,
		0x96060E81CEECE4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C0387A095834BFULL,
		0x47598C670FC80E71ULL,
		0x096AC21BB0F88FAFULL,
		0xC8E8ED693A10E28BULL,
		0x416C0026929FACEFULL,
		0x31F52DF8617DF5D8ULL,
		0x4A3C8BB723BF0F6CULL,
		0xC0BEF3A91D6B5DAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC19BE33D11F04066ULL,
		0x30B09821E5A2F14CULL,
		0x68F9995324CAB705ULL,
		0x501A78D6E6C8948FULL,
		0x1CE52123BA7FDA74ULL,
		0x48A48E0CE2CA92B3ULL,
		0x12BED87DFE5C431AULL,
		0x56B8FD28D387B95EULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37C716DD47892297ULL,
		0x5B938D314ED0A129ULL,
		0x3FAF6A9CFD859104ULL,
		0x61A011CC6D1EF85BULL,
		0x980FACED978F73CCULL,
		0x6E703F83BED0EF5BULL,
		0x69DE36673EEA9C56ULL,
		0x7AA48897AE1052AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74C50E35FFEB8F12ULL,
		0xDA2B9E32660EA6DEULL,
		0xBB223C0E4D0DD640ULL,
		0xF3FD3356F8E9B977ULL,
		0x08CF0C14EED045D9ULL,
		0x6CE7CA2131995CCDULL,
		0x6CB5784A22C98A6CULL,
		0x01D36972D1849E15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x430218E8B862AD85ULL,
		0x81B8130328DE07F7ULL,
		0x848D5692B0884744ULL,
		0x925D229A95F7412CULL,
		0x90C0A0F9795F3615ULL,
		0x0297F5A28F49B396ULL,
		0x056B4E2D1C23163AULL,
		0x7B77E1E57F94CCBAULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x272423414C005423ULL,
		0x9BFFDA021B484C75ULL,
		0x75571E117B3C5231ULL,
		0x09C0E42E3A8F28AAULL,
		0xFA0639FF2C7D81B5ULL,
		0x6397F5588324E056ULL,
		0xB3603465971EC789ULL,
		0x77A7A227E693C4C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6519C464CA8CB2ULL,
		0x5BF75B6BF861554BULL,
		0x201F99797AED445EULL,
		0xE8DCAB7C7402A25AULL,
		0xD79DF78F35F81504ULL,
		0x95C6BF346FDDBB72ULL,
		0xC40869CBBDEF3813ULL,
		0x97F910FE56FF02CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A413A8528CAD891ULL,
		0xC0088169E329193EULL,
		0x5548876801D1166FULL,
		0xE11C4F524E8D8AF0ULL,
		0x2D9BCE70198594B1ULL,
		0xF6514A6CECF95B24ULL,
		0x77685DAE2AF1FF9AULL,
		0xE05EB2D9B06CC60DULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67E669F982AD75EEULL,
		0x8F351C1D6F69FA89ULL,
		0x0168E3F770547A20ULL,
		0x55EDA82277FE1E6BULL,
		0xA1B034703A0E3E88ULL,
		0x54504878415CEDB0ULL,
		0x544E77F7F5DD1F7AULL,
		0x209D7328F7179A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD822B66159C8C07AULL,
		0x644DFEAAE172B122ULL,
		0x56AB066D8235C3B1ULL,
		0x01F8BE189D6EEB55ULL,
		0x26C77DC36BE6DD11ULL,
		0x5A3DFA1DEFC3FC66ULL,
		0xA5C6D36F0F0A4D17ULL,
		0x0F7F07F7C090B8D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFC4DF98DB65B594ULL,
		0xEB78E2B78E1B4BABULL,
		0x57C3E59AF261B991ULL,
		0x5415163AEA90F53EULL,
		0x877749B351E8E399ULL,
		0x0E6DB265AE9F11D6ULL,
		0xF188A498FAD7526DULL,
		0x2FE274DF378722C1ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8067D69714CDEAA7ULL,
		0x76A505F1A26243D8ULL,
		0x91C5E2BF3AB84E77ULL,
		0x97BCB4E8EC35D5F1ULL,
		0xE03764355814B2FAULL,
		0x1FD493C081CF3525ULL,
		0xBAC7D28A5D8C1789ULL,
		0x18BD1BB1D93B8B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ED875A98ED88595ULL,
		0xD8B784EDF5511DC0ULL,
		0x766A408E683DFDBFULL,
		0x2724938800C12706ULL,
		0xA1CBB94FC3B4D5A7ULL,
		0x0080602479B763BDULL,
		0x10568428D56FF37DULL,
		0x7A8F1F5D824672B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EBFA33E9A156F32ULL,
		0xAE12811C57335E18ULL,
		0xE7AFA2315285B3C8ULL,
		0xB0982760ECF4F2F7ULL,
		0x41FCDD7A9BA0675DULL,
		0x1F54F3E4F8785698ULL,
		0xAA9156A288E3E4F4ULL,
		0x623204EC5B7DF9CEULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x739A9FBFE8003289ULL,
		0x55CE6B29D0FAE8B6ULL,
		0xD7B8AC068E8FBABCULL,
		0x37592C1803148C15ULL,
		0x0061918329FC2AC1ULL,
		0x95F0489AA4126A59ULL,
		0xDDDD8951633DD8EAULL,
		0x7C598CD390D5742AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x506D7C56336082E6ULL,
		0xBD65E9AE96BB1BCFULL,
		0xC43F6C691380BBF7ULL,
		0xFFDD7BE63953BC23ULL,
		0x16757F899AF72E3BULL,
		0xAE780F950E7A7C96ULL,
		0x169046CBA7F8AD14ULL,
		0x9D154475709B8188ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23F7E3E9DB60B06FULL,
		0xE8AB82874641F379ULL,
		0x1387C06F9D0F014BULL,
		0xC88457FE3A473036ULL,
		0x1614EE0AB30B04FAULL,
		0x3B88470FAA6816CFULL,
		0xCB4DCF9AC4C575FEULL,
		0xE14CC8A6E04EF5A2ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0740843C22FBEBE8ULL,
		0x3DB7DCD9B0447E62ULL,
		0xBAE2B6665754EA26ULL,
		0xD50BC7FC73BBFF85ULL,
		0x863F093369D03D72ULL,
		0x048ACDA2157D8EB8ULL,
		0x32CA47CEE8CF88E0ULL,
		0x14F5FA168EF0A1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F066F96BAFBB913ULL,
		0x1297A9D5630C8DC1ULL,
		0xCBF3285A763BDA11ULL,
		0x23208E1267FC0E86ULL,
		0xA39C321A70D9C858ULL,
		0xD8481977EE1F6EC9ULL,
		0x612365960735A507ULL,
		0x99A63CCE0B1D083DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1846EBAA980052FBULL,
		0x2F20750CD348F3A3ULL,
		0x71119E3C216F3037ULL,
		0xF62B49EE1447F103ULL,
		0x25A33B291909F52AULL,
		0xDCC2D4D5FB62E071ULL,
		0x53E92258EFFA2DE7ULL,
		0x8D53C6D885EDA9F9ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE144912567AF2173ULL,
		0x384266FE8FA8777CULL,
		0xA21930C25C4FCED2ULL,
		0xD899FAA02B86C454ULL,
		0x40890412607703FCULL,
		0xEE9961E9075DF1F9ULL,
		0xA265BC8840190812ULL,
		0xED874DCDAA8F8F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD5EC144F0572D5ULL,
		0x21C1EA700983F2F5ULL,
		0xB69BAA7653937E72ULL,
		0x3B1CDD9B977D5E67ULL,
		0x297EE0C30E889981ULL,
		0x6FE0224352876CABULL,
		0xCD042D4847F8E8EFULL,
		0xC15F8ADBCE330F5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD917D3128AA53A6ULL,
		0x19838C8E862B8589ULL,
		0x14829AB40FDCB0A0ULL,
		0xE385273BBCFB9A33ULL,
		0x69F7E4D16EFF9A7DULL,
		0x817943AA55DA9D52ULL,
		0x6F6191C007E1E0FDULL,
		0x2CD8C71664BC8031ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8700B780F853EE90ULL,
		0x2E27563C69B74A6FULL,
		0x2BE5D95108616F64ULL,
		0xEB551D930357D2DCULL,
		0xF8334CA14E14672CULL,
		0x46C7740755022F3EULL,
		0xBB01CF05E89EFCF6ULL,
		0x852B75C0F8F32B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A062A087424496EULL,
		0x8C66006078164833ULL,
		0xD8FE9611366A5FACULL,
		0xE859952B45CB8821ULL,
		0xDC48679E12D2FB82ULL,
		0x92AD124151D7BE8FULL,
		0xAC2EA734445AFB9EULL,
		0x867275247AE921C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D069D888C77A7FEULL,
		0xA241565C11A1025CULL,
		0xF31B4F403E0B30C8ULL,
		0x030C88B8469C5AFDULL,
		0x247B2B3F5CC69CAEULL,
		0xD46A664604D591B1ULL,
		0x172F6831ACC40768ULL,
		0x035900E4821A0A9EULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CA6CABD80BFB655ULL,
		0xAD40E2E02A63837FULL,
		0xCA0B2075B2BE74E4ULL,
		0xEDBF32BA2121D80EULL,
		0x04BD564FA78EE56AULL,
		0xCAF0E8D2B8A836EFULL,
		0x1C0CDA112937134FULL,
		0xBD89DE9A2B7C726CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC039608FD1FA082AULL,
		0xA13175D3FD88A66CULL,
		0x08D32AFFB801CBEFULL,
		0x070756614295C5D0ULL,
		0xEC0D2A5A00DED5A4ULL,
		0x1215BD835BA9EF0BULL,
		0x159BAA896570F695ULL,
		0x68CB17D163835553ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9FAA325145BE7FULL,
		0x0C719733D7EB2513ULL,
		0xC2D80A8A0ABFBF0BULL,
		0xEAB864DB63B41DDEULL,
		0xE8B07C15A75030CEULL,
		0xD8E55551E301D9E4ULL,
		0x099770984C47E5DAULL,
		0xD542C94B48FF273FULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BA1EF4DB64EF29AULL,
		0xCDDDF5C2A3C5B98DULL,
		0xFFB44689244D42EFULL,
		0x025D0648DDCCCAB7ULL,
		0x29161B9030D68A2CULL,
		0xE164ED974CA375EFULL,
		0x7347E6944F8E3878ULL,
		0x7B1767725C7D3985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B5D28E52B8BF13ULL,
		0x65B237AF43BD05F6ULL,
		0x0F66C77F110FF506ULL,
		0x5B0537D27A354D60ULL,
		0x561CA4F224B06065ULL,
		0xE569D6C1B2F1E5DAULL,
		0xB3EF3EF55605D0AEULL,
		0x7952ED78B2517481ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F143DC3E4F64D89ULL,
		0xA86FC26DE078BC7BULL,
		0xF0D281F63542B7E9ULL,
		0x5958319AA7F987D7ULL,
		0x7F0ABF621466EA49ULL,
		0x040D3B56FE529035ULL,
		0xC0A8D861198BE8D6ULL,
		0x02458A0AEE2C4D04ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC13206AAF0FADD1ULL,
		0x6EE6EE16C9FA8AAEULL,
		0x0FD65CE47C497940ULL,
		0xD9B6273FFDF24420ULL,
		0x42EBDB011E45BB73ULL,
		0x72ABA23A22339C48ULL,
		0x1D8004CAD21958F4ULL,
		0x81860387CDA7DAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1E4363A96902C6EULL,
		0xE1CACEEAF6E10988ULL,
		0x28C8852126082AABULL,
		0xEBE839ED42BD86F1ULL,
		0xF8AEF93CBC95D405ULL,
		0x1AB23590DA901EE2ULL,
		0xACB46AC2517FCF99ULL,
		0x887661DFF18D4888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DF71650399F81BFULL,
		0x8F2C20FC3F1B8326ULL,
		0x271ED9C55A4153EBULL,
		0x325E1ED2BF4FC2D1ULL,
		0xBA45223DA2D06F76ULL,
		0x681997AAF8A382AAULL,
		0xB1346E088366976DULL,
		0x09F062583C2A9266ULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D211EEE643A5BF7ULL,
		0x8D085B9BAAA43579ULL,
		0x50E0CB20C362C399ULL,
		0xDA1E75EDBC786997ULL,
		0x72CFC7AC2CC84D29ULL,
		0x2DE48595592A3F7FULL,
		0x870197F38195AC43ULL,
		0x1BBC288D605176CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83EA6A4D993F314DULL,
		0x255E92DA2AA81031ULL,
		0xDF6715BACBBC8D0EULL,
		0xB4D638F1E0F3FA8AULL,
		0xFE9979628314F90FULL,
		0x5456C56322742A68ULL,
		0x720AC10C000C2C13ULL,
		0x15FC6EA5C6BB3CFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEECB74A3FD056ABAULL,
		0xA856C941800C2548ULL,
		0x8F87DE9A08DE4E97ULL,
		0x6EC84D1C5C8B931DULL,
		0x8C56BECEAFDCB426ULL,
		0x79B240F67B5E1517ULL,
		0xF50B56FF81998050ULL,
		0x0E404628A6EA4A30ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55D2DB2A3F6CA463ULL,
		0x15CFB6F03261811FULL,
		0x4DB3F4F85EB9A1EFULL,
		0xE1E7E840D6D97146ULL,
		0x191C975A5DF22BACULL,
		0x7C5DF83560DEBB12ULL,
		0x71877207FB8C5B20ULL,
		0x55FD62B1BC2E592BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5326D434ACD3C2BULL,
		0xC2347F33554C64DEULL,
		0x3EC75F34894D1805ULL,
		0x4BC6C9834FD0FD33ULL,
		0x8F78A9A6020C4CC4ULL,
		0xC7D15C1F1C459E68ULL,
		0x99F99D24A7418624ULL,
		0x376A9C4FAA7FA673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80E0B66975A19848ULL,
		0xD7FBC9C3672DE5C1ULL,
		0x7374ABCCD7F4B9EAULL,
		0xAA2121C399098C75ULL,
		0x96643EFC5FFE6768ULL,
		0xBB8CA42A7C9B257AULL,
		0xE87EEF235CCDDD04ULL,
		0x6297FEFE1651FF58ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BB94711BE401184ULL,
		0x53A9FCC510EE1939ULL,
		0x22E00EA969990406ULL,
		0x8CCF9722A953A9D2ULL,
		0x5FC99339079325DFULL,
		0x2C85CA2E68E85AE7ULL,
		0x3569A43DCBCED8C8ULL,
		0xDA1052A6C002A371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE290128E8F97AE09ULL,
		0xD2CAE9BF88B90C84ULL,
		0x36EC5EDFCF8A5BAAULL,
		0x3A4A45B388FE6707ULL,
		0x1C836D5E325AF4A8ULL,
		0x47C4D6B1BC27F6B4ULL,
		0x1541D8E9F4D607D6ULL,
		0x7C3E018585505FFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF929559F31D7BF8DULL,
		0x8163157A985715BDULL,
		0x140C5076A6135FACULL,
		0xB685D29121ADCED5ULL,
		0x434AFE6735C9D177ULL,
		0x6B411C9FD4CFAC53ULL,
		0x20287CD43F18DF1EULL,
		0xA62E53234552FC8AULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x716EEB2A21D930BBULL,
		0xAAF180D983DD33A7ULL,
		0x417A9A5AD19A45B7ULL,
		0x3654B1CD2E58E558ULL,
		0x083CE7F1CD7C7DF6ULL,
		0xE14194EF03661433ULL,
		0xC54046580BAFE426ULL,
		0x9B0C60B05BEB93ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13286E4229DC0224ULL,
		0x8D0533635F55FB37ULL,
		0x1D4518C3B67C4B3DULL,
		0x9AE8DCF2DE8E8761ULL,
		0xC623D97C9052895BULL,
		0x0F89DD0D6B2549F9ULL,
		0x96705BB9D02CDAD2ULL,
		0x42056D4CB8946493ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x624685680805329FULL,
		0x27F4B3BADC88C890ULL,
		0x5C3F829967E60E8AULL,
		0xACBC6D3FF0D66239ULL,
		0xCE1F3E8D5D2EF4ADULL,
		0xEEC849E268435DCAULL,
		0x53301DE1DB833EF4ULL,
		0xD9090DFCE37FF738ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E912A39545E8CD0ULL,
		0xF915861700526BCAULL,
		0xD370F9FDD85BB1EBULL,
		0x7C065514F8043694ULL,
		0x161591DB8E629785ULL,
		0xD6215B4C680D8FBFULL,
		0x5B8393346E8C59D8ULL,
		0x801F07D17B890EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08EA201781A508DEULL,
		0x27A583E58FD01C46ULL,
		0x2A421AD77F8D707AULL,
		0x04282F9817B68449ULL,
		0x21B0DC7AB128A2B0ULL,
		0x1EBF32A36E18C98AULL,
		0xFD6A05458A17965EULL,
		0xD1E27B8816BE1FF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x067B0A2ED5FB840EULL,
		0xDEB005F28F82778CULL,
		0xF932E32AA7D6C191ULL,
		0x782E7A8CEFB2B2DDULL,
		0x37A54DA13F4A3535ULL,
		0xC89E69EF06154635ULL,
		0xA6E99671E49BCF86ULL,
		0x51FD7C596D37115BULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5058D1E207200024ULL,
		0x8380E0A882D9680CULL,
		0x96EE4FEFCDC854ECULL,
		0x5E8A3727FAE0F561ULL,
		0xD4EB5D22D0549586ULL,
		0x3ABD965379240379ULL,
		0x9ECB37F847564260ULL,
		0xC212201B5C204C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CD278A78299AB7ULL,
		0xB012D8A4ED99A830ULL,
		0x33376FA54F55B844ULL,
		0xCC2F5591872580C0ULL,
		0xAD31364FB62DEE6BULL,
		0x169CC4208ACEE69FULL,
		0x1F936BDD48FB9EF1ULL,
		0x3F1C257A9F614A88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1695F6687F099A93ULL,
		0x3392380C6F40C03CULL,
		0xA5D9204A829DECA8ULL,
		0x92A562B67DC575A1ULL,
		0x79DA6B6D66797BEDULL,
		0x2C215273F3EAE5E6ULL,
		0x81585C250FADDC91ULL,
		0xFD0E0561C34106ADULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FA27F7D29D329CDULL,
		0xEF64CDBEB58FC9FFULL,
		0xB3867FB5365B615BULL,
		0x499A14652AD5276FULL,
		0xDCB6A282A2AAEAEFULL,
		0xEE537F6F381D6FBEULL,
		0x59C9431C544B6CE8ULL,
		0x8C2712DDA2E3960AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67251D91BE3047CULL,
		0x9CE631F4BDEADD9FULL,
		0xA98C6DE453C1BFC0ULL,
		0xBFDFA83ADC58C314ULL,
		0xB746190692E7F13FULL,
		0x13B704A078F98BF4ULL,
		0x5D54248849D5A4E7ULL,
		0x14872CC43C06DF70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9D02EA432302DB1ULL,
		0x7382FC4A08651460ULL,
		0x1A0A1251659ADE9BULL,
		0xF645BC5FF68DE47BULL,
		0x6BF0BB84304D1BD0ULL,
		0xFDE47BCF40E4E44AULL,
		0x049D67941D9EC80FULL,
		0x98A03E199EE5497AULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED58DF30310BA0E7ULL,
		0x9ADBF6528A3F5F12ULL,
		0x1637F64AE2E301D4ULL,
		0xF26C90A80832A41DULL,
		0xFF64E11CD1C1250AULL,
		0xFFD9FAD505BC496CULL,
		0xE3027DF3A38A8C0BULL,
		0x8DB58AF2DA1AF3B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF22A74D3D006C3BULL,
		0x66D569E4F8E82CCFULL,
		0x9C0784CA84B2830DULL,
		0x06BE88DF3D78589BULL,
		0x7E5ECA2B496D4782ULL,
		0xC73E14029BF350A1ULL,
		0x97EDE96207A7C811ULL,
		0x3917F4288D4073EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x327A787D0C0BCCDCULL,
		0xFC0E9FB672D773DDULL,
		0x8A307280665182D9ULL,
		0xF4D21877354AFC86ULL,
		0x813A2B3798AC6288ULL,
		0x38E7EED79E4F19CDULL,
		0x74EF9491A42D441AULL,
		0xB4A27EDA575A805DULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE63572D9ADB56B8FULL,
		0xF18B571B175EEC95ULL,
		0xB30AF682DBC7A8CFULL,
		0xE6CB8E9E204275B3ULL,
		0x9834D5FEB518FFACULL,
		0xFBC5C120AEA3FF5AULL,
		0x37D41EEA67B35D24ULL,
		0x42C244C0C55C037FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D4F5529BEF8C0BULL,
		0x7234DC677B2C24E6ULL,
		0x5B7E53DC07B743D0ULL,
		0x2ADC677F45D73319ULL,
		0xF5767F646B1BB6B4ULL,
		0xF2E8400BE3ABD457ULL,
		0xB30FE1EFE711A1B4ULL,
		0xDF2C784B38EE254FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEE1878B365AE784ULL,
		0x83BF8B7C6C72C873ULL,
		0xE874A55EDC70EB1FULL,
		0xCC17E9E1659546AAULL,
		0x6D42AA9ADE034918ULL,
		0x092D812B4D082B0DULL,
		0x84DBFF0580A2FC90ULL,
		0x9DEE3C8BFDB22630ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAC798B3AA058C10ULL,
		0xD1395D5204E168F1ULL,
		0x13A3AB0C6646B5C4ULL,
		0x2065C5460F752466ULL,
		0xF6EF1EA848CB6FB9ULL,
		0x5BAAC63EA49FE4F3ULL,
		0x7E9AC208204D91E2ULL,
		0xA1115C6745B72561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDD88D5FBC9A2D1ULL,
		0x7966884AC270B780ULL,
		0xE1F170DB5B253908ULL,
		0x2679594A6BC0741BULL,
		0x8F31037B272A0491ULL,
		0xAF24B350DC8112D6ULL,
		0x404ABB5443147BA5ULL,
		0xA62339AB0BC46BD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261A106651CC2EC1ULL,
		0xA85FD518C691DF71ULL,
		0xF252DBD73D638CCCULL,
		0x061C9C0C64B5507DULL,
		0x79DE1DD36FE16B28ULL,
		0xF48E756E781EF625ULL,
		0x3ED0795C6359EA47ULL,
		0x073265CC4E734EB7ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20B162A396DC7000ULL,
		0x46949D5A99BD2EE7ULL,
		0x23ADC5DF4D84712FULL,
		0x972044A4A2E7BAB9ULL,
		0xA820C08DF28C4F93ULL,
		0x139C4CB398933357ULL,
		0x6B4A0C489C9D2BB4ULL,
		0x4D6FFB3D2C22A87EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C33223447B48BACULL,
		0x1CFB1137ECA896B1ULL,
		0x8117A86D541A9251ULL,
		0x593C9D61AA5A4511ULL,
		0x8C73B4EDB30DED16ULL,
		0x30A5112098DBABC8ULL,
		0x1DE52669B9ADCEEDULL,
		0xC767614DA68C2B0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC824097D168FBACULL,
		0x5A6F8C6D7515B856ULL,
		0xA2BA6DB2199EE37EULL,
		0xCE1CD9C508BDFFA8ULL,
		0x245374604181A285ULL,
		0x23395D930048989FULL,
		0x76AF2A212530E559ULL,
		0x8A089A708AAE8375ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4CA7EBBCB46E1C9ULL,
		0x29792F0770A80B32ULL,
		0x8D162F1CDD25C6F7ULL,
		0x132898C3EA8AC443ULL,
		0xBD20A196BD509185ULL,
		0x3ACF5DCD1D5E9F8BULL,
		0x1513E8010901EE91ULL,
		0xA2722D64BB891F7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B227729C1796F4DULL,
		0x51C508EACCDC5984ULL,
		0xB8CDDBFF5C41E7DAULL,
		0x07CA21D4F7954BE3ULL,
		0x52039F46F3585BC4ULL,
		0x79017D06D8FF7FF7ULL,
		0x11BD90B04DAAC0E8ULL,
		0x9103EB4A259ED724ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE809920A3F8E84ULL,
		0x78BC27EDBC7452B6ULL,
		0x35DBF4E38164212DULL,
		0x14E2B9171D1F8FA0ULL,
		0xEF233ED04E08CA41ULL,
		0x43CE20CBC5A1E07CULL,
		0x04AE78B144AB2E79ULL,
		0x3371C62E9E17C85FULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA22387957D4B2B82ULL,
		0x22A543D4D0B647F4ULL,
		0x046B42F248FABC40ULL,
		0xDC6A72A15E28AAA2ULL,
		0xE6953894F7B6F267ULL,
		0x858DBF2A86D33033ULL,
		0xFD862203C875375BULL,
		0xDDE3B5800390B02EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE40F7B03025FCE6ULL,
		0xD8911BD6EF2300FAULL,
		0xF20DDDBDD303360DULL,
		0x91DEB23988C737F6ULL,
		0x143625A3A8DC101BULL,
		0x6C05C4FA0B23FE68ULL,
		0x02E1495B9DB4ECFDULL,
		0x852CE71B7E2693E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C6370254D6ED764ULL,
		0xFA3458023F95470EULL,
		0xF6669F4F9BF98A4DULL,
		0x4DB4C098D6EF9D54ULL,
		0xF2A31D375F6AE27CULL,
		0xE9887BD08DF0CE5BULL,
		0xFF676B5855C1DBA6ULL,
		0x58CF529B7DB623CBULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53A6DEC94E312F9AULL,
		0xC96C2BA9866420D6ULL,
		0xFBD33E9369F14493ULL,
		0x414C0C14D18E444CULL,
		0xC17A6200F4ABD674ULL,
		0xF80E86B341F624BBULL,
		0xF28BFA4C16281D1BULL,
		0x5B5C1E4FD9CD8F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB585862AF57853C6ULL,
		0x421F313A0FE663BEULL,
		0x4B40BC09894BE6B1ULL,
		0xA5FF050505391615ULL,
		0x3AA566983124F290ULL,
		0xDFD3FA92BA10EF09ULL,
		0x583A0BB104BC4D46ULL,
		0xC9B6D3200A3040DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE62358E3BB497C5CULL,
		0x8B731A9389824368ULL,
		0xB093829AE0BAA222ULL,
		0xE4B30911D4B75259ULL,
		0xFBDF0498C58F24E4ULL,
		0x27DD7C21FBE6CBB2ULL,
		0xAAB1F1FD1294505DULL,
		0x92EACD6FD3FDCFCDULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE0C14880181230ULL,
		0x6BC3105A43FD66EBULL,
		0x85D52B14F3C5A90DULL,
		0x6B6905486E8869E2ULL,
		0x47EC4CCDE4490FA2ULL,
		0x389C28F111CC13FBULL,
		0xDB4CC72D2F1A1E6CULL,
		0x8BE33E5D597E02A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13C27F9278F456AULL,
		0xEBB5E5363DE07E59ULL,
		0x5323B96E7DB2C782ULL,
		0x182B719B0DD2B4E6ULL,
		0xCE38409538472BC2ULL,
		0x54F11CA62DB91EF9ULL,
		0x86B3205C3E583462ULL,
		0x5F302BBE87CB4320ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DDCE6B1A797575AULL,
		0x8076F56C7E1D18B2ULL,
		0xD6F6927A8E776E8FULL,
		0x734274D3635ADD04ULL,
		0x89D40C58DC0E2460ULL,
		0x6C6D34573C750D02ULL,
		0x5DFFE77111422A0EULL,
		0xD4D315E3DEB54186ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC11C9DF22AA75DE0ULL,
		0x0F93D3CD9B50F8F0ULL,
		0x1F59EA01BF730629ULL,
		0x1BF1FD13D2386359ULL,
		0xAC4C3F7C04A55E6EULL,
		0x835D3FBC7B5DF9E6ULL,
		0x9C4D580A7DA4C3DEULL,
		0x091B8FCC6C66CDC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6257823C3A7C46A0ULL,
		0xBFC86EBC8DF141DFULL,
		0x7C2FEC62CD2E4DF8ULL,
		0x688D6A0A4C48C492ULL,
		0xD306C35B2ED6FEA0ULL,
		0x16C0DEEA705AAE85ULL,
		0xA74A379FCCE7D0A2ULL,
		0x3ADD507D0B0221FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA34B1FCE10DB1B40ULL,
		0xB05BBD7116A1B92FULL,
		0x63760663725D4BD1ULL,
		0x737C97199E70A7CBULL,
		0x7F4AFC272A73A0CEULL,
		0x959DE1560B075763ULL,
		0x3B076F95B143137CULL,
		0x33C6DFB16764EC3AULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9738282195313B2DULL,
		0x8B72759F2D83291CULL,
		0x63651C3074C637EDULL,
		0x44D88F7821B50EE6ULL,
		0x1CD71C3AE8AE9C89ULL,
		0x4AF3EF3A85D49A96ULL,
		0x576AEEBB6307500DULL,
		0x6CF65571CF37E545ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4596EEDE4EF9F7ULL,
		0xFB54BE133828A7B8ULL,
		0x48916C9B21352314ULL,
		0x75E781F58989B092ULL,
		0x1020A28858B7AD3AULL,
		0x6FE40FEA0B7A26BDULL,
		0x5149013D89DEFD80ULL,
		0xBC6E4F516A7BD3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x687DBECF4B7FC2DAULL,
		0x7026CB8C15AB8EA4ULL,
		0x2BF470AB55F314F9ULL,
		0x313F0E8DA83CBE74ULL,
		0x0CF7BEB2B01931B3ULL,
		0x2517E0D08EAEBC2BULL,
		0x0623EF86EAD9AD8DULL,
		0xD0981A20A54C36F7ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FFCAA9620660B5FULL,
		0xE98DC4E36C533571ULL,
		0xB945646AA03AC624ULL,
		0x84A0B8265E208DEEULL,
		0x96BEC656C520D5D9ULL,
		0x702E489F0AD62B93ULL,
		0xF23316AFACB99AD5ULL,
		0xDC87E13F0E1395E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97ADDDFF28399A8ULL,
		0x142292FEC60BE2B7ULL,
		0x4CD264043965BF9AULL,
		0x1ACDE6A86B274F26ULL,
		0x08FACF1AA831FF8EULL,
		0x13B3417D57C785B8ULL,
		0xC504DA3BC9ECBCA1ULL,
		0x5069394B1D463E0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96867749D2E592F7ULL,
		0xFDAF561DAA58D7C6ULL,
		0xF597006E995F79BEULL,
		0x9E6D5E8E3507C2C8ULL,
		0x9E44094C6D112A57ULL,
		0x639D09E25D11AE2BULL,
		0x3737CC9465552674ULL,
		0x8CEED8741355ABEBULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FD92EDBBB7A6796ULL,
		0x08F78D8E1ECB85CEULL,
		0x6183FFCEA0B03076ULL,
		0xFF778A8755381117ULL,
		0xDC8174F279BAE284ULL,
		0x9EA4C7669DCA0876ULL,
		0xBFEEEB248A81F1B0ULL,
		0xDB6A1D82914092F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA27DA427F14ED068ULL,
		0xC1961D961347E777ULL,
		0x92BA26B356D0FED4ULL,
		0xA9AEE91994DA6584ULL,
		0x028A588FAF6E770AULL,
		0x37951507A501F22EULL,
		0x6C68329895241293ULL,
		0xBE908843F0ACE257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDA48AFC4A34B7FEULL,
		0xC96190180D8C62B9ULL,
		0xF339D97DF660CEA2ULL,
		0x56D9639EC1E27493ULL,
		0xDE0B2C7DD6D4958EULL,
		0xA931D26138CBFA58ULL,
		0xD386D9BC1FA5E323ULL,
		0x65FA95C161EC70A6ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA7DA38D258A7715ULL,
		0x39C8963FBA6ABEDCULL,
		0x7B8DB395B9A67774ULL,
		0xD015FAA2630C37F5ULL,
		0x8CBC4EED33469C3BULL,
		0x195D80F77AB60F88ULL,
		0x7C65AC2B1AB67EABULL,
		0x31D4340F7856D13DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AFCD19D47F83286ULL,
		0x333CF5C027CE766EULL,
		0xD8B0FB53520EFF2FULL,
		0x04230408CD466796ULL,
		0x8FC54FEC921298BCULL,
		0x54EA35CC36A830DBULL,
		0x6D7C4550A75D2BE9ULL,
		0xF4E33DA9DF0E32C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9081721062724593ULL,
		0x0AF463FF9DA4C8B2ULL,
		0xA33D48C6EBA8885BULL,
		0xD436FEAAAE4A5063ULL,
		0x03790101A1540487ULL,
		0x4DB7B53B4C1E3F53ULL,
		0x1119E97BBDEB5542ULL,
		0xC53709A6A758E3FDULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47834148D4E35440ULL,
		0xA77AC731F208F654ULL,
		0xA2D8E5226BCD7922ULL,
		0x8731634638B66C3DULL,
		0x3B0EA79FF0297B46ULL,
		0x82340C929A059A34ULL,
		0x0B3CC5E3D8BC6B36ULL,
		0x5817E2013D0923D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21BE360F5295A0E4ULL,
		0x648B499346E45569ULL,
		0x3EA6F196834EC81BULL,
		0x589B2DE4B448C8F3ULL,
		0x0CE72CB01B6C5085ULL,
		0x2F9A971ECC36712FULL,
		0xFB9FCC7A2E221843ULL,
		0x96730FF0C14C3752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x663D77478676F4A4ULL,
		0xC3F18EA2B4ECA33DULL,
		0x9C7E14B4E883B139ULL,
		0xDFAA4EA28CFEA4CEULL,
		0x37E98B2FEB452BC3ULL,
		0xADAE9B8C5633EB1BULL,
		0xF0A30999F69E7375ULL,
		0xCE64EDF1FC451484ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6638F71060600860ULL,
		0x16F1BF2149C3B962ULL,
		0xB54E3DE41EA5A192ULL,
		0x2880883F20D633A6ULL,
		0xA10B3FB75C4F444EULL,
		0xAC61621B7EFBEE19ULL,
		0xB7F7104A7D76CB46ULL,
		0xE93535ED7B33E0D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21CB528AF9E532B8ULL,
		0x62D61645BE5CEEE5ULL,
		0x0D90D206A2581068ULL,
		0x0D30B036B2660D0AULL,
		0x5A0C41768D18890CULL,
		0xECD99271449732BAULL,
		0x1D9BF240DB683DFBULL,
		0x0600858227A13AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47F3A59A99853AD8ULL,
		0x7427A964F79F5787ULL,
		0xB8DEEFE2BCFDB1FAULL,
		0x25B0380992B03EACULL,
		0xFB077EC1D157CD42ULL,
		0x40B8F06A3A6CDCA3ULL,
		0xAA6CE20AA61EF6BDULL,
		0xEF35B06F5C92DA3AULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BE5CBFE832EE9E7ULL,
		0xA16F8E7FE861DCE5ULL,
		0x472C743A4FE41BB7ULL,
		0x2AA152C2C9A37AD8ULL,
		0x552B364ABB50BEF5ULL,
		0xBE2C757DEFB426EBULL,
		0x658EC8C514F2B3CFULL,
		0xA96B7BCBACB01B82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C13D53BC15648B4ULL,
		0xB4050996B5CF99C2ULL,
		0xF601CC8D1541DBFBULL,
		0x7AAA4F0DB5CC2611ULL,
		0x8503C435E0EB1165ULL,
		0x6D900C571462AEAEULL,
		0xE51B3D3DE429605DULL,
		0x7EC81989BA953F4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77F61EC54278A153ULL,
		0x156A87E95DAE4527ULL,
		0xB12DB8B75AA5C04CULL,
		0x500B1DCF7C6F5CC9ULL,
		0xD028F27F5BBBAF90ULL,
		0xD3BC792AFBD68845ULL,
		0x8095F5F8F0DBD392ULL,
		0xD7A36242162524CDULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C751B9860FC1336ULL,
		0xD76F306B7D17C11EULL,
		0xA983B5B483731333ULL,
		0x368BD550063C3BE8ULL,
		0xE73BDADDC1F3FDEFULL,
		0xBF313F0B37D0B044ULL,
		0x5DF9A446607BC00AULL,
		0x61EB4D953255CBFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x076E4275D49ACA80ULL,
		0xA371AD4FAE85780DULL,
		0x689A67D74B406076ULL,
		0x7FB94BF9D3D8B47AULL,
		0x370DEDA4CFF692EDULL,
		0x0B2A71699FDC3D19ULL,
		0x00394944FDEBFB59ULL,
		0xEFFCA8DA64893E13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B1B59EDB466D9B6ULL,
		0x741E9D24D392B913ULL,
		0xC119D263C8337345ULL,
		0x49329EA9D5E48F92ULL,
		0xD03637790E056F02ULL,
		0xB41B4E62A80C8D5DULL,
		0x5DC0ED029D903B53ULL,
		0x8E17E54F56DCF5EFULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC7A50224CAD3E12ULL,
		0x8C01068354006405ULL,
		0x2A86D85FA404A18BULL,
		0x66F88C6932E7C1F0ULL,
		0x781DEC67FDE01AC8ULL,
		0x50E73E05E77E7B57ULL,
		0xCB5E231A0C430D6FULL,
		0x6E8F06E7DFE6EDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6386D310E0120DDDULL,
		0xED0AC8054477B727ULL,
		0x416DF2C27292DF0FULL,
		0xC09C40A4A1CEAE87ULL,
		0x4F24D1F7EE39FCB2ULL,
		0xC2B854FF1E8C16C6ULL,
		0x89DCF6E8A4C0A9F8ULL,
		0xE6F57879A75761CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FFC8332ACBF33CFULL,
		0x610BCE861077D322ULL,
		0x6BEB2A9DD6967E84ULL,
		0xA664CCCD93296F77ULL,
		0x37393D9013D9E67AULL,
		0x925F6AFAF9F26D91ULL,
		0x4282D5F2A883A497ULL,
		0x887A7E9E78B18C17ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E79409BA7E72B9ULL,
		0x72D6C475FE7795D5ULL,
		0x0FFEE40E74D2CDADULL,
		0xAC397FEDDC93FA13ULL,
		0xEA798098D4493CFDULL,
		0xD7041E8C9768B183ULL,
		0xB164E1F54FC6CA7FULL,
		0xC95BE993209225BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9D8BC14B1F385BULL,
		0xBCD064292DB962C5ULL,
		0xDBC4E273422BE098ULL,
		0x67BB77A5591CCD3CULL,
		0xA6E895940C280200ULL,
		0xCB3A7B2BFDE497FFULL,
		0xC131CDB2BBA050BBULL,
		0x5C6C8083BEAC0FEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x387A1FC8F1614AE2ULL,
		0xCE06A05CD3CEF710ULL,
		0xD43A067D36F92D35ULL,
		0xCB820848858F372FULL,
		0x4C91150CD8613EFDULL,
		0x1C3E65A76A8C267CULL,
		0x70552C47F4669AC4ULL,
		0x953769109E3E2A56ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46577A92604DE1BAULL,
		0xF54CDABC80DD48BFULL,
		0xE6A1062689C2DD61ULL,
		0xC314E29BF639E22CULL,
		0xB228B9D99F545041ULL,
		0xDAF8599DABC08078ULL,
		0x45868175BCACDB0EULL,
		0x65276B14DB22A893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC69CAF5B42F20C3ULL,
		0x8202C64EE238D186ULL,
		0xD7FCE863823E438EULL,
		0xBB3DC417EEEB6D25ULL,
		0xD9D266723919BD1BULL,
		0x565FE39B1FAF88BAULL,
		0x6D1009AFB417DA08ULL,
		0x7206868B13E06048ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA3EB067D462C179ULL,
		0x774E1CF262E59939ULL,
		0x315DEE450BFC9EEFULL,
		0x7829268C18D28F09ULL,
		0x6BFADFABA64DED5AULL,
		0x8CA7BA06B46F08C2ULL,
		0x289688DA08BB0106ULL,
		0x1721ED9FC8C2C8DBULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95C0E100D06C2316ULL,
		0xE695F4C446859D58ULL,
		0x2E1A6EBBFD40EEDDULL,
		0x0FD04BC034142E1BULL,
		0x74C2F14EA972E016ULL,
		0x9A74F92D960724ADULL,
		0xB547613221EE432BULL,
		0x3F911F458B14CAACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145C0DA2F8AEDCE4ULL,
		0x6C996DF89254196DULL,
		0x6F37290CDF1EA1CEULL,
		0x2815667196D032DAULL,
		0x9742C38151E8CF7CULL,
		0x1B8A1791516F8431ULL,
		0x4E0795FE67585A10ULL,
		0xDBDC190D3EF87037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x819CECA228C2FFF2ULL,
		0x8A0C993CD4D18435ULL,
		0x412D47B7225E4F13ULL,
		0x27C52DB1A2C41CC1ULL,
		0xE38032CFF89A2F6AULL,
		0x81FEEEBCC768A09CULL,
		0xFB40F4CC46B6193BULL,
		0xE44D0648B5ECBA9BULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7C90EA571013DE7ULL,
		0x4DA15A079BB6813DULL,
		0xC73EC7A2AC4F87CCULL,
		0x1659BC5D8A2A0BBAULL,
		0xA5033C844F790E35ULL,
		0x1E7651B14CCAA335ULL,
		0x1403BC1D73A871C0ULL,
		0x73781FCDE1D536B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7119EDE9E30107ULL,
		0x26EEB35983290BADULL,
		0x6B1DD1E15B89E2E8ULL,
		0xFEC7F94AA31C6011ULL,
		0x48AEA0524F3B37E5ULL,
		0xB13816BC50FF2F66ULL,
		0xACC593A8078A5140ULL,
		0x0F693B63DA86D87EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAB8174898E23CE0ULL,
		0x6B4FE95E189F8A90ULL,
		0xAC231643F7C66524ULL,
		0xE89E451729366BABULL,
		0xEDAD9CD6004239D0ULL,
		0xAF4E470D1C358C53ULL,
		0xB8C62FB574222080ULL,
		0x7C1124AE3B53EEC8ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B2BE2066B389DD0ULL,
		0x6001C3C56B47F11AULL,
		0xCBFBFBB6F8664E8DULL,
		0xF4A7470AE8760153ULL,
		0x690168C21CD9FF5CULL,
		0xD2571C4D16AAC085ULL,
		0x7E828ABC42ED3798ULL,
		0x107600BC13722BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB35CB83D4732A1A4ULL,
		0x37CD55B5A9F1F51BULL,
		0x4D83BB987565BDB5ULL,
		0xD5139E778C846E00ULL,
		0x69C6322391957423ULL,
		0xC0544E8AD1EC81BFULL,
		0x669EBE2A375AC76EULL,
		0x4DC137474BD4E875ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8775A3B2C0A3C74ULL,
		0x57CC9670C2B60401ULL,
		0x8678402E8D03F338ULL,
		0x21B4D97D64F26F53ULL,
		0x00C75AE18D4C8B7FULL,
		0x120352C7C746413AULL,
		0x181C349675B7F0F6ULL,
		0x5DB737FB58A6C3C7ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A18F428028EC844ULL,
		0x5C93FF0F6125B536ULL,
		0x53C1BCA8F1C31DA8ULL,
		0xB7E8ABBFA40DF5EDULL,
		0x1A1152D53FA9D2CFULL,
		0xACF3E225C9C30446ULL,
		0x4E3152216C52F9C6ULL,
		0xDFF3172D492F8FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE905B2A40CB30CD9ULL,
		0xEAD28504C0438313ULL,
		0xA2CDC9660E7B725CULL,
		0x94E61CB7EAD7D162ULL,
		0x2C7F27B42855050BULL,
		0xF6FFABCE34947844ULL,
		0x7D3CD92DCC2F548EULL,
		0xC086EA02F3AF31B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x631D468C0E3DC49DULL,
		0xB6417A0BA1663625ULL,
		0xF10C75CEFFB86FF4ULL,
		0x230EB7084EDA248FULL,
		0x366E756117FCD7C4ULL,
		0x5A0C49EBFD577C02ULL,
		0x330D8B0CA07DAD48ULL,
		0x1F75FD2FBA80BE72ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C99098EA11003BEULL,
		0x35CDE8AF06781836ULL,
		0xF493F6A2D015D0DFULL,
		0x0B632812ADBAC237ULL,
		0x1FA5CB0DBE5C490AULL,
		0x816AD9E2EE294E7EULL,
		0xAD53363D6A86376EULL,
		0x305AAC0196037DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1701B249F0F09F3FULL,
		0x12807BC642DAD50CULL,
		0xFFD65A12DC132501ULL,
		0xE88BFECC0A5C4A84ULL,
		0xBED1B50A69A4C161ULL,
		0x49DDD3210B688D3DULL,
		0x328BA06BE3B279AAULL,
		0x3C836E5F61DD815AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B98BBC751E09C81ULL,
		0x274D936944A2CD3AULL,
		0x0B45ACB00C06F5DEULL,
		0xE3E8D6DEA7E688B3ULL,
		0xA1747E07D7F8886BULL,
		0xC8B70AC3E541C343ULL,
		0x9FD8965689344EC4ULL,
		0x0CD9C25EF7DEFCAAULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x419F5C29DA535F52ULL,
		0x4A5EDE977BCBB54FULL,
		0xAB6A8EF8869439CAULL,
		0xBFB7EB621847513FULL,
		0x10801F47A183230FULL,
		0xFC9D3700CFF2016BULL,
		0x1D471977547B5329ULL,
		0x1B0E918F48AE4E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF94B01749A68D3ULL,
		0x239494CE3F0C7136ULL,
		0xA128857F1AAD0BFEULL,
		0xF21EB9F37AB2BF1BULL,
		0xBA1EDE1F4E3B2EEAULL,
		0x6A8DC6E8832A3ED9ULL,
		0x19EFDFC528F3B9ACULL,
		0xA7A591BFD9358AADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E661728AEC93781ULL,
		0x69CA4A5944C7C479ULL,
		0x0A420B879C393234ULL,
		0x4DA9529162F5EE24ULL,
		0xAA9EC158EFB80DE5ULL,
		0x9610F1E84CD83FB2ULL,
		0x04A8C6B27C88EA85ULL,
		0xBCAB0030919BC4E3ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C9E2E85FE81673BULL,
		0x82A7F6F8C3CE7AF5ULL,
		0x938A664E61F93055ULL,
		0xEED97AC2F475504FULL,
		0x8E28DDAE23F5AF2BULL,
		0x440078E087064CACULL,
		0xCE435939D4453614ULL,
		0x34E5ED877415A689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B5ED7CF3CC0EE1CULL,
		0x63D8A2C0E8A330E9ULL,
		0x416CD0730E068A57ULL,
		0x3C26DB506A57C25BULL,
		0x463D2CD41455BB92ULL,
		0x67F31DBD48990B5CULL,
		0x852B6D6EC4316475ULL,
		0xDAF5B2FD1205759FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7C0F94AC2418927ULL,
		0xE17F54382B6D4A1CULL,
		0xD2E6B63D6FFFBA02ULL,
		0xD2FFA1929E229214ULL,
		0xC815F17A37A014B9ULL,
		0x23F3655DCF9F47F0ULL,
		0x4B68345710745261ULL,
		0xEE105F7A6610D316ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25103D242DF17BCCULL,
		0xE67E7B659415D16BULL,
		0x6CB8A89E87825AC3ULL,
		0x3810CCE9C03C02E6ULL,
		0x54A5F93C4CDDFE0EULL,
		0x29FE7586F9494362ULL,
		0x850EA586F1B0F9A3ULL,
		0x70AA59D70C350B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47879F9A155187E4ULL,
		0x42B83BDB97672065ULL,
		0x513D579CAAAF8135ULL,
		0xA30760AB5132C6A5ULL,
		0xC05AB8A0234809E4ULL,
		0x97FA482AEC767555ULL,
		0xBF99E16388F5CAE9ULL,
		0xC3B6AFBD2DD5BC43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6297A2BE38A0FC28ULL,
		0xA4C640BE0372F10EULL,
		0x3D85FF022D2DDBF6ULL,
		0x9B17AC42910EC443ULL,
		0x94FF419C6F95F7EAULL,
		0xBE043DAC153F3637ULL,
		0x3A9744E57945334AULL,
		0xB31CF66A21E0B70EULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCE724687AAE5DC0ULL,
		0xE1F7FF0A15F68EE9ULL,
		0x4D92BF74C5E95690ULL,
		0xD68186B599782A2CULL,
		0xC65C9067B8E61250ULL,
		0x294977FDB147ACB7ULL,
		0x5E490E0254AAEBC1ULL,
		0xB422F752A4ED35BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF299BE5B5963253BULL,
		0x2AA0C4F098097E70ULL,
		0x479BB904C87C67D3ULL,
		0x889978B458E9F27FULL,
		0x81B46D8AAC3AD926ULL,
		0xF3138D891EE28B49ULL,
		0x0B732788BE2E4D4BULL,
		0x601636954ED01F60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E7E9A3323CD78FBULL,
		0xCB573BFA8DFFF099ULL,
		0x0A0906700D953143ULL,
		0x5E18FE01C191D853ULL,
		0x47E8FDED14DCCB76ULL,
		0xDA5AFA74AFA527FEULL,
		0x553A298AEA84A68AULL,
		0xD434C1C7EA3D2ADBULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9CCE8F5108FD0ACULL,
		0x58BC70DD3F9A46BCULL,
		0x8908E9B8DF8BB0F8ULL,
		0xBCC2E7EF67F6F837ULL,
		0x3D1B1EF9A16C471AULL,
		0xE4E1F369D6096168ULL,
		0x872449707EF49E48ULL,
		0x91808629F427E03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x485F4642BF449A39ULL,
		0xB14A36E6ECBAE0CFULL,
		0x751543D85027DC77ULL,
		0xDDE9E19E69699A52ULL,
		0x732C0CF964489C56ULL,
		0xF285E8DA9036553DULL,
		0x64C38BCF1F059242ULL,
		0xA7B371D03AEA9EAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB193AEB7AFCB4A95ULL,
		0xE9F6463BD320A673ULL,
		0xFC1DAA608FAC6C8FULL,
		0x612B06710E9F6265ULL,
		0x4E371200C524DB4CULL,
		0x16641BB3463F3455ULL,
		0xE3E7C2BF61F10C0AULL,
		0x3633F7F9CECD7E97ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66EBB2A95A2455CDULL,
		0xC7EBA4754792D6E1ULL,
		0x384750597C7A6B61ULL,
		0xBD0451919D911B82ULL,
		0xD15610DFF20FBB49ULL,
		0x2C9E70A61C8567ECULL,
		0xCC21B81AB37A84FBULL,
		0x1B7D90A98F46DD69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23709C26A1514966ULL,
		0xAA3AE89FBB468519ULL,
		0xDD5C6771889AE5DDULL,
		0x346C3A2C9F1AC312ULL,
		0x1FB9BABB1C76E6E8ULL,
		0xD92994DCDFE56FD0ULL,
		0x4AA3E19091C2AA3DULL,
		0x01F9E86FAFCCFC2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x459B2E8FFB751CABULL,
		0x6DD14CEAFCD453F8ULL,
		0xE51B3728F4E08EBCULL,
		0x89686BBD028BD890ULL,
		0xCEEFAA64EE795DA1ULL,
		0xF5B7E47AC360083CULL,
		0x8682598A22B82EC6ULL,
		0x1A8478C6208A2147ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01CD957F918BDD15ULL,
		0x6D421D1A6A345FDEULL,
		0x9AF133CD6ECEF41CULL,
		0x591CC8B59EEEFF5EULL,
		0xB9D6A652275DC707ULL,
		0xFE2DE33288D3BC0FULL,
		0x31D7DEF6B87443F1ULL,
		0xA9840555686BE991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE948EEC8E20BAFE2ULL,
		0xDDA4DDA40E120BBCULL,
		0x638452093637E476ULL,
		0xC96050A8C646752DULL,
		0x2809F68A5FEA347CULL,
		0x44BB22EC253D26F1ULL,
		0x10F1A44F0118DAA8ULL,
		0xCDDDEAC44271D177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8857BB7738072F7ULL,
		0xB0E6C0BE64265462ULL,
		0xF97561C458F9106AULL,
		0x907C981D58A88A73ULL,
		0x91DF50D878B7F37BULL,
		0xBA96C1DEADEE9AFEULL,
		0x21267AB9B96C9959ULL,
		0x6459EF912A1A38E6ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D8DE0C0A78FA83BULL,
		0x5AD763A51C767B25ULL,
		0x380E4B5415A8525BULL,
		0xFFA4A0D328CF04B3ULL,
		0x260D3C559910C461ULL,
		0x1EF75504933FCDBBULL,
		0xFD32BAD399EAE693ULL,
		0x25017682BADF77D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38ED02B5C5B17A57ULL,
		0x0ED746A15C68EEE1ULL,
		0xB8CB65CF450D9B3FULL,
		0x59A8E9991FFBCF59ULL,
		0x1728A22EE79F4035ULL,
		0xD56B42F23C53B9AFULL,
		0x84918C7D4BB1C8E2ULL,
		0xFC16B3BCDD3F1006ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3560E275623ED26CULL,
		0x54002504401E95C4ULL,
		0x80C52E9B50A5C964ULL,
		0xA60C494A3734CBEAULL,
		0x31259E7B7E8F8454ULL,
		0xCB9C17F6AF6C7414ULL,
		0x79A336AED25B2E71ULL,
		0xD917C53E67E067D7ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA56B83D2B12D278CULL,
		0x1633CC3A5154081BULL,
		0xD36581267C226C75ULL,
		0x588DD5EE1F103CF4ULL,
		0x05BE45ACBC53BA3CULL,
		0x0F04FD32218A3B6AULL,
		0x10B80A83797A1C74ULL,
		0x41EED20BD9B2D3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB1A004375102522ULL,
		0xC571FAE4739A2456ULL,
		0x502647C16A8B3F68ULL,
		0x4AA447910A7A092EULL,
		0x516CA8CFAD4C3DC1ULL,
		0x2A0AFAC8F1CBF923ULL,
		0x6CAFD81B3721E388ULL,
		0x34E9CE63E153D3C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E718391C43D02AEULL,
		0xD34236DE22CE2C4DULL,
		0x8343C6E716A9531DULL,
		0x1229927F156A35DAULL,
		0x54D2ED63111F87FDULL,
		0x250E07FAD041C249ULL,
		0x7C17D2984E5BFFFCULL,
		0x75071C6838E1007FULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58C08E5EF3F734ECULL,
		0xC635B58BDDB75D1CULL,
		0x1C55723B1BA002B9ULL,
		0x79FBF5B1C78A7625ULL,
		0x989AC0C0A883EF2AULL,
		0x6AEC4F1B0798B321ULL,
		0xFB5E6FEBE0996720ULL,
		0xBB0313D06E9626DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78706D6B000F2CFULL,
		0x2BE09DEF43235A6EULL,
		0x321881624725F10AULL,
		0x673FD201712556C0ULL,
		0x3E34472E9120B61BULL,
		0x9562B69EF076648CULL,
		0xDDC89DA42FC3575CULL,
		0x38ECC2DF8F6C77CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F47888843F7C623ULL,
		0xEDD528649E940772ULL,
		0x2E4DF3595C85F3B3ULL,
		0x1EC427B0B6AF20E5ULL,
		0xA6AE87EE39A35931ULL,
		0xFF8EF985F7EED7ADULL,
		0x2696F24FCF5A307CULL,
		0x83EFD10FE1FA5113ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8429956D3B7F0285ULL,
		0xE45C9DE986D1296FULL,
		0x7352CA7122595748ULL,
		0x7BD44D393E5BA9F2ULL,
		0x0001E1604121E6EBULL,
		0x75BDF86DFC823E25ULL,
		0xAEEA8E60019ACA22ULL,
		0xE95174320571532EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8788E68FD258B004ULL,
		0x43A436F478212A8AULL,
		0x9D4C5BD21FCF3FE4ULL,
		0x9B53D1117C2301A9ULL,
		0xD2883776F675D57FULL,
		0xDBB82DCC8968E16BULL,
		0x2DE01C7D6CF3160EULL,
		0x3BA87A79C280A793ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A173E2E927B281ULL,
		0xA7F8AB1DFEF003E5ULL,
		0xEE1E91A33D9668ACULL,
		0xE0879C284278A85BULL,
		0xD289D616B7543394ULL,
		0xAE05D5A175EADF4EULL,
		0x830A921D6D69DC2CULL,
		0xD2F90E4BC7F1F4BDULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3242982BC25420AULL,
		0x6946DE0DE975478DULL,
		0x55673D4556A874DDULL,
		0x7D4B59890BB23E9CULL,
		0xDDF437097970C91CULL,
		0x9F71824C93A79D27ULL,
		0xB0CE5248BDCA1FA1ULL,
		0xB3B457C4E42ED388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB17613538E06C4ULL,
		0xB81CFF2A2BE07AB0ULL,
		0xA6F4B1F16D4ECEB0ULL,
		0x86E3971ED2ECE46DULL,
		0x487693511E23B825ULL,
		0x4029FAF8A81564FFULL,
		0xC1F9D05500B59CF0ULL,
		0x5AA8CD8513D6DA65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D955F91EFAB44CEULL,
		0xD15A2127C2953D3DULL,
		0xF3938CB43BE6BA6DULL,
		0xFBA8CE97D95EDAF1ULL,
		0x9582A45867537139ULL,
		0xDF5878B43BB2F9D8ULL,
		0x7137821DBD7F8351ULL,
		0xE91C9A41F7F809EDULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAAAA46E83095ECCULL,
		0x00B56A7C1F4882C4ULL,
		0x98E09F47E4DEB261ULL,
		0xF85BE4F7AEDD86B9ULL,
		0x035198890FA8313DULL,
		0xA97FDDF132C3A141ULL,
		0x8CF9E27C797A8012ULL,
		0xE896B59326C5A3D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D703E921E1D89BULL,
		0xB43BF579C20B2FDDULL,
		0x24E029AB2D84656AULL,
		0x4AD5087972566C35ULL,
		0x8F9AB95EF503B1E5ULL,
		0x72C925493EF55C6CULL,
		0xB51207A18E9F446DULL,
		0x69FA247DC01F2E33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B7DA787A2E88657ULL,
		0xB48E9F05DD43AD19ULL,
		0xBC00B6ECC95AD70BULL,
		0xB28EEC8EDC8BEA8CULL,
		0x8CCB21D7FAAB80D8ULL,
		0xDBB6F8B80C36FD2DULL,
		0x39EBE5DDF7E5C47FULL,
		0x816C91EEE6DA8DE1ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BFDF47E91ABF1C8ULL,
		0xAE6A2E6447096C54ULL,
		0x7BDC4AD93F6FD016ULL,
		0x4B9ABD4C8C55A2BAULL,
		0xD2D84CD917EE471DULL,
		0x2FCBCECB6BAD6CE2ULL,
		0xEE025092BB09259AULL,
		0xB748F4AA320FFFF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB881E840A8C3A3ULL,
		0x31D3559559ECC631ULL,
		0x56449AF8206322C5ULL,
		0x80B0971DA053BE76ULL,
		0xE52BDDFBAA7B8B56ULL,
		0xA0028D9D73C9F41AULL,
		0xC45265470F67B25BULL,
		0x20BD2425DC3A5DEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6457596D103326BULL,
		0x9FB97BF11EE5AA65ULL,
		0x2D98D0211F0CF2D3ULL,
		0xCB2A2A512C061CCCULL,
		0x37F39122BD95CC4BULL,
		0x8FC94356186498F8ULL,
		0x2A5035D5B46E97C1ULL,
		0x97F5D08FEE35A21DULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77C03DD64D0BCF4FULL,
		0x67871CB0778A53FFULL,
		0xC66136662BE337DCULL,
		0x148E2BB5C24F84EFULL,
		0xCFAE8E83E8A183B5ULL,
		0x832D8D6162A5A8DCULL,
		0x82EBD79649ED3618ULL,
		0x85C58B5E9E89EDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E045992C1791EB0ULL,
		0xB29F9B532C61EA2AULL,
		0xEC2F96FFAAF2ACA5ULL,
		0xD946C9880C286F04ULL,
		0xF2793DAF065521D7ULL,
		0x5BF61E879C030E62ULL,
		0xAEF3D173F9D6D229ULL,
		0x753FA7E61E83F018ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49C464448C72D1FFULL,
		0xD51887E35BEBB9D5ULL,
		0x2A4EA09981119B79ULL,
		0xCDC8E23DCE67EBEBULL,
		0x3DD7B32CEEF4A262ULL,
		0xD8DB93E6FEA6A6BEULL,
		0x2C1806E5B03BE431ULL,
		0xF0FA2CB8800A1DCFULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DBC83930C90A767ULL,
		0xA48D9CE937A0DAF7ULL,
		0x1DE29C48C15813FEULL,
		0xF1AD6315ECB98CEBULL,
		0x13D83A3A1E60F50FULL,
		0xB196E92EC303523DULL,
		0x02C44C3DD4D75A40ULL,
		0xFF93E4DDBB036E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6A202D1901E486ULL,
		0xE6F0C2759D75385AULL,
		0xE39E8D8664B3A496ULL,
		0x675DEA282A1F4D1AULL,
		0x70EE6E4842896DC1ULL,
		0x1655B85BBB918C83ULL,
		0x4D4B41A273D219AEULL,
		0x8B98F990A3E2BDFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90D6A3BE159143E1ULL,
		0x427D5E9CAAD5E2ADULL,
		0xFE7C11CEA5EBB768ULL,
		0x96F0893DC6A6C1F1ULL,
		0x633654725CE998CEULL,
		0xA7C351757892DEBEULL,
		0x4F8F0D9FA70543EEULL,
		0x740B1D4D18E1D3FCULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC59C368529394866ULL,
		0x874BD3469BDB5517ULL,
		0xC0564B8FE7AAD8DEULL,
		0x0B7A69139F1D8935ULL,
		0xE6F442DF0621C493ULL,
		0x1739155C3419C730ULL,
		0xD79330C5C7F60F17ULL,
		0x70684513A176EDE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AEF92E687DD64E4ULL,
		0xD59EF6E29A8F7258ULL,
		0x44D317B5DCC0B0A3ULL,
		0x0B3B06B8CD793198ULL,
		0xF50EA9D4F267FDF5ULL,
		0x89064B43F7358326ULL,
		0xCF04256720D04F19ULL,
		0x4DFA0FE660665486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF73A463AEE42C82ULL,
		0x52D525A40154274FULL,
		0x84855C3A3B6A687DULL,
		0x00416FAB5264B8ADULL,
		0x13FAEB0BF4463966ULL,
		0x9E3F5E1FC32C4416ULL,
		0x189715A2E726400EULL,
		0x3D924AF5C110B967ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C681435CA36EAAEULL,
		0x87D4C4D92B597B91ULL,
		0x76915BAF36765186ULL,
		0xB5CACB0F632B056DULL,
		0x33BC8169D57FE353ULL,
		0xF29D5611028169E3ULL,
		0xF9FDB77349C7E197ULL,
		0x36916F1A0B08581BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x109CFD2AD63807CAULL,
		0x0905623F5DFA85CDULL,
		0x216CEB2E7C461850ULL,
		0xF3308309866975E5ULL,
		0x3C90525776D72A15ULL,
		0x1698A8AD95138704ULL,
		0xA2EBB14492A1CEEAULL,
		0x699A18A7487A585DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CF4E91F1C0EED64ULL,
		0x8ED1A6E676A3FE5CULL,
		0x57FDB0814A3049D6ULL,
		0x46FA4806E5427088ULL,
		0x0F2CD33EA3A8C946ULL,
		0xE405FEBC9792EEE7ULL,
		0x5B160637DB662F7DULL,
		0x5F0B77BD43720046ULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1859286439F61103ULL,
		0x8FF8869C5BC084F2ULL,
		0x6EC1C64B59C07FD8ULL,
		0x71C5BF09F65951C4ULL,
		0x5A67BD504ABAA427ULL,
		0xB0D609F79B809743ULL,
		0xC7AF7B4A3A127541ULL,
		0xD93C6FE16BD0FAB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB774F30CB8DA01ULL,
		0x03570156DD57CB92ULL,
		0xCD9343C0C133E5B0ULL,
		0x10C2329447C8B073ULL,
		0xBF42EDB527254EF7ULL,
		0xA01405C6844F5220ULL,
		0x061D2A0CDCDA95C7ULL,
		0x00B5ADB104F19E05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7EE5C97354ECB02ULL,
		0x8CAF87CA86974F60ULL,
		0xA352858B98F39A68ULL,
		0x61078D9DB191E1B7ULL,
		0xE52550E56D9FEAD0ULL,
		0x10C20C311FCFC563ULL,
		0xC1B25146E6C8E086ULL,
		0xD989C2506F2164B0ULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC57FE192B57956F1ULL,
		0x150E06465C2C7F5EULL,
		0x64B749BB482736B7ULL,
		0x1DA974F107A66506ULL,
		0x0222B3B53F48833BULL,
		0xC2A8735E8B579856ULL,
		0x0F81DE8E360986B2ULL,
		0x1F2789AF7C64F081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A70E94897281F0ULL,
		0x6BF0FFE80F0BEA74ULL,
		0x90660C18921590C1ULL,
		0x179E979BEF39003EULL,
		0x27DDB09581F3749CULL,
		0x5DF31502F0C88B2DULL,
		0xC02974A951F20857ULL,
		0x106F046B57EF36A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34D8EF063C0BD701ULL,
		0x7EFEF9AE5327952AULL,
		0xF4D145A3DA32A676ULL,
		0x0A37E36AE89F6538ULL,
		0x25FF0320BEBBF7A7ULL,
		0x9F5B665C7B9F137BULL,
		0xCFA8AA2767FB8EE5ULL,
		0x0F488DC42B8BC627ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE531D00B429189FEULL,
		0x30E22A703D425786ULL,
		0x82954028105EC14CULL,
		0xC16EFD6DBCC83576ULL,
		0x0E16A9E3D6C0E89BULL,
		0xAB0BD5EC23B679A2ULL,
		0x9725B5B011772824ULL,
		0xBAA85836C6E9E861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD13BE3B8B72AEBC0ULL,
		0xD2998EB3D520E611ULL,
		0xC5800303BB434149ULL,
		0x96CCA9059235559FULL,
		0xD053ED8034F4210FULL,
		0x71485D58859ADAA7ULL,
		0xB6D0799A9CB07E89ULL,
		0x44A14C75223570CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x340A33B3F5BB623EULL,
		0xE27BA4C3E862B197ULL,
		0x4715432BAB1D8005ULL,
		0x57A254682EFD60E9ULL,
		0xDE454463E234C994ULL,
		0xDA4388B4A62CA305ULL,
		0x21F5CC2A8DC756ADULL,
		0xFE091443E4DC98AEULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B560859D5D68AE3ULL,
		0xB4D7C05308367E9CULL,
		0x27F54F4EA9D9B70DULL,
		0x2B82E947DFA7B99DULL,
		0x34D2BC3CC621DC1BULL,
		0x8F2299E0BFE7B30FULL,
		0x57F25886E237FFBEULL,
		0x0139B07509E0A8BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80FA09FC1063F104ULL,
		0xBB7A5561E81E8DD5ULL,
		0x5E5FF791CEDB8534ULL,
		0x992DEFC72186C7A3ULL,
		0xD99AA8F0D85A48A8ULL,
		0x57DC0692B807B264ULL,
		0x2884622A2F7759CEULL,
		0xB3622DDC881E55C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BAC01A5C5B57BE7ULL,
		0x0FAD9532E028F349ULL,
		0x79AAB8DF67023239ULL,
		0xB2AF0680FE217E3EULL,
		0xED4814CC1E7B94B3ULL,
		0xD8FE9F7207E0016BULL,
		0x7F763AACCD40A670ULL,
		0xB25B9DA981FEFD78ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x758D050504CE0001ULL,
		0xE4102D083774DF8EULL,
		0xD2A992814C5676C0ULL,
		0x182EBDF15043C826ULL,
		0x9310A425C0871783ULL,
		0x328AEA167160D585ULL,
		0x101B25A9719011E3ULL,
		0x2BD7E9BCC67C3A35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DF8AE3AD523842CULL,
		0xCE9D1A14228D4DE1ULL,
		0x0E8F061D0E9A9390ULL,
		0x93CD6A745B1A848CULL,
		0x3D6DB13563A48170ULL,
		0xD499FAB94D821788ULL,
		0xD34AEDBC46635E6AULL,
		0xEFB3DFC76E2D0AA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1875AB3FD1ED842DULL,
		0x2A8D371C15F9926FULL,
		0xDC26949C42CCE550ULL,
		0x8BE3D7850B594CAAULL,
		0xAE7D1510A32396F3ULL,
		0xE61310AF3CE2C20DULL,
		0xC351C81537F34F89ULL,
		0xC464367BA8513094ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C27F3FA2B02840EULL,
		0x712E05857E61628BULL,
		0xB18E9CE0B783C6F3ULL,
		0x2E0F9BA3C4694A47ULL,
		0x5DEAE3B05068C5FAULL,
		0xA40938306FDD0C95ULL,
		0x62D934A32B5F6356ULL,
		0x0B68D7B779843DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78FA7EE6BE3C606DULL,
		0x09FCC06121C58BC8ULL,
		0xDDB463F3402D912BULL,
		0xD0EB2100D5208762ULL,
		0x578A50986BB3D972ULL,
		0x5E8F1E3C88F2226BULL,
		0xC506F979C13D498DULL,
		0x5F6272017A61C3B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74DD8D1C953EE463ULL,
		0x78D2C5E45FA4E943ULL,
		0x6C3AFF13F7AE57D8ULL,
		0xFEE4BAA31149CD25ULL,
		0x0A60B3283BDB1C88ULL,
		0xFA86260CE72F2EFEULL,
		0xA7DFCDDAEA622ADBULL,
		0x540AA5B603E5FE0CULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x473EBDA924A680E5ULL,
		0x0145F484EE7FD214ULL,
		0xB25A489CCD4A5B3AULL,
		0x80E4BAC9F3290B94ULL,
		0x90A44D168A436002ULL,
		0xA9BD76622C7BEED7ULL,
		0xF7CFCDF1B08FA053ULL,
		0x19CC853789443CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2FFA5ED49E9FF76ULL,
		0x29C03FCB8E3A1F7EULL,
		0x424125D0432556E0ULL,
		0x050E602E93A14FFEULL,
		0x0C1AF65F0537D0FDULL,
		0x0C469CAAB3523BD8ULL,
		0xB7A109BD837929EDULL,
		0x14CAC62038D4A0CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5C118446D4F7F93ULL,
		0x2885CB4F6045CD6AULL,
		0xF01B6D4C8E6F0DDAULL,
		0x85EADAE76088446AULL,
		0x9CBEBB498F74B0FFULL,
		0xA5FBEAC89F29D50FULL,
		0x406EC44C33F689BEULL,
		0x0D064317B1909C7CULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEDC8959FC07D002ULL,
		0x526F34D896BCB76FULL,
		0xEE5F3BB60F31D964ULL,
		0x9CF1B667A893F91DULL,
		0xA23E15C0862A579BULL,
		0x647F0CB93B9B8C1CULL,
		0x8CEC797F408A0E77ULL,
		0x4330EA7207932127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF1154A509FF1611ULL,
		0x4604F6B90CC29C72ULL,
		0x48BB9BDB88D38FD2ULL,
		0x7004CFDCE7976B9FULL,
		0xEBC0ADE57D14D77BULL,
		0xF2A3E129945524E4ULL,
		0xB33D33B08AEEDC16ULL,
		0x037F319E2246AA81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11CDDDFCF5F8C613ULL,
		0x146BC2619A7E2B1DULL,
		0xA6E4A06D87E256B6ULL,
		0xECF579BB4F049282ULL,
		0x49FEB825FB3E80E0ULL,
		0x96DCED90AFCEA8F8ULL,
		0x3FD14ACFCA64D261ULL,
		0x404FDBEC25D58BA6ULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDE17D14A1FD4D39ULL,
		0x352B0B9115E3198BULL,
		0x6FA27CE37B9FD35EULL,
		0x892376B565921719ULL,
		0x2E4F9523BCB1A1FEULL,
		0xF187E47F359342D7ULL,
		0xEBA8ED151E26584DULL,
		0xE7C5D364D010D7E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC1D2F460177C7AULL,
		0xC9350370614FBDF4ULL,
		0xA341B36FAAF29A63ULL,
		0xBA2B17D5CDD30034ULL,
		0xEA867DA28E8A3181ULL,
		0xAE01D21DF0C6DE18ULL,
		0x037442F1EE8985CFULL,
		0x4364C5AFA811E71BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC020AFE0C1EA3143ULL,
		0xFC1E08E174ACA47FULL,
		0xCCE3CF8CD16D493DULL,
		0x33086160A841172DULL,
		0xC4C9E881323B907FULL,
		0x5F863662C5559CCFULL,
		0xE8DCAFE4F0AFDD82ULL,
		0xA4A116CB780130F2ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D85100161BB2E43ULL,
		0x15AF91468E0E1130ULL,
		0xA3649D9C83EB3103ULL,
		0x417F1D6D47FFC1C7ULL,
		0x53BA0C7EC787AED7ULL,
		0x1BF4E218D4732BFEULL,
		0x952E62A9EE603312ULL,
		0x091D2F543A196EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB108EA3EF19D8C13ULL,
		0x002157B5507EEBD8ULL,
		0x8B317544A45BAC96ULL,
		0x6E5D23D310C60E82ULL,
		0x2F70234A88A722EBULL,
		0x6716E92B2D8F3125ULL,
		0xF51914A576B31F67ULL,
		0x99ECAF242494E05EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC8DFA3F9026A250ULL,
		0x158EC6F3DE70FAE8ULL,
		0x2855E8D827B09D95ULL,
		0x2F223EBE5739CF45ULL,
		0x7CCA2F344F208C3CULL,
		0x7CE20B33F9FC1ADBULL,
		0x6037760C98D32C75ULL,
		0x90F180701E8D8EA3ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x424E5889C269A5FFULL,
		0xEDFCB3C5EC883AEAULL,
		0xD42AF50AF7729BFDULL,
		0x3803BCB2A791A21EULL,
		0x8FE63B65BFC3C740ULL,
		0x321CD37D2B7781DFULL,
		0x34D0204AB53131DCULL,
		0x77CDAFC1B87A01DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B50F56E3F92033ULL,
		0xA9303C71A3425B68ULL,
		0xE522FCB958161999ULL,
		0xEB6A2E5DB55CF2CFULL,
		0x360B8AE36C4464ADULL,
		0x67D25C00DF73BC80ULL,
		0xD25D3F07BE3701CCULL,
		0xC7BBC813194C1AF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1FB57DF219085CCULL,
		0x44CC8FB44FCA6182ULL,
		0x310809B3AF648264ULL,
		0xD36992EF12CD50D1ULL,
		0xB9EDB186D387A3EDULL,
		0x55CE8F7DF4043D5FULL,
		0xE68D1F4D0B063010ULL,
		0xB07667D2A1361B2DULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A64E18E56055C98ULL,
		0xA20CC91056E73AF6ULL,
		0xF0439E0ED59A12F2ULL,
		0xF225F1FC7C4C9F78ULL,
		0xF8CECA0DF15E63A4ULL,
		0x395A7BEB3C468C88ULL,
		0xF1DBFAE1C23C05CCULL,
		0xF5E9A2508C684F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B7A89D9EAE12DADULL,
		0xC4F78F7F1FA48B5FULL,
		0x979E7FDEFA5F3C88ULL,
		0xA2524B33CD5E4202ULL,
		0xFB5D181638B7A323ULL,
		0x864D19611663F91EULL,
		0xFBF15AE48BC4BAF2ULL,
		0x2F1B22FDEF624AF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x211E6857BCE47135ULL,
		0x66FB466F4943B1A9ULL,
		0x67DDE1D02FC52E7AULL,
		0x5077BACFB112DD7AULL,
		0x0393D21BC9E9C087ULL,
		0xBF17628A2A257596ULL,
		0x0A2AA00549F8BF3EULL,
		0xDAF280AD630A0561ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72DA6214D730231DULL,
		0x44A5F365FAEB3996ULL,
		0xEF4D14999ABBE85DULL,
		0xA464DBB2B4814B05ULL,
		0xA6F95F3B5A6007B8ULL,
		0x57DF0E0E1A0606F9ULL,
		0xD276D1EF7D038148ULL,
		0x890F9D83B7A90251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478F2D98E8196A76ULL,
		0x1DB2D0BC0BE975F0ULL,
		0x5D0543894DCEE2A5ULL,
		0x283265C5903A84F4ULL,
		0x6F28048794D4B9D8ULL,
		0x492D0835F54F9EA1ULL,
		0x8EA88335F4B4AEE3ULL,
		0xD5B4B935BA5F72DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35554F8C3F29496BULL,
		0x591723D9F1024C66ULL,
		0xB2485710D7750AF8ULL,
		0x8C56BE7724BBCFF1ULL,
		0xC9D15BBCCEB4BE60ULL,
		0x1EF2063BEF499858ULL,
		0x5CDE52DA89B72FABULL,
		0x5CBB24B60DF6708DULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x521E34C5A923076FULL,
		0xD3465A654FD2A2B2ULL,
		0xDC4C83734F67E299ULL,
		0x044F2AA44AE514BFULL,
		0x2E4DA7305057B4F0ULL,
		0x2D894797A3B67BE4ULL,
		0x0B817928F9388FA4ULL,
		0x93CFC34DF68265FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC812FEA7170189A0ULL,
		0x4361EDFF4B9810CAULL,
		0x6637B27AE66740FDULL,
		0x52945E278E77E316ULL,
		0x2B46EB7FA5493035ULL,
		0xA129A7DCEF78C8E4ULL,
		0x88DD0D839E81B791ULL,
		0x314E20988CDA96D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A0CCA62BE228ECFULL,
		0x9027B79A044AB278ULL,
		0xBA7B3109A900A264ULL,
		0x56DB7483C492F7A9ULL,
		0x050B4C4FF51E84C5ULL,
		0x8CA0E04B4CCEB300ULL,
		0x835C74AB67B93835ULL,
		0xA281E3D57A58F32CULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x770E495510620DCAULL,
		0x738FE42517381727ULL,
		0xB637AF1D2857713BULL,
		0x5CA4D7DA82A169C4ULL,
		0xB04AD7CAB90C4F3EULL,
		0xD912567945F3401AULL,
		0x6184CDC85583F154ULL,
		0x94006C4DF7CFC2DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F78D856C5009404ULL,
		0x2FDBA13E3BF08B3DULL,
		0x1636C691DE31A233ULL,
		0x5ACDA3A69F13FFA9ULL,
		0x70D60042990B7F09ULL,
		0x3209C059C0456D10ULL,
		0xC26060DA1D803435ULL,
		0x8FA2F4C14531FC71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8769103D56299CEULL,
		0x5C54451B2CC89C1AULL,
		0xA001698CF666D308ULL,
		0x0669747C1DB2966DULL,
		0xC09CD78820073037ULL,
		0xEB1B962085B62D0AULL,
		0xA3E4AD124803C561ULL,
		0x1BA2988CB2FE3EACULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC5F30EBB7279F3CULL,
		0xB76BC8B2A624EC78ULL,
		0xE3B522E6136EAC0AULL,
		0x09326F1165D8FD3CULL,
		0x76EB0AFA57A38CFBULL,
		0x90DA12A526A74ADAULL,
		0xE0A28EE040AA9073ULL,
		0xAC08BB80D00CAFD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB52DF7730961700ULL,
		0x4C65A0F4C50DF877ULL,
		0xEA528D44F3841F1AULL,
		0xD83ACA165F851417ULL,
		0x0123033B9DAB6F28ULL,
		0x3B2CB619C2EFB7B1ULL,
		0xE4AD03787ED53F69ULL,
		0x34D9C8E58907F242ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x070DEF9C87B1883CULL,
		0xFB0E68466329140FULL,
		0x09E7AFA2E0EAB310ULL,
		0xD108A5073A5DE92BULL,
		0x77C809C1CA08E3D3ULL,
		0xABF6A4BCE448FD6BULL,
		0x040F8D983E7FAF1AULL,
		0x98D17365590B5D93ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CCABF7DB3A5B445ULL,
		0xA77678BC9121828DULL,
		0x68DECA4AC9059ADBULL,
		0xAB166ED44C9AACA7ULL,
		0x54ABDC6A2844538CULL,
		0x78D3E22C354A18DDULL,
		0x8A297EFD9210D0B3ULL,
		0x96C79A93447EF5A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A33A1F1D172D389ULL,
		0xF801F7A0519C4658ULL,
		0x522361ED485FD5F3ULL,
		0x09A92E28BF3F5F04ULL,
		0xB0F28AB1F87992B9ULL,
		0xF8D42144B4E9D252ULL,
		0xB8FFA5DA01A6FAF0ULL,
		0x00E517586E796AACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06F91E8C62D767CCULL,
		0x5F778F1CC0BDC4D5ULL,
		0x3AFDABA7815A4F28ULL,
		0xA2BF40FCF3A5F3A3ULL,
		0xE45956DBD03DC135ULL,
		0x8007C36881A3CA8FULL,
		0x32D6DB2793B62A43ULL,
		0x96228DCB2A079F0BULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6EAEBCB63714744ULL,
		0x8EEE04835C86B3DAULL,
		0xDD3AD0082EA6B40AULL,
		0xA574490D5498ECEAULL,
		0x06BFB7EF2D99CE9FULL,
		0xC3795B0A6AEDD227ULL,
		0x8C7E825C75E7909DULL,
		0xF0B589A9B0381686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB8045315F98638ULL,
		0x6E913EF3EAED54C3ULL,
		0xBE9AB7E7D0EF9B84ULL,
		0xD2FD68271E367516ULL,
		0x82B8C2E4360AAD42ULL,
		0x34D28034881D4F00ULL,
		0x7B4D9A5105C5B989ULL,
		0xD895DE2D8173FC25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B52EF987688C17CULL,
		0xE07F3A70B66BE719ULL,
		0x63A067EFFE492F8EULL,
		0x7789212A4AAE99FCULL,
		0x8407750B1B9363DDULL,
		0xF7ABDB3EE2F09D27ULL,
		0xF733180D70222914ULL,
		0x28205784314BEAA3ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98FF8C26A20A0F35ULL,
		0x60BE83768EE5FAC6ULL,
		0xFA2AA126F23291D2ULL,
		0xFC8F7448AD5C557FULL,
		0xEC0BA9955901FBD5ULL,
		0x823F35AAB4E34105ULL,
		0x9F8287F6B4AA2E8EULL,
		0xF3C54D63E386B259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD859A8DC0BE94EFULL,
		0xCE8BFB33E6AD485EULL,
		0xA745B73D9BEDEB70ULL,
		0xAACE17E35DB7E751ULL,
		0x395CBB633C13727EULL,
		0x6D953618917BDF22ULL,
		0x674609327088BF65ULL,
		0xE0D1A8152AF77BD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x657A16AB62B49BDAULL,
		0xAE3578456848B298ULL,
		0x5D6F161B69DF7AA2ULL,
		0x564163ABF0EBB22EULL,
		0xD55712F6651289ABULL,
		0xEFAA03B225989E27ULL,
		0xF8C48EC4C42291EBULL,
		0x1314E576C971C980ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBCCDF0F0A947B7BULL,
		0x948B4013BFC4AB75ULL,
		0x749A8DF5C149420AULL,
		0x48602F3B74A9248DULL,
		0x7AA8B9AF0A4B7FA1ULL,
		0x78D53FFDC15AF4B8ULL,
		0x4B6ED20BE1C42AC2ULL,
		0x9A37EABAFDBA35B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6BE8EDC09146C8EULL,
		0x004CD9FE440C71BBULL,
		0x3593D8C74EB99DE8ULL,
		0xB5138796ABE3A5DDULL,
		0x65BAA98515B4D401ULL,
		0xD0F9113811A109C0ULL,
		0x008FE3B1B6DA4AA2ULL,
		0x048B97BB82D07F9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D7251D3038017F5ULL,
		0x94C799EDFBC8DACEULL,
		0x410955328FF0DFE2ULL,
		0xFD73A8ADDF4A8150ULL,
		0x1F12102A1FFFABA0ULL,
		0xA82C2EC5D0FBFD78ULL,
		0x4BE131BA571E6060ULL,
		0x9EBC7D017F6A4A2AULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4227A361DA3BAB57ULL,
		0xD8A859BA0B689BCAULL,
		0x78A96AA586E945E3ULL,
		0xECA82475179E5901ULL,
		0xE106EB1E4944FE43ULL,
		0x4621291C5EB0AF73ULL,
		0xA96F0FC76CB6B7C2ULL,
		0x19F7438056CCEA88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x089B5B16CF386469ULL,
		0x1570E3AA00465224ULL,
		0x0EB22A37053B956FULL,
		0xB5C10A2066C91998ULL,
		0x81163D4F760C57E3ULL,
		0xE3F47D4BE372FBEDULL,
		0xD4D3008B2A6A894AULL,
		0xF5A1958F5ECE93DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ABCF8771503CF3EULL,
		0xCDD8BA100B2EC9EEULL,
		0x761B409283D2D08CULL,
		0x59692E5571574099ULL,
		0x6010D6513F48A9A0ULL,
		0xA5D55457BDC2549EULL,
		0x7DBC0F4C46DC3E88ULL,
		0xEC56D60F08027957ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6490359FA2AB8320ULL,
		0xDE49F562501CDA0FULL,
		0xD59AC6775D38A2D1ULL,
		0x740EF45DF4E591C1ULL,
		0x85B0564F53B3124DULL,
		0x3FB89D0F910FAD46ULL,
		0x9A91932C542E4442ULL,
		0x6632B0DCB43E0443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A163109E67F6955ULL,
		0xE1C38B59276696F9ULL,
		0xFC97A6C6860B6B0CULL,
		0x2BAC4C48ED93BAB7ULL,
		0x829664E6294150B6ULL,
		0x3EB129D28B2CF480ULL,
		0x5D6FF2770BE73FBBULL,
		0xD1ED64AB5EEF1067ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E86049644D4EA75ULL,
		0x3F8A7E3B777A4CF6ULL,
		0x290D60B1DB33C9DDULL,
		0x5FA2B81519762B76ULL,
		0x072632A97AF242FBULL,
		0x0109B4DD1A2359C6ULL,
		0xC7FE615B5FC97BF9ULL,
		0xB7DFD477EAD11424ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC1A0E9EF8AF2D5BULL,
		0x54305475A9D90515ULL,
		0x126A3D626450E250ULL,
		0x955A971EC4CD6AC9ULL,
		0x381812A5448C57ABULL,
		0x4657385DE859E207ULL,
		0x1F783D451645E40FULL,
		0x3801615B8E85CEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623E6C1CD225634EULL,
		0x229374B514903A95ULL,
		0x1CE6C17E034B9BA1ULL,
		0x455D55ECF77DB621ULL,
		0xB0360949B10C565EULL,
		0xA7C33BA2699E6622ULL,
		0xC755F37E860C58CDULL,
		0x65C6536A885BBB50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE2462822A8A4E15ULL,
		0x76A320C0BD493F80ULL,
		0x0E8CFC1C671B79F1ULL,
		0xD007C2F233B0DCE8ULL,
		0x882E1BECF58001F5ULL,
		0xE19403FF81C78425ULL,
		0xD82DCE3B9049BCC2ULL,
		0x5DC7323106DE758CULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x744B3731FDB5B416ULL,
		0x1818656BD59B80AAULL,
		0xE9208BEC72839C25ULL,
		0x87504ED80CEBD79DULL,
		0xD8227EFBD3CC8E45ULL,
		0x3A33DAD8BBE11A1BULL,
		0x6E7B91BA59A3CBEDULL,
		0xDD2C5A2C2F74630EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A89DFBC03B2C83ULL,
		0xBA737BAAA7CE9DD7ULL,
		0xFE4A8E36F480A8C1ULL,
		0xE973D3A005C0E9ADULL,
		0x3D984E03C5AB1C3FULL,
		0x4B4D2C3EE4FE9E6EULL,
		0x883A657AC11E4FDDULL,
		0x4B9669CE8D97BDF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6E3AACA3D8E9895ULL,
		0xA26B1EC172551D7DULL,
		0x176A05DA860334E4ULL,
		0x6E239D78092B3E30ULL,
		0xE5BA30F81667927AULL,
		0x717EF6E65F1F8475ULL,
		0xE641F4C098BD8430ULL,
		0x96BA33E2A2E3DEFEULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0067830A04B55423ULL,
		0xE0D92235635A02E7ULL,
		0x38EBF3646DC7F316ULL,
		0x10E5665F157B84E5ULL,
		0x937E322ED0EF15CAULL,
		0x09D1C9BD11F81368ULL,
		0xBFB32765C5E1B20FULL,
		0x78B5E52E91D7403DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD932BE4DB15696ULL,
		0x35D61F7AB1D1E497ULL,
		0x904957CDBCB76C91ULL,
		0xC6DB8EF93E36EACAULL,
		0xAC075FE281A7F2CDULL,
		0x5D174305E0B5A0ACULL,
		0x7834C32ED054B05CULL,
		0x36B9EA279E47B967ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CBEB1B4490402B5ULL,
		0xD50F3D4FD28BE670ULL,
		0xA8A2A4A9D1709F87ULL,
		0xD63EE8A62B4D6E2FULL,
		0x3F796DCC5148E707ULL,
		0x54C68AB8F14DB3C4ULL,
		0xC787E44B15B50253ULL,
		0x4E0C0F090F90F95AULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B02966CD294B44BULL,
		0xA73C86E8E289616CULL,
		0xE91DB2AD08D772AAULL,
		0x9AB9DAF68398A8EBULL,
		0xB7F8663D2A33EB1DULL,
		0x59F537899CB87803ULL,
		0xD72F0BE8E5A916A8ULL,
		0x9F6A1198E0A59EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF63056542692A76ULL,
		0x228180541CED4CCAULL,
		0x387CB1C5D5EF775BULL,
		0xCC287B487A70723CULL,
		0xC685B6701258C325ULL,
		0x906D5610EF1389D2ULL,
		0x1DF3EB30F1DCA48BULL,
		0x7E470B5064C5F1A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA461930990FD9E3DULL,
		0x85BD06BCFE642DA6ULL,
		0xD1610368DD3805F1ULL,
		0x5691A1BEF9E8DAD7ULL,
		0x717DD04D386B2838ULL,
		0xC998619973ABF1D1ULL,
		0xCADCE0D81475B223ULL,
		0xE12D1AC884606F4EULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC5C6C0BCEDFB17DULL,
		0xC3911727A1C23B05ULL,
		0x73DCBD311673FB89ULL,
		0x9AC105791C12FE8AULL,
		0xE0169E6DFFAC749DULL,
		0x063E41AC2D8D355DULL,
		0x5C3698DF19FAD358ULL,
		0xA72DAC3968DBCBBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56B93AA91C4551FULL,
		0xCE86983EE0D854E0ULL,
		0x1D7E3772D4012E23ULL,
		0x2DBF4F2877407850ULL,
		0x5365B3484557AB91ULL,
		0xFE66D49F64D550B4ULL,
		0x02808DA9ABDFA63EULL,
		0xD67B1474BF2E5A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2937FFA15F1BE462ULL,
		0x0D178F19411A6FE5ULL,
		0x6EA28A43C272D5AAULL,
		0xB77E4A516B5286DAULL,
		0xB3732D25BAFBDF0CULL,
		0xF8589533495865E9ULL,
		0x5EB61576B2257566ULL,
		0x7156B84DD7F591ACULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF536FDC2798F6CDULL,
		0x8316C7261FBDAEEAULL,
		0x26772530E362C7C3ULL,
		0xD383EC6F0CB75013ULL,
		0x8E077696FD7C651AULL,
		0x17A09FECCCF457ABULL,
		0xEEA0033611C72551ULL,
		0xA58EB3E6320EDCF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53DB7974A2116067ULL,
		0xEFFE138D1E8ED5F3ULL,
		0xFA1056CF3815D139ULL,
		0x803547C5DA5C675FULL,
		0xA36916A06394076FULL,
		0x13BC106D266A120CULL,
		0x686BF19D5D9F3C52ULL,
		0x703BC568CA09873EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC8816A8858996AAULL,
		0x6CE8D4AB01337B19ULL,
		0xDC6773FFDB7716FAULL,
		0x53B6ABAAD6EB374CULL,
		0x2D6E60369EE86275ULL,
		0x041C8F81EA9E45A7ULL,
		0x86CBF2AB4C581903ULL,
		0xD5B5768EF8075BC9ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393FC47907A76EDDULL,
		0xCC80004CC1B1B81CULL,
		0x3AEADC5B5377B879ULL,
		0xA632688B658B32FDULL,
		0x022EF527EF8E5EFAULL,
		0xE6C4D966B586A8F8ULL,
		0xB76027927884945DULL,
		0x51F5222B0BE0726BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED50760935348ECULL,
		0x74B94C1110CB9B7DULL,
		0xFEBA91DBAC95334BULL,
		0x79B003B0F7BA44DEULL,
		0x74CFFE58C6FC8014ULL,
		0x649CB24D4FD8EB2EULL,
		0xBBF3A1031F7ECDA4ULL,
		0xF604C5F99669F1ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7EAC31994F42631ULL,
		0xB8394C5DD17A2361ULL,
		0xC4504D80FFE28B32ULL,
		0xDF826B3B92317623ULL,
		0x76E10B7F2972DEEEULL,
		0x82586B2BFA5E43D6ULL,
		0x0C93869167FA59F9ULL,
		0xA7F1E7D29D8983C6ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC203197F5ADE8DA5ULL,
		0xC81283B4F6C88BFCULL,
		0x255C2FAD703D271AULL,
		0x436C8E373315C09EULL,
		0x685E1807B432F076ULL,
		0x6635CEA09C8F01D5ULL,
		0x8B75F2B1C9693781ULL,
		0x8940703C0949CFBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6647897F8905F4ULL,
		0x7724315EB336FE02ULL,
		0xFB0EB80FDA9B2235ULL,
		0xFBBBA88C1AD15A35ULL,
		0x92242A766435234DULL,
		0x3AA2DEFD751D4A81ULL,
		0x6C87D4CFDE1159FFULL,
		0xBBDBCA9EBBD63C77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF655EF625578851ULL,
		0xBF36B2EA45FE75FEULL,
		0xDE5297A2AAA6052FULL,
		0xB8D726BB29C49AABULL,
		0xFA7A3271D007D33BULL,
		0x5C97105DE9924B54ULL,
		0xE7F2267E17786E7EULL,
		0x329BBAA2B29FF3CBULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA656E50F22E3170EULL,
		0x6601F03588DC9B3BULL,
		0xC2A45BE02A4E1E08ULL,
		0x8519265497D39853ULL,
		0x9DFD6376E40AE61FULL,
		0x48450FC78C1413F3ULL,
		0x0BEBC402EBA5469BULL,
		0xC1A72D2007EEA158ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4B792FC9B97548ULL,
		0xECDC8439617E4131ULL,
		0xC190FCB54FF3AB6BULL,
		0xB4D1CBEC7B4ED01FULL,
		0x03F838E6B44F3E61ULL,
		0x7B7A8CA3B2FC6794ULL,
		0xF8B1AEFA6F3F6968ULL,
		0x047B904E87DB980EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D1D9C20EB5A6246ULL,
		0x8ADD740CE9A2DA0AULL,
		0x0334A75565BDB563ULL,
		0x31C8EDB8EC9D484CULL,
		0x9E055B905045D87EULL,
		0x333F83643EE87467ULL,
		0xF35A6AF8849A2FF3ULL,
		0xC5DCBD6E80353956ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1612F0CAE2E386C6ULL,
		0xED47CA903B07BA4BULL,
		0x66784E455A2694C6ULL,
		0x62E8B293B19E9B3EULL,
		0xBF1EA4F6FCF2940BULL,
		0xB9E8B6036D220C9EULL,
		0x314FBF9A1F057275ULL,
		0xB65DB1C8748A2EB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BC7378A3ABE2FBULL,
		0x35A56663CADE2992ULL,
		0x0B0F853B5835E4A0ULL,
		0xDB10E0A1C52B8799ULL,
		0x3BB9F795A59B35F2ULL,
		0x0313C82DC49A5FD5ULL,
		0x7B988833DE57B806ULL,
		0xFC440F602D02F0E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35AE83B24148643DULL,
		0xD8E2ACF3F1D993D9ULL,
		0x6D77CB7E02137066ULL,
		0xB9F8523274B51CA7ULL,
		0x84A753635969A1F9ULL,
		0xBAFB7E2EA9B8534BULL,
		0x4AD737A9C152CA73ULL,
		0x4A19BEA85988DE56ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C7CA3A59A255957ULL,
		0x87BEAC6AAE7306B4ULL,
		0x83DFC08D153FCECEULL,
		0x0FBE24466D080688ULL,
		0x1EE322CC7292EAA8ULL,
		0x50A71896C9F78BD3ULL,
		0xB2CA3833EDE92536ULL,
		0x1AEBD62B4296B634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB324866BDE811F8ULL,
		0xB8F5693814F1FC6DULL,
		0x564909A9E8FA93FAULL,
		0x40D24E6F0A41527FULL,
		0xE3B4C8C02310698FULL,
		0xA3031A4F6F443DE0ULL,
		0x761B42742567436CULL,
		0x4BE9817FE747D585ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x874EEBC327CD48AFULL,
		0x3F4BC552BA82FAD9ULL,
		0xD596C924FDC55D34ULL,
		0x4F6C6A29674954F7ULL,
		0xFD57EA0C51828327ULL,
		0xF3A402D9A6B3B633ULL,
		0xC4D17A47C88E665AULL,
		0x51025754A5D163B1ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4000F080C0BF67BBULL,
		0x5D7F70270C0B55D9ULL,
		0x0CB62594C51F3F29ULL,
		0x411BCE692AB928ACULL,
		0x384517CBDCBE8FBEULL,
		0x8C475976BB02AF42ULL,
		0x0D781F9074D094CFULL,
		0x40A2602E1D7341DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86FEEA7DAC363E0ULL,
		0xE834BF745E215F99ULL,
		0x65045D6863738E2DULL,
		0x8415A291A988FD44ULL,
		0x83F761070942EED8ULL,
		0xB32B6914E22CB4DBULL,
		0x74C1E2A6C3BFB5EAULL,
		0xAD7EA4344C65ADF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF86F1E271A7C045BULL,
		0xB54BCF53522A0A40ULL,
		0x69B278FCA66CB104ULL,
		0xC50E6CF88331D5E8ULL,
		0xBBB276CCD5FC6166ULL,
		0x3F6C3062592E1B99ULL,
		0x79B9FD36B76F2125ULL,
		0xEDDCC41A5116EC23ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3441BF2003A1456CULL,
		0xFBCD46C739931FA3ULL,
		0x8C975F5646FD7539ULL,
		0x172526B711455C78ULL,
		0x300044B77E5CD588ULL,
		0xED36D8AB784EE178ULL,
		0xD243CBD89BF09E03ULL,
		0xDDD9D26C1F4E4B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C08FDCEC5A72640ULL,
		0xAB282201E11CDD3FULL,
		0x558570DDA153E813ULL,
		0x32327BF919E86DE6ULL,
		0x0A5C5B6F8772477EULL,
		0x74E2A3973C23A200ULL,
		0x70323EF33E378FDAULL,
		0x214747B6EF7792D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x784942EEC606632CULL,
		0x50E564C6D88FC29CULL,
		0xD9122F8BE7AE9D2AULL,
		0x25175D4E08AD319EULL,
		0x3A5C1FD8F92E92F6ULL,
		0x99D47B3C446D4378ULL,
		0xA271F52BA5C711D9ULL,
		0xFC9E95DAF039D99DULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA427E066D58D33BCULL,
		0xCA09108B489F9EBEULL,
		0x2999AB24EC8ADEFCULL,
		0x78E7D37504B49D04ULL,
		0x488B6FF12838F0DFULL,
		0xD6D1F5C32DF22292ULL,
		0xD87AAE0F762E41CEULL,
		0x704D7339FE63BC2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5771A76D12FC6D12ULL,
		0xAC8FB7D62FCE6D55ULL,
		0xF19B69E092174D2EULL,
		0x4980638008298034ULL,
		0xB661CAE695C2EAECULL,
		0xAF0E18FA496FF58BULL,
		0x336BAA5EA8945AB5ULL,
		0x7FC52669D71D09BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF356470BC7715EAEULL,
		0x6686A75D6751F3EBULL,
		0xD802C2C47E9D93D2ULL,
		0x3167B0F50C9D1D30ULL,
		0xFEEAA517BDFA1A33ULL,
		0x79DFED39649DD719ULL,
		0xEB110451DEBA1B7BULL,
		0x0F885550297EB593ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD07D31BE2C5D2416ULL,
		0x8370213CE90E4EEBULL,
		0xEDA7258265042605ULL,
		0x0542E5D6F11BDE1EULL,
		0xCB53593B0E33A239ULL,
		0xC7E040C77B8F26BEULL,
		0xF97839F858A2888AULL,
		0x726807C4DF5F130AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C69FA2F4A4B83DULL,
		0x6E8FC3ED8E2CFB32ULL,
		0x7971C175A50A43B1ULL,
		0x2343A2FFDC1DEAF1ULL,
		0xC43F79893DF14290ULL,
		0x0ACA524951B797ACULL,
		0x753B77CC27E32766ULL,
		0x94130E15837E9E01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3BBAE1CD8F99C2BULL,
		0xEDFFE2D16722B5D9ULL,
		0x94D6E4F7C00E65B4ULL,
		0x260147292D0634EFULL,
		0x0F6C20B233C2E0A9ULL,
		0xCD2A128E2A38B112ULL,
		0x8C434E347F41AFECULL,
		0xE67B09D15C218D0BULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89BE9BD1F24493A1ULL,
		0xE153BDFDD451E35EULL,
		0x8F3BA74FF4A18DD2ULL,
		0xD94C97E1E2CE8E03ULL,
		0xED9E518314880FCEULL,
		0x1B69ECF2EED23A26ULL,
		0x3C9C38E4E30B9E0AULL,
		0xC44D137AC3A20C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9564C1CC20BDEAD2ULL,
		0x28D09B741E462334ULL,
		0xFCC2514AC4C54C1AULL,
		0xF2F3E2E86B5178AFULL,
		0x172F8510E550390EULL,
		0x643CB7E62CC8DB71ULL,
		0x96A907DD86D44C26ULL,
		0xE667FC17BFFC61CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CDA5A1DD2F97973ULL,
		0xC9832689CA17C06AULL,
		0x73F9F6053064C1C8ULL,
		0x2BBF7509899FF6ACULL,
		0xFAB1D493F1D836C0ULL,
		0x7F555B14C21AE157ULL,
		0xAA353F3965DFD22CULL,
		0x222AEF6D7C5E6DB8ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5B8692C4EFDFDD6ULL,
		0xDC472F6ADC3F931EULL,
		0x0F69424E7634CBFCULL,
		0xCC6686224AAEA9C2ULL,
		0xDD9C2080B96CBB53ULL,
		0xDC50690935354C9AULL,
		0x675F3AFA7FCA513BULL,
		0x3F28331199B85E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA797A487AA4A09EULL,
		0x7A8CACD77C0388CEULL,
		0xB57E3620873D06F1ULL,
		0x4E49E62F5258DC84ULL,
		0x7847F33562F578CEULL,
		0x2C8AC766834A1653ULL,
		0x9C768D8B4382BDF3ULL,
		0xA53054335AEF1589ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FC1136434595D48ULL,
		0xA6CB83BDA03C1BD0ULL,
		0xBA17746EF109CD0DULL,
		0x822F600D18F67546ULL,
		0xA5DBD3B5DB99C39DULL,
		0xF0DAAE6FB67F5AC9ULL,
		0xFB29B7713C48ECC8ULL,
		0x9A186722C3574BCEULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBB71C589FA4410CULL,
		0xC88D4E1747791419ULL,
		0x76AE4B1872650E32ULL,
		0xE7DCC3C04AE17ED4ULL,
		0x93EAD7E426CAA97DULL,
		0xFBFD6B30A7140826ULL,
		0x56023EB30DF76609ULL,
		0x84E57090056EC2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB404831859D67649ULL,
		0xFF90870ADB99B5BFULL,
		0x15D5EBD7BE1FEEAAULL,
		0x0626DAC4E4F60457ULL,
		0x8BC1EEF9E0B8ED33ULL,
		0x7C17E4B07EF5F8ACULL,
		0xD7DBD5D31BB6010EULL,
		0xA48A0104E9D2220CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FB39F40C6723745ULL,
		0x371DC91D9CE0A1A6ULL,
		0x637BA0CFCC7AE098ULL,
		0xE1FA1904AE177A83ULL,
		0x182B391DC672444EULL,
		0x87EA8F80D9E1F08AULL,
		0x81D9EB6016416707ULL,
		0x206F7194ECBCE0E4ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4E9D13479577476ULL,
		0x3A056E0C151CD839ULL,
		0x54B81E29C320550CULL,
		0x9894C0320F0C765AULL,
		0x7BAC3131916899AFULL,
		0xA517A43CC18CA117ULL,
		0x7653126903561B59ULL,
		0x1F5F3B699F4B454FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD0E3FF5DC9C468ULL,
		0x8B1A6899F182911EULL,
		0x5FDA60D2D6993D9BULL,
		0x9C0A3AE31D5B7649ULL,
		0x83BC520B210BCA73ULL,
		0x614A797741C1C2D4ULL,
		0x212714F64F383DB9ULL,
		0xE86027F81D0B977DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB83932CB249EB01EULL,
		0xB11F0695E49E4927ULL,
		0x0B627EFB15B96897ULL,
		0x049EFAD112570013ULL,
		0xF810633AB06353DCULL,
		0xC45DDD4B804D63C3ULL,
		0x5774069F4C6E26E0ULL,
		0xF73F1C918240D232ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB7493AD75E44F60ULL,
		0x8247E1D2202736B6ULL,
		0xB196A98B485FE15FULL,
		0x71A93956EB6B697FULL,
		0xF62CEB0EEA8B8179ULL,
		0xC96536678D308E8DULL,
		0x3F8C06664891344CULL,
		0x0E2B6ECD9AEC5935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x006F76BA03655C14ULL,
		0x54B42EA6345261BBULL,
		0x008BE16E9B1C7DBEULL,
		0xFBAA28A08AB2B60AULL,
		0x907552806474AF79ULL,
		0xF61DCE6A8E346555ULL,
		0xCA4614678F8E6396ULL,
		0xFC544561DEA44A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB1BE51776811374ULL,
		0xD6F3CF741475570DULL,
		0xB11D48E5D3439CE1ULL,
		0x8A0311F661D9DF75ULL,
		0x6659B98E8EFF2E00ULL,
		0x3F78F80D0304EBD8ULL,
		0xF5CA1201C71F57DAULL,
		0xF27F2BAC4448135EULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE48616FACED92FC0ULL,
		0x5749773DAD88FECDULL,
		0xA2E1C91727BD9263ULL,
		0x6F03E650844C78CEULL,
		0xE0F0AB779403C7E0ULL,
		0xA0FA6A818D55A6F9ULL,
		0x503CA0C243E651F6ULL,
		0x618AFD5A9D6B33A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA0DBF0C51AC1CFULL,
		0xFF34976273D7EE60ULL,
		0x41FD4003616F4E71ULL,
		0x4939DE774334FABEULL,
		0xAB2EFF0DAEEB93CCULL,
		0xE01F8D504C2C9DC1ULL,
		0xC8A3F55154FF3E53ULL,
		0xE2B51272F5D3413EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F26CD0A0BC3EE0FULL,
		0xA87DE05FDE5F10ADULL,
		0xE31C891446D2DC12ULL,
		0x263A3827C7788270ULL,
		0x4BDE547A3AE8542CULL,
		0x40E5E7D1C1793B38ULL,
		0x989F559317196FA5ULL,
		0x833FEF2868B87297ULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61CCA2539D09A92EULL,
		0xAE151634FABE3565ULL,
		0x3DF91AF801C13403ULL,
		0xE64EE53D39D95321ULL,
		0xF6D0F804F5F5AF2DULL,
		0x0552FBACA3C74A41ULL,
		0x535433CB71DB0923ULL,
		0x6CA16E8DDBE91290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45F3C1B00EB7A142ULL,
		0x3E339222ADC148A6ULL,
		0xDDC2B69D89440A2DULL,
		0xD44646131F33A278ULL,
		0x1C3B41BA47F50CA5ULL,
		0xA374D94A1FB91865ULL,
		0xE753CD7831DB15BDULL,
		0x12C821184CFADE84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x243F63E393BE086CULL,
		0x90268416577F7DC3ULL,
		0xE03BAC6588853E2EULL,
		0x3208A32E26EAF159ULL,
		0xEAEBB9BEB200A388ULL,
		0xA62622E6BC7E5224ULL,
		0xB407FEB340001C9EULL,
		0x7E694F959713CC14ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84C4635E9667B5DFULL,
		0x7225AA2ED82135DEULL,
		0x0434016DC878B2C6ULL,
		0x0B6CA73A485AEC91ULL,
		0x3A09A17BD8C81002ULL,
		0xE49241ACA85F3185ULL,
		0x55B9334E21EE64CEULL,
		0x2A8700D72F255265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA85D75DF413B4D8ULL,
		0x86B4AB963FA013D2ULL,
		0x5DB9568DBCB8374EULL,
		0xBB40E773CD2D9D6EULL,
		0x130E206E58440D4AULL,
		0x60F6FF067B342D63ULL,
		0x7315FAAFF66A0A90ULL,
		0x1B441A7D41DE6076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E41B40362740107ULL,
		0xF49101B8E781260CULL,
		0x598D57E074C08588ULL,
		0xB02C4049857771FFULL,
		0x29078115808C1D48ULL,
		0x8464BEAAD36B1CE6ULL,
		0x26ACC9E1D7846E5EULL,
		0x31C31AAA6EFB3213ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFBC8463ABBF9A86ULL,
		0x5B0584F1AA301678ULL,
		0x44B27E24D44F9775ULL,
		0xF7DB11D71B9EFF74ULL,
		0xF1C25B92172FD3F7ULL,
		0xB2021DBF88100EFAULL,
		0x238F4DB657D6E534ULL,
		0x1275BBB1D64424E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7CC312001FB9A94ULL,
		0xC6A5809D2A80F55AULL,
		0x58C19CB9B0CE5D86ULL,
		0x3C2385446C5BBD8FULL,
		0xB34EA31787D571BEULL,
		0x766E8BB2A20900A7ULL,
		0x46A7AFEC2882D46DULL,
		0x51AE0D06BAD789C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3870B543AA440012ULL,
		0x9DA0046C80B0E322ULL,
		0x1C73E29D6481CAF3ULL,
		0xCBF8949377C542FBULL,
		0x428CF88590FAA249ULL,
		0xC46C960D2A190E5DULL,
		0x6528E25A7F543159ULL,
		0x43DBB6B76C93AD24ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC173E5CCB05F69F9ULL,
		0xD4FEB68BC72B89F3ULL,
		0x04F1563BEB913907ULL,
		0xE8CA11B2BF0C155DULL,
		0x48B99AC28A8736D3ULL,
		0xF8A748C2341CC333ULL,
		0x1E3748C2B298F97CULL,
		0x64596B37F53880F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64836F51F6AC63D5ULL,
		0x3E1EA1BF66BE6337ULL,
		0xEF1F5C81EC9C0A28ULL,
		0xB23D2489EE1DBBA7ULL,
		0xD9E11CD99D84D3C1ULL,
		0xA944F295F44A7F14ULL,
		0xFA47ACBAE0E6CDFFULL,
		0x7F5371CF84CC43CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5F08A9D46F30A2CULL,
		0xEAE01734A195EAC4ULL,
		0xEBEE0ABA070D332FULL,
		0x5AF7353B5111AEFAULL,
		0x9158861B1703E512ULL,
		0x51E3BA57C056BC27ULL,
		0xE470E478527E3483ULL,
		0x1B0A1AF871F4C339ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9294B1AFF43DCFDULL,
		0xACFD36CB81B300F3ULL,
		0xC012B59E09ABEE81ULL,
		0x85902BE564A06F08ULL,
		0x4551D9CF11428CEAULL,
		0x913861613EAD1634ULL,
		0xE30ACB21704A87CBULL,
		0xC28D04FC5C6EFA18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C227CE482AC1284ULL,
		0x8076D91CDC164B0DULL,
		0x4137B875A1A278DAULL,
		0xE745B2699655FBC0ULL,
		0x31147BD6CADB830DULL,
		0x6EF954F806AAACA9ULL,
		0x62DA23D204466650ULL,
		0x8A0FB6E8A262125FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF50B37FE7DEFCE79ULL,
		0x2C8BEFD75DA54BFEULL,
		0x81250DEBA809965BULL,
		0x62D5998CF2F594C8ULL,
		0x7445A219DB990FE7ULL,
		0xFFC135993807BA9DULL,
		0x81D0E8F3740CE19BULL,
		0x4882B214FE0CE847ULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5702EED1D26AA30FULL,
		0x547207FBD9EE3B8DULL,
		0xDCFBAC50D79EE6EDULL,
		0x3FF639E9C2A08A05ULL,
		0xE01EF6872F19075DULL,
		0x5445227ED81ACB46ULL,
		0x46697B80C31A7C7CULL,
		0x13102BA5DBCE87B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7ED2FF14F510CEULL,
		0xD56C915C2E21875EULL,
		0x76BEA3EDD0B56D71ULL,
		0x056CBD56008E9897ULL,
		0xA997C5715BB727E0ULL,
		0x1733B0CC82066154ULL,
		0x0C4C0FF563614A3AULL,
		0x0D9A1ED1C53327DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D7C3C2EC69FB3C1ULL,
		0x811E96A7F7CFBCD3ULL,
		0xAA450FBD072B8B9CULL,
		0x3A9A84BFC22E1292ULL,
		0x498933F674AE20BDULL,
		0x437692B25A1CAA12ULL,
		0x4A257475A07B3646ULL,
		0x1E8A35741EFDA066ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E6171CB0C4CFE6ULL,
		0x35789FA1E736857BULL,
		0xB3D2575B7D0797B5ULL,
		0xED32F8A9E4748843ULL,
		0x6D3C4DB8CC0B1D5BULL,
		0xEB4D53CE146070ABULL,
		0x934E88BE7D781262ULL,
		0xCBF744E086385C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202E017E2E4628D8ULL,
		0xA846015CC102B9ABULL,
		0x11FD61F94FF0AB00ULL,
		0xE1CD649759F479DBULL,
		0x68DC00F6890BF07AULL,
		0x37F8C278FBFBDCE5ULL,
		0xBC842C33355707EFULL,
		0x007AC161AB5E6164ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C816629E82E73EULL,
		0x9D3E9EFD26343CD0ULL,
		0xA22F36A232F73CB5ULL,
		0x0CFF9C3EBD80F198ULL,
		0x05E04D4E4500ED21ULL,
		0xDCB591B6EF9BAC4EULL,
		0x2FCAA48D482F158DULL,
		0xCB8D85812D663D28ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEB732D075B92AA9ULL,
		0x37375A2AADB01FB4ULL,
		0x220D806634851060ULL,
		0x5CBD232C6379E203ULL,
		0x3F7ACA95A203250AULL,
		0x099B20A54646B941ULL,
		0x7E2B088FAC4AC600ULL,
		0x124DD379035CB3CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62D326D2FAC07D2ULL,
		0x51CA133313050C8DULL,
		0x2D2D9238F32C4663ULL,
		0x305DC97969E22FCBULL,
		0x6FC01566E4FB910BULL,
		0x5DC508BA2A13DCB3ULL,
		0xE5DE8F7F5E8B0DFBULL,
		0x31A8D4E9DDBAE85FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089A00BD5A152D7BULL,
		0x66FD4919BEB51339ULL,
		0x0F20125EC7A95603ULL,
		0x6CE0EA550A9BCDC8ULL,
		0x50BADFF346F8B401ULL,
		0x545E281F6C5565F2ULL,
		0x9BF587F0F2C1CBFBULL,
		0x23E50790DEE65B91ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6599654762654177ULL,
		0x36646DC98BDF2711ULL,
		0xAC70E763C5481988ULL,
		0x0D0A28D079132FD8ULL,
		0x977625AAA98EAA7EULL,
		0x512DB172FAE0B224ULL,
		0x53541A9799C8D7A1ULL,
		0x899B84BC8DAC7F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29EB79F7FDB4D0BULL,
		0xE289C1B7A144F0ECULL,
		0xB55E4F086301C0C8ULL,
		0xDE4855F47DC3CEDFULL,
		0x3A9AC09D98D27D24ULL,
		0x76B398D1F863A96DULL,
		0xC1F354DA3054F7F1ULL,
		0x9B7BFB5CC180EE1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA707D2D81DBE0C7CULL,
		0xD4EDAC7E2A9BD7FDULL,
		0x192EA86BA649D940ULL,
		0xD3427D2404D0E107ULL,
		0xADECE537315CD75AULL,
		0x279E29A302831B49ULL,
		0x92A74E4DA99C2050ULL,
		0x12E07FE04C2C9181ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD01719A51E6EF424ULL,
		0x46C651732237D6E3ULL,
		0x48FE4A350E59C38EULL,
		0x8E1014CE8D3D7FDBULL,
		0x7528DB81D7D6DEE2ULL,
		0xBB84A5CE3DB3BBCAULL,
		0xB90CE1976729AD51ULL,
		0x6EB3F0EE4D687FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBD8936B118EC1AULL,
		0x1020D51CE0C9BDEBULL,
		0xF594531EED3B2881ULL,
		0xBE80D35434C37AD3ULL,
		0xFF9D6C76D70A926FULL,
		0xD5F37D0AC05CEBE1ULL,
		0x7859B4F0431675AFULL,
		0x17E8F05608EEAD91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FAA9093AF76183EULL,
		0x56E6846FC2FE6B08ULL,
		0xBD6A192BE362EB0FULL,
		0x3090C79AB9FE0508ULL,
		0x8AB5B7F700DC4C8DULL,
		0x6E77D8C4FDEF502BULL,
		0xC1555567243FD8FEULL,
		0x795B00B84586D23FULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42C9378E481D611CULL,
		0xF5FD7AE07717EF1DULL,
		0xA196B24F9F6E2D56ULL,
		0x092D82A5DB76C4EAULL,
		0x7CA3A2D779EE9501ULL,
		0x767E7F66262D202DULL,
		0x6CABE727B501EAAEULL,
		0xA9F6E92C2D7D9788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9310405DE0A47737ULL,
		0x0EBBCE1315A0C653ULL,
		0x91810FE5300EF88BULL,
		0x2C42AF9951C17677ULL,
		0x4F4F41CF88F7B9A9ULL,
		0xD633809359F0C340ULL,
		0x6A5B7A9C56729099ULL,
		0x1832C557944B9E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1D977D3A8B9162BULL,
		0xFB46B4F362B7294EULL,
		0x3017BDAAAF60D5DDULL,
		0x256F2D3C8AB7B29DULL,
		0x33ECE318F1192CA8ULL,
		0xA04DFFF57FDDE36DULL,
		0x06F09DBBE3737A37ULL,
		0xB1C42C7BB936091AULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x027E4CDD9A40F2DDULL,
		0xA3031A0E0E32AC7BULL,
		0x8BFF87E741517F93ULL,
		0xD0F2C3063DFE8138ULL,
		0xEC8C0ECE868D218CULL,
		0x7B3BB6D6372251DEULL,
		0x34F480A728A5CE0DULL,
		0x42E91DCC7B60A5C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD730CF8ACAF25C28ULL,
		0xABB3CAE5D60E65D1ULL,
		0x5B7E0C837E8EF06EULL,
		0x0837EEDE51BE5AC8ULL,
		0x5CC87159BC13B85CULL,
		0xAD478588C0486651ULL,
		0x27C1FDA17008D690ULL,
		0x340B17D5FF8D8FB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD54E835750B2AEF5ULL,
		0x08B0D0EBD83CC9AAULL,
		0xD0818B643FDF8FFDULL,
		0xD8C52DD86C40DBF0ULL,
		0xB0447F973A9E99D0ULL,
		0xD67C335EF76A378FULL,
		0x13357D0658AD189DULL,
		0x76E20A1984ED2A74ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC641B0D39F9354BULL,
		0x4E04AD48BE58BD8EULL,
		0x5A9FD7CE31B9E975ULL,
		0xD16F30D6EA0DBDDDULL,
		0x979B18A39829C612ULL,
		0xC8E0F7A2FA7AA81FULL,
		0xF6CA620FF332000EULL,
		0xD1B95A5D380614EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7E708975E068BBULL,
		0xFEE3B1A0F89069B5ULL,
		0x8710483E1FD8A56AULL,
		0x6B21DE0E0F04F405ULL,
		0xFED60E6FE1E46A0CULL,
		0x263C5F530DD9EA24ULL,
		0x179B1654B15AA911ULL,
		0x7A164BED5048F93DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71A6B844C195DF0ULL,
		0xB0E71CE846C8D43BULL,
		0xDD8F9FF02E614C1FULL,
		0xBA4EEED8E50949D8ULL,
		0x694D16CC79CDAC1EULL,
		0xEEDCA8F1F7A3423BULL,
		0xE151745B4268A91FULL,
		0xABAF11B0684EEDD6ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9A49DAE0A533B1BULL,
		0x9F2038EF5DB92237ULL,
		0xE57F16926BE34D00ULL,
		0xA34BAA9944B5AA4CULL,
		0x352F2DB59726DBA5ULL,
		0x2B92433B0F3C21DEULL,
		0xEC9FF132D843F526ULL,
		0x787408B94ED28B61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DFF7451AA4EB7A1ULL,
		0xBDDD3D8A26412050ULL,
		0x79F1E0CFF533F639ULL,
		0xD987B2EBEFB42CF9ULL,
		0x086109F727916010ULL,
		0xD581D175244BA8E2ULL,
		0xFC5312CB87FA701EULL,
		0xA314CE4101C66683ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x645BE9FFA01D8CBAULL,
		0x22FD05657BF80267ULL,
		0x9C8EF65D9ED0BB39ULL,
		0x7ACC1872AB0186B5ULL,
		0x3D4E2442B0B7BBB5ULL,
		0xFE13924E2B77893CULL,
		0x10CCE3F95FB98538ULL,
		0xDB60C6F84F14EDE2ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x114B81BA13BCA5BEULL,
		0x440625DAD0A538BFULL,
		0x1D54BE70D00016C0ULL,
		0xA7F6F55807F9AC33ULL,
		0x3975AC617556411DULL,
		0xDB1749460136AE33ULL,
		0xDFAFB521C8EC8EC2ULL,
		0x3089FB0D4A69B31EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E60B7803332F021ULL,
		0xB505A3495D2FA515ULL,
		0x55E038C0D1BCFA43ULL,
		0xA12D8D2E4905235DULL,
		0x9C05E7993C82C460ULL,
		0x01AC9F7AA0E53250ULL,
		0x7CCDDD50E0F6CE7DULL,
		0xA9AE42E9AAA0EA87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F2B363A208E559FULL,
		0xF10386938D8A9DAAULL,
		0x48B486B001BCEC83ULL,
		0x06DB78764EFC8F6EULL,
		0xA5704BF849D4857DULL,
		0xDABBD63CA1D39C63ULL,
		0xA3626871281A40BFULL,
		0x9927B9E4E0C95999ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2F598A2AE8F0040ULL,
		0x8BBEA51E09C39EC9ULL,
		0x678D7C8CFC66E60EULL,
		0x3576A97E12CA0635ULL,
		0x4A81ED753EE87C57ULL,
		0x23B1BAB87E6B9663ULL,
		0x5ACC827F6D05BEB4ULL,
		0x552BCEAB35FAEB38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEEE75219122BE10ULL,
		0x381608244F55D35CULL,
		0x422F67007C3DBFAEULL,
		0x0D3A4FA8239F7460ULL,
		0x9D29BED4EDC9B06BULL,
		0x852340ABE550755CULL,
		0xB79F42C23C45B873ULL,
		0xEABD291CBA6E9E3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C1BED833FADBE50ULL,
		0xB3A8AD3A46964D95ULL,
		0x25A21B8C805B59A0ULL,
		0x384CE6D631557255ULL,
		0xD7A853A1D321CC3CULL,
		0xA692FA139B3BE33FULL,
		0xED53C0BD514006C7ULL,
		0xBF96E7B78F947503ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBEF802414C712DBULL,
		0x4F5FBCF7B4E0954DULL,
		0x618E8038FE2818B2ULL,
		0xB7BF3770FA7E62BBULL,
		0x9D63EC04F7A376EFULL,
		0x61E5A85F20135A9DULL,
		0xD7DC916DD26C2B02ULL,
		0x2FD7F7F61A9D4552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00EBA81450B2B11ULL,
		0xCA3E64783B8854A6ULL,
		0xC97BC90B52BADE34ULL,
		0x80803055B9907CF2ULL,
		0xBD284D13BD34225BULL,
		0x8B853CC385B56765ULL,
		0xE8D38085A813A32BULL,
		0xF4192028693434ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BE13AA551CC39CAULL,
		0x8561D88F8F68C1EBULL,
		0xA8F54933AC92C686ULL,
		0x373F072543EE1E49ULL,
		0x204BA1174A9754B4ULL,
		0xEA60949CA5A63DF8ULL,
		0x3F0F11E87A7F8829ULL,
		0xDBCED7DE73A971FFULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A576B497FF60AF7ULL,
		0x6546C3148EAAC6E9ULL,
		0x12772B0AF922BEAFULL,
		0xA7D83B6A3ACDCAD5ULL,
		0x2F97398059F6596CULL,
		0x992D87CA1109DD7EULL,
		0x93CA3DC20148EB7BULL,
		0xCBFFF85D15E3C438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C16DC04CF3FCF7AULL,
		0x9AA4155AC53D627FULL,
		0x2833FCEC8F95A942ULL,
		0xCD1A9BAA5D6A0579ULL,
		0x5CCCA6DD2F8E4A64ULL,
		0x6BB70A4DA222D6D7ULL,
		0x17725BEE9C3DE5D8ULL,
		0xCCF3091FE2ED4AC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7641B74DB0C9C58DULL,
		0xFFE2D64E4B97A496ULL,
		0x3A44D7E676B717EDULL,
		0x6AC2A0C067A7CFACULL,
		0x735B9F5D76781308ULL,
		0xF29A8D87B32B0BA9ULL,
		0x84B8662C9D750EA3ULL,
		0x070CF142F70E8EFFULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x549191338B432483ULL,
		0x6AC89F03F39D77F0ULL,
		0xA12D31263182E184ULL,
		0x98D5DE89531E3DACULL,
		0xCE577FF7256FC704ULL,
		0xE058F00A8DE574F5ULL,
		0x3E121DF3CC522802ULL,
		0x928E733C830EA8E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AF59AB68BCE390DULL,
		0xA83FE85D86AB5122ULL,
		0x2B172339438686F9ULL,
		0x0898F1D271B466ACULL,
		0x3105E93050763724ULL,
		0x3929D855F128294FULL,
		0x38861B9224DF247AULL,
		0xDF158553A23EB8CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E640B85008D1D8EULL,
		0xC2F7775E753626D2ULL,
		0x8A3A121F7204677DULL,
		0x904D2F5B22AA5B00ULL,
		0xFF5296C77519F020ULL,
		0xD971285F7CCD5DBAULL,
		0x06940661E88D0C78ULL,
		0x4D9BF66F2130102BULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE564A049A8B031B8ULL,
		0xF50170A9AA4DB89AULL,
		0x4FA4C808FA107EE7ULL,
		0xF3231868BCBE5BBAULL,
		0x5341E46B985E2954ULL,
		0xC7DD1D59B80250AFULL,
		0x824918B630F97BCEULL,
		0x4B0A257F5442856CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA361279C0E2DAEULL,
		0xA35CFBED02026962ULL,
		0x31AC55D861FB856BULL,
		0xC6999B5B649005A2ULL,
		0x034B6A4E8C74443FULL,
		0x6794B47A41914097ULL,
		0xCBF2845297AE9777ULL,
		0x60C855C2385DAB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFC7C16E34BE1C16ULL,
		0x565D8B44A84FD1F8ULL,
		0x7E089DD09BEBFB8CULL,
		0x35BA8333D82E5E18ULL,
		0x500A8E25142A6D6BULL,
		0xA049A923F9931038ULL,
		0x49BB9CE4A757ECB9ULL,
		0x2BC270BD6C1F2E35ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0CD05776EE3D16CULL,
		0xDBFE064E51DCE648ULL,
		0xD02A6BC0425B7FAEULL,
		0x75179011E4448A7EULL,
		0xC1949148D350400AULL,
		0x27292B83353B6747ULL,
		0xA110D5411B0FF56BULL,
		0xF606F25D4B86216BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2228B17D64B4CBCFULL,
		0xC766D8879827E23EULL,
		0x9FBF70ACD4ED7E25ULL,
		0xFDC43E5523F4C5F9ULL,
		0xE7FA12EAEC6C9B5DULL,
		0xADD1799A61648097ULL,
		0x16FA6198AEB5BB52ULL,
		0xC764D1D7B69A8441ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92E5B40A0A571AA3ULL,
		0x1C98DEC9C9FB0476ULL,
		0x4F951B6C96B6018BULL,
		0x88D3AE44C7B04F87ULL,
		0x266E83A23F3CDB57ULL,
		0x8AF85219545FE7D0ULL,
		0xB7EAB4D9B5BA4E39ULL,
		0x3162238AFD1CA52AULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6C798974F836688ULL,
		0xF87D5E3761309715ULL,
		0xBE00DD4417EF7822ULL,
		0x3FEB811EAAFC3275ULL,
		0xB88D26F0487AB02DULL,
		0x0D34D149FF69FC22ULL,
		0xEC598D2816874C28ULL,
		0x651C9083AD11A6D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84EB0EDBEFF42FAULL,
		0xF26BDD8DDE2705BEULL,
		0x84A97E343E3C3D5AULL,
		0x8A960A97ADE5CE68ULL,
		0x59720CBF1FE16131ULL,
		0xBE6E59B2ED6E3E28ULL,
		0x4A55880F0AD0C08FULL,
		0x9446F3EDF1B535EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E89287AF17C2472ULL,
		0x0A1683BABF1792ABULL,
		0x3AA9A37029D34578ULL,
		0xB57D8B890719FC1DULL,
		0xE1FF2A4F579BD11CULL,
		0xB35A88FB1207C20AULL,
		0xA60C05271C578CA7ULL,
		0xF15A636E5CA49332ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DA6E43B4F4DC319ULL,
		0x35C28640A5D1D46CULL,
		0x8CFDBDC38A9F57BCULL,
		0x31C44D8367939F7AULL,
		0x0ED5BC60EA2EBC4FULL,
		0xB402008BDCF9F049ULL,
		0xEC32E9066F610A6FULL,
		0xCDC34DF264F5DE9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD100AE0AF118B8ULL,
		0x5A8A55CB58C1E10BULL,
		0x0FA4FBAFDADFA66EULL,
		0xF6BA0BB65D56B1FDULL,
		0xD131F798FE68B567ULL,
		0x255E496A7591F237ULL,
		0x639266B1AFF96407ULL,
		0x60DB48A2F907CEF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC777E49545BCDBA1ULL,
		0x6F48D38BFD103567ULL,
		0x8359466C5040F1D2ULL,
		0xC77E46353AC52E87ULL,
		0xDFE44BF814460928ULL,
		0x915C49E1A968027EULL,
		0x8FA08FB7C0986E68ULL,
		0xAD1805509DF2106DULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69798496DC52665ULL,
		0x7447A6F5848BBCC4ULL,
		0x46CE61D6BFB97312ULL,
		0xC77D91FEEE9DC44DULL,
		0x3C1DA6E9025405DEULL,
		0x34194D62C381A254ULL,
		0xB0107262B0B806A7ULL,
		0x026487D62E1DFD25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A9D6103F5C4DE5ULL,
		0xBB932F4BEB09E072ULL,
		0x91C84D26694C63D5ULL,
		0x64526E1A67439F6EULL,
		0x2B36441DB98535B9ULL,
		0x6B9F0E5D47C29F9BULL,
		0x7BF79BFDAA7569F5ULL,
		0x198B6AD3D6095106ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC73E4E5952996B80ULL,
		0xCFD489BE6F825CB6ULL,
		0xD7062CF0D6F510C7ULL,
		0xA32FFFE489DE5B23ULL,
		0x172BE2F4BBD13067ULL,
		0x5F86433F84433DCFULL,
		0xCBE7E99F1ACD6F52ULL,
		0x1BEFED05F814AC23ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE63AFC232869FE5DULL,
		0x135CC04DA01FFCA0ULL,
		0xF738D7AE39F572F4ULL,
		0x4B1CD3744D65B589ULL,
		0x966AD7BDE789697CULL,
		0x3E5503643BF7EA42ULL,
		0xC7DBE469AD795D89ULL,
		0xB0671CF3A845AC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D7C642D85ED2183ULL,
		0x9008F1B217B80AB6ULL,
		0x46F1C3D348805D16ULL,
		0x36E8D0D9264DF123ULL,
		0xFA42D75A1EB6B60DULL,
		0xC8E5796397696F41ULL,
		0xBB35F8F7F3AE3C88ULL,
		0x83BCE148012D7F1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB46980EAD84DFDEULL,
		0x835431FFB7A7F616ULL,
		0xB1C9147D71752FE2ULL,
		0x7DF403AD6B2844AAULL,
		0x6C2800E7F93FDF71ULL,
		0xF6B07A07AC9E8503ULL,
		0x7CEE1C9E5ED76101ULL,
		0x33DBFDBBA968D337ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EAA8A3D8D6AC011ULL,
		0xE4991392F93477ADULL,
		0xE74D139E55BB0B91ULL,
		0x0857C37E8FD20C4AULL,
		0xFDA063A9B1CE52DDULL,
		0x88BF7D8139E46C45ULL,
		0x411F3D4B7A95B87DULL,
		0xD9FADC0AEDE56537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA42C169E57050D9ULL,
		0xADD2C9F0FFE8E993ULL,
		0xBE638776ABEFC6E7ULL,
		0x61152D31B43FD7EFULL,
		0x7F67C64814F41A7AULL,
		0x58CD7E94AAA6DDDAULL,
		0xD7566EB1D38E6BADULL,
		0x03644C7010574C44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4E84B54681A90C8ULL,
		0x494BDA6206DC9E3EULL,
		0x592E94E8FE54CD76ULL,
		0x6942EE4F3BEDDBA5ULL,
		0x82C7A5E1A53A48A7ULL,
		0xD07203159342B19FULL,
		0x964953FAA91BD3D0ULL,
		0xDA9E907AFDB22973ULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6E2688106066DC8ULL,
		0x77C0B25340321335ULL,
		0x064B188192FB6EEDULL,
		0x2F29AEB5215B0784ULL,
		0x88AF837333E8CA3BULL,
		0xFD9C4CB0E50BCEE8ULL,
		0x9B5B31606E47AE23ULL,
		0x7A4CA340E8050BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3160155885D7FBULL,
		0x2C5EFF5A3968CBD4ULL,
		0x61A199A4CD3954BAULL,
		0xC0084B52BEC59303ULL,
		0xBFB2864BC1F97BA8ULL,
		0xB3AF79C054B43E71ULL,
		0xFA0353BFA2587D81ULL,
		0x8366B81910F23AD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBD308945E83BA33ULL,
		0x5B9E4D09795AD8E1ULL,
		0x67EA81255FC23A57ULL,
		0xEF21E5E79F9E9487ULL,
		0x371D0538F211B193ULL,
		0x4E333570B1BFF099ULL,
		0x615862DFCC1FD3A2ULL,
		0xF92A1B59F8F73106ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8243C5B1C09F7AFAULL,
		0x985FF99732BD32BFULL,
		0xB5565C3A8E25BAB4ULL,
		0xD10E776851364A82ULL,
		0x1D37A7B09E228FC0ULL,
		0xF683F012B49F7F56ULL,
		0x2E406241514C3B33ULL,
		0xEDC1C8E6C430AA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2790C11D4CD67860ULL,
		0xB8F90978D4B70B90ULL,
		0x2384E451C6E006F9ULL,
		0x7A00E5997C158712ULL,
		0x6204638209D168CCULL,
		0x2C435236C5F95BCFULL,
		0xEB94B053D6120931ULL,
		0xF27ACD16025F60DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5D304AC8C49029AULL,
		0x20A6F0EFE60A392FULL,
		0x96D2B86B48C5BC4DULL,
		0xAB0E92F12D23CD90ULL,
		0x7F33C43297F3E70CULL,
		0xDAC0A22471662499ULL,
		0xC5D4D212875E3202ULL,
		0x1FBB05F0C66FCA50ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x712FD4B2D1115FFEULL,
		0x16AE498ECD0F4A87ULL,
		0x909FDF20B8AD9BE2ULL,
		0xFA102AD5299F97B5ULL,
		0x6C70B52C71A3A571ULL,
		0x5EC46439D790D1B7ULL,
		0xFF485ADE429583A5ULL,
		0x5FF2BF234BD49BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B66B8BBFAE87654ULL,
		0xC6706D9C5B978FC0ULL,
		0xDE968ED82DE3A503ULL,
		0x45A7E6BED62B9FB8ULL,
		0x9172E7D7716530E2ULL,
		0x7739A58AB027286CULL,
		0x2262D3D86DF31375ULL,
		0xCB6985CF025206D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A496C092BF929AAULL,
		0xD0DE24129698C547ULL,
		0x4E0951F8954E3EE1ULL,
		0xBFB7CC6BFFB4080DULL,
		0xFD0252FB00C69593ULL,
		0x29FDC1B367B7F9DBULL,
		0xDD2A89062F6690D0ULL,
		0x949B3AEC49869D2CULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6427FF2AE1AA779ULL,
		0x443919E3286BF16CULL,
		0x75DFD617362AC525ULL,
		0x989B49ABE985F22BULL,
		0x016543F5140F7677ULL,
		0x3975E2AC16EAFDF3ULL,
		0x4FCB3E990D3D8520ULL,
		0xCFB42A5E00FF3E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56DF6DCC8C4EBECULL,
		0xC6E52FBB7DD752B1ULL,
		0xFE9F9C4775679B9FULL,
		0x19CE8F973CDA60E1ULL,
		0x7633467779ADB05BULL,
		0x7136D98E25AEC706ULL,
		0x69682EA27FCF0361ULL,
		0x5663ED27DE096257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x732F892E66DE4C95ULL,
		0x82DC365855BCA3DDULL,
		0x8B404A50434D5EBAULL,
		0x8155C63CD55F92CAULL,
		0x775605826DA2C62CULL,
		0x48433B2233443AF5ULL,
		0x26A3103B72F28641ULL,
		0x99D7C779DEF65C35ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x382426AE252E4112ULL,
		0xC3DD82EEFB8E10A0ULL,
		0x202A052F89EB8A5DULL,
		0x65C2380F917118F5ULL,
		0x5FCF1ACE1D6B0E78ULL,
		0x19DC20FE7B0ED4E4ULL,
		0xDEA9CD97BC7FE33DULL,
		0x36B97C417D739F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25C01473FF5673AULL,
		0x6E8FBFB27A83E441ULL,
		0x91925D7E026D9524ULL,
		0x90CC212B4689F259ULL,
		0x979A5D9AD5AF1F89ULL,
		0xBEEEDF71AFF659B6ULL,
		0x465587706C8DA2F7ULL,
		0x6A349EE6F1A4F3E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A7827E91ADB2628ULL,
		0xAD523D5C810DF4E1ULL,
		0xB1B858518B861F79ULL,
		0xF50E1924D7F8EAACULL,
		0xC8554754C8C411F1ULL,
		0xA732FF8FD4F88D52ULL,
		0x98FC4AE7D0F241CAULL,
		0x5C8DE2A78CD76CF4ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6DA619BBD83138AULL,
		0xCE2A3422AB6D4367ULL,
		0xF2A413D4140AD881ULL,
		0x4E58F0B3AB0ED9B9ULL,
		0xA1099573581CF792ULL,
		0x9ECB36E51A390411ULL,
		0x3DD2D26B81AE1C24ULL,
		0xB20D7FC7C5287059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDADA28CE947330C0ULL,
		0xDEC2744C7EF0B53BULL,
		0xCADBABC18204024EULL,
		0x59A0AD528081A3DFULL,
		0x25676FA028AF37A6ULL,
		0xF4D5A274E1DCE359ULL,
		0x16987AC8B198A732ULL,
		0x81B99F653F77DF5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C00495529F0234AULL,
		0x10E8406ED59DF65CULL,
		0x387FB815960EDACFULL,
		0x17F85DE12B8F7A66ULL,
		0x846EFAD370B3C034ULL,
		0x6A1E9491FBE5E748ULL,
		0x2B4AA8A33036BB16ULL,
		0x33B4E0A2FA5FAF07ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D51378C0FC82E2AULL,
		0x8F93B4E16E6B1931ULL,
		0xA720BF83CD44FABBULL,
		0xAE442114A7DF05E9ULL,
		0xE840B587F8DA7816ULL,
		0x139249296FFB11B2ULL,
		0xC73499EF7C0E73D2ULL,
		0xD5574E8A49243F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB25247888C0F0CULL,
		0x2F25B5B0733990E9ULL,
		0xB9885DFB3B56338AULL,
		0x0B505DB7E38F2B82ULL,
		0xC42A2BEB4896C27DULL,
		0xE2B75EB824B4983FULL,
		0x4040BE49598F0FB8ULL,
		0x724F41C461C65284ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43E365CB87442126ULL,
		0xA0B601511D5289D8ULL,
		0x1EA8E278F612C931ULL,
		0xA5147CA344502E6BULL,
		0x2C6A9E6CB04CBA6BULL,
		0xF12517914B4F898DULL,
		0x877427A625817C6AULL,
		0xA7180F4E28E26DD7ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18D27FCC41EF7E41ULL,
		0x0530F5FF6F381610ULL,
		0x92E5690A214CA2F3ULL,
		0xE014BBACF544A57EULL,
		0x91EA8750AC18EE22ULL,
		0x0ABD949EA1538F28ULL,
		0xF40CC5501061666FULL,
		0x3C3A4B1DDF80C33CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD220A692BE6E82D9ULL,
		0xDA22037B08A3B156ULL,
		0xDC97750D6137938FULL,
		0xFC0066D06F3E8890ULL,
		0xC526120D5FA19F73ULL,
		0x208101CAFDE66E61ULL,
		0x5F918D7A74229003ULL,
		0x01CDE71B2E1D19B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAF2D95EFF81FC98ULL,
		0xDF12F684679BA746ULL,
		0x4E721C07407B317CULL,
		0x1C14DD7C9A7A2DEEULL,
		0x54CC955DF3B97151ULL,
		0x2A3C95545CB5E149ULL,
		0xAB9D482A6443F66CULL,
		0x3DF7AC06F19DDA8EULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C88FD67DA80C2DAULL,
		0x03E5F17BE259B21BULL,
		0xBE32CC12FE127530ULL,
		0xD7414C04576FB4E0ULL,
		0xE6C9074007C7619BULL,
		0x577E03FE37E6651AULL,
		0x4839DCE12A397382ULL,
		0x887E15076CB6C25EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6576808634F8CCDULL,
		0xA89D9D701392E8CAULL,
		0xE1A4D31E5E88C165ULL,
		0x103A86B0F9B263FBULL,
		0x69AE1AC01D449402ULL,
		0x4E56F6972BF53DCEULL,
		0xE762E483877321B9ULL,
		0xA8B29AFC17D33C2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFADF956FB9CF4E17ULL,
		0xAB786C0BF1CB5AD1ULL,
		0x5F961F0CA09AB455ULL,
		0xC77BCAB4AEDDD71BULL,
		0x8F671D801A83F599ULL,
		0x1928F5691C1358D4ULL,
		0xAF5B3862AD4A523BULL,
		0x20CC8FFB7B65FE75ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F7A46D91D9A5154ULL,
		0xB60F9E2917760A4CULL,
		0x2EA418A7F8C00DCCULL,
		0x44E0D07499D875A0ULL,
		0x9B259D1F6C5C495FULL,
		0x647EF67E1E79FBFEULL,
		0xC53FA54C0B34722FULL,
		0x640679749AF6902CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380C333CC5789EFDULL,
		0xEAF02DCE84F71672ULL,
		0x6433A73BE057EE9AULL,
		0xE7F153C4B4D72CF3ULL,
		0x039E07D9BA902777ULL,
		0x3F7D68E816ABF6A7ULL,
		0xD654CD4AB2C099F6ULL,
		0xC8A093C814AFB6E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x777675E5D8E2CFA9ULL,
		0x5CFFB3E793811C3EULL,
		0x4A97BF9C1897E356ULL,
		0xA31183B02D0F5953ULL,
		0x98BB9AC6D6CC6E28ULL,
		0x5B039E9608D20D59ULL,
		0x136B6806B9F4EBD9ULL,
		0xACA6EABC8E5926CBULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB812C12E94BF9BAEULL,
		0x8781ECD2A78BA84CULL,
		0x4A5130606FC70C30ULL,
		0xF06862F734FBE5E0ULL,
		0x7F47749FC4D02A71ULL,
		0x66F5C79E278C34B6ULL,
		0xB44AFA2BFA82AC14ULL,
		0x3A9917859FA5D946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDDEA828E45C314ULL,
		0xEA94BACB092392D0ULL,
		0x535777EBC6B93C22ULL,
		0x81853026D63C07C3ULL,
		0x7EFE04BF925AF24DULL,
		0xEFBC5D422E5012F0ULL,
		0x7978B5DA4E5808F5ULL,
		0xAA581057BE9CF2FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7CF2BAC1AFA58BAULL,
		0x6D155619AEA83A9CULL,
		0x1906478BA97E3012ULL,
		0x71ED52D1E2C7E223ULL,
		0x01B97020568AD83CULL,
		0x89499ADC09DC2646ULL,
		0xCD324FF1B4DAA4E1ULL,
		0x90C107D221392BBAULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8983922D91C91D4AULL,
		0x8E38720DEC5D8691ULL,
		0x03EB0F68D6220B16ULL,
		0x39D5C751B5C3F21FULL,
		0xD4874367E8151657ULL,
		0x9E28DA03FF366BABULL,
		0xB4FA966ED7A81B4EULL,
		0x6702620B1CE8412BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F24C370C0BCBBDULL,
		0x84B746189F468DEFULL,
		0x76D68B2119D1DA52ULL,
		0x67AA8BF34775B1DBULL,
		0x725A35AB386BC9B1ULL,
		0xC241527964DF7D21ULL,
		0x1404EE92FCD9A6F8ULL,
		0x3E021362D154AA90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB971DE1A9DC2D6F7ULL,
		0x0A8F3415731B0B7EULL,
		0x753D8449CFF3D144ULL,
		0x5E7F4CA2F2B643C4ULL,
		0xA6DD76CCD07EDFE6ULL,
		0x5C69887A9BE9168AULL,
		0xA0FE78FC2B71BDB6ULL,
		0x59007169CDBCEBBBULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05CE83FF2ECAA4DBULL,
		0x18EC75DDE3D74937ULL,
		0x6F1A8A1342E6A16AULL,
		0x80AD807490FCF224ULL,
		0x49145FB4E19D4CABULL,
		0x4377C3E7BB36D66EULL,
		0x3C00A1B4CAAEC983ULL,
		0x64C14DB5568B2D77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0436A95A7B4ECB44ULL,
		0x89ACFA0FD8284EB3ULL,
		0xEF1AAE4BEB85C460ULL,
		0x4E66937E83740C38ULL,
		0xEEEC5B9A86B8990DULL,
		0xC4FFCB4A49A2C3CCULL,
		0x6EC740E87F40EC3BULL,
		0x54AB4721ECFDF2E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01F82AA555846F9FULL,
		0x91408FD23BFF0784ULL,
		0x80002458A963650AULL,
		0xCECB130A1388FE1CULL,
		0xA7F8042E6725D5A6ULL,
		0x878808ADF29415A2ULL,
		0x52C7E15CB5EE25B8ULL,
		0x306A0A94BA76DF97ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D949B979DA57B49ULL,
		0x761D4EDC8AF46DE2ULL,
		0x0F502EBC5B6EB353ULL,
		0x9AB1411E404F9A61ULL,
		0x8D6BBBFD84B5F261ULL,
		0x930FCBE4D856FAD6ULL,
		0xBB2372EA8060DD58ULL,
		0x6E6F72696247DAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA752AC295167D4ULL,
		0x073FD77C4B93A86AULL,
		0xB56281089E451D1FULL,
		0x879B13564596E9FFULL,
		0x67909FC189ECBD7DULL,
		0x9106B0842143231EULL,
		0x85181C58EB813FC3ULL,
		0x9C0ABA61B63B5975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB033C93BB4F41C9DULL,
		0x712299A0C167C588ULL,
		0xBA32AFB4C52BAE4CULL,
		0x1D2A524805D9739EULL,
		0xEAFB243C0D594F1CULL,
		0x02097B60F915D9C8ULL,
		0x3E3B6EB26BE1E29BULL,
		0xF265C808D47C8398ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02AF50CCDA8C4C88ULL,
		0x8ACEAC86F20340F8ULL,
		0x9AF90CE2145272C4ULL,
		0x3E8C31E9764C75FBULL,
		0xF43A0D8F1C9F1A1EULL,
		0xA50739DA2F9518BBULL,
		0xF54A42542CD146C4ULL,
		0x8238A04D9FE11507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x452ED67BA019940FULL,
		0x422F5765B28B05ECULL,
		0x2A38505C71BE135EULL,
		0x9FFED1E436D3137CULL,
		0xAF8E254066201E40ULL,
		0x8FCF9AA56DA32ABAULL,
		0x9979D48850F034AEULL,
		0xF741A270A81C160FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x478186B77A95D887ULL,
		0xC8E1FBE340884514ULL,
		0xB0C15CBE65EC619AULL,
		0xA172E00D409F6687ULL,
		0x5BB428CF7ABF045EULL,
		0x2AC8A37F42363201ULL,
		0x6C3396DC7C21726AULL,
		0x7579023D37FD0308ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x344C7EB47563FB39ULL,
		0xD6B3CDFC941D5724ULL,
		0x1B8F1AA6B21CE184ULL,
		0x5A452A48B0FF106DULL,
		0x1E0CD8C15F69E1F5ULL,
		0xC7CB1C4506FE6B3FULL,
		0x01C878DBB82A2C7CULL,
		0xD5DF949EC3D870A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92684765FD1EC481ULL,
		0x225B978C6739274EULL,
		0x8911FDEC37A17342ULL,
		0xCA914348CD1BD868ULL,
		0xFDA3FC8402C9616FULL,
		0xB60EAE82CC4632E3ULL,
		0xAAC796D38C474A3FULL,
		0x9108A825C9C29DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA62439D1887D3FB8ULL,
		0xF4E85A70F324706AULL,
		0x929EE74A85BD92C6ULL,
		0x90D469007DE4C805ULL,
		0xE3AF24455DA0809AULL,
		0x71C5B2C7CAB859DCULL,
		0xAB0FEE08346D6643ULL,
		0x44D73CBB0A1AED53ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4DF9BB521D18FEBULL,
		0x80EE7F6C46E02DD5ULL,
		0x334D7816E04CD5FEULL,
		0x89F349BE46DEBD11ULL,
		0x107ED4A052AE4606ULL,
		0x419EB99310CAC820ULL,
		0xED2633B0BB639F64ULL,
		0x05D9AA1E02BE6284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6760183A55E72C8CULL,
		0x1683397DC42920C4ULL,
		0xD0FB84049CE21B75ULL,
		0x9D2583A35476FA3FULL,
		0x399D3EB28F663099ULL,
		0x4671D80265E4CA73ULL,
		0xF472C889FC5ADBD2ULL,
		0xD4AD78BD863E74DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3BF838F7436A367ULL,
		0x966D461182C90D11ULL,
		0xE3B6FC127CAECE8BULL,
		0x14D6CA1D12A8472EULL,
		0x29E3EA12DDC8769FULL,
		0x07EF6191752E0253ULL,
		0x1954FB39473944B6ULL,
		0xD174D2A38480165BULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0255A9D0FFC0C9DULL,
		0xA2ED1E3026806157ULL,
		0x91FF4B0E15E18BF8ULL,
		0x4E3BFDA3A0E64A45ULL,
		0x377F4FBDD16405C5ULL,
		0x816D17E3AFC40688ULL,
		0x783665530D8B3FE5ULL,
		0xEAD763E29B1997B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C731E20A6CED51CULL,
		0x0D8D5DE2277B5630ULL,
		0xAC8D5CD35BE447F5ULL,
		0x0C87562B284EA664ULL,
		0x698D02F9D68B064FULL,
		0x680CB73AD681BFDFULL,
		0x2A4FFDA990514552ULL,
		0x429AB7B9377FCB87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC5644BDA932D981ULL,
		0xAF6043D201FB3767ULL,
		0x3D7217DD4E05CC0DULL,
		0x42BCAB8888A8EC21ULL,
		0x5EF24D4407EF038AULL,
		0xE961A0D97945B957ULL,
		0x527998FA9DDA7AB7ULL,
		0xA84DD45BAC665C33ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63D1434A8D90E3D9ULL,
		0x3A4188FAFCC7D661ULL,
		0x9DE29FEFE392585EULL,
		0x1E7EDC9800B19297ULL,
		0x6E016562B49FF399ULL,
		0x6285D94B72F924B7ULL,
		0xF721574FDB61A703ULL,
		0x36FD227EFAA7EA33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E501975136ABA81ULL,
		0x00AE8F628A71E10DULL,
		0x0AC70799EED80A92ULL,
		0x644206A82A74F5DDULL,
		0x2D05421079AB6397ULL,
		0xEDA2CEE6C416654BULL,
		0x1D76DDEC47C93A00ULL,
		0x375AE19AA9032093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D815A3F9EFA5958ULL,
		0x3AEF079876B6376CULL,
		0x972598760D4A52CCULL,
		0x7A3CDA302AC5674AULL,
		0x43042772CD34900EULL,
		0x8F2717ADB6EF41FCULL,
		0xEA578AA39CA89D03ULL,
		0x01A7C3E453A4CAA0ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA180E5D157BBDFC1ULL,
		0x328250C7706250B8ULL,
		0x3F42BB6266BBA39CULL,
		0xC85028ED4B63A684ULL,
		0x8CD4271E24373050ULL,
		0x0B16DD6734B810E2ULL,
		0xC3048D438E2C1AC8ULL,
		0x1827FB4551FFE951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D918B2483681BFBULL,
		0xC562A06F706B578EULL,
		0x5FE449608A52B7C3ULL,
		0x52FE4C5783DA82A4ULL,
		0x60AE72D20FE912DBULL,
		0x5E47196B97DDC93BULL,
		0x0C8C1E2F87B4A797ULL,
		0xC3D98239DB97C6B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C116EF5D4D3C43AULL,
		0xF7E0F0A800090736ULL,
		0x60A6F202ECE9145FULL,
		0x9AAE64BAC8B92420ULL,
		0xEC7A55CC2BDE228BULL,
		0x5551C40CA365D9D9ULL,
		0xCF88936C0998BD5FULL,
		0xDBFE797C8A682FE8ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8700EB584A518821ULL,
		0x278B4E71C22D29E6ULL,
		0x6157709A6AC2E2EDULL,
		0x786ABEB09B90C95EULL,
		0x378D127615DDE045ULL,
		0x37DC91F08B315262ULL,
		0x2A4234EFCCA570D1ULL,
		0x570F8DE462B15EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B88AEDF14AAC3D8ULL,
		0x4D7CDF01EC55086EULL,
		0x166C54FBD7CD0D41ULL,
		0x6F69B03965EF53D4ULL,
		0x7CCAA799EF745AB3ULL,
		0x5148C4E45D14AFACULL,
		0xCECEC034C38ED66EULL,
		0x51F284FC5BA31E66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C8845875EFB4BF9ULL,
		0x6AF791702E782188ULL,
		0x773B2461BD0FEFACULL,
		0x17030E89FE7F9A8AULL,
		0x4B47B5EFFAA9BAF6ULL,
		0x66945514D625FDCEULL,
		0xE48CF4DB0F2BA6BFULL,
		0x06FD0918391240C4ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD580CFAA451B97FULL,
		0xCBE4233248A09821ULL,
		0x487687AE1B6B0CE5ULL,
		0xF20307450BE89503ULL,
		0x4F86C29151B16371ULL,
		0x96AEFEC14976C904ULL,
		0x92F5420F91AF7C31ULL,
		0x68378EA0A5B22133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99CDD96EF8D46C46ULL,
		0x4C4725BCD9E4B9E8ULL,
		0x9C92B40331825713ULL,
		0xE1D18F89C9A49EA6ULL,
		0xB5E8A012C12E3181ULL,
		0xE042B6580EBCAC70ULL,
		0x3D623B0CC1AC9807ULL,
		0xCB78DAF226F1F145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6495D5945C85D539ULL,
		0x87A3068E914421C9ULL,
		0xD4E433AD2AE95BF6ULL,
		0x13D288CCC24C0BA5ULL,
		0xFA6E6283909F52F0ULL,
		0x76EC489947CA6574ULL,
		0xAF9779035003E436ULL,
		0xA34F54528343D076ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x256C90812628B4EDULL,
		0x8DF3FBA9D3638578ULL,
		0x4A796C6DB8B07C75ULL,
		0x03C8576C11B55216ULL,
		0x99EA74135C71FF15ULL,
		0x079586C7DA6D1229ULL,
		0x9F477E316087FAC3ULL,
		0x0F778F5D1C4A946FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61ADDE2653B5C56ULL,
		0x9C4F640BD577DCCBULL,
		0xF01623694435CF42ULL,
		0x0C33991C7A3AA25BULL,
		0x3C5B7D157F82089EULL,
		0xB6B163CF463D8A5BULL,
		0xA539579BD403CDD0ULL,
		0x113254CCD9252018ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3764D634313E8BBULL,
		0x11BC9FA2061459B3ULL,
		0xBA6F4F04FC85B337ULL,
		0x0FFBCE706B8FF04DULL,
		0xA5B1090623F3F78BULL,
		0xB124E5089C509872ULL,
		0x3A7E29AAB4843713ULL,
		0x1E45DB91C56FB477ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5158064CC2A216BULL,
		0x92B351D0E4303AEAULL,
		0xED7A65182497DB1EULL,
		0xAC23C8B41E0DB06FULL,
		0x8DA2D1B8D83566BCULL,
		0x5520386598B87FCDULL,
		0x95FB16C6E1F6CEBEULL,
		0x747ABCCEF4706577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9AB7BA095C0E553ULL,
		0xF6762CF2FE0B69A6ULL,
		0x04B386F696EE4B8BULL,
		0x2795F9B951BF45CDULL,
		0xFD129CB532148228ULL,
		0xD1A3C9B9E5745BFAULL,
		0x7962C83B0EEEE330ULL,
		0xB7D36C937E5C373EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CBEFBC459EAC438ULL,
		0x64C57D221A3B534CULL,
		0xE9C9E3EEB2799095ULL,
		0x8BB6310D4FB2F5A2ULL,
		0x70B04D0DEA21E494ULL,
		0x8483F1DC7DCC2437ULL,
		0xEC99DEFDEF182D8EULL,
		0xC3A9D05D8A2C5249ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40727535FBF57EC9ULL,
		0x1418583290C94AA5ULL,
		0xA690EC6EEAADE57BULL,
		0xABCC0982E0109D4AULL,
		0xB5D546ECB432B60AULL,
		0x153D9D394184B6A9ULL,
		0x8993FDD423CB4DEBULL,
		0x47B08B9E00989822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B1FAF223747A690ULL,
		0x338E0B0482EDC771ULL,
		0x42086A51D03E43CDULL,
		0xDAFF5239068847F1ULL,
		0x343725F51137C165ULL,
		0x578709EBBD3F872EULL,
		0x7ECE04CC2D1CCDDBULL,
		0x73DD825F081B579DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B6DDA17CCB2D859ULL,
		0x2796533612248DD4ULL,
		0xE498863F3A93A6B6ULL,
		0x71335BBBE698DABBULL,
		0x81E26319A505776FULL,
		0x42BA94D2FCBB3187ULL,
		0xF75DF9180ED78030ULL,
		0x346D09C10883CFBFULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4544838A9FACC3EDULL,
		0x98F3E626D05ECFF6ULL,
		0x01C2751F01D43FF9ULL,
		0xF4F15749C66873A4ULL,
		0x972C93676172DABEULL,
		0xBFEB34A724B9B880ULL,
		0xC40D34C22D81C6FCULL,
		0x062427F7CE2B4D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E585FFF0BDEAC4ULL,
		0xF41D4A60E91A6A0CULL,
		0x8051700AEC2F8F46ULL,
		0x68B2D55157AF9EA0ULL,
		0x870A4AA45DA0104BULL,
		0xF985B4FDFBAF83BCULL,
		0xB155FF5F3A6ACE13ULL,
		0x6ED44F10F2FE211EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A106756F112929ULL,
		0x6CEEAC463944A5FAULL,
		0x81930515EDFBB0BFULL,
		0x9C43821891C7ED04ULL,
		0x1026D9C33CD2CAF5ULL,
		0x466E805ADF163B3CULL,
		0x7558CB9D17EB08EFULL,
		0x68F068E73CD56C3BULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E4F17995D795F1ULL,
		0xC558455F27F606CDULL,
		0x90A24C31D67885A3ULL,
		0xDE4CF18DA0F7F662ULL,
		0x3C55B7403C627BD3ULL,
		0x4D81275958194FFCULL,
		0x5CE432CF805D9219ULL,
		0xA50DAB9DA269F91AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A1CA8C6835C08E0ULL,
		0x254B9A6A90EBAFEFULL,
		0x2525F24350957E7CULL,
		0xA86F94DE8760B97BULL,
		0x9849DFB7146E97DEULL,
		0xC79CAC3DEC0351F9ULL,
		0x8787570A08C62021ULL,
		0x6E619BC3EE09E6F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF859BF168B9D11ULL,
		0xE013DF35B71DA922ULL,
		0xB587BE7286EDFBDFULL,
		0x7623655327974F19ULL,
		0xA41C68F7280CEC0DULL,
		0x8A1D8B64B41A1E05ULL,
		0xDB6365C5889BB238ULL,
		0xCB6C305E4C601FE2ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB82B5A69A4F879BFULL,
		0x82180F525824E2FFULL,
		0xA1D0D83F7FDB7C7AULL,
		0x2DCBE6EB34A51252ULL,
		0xBB6078A7664531FCULL,
		0x4F3ED0B856584949ULL,
		0x23B509500C1AF45CULL,
		0xB69908E36D95F99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119E866F1EB0A4F8ULL,
		0xAE04E529ADB52B0BULL,
		0xBD16A063C1CB7D49ULL,
		0x68695F54AD6CFBA6ULL,
		0x2CEE6D25DEE11068ULL,
		0x38EC479AD74EBD60ULL,
		0x95A98DFAEE1AA8D3ULL,
		0x1A53FADFD16C6E28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9B5DC06BA48DD47ULL,
		0x2C1CEA7BF591C9F4ULL,
		0x1CC6785CBE100133ULL,
		0x45A2B9BF99C9E9F4ULL,
		0x978E1582B8A42194ULL,
		0x77D297228116F429ULL,
		0xB61C84AAE2005C8FULL,
		0xACCAF23CBCF997B7ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB60E8FD31C521D1DULL,
		0x0344EA199C5ECCB5ULL,
		0x2B193E8D79E525AEULL,
		0x68B52D7B2EB3A3F1ULL,
		0x654679F1E841A736ULL,
		0xCC99FD49C247EC1CULL,
		0xE6782BE86A4604C5ULL,
		0x8FBE5C2CECFC5974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CAF58FCD5891893ULL,
		0x67812F6DB777DD6CULL,
		0x6F6DC821E8D68D2FULL,
		0xB12B9B543D99DD24ULL,
		0xC1A27A97A15F131BULL,
		0xBB43FAA24DDB7E32ULL,
		0x70D439AB6C18A9E6ULL,
		0x4A52A5E97D53492FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAA1D72FC9DB058EULL,
		0x64C5C5742B2911D9ULL,
		0x4474F6AC9133A881ULL,
		0xD99EB62F132A7ED5ULL,
		0xA4E40366491EB42DULL,
		0x77DA07EB8F9C922EULL,
		0x96AC1243065EAD23ULL,
		0xC5ECF9C591AF105BULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9653370A4C3B5405ULL,
		0x3E4D8D3A7ADB74EAULL,
		0xA0F968FD9C824C21ULL,
		0xE401EE3972157D4CULL,
		0x1DDE1C83297B3AB2ULL,
		0x09EF3418F33BB50BULL,
		0x5E344E90A39F1321ULL,
		0x88CDCA98EF42414BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44C9FE51472BA276ULL,
		0x03E74B08C756C205ULL,
		0x2152F564930768DFULL,
		0x63D96F12FA484BBCULL,
		0x8FEBF4C56E6EE0D0ULL,
		0x2AC1ACDD85BCA9E7ULL,
		0x3A23B68207D2742BULL,
		0x34AFD1B00CAFA919ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD29AC95B0B10F673ULL,
		0x3DAAC632BD8DB6EFULL,
		0x81AB9D990F8524FEULL,
		0x87D8812B885D36F0ULL,
		0x9235E8464715DA62ULL,
		0x232E98C576871CECULL,
		0x6417F812A44D670AULL,
		0xBC621B28E3EDE852ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B703F97A6F3CFDULL,
		0x194DF3F46E1112B3ULL,
		0x8F272809CEF4B7CAULL,
		0x4CF16BE3E3BF2139ULL,
		0x302EEE55A68F3A65ULL,
		0xBAD4DE3C53CCCD59ULL,
		0xFC907CAAA4923A7FULL,
		0x9114021A852E0146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149237456C141492ULL,
		0xE226C2659316ED14ULL,
		0xF69E28BDE73F4A05ULL,
		0xDA350F5D08A7BED4ULL,
		0x37FD6FEEF9211331ULL,
		0xC0F380C3FA042510ULL,
		0x2B046F2E50C9BE6BULL,
		0xF0ABE0777E4F5A2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA62534BC167B286FULL,
		0xFB6B3191FD07FFA7ULL,
		0x79B900B429CBFDCFULL,
		0x96C464BEEB189FEDULL,
		0x07D381BB5FAE2954ULL,
		0x7A275EFFA9C8E849ULL,
		0xD7941384F45B8414ULL,
		0x61BFE26DFB615B68ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC105B32A0DBFE90ULL,
		0xF26E9B3CF6927750ULL,
		0x548D7F7E3A8C05C0ULL,
		0x3DDFAEFB9AEEC38AULL,
		0xE13DFFC39BBD4FB2ULL,
		0xDC9AC40EE34367DCULL,
		0x2725F1232B1E851EULL,
		0x3A8BB10693C68A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x429B40C389E59D8FULL,
		0xCD674178FCAFE52AULL,
		0x4CFFBB38861781CAULL,
		0x1A462F7C093A350FULL,
		0xA95ECDDC302BD928ULL,
		0xF14519A4272F1D19ULL,
		0xBF4ADBD073204E6AULL,
		0xD9F10AA28D494113ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE8B1BF1293E631FULL,
		0x3F09DA440A3D927AULL,
		0x1872C446BC9B840AULL,
		0x2799818793D4F685ULL,
		0x4863321FAB96969AULL,
		0x2DDFDDAAC46C7AC5ULL,
		0x986F2AF3583ECB74ULL,
		0xE37ABBA41E8FCB65ULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2AE84653A22741CULL,
		0x5AEBD8F557AF2B38ULL,
		0x53C7E0224348898FULL,
		0x675DA7838A9E6E47ULL,
		0x78AF888EFBBC53D0ULL,
		0x511522DB2CB6746BULL,
		0xAB902A653356B6DCULL,
		0x49D6ACB0FAE9796BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE81CE291491721CULL,
		0x7792F9CB7DF13126ULL,
		0x57DB9C05034FC621ULL,
		0x504C18F82BBE7798ULL,
		0x275EF43DC52FA4C6ULL,
		0xFAA2172B1DDE5659ULL,
		0xF8AEAA0BF5D625CBULL,
		0x297FC95F46CB861EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C2F4A4C2EB30600ULL,
		0x2D79213E2A5E1A1EULL,
		0x041C7C2740074FAEULL,
		0x3711BF7BA12019DFULL,
		0x5FF17CB33E93F716ULL,
		0xABB735F031682232ULL,
		0x533E806EC6809317ULL,
		0x60A965EFBC22FF75ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DECF21D3FA2E409ULL,
		0x2F19D2CCEC978819ULL,
		0xC8FB65C35CF3B014ULL,
		0xA6E5978760B60C35ULL,
		0x809D3A5FDFC4E0F3ULL,
		0x956D6E8809469F6DULL,
		0xC6F8CEF9AA011C93ULL,
		0x3251AB4F287E0857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3619A2D78ED7F77ULL,
		0xB9D949A90C423EDDULL,
		0x2ED7AC54C76F3FB4ULL,
		0x7F449754C1D879A2ULL,
		0xF8EF7AB78790C2EEULL,
		0x05BF9C1B6A0828CAULL,
		0x1A093D8D4B37956BULL,
		0x94F8F96A1CC0CA4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE8D6830474F9B7EULL,
		0x96C09B65E0D5B6C4ULL,
		0xE62CC9979B9C8FA0ULL,
		0xD9A100D3A16E7597ULL,
		0x787240E85854221DULL,
		0x90D2F293634EB7A7ULL,
		0xDCF1F374E13689F8ULL,
		0xA6A9522534BEC21CULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF18E6D296AC7CD8ULL,
		0xBEB914F7DD00B825ULL,
		0x376893016651741EULL,
		0x8F64E6F8430360D9ULL,
		0x0817245E986A0C89ULL,
		0x00491CB698C34282ULL,
		0x75CB8AE0619982F2ULL,
		0x7003202AAB139B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC24C96F1787DBAF8ULL,
		0x75DCB86272E9049EULL,
		0xE30CB20C10C2395AULL,
		0x651E86AB82086406ULL,
		0x0E26137D70FD7971ULL,
		0x88391965206B964FULL,
		0xBFE7B2A536385F84ULL,
		0xF456A2234C140759ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D547023EED1C620ULL,
		0xCB65AC95AFE9BCBBULL,
		0xD464210D76934D44ULL,
		0xEA7A6053C10B04DFULL,
		0x06313723E89775F8ULL,
		0x887005D3B8A8D4CDULL,
		0xCA2C384557A1DD76ULL,
		0x84558209E7079C73ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBCADBC1157714BBULL,
		0x0BE88F26B9985920ULL,
		0x38BF8CD3128C2127ULL,
		0xB32327F8B9BAD019ULL,
		0xA564FD7D84DE58C3ULL,
		0xC5B1515DAA9DE978ULL,
		0x74E323B9A0C78E20ULL,
		0xA37465CFCD6682C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA108B836785A2EE8ULL,
		0xD0B4366A9F91D705ULL,
		0x225C52BC7EAF2A17ULL,
		0x073096C0680D3CA6ULL,
		0x3002BCCBC918516AULL,
		0x13738A4EE77BA73AULL,
		0xEAD39B6CD400B28AULL,
		0x644C6A49C98D6BA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AC263F76D2D3A53ULL,
		0xDB5CB94C26098E25ULL,
		0x1AE3DE6F6C230B30ULL,
		0xB413B138D1B7ECBFULL,
		0x956641B64DC609A9ULL,
		0xD6C2DB134DE64E42ULL,
		0x9E30B8D574C73CAAULL,
		0xC7380F8604EBE960ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18A17C7DE91C67A8ULL,
		0x6E46A6B5AF2BC2D0ULL,
		0x3A125BC9DD55241FULL,
		0x1A2EE1631C18BA13ULL,
		0xD808AB876B12D72DULL,
		0x81D753FB4BE991C5ULL,
		0x0FB8F48321EDF94CULL,
		0xDC2B53FD47D6E4DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E28691799C0E79ULL,
		0x325E8D226F44BDB6ULL,
		0x692710EE942FD4D9ULL,
		0x1780343078518BB3ULL,
		0x2623C313CDA2A2A0ULL,
		0x4FD7A2748F53A3ECULL,
		0x2C5C07A678B07475ULL,
		0x0F6601914DF2B933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B43FAEC908069D1ULL,
		0x5C182B97C06F7F66ULL,
		0x53354B27497AF0C6ULL,
		0x0DAED553644931A0ULL,
		0xFE2B6894A6B0758DULL,
		0xCE00F18FC4BA3229ULL,
		0x23E4F325595D8D39ULL,
		0xD34D526C0A245DEEULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF669ED58A9D5933ULL,
		0xCF13AD6D4CCCB5E1ULL,
		0x5656A210BB421335ULL,
		0x161041456DDE04D5ULL,
		0x8488C00BAC9F882AULL,
		0xB4610AB4D7C977F1ULL,
		0x3A58F55977629DD2ULL,
		0x674F679648FB01B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DFB97DB018056F8ULL,
		0xAAAEECA869CB32D1ULL,
		0xC40A3D4E57A47E03ULL,
		0x78B7AF38B7650E3FULL,
		0x135ED127C0FCA2D4ULL,
		0x834244CDBBA05A04ULL,
		0xB9042E54FB813D3BULL,
		0x311D18BAFDAF4834ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x829D090E8B1D0FCBULL,
		0x65BD41C525078730ULL,
		0x925C9F5EECE66D36ULL,
		0x6EA7EE7DDABB0AEAULL,
		0x97D6112C6C632AFEULL,
		0x37234E796C692DF5ULL,
		0x835CDB0D8CE3A0E9ULL,
		0x56527F2CB5544985ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37F43881E10E489CULL,
		0x572947B79F46CC68ULL,
		0xC59A5432A16447B2ULL,
		0x1C713A885C66062BULL,
		0x263CD7193809B4B7ULL,
		0xA5B87C031A586914ULL,
		0x92B33F403910A8D0ULL,
		0x94206606858CB56DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CA642C286C0D20ULL,
		0x0DC9B8547A01B6D7ULL,
		0x7624DDEF97EE0347ULL,
		0xF19B75C7E7695AC7ULL,
		0x6B5552729CC5A5E3ULL,
		0xD7678C9AFB0F107FULL,
		0xE02B9BCFF68EE469ULL,
		0x7319EEFDF4726206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x713E5CADC96245BCULL,
		0x5AE0FFE3E5477ABFULL,
		0xB3BE89DD368A44F5ULL,
		0xEDEA4F4FBB0F5CECULL,
		0x4D69856BA4CC1154ULL,
		0x72DFF099E157796BULL,
		0x7298A48FCF9E4CB9ULL,
		0xE73988FB71FED76BULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A4C7951A5AA0D48ULL,
		0x03F64502CDB52AE8ULL,
		0xB839803DA862B1DAULL,
		0xF6A4442496A92AD8ULL,
		0xACEC75F41AB90E08ULL,
		0xB4021F827F17CF25ULL,
		0x91C0B618E17D3435ULL,
		0x11797E4D8F2708B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4EC8F1C6A165B48ULL,
		0x5FC8FCEDFEEF6677ULL,
		0x587F2318BFD173DAULL,
		0x5C42BAB2867FBD65ULL,
		0x9DD81E9F40AD861BULL,
		0x75C680492546BF30ULL,
		0xBDD7DCDC9A372CD1ULL,
		0x0FD091FA53DED8A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEA0F64DCFBC5600ULL,
		0x5C3EB9EF335A4C9FULL,
		0xE046A32517B3C200ULL,
		0xAAE6FE9610D697BDULL,
		0x31346B6B5A148813ULL,
		0xC1C49FCB5A517015ULL,
		0x2C176AC47B4A18E4ULL,
		0x1EA9EFB7DCF9D01EULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46BD637E7F55E0ABULL,
		0x22A586D842BEA000ULL,
		0x8F9B3C4D5355504AULL,
		0xF38727B7BDE77B42ULL,
		0xE5A1BC0D38540D7DULL,
		0xF09299205E0CEC66ULL,
		0xF46405E2A4BCDE1DULL,
		0xE559FFB03F042C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08146509576D9A4AULL,
		0x59100A9E075C2B60ULL,
		0x9E2DD8B34E096627ULL,
		0x2C250EE189EC5C4FULL,
		0xB65AA8E736A09EF1ULL,
		0xEE0EB56DF57655A4ULL,
		0x360E0E24A8F1F169ULL,
		0x3C119D5BE12D6629ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EA9067728387AE1ULL,
		0x7BB58C4645E28B60ULL,
		0x11B6E4FE1D5C366DULL,
		0xDFA22956340B270DULL,
		0x53FB14EA0EF4938CULL,
		0x1E9C2C4DAB7AB9C2ULL,
		0xC26A0BC60C4D2F74ULL,
		0xD94862EBDE294A7BULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD234FA7E875F555FULL,
		0x35A30562C4EDAA30ULL,
		0x1206190A3F3F37C1ULL,
		0x42A1D80E57CB7D5CULL,
		0x0B85A59ED5B6B502ULL,
		0x8300922CA3EFBAFEULL,
		0x1DA583E738BCF217ULL,
		0x95F6989A69CE7BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA322BB2F2BC4619ULL,
		0xC7BE5D2D2B65CFD9ULL,
		0x5EE84D2AB20E2958ULL,
		0xC8470E76875DCA8DULL,
		0xE042C24D247192A7ULL,
		0x39E1778E05BC1592ULL,
		0x17F3AF57C7B820A3ULL,
		0x3531B9CAF1873403ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7806D1CC75E31346ULL,
		0xF21D584FEF8865E9ULL,
		0x4CEE54208D311E99ULL,
		0x8AE6D678D096B7D1ULL,
		0xEBC767D3F1C727A5ULL,
		0xBAE1E5A2A653AF6CULL,
		0x0A562CB0FF04D2B4ULL,
		0xA0C7215098494FC2ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2F778E35053E07AULL,
		0x6806D500A07A87EDULL,
		0x699DF342D4DD53FBULL,
		0x4680621B36C89C2FULL,
		0xA0B36EB1EA5221A9ULL,
		0x2F51BA48B739B90FULL,
		0xF584949F4A50B9D3ULL,
		0xF2DD7E9FB11F917FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF982340C053B045ULL,
		0x466A31F099B88CC2ULL,
		0xD819B1585E66B94EULL,
		0x518985C615BF4EBFULL,
		0xB1BCABB25A96D4AFULL,
		0x14ACD8EF47B3F936ULL,
		0x6F9644BDD34B71C5ULL,
		0x9C88E879C9D2980EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D6F5BA39000503FULL,
		0x2E6CE4F039C20B2FULL,
		0xB184421A8ABBEAB5ULL,
		0x1709E7DD2377D290ULL,
		0x110FC503B0C4F506ULL,
		0x3BFD62A7F08A4039ULL,
		0x9A12D022991BC816ULL,
		0x6E5596E678CD0971ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA411D2D04371B628ULL,
		0x2CF56DCAA3A62AC4ULL,
		0xDE83CBA2DFBB2F9FULL,
		0xE9C3B2656DB14B66ULL,
		0x4F4C431CB01774F0ULL,
		0x8C224B2DADF6B374ULL,
		0xBDE5B052A859E462ULL,
		0xE39DB18370F7B6C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C553120401ACB9ULL,
		0x66CC924519AFD44FULL,
		0x3A2DABCB877D609AULL,
		0x174A2D4A94ACC966ULL,
		0x361C2E0D08F3F917ULL,
		0x7DC348742BE63FDBULL,
		0xB0AB3459056C4818ULL,
		0xED3E21BF59F6230CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6D481C247701A91ULL,
		0x4A39FF8FBA09FE8BULL,
		0xE4AE606958C64F05ULL,
		0xFE899F2FF91D8200ULL,
		0x79506D11B8E48DE7ULL,
		0xF1E1035986108CAFULL,
		0x0D4E840BAD35AC7AULL,
		0x0EA3903C290195CCULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AC4279B81CF7E39ULL,
		0x79F5FBC16F4843A9ULL,
		0xE95B5E24C38B650EULL,
		0xC161A729FD8D3209ULL,
		0xB7FBDE2CDDFB2887ULL,
		0x0483312A048E1E2EULL,
		0xF4389100B8AF6A34ULL,
		0xA3CDDB7A300219B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD24602AEAA2159A3ULL,
		0x94C6D82616554A14ULL,
		0xF33DEDBAB8D3EDE6ULL,
		0xFDD50D6EEF46A0E1ULL,
		0xA4F76EC5EB1A9195ULL,
		0xB0333D2963428462ULL,
		0x28D11D068E7024CCULL,
		0x0987F20F40157AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE88225352BEE279AULL,
		0xED3323E7791D09BDULL,
		0x1A66B39E7B5888E8ULL,
		0x3CB4AA4712CB92E8ULL,
		0x130CB0E936E1B912ULL,
		0xB4B00C0367CC9A4CULL,
		0xDCE98C0636DF4EF8ULL,
		0xAA4A297570176316ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54FA5AC4BE1DFA31ULL,
		0xE93774BDC6C53276ULL,
		0x9B6B78060C164EBFULL,
		0x937BF52DDBDF7E74ULL,
		0x434EAA8A895BFE78ULL,
		0x883B2DF6B3A4F133ULL,
		0x85850873E6799B44ULL,
		0x386251CEFD7C9C69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F1C72AADEED75EULL,
		0x1E6D75FE7B8C47A9ULL,
		0x5902B1B1D41550D7ULL,
		0x24B0D07C1C0D0FE3ULL,
		0xA30B9BA202AEFCEEULL,
		0xBA15A199A2D80202ULL,
		0x5E33B1F064523EC8ULL,
		0x57E820A2E72BA12FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x360B9DEE13F32D6FULL,
		0xF75A0143BD4975DFULL,
		0xC269C9B7D8031E68ULL,
		0xB7CB2551C7D27197ULL,
		0xE04531288BF50296ULL,
		0x322E8C6F117CF331ULL,
		0xDBB6B983822BA58CULL,
		0x6F8A716C1A573D46ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9188EBD2A31FFC62ULL,
		0xDEEE92F52E87A94FULL,
		0x0F4F5EC7A93B35C0ULL,
		0x154313F9D342BF0DULL,
		0xDE8944A50B061960ULL,
		0x7BC1D617EE3C786FULL,
		0x8EFA942A6FDFE68DULL,
		0x5DA6E64A5C4ED17CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEFBF79658ADCB2ULL,
		0xEE52AA9FE14A20ABULL,
		0x0BEBA84BA364D21BULL,
		0x61773C4C35BB54FDULL,
		0x332CAB9ECA8A115AULL,
		0x755CA44A7EA77B39ULL,
		0xE9579480FC2FCB7CULL,
		0xF34A32243204A712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B6754ABC69520D0ULL,
		0x30BC386ACFCD89E4ULL,
		0x04A4F68C0A5FE7DBULL,
		0x74342FB5E6F9EBF0ULL,
		0xEDA5EF3BC18C083AULL,
		0x0E9D725D909B0356ULL,
		0x67AD00AA93F02DF1ULL,
		0xAEECD46E6E4A766EULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE4D667033B0BE41ULL,
		0xC7E1D1921FD0DAAEULL,
		0x768A0D7A044AA899ULL,
		0x1A11A5F3C75F99C8ULL,
		0xD0862883AFA6D784ULL,
		0x5B7BFC159FCB5034ULL,
		0xC46B0E4FB26359B5ULL,
		0xC6903E9B85CE9FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3376E756EAC74762ULL,
		0x8BF06546CF6E6510ULL,
		0xD6B2FE75A2573035ULL,
		0x4F4AE1644C07C1F0ULL,
		0xFB5CAFE5772EFAA3ULL,
		0x1F0C8EB0560ACE9DULL,
		0x8548484E27B44D6EULL,
		0x8F84E745B7BC1969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD3B8126D977F923ULL,
		0x4C11B4D4D0BEBFBEULL,
		0xA038F30FA61D98ACULL,
		0x555B44978B585838ULL,
		0x2BDA8766D8882D27ULL,
		0x447772A5C9C19EA9ULL,
		0x4123460195D714DBULL,
		0x4914D9DE327286B2ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B9D69D4C2311649ULL,
		0x7147A29DD4F83D67ULL,
		0xC251523E59C64DFFULL,
		0x5E1BE32E82D3B6B1ULL,
		0xD6B5BAA1C4BFC152ULL,
		0x0F3D37996F63F08EULL,
		0x968A205A5992C654ULL,
		0xD3F6DEC9959CB175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD034F59197790D9FULL,
		0x417F3F29B0478DABULL,
		0xF65F18335AA1727EULL,
		0xA5028DEDBC0D1154ULL,
		0xBFDC84468227DFAAULL,
		0xC5454689DF60A84EULL,
		0x6EEB36CAFA578D06ULL,
		0xE32F481160DD9D54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA99C4555481BD6ULL,
		0x30389DB464BFB0CCULL,
		0x340E4A0D03673F81ULL,
		0xFB196EC33EDEA7E5ULL,
		0x69693EE746981EF8ULL,
		0xCA787110B00358C0ULL,
		0xF8611690A3C54B52ULL,
		0x30D996D8F5412C21ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3A03D626A62EA0BULL,
		0xF098BE8E48745F23ULL,
		0xCC903A89D9E854BCULL,
		0x3C97B1C5AFC32603ULL,
		0x2704FC180B8D6D99ULL,
		0x66D1B8EF80D1B9F9ULL,
		0x851FB9564DD75C24ULL,
		0x5C39E1B3CC4FBD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7487DB174CFA32EULL,
		0x3E54F03F7BBD3A9DULL,
		0x1290576384B1C86AULL,
		0x4E4F906EF465B4DCULL,
		0x358C97AF90F3C7CDULL,
		0x5F9C7DC9686C26F2ULL,
		0xF522319D900236D3ULL,
		0x29B1D839E0EC1659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44E840D31EAD4925ULL,
		0xCECC4EB133C965BEULL,
		0xDE006DEA5D599CD6ULL,
		0x72D821AB5BA692DFULL,
		0x12886BB79B7EAA54ULL,
		0x394DC526E8BD9F0BULL,
		0x703D88CBDDD56AF7ULL,
		0x7588398A2CA3AB12ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10504B8F1FD0AC95ULL,
		0xEA99807E6C18902BULL,
		0x8AE536E37992ABBDULL,
		0x033DF242B5D9A369ULL,
		0x5A0ADA494C717A56ULL,
		0x36DA616670E084DBULL,
		0x1EFBA560FCB704D5ULL,
		0x6AFD16182AD8B9FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC619830171B8B6DEULL,
		0xB11DFC8F09F44443ULL,
		0xFF7CF323E98CFDAEULL,
		0xFBACBE4012BA3E9EULL,
		0x8396222E922DD644ULL,
		0x1A6D3B5582B739A1ULL,
		0x2EC66810A4CCCE4CULL,
		0x9D5E19265B15F713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD649C88E6E681A4BULL,
		0x5B847CF165ECD468ULL,
		0x7599C5C0901E5613ULL,
		0xF8914C02A7639DF7ULL,
		0xD99CF867DE5CAC12ULL,
		0x2CB75A33F257BD7AULL,
		0x303DCD70587BCA99ULL,
		0xF7A30F3E71CD4EEEULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF30BC4F3F1F06034ULL,
		0xF8A254CC020D8B23ULL,
		0xF5DADBA4BCDF2697ULL,
		0xAD6EDCA697758DD7ULL,
		0xCF71551639BB8C50ULL,
		0x9E9CECC62671841EULL,
		0x042A9F67DA396A94ULL,
		0x2819565396936B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A457B8F3212C68ULL,
		0x4F258C453ACCFE94ULL,
		0xDBB0671DD0E639E6ULL,
		0x3E4A971F75472A6CULL,
		0xB1590C0C5CE3045FULL,
		0x139407BB37BD5472ULL,
		0xDC9D897465175EBDULL,
		0x7B24EE05525B4B91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80AF934B02D14C5CULL,
		0xB787D88938C175B7ULL,
		0x2E6ABCB96C391F71ULL,
		0x93244BB9E232A7BBULL,
		0x7E28591A6558880FULL,
		0x8D08EB7D11CCD06CULL,
		0xD8B71613BF2E3429ULL,
		0x533DB856C4C82099ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8ABC325131C7A38ULL,
		0x2476035293305A3CULL,
		0xA7D5694914D9D2F5ULL,
		0xDA08F0BE087B525BULL,
		0x097EFE828591AC84ULL,
		0x4AD03A0C2D5F5BECULL,
		0xF75042D878B9E667ULL,
		0x24AD530881A35B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1921FCCBC95FA4DULL,
		0x06A0B35065033FDAULL,
		0x0B53559205AEFD0AULL,
		0x2218931C96788564ULL,
		0xEF0930BCAADDC933ULL,
		0xA56DBF9E12782CE7ULL,
		0x96F8CB679F8B4FA8ULL,
		0x44AA02193EE6D2C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0939DCE9AF898075ULL,
		0x22D6B002F63365E6ULL,
		0xAC863CDB11772FFFULL,
		0xF81063A29E03D73FULL,
		0xE677CE3E2F4C65B7ULL,
		0xEFBD85923F27770BULL,
		0x61A889BFE732A9CFULL,
		0x60075111BF458998ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A9D6A95911AB4BULL,
		0x67E4A6E2C0E63607ULL,
		0x09DB243B9BF4B7B4ULL,
		0x17832B6BA547C91DULL,
		0x63469A28A591F736ULL,
		0xA3D34C4F41A44033ULL,
		0xF6A5B17DFBD6B1B5ULL,
		0xDCC79A327A8AAD6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19F5FEE096D664E2ULL,
		0x905FE2CBA4EC31F4ULL,
		0x63D8490A4F15F1AAULL,
		0x22B7E3E68AC8B969ULL,
		0x2536CE07F3ABE4FFULL,
		0x2951C1E69CFF7135ULL,
		0x646809B46B1D12DBULL,
		0x7BCFF47EBB08D403ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E5C2849CFC7CFA9ULL,
		0xF7BB4429640A07F3ULL,
		0x6A036D31D4E1461EULL,
		0x3534C88D2F8F7074ULL,
		0x4670542F563A13C9ULL,
		0x8A828DA9DD5B3106ULL,
		0x92CDB8C990CBA36EULL,
		0xA7086E4CC182796CULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C73399D238E38CEULL,
		0x0B13F65CF099051AULL,
		0x626213C95E17C388ULL,
		0xA0FAB7DB4AFDC423ULL,
		0xF24ABBAE10BBF4C5ULL,
		0x65EACC927C5F5915ULL,
		0xF1C45499F6D2BAB8ULL,
		0xD529B11493BFCC3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED53EFDF536A35D6ULL,
		0xA227F3D195E4CCE1ULL,
		0x425404A5CB23F074ULL,
		0x2A00869349704937ULL,
		0x75147B9B7FA6626BULL,
		0x78F90E1ECB018967ULL,
		0x1C2CE1DA8E8F2D91ULL,
		0x1E6466E52CE0E042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB120D64270E40D18ULL,
		0xA934058D657DC9FBULL,
		0x2036176C953433FCULL,
		0x8AFA3148038D8D14ULL,
		0x875EC0356F1D96AEULL,
		0x1D13C28CB75ED072ULL,
		0xEDE8B543785D9729ULL,
		0xCB4DD7F1BF5F2C7DULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C6CDBAD1DE13B5EULL,
		0x3F4C0B8190180508ULL,
		0xFDD7AD3E7366B376ULL,
		0x845B020E91FE9035ULL,
		0x4462A4264D90396BULL,
		0xA1782E2F6AE3D890ULL,
		0xE7CE0FC684480AF2ULL,
		0xFCF84D70E5D8B544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4068E14C0BD58F67ULL,
		0x3D042B6CD87ECBB9ULL,
		0x917CBE2F082B4D39ULL,
		0x3F2D80E0527FE554ULL,
		0xEE8CA9AB15CFFA1CULL,
		0x7BB47495DF004B2AULL,
		0xEAAC42E0B1BE5061ULL,
		0x44DCAF2B2DADD308ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C043AE11634B439ULL,
		0x024820ED4866CEB1ULL,
		0x6CAB13117B4DFE4FULL,
		0xBB7682EEC3817561ULL,
		0xAAEE0D8D585FC377ULL,
		0xDACC5ABAB5E393BAULL,
		0x0D624D2635F65A93ULL,
		0xB824E25BC875664CULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8006CF91F4A26B2CULL,
		0x7926B7FAE71A91CFULL,
		0xAA8231C43F475381ULL,
		0xFA3EB1E4B1FB1777ULL,
		0x4751057223C03599ULL,
		0x65DB77608A6BD1B3ULL,
		0x48443A72F304C300ULL,
		0x66BE8E34837D45E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F7DF26E13078956ULL,
		0x08CDFB9C11A5E089ULL,
		0xD537A3275D758CF5ULL,
		0x02D88C7F7964D3D3ULL,
		0x59C91E76936BBA80ULL,
		0x443567303B4677FAULL,
		0xD367157E18FBB0D5ULL,
		0xAB79E208D62F048EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF7B3DFFE7A5E27AULL,
		0x71EB4C66F6BF7146ULL,
		0x7FB592E36232DF74ULL,
		0xF8E63D9BC89FC4A4ULL,
		0x1E981B04B0AB8F19ULL,
		0x21EE1050B12DA649ULL,
		0x9B232F0CEBFF73D5ULL,
		0xCDC76C3C55524167ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DEBB58961C908FCULL,
		0xD760D3CC119140B9ULL,
		0x50D3776A42499D66ULL,
		0xED330A6901E8D221ULL,
		0xD7BF6DCF3ECE0D11ULL,
		0x8AD59ED24D19F685ULL,
		0x0665825C3F023308ULL,
		0x8AC534E67679E670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E58CEE4D9B234FULL,
		0xD278F11BE2FB752EULL,
		0x6A9CCDC91041D13DULL,
		0xD218F6186C85E56AULL,
		0xDE638FA02A2D8CBCULL,
		0x2A2F5B4768E61C2DULL,
		0xC010628F367CFBA2ULL,
		0x46AE9989E12C6582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050E39672C522BB3ULL,
		0x051822D7F36A3597ULL,
		0x3A4FBAA352084C5BULL,
		0x3F2BFC716D6D374BULL,
		0x09DCE26F14E381ADULL,
		0xA0FAC59525FFEAA8ULL,
		0xC675E0D3097EC8AAULL,
		0xCC6BAD6F975583F2ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x256A09677246207FULL,
		0xF0B25E3A64D1B356ULL,
		0x18B459439768A458ULL,
		0xFDE1C3319F4274EDULL,
		0xB1453E05D6037EC1ULL,
		0x2B3E94940AB08C79ULL,
		0x7C9EF9A889E5C411ULL,
		0x84246782C4EBFACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F5685A6864CF15ULL,
		0xF255C41DEF88CDC1ULL,
		0xE049C645E0C688B9ULL,
		0x88C9823EE5D30E37ULL,
		0xB9DB1C72D0BD5B79ULL,
		0xF11FB1950024740CULL,
		0xEA377FE11A0EA2A4ULL,
		0xBCA51977EEF17462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD9F613D1A22EF6AULL,
		0x02E79A278B597E97ULL,
		0xF8FD9F0677AE2CE1ULL,
		0x7528410F7A917ADAULL,
		0x089E227706BE25B8ULL,
		0xDA2125010A94F875ULL,
		0x96A9864993EB66B5ULL,
		0x38817EF52A1A8EADULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E105C2C7D9AD1E6ULL,
		0x8CAFFA4386301446ULL,
		0xE34E619779450C1DULL,
		0xB5A33DB39B1AC791ULL,
		0x0B6831EF8F1327CCULL,
		0xB992E6E39345E071ULL,
		0xC80E1090559A8D66ULL,
		0xE464636FA4C69C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E35252B1732D7E8ULL,
		0xBDD588DB79C9BF29ULL,
		0x793CBE08EE2A1E7EULL,
		0xDD1B47DA2933B5D6ULL,
		0x61F2497DED2D02B6ULL,
		0x41F7C4E0B6F0A5A4ULL,
		0xF29E41D7D65D3E54ULL,
		0x943BCECCCF887FD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x102579076AA8060EULL,
		0x317A7298FFF9AB6FULL,
		0x9A72DF9F976F1263ULL,
		0x68B87A69B2297247ULL,
		0x6A9A7892623E257AULL,
		0xF865220325B545D5ULL,
		0x3A90514783C7B332ULL,
		0x705FADA36B4EE393ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x372FC828EEE3A7E7ULL,
		0xD4247B94B05405CBULL,
		0x8C0717258F1E9251ULL,
		0x97075C2D75598DF0ULL,
		0x0E4ACBE2E84A22A7ULL,
		0xA659BA67795F4E2BULL,
		0x15FF37DDC9A8F880ULL,
		0x64D90C328E316E91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD311FF052D7E297BULL,
		0xFA1D371EB843D2DFULL,
		0xE97D6A0E598B75B3ULL,
		0x95A86BBBF64C369CULL,
		0x4A8E613A7CF035F6ULL,
		0x8C5C5C57C8B96C5AULL,
		0x53FC1EAC812AD18EULL,
		0x5A240E4E8761ED59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE43E372DC39D8E9CULL,
		0x2E394C8A0817D714ULL,
		0x657A7D2BD695E7E2ULL,
		0x02AF37968315BB6CULL,
		0x44C4AAD894BA1751ULL,
		0x2A05E630B1E62271ULL,
		0x460329714882290EULL,
		0x3EFD027C095083C8ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7515904D94B4789CULL,
		0xC6655799DEF2DBD0ULL,
		0x56418D811ABEF42FULL,
		0x2A695F8A057C877DULL,
		0x5406D4A3AC7BBD68ULL,
		0xA4E1757CB1FAA7A9ULL,
		0x74C912C8F3716675ULL,
		0xA5959897DFB4CC8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA044CBF892F524B3ULL,
		0x2B2DA9A19580A6FEULL,
		0x1312359B21BE4136ULL,
		0xF2024BAB6E1BB5C3ULL,
		0x4AEC93F095B09752ULL,
		0xD16AB8F214B534F0ULL,
		0x04BFFD5DFE817001ULL,
		0x3412F75E7F1873BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5515BB506415C2FULL,
		0xED48FE384B727D2EULL,
		0x4553B81A3B00B519ULL,
		0xD86B14216B6732BEULL,
		0x1EEA475339CB2A3AULL,
		0x758BCD8EA54F9359ULL,
		0x7076EF950DF01674ULL,
		0x91876FC9A0ACBF34ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF82FA927F493FC26ULL,
		0x701D628AD2068801ULL,
		0x7261EC7E3D0D4DDAULL,
		0x0AD5CC9F1B067608ULL,
		0xF4E1499FDD0CB3A6ULL,
		0x44F0FC78E60E0579ULL,
		0x9EECAC2E74A806F1ULL,
		0x61EDDDE1175A10CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8805532C14C9BBEDULL,
		0x2D96368F016809E6ULL,
		0xF9FE6B5C4E4CC90DULL,
		0xE4081242A0CD381DULL,
		0x2DA943AC503C6291ULL,
		0x0ADC07E266B78BD4ULL,
		0xA2F49C69FB9BDEF2ULL,
		0xB52F1E90D8CE14B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x702AFA0BE05A47CBULL,
		0x5D8B5405D36E81E7ULL,
		0x8B9F8722734184D7ULL,
		0xEEDDDEDDBBCB4E15ULL,
		0xD9480A338D30D137ULL,
		0x4E2CFB9A80B98EADULL,
		0x3C1830478F33D803ULL,
		0xD4C2C371CF94047AULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C324C10E21459BULL,
		0x9C1DA0E1E3726BF2ULL,
		0xBA6FC1F4FA3053BCULL,
		0x2D4B171E84AA6D9CULL,
		0xA35F9486B5639230ULL,
		0xB5A39129DCD18794ULL,
		0xD504A090D2D290EBULL,
		0xBE396FEACFF26C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2009002AE645FEFULL,
		0xE3F4B3D5664911D7ULL,
		0x38BEE1B3A793BBA5ULL,
		0x1B264EDD92416AC7ULL,
		0x9AB085E0FC062402ULL,
		0xA16EE4878F59379AULL,
		0x11EB3BC99729AF00ULL,
		0x0A3CB07817541F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0C3B4C3A0451A74ULL,
		0x7FE91334853B7A25ULL,
		0x82D120475DA3E819ULL,
		0x366D59C316EB075BULL,
		0x39EF11664965B632ULL,
		0x14CD75AE5388B00EULL,
		0xC4EF9B5945FB3FEBULL,
		0xB405DF92D8A673B7ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD37FDC8A0913F5CULL,
		0xC36CB53CF36A3A0EULL,
		0x10944160A7C7DBB1ULL,
		0x563AB913B1D677ACULL,
		0x490877893E0CB321ULL,
		0xFD65BF1A6F2C1E75ULL,
		0x237970CCCB0478B1ULL,
		0x3FD6612FDAEF6B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2EDCE3FA86127E9ULL,
		0x2E7671E9F6F0B093ULL,
		0x9DE6CE68F568F8AAULL,
		0xD617073F5986B294ULL,
		0x1819E220E61252CFULL,
		0xDC4554CBA8B3134EULL,
		0x53AADBAC0878BF66ULL,
		0x14BF71097566C3B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FDA33F708F018B5ULL,
		0xED1AC4D5059A8A9DULL,
		0x8D728F0852AF231BULL,
		0x802DBE2CE850C538ULL,
		0x511195A9D81EE1EEULL,
		0x2120EBD1C79F0D3BULL,
		0x70D3AB60C37CC7D7ULL,
		0x2B691026AF89A8DCULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB2FC26EFAB03325ULL,
		0x01BF2FA14E911BF4ULL,
		0x76E50BAB396F01DEULL,
		0x8694EF45614397A7ULL,
		0x3F86B1CF6B91C43AULL,
		0x439F3D48B95385DAULL,
		0x1C3989A09FF9FB94ULL,
		0x9FFB22848D5126EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFEED9B0935CC980ULL,
		0xC802094B6325882CULL,
		0x68A6FCA49DC59A9CULL,
		0x2B782A8F07CBAF27ULL,
		0x817A9BA40DDBF02BULL,
		0x42ACDDC0EE726623ULL,
		0xA6EA0748D03338C2ULL,
		0xFED85830D8BB7EE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64C11BDE69ECFAA5ULL,
		0xC9BD26EA2DB493D8ULL,
		0x1E43F70FA4AA9B42ULL,
		0xADECC5CA66883880ULL,
		0xBEFC2A6B664A3411ULL,
		0x0133E0885721E3F9ULL,
		0xBAD38EE84FCAC356ULL,
		0x61237AB455EA580EULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56FA4A5C790D2207ULL,
		0x04FD5717FC742106ULL,
		0x858429EB206386A8ULL,
		0xD52B9FB3A78846C2ULL,
		0xD57A9708E57293BBULL,
		0x9A7E3025CAA5CEF5ULL,
		0xCA963245FD4CCE4CULL,
		0x114BCC4431572B60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8750AE8F2AC70F5AULL,
		0xFFDDF9D6BE7B4814ULL,
		0x3D0E8A9EA053EB97ULL,
		0xA85A48946A37C411ULL,
		0x563F6076458D97F5ULL,
		0x9995CC4EA27CBDA6ULL,
		0x01122A414AC77C13ULL,
		0x53C0F51AC2E08E7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1AAE4D353CA2D5DULL,
		0xFB20AEC1420F6912ULL,
		0xB88AA37580306D3FULL,
		0x7D71D727CDBF82D3ULL,
		0x8345F77EA0FF044EULL,
		0x03EBFC6B68D97353ULL,
		0xCB841804B78BB25FULL,
		0x428B395EF3B7A51AULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA50904E92FF6CCAULL,
		0x05EDEC3DA0AF8CB4ULL,
		0x19C3DA968877031BULL,
		0x04399B2C2B441097ULL,
		0xE8B3A2C5BE52CAE0ULL,
		0xBAE0148C76F75C28ULL,
		0x456FAFADE4F180C2ULL,
		0x7C9157EC980D2BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CCA88B4077F1E6ULL,
		0x88E1991221762676ULL,
		0xAB9B3C6B29595842ULL,
		0xD1EE479DA0072685ULL,
		0x260AA2A6DD9334FAULL,
		0x82856E73117BC524ULL,
		0x411300B900E8D816ULL,
		0xE71BB92B2D100C1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC89C38C5D2889D2CULL,
		0x8D0C752F81D9AAC2ULL,
		0xB258E6FDA12E5B59ULL,
		0xD5D7DCB18B433612ULL,
		0xCEB9006363C1FE1AULL,
		0x38657AFF678C990CULL,
		0x047CAF14E41958D4ULL,
		0x9B8AEEC7B51D27F7ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77966D39637CC20BULL,
		0xC1163F56CC54E1E9ULL,
		0x82AB662D23837E3AULL,
		0xE7475C004B6D2FCDULL,
		0x31047561E3A9B963ULL,
		0x060BDFB4F8E7A4C5ULL,
		0x78EC2F9D94FD2E25ULL,
		0x2403FA696D051EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD1A6C9CEF68B4BULL,
		0x2C680BF73256017AULL,
		0x6F874246CEB84898ULL,
		0xEDB14C4165F45D67ULL,
		0xC47002FF608C07D0ULL,
		0x6342AC4F7216CFC3ULL,
		0x6B34F83C8AD54BB6ULL,
		0xA5C649D7B663572EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD47CBF0AD8A4940ULL,
		0xED7E34A1FE02E093ULL,
		0xED2C246BED3B36A2ULL,
		0x0AF610412E9972AAULL,
		0xF574779E8325BEB3ULL,
		0x654973FB8AF16B06ULL,
		0x13D8D7A11E286593ULL,
		0x81C5B3BEDB66498FULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x058AE3A6195BE8D5ULL,
		0xB9279F21ECED037DULL,
		0x043F282D9F1EC8C8ULL,
		0x3F7F35B7032037B2ULL,
		0xEC124DF9F5BCB1EFULL,
		0x0DE99A36C2DF1743ULL,
		0x423223C7EF488916ULL,
		0x32EDEFD9769AF9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16D099120BAE0B6ULL,
		0x5D84A71282B70C5BULL,
		0xB16C12612BA43020ULL,
		0x0C263DB22019CDEAULL,
		0xD1F770E2E0BECEE0ULL,
		0xDDD1A0169454D974ULL,
		0xC6AB8AB6E30994EBULL,
		0xDC59AE5ABFC9A534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4E7EA3739E10863ULL,
		0xE4A338336E5A0F26ULL,
		0xB5533A4CB4BAF8E8ULL,
		0x335908052339FA58ULL,
		0x3DE53D1B15027F0FULL,
		0xD0383A20568BCE37ULL,
		0x8499A9710C411DFDULL,
		0xEEB44183C9535CF5ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22FED1EAD9B15A3BULL,
		0x54FE618A5B36283BULL,
		0x5D3E803028E5BC7FULL,
		0xB37FA948358BC211ULL,
		0x98E57240A344D61BULL,
		0x8560904F3F912986ULL,
		0x6889FAA0311B1CCEULL,
		0x60388275150D4F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE6FC07B12F69C2ULL,
		0xAE26666685C36D66ULL,
		0xB091F0E4AC29CC61ULL,
		0xBCAB71F4FF49470DULL,
		0x1AB43BF20A666EE0ULL,
		0x7DDB7BB1EC426EF4ULL,
		0x82B3BAB6121ED1BDULL,
		0x8016DFD6AA6D7D2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18182DED689E33F9ULL,
		0xFAD807ECDEF5455DULL,
		0xEDAF70D484CC701EULL,
		0x0FD4D8BCCAC2851CULL,
		0x825149B2A922B8FBULL,
		0xF8BBEBFED3D34772ULL,
		0xEA3A40162305CD73ULL,
		0xE02E5DA3BF60321EULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01534B77D6375BD6ULL,
		0x270D4D949AB53A9CULL,
		0x335CFCDD6AD3B889ULL,
		0xF5673F6A18C2CED1ULL,
		0x77A87AF4A3EB3C5BULL,
		0xDABC80B835B5F5DFULL,
		0x9D5D39E3A130A66EULL,
		0xBD6A92DC3C691376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0516ABC09CFEF26ULL,
		0xE0C25BA98AA9ADDEULL,
		0xBE443BDC85225292ULL,
		0x48B2692CD447217BULL,
		0x254ADC734AC6908EULL,
		0x8E6C84B4C5DEEED8ULL,
		0x53E4FC43CDA2A9C8ULL,
		0xEA02354CDC59D11DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD10221CBDFF8B4F0ULL,
		0xC7CF163D101C9742ULL,
		0x8D18C701EFF1EA1BULL,
		0xBDD55646CC85EFAAULL,
		0x52E2A687E92DACD5ULL,
		0x54D0040CF06B1B07ULL,
		0xCEB9C5A06C920FA6ULL,
		0x5768A790E030C26BULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE28C84C9804C49C8ULL,
		0xAAC561487A6CDA88ULL,
		0x82F144114EC8C87DULL,
		0x13009B87E2E53E3AULL,
		0x44FE63FDD5B92E0AULL,
		0x8C118C3627BCC864ULL,
		0x0D9E9A5524E4D43BULL,
		0xDD02546D7F81825FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8378FEB6D91AF6C0ULL,
		0x2496DC966BE0F186ULL,
		0x8FA887606C924F09ULL,
		0xA8ECB936A1B651EAULL,
		0x7F4D8DABAF1E453FULL,
		0x8892C6D95DF25CF9ULL,
		0x22BE5DB66437519DULL,
		0x309D5582AAA284CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61F47A7F5956BF08ULL,
		0x8E53BDDE118C2B0EULL,
		0x0D59C371225A8774ULL,
		0xBBEC22B143536FD0ULL,
		0x3BB3EE567AA76B35ULL,
		0x04834AEF7A4E949DULL,
		0x2F20C7E340D385A6ULL,
		0xED9F01EFD5230694ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A65484330FDB3FULL,
		0xB2710D662A7ABB76ULL,
		0x535613E35A331C90ULL,
		0x8A11657E6044CB5CULL,
		0x53B80502EFEF0054ULL,
		0x2F6CF57B4E5AE57FULL,
		0xE8AC7E1E203F8B8EULL,
		0xDC8522213C02EDBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B833502ED05ACA1ULL,
		0xE9FA219A63D9DBE5ULL,
		0x4D08BA8637682620ULL,
		0x6FD638C3042BD199ULL,
		0xED579301CD196D4CULL,
		0xB1D27D2DE127483FULL,
		0xEB2D6F9A87608D1CULL,
		0x2264E2F4FA64031DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C256186DE0A779EULL,
		0x5B8B2CFC49A36093ULL,
		0x1E5EA9656D5B3AB0ULL,
		0xE5C75DBD646F1AC5ULL,
		0xBEEF960322F66D18ULL,
		0x9EBE8856AF7DAD40ULL,
		0x03811184A75F0692ULL,
		0xFEE1C0D5C666EEA1ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D8B7825DEF42274ULL,
		0x8C7C727DC5F2BC73ULL,
		0x56C2311302E97131ULL,
		0x1D4E7814139B8B69ULL,
		0xCD18685ADBBB39AEULL,
		0xC54C8AF7D0D2FB4FULL,
		0x04F9699663B1E72DULL,
		0xF74A13BF2F588915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F40433D0E1CFAAAULL,
		0x1207FB6D80ECAB13ULL,
		0x87F6903AE2DF696AULL,
		0x83C24623C9DF8998ULL,
		0x285938CF8CD8F7EDULL,
		0x4012AB231F464B4FULL,
		0xF0F9B7DD0C789E60ULL,
		0xDDCB985EC73F82F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72CB3B18D0E8D8DEULL,
		0x9E7B8910451E1760ULL,
		0xD134A129E036185BULL,
		0x9E8C3E37DA4402F1ULL,
		0xE54150955763CE43ULL,
		0x855E21D4CF94B000ULL,
		0xF400DE4B6FC9794DULL,
		0x2A818BE1E8670BE6ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0173C51C39C5E6EEULL,
		0x14A714A44D1F7DB5ULL,
		0x2F2CA45B230E2927ULL,
		0x701839E2BFFA8FB8ULL,
		0x608723C271C513F2ULL,
		0x9C3A4C49B114B5E1ULL,
		0xF45B731B91105181ULL,
		0x3C3D2E173F4A8BEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143274A8566937F4ULL,
		0x1DCB05AC1EC13989ULL,
		0x28AE2F49D88C27A5ULL,
		0x55D5DDFEFC8500B9ULL,
		0x4B61C716C85EC863ULL,
		0xC583D47A128BC104ULL,
		0x6262E18C4C97D97EULL,
		0x0F063C80E2D98324ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1541B1B46FACD11AULL,
		0x096C110853DE443CULL,
		0x07828B12FB820E82ULL,
		0x25CDE41C437F8F01ULL,
		0x2BE6E4D4B99BDB91ULL,
		0x59B99833A39F74E5ULL,
		0x96399297DD8788FFULL,
		0x333B1297DD9308CEULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x872E4444A29472CCULL,
		0xA86CB4055EFBC20FULL,
		0xDF8ADCA823F1398DULL,
		0x484526B3F641DADCULL,
		0x89D69413BBD882D6ULL,
		0x009E9A5BB9F75702ULL,
		0xBACE25CC94DF5F90ULL,
		0x1AD51DB6BF85B20FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x316F5F1232942F1EULL,
		0x101E822C29FF4A5EULL,
		0x89275352744E15BFULL,
		0x753B0E56FD1BABAEULL,
		0xE4CD5EFE32B643CEULL,
		0x298DD2C827A805EBULL,
		0x67B4B4B2415B1122ULL,
		0xF0C3F50445EE38F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6411B5690005DD2ULL,
		0xB872362977048851ULL,
		0x56AD8FFA57BF2C32ULL,
		0x3D7E28E50B5A7172ULL,
		0x6D1BCAED896EC118ULL,
		0x291348939E5F52E9ULL,
		0xDD7A917ED5844EB2ULL,
		0xEA16E8B2FA6B8AFDULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC185AD26409E7B90ULL,
		0xB4B0C2ADFDEB50FDULL,
		0xBE1EDE94A9C1C112ULL,
		0x44119CD08628C4B9ULL,
		0x2CEA170A6CA15C4BULL,
		0x705FB483F05EB52FULL,
		0x58A29BA7BB9D531BULL,
		0xB75CCFE1584A3EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34078AC069A1D7B4ULL,
		0x18CB63FA42BCBE5FULL,
		0x29EF02B3F5786C9EULL,
		0xBAA21C23EC6B6DD8ULL,
		0xDB89C95E8BA9B749ULL,
		0x72334E8826CA2C81ULL,
		0xF1A0D136AA2A6552ULL,
		0xFE821455BBB169AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58227E6293FAC24ULL,
		0xAC7BA157BF57EEA2ULL,
		0x97F1DC275CB9AD8CULL,
		0xFEB380F36A43A961ULL,
		0xF763DE54E708EB02ULL,
		0x026CFA0BD69499AEULL,
		0xA9024A9111B73649ULL,
		0x49DEDBB4E3FB5773ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x795ECF79B7802509ULL,
		0x6CCC0D2CD8A9C0F4ULL,
		0xDE8CC0F38C8F77A2ULL,
		0x884DB74C46D751ADULL,
		0xF94638BB89AF9F2AULL,
		0x5D82AD5BF1368C17ULL,
		0x063DFE1B3C2293A0ULL,
		0x9877EF7F84A31990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29E8FE711E28C51ULL,
		0x55F3B546FA18E2FDULL,
		0xC95E6D0149653153ULL,
		0x432BE11423F7F7C9ULL,
		0xCAE5EC8383E5406EULL,
		0x1F3E1CB9EF37F007ULL,
		0xDEC73A6C9CA9E782ULL,
		0x1682FF1272098B16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBC0409EA662A958ULL,
		0x393FB86A22B12209ULL,
		0x17D2ADF2C5EA46F1ULL,
		0xCB6656586520A664ULL,
		0x33A3D4380A4ADF44ULL,
		0x42BCB1E21E017C10ULL,
		0xD8FAC477A08B7422ULL,
		0x8EF5106DF6AA9286ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5C97714168D51CAULL,
		0x3F73DCB49EB99235ULL,
		0x162B7AD4E7F4313DULL,
		0x37EEC2C3357A0EA0ULL,
		0x6FB35D631088284FULL,
		0x10FDCA7A59F1B37CULL,
		0x6DB0243573B0D9DFULL,
		0xB5F5DED921CE2220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E4B360BFFD11CF7ULL,
		0xDFD71F710EB897C4ULL,
		0x93152E6848F25F46ULL,
		0x1D1052738ABE32EAULL,
		0x6B130334C73BED7CULL,
		0xC78802EFAD5BF8AAULL,
		0xACE5A372FE421C39ULL,
		0x9196A1AE7060E62EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB82411FE95C4D3DULL,
		0xE0A4C3C5900105F1ULL,
		0x853E54BCAF066E7BULL,
		0x2AFE90B0BFC43C4AULL,
		0x04A05E57D7B3C533ULL,
		0xD775C895F4AA4BD6ULL,
		0xC15587478DF2C5E6ULL,
		0x24637F7751AEC40EULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x645858D21CB332DCULL,
		0xFF760D8902224CE8ULL,
		0x9C9827C07C14D600ULL,
		0xDAA6CC198F04E45AULL,
		0xE7988DD818A57C93ULL,
		0x3164EB5D2C252353ULL,
		0x18F016D51C87F26DULL,
		0x32C438E1A68A1FE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C889F8899B359EULL,
		0x534D0F3A08387147ULL,
		0x4E984E6D5B0A0821ULL,
		0x432738C164453934ULL,
		0x7511DDFC7E5C6B4BULL,
		0x649BE23876B581B9ULL,
		0x8018A008C7D2B794ULL,
		0x60CCE0396AD33ADDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7590D12A95280742ULL,
		0xAC3B02B30A1A3DAFULL,
		0xD20069AD271EDE21ULL,
		0x9981F4D8EB41DD6EULL,
		0x9289502466F917D8ULL,
		0x55FF09655A90A2EAULL,
		0x98E8B6DDDB5545F9ULL,
		0x5208D8D8CC592535ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD66E3DB7788B44EULL,
		0x33A549CCD79256BCULL,
		0xF54C563E5F40D4B1ULL,
		0xC35415C1F22AEBF4ULL,
		0xE9EC785AC9C426B7ULL,
		0x3D5E3ACECBF6F6A7ULL,
		0x7951DA51212664A5ULL,
		0xAD007480B12C2B0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C9CAB19E4FCDADULL,
		0x10AE580A7CE05A1AULL,
		0x8FD780F956318892ULL,
		0xD5503FBB501F047EULL,
		0x2B2E93D95F68C0C7ULL,
		0x327D542084896053ULL,
		0x99F9F02747282399ULL,
		0x405B47C7C4A80C40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65AF296AE9C779E3ULL,
		0x230B11C6AB720CA6ULL,
		0x7A9BD6C709715C23ULL,
		0x16042A7AA235EF8AULL,
		0xC2C2EB8396ACE670ULL,
		0x0F236EEE4F7F96F4ULL,
		0xE0A82A76660E473CULL,
		0xED5B33477584274BULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB233963B665A2E5ULL,
		0xF33349D5FEFAF6E7ULL,
		0x35AF37471E448080ULL,
		0xFFEAD598BF36AEA9ULL,
		0x7C829F53F69307D7ULL,
		0xD4B5CFA48C637116ULL,
		0xEC04666DB4E879B3ULL,
		0x7EDB38F33441AB7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51BD250964332230ULL,
		0xACF0A683F5FD735DULL,
		0xDB73033ED2791E04ULL,
		0xB29FBA9597E5B801ULL,
		0x9EF5E87551200E0BULL,
		0xF6C2A02B0CBE25C4ULL,
		0x1DA9B4FB9CEFEC5DULL,
		0x66672130C68E6D8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A9E1C6AD25680D5ULL,
		0x5FC3EF560B0785BAULL,
		0xEEDC3479CC3D9E84ULL,
		0x4D756F0D28D316A8ULL,
		0xE2777726A7B309DCULL,
		0x22776F8F80DD54D2ULL,
		0xF1ADD296280795EEULL,
		0x18BC19C3F2CFC6F1ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3071D7A521A554F5ULL,
		0x457A671E8DD611A0ULL,
		0x26039B9372FE6BFEULL,
		0xFF2063F8CDF75920ULL,
		0x92738DBFB3FBC712ULL,
		0x6A1E43423FE2BD7DULL,
		0xC2FCADF1ECCD5E4CULL,
		0x6F9BB6FD10CDDAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A8D89272BCCEB8EULL,
		0xDC5828C428B5DF54ULL,
		0xCCAA0AA7BEB3FA4EULL,
		0x75126339DD1B372AULL,
		0xC6671F670AD3118AULL,
		0x35B5AE7F16F1E645ULL,
		0x0AE601197A27C1CDULL,
		0xFC45E4DD1B1F08C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAFC5E820A69BF7BULL,
		0x99224FDAA563CEF4ULL,
		0xEAA99134CC4D91B0ULL,
		0x8A3200C110EC6E0AULL,
		0x541492D8B928D698ULL,
		0x5FABED3D29135B38ULL,
		0xC81AACE896EA9F81ULL,
		0x93DE52200BD2D23CULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3672DE0B605EBE43ULL,
		0x80265546656FF055ULL,
		0x04A521949F477F17ULL,
		0xAE0A85857BD891E3ULL,
		0x8D24D702AA632018ULL,
		0x98BB63F1585F5EAEULL,
		0xA9B920E8C05BCF4CULL,
		0x0870EC2DA1D13373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A936F0A7AAC6036ULL,
		0xD7B53EB30478054FULL,
		0x9BD2123FE4AEE42AULL,
		0x08F78912518B2EDAULL,
		0x668E2E6FC550BA42ULL,
		0xCE2F509D18113ED1ULL,
		0x011FCA2BC1C6211AULL,
		0xF974A7A77C9D4657ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CE1B1011AF2DE75ULL,
		0x57936BF56117F51AULL,
		0x9F7733AB7BE99B3DULL,
		0xA6FD0C972A53BF39ULL,
		0xEBAAF96D6F339A5AULL,
		0x5694336C404E607FULL,
		0xA8A6EAC3019DEE56ULL,
		0xF1044B8ADD4C7524ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD32AA2BA2AB7AC16ULL,
		0x9861A94738594886ULL,
		0xDAC30244C19C934FULL,
		0xA9CFF21CA96C182CULL,
		0x431133C3C0703378ULL,
		0x794514F7D071BF36ULL,
		0x5789315D9752DD8EULL,
		0xFE38F94D9887CE59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD558F36A283D77A3ULL,
		0xBEDA998EA28E979CULL,
		0x2E597D34E526BECCULL,
		0x3C1760BC177FB990ULL,
		0x690DDB104D99DDD2ULL,
		0x572E68138AE0F4BBULL,
		0x0E0936924A8121A3ULL,
		0x99BDE9BB1264FE64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x067251D0028ADBB5ULL,
		0x26BB30C99AD7DF1AULL,
		0xF49A7F7024BA2D83ULL,
		0x95D892A0BE13A1BCULL,
		0x2A1CE8D38DE9EEAAULL,
		0x2E6B7CE45A914B8DULL,
		0x598007CFDDD3FC2DULL,
		0x678510F68AE3303DULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D470641D86EC98ULL,
		0x08E322196C4C2AF1ULL,
		0xAE2D545E77C34838ULL,
		0x2EF830FCB5BEEFC6ULL,
		0x1478203CD988AF80ULL,
		0x119E629220461AFCULL,
		0x854C3EFB22A97A67ULL,
		0x0ED78AB58A5DE4A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE954C789CBC46845ULL,
		0x38BC2966D17060DBULL,
		0x0551899D51FE3F5CULL,
		0x89F995F720363051ULL,
		0xFCE71FBFC5593A86ULL,
		0xAD8B83E65F6F52F6ULL,
		0x18272B8033EC22B9ULL,
		0x903A7ED3B5EA8A13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B80B7EDD64284DDULL,
		0x305F0B7FBD3C4A2AULL,
		0xAB7CDDC3263D7764ULL,
		0xA701A50B9588DF97ULL,
		0xE89F3F831CD19506ULL,
		0xBC15E1747F29480AULL,
		0x9D6B157B114558DEULL,
		0x9EEDF4663FB76EB4ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x859E31CD32ADDCFCULL,
		0x70955096A98C3ABDULL,
		0xC69ADB842034C3CFULL,
		0x9BB7DEEEA0685A3DULL,
		0xD6DA9B59D8A9FF17ULL,
		0xDEE22814D1825D39ULL,
		0x91E95B0DDCBC162FULL,
		0x89A95A05DB6008EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA5759D1D01CF8EULL,
		0xA721649474914A3DULL,
		0x97C18DB256643A90ULL,
		0x9DD6B91229CD227BULL,
		0xA9362F5FD497C937ULL,
		0x016CB58AAF4A3408ULL,
		0x0598B2CBA61E986CULL,
		0xD8E104EA79ADB1C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB3B44502FAC1372ULL,
		0xD7B43402DD1D7080ULL,
		0x515B56367650F95FULL,
		0x066167FC89A57846ULL,
		0x7FECB4060C3E3620ULL,
		0xDF8E9D9E7EC86931ULL,
		0x9471E9C67AA28E43ULL,
		0x51485EEFA2CDB922ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1813795AB24559E1ULL,
		0xD31C383901463424ULL,
		0x9DA3B7F4D4C9C9EAULL,
		0x6DF75E6CC6E37302ULL,
		0x74D8F26B4983ED75ULL,
		0x9E7B325045AFBEB9ULL,
		0xF5B7BCA5596A3943ULL,
		0x765186F9745C315DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53199E25878A70CCULL,
		0xAE23D7F11133DB38ULL,
		0x5A3C14908C83D6FBULL,
		0xFEFDC4E1589BCF33ULL,
		0x12C5FA323E638AAAULL,
		0x2CDDB4486B878DA8ULL,
		0x55BACAA5D77810E0ULL,
		0xDBF354E330E428FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B0AE77F35CF292DULL,
		0x7D3FEFC81075EF1CULL,
		0xC79FA364584A1F11ULL,
		0x930A9A8D9E78BC31ULL,
		0x661D085977E067DFULL,
		0xB2A686182E283311ULL,
		0xA00D76008E1229A3ULL,
		0xADA2D21A44B819A3ULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD504A3D066A2F6DDULL,
		0x8A027591937AC2BFULL,
		0x396889BC5AD30A82ULL,
		0xAEC2C6061459B6DBULL,
		0x8FA131B5353E45A5ULL,
		0x8F25E7EE97FD89E5ULL,
		0x66436A340BEFCF4FULL,
		0x8F77F4BF42BA7781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F258758A94BBB9DULL,
		0xD9B712BB378EC8F5ULL,
		0x90DEF16C6948C802ULL,
		0x6E06ABB72E15D478ULL,
		0xCA6D24D25D0DB4DDULL,
		0x268A6EEC4852B96DULL,
		0xE6B973345E6EDDDBULL,
		0xA2C001528AA8CECCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA212488CFE94D40ULL,
		0x53B5672AA4F40A4AULL,
		0xA9B678D0339BC280ULL,
		0xC0C46DB13A4C62A3ULL,
		0x45CC15676833F178ULL,
		0xA9AF8902DFAF3088ULL,
		0x80FA190055811294ULL,
		0x2DB7F5EDC812B94DULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47B8EE4D9A1FC1C9ULL,
		0x7C4E1DB3E010AAD3ULL,
		0xE00DA379A7332C15ULL,
		0x4CD4BB4195C0C9DFULL,
		0x07773872CA06CBFDULL,
		0x0A08CF73A9AB00B0ULL,
		0xDFB143326953AFB3ULL,
		0x5010F296B0548BB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B816A7FDB00B396ULL,
		0x87103CE75FC7F848ULL,
		0xFB469798E1C43E39ULL,
		0xD379B665733FAEC4ULL,
		0xCD87E3D44A2B5D08ULL,
		0x23BE810929AEDF94ULL,
		0x12CE707C32695577ULL,
		0x60F891D97C4C560BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C398432411F725FULL,
		0xFB5E2154BFD7529BULL,
		0x1B4B34E146F7122CULL,
		0x9FAD0D24E6FF671BULL,
		0xCAF0DBA6802D96F5ULL,
		0x29B64E7A8005DF24ULL,
		0xCD7F334E5B3AFAC4ULL,
		0x30E8634FCC18DDBBULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BF353000C7352A1ULL,
		0x79BC201F8D075848ULL,
		0xE91394B6B341C421ULL,
		0x2AD93EAFA57AF4D8ULL,
		0xEAEC93B974A83F47ULL,
		0x5D28789A55458101ULL,
		0xFD1BA43AC307491EULL,
		0xF50BA235D1010779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD98B6BAC2102913AULL,
		0x21934ADEE42C2E86ULL,
		0xCAFD60262E4D0862ULL,
		0x9FE6FB033546386CULL,
		0xE40D23BE6C4D2639ULL,
		0x3158A9415D06D23EULL,
		0x2B0964413A30EC10ULL,
		0x551590A461B0F6E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x927838AC2D71C39BULL,
		0x582F6AC1692B76CEULL,
		0x23EEF4909D0CCC43ULL,
		0xB53FC5AC903CCCB4ULL,
		0x0EE1B00718E5197EULL,
		0x6C70D1DB0843533FULL,
		0xD612C07BF937A50EULL,
		0xA01E3291B0B1F19CULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D127A0B0A99BFFEULL,
		0x33E07C5C8CEB9CD9ULL,
		0xFCEED1E131313DB0ULL,
		0x15B5AD39382EA992ULL,
		0xF22E6A7EC3DE0476ULL,
		0x74C59E1D2C13BC55ULL,
		0x02DAE46D1A55BE17ULL,
		0x18CFBDDE3DA73514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA22F204D64C9793ULL,
		0x393426A646743B23ULL,
		0x388DA9FA37A15086ULL,
		0x79324DDE2C29B706ULL,
		0x595D1C65C623E395ULL,
		0xAA0E65B7CB3CDF6FULL,
		0x63F347E8F0C12770ULL,
		0x7F844A5BDE6480C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC730880FDCD5286DULL,
		0x0AD45AFACA9FA7FAULL,
		0xC463781B06906D36ULL,
		0x6C87E0E714071E94ULL,
		0xAB73761B05FDE7E3ULL,
		0xDECBFBAAE72F633AULL,
		0x6129A385EA949967ULL,
		0x674BF785E3C3B5D5ULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E44E4DABA723C1ULL,
		0x1AD351793C646176ULL,
		0xAC8DF648474B70E1ULL,
		0x7F8A30E67C52B667ULL,
		0x92F043AECE218D77ULL,
		0xE5B412A4DF95504BULL,
		0x0DD0BB12E47D179CULL,
		0xDD6CCA7BF910C18EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2C81C8CB242FF5BULL,
		0x8D5F54AFDD261B31ULL,
		0x14E902F3F24A0E96ULL,
		0x6D3E32852C4FB770ULL,
		0xDE26C1E12B553FDBULL,
		0x6D046A78BFDB79E4ULL,
		0x781CDFC21C266E92ULL,
		0x4BC92966782A4DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x652C52C119E5DC9AULL,
		0x978C05D6E1427A47ULL,
		0xB864F4BBB5017E77ULL,
		0x12B40263501D0117ULL,
		0x4CD6824FE574B2ACULL,
		0x88B078DC604E29AFULL,
		0x75CC64D0F85B790EULL,
		0x96A5E31D813A8C3FULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80BE8AD2FFBC2550ULL,
		0x07E0F948FCB2E307ULL,
		0xEAA8AE43DB3BFA0EULL,
		0x479371C21D1FB914ULL,
		0x46B3B50D2B05B886ULL,
		0xA2F2F2BED645F9C1ULL,
		0x5AB8EB69C3E40327ULL,
		0x1F09D74D0CAC8211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF098A0947770943ULL,
		0x07A8759FF5538CBDULL,
		0x0712C23735255CB5ULL,
		0xCEE4DBB1518BE785ULL,
		0xC5543C8FEDFF8345ULL,
		0xFA2EA93BE408E306ULL,
		0x9DD4A3FAEF0F6DDEULL,
		0x66F4F5A873767D80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FB700DBB8CB2C13ULL,
		0x00488CD709E16FBAULL,
		0xEDBA6C74EE1EA6BBULL,
		0x8977AA734C945E91ULL,
		0x83E78982C6FA3BC3ULL,
		0x58DC5B85324D1AC7ULL,
		0xC76C48932CEB6EF9ULL,
		0x79FD22E57FDAFF91ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD644FC2799B7115BULL,
		0x95EDEC019BF9A0C3ULL,
		0x863AEE372D843E0EULL,
		0xF459A1F4ECACD350ULL,
		0x15F019DC475A1A2DULL,
		0xB02602F170C2EF2CULL,
		0x6502DA92A85EFCC0ULL,
		0x912A1E277B6264F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51224BD3DCD9C5F9ULL,
		0x2466BCCF7508CCA0ULL,
		0x35BDA5F4B0B156A3ULL,
		0xC84D99D843715E74ULL,
		0x9D38EA6D31A1998DULL,
		0x2AF73B1C4D826D49ULL,
		0x8916027B0AEA510FULL,
		0x765665B62D728C2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8766B7F4456ED4A2ULL,
		0xB18B50CEEEF16C63ULL,
		0xB3874BC39D3568ADULL,
		0x3C14382CAFDD8D24ULL,
		0x88C8F3B176FB83A0ULL,
		0x9AD139ED3D408265ULL,
		0xEC14D8E9A2B4ADCFULL,
		0xE77C7B915610E8DDULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE59395F3E1853E4EULL,
		0xA7A13E826D93C7E7ULL,
		0x0CF0C260D7CCAA66ULL,
		0xFD4A7C15531B8E5BULL,
		0x009795A887A091E1ULL,
		0x9581657947C9CD98ULL,
		0x1EA0FF361F0436F3ULL,
		0xFFC05F16D2F35901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B4B0C168FAD6F9ULL,
		0xDAD10A4AC2A20503ULL,
		0xF069321CD55178C5ULL,
		0x5FCFCB9BC4A0A614ULL,
		0xE594EE049725F28AULL,
		0xE1E45819E429AD3FULL,
		0x669CB779A868EE1DULL,
		0x04B15882CCCEFDAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62272532897FE8B7ULL,
		0x7D7034C8AF31C2E4ULL,
		0xFC99F07C029DD2A3ULL,
		0xA285B78E97BB284FULL,
		0xE5037BAC1085636BULL,
		0x74653D60A3E060A7ULL,
		0x783C484FB76CD8EEULL,
		0xFB7107941E3DA4AEULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDE8B864C53AE874ULL,
		0x9883998E9905CD47ULL,
		0xCACD3B8562628616ULL,
		0x94A7A2E17EFF049AULL,
		0x78798CE861C611D5ULL,
		0x73BDB67FE35438A3ULL,
		0x882BFBF1B34FE31AULL,
		0x122678137E714F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D2A5773F708F5CULL,
		0x98FF09697423D555ULL,
		0xC0AFAED703F353CBULL,
		0xC1A198C0FD4B9D1EULL,
		0xCF40CD76C915A0F9ULL,
		0x00A829FC3346FFB7ULL,
		0xB54148F36496535AULL,
		0x16B5E55D8177158AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x983A1D13FA4A6728ULL,
		0x007C90E7ED261812ULL,
		0x0A6295526191D5DDULL,
		0x55063A2183B49984ULL,
		0xB739419EA8D3B12CULL,
		0x73159F83D012C714ULL,
		0x3D6AB302D7D9B040ULL,
		0x04939D4EFF065A14ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D261CAC2C217E67ULL,
		0xEE1E6E76297A8A6DULL,
		0xB243E503858B1AB5ULL,
		0x17598DE5017B6608ULL,
		0xBB23662B8F1F6EA8ULL,
		0xC16B0F2A331EBDACULL,
		0x64CBF6E1AE285126ULL,
		0x6CDE25D51DAF3962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1199572A539DFC8ULL,
		0x645D61447995E5EFULL,
		0xD1645FAB5ED6751DULL,
		0x6212340399DA4F50ULL,
		0x5B096436FCD5CF2BULL,
		0xDF66D1E32724D618ULL,
		0x27A0383736C37CE1ULL,
		0xB9883DBF96AB106FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC3F89DE8918A1AFULL,
		0x8A430F3250EF6F82ULL,
		0x6327BAA8DB5D6FA8ULL,
		0x754BB9E698A12958ULL,
		0xE02A021D73CAA183ULL,
		0x1E0DDEC9143A6BB4ULL,
		0x436BCED698EB2DC7ULL,
		0xD556186A8B04290DULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x698CA65F7C82A12FULL,
		0x4236D7E848DAF7DCULL,
		0xBEB27C64CD2C1B5BULL,
		0xD76AC6FFB1B2CEDAULL,
		0x170E36A4B2D93294ULL,
		0x29C8B22EE1FF3DA4ULL,
		0x9B5CE11D07B176B5ULL,
		0xD82FBD3840C68138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB3D6688EDF968EULL,
		0x1865A1DB086E6095ULL,
		0x67AA1459C2801496ULL,
		0x3095C0965AE96F09ULL,
		0xC7E2D8108224D0CFULL,
		0x7AD9670DF62E89D2ULL,
		0x5DB9F16BE29AF7E9ULL,
		0x7327253C18FF926AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x743F7037F25D37A1ULL,
		0x5A53763340B49749ULL,
		0xD918683D0FAC0FCDULL,
		0xE7FF0669EB5BA1D3ULL,
		0xD0ECEEB430FDE25BULL,
		0x5311D52317D1B476ULL,
		0xC6E51076E52B815CULL,
		0xAB08980458391352ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55E73E8C77D2B1ECULL,
		0xA757E205F900BE4EULL,
		0xD15FE36A7245C849ULL,
		0xAA4844CF88553495ULL,
		0x79B8A95E699EDE19ULL,
		0x8DFF13F9C9AF7029ULL,
		0xBD64E083119D22F2ULL,
		0xE3A22BBDDCA86066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA54DB335F93E15A1ULL,
		0x77CAD7C9C920D1F3ULL,
		0xD9C62C36C3F29D7DULL,
		0x9DD92E91ED67CE62ULL,
		0x3DD710F2651F17DEULL,
		0xB8651461E3A29AE7ULL,
		0x4C4D16A1E2AF0D81ULL,
		0x9CFEB63B90A60AF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0AA8DB98EECA44DULL,
		0xD09D35CC30206FBDULL,
		0x0899CF5CB1B75534ULL,
		0x37916A5E6532FAF7ULL,
		0x446FB9AC0C81C9C7ULL,
		0x359A07982A0DEACEULL,
		0xF129F622F3322F73ULL,
		0x7F5C9D864C0E6A96ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E9DEB44C92A0D0EULL,
		0x8E5C676E51142981ULL,
		0xE6BE84B1816BCF68ULL,
		0x53A2D6E6A32BCCCDULL,
		0x9FC8901067465078ULL,
		0x745A57F10BDAC34FULL,
		0xA8C4751D816B5B97ULL,
		0x61F9B11E46FCE15CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1E86CE57B54F94EULL,
		0x7F69208C218BD368ULL,
		0x0161A80314C2F1A4ULL,
		0x49B2E2693DA716ADULL,
		0xAAFCA4964F38798DULL,
		0xD82C717C1133C409ULL,
		0xD7D7F10D74DAB213ULL,
		0x4D0E4089B7DA58A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7587A1B27EF440ULL,
		0xF13547E2709FFAE9ULL,
		0xE7DF2CB295A93ECCULL,
		0x1A10348F9E8CDA60ULL,
		0x35343486287E29F5ULL,
		0xAC76268D1AE90746ULL,
		0x7F138410F5B1E984ULL,
		0x2CF7F197F126B9F8ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9D2FCB8564B502EULL,
		0x826A732854CBF238ULL,
		0x0582E0E85B0D3D04ULL,
		0x0E460B1F0D4E0DB0ULL,
		0xBA13CD4A0ADD8FA3ULL,
		0x21D6BFBD6FFE8D10ULL,
		0x7E881FE321288962ULL,
		0xFDA362F1CEBF8943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86BB82E34F247187ULL,
		0x0026B9260D98C762ULL,
		0xAAE3AE7DF8485909ULL,
		0xA3500BE4F2777E1AULL,
		0x6C96D8C6B9E1EFFBULL,
		0x658243FAAB6629F9ULL,
		0x19BF86E5412DC24FULL,
		0x7D294101B5C4AE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F697E5B196F21A9ULL,
		0x824CCA0E5953355AULL,
		0xAF614E95A345640DULL,
		0xAD1600FBFF3973AAULL,
		0xD685158CB33C6058ULL,
		0x4454FC47C498A4E9ULL,
		0x6737990660054B2DULL,
		0x808A23F07B7B27DEULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D93CBA6F64BA96EULL,
		0xE8837B374993C467ULL,
		0x4E9F561245FA3526ULL,
		0xDBF7B83E4FAF06FFULL,
		0x17E0E79090A39AC2ULL,
		0x7A9FC54588F4F473ULL,
		0x0D9D79CA2254F4C8ULL,
		0x4419B357EA3F3339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFB7EB570BDB032AULL,
		0x032D84A6B785D329ULL,
		0xB4E6EF111DC30B42ULL,
		0x7F45224982276AB4ULL,
		0x3F3930EE9A04B72BULL,
		0xD5F64913BA6705DEULL,
		0xB905837E26337A2EULL,
		0xA49E0267D665DBE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF22420F1FD90AA44ULL,
		0xEBAEFF91FE16174EULL,
		0xFA79B90358393E64ULL,
		0xA4B29A77CD886C4BULL,
		0x28D9D77E0AA72DE9ULL,
		0xAF698C563293F1ADULL,
		0xB498FAB404678EE6ULL,
		0xE087B1303C5AE8D1ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12EEFC4F093673C4ULL,
		0x83C7F70BBEB37364ULL,
		0x2976500789767AAFULL,
		0xF3ADA26E159CC3D7ULL,
		0x1947411733ACBA72ULL,
		0xBDF556AC4E65605AULL,
		0x1F9B22619BD29D7DULL,
		0x7ED00FE0DACE7917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB279FBD469129487ULL,
		0x379E94F39AF63D01ULL,
		0xF5C8D1D44A0609F8ULL,
		0x235DD61B396421B1ULL,
		0xA719069F33E1B70EULL,
		0xC64ACB8381EFF149ULL,
		0x542CDB187BE97FC3ULL,
		0x1FA39A4171EC460CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA097079B6024E743ULL,
		0xB45963F824454E65ULL,
		0xDCBE81D3C3707357ULL,
		0xD0F074752CF8E266ULL,
		0xBE5E4788004D0D7CULL,
		0x7BBF9D2FCF8A9113ULL,
		0x4BB7F979E03BE2BEULL,
		0x617395A1AB223F1BULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDCF28FB664FC767ULL,
		0xEF334C216EEB791FULL,
		0x8DA999F7106A8C2EULL,
		0xA048D99F673462E9ULL,
		0x066B2C0D013688FEULL,
		0xBE904EC39F60E507ULL,
		0x693BCB1BD223A2E3ULL,
		0xBBE2A8A1A1BA85F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F94C46E80236B2ULL,
		0x6170343EB637AB3FULL,
		0xE7DAAB68AEAFB97CULL,
		0x0948548BC66304EAULL,
		0x7FC7B3A89987C2CBULL,
		0xA8B07214A96828E7ULL,
		0xDBA9D36A400AD06BULL,
		0xFB919AA6ECA75993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53664BD8E4DF1D5ULL,
		0x8E43781FD8DCD220ULL,
		0x6A73329FBEC53552ULL,
		0xA9008D14A1576603ULL,
		0x79AC9FA598B14A35ULL,
		0x16203CD73608CDE0ULL,
		0xB292187192297288ULL,
		0x407332074D1DDC67ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12F5CFB2D89AD95EULL,
		0x5630039BB9598B26ULL,
		0xA7D9107B672E71D3ULL,
		0x782112B951559DFDULL,
		0xFA8417C1C938D045ULL,
		0xFD6D26D89E3C21E8ULL,
		0xCEB21D839C2017A2ULL,
		0xBB15513ED5F56046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E26597F5FC0F29ULL,
		0xF6879DF99A84D242ULL,
		0xD61347D99D935EB8ULL,
		0x1CFBAAD60B5C79D4ULL,
		0xC4AE08740C044005ULL,
		0x837A801881C85F5EULL,
		0x84D086F414CEFBE9ULL,
		0x205112BCEC4EC75FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6217AA252D66D677ULL,
		0xA0B79E6223DD5964ULL,
		0x71CA57A2FABD2F6BULL,
		0x64DAB86F5A09E429ULL,
		0x3E2A1FB5C53C9040ULL,
		0x7E17A6C01FF47EB6ULL,
		0x4A629B7788EEEC4BULL,
		0x9B44438239BBA719ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x692C949B6FF641E2ULL,
		0x9F65294C6437061FULL,
		0xF2E428B3CF6DDC8FULL,
		0xBE67D481CFD05B9EULL,
		0x8F999B42A600B8B4ULL,
		0x0851C65FF36D8967ULL,
		0xB7A425F3C07597BBULL,
		0xD53C202BA1F3B513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F9E63D1BF25DF75ULL,
		0xBBCB1A39155B2DFCULL,
		0xFBBD50890096A244ULL,
		0x5E9C20EC26BD055CULL,
		0xBF6E7989791AD3A6ULL,
		0x8BAB8AF6FB15CC45ULL,
		0x4AC6B61B45036B6AULL,
		0x12B3509105E15ABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26B2F74AD0D39E97ULL,
		0x24AE3375716C2BE3ULL,
		0x0959783ACFFB7ECBULL,
		0xE0FBF46DE96D5EC2ULL,
		0x30F7E2CBDF1A6B12ULL,
		0x83FA4CA908784522ULL,
		0xFD6293E88576FCD1ULL,
		0xC78F70BAA412EFACULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD91F7F6D421C1DCDULL,
		0xEEB7AAC41D415428ULL,
		0x0AF6B6B389493F37ULL,
		0x942991689655C943ULL,
		0x82CFAA19B5866FFEULL,
		0x4D20D0B7CA2C87B3ULL,
		0xAC563C462350555AULL,
		0x839D51D0D666EBB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE1986B534204F4ULL,
		0x41FA747E2EE33859ULL,
		0x74399BEBD10D4AAFULL,
		0xC7B7D98CEB50CB90ULL,
		0x2F37C084B53BEC32ULL,
		0xC2DF046723DEE668ULL,
		0xF7387295657447A6ULL,
		0xB729CE818CF00233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56FEE706115E1939ULL,
		0xAF4DDEBA33A26C71ULL,
		0x7ECF2D5858447598ULL,
		0x539E48E47D0502D3ULL,
		0xADF86A9D00BD83CCULL,
		0x8FFFD4D0E9F261DBULL,
		0x5B6E4ED3462412FCULL,
		0x34B49F515A96E982ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99E07421C7493322ULL,
		0xD244D94C0CBF2247ULL,
		0x5649956FEB59EA77ULL,
		0x734156117E8C198AULL,
		0x2746FB877CAC45C7ULL,
		0x6B50E2E02AD2601DULL,
		0x454E3D464D21714BULL,
		0x1EDE24B86D5315A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62FAFEF9C891D03DULL,
		0xA7199D24023C7446ULL,
		0x5923ADDB2144EF68ULL,
		0xD463A6F4F263CC8DULL,
		0x3254EFFF00BB51FCULL,
		0x9716B23C33DDC036ULL,
		0x66DAD54D7CB48668ULL,
		0x86C8E49D7951C64EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB1A8AD80FD8E31FULL,
		0x755D44680E835601ULL,
		0x0F6A38B4CA1D051FULL,
		0xA722F0E58CEFD507ULL,
		0x151214787C17143BULL,
		0xFC4650DC190FA02BULL,
		0x2394E80B3195F723ULL,
		0x9816C0251402D3EAULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23B1309C4297FEE9ULL,
		0xA4367B9C5BF32EE6ULL,
		0x826BDA158F1D16A8ULL,
		0x8705C2D8F8EC67F8ULL,
		0xB7AD0FC06FC9BB5DULL,
		0xB3AC67B736FBBE0EULL,
		0x97C49333F0E920BCULL,
		0xED4FF7D9E3A8FE3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133ED0BD91C98321ULL,
		0xC36DD93F465665B5ULL,
		0xAE640F5BEEE008FBULL,
		0x1811F70949552874ULL,
		0xCB3E73933FF2D9D5ULL,
		0xA0E785F5F0FF424FULL,
		0x036C0B09D78C4F34ULL,
		0x66C3AF660284CEB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x308FE021D35E7DC8ULL,
		0x675BA2A31DA54B53ULL,
		0x2C0FD54E61FD1E53ULL,
		0x9F1435D1B1B94F8CULL,
		0x7C937C53503B6288ULL,
		0x134BE242C604FC41ULL,
		0x94A8983A27656F88ULL,
		0x8B8C58BFE12C308FULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x945281E3792B6C12ULL,
		0x0FA37A90CB2C411FULL,
		0x5A8D3DB51F3B877FULL,
		0x001A8EE1AD657B17ULL,
		0x7D6513DF74C8123FULL,
		0xDB2E015597748C13ULL,
		0x4C38C280BD260AC7ULL,
		0x062FE5E7687FF97EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF79F74B844C98BAULL,
		0x7C28A17E7B091FC4ULL,
		0xFA6532A92357493BULL,
		0x5CD6C30505F48C0AULL,
		0xB54E781A8562FBC4ULL,
		0x4A0680FF51899771ULL,
		0x98A35764893FBEF2ULL,
		0x3570E82CE9AE44CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B2B76A8FD67F4A8ULL,
		0x738BDBEEB0255EDBULL,
		0xA0E80F1C3C6CCE44ULL,
		0x5CCC4DE4A891F71DULL,
		0xC82B6BC5F1AAE9FBULL,
		0x912881AAC6FD1B62ULL,
		0xD49B95E43419B435ULL,
		0x335F0DCB81D1BDB2ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5368EACE5B6B238ULL,
		0x3F5BF35CEECC7FE6ULL,
		0xCE435B7A158D8547ULL,
		0x5C49862189D1CD99ULL,
		0x2AA86F5EB7411ED4ULL,
		0x465C44847D4F510DULL,
		0x3AE116821605C29CULL,
		0x1AED890D5DA9E519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x465467B10A71545AULL,
		0xA163F8B333ADA55DULL,
		0xC77F4A5DE5D5F178ULL,
		0xA167AD78CFA19C41ULL,
		0xFD5F053B3A693E44ULL,
		0x21D37B5FB42FEB3FULL,
		0x33A20130A84CC3F9ULL,
		0x98640A1C6C3475A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA362E91DEFC7E662ULL,
		0x9E380BEFDD61DABBULL,
		0x093C1127F058743FULL,
		0xFD2E2B59467051D8ULL,
		0xD7F76A658D282090ULL,
		0x678F3FDBC960BA32ULL,
		0x094317B2BE490165ULL,
		0x82898311319D90BCULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D25B286ED1F1C11ULL,
		0xC3A912D9C99251DAULL,
		0x0713970C0D36CEAFULL,
		0x72527AC2D35546A7ULL,
		0x32FBFFD65C724DA5ULL,
		0xD24273DFCE38BEAAULL,
		0x43D5738F2D9B13A4ULL,
		0x480EF77F4D212748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4E2C3D27F5BAA5ULL,
		0x57EBF1CCDD74CDB7ULL,
		0x92FD3BB55EBE3C34ULL,
		0x35FF49090B971B2EULL,
		0x6A4893B92BC2A2BDULL,
		0x49833D0B0A78C2F7ULL,
		0xE5F24A4DB236EFB8ULL,
		0x4C1D915BC9A77B28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC26B9EBBCAEAA6B4ULL,
		0x9442E31514E69C6DULL,
		0x95EEACB95388F29BULL,
		0x47AD33CBD8C25D89ULL,
		0x58B36C6F77B0EF18ULL,
		0x9BC14ED4C4407C5DULL,
		0xA62739C29FADFC1CULL,
		0x0413662484865C60ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89F08BCDCE141E60ULL,
		0x61DE42DF491FDADCULL,
		0x6A2BA5AB0671B275ULL,
		0x607427D4712D66DAULL,
		0x9678F4BF85AF9245ULL,
		0x799DD45488732B95ULL,
		0x285BFA447BAD3081ULL,
		0x676B68670F9341ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F326CFD5656C19DULL,
		0x37214B4AF0BC9176ULL,
		0x74637D4F108A8AC1ULL,
		0x09D5F929F42A2A79ULL,
		0x89F6C749CAE0AFC7ULL,
		0x4C7F751D133118FBULL,
		0x0E77C58ADDB4A11FULL,
		0x00A947EE81ADAC01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6C2E7309842DFFDULL,
		0x56FF0995B9A34BAAULL,
		0x1E48D8E416FB38B4ULL,
		0x69A1DEFD85074CA3ULL,
		0x1F8E33F64F4F3D82ULL,
		0x35E2A1499B42336EULL,
		0x262C3FCEA619919EULL,
		0x67C22F898E3EEDADULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFB2B513B83E34E1ULL,
		0x6EA87F2EE5554203ULL,
		0x90442D74641855E8ULL,
		0xAD98A5B1E9DB2E3AULL,
		0xA816D187F500871FULL,
		0xFED9CCFA5665A422ULL,
		0x6060935BCE81A495ULL,
		0xEB5418C5805E2270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DEAE29AFBC72F60ULL,
		0xDAA32C06B9058C43ULL,
		0x6B7E3479D8336D78ULL,
		0xE37AEB3F159E3104ULL,
		0xC2CE374282FB2DDDULL,
		0x55F5801864ECA05FULL,
		0x321019856828888CULL,
		0x8ED20AECEF5E06F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB258578943F91B81ULL,
		0xB40B53285C50CE40ULL,
		0xFB3A190DBC2B3890ULL,
		0x4EE24E8EFC451F3EULL,
		0x6AD8E6C577FBAAC2ULL,
		0xAB2C4CE23289047DULL,
		0x52708ADEA6A92C19ULL,
		0x658612296F002484ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5441660AD4CB7BFFULL,
		0x5ED7F7CDA6A1BC55ULL,
		0x0DC22486B69FF97DULL,
		0x213496C47211076DULL,
		0xB63A19B4233C4E8BULL,
		0x6AF90391FE348835ULL,
		0x63A5E5478557B1ECULL,
		0x21D59F228D6B1E39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63357777F040C343ULL,
		0x45E448EEAE44BEC9ULL,
		0x714F590171DB332AULL,
		0xCD8B6CC02B4DD89CULL,
		0x601B20E1E94A753AULL,
		0xA28ECED575A37FCCULL,
		0x7022AD0164009F1EULL,
		0xA31CD1C257EB98CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3774117D248BB8BCULL,
		0x1B33BF2308E5029CULL,
		0x7C8D7D87C744CA57ULL,
		0xECBFFA04595CDFF1ULL,
		0xD6213955CA763BB1ULL,
		0xC877CD448B97F7F9ULL,
		0x13874846E1572EF2ULL,
		0x82C94EE0DA8086F7ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DEF0E0FF5565A26ULL,
		0xE5AB137D3A78099AULL,
		0x8C600E6D9E71ED92ULL,
		0xC31534BDDEF49978ULL,
		0xBA218231821F5992ULL,
		0x0045B84132268EFBULL,
		0x693AB39CEDE2360BULL,
		0x292F00F3C36D62B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61E1B2705B6321E1ULL,
		0x1E74BDAC77F4A7CFULL,
		0x38A109EA7DC16B0BULL,
		0x90A4C81DA528FD3EULL,
		0x88B5ED3046985C9CULL,
		0x66CDDBCC492220FDULL,
		0xF3BAFDDAC885D054ULL,
		0x77C668AC6EE544CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C0EBC7FAE357BC7ULL,
		0xFBDFAED14D8CAE55ULL,
		0xB4C10787E3B08699ULL,
		0x53B1FCA07BDC6446ULL,
		0x32946F01C487050EULL,
		0x6688638D7B04AE06ULL,
		0x9A804E462567E65FULL,
		0x5EE9685FAD88267BULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x510C4713E6507C95ULL,
		0x0CE06834A834C17BULL,
		0xAE12254372112443ULL,
		0x13B3AC9BD9D68DC7ULL,
		0x6876A4B289BB584BULL,
		0x0F25C02C5DC23343ULL,
		0xEC88594E5FD8565FULL,
		0x0D94582C7CCF7403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD2F660CF4E640AULL,
		0x104B78FAA6020257ULL,
		0xD18ABCF6311F487FULL,
		0x2D79CD21B93480EBULL,
		0xA378A6CDECA48223ULL,
		0x0D29C373DA1DAB99ULL,
		0x835A8B01C2A07684ULL,
		0x76E437D8C4EF0A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CDEB173291E189FULL,
		0x1CAB10CE0E36C32CULL,
		0x7F9899B5430E6C3CULL,
		0x3ECA61BA60E20D2CULL,
		0xCB0E027F651FDA68ULL,
		0x020C035F87DF98DAULL,
		0x6FD2D24F9D7820DBULL,
		0x7B706FF4B8207E1FULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF37852BEA0C3F0FEULL,
		0x48BB86E09C126115ULL,
		0x3ACEBAFF9F920F55ULL,
		0x43EEF97C5DD0D42EULL,
		0x8AE5767121A7B93EULL,
		0xF8E71B5A9953477AULL,
		0xAE8D9A97A0CA4ACDULL,
		0xB742B8C133FF4D1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0489BE670B5CCADULL,
		0x2B57827FCD57F842ULL,
		0xF0BF3ED9CE56C36FULL,
		0x0FEFB4498ADF257BULL,
		0x34AE1323138768FBULL,
		0x2F82AD34AE61177AULL,
		0xE36A8448A234D4C5ULL,
		0xE128BDD70600DB08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5330C958D0763C53ULL,
		0x63EC049F51459957ULL,
		0xCA71842651C4CC3AULL,
		0x4C014D35D70FF155ULL,
		0xBE4B65523220D1C5ULL,
		0xD765B66E37325000ULL,
		0x4DE71EDF02FE9E08ULL,
		0x566A051635FF9617ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25F85ACBBF67F6B2ULL,
		0x256C388D1BF0B66DULL,
		0xD5C5C092B5827905ULL,
		0x9088BF852026F709ULL,
		0xD5EAE286FF13670FULL,
		0xC3EDB857796EF931ULL,
		0x6B524195B3A931DBULL,
		0x161286AD530B8F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13985F04B6567517ULL,
		0x08BE0A6EAB8B24EBULL,
		0x289FF6475969CBF2ULL,
		0x5AAF51A4ABC3AE41ULL,
		0x8371C0C2BF4913A9ULL,
		0x1FC4431A16297D4FULL,
		0x04C174A15F31F871ULL,
		0x4B5733A40C55A0CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x366005CF093183A5ULL,
		0x2DD232E3B07B9286ULL,
		0xFD5A36D5ECEBB2F7ULL,
		0xCA27EE218BE55948ULL,
		0x569B2244405A74A6ULL,
		0xDC29FB4D6F47847EULL,
		0x6F933534EC98C9AAULL,
		0x5D45B5095F5E2F88ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x930F15CE1EEC864CULL,
		0x5CF8659180E6684EULL,
		0x2D7F3E2625A9957FULL,
		0xF6AF8BA3A531FFEFULL,
		0xDF82495A94F02000ULL,
		0xBCEE778E89B89695ULL,
		0xCBDD801E251F061AULL,
		0x672DF87F496D5444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09918222AA679D4ULL,
		0xB324E9AB12BA304AULL,
		0xFEF18D542AECBC07ULL,
		0xE5C334190B6EB4D7ULL,
		0x778B8D6F723C29F6ULL,
		0xBF54BA3E3FAEDF53ULL,
		0xE7FDC1BE863D2192ULL,
		0xEE778D48A88773E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63960DEC344AFF98ULL,
		0xEFDC8C3A925C5804ULL,
		0xD38EB3720F452978ULL,
		0x136CBFBAAE5F4B38ULL,
		0xA809C435E6CC09F6ULL,
		0x03BACDB0B61649C6ULL,
		0x2C2041A0A3222788ULL,
		0x895A7537E1EA27A2ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD158DB3E5004A7B9ULL,
		0x2D5646F62D4179C3ULL,
		0xF700335C0CD59BA1ULL,
		0xB62F142D7D9BF333ULL,
		0x357F85CA4DD72321ULL,
		0x40AF42761BB781F7ULL,
		0xA69EA0EA8C86ED2FULL,
		0xFC395F451C076BA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE80FD5CCF6BFD6ULL,
		0x3621CF7C534726C3ULL,
		0xB95F43DF59181C3CULL,
		0xC0B08CAD3B92C3EBULL,
		0xE10AA3CF19219493ULL,
		0xAC69B85EF0F77AADULL,
		0xA70479FEB1A44AC7ULL,
		0x84704674C9529710ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB0D4EB9CF2186FULL,
		0x1B77898A7E065F00ULL,
		0x4E5F708355CD879DULL,
		0x769F9880460930D8ULL,
		0xD475260554F6B7B2ULL,
		0xECC6FA28EB40FB5AULL,
		0x019AD9143D22A7E8ULL,
		0x78491931D555FCB8ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB796DFA2520DC15FULL,
		0xCFECF7AFB9EA291DULL,
		0x3235112E7615D2C2ULL,
		0xF5521C92B2D4E348ULL,
		0x216E2298C3C315DFULL,
		0xA6526BC8CA1C8BB9ULL,
		0x6BB7B36483CFAF96ULL,
		0x6F7CF3E264AB90ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C98B42100CA69AFULL,
		0xD48A0FC19EF22796ULL,
		0x9911290DBE587981ULL,
		0x36097DD256AE5777ULL,
		0x4598FF416EA27990ULL,
		0x8A217064A7479EDBULL,
		0x92F0DD83153FEEABULL,
		0xF7DC39017F7C31CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB0E6B8352C7A8F0ULL,
		0x1B66F86E27180E8BULL,
		0xAB243823C84DAB43ULL,
		0xC35B6140E47AB43FULL,
		0x64F6DDD9AD616C4FULL,
		0x2C731BAC6D5B1562ULL,
		0xF9476EE796F0413DULL,
		0x98A0CAE31BD7A126ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47B8294DBEF9F0DBULL,
		0xBBCB387DE0EB1DFCULL,
		0x3B6FB362C0DFB3D9ULL,
		0x1E49B8AED39115DCULL,
		0xC560EECDFFF2F165ULL,
		0x14EFA0F211018C39ULL,
		0x380049C00459EE66ULL,
		0x38DD04774581FAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923E1BB911654E4FULL,
		0x44F16F1F7B0FF6CDULL,
		0xC6E22A5147A5B6A6ULL,
		0x170BEC690DD6558BULL,
		0x0B5277465673C155ULL,
		0x5CEE7CBD473261C2ULL,
		0x652919B2381A89B8ULL,
		0xE972F2F0A4809C33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD58632F4AF9CBE94ULL,
		0xFF3A57629BE4EB31ULL,
		0xFD8D9933877A057FULL,
		0x094254C7DE474057ULL,
		0xCE32998BA9813030ULL,
		0x4801DC4F5633EDFBULL,
		0x5D2950723C4367DEULL,
		0xD1AFF687E10166DEULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EBD724B1BD074FCULL,
		0x6AC2831AD43C4EE3ULL,
		0xC35EC8D1A13417D2ULL,
		0xCE8D04F829EF8B12ULL,
		0xF0D85ED3B8D017D6ULL,
		0x8A89D5BAEB6267FAULL,
		0x1DE26BDF913DDD69ULL,
		0xFBBC81B3768D1CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D83AF73A063DE3ULL,
		0x1BD0B4681C46A7DAULL,
		0x172D578106153517ULL,
		0xB07CECAB03E22341ULL,
		0x85EC6067F4552C78ULL,
		0x415B4CC033AD0695ULL,
		0x12AB5FE9CEF28378ULL,
		0x9584BAAFCD42C51DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x766548BC21D6491FULL,
		0x71123772C87AE939ULL,
		0xD4739F50A72122C5ULL,
		0x7EF1E8532A0DA853ULL,
		0x75343EB44C853BAEULL,
		0xCBD2997AD8CF616FULL,
		0x0F4934365FCF5E11ULL,
		0x6E383B1CBBCFD9FAULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8FD6BA987D0FF34ULL,
		0x8EA532894F0BFD8FULL,
		0x8B69ECC3B76B1A9DULL,
		0x28814213DCCBD841ULL,
		0x3727B8053F4ED2F0ULL,
		0xC6991E55C08AB846ULL,
		0x2AC704B928957D0DULL,
		0xE8618561166250E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBD794F020DC2DFULL,
		0xF73C4FE53AD719AEULL,
		0x28EDED9935ED6143ULL,
		0xFB73CBBC5DDA2650ULL,
		0x5F74A7CFA868DDBEULL,
		0x18ECD072C6AF54FCULL,
		0xB8F470E152ADDF67ULL,
		0x4934EE126A1DEFE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x534012E685DD3DEBULL,
		0x79997D6C75DCE421ULL,
		0xA384015A82867BDEULL,
		0xD3F289AF8111FE11ULL,
		0x68531FCA97260F4EULL,
		0xDE75CE270625ECBAULL,
		0x923374587A38A26AULL,
		0xA1556B737C7FBF07ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC0ACA45D709E55ULL,
		0xC60354D287BAFB9FULL,
		0xE85FC57636E225F7ULL,
		0xE08572B494EDAAC1ULL,
		0x2833F905BF3130CFULL,
		0xBBD716E2A76DB63BULL,
		0xC4E52A707A59B3BFULL,
		0x037A9E8367AEC350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC82089794C98713BULL,
		0x777E67E6F36EDA4FULL,
		0x88713AB7F29DE98BULL,
		0x4557E87280CAEAC2ULL,
		0xA6F1BB91D6B5F151ULL,
		0xA61D8FF2916A5F6AULL,
		0xF8A821FBA886B556ULL,
		0x188E3DC5D9D8728FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6E025DD11E8EF6EULL,
		0xB17D333474D421D0ULL,
		0x602EFFC1C47FCC7CULL,
		0xA5D29AC614274003ULL,
		0x8EC242946984C19EULL,
		0x1DCA99103607E951ULL,
		0x3C4D0B8BD2DF06E9ULL,
		0x1BF4A346BE76B1DFULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85139666AE77C705ULL,
		0x75491AD3DBADF0D3ULL,
		0x29E0BEE4B512C67BULL,
		0x448930896D81A5BFULL,
		0xAD018F6C074EA14EULL,
		0x7D3429CC10741C7DULL,
		0x7291D918D8501BC3ULL,
		0xC88F8006AA852638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFB2B547CA219D0DULL,
		0x33854AC5FD10FD5EULL,
		0xD373FE252E2727FAULL,
		0xDF91952E13B674AFULL,
		0x00BD8B3792382F84ULL,
		0xF67B4C6FDF544BA6ULL,
		0xFE2E810273246A47ULL,
		0x47CE11EB0EEAE616ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA1232164565A08ULL,
		0x46CC501626BD0D8DULL,
		0xFA9340C19B35E181ULL,
		0x9B18A5A77E37D110ULL,
		0xADBC045B95768ECAULL,
		0x8B4F65A3CF2057DBULL,
		0x8CBF581AAB747184ULL,
		0x8F4191EDA46FC02EULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDA9488994699FB8ULL,
		0xA8828644513C9522ULL,
		0xDCDD98EEFA909D8CULL,
		0x5CF386886EFEE6EAULL,
		0x7A6F04EEB2CDDE53ULL,
		0xDDB63ADB03202ED2ULL,
		0x2361674FD8C4C419ULL,
		0x02E1FDD9E6AA60A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D38EF6A8EDFFF8BULL,
		0x97BE9F3A2F9646A6ULL,
		0x17434BE3910EC42BULL,
		0xD92A30EE75109F35ULL,
		0x487B6AC9D44E3407ULL,
		0x9AB9CEFF5AEE0FDDULL,
		0x893713F5A9B0DA00ULL,
		0x493CD38873939C2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8091A7E31AB66033ULL,
		0x3F3C197E7EAAD384ULL,
		0xCB9ED30D6B9E59A7ULL,
		0x85D9B6661BEE79DFULL,
		0x32146E276683EA54ULL,
		0x470FF42459CE210FULL,
		0xAA5674BA71741E19ULL,
		0x4BDD2E519539FC8CULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7E6542336F2A5DULL,
		0xD72589746B522507ULL,
		0x7FCD788DA5D4F9D3ULL,
		0xE844B6028252A84FULL,
		0xCE355F48EB3752C0ULL,
		0x14EDDDF6FA2D6DE2ULL,
		0x5979ED2A7639936DULL,
		0x6CC63978D5EE99CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88F26461FCC3488ULL,
		0x19D3A3F1E4ACE4E3ULL,
		0xF88E52E7A7068F84ULL,
		0x0CB0E6B4B3DB9DEFULL,
		0xC2D882441D4F7A90ULL,
		0x7257D8A39FF4FCABULL,
		0x36D0334E385A3C3FULL,
		0x7813E1749D8F9EB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45F143042CA31ED5ULL,
		0xCEF62A858FFEC1E4ULL,
		0x87432A6A02D27657ULL,
		0xE4F450B6318935A0ULL,
		0x0CEDDD0CF6782850ULL,
		0x66BA055565D99149ULL,
		0x6FA9DE644E63AF52ULL,
		0x14D5D80C48610775ULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24B1E63AB8533621ULL,
		0x51B3127E76788E1BULL,
		0x20F1C3C82E8CB918ULL,
		0x6C7E05F6688BBFFCULL,
		0x25B658554948F50FULL,
		0x907DFCD1F5AFD6E8ULL,
		0x51B27FCFFEA0099BULL,
		0x5C35C89714FC5B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE2C21F7B1B5AB6ULL,
		0x9E82A4A405250085ULL,
		0x49FC54C75D6271D2ULL,
		0x989B8CA25EA1CDD2ULL,
		0xBAA6CAF8CB0CB399ULL,
		0x55CB923C5369B338ULL,
		0x831D40798064D516ULL,
		0xA743348D095816C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF532425C3486C97ULL,
		0xCF31B6DA735D8E9EULL,
		0x690D970F73EEC8CAULL,
		0xF4E58954362A722EULL,
		0x9F1092AD82444696ULL,
		0xC5B66EEDA6C665D0ULL,
		0xD2AF3FB67EC4DC8DULL,
		0xFB76FC1A1DA44DC5ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7013D887185FBC2ULL,
		0x168E67A49E8CCAF3ULL,
		0x37793CEFFF775231ULL,
		0xFF7DADAF0DC1300AULL,
		0xE0455762AA7A56AEULL,
		0x6323F81677A4FBE7ULL,
		0x565A57E017B715E4ULL,
		0x467F2E92243F1C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC13EB81D8AA41460ULL,
		0x125F2984AEABFC66ULL,
		0x0C27D3320E561D79ULL,
		0xFA922B2ADABB77D0ULL,
		0x3B42F7B29377026AULL,
		0x3F62A254B09CBEF4ULL,
		0x9B3DB6B1FECD46DBULL,
		0xD7BBDDCFD3E147D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x063F8595FB21EFA2ULL,
		0x04D14E2030273695ULL,
		0x3B5EEFDDF1214F48ULL,
		0x05EF8685D77A47DAULL,
		0xDB07A0D0390D54C4ULL,
		0x5C415A42C7384513ULL,
		0xCD67E151E97A533FULL,
		0x91C4F35DF7DE5BCCULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x482574F8C3FD1BCBULL,
		0x6FF641794A13A798ULL,
		0x8FB5C4CCB4C9BBA1ULL,
		0xC8AEB543E1104396ULL,
		0x54D7A232B0A01B2DULL,
		0x6D671FE96A9ABDE0ULL,
		0x1CDB5BB2AB52CAC0ULL,
		0x032BED192CBAF0F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A462D30331165CULL,
		0x5EA28109F1BB530AULL,
		0xF6E846E0451AF936ULL,
		0x1DDBFB59242C3485ULL,
		0xF941CBF281F9C70CULL,
		0x6E63B6C0D1DB08CFULL,
		0x98F6F24E333A853CULL,
		0x01A974EB2873FC82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4181162BC0CC0D97ULL,
		0x3154C070BBA8F492ULL,
		0x795D822CF1D34297ULL,
		0xD5754E1AC53C7713ULL,
		0xAD9669C03159DC21ULL,
		0x0304A929BB41B52FULL,
		0x842DA9FC98684FFCULL,
		0x028299F204C90C71ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB37DFB550776DF90ULL,
		0xF2683F6BAC5381C3ULL,
		0x2FEC73BA02343672ULL,
		0x5372DAA567DED40BULL,
		0x5E2A3BABBF8E3A51ULL,
		0x5E8F5F1933F520A0ULL,
		0x9046B00D28E53FFBULL,
		0x3DBD96B16F352471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF55B0FC637649166ULL,
		0x32F7715700905872ULL,
		0xE49D91DCC48E22E9ULL,
		0x4862AFDBC26ACD41ULL,
		0xFB23B56C32B80944ULL,
		0xE9578D3AA19DACAFULL,
		0xC89C71E4552C674EULL,
		0x4E5E9521F2245ABDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4626F49330124EF6ULL,
		0xC09F4E3CACC3D9B1ULL,
		0xCB71E266C6BA149BULL,
		0x1B10757EA5B4194AULL,
		0xA5098EC78D363315ULL,
		0xB7D8D22392688C0FULL,
		0x58DAC1E97DC958B5ULL,
		0x73E303909D117ECCULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C32B674C2D52594ULL,
		0x436ED9B0E524A678ULL,
		0x282D3B8B06C85D0AULL,
		0xB322ECCF84F3C244ULL,
		0xA9DC911A19B43800ULL,
		0x19941B7253428689ULL,
		0x639EA39F688E0186ULL,
		0x2C8E90D20CDB751BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D88B918B72CF24ULL,
		0xE1359C6C19C78D21ULL,
		0xC6ADF34C09A6E2B9ULL,
		0xA0A036794E8ACFCBULL,
		0xEC27A9DE01AADC0EULL,
		0xA880307F62298A5EULL,
		0x14A44A62D82C2A44ULL,
		0x14FDAD919FE4E863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEEA3DE549A7EAB0ULL,
		0xA25B45DCFCE32B59ULL,
		0xEE80C8C70F6EBFB3ULL,
		0x1382DAB6CA790D8FULL,
		0x45FB38C4181EE40EULL,
		0xB1142B0D316B0CD7ULL,
		0x773AE9FDB0A22BC2ULL,
		0x38733D43933F9D78ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F7B0997A6D24C60ULL,
		0x58036E0C91434D43ULL,
		0x48F34BB6024D5010ULL,
		0xA6AFF537EDAD505EULL,
		0xA411994A41A4EF4AULL,
		0x83A894851E41F89FULL,
		0x1B7AA35E1359F32EULL,
		0x83AB9DBBF01B2C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB700E3015311A2E9ULL,
		0xC19408DE79EB53D0ULL,
		0x84EF2A5AA08062B7ULL,
		0x2E863203BA300A65ULL,
		0x61E7C7B1A8CA6B54ULL,
		0x61FEB65B8D2EEDC7ULL,
		0x3151854489307AF2ULL,
		0x7B9D19571D904669ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287BEA96F5C3EE89ULL,
		0x999766D2E8A81E93ULL,
		0xCC1C61ECA2CD32A7ULL,
		0x8829C734579D5A3BULL,
		0xC5F65EFBE96E841EULL,
		0xE25622DE936F1558ULL,
		0x2A2B261A9A6989DCULL,
		0xF83684ECED8B6A1BULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x920FF5D2E5E5DDC5ULL,
		0x8ECB83C922A76D7FULL,
		0x61FB509787C945C7ULL,
		0x4E597C6479D70C9BULL,
		0xB86EB2DA08B0E79CULL,
		0xA0C7590F914F74BFULL,
		0x2740A803415D5108ULL,
		0x2511C5674F8384C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1472000EE38564ULL,
		0x8B38495F86A57766ULL,
		0x980E1FDB28F2D9B3ULL,
		0xFC500D03D5F57903ULL,
		0xC5EEBEBB45762B0EULL,
		0x7D0CDF5D64334426ULL,
		0x0F0D210D218592A5ULL,
		0x5BDE8E3B0B979B37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D1B87D2EB0658A1ULL,
		0x05F3CA96A4021A19ULL,
		0xF9F54F4CAF3B9C74ULL,
		0xB2097167AC227598ULL,
		0x7D800C614DC6CC92ULL,
		0xDDCB8652F57C3099ULL,
		0x284D890E60D8C3ADULL,
		0x7ECF4B5C44141FF4ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87FE0D47278E0693ULL,
		0xF2408AB9D80B9A4FULL,
		0x74B9F07859EB9826ULL,
		0xC92B49BD086ADAF7ULL,
		0x1875FD859EAC5ADFULL,
		0xFB01F38B87512628ULL,
		0x1794CF7CC5D46066ULL,
		0x0E9D3D3A83820017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E6A180691C5ED4ULL,
		0xD7EBBCDB1F2EF6FFULL,
		0xFE2EDE234CB371A4ULL,
		0x96D33B1C01A6B66EULL,
		0xC74EC7F716AED977ULL,
		0x760B652E93306439ULL,
		0x773662DFC4C540FAULL,
		0x45A9F96CBEDE8631ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3118ACC74E925847ULL,
		0x25AB3662C7256CB0ULL,
		0x8A972E5B1558E982ULL,
		0x5FF872A109CC6C99ULL,
		0xDF3B3A72880283A8ULL,
		0x8D0A96A514614211ULL,
		0x60A2ADA30111209CULL,
		0x4B34C4563D5C8626ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF78B7C747724598DULL,
		0x046AA2440FA52728ULL,
		0xB15233E25A347377ULL,
		0xD7F53FD5B8ADFB75ULL,
		0xA11C68859633CEF0ULL,
		0x52C5D3EC04B6207EULL,
		0xB6A686E3E4B9F9DDULL,
		0xDF7966EB22B2EFFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5C9B850A0CF126ULL,
		0xF273CC6EB3BC7E89ULL,
		0x3E9D32A2E41BC62CULL,
		0xC1B2476C57C7E9B8ULL,
		0x7C63A01A9F5FE112ULL,
		0xEBBDFE8024E824ABULL,
		0x288A34339BFE5734ULL,
		0x0993A284A9447B40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8D7E7F17D28A8ABULL,
		0xF6196E2ABC1959A1ULL,
		0x8FCF0140BE2FB55BULL,
		0x164778B9EF6A12CDULL,
		0xDD7FC89F096C2FE2ULL,
		0xB9782D6C205E04D5ULL,
		0x9E2CB2D07F47AEE9ULL,
		0xD6EAC46F8BF694BCULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00BED4433D93CA6BULL,
		0xA3D4505C1976DA1CULL,
		0x65E1B735F4476899ULL,
		0x05ACE04CCEF77E37ULL,
		0x55A816D37FEFD81CULL,
		0xC9B86ABC23A3607CULL,
		0xB463DA3A541489C3ULL,
		0x35F6251B3958E61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E9910C9435260DFULL,
		0x56DAE86C08B10A21ULL,
		0x637B942B2B878CA7ULL,
		0x84F0539BAD5D66F2ULL,
		0xB5BC565C57C77D76ULL,
		0x3AE11B241313D9F1ULL,
		0xB528973CA038C9D1ULL,
		0x2E7313D9C867D7D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E27C48A7EC1AAB4ULL,
		0xF50EB83011C7D03DULL,
		0x069A231EDFC0E43EULL,
		0x815CB3D763AA18C5ULL,
		0xE014408F2828A56AULL,
		0xF359719830B0B98DULL,
		0x014B4D06F42C4012ULL,
		0x1B8536C2F13F31CCULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0823E7AAB36DDDULL,
		0x9E1D8F94274B4762ULL,
		0x0BD2276C4D1525BBULL,
		0xE1A1BD22408C386FULL,
		0x821A7C6FC5A8802DULL,
		0x061A64339E0F2E86ULL,
		0xF7DA39C1136931D2ULL,
		0x806CF54CD2A66770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F7E70A35CD0AC9CULL,
		0x0F8EA35F59ECE1B4ULL,
		0xEFF2A0C05CEC07E5ULL,
		0x4D7F58F6D71BBD7FULL,
		0x2D557183BEA54658ULL,
		0x5B9FA0C3CC27C7EDULL,
		0x5ABBF93B47D7AFB7ULL,
		0x7C9533957A94FC66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12765344F663C141ULL,
		0x91932CCB7EA7A6D6ULL,
		0xE42087AC11F9225EULL,
		0xACDEE5D497978510ULL,
		0xAF4F0DEC7B0DC675ULL,
		0x5D85C4F05228E96BULL,
		0xAD61C0FA54BE9E65ULL,
		0xFCF9C6D9A8329B16ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38D420C1E4836D54ULL,
		0x5A80CF75E3D4B770ULL,
		0xCC06AB7715A0939DULL,
		0x131C85D246AB5388ULL,
		0xAB244EF996BCCDE0ULL,
		0xF198CD95A3A0A504ULL,
		0x7DDD5BC556847E5AULL,
		0x551A44444223B362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECFF37611123229AULL,
		0x081B799D3CDA36A4ULL,
		0xFDBA8E809137AC32ULL,
		0x53960F62BF6DEA99ULL,
		0xFC74272214F0C27AULL,
		0x82699745C68BCE94ULL,
		0x6BAF3D5C5AE9C5A0ULL,
		0xE0F655FC2A8E9CEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD42B17A0F5A04FCEULL,
		0x529BB6E8DF0E81D4ULL,
		0x31BC25F784973FAFULL,
		0x408A8AB0F9C6B911ULL,
		0x575069DB824C0F9AULL,
		0x73F15AD0652B6B90ULL,
		0x167266990C6DBBFAULL,
		0xB5EC11B868AD2F89ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79CA0C346E06B1C0ULL,
		0x7BBB75F153CD6CA5ULL,
		0xC82E9A3F3FE9D657ULL,
		0x6C8876BDD11BE062ULL,
		0xBA710BE5735C1B8EULL,
		0x2BB8793F54018CA3ULL,
		0x437F08D339997A3EULL,
		0x5999A22577339658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669FEAB05D53730CULL,
		0x1BA708B32138EAD1ULL,
		0xFD2FAE7D07395D93ULL,
		0x49E73BE2729FB682ULL,
		0xFE86E33497480439ULL,
		0x4DD8F9A8B8EE4074ULL,
		0xFD6A90192F5852B7ULL,
		0x43D5E8C0279232E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F55E6843355C2CCULL,
		0x601C7D4272F58674ULL,
		0x3501344238D08BC4ULL,
		0x256F4D5FA38456E0ULL,
		0x44F7E8D1E4141FB7ULL,
		0x66608097ECEFCCD7ULL,
		0xBE1598CA16C12889ULL,
		0x1A4C4AE550A1A4B8ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x057B609DEA1634C7ULL,
		0xD8D9A5A46A385FA6ULL,
		0xFEA14C8199D4A290ULL,
		0xCDFF7827130BCDE5ULL,
		0xC59F1A0EDCBE218FULL,
		0x1DFF19D9E452D7ECULL,
		0xD1EC8F976F51EE20ULL,
		0x393AA35C3862E739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BEE27A13A0BB80ULL,
		0x9D892EF88A351FB2ULL,
		0x6AEAF481264025D6ULL,
		0xAF77496A70B54D98ULL,
		0x05962B0A8ACCE610ULL,
		0x090C584AC228BD11ULL,
		0x707C909750ECA468ULL,
		0x194EDDA61D6A18A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3C582E7F9B68F47ULL,
		0x45508B5CE00D4014ULL,
		0x944BB800BF948746ULL,
		0x6288314D63BE807DULL,
		0xC00931045672C79FULL,
		0x14F34193267A6AFDULL,
		0xA1901F003FBD4A48ULL,
		0x20747EFA2508FF9AULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FE313C6E5DEC6D0ULL,
		0xC36F542B1F2BE348ULL,
		0x4AC1362814389013ULL,
		0x9BD8595C3973F52FULL,
		0xE464AC0268CD47A2ULL,
		0x3F441BC7C4F61448ULL,
		0x6259550C28E22CC1ULL,
		0x27A1D2D28E98D08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6ACCB3A7F1AC95DULL,
		0x0270AE6CA8C7D43CULL,
		0xA83285080DE39944ULL,
		0x4F69A24A92E52541ULL,
		0xD6DF0BCB69B3856BULL,
		0xBAF401F57C661FC1ULL,
		0x0D4BE1D107A770C9ULL,
		0xDDF6B2984E9A1DBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC94FD8FC9AC40F8DULL,
		0xC11FFA47B7EC3774ULL,
		0xE2F3B32019DB0957ULL,
		0xD4B1FB16AB96D06EULL,
		0x32BBA7C9017EC2C9ULL,
		0x85B01A32B8900B89ULL,
		0x6F12B4DD2F455C08ULL,
		0xFA57604AC002CD35ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5769531158C2AEF2ULL,
		0xE6C4C7E9A06FF188ULL,
		0xE51E99DC1EB5DD6AULL,
		0x74016A2867F4CD5AULL,
		0x50A8D356B913B832ULL,
		0x94665A8357AB44A6ULL,
		0x82C9A2D21AD68950ULL,
		0x00AC31556730957EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC9B91A0B746054ULL,
		0x3B390DC50AACB5B7ULL,
		0xAC031752B34EE238ULL,
		0x98D1365FBA99AB17ULL,
		0x90FCBACF2BB37B64ULL,
		0x60DEB56FFE192404ULL,
		0xAC7EB25A9B94B14AULL,
		0xDA2886464A2879C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA0EA0B53B6CEA6ULL,
		0xDDFDCA2CAAC3443FULL,
		0x491D8E8EADFB3F52ULL,
		0xECD05C77DD6D664DULL,
		0xC054699992A0C356ULL,
		0xF4B8EFECA9B260A2ULL,
		0x2EB710888142381AULL,
		0xDA84B7132D18ECBCULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7624062BA41500ULL,
		0xB2EC4A22813544B8ULL,
		0x7C0A4F7204EC51C2ULL,
		0xE98765DE570B2D71ULL,
		0x6BDC26E567A057F3ULL,
		0xC55BC4CA2F08D1D6ULL,
		0x6EEC985A2C4D864BULL,
		0x2636924EF70C0162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B206F89A0242B3ULL,
		0x2534611917ED3B54ULL,
		0x90A933C1C77C79FEULL,
		0x1E3A018F0DFE26B0ULL,
		0xB96577CC7EDA4855ULL,
		0x58803D8C214261F7ULL,
		0xABE0A0889766047DULL,
		0xC6BC93BBAB801A67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BC422FEB1A657B3ULL,
		0x97D82B3B96D87FECULL,
		0xECA37CB3C390283CULL,
		0xF7BD64515AF50BC1ULL,
		0xD2B95129197A1FA6ULL,
		0x9DDBF9460E4AB021ULL,
		0xC50C38D2BB2B8236ULL,
		0xE08A01F55C8C1B05ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE193B822EAA41A03ULL,
		0x797EF3D7A4A89B7DULL,
		0x79407841FC2FC692ULL,
		0x18DCA0859E1ABB39ULL,
		0x97FFDA03943D5452ULL,
		0xC8C44CF854BFA194ULL,
		0xE0FB2AED9A10F020ULL,
		0xAC983EB6CBEE860BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89E9541E37EDDD9ULL,
		0x8AB88092E919756AULL,
		0xF6A314C45416C1D5ULL,
		0xD282E50E436A15BCULL,
		0x225246E9B4CDD33CULL,
		0x6068D5B6D7531526ULL,
		0x313741E5C79AB93BULL,
		0x41074D1DC55AD4CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490D2D6309DAC7DAULL,
		0xF3C673454DB1EE17ULL,
		0x8FE36C85A8390747ULL,
		0xCA5E458BDD70AE85ULL,
		0xB5AD9CEA20F0876EULL,
		0xA8AC994E83ECB4B2ULL,
		0xD1CC6B085D8A491BULL,
		0xED9F73AB0EB452C0ULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD59D81C5721E8000ULL,
		0x38BC326F1F5AB605ULL,
		0x2BFF2D4B4C2C636FULL,
		0xB0952A13183B20C0ULL,
		0x91173354FBC40F2CULL,
		0x13558DACCF6E72A6ULL,
		0x3966A698EB9C7F42ULL,
		0x00C2D9083A5FCE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9664CD5A33E74C05ULL,
		0x928043A11B185193ULL,
		0x373564F28FDB14DEULL,
		0x3D27127054D0D92FULL,
		0xC2ECF144A40CEA86ULL,
		0x8C39EEB0C4FBD79FULL,
		0x62B3BC0135F7B5F8ULL,
		0xE1538E3324929F9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43F94C9F41F9CC05ULL,
		0xAA3C71CE0442E796ULL,
		0x1CCA49B9C3F777B1ULL,
		0x8DB238634CEBF9EFULL,
		0x53FBC2105FC8E5AAULL,
		0x9F6C631C0B95A539ULL,
		0x5BD51A99DE6BCABAULL,
		0xE191573B1ECD51D8ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5D2A5D8F6EE7E37ULL,
		0x86A33CC2BE090488ULL,
		0x7594D9FF872634EDULL,
		0x45BC26E32878A284ULL,
		0xF696D1AA2916C788ULL,
		0xB4E11B35EAC96DFFULL,
		0xED100A8A5DF8C4B3ULL,
		0xC8B832659A902384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD69163FBD0C74B7FULL,
		0xD251055133843F2BULL,
		0x5A3786343577B3F9ULL,
		0x06B85B1D663200E2ULL,
		0x580DDC6E1D68F2F0ULL,
		0x1CDBC44D260D28B6ULL,
		0x778650B2833A5403ULL,
		0xC849D54BC68C5030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6343C62326293548ULL,
		0x54F239938D8D3BA3ULL,
		0x2FA35FCBB2518714ULL,
		0x43047DFE4E4AA266ULL,
		0xAE9B0DC4347E3578ULL,
		0xA83ADF78CCC44549ULL,
		0x9A965A38DEC290B0ULL,
		0x00F1E72E5C1C73B4ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27AE16409148ECA2ULL,
		0xD9472BD6A83DD2B8ULL,
		0x658978BEF3A95275ULL,
		0x503E84C78B074511ULL,
		0x5AEF74ED8EC9C3BAULL,
		0xB2ED215CA26C24ADULL,
		0xE2CBF90074EB7EC5ULL,
		0xF8CB70D78C561314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98D30A304F9F9BFULL,
		0xE5279C9E17236D50ULL,
		0x01062D0A65163E48ULL,
		0xBEE331E6C58C3888ULL,
		0x931E07F54419E10DULL,
		0x3918B7E8E7B44BFCULL,
		0x097CB4C41EF9C423ULL,
		0x4796AA92AD3F5AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E2326E395B1151DULL,
		0x3C60B748BF1EBFE8ULL,
		0x648F55B496BF6C3DULL,
		0xEEDDB5214E8B7D99ULL,
		0xC9F17318CAD022B7ULL,
		0x8BF596B445D86F51ULL,
		0xEBB74DC46A12BAE6ULL,
		0xBF5DDA45216949DDULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD29671C229A01CEULL,
		0x15D919EE5220E87DULL,
		0xCDA32AD5158B18C8ULL,
		0xEAF1E4733748D72CULL,
		0x3A79A844729A1C0FULL,
		0xF4B9840B566D88BEULL,
		0xFE893E0AA59F69C3ULL,
		0x731BE2A54933DA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6345D2FC77FD37DULL,
		0x5DA5DB3238660C28ULL,
		0xBD29982E74C1B538ULL,
		0x813D15F84A87A7E5ULL,
		0x814923893DA81A2DULL,
		0x4C382C4A7C6E00D3ULL,
		0xF633C0B3F38E5894ULL,
		0xE89C3106E4286122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B1D3A33E5E5D2B3ULL,
		0x487CC2DC6A46E455ULL,
		0x708AB2FB614AADF0ULL,
		0x6BCCF18B7DCF70C9ULL,
		0xBB308BCD4F320622ULL,
		0xB881A8412A03886DULL,
		0x08BAFEB956113157ULL,
		0x9B87D3A3AD1BBB28ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39433BB2BB6205CFULL,
		0x1366016A6627DF7CULL,
		0x8F0A8516CE431C76ULL,
		0x06A2A11F9C5DDBD1ULL,
		0x47BF575421FE3AB5ULL,
		0x9F5889D9B19ED9E3ULL,
		0x9A5FA91453378548ULL,
		0xEC593FDC5C8AD2B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36DE41AEEB3733E8ULL,
		0x9C0343362D23B2C7ULL,
		0xB85357BF51AA7B6BULL,
		0xA7EA540120B18512ULL,
		0xCEEBC02C4E8C11A1ULL,
		0xD8B1ADC5B478B5A8ULL,
		0x72B4F5F1B6ED290CULL,
		0x4369C4EA815F3460ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F9D7A1C50553627ULL,
		0x8F65425C4B046DBBULL,
		0x3759D2A99FE9671DULL,
		0xA148F51EBCEC5EC3ULL,
		0x895497786F722B14ULL,
		0x47E9241C05E66C4BULL,
		0xE8EB5CE5E5DAAC44ULL,
		0xAF30FB36DDD5E6D8ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DA09CC258673214ULL,
		0x4B8CA1268C2680F9ULL,
		0x12DE4A6F52E90E15ULL,
		0x9A5FD952B11F44FFULL,
		0x674A064CB608D120ULL,
		0x2EA088B86DDDE6BFULL,
		0x8F0FC7CD20EA4509ULL,
		0x3C3F6087A5A1B22FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A0069147518489ULL,
		0x73D7AFD390FC76C0ULL,
		0x4AB754F791030E9DULL,
		0xCAB55CFA52D3E86AULL,
		0x39E356DB89E3C42CULL,
		0x86A1E79076AF70E1ULL,
		0xACAED0DA13938984ULL,
		0xDCCEC9220CD6EC68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A009A531F36B69DULL,
		0x385B0EF51CDAF639ULL,
		0x58691E98C3EA0088ULL,
		0x50EA85A8E3CCAC95ULL,
		0x5EA950973FEB150CULL,
		0xA8016F281B72965EULL,
		0x23A117173379CC8DULL,
		0xE0F1A9A5A9775E47ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DC5B65E07607AB2ULL,
		0xD7648452C381BDEDULL,
		0x1947E2728F945B10ULL,
		0x99D67D97A430FFECULL,
		0x4B8CA77F5696AF1FULL,
		0xF57073E6C4CBAF6FULL,
		0xD69C571820E7A0A0ULL,
		0xBFDCBEB9B57E7B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921E9577834B402CULL,
		0x8DBFBBA1209D75F8ULL,
		0x25C89E84C49A974CULL,
		0xC8AEF1AA9E604EEAULL,
		0x18B6484523CAE839ULL,
		0x886D5BE8EAB85DBEULL,
		0xA3DB9D3EC17F4CE2ULL,
		0xDDBC98AD820347C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFDB2329842B3A9EULL,
		0x5ADB3FF3E31CC815ULL,
		0x3C8F7CF64B0ECC5CULL,
		0x51788C3D3A50B106ULL,
		0x533AEF3A755C4726ULL,
		0x7D1D280E2E73F2D1ULL,
		0x7547CA26E198EC42ULL,
		0x62602614377D3CCCULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33DAF277D93AD98FULL,
		0x1BB66FA8C43CA987ULL,
		0x1162BFBF91E7B862ULL,
		0xCA0FEE9D53055CD0ULL,
		0x992746C1DA115B9DULL,
		0x7D332F4E58C94E16ULL,
		0x8E30F67EBE91B83DULL,
		0xC16BAAA1A3309B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF676EF6FB15ACD36ULL,
		0xBA06F127105B31D3ULL,
		0x2B02ED627E234B7FULL,
		0xD918CAFF785D6726ULL,
		0x06DE5CDA23803FFFULL,
		0x68EF0CD1F906032EULL,
		0xBD55BFECCD9723FAULL,
		0x791350AF49D3111BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5AC1D18686014B9ULL,
		0xA1B09E8FD4679854ULL,
		0x3A6052DDEFC4F31DULL,
		0x131724622B583BF6ULL,
		0x9FF91A1BF9916462ULL,
		0x15DC239FA1CF4D38ULL,
		0x3365499273069BC7ULL,
		0xB878FA0EEAE38A3FULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9B906724A00CF8FULL,
		0x6FD1A536B76E3F7DULL,
		0xD9A4A6DC4E63F3D8ULL,
		0x8BD4CB7124DE2896ULL,
		0x9024BFCFC76E17E8ULL,
		0xE3C7095EEB4F68D0ULL,
		0x93DCCBD35DFE8EDEULL,
		0x5E2E4AB7AE0AB5A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3026EE4FDFC6E92AULL,
		0x209DA547ECA04837ULL,
		0x29224CB4272D29F6ULL,
		0x70A9147D6DAC1FDCULL,
		0x8CA7C4B9D194E859ULL,
		0x5ACEAF50035ACC00ULL,
		0xB32100462E4675B9ULL,
		0x76C04FF43A2582B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x999FE83D95C626A5ULL,
		0x4F4C00715BCE774AULL,
		0xF086EA68694EDA2EULL,
		0xFB7DDF0C4972374AULL,
		0x1C837B7616FAFFB1ULL,
		0xB909A60EE815A4D0ULL,
		0x20FDCB9573B8FB67ULL,
		0x28EE0543942F3715ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70AE482243DCE2B1ULL,
		0x8426ADF42C9195E4ULL,
		0xDD80605D8EAEF19DULL,
		0xF379092FE80B5598ULL,
		0xCEAA6940B308EA45ULL,
		0x644CC477E5903CFAULL,
		0xA94FC66F2335C4DBULL,
		0x92607445F5D51058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA49588C374E16DULL,
		0xB7104E71318C93E0ULL,
		0x3100DBF7FC4C96C1ULL,
		0x602F42F15DD73FB6ULL,
		0x9E949F6EA077C0FEULL,
		0x7C1913B43DA487D9ULL,
		0x005955AF5338E790ULL,
		0x34E6FE3672A160DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE0ADDAA80A803DCULL,
		0x3336E3851D1D0604ULL,
		0xEC80BBAA72E2675CULL,
		0x93564BDEB5DC6A2EULL,
		0x503EF62E137F2ABBULL,
		0x1855D7C3D834BB23ULL,
		0xA91693C0700D234BULL,
		0xA6868A7387747084ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFB87ADB18BCEA1DULL,
		0xD4F25E082C6B7494ULL,
		0x40F6F7E52A7CA50BULL,
		0xBF2215094B9075FCULL,
		0xC81ABA708C70A5A0ULL,
		0xB5029085FDD9EF07ULL,
		0x63CBC91F61AA85F8ULL,
		0xF0282AA0DC77B301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BD6F0060676A87ULL,
		0x8BF40A9BFFCBF585ULL,
		0x146014251E605815ULL,
		0xCC78F46C58851660ULL,
		0x90F90030E4D1C3CCULL,
		0x09F968DAAE8706FFULL,
		0x66F062504D1F76C4ULL,
		0x9DE75BCB000832F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E0515DB78DB809AULL,
		0x5F065493D3A08111ULL,
		0x5496E3C0341CFD1EULL,
		0x735AE1651315639CULL,
		0x58E3BA4068A1666CULL,
		0xBCFBF85F535EE9F8ULL,
		0x053BAB4F2CB5F33CULL,
		0x6DCF716BDC7F81F4ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2063F576E0B1F22DULL,
		0xA740D0648BA0F6EDULL,
		0x04BA28490371EE04ULL,
		0x7953843177F8FD97ULL,
		0xA67B5682AD92DCE9ULL,
		0x90BF33CAFAE771C0ULL,
		0x1FEA851226D3DAFDULL,
		0x00759B29ED65FD7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2216930E0CF285ADULL,
		0x655763C62B29FEC9ULL,
		0x74F174DC988B1CF7ULL,
		0x6D90884F05B3F77FULL,
		0xCD255BB58D73B98AULL,
		0xC0A73DE68A5A20F7ULL,
		0xB197C97FE3D3E4B9ULL,
		0x4E00F7AAB7EAA978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02756678EC437780ULL,
		0xC217B3A2A0890824ULL,
		0x704B5C959BFAF2F3ULL,
		0x14C30C7E724B0AE8ULL,
		0x6B5E0D3720E16563ULL,
		0x50180E2C70BD5137ULL,
		0xAE7D4C6DC5003E44ULL,
		0x4E756C835A8F5405ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2367E380EF097169ULL,
		0xBC6436FB64A4650EULL,
		0x4BB2AC49ACFEAC0BULL,
		0x5712329A98817871ULL,
		0xAC1255872A8C19D9ULL,
		0x030133C3FC3112DBULL,
		0xD5C7A918DD1F4F1AULL,
		0x8836D8048CD41A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x344890D769CD014EULL,
		0x1384C786C2F7B3D6ULL,
		0xA779D2B0F1D3A7FFULL,
		0x89364D77E1F37BD9ULL,
		0xF918FD6E423968CCULL,
		0xFD406570922D6EE5ULL,
		0xDAF927C89461F362ULL,
		0xB769D21A58F4B804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x172F735786C47027ULL,
		0xAFE0F17DA653D6D8ULL,
		0xECCB7EF95D2D0BF4ULL,
		0xDE247FED797203A8ULL,
		0x550AA8E968B57115ULL,
		0xFE4156B36E1C7C3EULL,
		0x0F3E8ED0497EBC78ULL,
		0x3F5F0A1ED420A279ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43DA52AB4316789BULL,
		0x020C82168CAAF17FULL,
		0x4DD8F913EE5E6E86ULL,
		0x530A8B5DF6D31575ULL,
		0x0015B1B74EBD031AULL,
		0x6601DB7EC13030C8ULL,
		0x1D24C23005BE6AE8ULL,
		0x175EC82EF5B11576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDACFC94F0C2FAC5EULL,
		0xAAACEFC33ACE4FB2ULL,
		0x9EA1B96506313C2FULL,
		0x8128F1CC2D1335CCULL,
		0x3BBD36C54DEC6A71ULL,
		0xEC1A75E13B46A0F8ULL,
		0x26BECE75E88AF94CULL,
		0x56D51A6DDE4671CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99159BE44F39D4C5ULL,
		0xA8A06DD5B664BECDULL,
		0xD3794076E86F52A9ULL,
		0xD2227A91DBC020B9ULL,
		0x3BA887720351696BULL,
		0x8A1BAE9FFA769030ULL,
		0x3B9A0C45ED3493A4ULL,
		0x418BD2432BF764BCULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FCA1439D1E6C8B3ULL,
		0x04A97585A136C16BULL,
		0x75C079AA28A871B0ULL,
		0x85B4200AD0A38D60ULL,
		0x76268636D42930AEULL,
		0xDC28DBAA86336834ULL,
		0x1E1CD6682EF7991DULL,
		0xBDCF7A02E8690E0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE734E0B1C0E2D0A2ULL,
		0x0C266C128B5B1564ULL,
		0xA835929B8AB9F4C1ULL,
		0xF95B9CB871673253ULL,
		0xE06DDF1FAC572143ULL,
		0xA225986CAF83A4C3ULL,
		0xB002D8F633ACA039ULL,
		0x1EFAC5DCE703E86AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8FEF48811041811ULL,
		0x088F19972A6DD40FULL,
		0xDDF5EB31A2118571ULL,
		0x7CEFBCB2A1C4BF33ULL,
		0x964B5929787E11EDULL,
		0x7E0D43C629B0CCF7ULL,
		0xAE1E0E9E1D5B3924ULL,
		0xA335BFDE0F6AE661ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA79ED9D7359FA174ULL,
		0x886BF8B647A1BF4EULL,
		0x6801ED3CA8BD88A7ULL,
		0xA4CA76AA5B00C1D0ULL,
		0xCF13C52198BC9A6DULL,
		0xFC6475C3DA58D256ULL,
		0xCD5432EAD59F1DACULL,
		0xD5C29AC297FF24EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C8BDD8BCE24B83ULL,
		0x0C702740EC3DE84BULL,
		0xAD680C751E7A5394ULL,
		0xA17DE2EAE984151DULL,
		0xBA4A45DFEB645268ULL,
		0x3EDE09FE44D1C3A1ULL,
		0x7B2FE28B3772FD48ULL,
		0xD21F252201FFCDC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3656640F897DEAF7ULL,
		0x841BDFF6AB9C5705ULL,
		0xC569E149B6C7DB33ULL,
		0x05B79440B284D4CDULL,
		0x755980FE73D8C805ULL,
		0xC2BA7C3D9E8911F7ULL,
		0xB67BD061E2EDE0E4ULL,
		0x07DDBFE09600E922ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F7280EFE56362DEULL,
		0x538A26BACC71DF69ULL,
		0xC9D7504977838A22ULL,
		0x5D8C6B16498E2256ULL,
		0x1C8C5CD5E360EDDBULL,
		0xC94B04459B015495ULL,
		0x424B3640A8485430ULL,
		0x7611683A1BA11577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573490E9671C9317ULL,
		0x7CE2E762E43402FCULL,
		0x2DB8223774E7FB95ULL,
		0x2E2074E170088C23ULL,
		0x8F93F2812661E091ULL,
		0xC39FC6B6A96DFEA5ULL,
		0x5B6AF4B3FD478BE3ULL,
		0x74250A1A98026F8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48461006827FF1C9ULL,
		0x2F68C1D82845DD95ULL,
		0xE46F727E036471B7ULL,
		0x73AC1FF73986AE75ULL,
		0x931FAE54C5010D4AULL,
		0x0AD4C2F3326CAA30ULL,
		0x1921C2F3550FDFD3ULL,
		0x0234622083A37AFAULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDDA558C3F825C04ULL,
		0xD8C1A5B730B5CB2EULL,
		0x032BF1DC42E80E6FULL,
		0xAE9289BD85CAFAB3ULL,
		0x81E6AA207E015E69ULL,
		0x71F398D7FEE307D5ULL,
		0xD440558C1C0967DFULL,
		0xB7CD329C33900D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D00D525FA4B169ULL,
		0x80B2B3C70FF5F712ULL,
		0x3737826A1724729EULL,
		0x3FF653BDE25F27A7ULL,
		0xE2A185AA3FC80446ULL,
		0x4BD17AA055584DEAULL,
		0x31B4E26AB418C5F1ULL,
		0x2245A682DEB79561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x440A58DE6026ED6DULL,
		0x587316703F403C3CULL,
		0x341C73B655CC7CF1ULL,
		0x9164DA006795DD14ULL,
		0x63472F8A41C95A2FULL,
		0x3A22E277ABBB4A3FULL,
		0xE5F4B7E6A811A22EULL,
		0x9588941EED27986FULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x809D84474B243F8FULL,
		0xB99A3D7EE3F5B02CULL,
		0x91216623D35F1A8CULL,
		0x7C7B57BE90522BA9ULL,
		0x5CAA8A50E83FFAE2ULL,
		0x09988C39AF20CD7BULL,
		0xB54E7BA92AA52C8DULL,
		0x336E320EFACC7D5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3DB4F7027C25ABBULL,
		0x23E4E3ADBDDF77CEULL,
		0xCA7C504AD0B2B8EFULL,
		0xDE0F15F1A6652CD3ULL,
		0x73203C46B01E1250ULL,
		0xFEE53274DAC88ABDULL,
		0x2E396F978D230354ULL,
		0x430A2AC5DA4880DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4346CB376CE66534ULL,
		0x9A7EDED35E2AC7E2ULL,
		0x5B5D366903EDA263ULL,
		0xA274424F3637077AULL,
		0x2F8AB6165821E8B2ULL,
		0xF77DBE4D75E847C6ULL,
		0x9B77143EA7862FD9ULL,
		0x706418CB2084FD80ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DEABC27FDA40909ULL,
		0x7211DD0E0471B928ULL,
		0x834FD28E4422E2AEULL,
		0x456C9DE18E73EE60ULL,
		0xB3DCDE5FAC835AB2ULL,
		0x2B599DCBA9BAD7AFULL,
		0xDD9EF877D723859FULL,
		0x0A44E006248214C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2AE6E2DACE8D42ULL,
		0xDCCA0D3DEAF51BDDULL,
		0xA78CDD260E0A609DULL,
		0x168306CC4E8B5E5EULL,
		0x2CC9156970F1DDD3ULL,
		0xD6CE2663833D2240ULL,
		0xD686ABA721298F42ULL,
		0x153F4E4B5F9F6D5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16C05AC5276A844BULL,
		0xAEDBD033EE84A2F5ULL,
		0x24C30FA84A288233ULL,
		0x53EF9B2DC0F8B03EULL,
		0x9F15CB36DC728761ULL,
		0xFD97BBA82A87F5EFULL,
		0x0B1853D0F60A0ADDULL,
		0x1F7BAE4D7B1D799FULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51EA31E0459964B1ULL,
		0x41EC7EF83CBE7666ULL,
		0x9E3B625F650F8241ULL,
		0x1F4972417F017F89ULL,
		0x76A11B30E864380AULL,
		0x5AC5DB0637591916ULL,
		0x80B567346ACD7017ULL,
		0x8C68085B82510099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6016CEFFC94294ULL,
		0x6E35F74A465ADF13ULL,
		0x9C33C38998DE4A4FULL,
		0x05BEDE234AD47852ULL,
		0xB57EC931FC01F60AULL,
		0x209E9CC2C0415BD0ULL,
		0x500EF0BA00DB8432ULL,
		0x633235857D81B42BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB8A272EBA502625ULL,
		0x2FD989B27AE4A975ULL,
		0x0208A1D6FDD1C80EULL,
		0x1AF7AC6235D507DBULL,
		0xC3DFD2011465CE00ULL,
		0x7A5B47C4F71842C6ULL,
		0xD0BB978E6A16F425ULL,
		0xEF5A3DDEFFD0B4B2ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B6BD8AD6E2C97F7ULL,
		0xB951F185E74B2AE1ULL,
		0xC07B5946205DDFC0ULL,
		0xD9545F9A781C9E78ULL,
		0x16279452C4E58995ULL,
		0x90050A8360358417ULL,
		0x08013FB1F723F41EULL,
		0x83CA3F6359207D04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EBF336C40B6539EULL,
		0x8FDEA4AB338F9691ULL,
		0xD3E311EB8A4AEB49ULL,
		0xFC7ACC3C023EC2B9ULL,
		0xF6161814BA08E7F6ULL,
		0x5B4025F008467FCCULL,
		0x7638AAEDA3C443ACULL,
		0x28CA5AE047FB1F29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05D4EBC12E9AC469ULL,
		0x368F552ED4C4BC70ULL,
		0x139848ADAA173489ULL,
		0x252E93A67A225CC1ULL,
		0xE0318C467EED6E63ULL,
		0xCB452F736873FBDBULL,
		0x7E39955C54E7B7B2ULL,
		0xAB0065831EDB622DULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA234696B30FE47A9ULL,
		0x15120ED89FA462A0ULL,
		0xA6920E7E86C7B7E4ULL,
		0x6D4EB457CBD572F6ULL,
		0x0B491DC30A4AA8B7ULL,
		0x1C4ACA9742157A4AULL,
		0x5FB1FF26FB7E42FEULL,
		0x12CFA5853D5865F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36F87BD7D9DA373ULL,
		0xC4DDB3D9A787F956ULL,
		0x554943A07F2992B7ULL,
		0x369F51B9A753F32FULL,
		0xCA166F62B500ED82ULL,
		0x029D340D70126363ULL,
		0xC72CC3B4CAA16478ULL,
		0x4D0D3A06D0B9F596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x615BEED64D63E4DAULL,
		0xD1CFBD0138239BF6ULL,
		0xF3DB4DDEF9EE2553ULL,
		0x5BD1E5EE6C8681D9ULL,
		0xC15F72A1BF4A4535ULL,
		0x1ED7FE9A32071929ULL,
		0x989D3C9231DF2686ULL,
		0x5FC29F83EDE19061ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC50D3FB165FE706ULL,
		0x8321AF4A27ABCAA2ULL,
		0xCA9B557127CF0C72ULL,
		0xBF91160C6A71FFDFULL,
		0xA09CB2BF5E8075F8ULL,
		0x33FD034EA40CCE9DULL,
		0x4598926E597ADEF7ULL,
		0xF4B9E60E9D1F7C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212FE5EE7A12DA27ULL,
		0xDD5986BC24D1E7DAULL,
		0x04C6206AFEBB09A9ULL,
		0xE0E8F773A7768C1CULL,
		0x3FD9515C8C9BA5E2ULL,
		0xFC7B5F954560CDBFULL,
		0x5C7310E6607E4E7BULL,
		0x2A4753F17ACB5A06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED7F36156C4D3D21ULL,
		0x5E7829F6037A2D78ULL,
		0xCE5D751BD97405DBULL,
		0x5F79E17FCD0773C3ULL,
		0x9F45E3E3D21BD01AULL,
		0xCF865CDBE16C0322ULL,
		0x19EB82883904908CULL,
		0xDEFEB5FFE7D42686ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EC712727F142AA9ULL,
		0x28D50E11A6F98136ULL,
		0xFE15A6D07D0989ADULL,
		0xA6EE36EF7BC2EF4AULL,
		0xA03E475C9E934AF9ULL,
		0x1C851C1A0457E3F1ULL,
		0x6B998550351473FBULL,
		0xECABE8B1AEEC9C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A80E7FBEF5FA557ULL,
		0x70B33E3BE3022F0DULL,
		0xD8D45A86B386C1E2ULL,
		0x436A315CF90E030AULL,
		0xDB2C72569CFA179FULL,
		0xB6ECB91F8E8A7A6AULL,
		0xECFBDFE1FFDF7172ULL,
		0x2E855CB87E64A009ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3447F589904B8FFEULL,
		0x5866302A45FBAE3BULL,
		0x26C1FC56CE8F484FULL,
		0xE58407B382CCEC40ULL,
		0x7B12350A02695D66ULL,
		0xAA69A5058ADD999BULL,
		0x87625AB1CACB0289ULL,
		0xC22EB409D0883C48ULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0236F32687A87E5ULL,
		0xAB9552C458D0FD7DULL,
		0x24C49F467B1A0D0BULL,
		0xEB8427D90A879352ULL,
		0xE24004415C2AF1F0ULL,
		0xB0C3A7242E17AC39ULL,
		0xB4731C0850F47DB6ULL,
		0xC947714093C624AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F37FBE461DDF7DAULL,
		0xDCA890124C03E099ULL,
		0x9958F8D6C0909573ULL,
		0xE427C4176D7A7032ULL,
		0xA4280367AB30A29EULL,
		0x2FEBE5A1CE46CF77ULL,
		0x0BB2A008521B0897ULL,
		0x1B6BAB3967FDD85CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF1494D609A7703FULL,
		0x773DC2D614D31DE4ULL,
		0xBD9C6790BB8A9878ULL,
		0x0FA3E3CE67FDE360ULL,
		0x46680726F71A536EULL,
		0x9F284285E051634EULL,
		0xBFC1BC0002EF7521ULL,
		0xD22CDA79F43BFCF3ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57EE9DD3A835BFA5ULL,
		0x9A015B55180EC1E3ULL,
		0xEE1FEB8A735B95F0ULL,
		0xFC80796AB5D6CD7FULL,
		0x83339AB86E1103A4ULL,
		0x558BD7EE352461CAULL,
		0xDC2A286907A159A4ULL,
		0x62BB5A10F7DD8D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x578E644359E1A668ULL,
		0x39548A20F7149AB0ULL,
		0x1171A5743650E98FULL,
		0x590CA79054AD11E2ULL,
		0xA5FCC1919D209680ULL,
		0x5EBD59CCE6DAA25BULL,
		0x992AD078BB02F3ABULL,
		0x23AB721B7ABDDCC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0060F990F1D419CDULL,
		0xA355D175EF1A5B53ULL,
		0xFF6E4EFE450B7C7FULL,
		0xA58CDEFAE17BDC9DULL,
		0x26CF5B29F3319524ULL,
		0x0B368E22D3FEC391ULL,
		0x4500F811BCA3AA0FULL,
		0x4110280B8D605149ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x098C6634B279E761ULL,
		0x3075CE7168F7576AULL,
		0xD209485A5434FE8FULL,
		0x270D39C75BE1DF2EULL,
		0xE6593EA80848C57CULL,
		0xDE4AB80E61C6DE17ULL,
		0x2C61E7AF909833EBULL,
		0xF9A65B8A922183C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A1F065966F918E0ULL,
		0x22DF40B8464D007AULL,
		0x470A529E45BF7C23ULL,
		0x60BD4B8EED43171CULL,
		0x7EB3FC8A2A7AD278ULL,
		0x3074C1876623C29AULL,
		0xAA39D39610ABDED6ULL,
		0xB6EED21280810212ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1393606DD480FF81ULL,
		0x12AA8EC92EBA5710ULL,
		0x95031AC4118B82ACULL,
		0x47B07249B6A2C832ULL,
		0x98EAC22222321704ULL,
		0xEE3E798907E51C8DULL,
		0x865834398033ED3DULL,
		0x4F48899812A081D1ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C0B314F5DEC9361ULL,
		0x8D30C72729C17CC0ULL,
		0xC6F82D16A8C01B70ULL,
		0xE53F58CF48527C2EULL,
		0x9AE92067173B2E17ULL,
		0x1A54892D92F94940ULL,
		0x469793E8D7CC13EFULL,
		0x2D2B7F765FE3D411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD072A0309E41C52CULL,
		0x961C02AFE6C1A856ULL,
		0x6F6452E669ED992FULL,
		0x5597BE3D28D19E99ULL,
		0xBD145F75FE5C0F71ULL,
		0xC772CE6AA06FEC8BULL,
		0xF7286A886D0EC5CCULL,
		0x357A62DBB5D2F633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C79917FC3AD564DULL,
		0x1B2CC588CF00D496ULL,
		0xA99C7FF0C12D825FULL,
		0xB0A8E6F26083E2B7ULL,
		0x27FD7F12E9672166ULL,
		0xDD2647473296A5CBULL,
		0xB1BFF960BAC2D623ULL,
		0x18511DADEA312222ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11E8D0E50AC511CBULL,
		0xD4198BB01F7F2B97ULL,
		0x31A5CD81DCE150C5ULL,
		0x00267AEDA8E3B059ULL,
		0x8111081F84059F37ULL,
		0x50AB9220C43434D0ULL,
		0x16C5190D40C63CF5ULL,
		0xD3C1E70128D8DFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69197BE9A4F75964ULL,
		0x3E2B541D1529DCE6ULL,
		0xB953896FD19884ECULL,
		0x780CFD203671571BULL,
		0x959B2BE5C034EA0DULL,
		0xB603C70B250A8FB7ULL,
		0x721B71A6FAF507A5ULL,
		0xA27FE280536ED6EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78F1AB0CAE3248AFULL,
		0xEA32DFAD0A56F771ULL,
		0x88F644EE0D79D429ULL,
		0x782A87CD9E92E742ULL,
		0x148A23FA4431753AULL,
		0xE6A8552BE13EBB67ULL,
		0x64DE68ABBA333B50ULL,
		0x71BE05817BB60919ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A24EA83D92CC90AULL,
		0xEF54B7C25AB4325BULL,
		0xFC6E997A757D986EULL,
		0xB9363FF9B1F6498FULL,
		0xA462DA3D273928D7ULL,
		0x17FF95A698D156C7ULL,
		0x3065EF3C1D500C73ULL,
		0x3C0802EB9D776F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB479E8D2F152186BULL,
		0x9733F74A66810613ULL,
		0x9E0D811942A1907EULL,
		0x03EB0C7B02D49064ULL,
		0xCD1C98333D64D48CULL,
		0xB4523234131E193CULL,
		0x8A74C1217DBC38B1ULL,
		0xDE1CF3A24A66F288ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E5D0251287ED161ULL,
		0x786740883C353448ULL,
		0x6263186337DC0810ULL,
		0xBADD3382B322D9EBULL,
		0x697E420E1A5DFC5BULL,
		0xA3ADA7928BCF4FFBULL,
		0xBA112E1D60EC34C2ULL,
		0xE214F149D7119DF4ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9A07954802DFFBDULL,
		0xDA615E97C012D0EDULL,
		0x4653B39CBD02373AULL,
		0xCCF08871C5FAC146ULL,
		0x6677D1571DA81741ULL,
		0x1F4660A3C5C12C4AULL,
		0x997AA67B8601F8DEULL,
		0x3875087F60F57993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FD8116E713F2D7ULL,
		0xF41A7855607C6ABCULL,
		0x324C8036BC455511ULL,
		0x0E8CBB9D3CFF6B07ULL,
		0x0AEE29907BB09897ULL,
		0xA1FA91B116250807ULL,
		0xBFE23A9416E26218ULL,
		0x84B15A3E695DD3B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D5DF842673E0D6AULL,
		0x2E7B26C2A06EBA51ULL,
		0x741F33AA0147622BULL,
		0xC27C33ECF905AA41ULL,
		0x6C99F8C766188FD6ULL,
		0xBEBCF112D3E4244DULL,
		0x26989CEF90E39AC6ULL,
		0xBCC4524109A8AA24ULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65E71F9CDBD4CD88ULL,
		0xF2512C6AE2B9A28DULL,
		0xA407FF9385E4C674ULL,
		0x71C376556C47CD64ULL,
		0xE45DC11A6D78A4BDULL,
		0x27F9CDF0D43E0D27ULL,
		0x21C401D80DEE3FD8ULL,
		0x183F9B6260E2C985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71A195155813337EULL,
		0xF5769C38D944314AULL,
		0x76C06A09266F7489ULL,
		0xB2EB0CF77D756723ULL,
		0x634487B61C91B8B4ULL,
		0x398B277A24F5FD95ULL,
		0x0047B933EC01DAD8ULL,
		0xB4B393D7DFDAE311ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14468A8983C7FEF6ULL,
		0x0727B0523BFD93C7ULL,
		0xD2C7959AA38BB2FDULL,
		0xC3287AA21132AA47ULL,
		0x871946AC71E91C09ULL,
		0x1E72EA8AF0CBF0B2ULL,
		0x2183B8EBE1EFE500ULL,
		0xAC8C08B5BF382A94ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x191A8725A9C5DF22ULL,
		0x68D08CC4720D8BD4ULL,
		0x543D6DAB38228D4FULL,
		0x3CF7FA1EC04B91CDULL,
		0xCD5079438614B054ULL,
		0x67A539FEFDE192C8ULL,
		0x94CB5E5CC63F49DFULL,
		0xC607F261AF48CFFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632240EE44B88221ULL,
		0x63D3F1A92F96FACCULL,
		0x8378DE46BE0258CDULL,
		0xD6E2EF382A4822DDULL,
		0x7312D0D123327CB2ULL,
		0x8FCB736ABA12C107ULL,
		0x4CFA369BC4A3E8F1ULL,
		0x00BF89892DDE93ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A38C7CBED7D5D03ULL,
		0x0B037D6D5D9B7118ULL,
		0xD745B3ED8620D582ULL,
		0xEA151526EA03B310ULL,
		0xBE42A992A526CCE6ULL,
		0xE86E4A9447F353CFULL,
		0xD83168C7029CA12EULL,
		0xC6B87BE882965C17ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3EC01CF6F180903ULL,
		0x96D3E9F55A7E3F23ULL,
		0x4D86C9B3C1C1ADECULL,
		0x1CD07C1D490138DBULL,
		0xAFDA4D71339917F5ULL,
		0x41C0B5F72316F9F3ULL,
		0x8D18B03CC602A40CULL,
		0xC6A1D4AC23502BB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA253306212802BULL,
		0x962800D9518F609FULL,
		0x1FF1399D1122B208ULL,
		0x771CEB63F883E8AAULL,
		0xD66F5BB76012B96AULL,
		0x2DC88278FF76A8D8ULL,
		0xDC4909CA06E37AC8ULL,
		0xEDB10A448DD400FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF94E52FF0D0A8928ULL,
		0x00FBE92C0BF15FBCULL,
		0x5277F02ED0E31FE4ULL,
		0x6BCC977EB182D071ULL,
		0x79B516C6538BAE9FULL,
		0x6C08378FDC60512BULL,
		0x5151B9F6C0E1DEC4ULL,
		0x2B10DEE8AE842B4FULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FAE897B7A181682ULL,
		0x6D9660B359443B9FULL,
		0xC69BD8E123EE50E1ULL,
		0x454418094F911F95ULL,
		0x40B0475587C1ACF7ULL,
		0x9007529224C85BD6ULL,
		0x20D9CED3C9530FE0ULL,
		0x68092514C4FA7F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8263FD42F9D29360ULL,
		0xE5CFB5E7476268C8ULL,
		0x35047CB44693ECDFULL,
		0x7A3D979AE8DD1E65ULL,
		0x8FC3EE7ECD452A15ULL,
		0x65221E3FEFE72E6AULL,
		0x98D22EAB58C5C1E8ULL,
		0xC6969E42ED80C6C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDCD743983CA85E2ULL,
		0x8859D5541E265357ULL,
		0xF39FA455657DBC3EULL,
		0x3F798F93A74C01F0ULL,
		0xCF73A92B4A8486E2ULL,
		0xF5254CADCB2F75BCULL,
		0xB80BE0789196CE08ULL,
		0xAE9FBB56297AB9D4ULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F715C6A7B934234ULL,
		0xAA37E3A18FFD24D7ULL,
		0x9BD4BFA42322BCBBULL,
		0x996C002BF30BC580ULL,
		0xA4186498745A9845ULL,
		0xB17264B308DA62F3ULL,
		0x5611A096AD044A6EULL,
		0x0D31AA333172B056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F758C17AFC43AB0ULL,
		0x0EA469DAE377B666ULL,
		0xAE5ECF9B9271F838ULL,
		0x41A85854D841CD82ULL,
		0x230C227B9889253CULL,
		0x4B056DEFFDAAC395ULL,
		0x792D3582249612E8ULL,
		0x76A082B9EC21F2BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7004D07DD4577884ULL,
		0xA4938A7B6C8A92B1ULL,
		0x358A703FB1534483ULL,
		0xD8C4587F2B4A0802ULL,
		0x871446E3ECD3BD79ULL,
		0xFA77095CF570A166ULL,
		0x2F3C951489925886ULL,
		0x7B91288ADD5342EBULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A52EA5CC1B8015DULL,
		0xDD64533A5FE6CCD3ULL,
		0xDB15D1AB49EB852AULL,
		0xB731156E7A3DACB8ULL,
		0xF1EA8D9F1CCBEA1BULL,
		0x00F59DD6DBC9866CULL,
		0xD98473BDA0DB8DD0ULL,
		0x661E80CAE63C8F56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x628380A9F5031455ULL,
		0xF3BC6E74C74971B7ULL,
		0xCA0F67AE59369F3DULL,
		0x3A2F776B823BAB11ULL,
		0x5918F90E66217866ULL,
		0xA73F68084F506DBAULL,
		0xE8968AA08F579F5CULL,
		0x41956EDEEB422FDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D16AF534BB1508ULL,
		0x2ED83D4E98AFBD64ULL,
		0x111AB60510DD1A17ULL,
		0x8D1E6205F80607A9ULL,
		0xA8F274917AEA927DULL,
		0xA7CAF5DE9499EBD6ULL,
		0x3112F91D2F8C128CULL,
		0x278BEE140D7EA08CULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x813F604268EDF28DULL,
		0x0B295E94E9D9DEF9ULL,
		0x11FFE3FA073CBB90ULL,
		0x27D23B65B2AAC91CULL,
		0x8E72792A982D608DULL,
		0x10B481081EA96B41ULL,
		0xC71BB31296F0AE73ULL,
		0x39D3D41AF3106775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE29FCC97AF5A69ULL,
		0x575C1BDE1AA255C6ULL,
		0xE555054103FF6CB8ULL,
		0xFC7F4C1FAB65D01EULL,
		0xB72FB21AF5AAE09BULL,
		0x6A43A449AC1D3DF7ULL,
		0xB9D75409AE08F668ULL,
		0x1B0360D841120849ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CDDFF8EFF42A8E4ULL,
		0x5C75454AF37B8B3FULL,
		0xF4AAE6BB04C3D728ULL,
		0xDBAD777A19CF1902ULL,
		0x395DCB306D878016ULL,
		0x7AF72541B2B456B6ULL,
		0x7ECCE71B38F8581BULL,
		0x22D0B4C2B2026F3CULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55B8C177EBC75789ULL,
		0x9F835D9B4C9881BAULL,
		0xEB5B7B0BB7384009ULL,
		0xBC5AA4655299DCEEULL,
		0x3BB0581E96A29D9EULL,
		0xDECC0BD431101B89ULL,
		0x3256A4E377627E1FULL,
		0x0D5FD0DFE162CD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB3FAF9664C566D5ULL,
		0x74E1600AE6BB9342ULL,
		0x8D53716292005B55ULL,
		0x010958997E3995ABULL,
		0x2EE9C9A4E0333DB0ULL,
		0x8F43D55B6BDE91A1ULL,
		0x3CC44ADF2F8D8601ULL,
		0x34BE0BC4B63AB43FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E876EE18F02315CULL,
		0xEB623D91AA2312F8ULL,
		0x66080A6925381B5CULL,
		0xBD53FCFC2CA04945ULL,
		0x155991BA7691A02EULL,
		0x518FDE8F5ACE8A28ULL,
		0x0E92EE3C58EFF81EULL,
		0x39E1DB1B575879A2ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB6C883E2E38B307ULL,
		0xA234F7E2F96DB24AULL,
		0x411CABA3DF9A4587ULL,
		0x88C7D03A2D2B7655ULL,
		0x6BDEAB8134ECCB61ULL,
		0xAE47AC0BF7319BDDULL,
		0xE35B3003ABCB1EF9ULL,
		0x8491D703B2AE6A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC313A7CEE0E555FULL,
		0xD55CCD3A67B161A4ULL,
		0x237A5141E381806AULL,
		0xEFFC6CADBE02A3FAULL,
		0x21AB3FE1B4A74F9CULL,
		0xB364C9CC469A7CE7ULL,
		0x980E786F36ABC66EULL,
		0x410CA48369800170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x075DB242C036E658ULL,
		0x77683AD89EDCD3EEULL,
		0x6266FAE23C1BC5EDULL,
		0x673BBC979329D5AFULL,
		0x4A759460804B84FDULL,
		0x1D2365C7B1ABE73AULL,
		0x7B55486C9D60D897ULL,
		0xC59D7380DB2E6B28ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC260ACF3164DB897ULL,
		0x16E32750C56A7B1BULL,
		0xC89C770000C1C34DULL,
		0x596D6734B8810639ULL,
		0xFC9D7E12CD21BF12ULL,
		0xFFE3B14C73EFE30BULL,
		0x090C61DE482182B7ULL,
		0x500D148D8F419ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA159E4C09FC1D3FULL,
		0x3CCC69F6FE9FBA6DULL,
		0xF525C9743480E69CULL,
		0x732303935E2C245AULL,
		0x2665AEFDD7D43515ULL,
		0x29B868198EA2F28EULL,
		0xFCE0952D7DF5B5B4ULL,
		0xCC95461621DDC92FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287532BF1FB1A5A8ULL,
		0x2A2F4EA63BF5C176ULL,
		0x3DB9BE74344125D1ULL,
		0x2A4E64A7E6AD2263ULL,
		0xDAF8D0EF1AF58A07ULL,
		0xD65BD955FD4D1185ULL,
		0xF5ECF4F335D43703ULL,
		0x9C98529BAE9C5391ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DCAD16330886580ULL,
		0xAFB398164786D83EULL,
		0x543BC97DF96E3332ULL,
		0x8BB1FF5E9B9923F6ULL,
		0x82536A9635FC4642ULL,
		0x5422D22EA4E547FDULL,
		0x95072E30CDD4F5BAULL,
		0x257714A850928755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9FD4A92B3770D6ULL,
		0xF30A861F18CB9E65ULL,
		0x5232EFFD87D31A05ULL,
		0xBACFF6E44E3D7BEFULL,
		0x2809ED567254042CULL,
		0x3162790845E553F4ULL,
		0x770C213A8E2FEF81ULL,
		0xA31C958FD2D3431AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF15505CA1BBF1556ULL,
		0x5CB91E095F4D465BULL,
		0x060926807EBD2937ULL,
		0x317E09BAD5A45819ULL,
		0xAA5A87C047A8426EULL,
		0x6540AB26E1001409ULL,
		0xE20B0F0A43FB1A3BULL,
		0x866B81278241C44FULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x533CF2D1DE4155D4ULL,
		0xB2801FFACF623C4AULL,
		0x8359F017BFCE0428ULL,
		0x056192008AFE293EULL,
		0x88E0ACC96CCDD0FEULL,
		0x75637F7086366231ULL,
		0x231AE759A7D59B16ULL,
		0x36872F388CCB9F6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x168398A7E60589FBULL,
		0xCE01F076B0CDDB17ULL,
		0xA552B3B26C402130ULL,
		0xEFB724A72754390CULL,
		0xC9EB019A8A8785C4ULL,
		0x8964339828BCA34CULL,
		0xCE80E822A79FA104ULL,
		0x29342B899E84F582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45BF6A763844DC2FULL,
		0x7C81EF8C7FAFE75DULL,
		0x260B43A5D38E2518ULL,
		0xEAD6B6A7ADAA1032ULL,
		0x410BAD53E64A553AULL,
		0xFC074CE8AE8AC17DULL,
		0xED9A0F7B004A3A12ULL,
		0x1FB304B1124F6AEFULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE209AB91B00B0FA6ULL,
		0x64993E54BEBBD13DULL,
		0x02FBB5708A46ECC0ULL,
		0x73A14EE1162810AAULL,
		0x11D2EAA772BEDCCFULL,
		0x7197574E2B565125ULL,
		0x367A5381E8DDB934ULL,
		0xBC2898D1DD2CB025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E1624C7049B4D3ULL,
		0x35277CFAEFDE36EAULL,
		0xBDCEFB2F6F94F517ULL,
		0x8E78305A1FEFC2B5ULL,
		0x5332F4C4FE096087ULL,
		0x3329192155E1EC12ULL,
		0x22E1B630C53BD6C5ULL,
		0x86AA23B564109D0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2E8C9DDC042BB75ULL,
		0x51BE42AE5165E7D7ULL,
		0xBF354E5FE5D219D7ULL,
		0xFDD97EBB09C7D21FULL,
		0x42E01E638CB7BC48ULL,
		0x42BE4E6F7EB7BD37ULL,
		0x149BE5B12DE66FF1ULL,
		0x3A82BB64B93C2D2EULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64DFB1B1F33A8356ULL,
		0x944F3F8784E5401EULL,
		0xBFF7A7C4E60EE387ULL,
		0x6755266A3E523D8CULL,
		0x3FD578F983F8EB0DULL,
		0x72B6F0634A5636A0ULL,
		0x26901817E3A5DF64ULL,
		0xCC65CF4BFCC33424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C009E08F94EF093ULL,
		0x1FE9F56B2F73EF51ULL,
		0x722EEA29A4DB858DULL,
		0x0B6A3FC4B44410BDULL,
		0xC31229CB99FC0F18ULL,
		0x12FEB1212BAC6CE4ULL,
		0x794118D7F6E8D51AULL,
		0x2443DDBB626CFFD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48DF2FB90A7473C5ULL,
		0x8BA6CAECAB96AF4FULL,
		0xCDD94DED42D5660AULL,
		0x6C3F19AE8A162D31ULL,
		0xFCC751321A04E415ULL,
		0x6048414261FA5A44ULL,
		0x5FD100C0154D0A7EULL,
		0xE82612F09EAFCBF0ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2132EBF2432FEF2EULL,
		0xFB8305551A9C1FC5ULL,
		0xB8E62E81DCBFAEEBULL,
		0x302F9C61C0494640ULL,
		0x8B7FFE219671FCFFULL,
		0x33C9A2B1CF462753ULL,
		0xAAF0304E6FD13A9FULL,
		0x1009DFFA30384418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC541C2B7D94A4C86ULL,
		0x2695630065C3E787ULL,
		0x4A93FC6AE41D2E32ULL,
		0x01CA90D96E6EFFABULL,
		0x3FBC2A30B7AD648BULL,
		0xD5566A4FF02C9357ULL,
		0xF929C330218E31E6ULL,
		0xDF2BBA4ED468A9A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE47329459A65A3A8ULL,
		0xDD1666557F5FF842ULL,
		0xF275D2EB38A280D9ULL,
		0x31E50CB8AE27B9EBULL,
		0xB4C3D41121DC9874ULL,
		0xE69FC8FE3F6AB404ULL,
		0x53D9F37E4E5F0B79ULL,
		0xCF2265B4E450EDB8ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5ABAD2613A121A0ULL,
		0x45E39B1E58854044ULL,
		0x1B4F0DE4717CDA14ULL,
		0xABF3D827B15212ABULL,
		0x9553240B80BC23D8ULL,
		0x703E0A2B99240346ULL,
		0xBF3514457A6BC229ULL,
		0xABCE8D3C4AAAA2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6ACEB13C5872ECULL,
		0x32F9FF8BAFFE4264ULL,
		0x0B4E410677E8EF97ULL,
		0x6625B5E6F2FCC15BULL,
		0xBB8EBCAF19BC1C97ULL,
		0xBDD38E867957B792ULL,
		0xE86C3BA734C61F95ULL,
		0x64860EBB786C4C10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9C163972FF9534CULL,
		0x771A6495F77B0220ULL,
		0x10014CE206943583ULL,
		0xCDD66DC143AED3F0ULL,
		0x2EDD98A499003F4FULL,
		0xCDED84ADE073B4D4ULL,
		0x57592FE24EADDDBCULL,
		0xCF48838732C6EEB4ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76B1B7CFDF09FFF1ULL,
		0x2509F5A52202E7D4ULL,
		0x6A9446BB2E020BFDULL,
		0x3896ECAB21117E49ULL,
		0xFD3AD11FC90A437DULL,
		0xC0EA07AEFB8C889EULL,
		0xFC7209C6FB5104C0ULL,
		0x4D9083AF1AEDFE8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577C2A95EC3AE255ULL,
		0xAC260FBE6356EA80ULL,
		0xC9CB97816250F1E0ULL,
		0xC272DCF23C7C6DA8ULL,
		0x021B64F9B3FB782EULL,
		0xCD93C1AF1C9EDBF9ULL,
		0x228EC3E414A7D45AULL,
		0xAB0A0C6700DB02B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21CD9D5A33331DA4ULL,
		0x892FFA1B41540D54ULL,
		0xA35FD13A4C52FA1DULL,
		0xFAE430591D6D13E1ULL,
		0xFF21B5E67AF13B53ULL,
		0x0D79C601E7125367ULL,
		0xDEFCCA22EFF6D09AULL,
		0xE69A8FC81A36FC3DULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D4A67DC65154A47ULL,
		0xFF8BFBCC8AE86ACBULL,
		0x4FCD76AF38977769ULL,
		0x71D9A956104A7BF0ULL,
		0x53914FCEF78BB359ULL,
		0xF188AFD326FDF4C1ULL,
		0xF430EA1AB8534FCFULL,
		0x1168CD757E65CD39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56227C4B37F0B541ULL,
		0xA2B5FC6E3E3DA4F8ULL,
		0x75DCCB598318B438ULL,
		0x83C43A8562BB12E0ULL,
		0xEABE233F6CAAF089ULL,
		0x7538BCEDEF8C1FD8ULL,
		0x374316449F125842ULL,
		0x2B5BF9036DD3E5D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB681B9752E5FF06ULL,
		0x5D3E07A2B4D5CE33ULL,
		0x3A11BDF6BB8FC351ULL,
		0xF21D93D372F16910ULL,
		0xB92F6CF19B2143D0ULL,
		0x84B0133EC971EB19ULL,
		0xC373FC5E2741178DULL,
		0x3A33347613B628E0ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C6A6AE41239AB91ULL,
		0x5BD3541294D385F6ULL,
		0xFD93B997FEF9FB24ULL,
		0x596B052B74DFA86DULL,
		0xC000BCF5B967236BULL,
		0xDCF94FD52EC2DF78ULL,
		0xE8A92DDEF1D7AE5AULL,
		0xC384005975D3E147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5ADEBD4D4A411AULL,
		0xC8D547BBA963484FULL,
		0xA11B7E37D295ADEFULL,
		0xDB53F968E4D5036CULL,
		0xF7FACF3A75348607ULL,
		0x4F67D8DAFB5F9BEDULL,
		0xE6AF499F95EF7FC9ULL,
		0xE3F83154B489721BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0730B4595F73EA8BULL,
		0x930613A93DB0CDB9ULL,
		0x5C88C7A02C6C56CBULL,
		0x8238FC43900AAB01ULL,
		0x37FA73CFCC53A56CULL,
		0x939E970FD59D4495ULL,
		0x0E0664416438D193ULL,
		0x207C310DC15A935CULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B5D242CD4CE16E5ULL,
		0xE03BA6AA916286BCULL,
		0x54C780F73F2CD3CAULL,
		0x007564F8942F86AFULL,
		0xEC49C975C4C12CE2ULL,
		0xC767AA6943974FCBULL,
		0x9D6D3512CD355B61ULL,
		0x58874095F00E5B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B02787F31B71D09ULL,
		0x1E9ABDA18A7520B9ULL,
		0x1658DEF1BDB15398ULL,
		0xBA6AC759B8D2169CULL,
		0x00E5042ABC54F346ULL,
		0xB21C6513A46A0C10ULL,
		0xE89A339B60FAB4A2ULL,
		0xC8F61B8BD48D973EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x205F5C53E5790BECULL,
		0xFEA11B0B1B17A605ULL,
		0x429F5E06829D8052ULL,
		0xBA1FA3A12CFD9033ULL,
		0xECACCD5F7895DFA4ULL,
		0x757BCF7AE7FD43DBULL,
		0x75F70689ADCFEFC3ULL,
		0x90715B1E2483CC56ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAE6CDFBF20E3BF5ULL,
		0x0AD34725CFA01805ULL,
		0x3D00CFD89A1C2CD4ULL,
		0x1158659A1AABBD58ULL,
		0xB020CC44C8B9592DULL,
		0x6C6B814C2D893118ULL,
		0x85FDA3B0C31CD3DAULL,
		0x12236D6CC0B6CA17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD42F553D3C72F397ULL,
		0x73393724361986ACULL,
		0x900C90E88C3D2355ULL,
		0x1ADDB6A46C7A7BDEULL,
		0x9D3575706D5E3877ULL,
		0x56EA41BCCD726EC0ULL,
		0x75282111EFACC6D3ULL,
		0x8B52377AA0EAD11DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EC998C6CE7CC862ULL,
		0x79EA7001F9B99EA9ULL,
		0xAD0C5F3016210F81ULL,
		0x0B85D33E76D1C686ULL,
		0x2D15B934A5E7615AULL,
		0x3A81C0F0E0FB5FD8ULL,
		0xF0D582A12CB01509ULL,
		0x99715A16605C1B0AULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3901E36279CFFBAULL,
		0x9130440609928268ULL,
		0xA374C111C01F5DBCULL,
		0x9AFB98C57DE7BCC5ULL,
		0xCA0DA699D2C87740ULL,
		0xA6299D0C2066143FULL,
		0x5A6F4A94BB347CE8ULL,
		0x007C3956434D13C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0827E688809CB806ULL,
		0x23220C9B285DD2C6ULL,
		0xA5BA935D6F4CB1DDULL,
		0x5E87E9DDBA60C4A0ULL,
		0x8018F12DF9103740ULL,
		0x5DA2A087B3FC7A1EULL,
		0x691A28E1545425F7ULL,
		0x3EDBA6ED4E3FFF17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBB7F8BEA70047BCULL,
		0xB212489D21CF50AEULL,
		0x06CE524CAF53EC61ULL,
		0xC47C7118C7877865ULL,
		0x4A1557B42BD84000ULL,
		0xFB8B3D8B939A6E21ULL,
		0x33756275EF60591FULL,
		0x3EA79FBB0D72ECD4ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x829DEE2AC8D68783ULL,
		0x5998780E0EFC3D1BULL,
		0x9D9B6F8F21DEE602ULL,
		0x2294C7D90BFB0F83ULL,
		0xFD582B6B79EBAB5BULL,
		0xA453CB5BCF75C503ULL,
		0xF7B669A7C7DE4E8DULL,
		0xFAF332446BEEDC4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEC3D5BCA74605DULL,
		0x2E795EE9BDEAC0DEULL,
		0xC520E2ABACCC7FFBULL,
		0x3FE48F9E2F55A84CULL,
		0x3AB1E33A6E8DDAC3ULL,
		0x2835366627DA1A10ULL,
		0x1FF881AC4964AF6EULL,
		0xF7883CCC5C0FB9B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F71D37102A2E7DEULL,
		0x77E126E7B316FDC5ULL,
		0x58BB8D248D1299F9ULL,
		0x1D70484724AEA7CFULL,
		0xC7E9C85117667198ULL,
		0x8C66FD3DE8AFDF13ULL,
		0xE84EE80B8EBAE1E3ULL,
		0x0D7B0E8837E165F8ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x364B2711EB047459ULL,
		0x4EA659E76C693A83ULL,
		0x39B7B2D9CB0EFD1AULL,
		0xF2A3E17778204325ULL,
		0x4D997E2BE72937DAULL,
		0xE3EB232058455FADULL,
		0x244EA9BEF7BCD231ULL,
		0x0B36A2B12BFDE611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9784C30A94320CC4ULL,
		0x85C04B9B51AFFC7FULL,
		0xD5BEBE521C37D5E6ULL,
		0x2089D73FCD03CD86ULL,
		0xD43FA3D3BFA8C956ULL,
		0xE1AFE0A5C438E0D7ULL,
		0x5AC594EA017FFA29ULL,
		0xFC5D96842B7C516BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1CFE41B7F36789DULL,
		0xCB66127C3DC6C6FCULL,
		0xEC090C8BD73928FCULL,
		0xD22A3648B5238EA3ULL,
		0x99A6DDF85881FE8CULL,
		0x0244C3859C7DBF7AULL,
		0x7E8B3D54F6C32818ULL,
		0xF76B34350081B77AULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4A6E432D16C4E79ULL,
		0x07B940F778163159ULL,
		0x61111C352E4BE953ULL,
		0xD5968826F397041DULL,
		0x54D7DC21C1756C5DULL,
		0x24FC0E6B5797839BULL,
		0x4B6D9376A2BA6369ULL,
		0x0E4CC358ABEE9282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3464FAAC5E998AD4ULL,
		0x9736D791FC9AFCF8ULL,
		0xF0C9B6D789D9E182ULL,
		0x5B48C9B124576907ULL,
		0x0402F68195372798ULL,
		0xDC1677D56AF496FCULL,
		0x8A9649B216C69E86ULL,
		0xCA04BCCDEF84A7A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C21E9E8FF5C4ADULL,
		0x908F9766848CCDA1ULL,
		0x91D8AAE2A79208D1ULL,
		0x8EDE4197D7C06D1AULL,
		0x50D52AA054424BC5ULL,
		0xF8EA79BE3D631567ULL,
		0xC1FBDAC4B47CFDEFULL,
		0xC4487F95446A3526ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0276674200B8F7FEULL,
		0x289B68C894F9FB66ULL,
		0x9F96D261817B573FULL,
		0x5417CDA164669F0FULL,
		0xD324A7249DB25372ULL,
		0x314EDF65E105DA13ULL,
		0x16344E09EBCAEF05ULL,
		0xA171B6E18DDA3D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F9F2C3402853F1ULL,
		0x0DAB39CDE6D867E8ULL,
		0x206CA01E66ABAA0AULL,
		0x277DC71F6D07A68EULL,
		0x556454FCCF52B037ULL,
		0x160F8AEE4AAF238CULL,
		0x9F7E3634B67DFE78ULL,
		0x36D288475F7D286BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA28F95814090A40FULL,
		0x2530510572219C8EULL,
		0xBFFA727FE7D0FD35ULL,
		0x736A0ABE09613981ULL,
		0x8640F3D852E0E345ULL,
		0x2741558BABAAF99FULL,
		0x894A783D5DB7117DULL,
		0x97A33EA6D2A71522ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00012F0EB2CB29DCULL,
		0x696D6B2761DBE3D1ULL,
		0xD2837AE721F8A58FULL,
		0xD2F00F4C8D03912DULL,
		0xE182F9F50B41D9F7ULL,
		0xBD8724C6B5DA82BFULL,
		0x65856B09F3356E94ULL,
		0x1D4885C2557239E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC8E19EDE0ABECEULL,
		0x37C7AEFF0580D629ULL,
		0xC79C12AE198D443BULL,
		0x8798D9C001D65642ULL,
		0x9F7345D2BF7B3609ULL,
		0xC98B5B5BB9C8350BULL,
		0xD8D5EDD48D216EE0ULL,
		0xDC2C882C4433D15CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFC9CE906CC19712ULL,
		0x5EAAC5D8645B35F8ULL,
		0x151F68493875E1B4ULL,
		0x5568D68C8CD5C76FULL,
		0x7EF1BC27B43AEFFEULL,
		0x740C7F9D0C12B7B4ULL,
		0xBD5086DD7E140074ULL,
		0xC1640DEE1141E8BCULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x374343BB62BBABFFULL,
		0xE4A681BC5DD8CCD9ULL,
		0xB187EBDE40058291ULL,
		0xA127188DFABE16DAULL,
		0xD3AB9F33919ED539ULL,
		0xE725ECBB37BE42EFULL,
		0xB98DC1C8942B9E31ULL,
		0xB29D46F76AD49B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A9F89149D505C1ULL,
		0xBFA80758FE5A4005ULL,
		0x9E4B77F746B25568ULL,
		0xE4A09B96BDB2DD43ULL,
		0xA7416B11AE994F3FULL,
		0xA163B1BDEF2A2C94ULL,
		0x1BD164D16137DB5AULL,
		0xD904C917B2547F09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1EABB2A2B6EAE3EULL,
		0x5B0E86E4A3828CDCULL,
		0x2FCC9C2906B7D7F9ULL,
		0x4587831B470CCB99ULL,
		0x74EAF4223F079A06ULL,
		0x46465D06D8946E7BULL,
		0xA25CA519F51C456BULL,
		0x6B998FE0D880E45FULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFBFAFA52F34EB2EULL,
		0x8C062999DC48B283ULL,
		0x20EA07C210DA4FEBULL,
		0xD7F1E45D7705D7EBULL,
		0xE928DF168E411159ULL,
		0x6616CE956864B3A8ULL,
		0xCB37B22AA70E5EA6ULL,
		0x0C31CEABED2830E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E5D7009DB2D8DFULL,
		0x2DD90FA948BD8212ULL,
		0x7E03771DA3B75276ULL,
		0x3D2DA2A1EDD5FE51ULL,
		0xCD868FE8D2669639ULL,
		0x0A45CE0ADA76F7F2ULL,
		0x843FF2D928ABAF8FULL,
		0xE8A855685942D531ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF5A78A5B28633F1ULL,
		0xA1DF263094F53091ULL,
		0x5EE970DFB36D1D9DULL,
		0xEADC46FC9AD029BAULL,
		0x24AE50FE5C278760ULL,
		0x6C53009FB212445AULL,
		0x4F0840F38FA5F129ULL,
		0xE4999BC3B46AE5D4ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x713F97FB0C18F385ULL,
		0x7E99B2CE891B7C76ULL,
		0x96CE56BF18B5CAB7ULL,
		0x8504F744CCD7A630ULL,
		0xF85B1278831F37D5ULL,
		0x461B61831E92116AULL,
		0x0D309477E680889EULL,
		0xF2F01F9783C2C1AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6D358DDDFF247DULL,
		0x75C6E40C246175D4ULL,
		0xD42A1C26CE1FE35EULL,
		0xAFA2E2B70CE7D417ULL,
		0x939BD454C1D34616ULL,
		0xEAA95C24A70C83B7ULL,
		0x1BB8F5B9D8AC2245ULL,
		0x053125B6D429DADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C52A276D1E7D7F8ULL,
		0x0B5F56C2AD7A09A2ULL,
		0x42E44A99D6AA29E9ULL,
		0x2AA615F3C0307227ULL,
		0x6BC0C62C42CC71C3ULL,
		0xACB23DA7B99E92DDULL,
		0x168861CE3E2CAADBULL,
		0xF7C13A2157EB1B74ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB50AAF50E4742108ULL,
		0xCF43BCF0E215A4CCULL,
		0x65F2419C6CF43046ULL,
		0x7502D28523B94E02ULL,
		0x307C247D59860C7FULL,
		0xC9530F8834196B38ULL,
		0x4CC588DADDA68D51ULL,
		0x6612833169D0DA43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15255FA791A5F24BULL,
		0xAA3B426BB33AC19FULL,
		0x3672A008B4A7E6ABULL,
		0x9142421D40C3323EULL,
		0x942A425B18C0D635ULL,
		0x979DD7A32B37B98DULL,
		0xEE35D4F213FA7564ULL,
		0xB01912CDA44864D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02FF0F775D1D343ULL,
		0x6578FE9B512F6553ULL,
		0x5380E194D853D6EDULL,
		0xE4409098637A7C3CULL,
		0xA45666264146DA4AULL,
		0x5ECED82B1F2ED2B5ULL,
		0xA2F05C28CE5CF835ULL,
		0xD60B91FCCD98BE93ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6BC05C0367F2087ULL,
		0xFE4E50A1498FF2C2ULL,
		0x5507E378154B6DF3ULL,
		0xF226A1F365375238ULL,
		0x87BB3567E35CDD56ULL,
		0x70EF49C30493318EULL,
		0x33220E2ED0D5F060ULL,
		0x3C99697A7FC8AC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F2A7C5268AF00FULL,
		0x2B8311B3DA4C3961ULL,
		0x9586A42F14C059E2ULL,
		0xED36808987798F8FULL,
		0xB1CDC8D0ABFEC3B3ULL,
		0xD621961CD0492624ULL,
		0x2C0B9D74A36F00DCULL,
		0x69E0456F714E53AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x234EA20510F5D088ULL,
		0xD5CD411293C3CBA3ULL,
		0xC0814757018B3411ULL,
		0x1F10217AE24EDDB7ULL,
		0x3676FDB748A21EE5ULL,
		0xA6CEDFDFD4DA17AAULL,
		0x1F29935A73BAF0BCULL,
		0x55792C150E86FFA3ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53633E1A786C0E7FULL,
		0x7734A1E43B63748DULL,
		0x0F68BBEC68B3D794ULL,
		0x0B74BB7E039E1AEBULL,
		0x2AEC2898AFB7AE6DULL,
		0xD0FFF32432E30629ULL,
		0x28E35EE432D1B554ULL,
		0x68C9F409095120E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E1CF54941F4E09ULL,
		0x5903ECF05776F663ULL,
		0x1EEA91A11423E2E0ULL,
		0xDC09BD9BD16EDCE3ULL,
		0x55B197F96F009C0AULL,
		0x129135C11FED8EDCULL,
		0x0341F17DB44028ACULL,
		0x6ECF4A7DB44B48D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7382F14EEC734076ULL,
		0x2E374D146C1582EEULL,
		0x11822A4D7C903574ULL,
		0xD77D06E5D2F0C608ULL,
		0x7F5DBF61C0B73267ULL,
		0xC26EC6E52D0E88F5ULL,
		0x2BA2AF9986919DF8ULL,
		0x0606BE74BD1A6832ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFCA22092A5E11F8ULL,
		0xAE68F46919A5ABDBULL,
		0xA855732D0C41AA86ULL,
		0x27CA1C39521F3EF4ULL,
		0xF8034BE315D12674ULL,
		0x57A047D6B55A29E9ULL,
		0x2685A40F27DC9FA8ULL,
		0x4EA6320B04E13D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E9AFFEE24E83EDULL,
		0x88C6169F21B18F2FULL,
		0x1D67AAF0670FEBF3ULL,
		0x01400330A5385AF5ULL,
		0xE5854597657B3CA1ULL,
		0x3BC3FF527391D66AULL,
		0xCA1CDD3CFBEAB844ULL,
		0x48B482A6E981C2A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7238DF7C8109215ULL,
		0x26AEE2F6381424F4ULL,
		0xB532D9DD6B4E4175ULL,
		0x268A1F09F7276401ULL,
		0x1D860E7470AA1AD5ULL,
		0x6C63B884C6CBFF83ULL,
		0xEC997933DC3627ECULL,
		0x0612B0ADED60FFE6ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE10D1AA8B0BB82B5ULL,
		0x8F3FA30D3FCAD98EULL,
		0x1FCC770D52C19C3CULL,
		0x5D5EAC3ED91C1B0EULL,
		0x1918F9D45A3C961FULL,
		0x436D694EEE52605DULL,
		0x274BF146A5D6F5D8ULL,
		0xB8FB57A1FB234C78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA500EF98A964CF9DULL,
		0xBF036B918F8F9500ULL,
		0x201C752BD746C5F8ULL,
		0xB989369D451A0110ULL,
		0x27EE5DDAAF378EC7ULL,
		0x0272869C1B3EA663ULL,
		0x43965E3C43E1AFFDULL,
		0x71EA48596CD255BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x440DF53019DF4D28ULL,
		0x303CC89CB0454C8EULL,
		0x3FD00226858759C4ULL,
		0xE4D79AA39C061A1EULL,
		0x3EF6A40EF50B18D8ULL,
		0x411FEFD2F56CC63EULL,
		0x64DDAF7AE6375A25ULL,
		0xC9111FF897F119C7ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC55148468AB8D53ULL,
		0x53E9B46FEC555099ULL,
		0xADAA7C40B9320FE5ULL,
		0x01327AED786FFB74ULL,
		0x6F6D54D2B1847BBFULL,
		0x959B37FD2DC476A9ULL,
		0x501AB4723F23874AULL,
		0x5BE4A945DE3E5A9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3509F10E731D71D1ULL,
		0xBDB938EAE779C683ULL,
		0xB9A3F15A0E673E66ULL,
		0x0060FA95C3C4B1A0ULL,
		0xAAB95CBD51303FB9ULL,
		0xB2C91618B7E5FED9ULL,
		0xDF770729B243BFF4ULL,
		0xE05885DE33C598CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE95CE58A1BB6FC82ULL,
		0xEE508C850B2C961AULL,
		0x14098D1AB7553183ULL,
		0x01528078BBAB4AD4ULL,
		0xC5D4086FE0B44406ULL,
		0x275221E59A218870ULL,
		0x8F6DB35B8D6038BEULL,
		0xBBBC2C9BEDFBC254ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE944B55A9ECBBB41ULL,
		0x580FCF3A675E690EULL,
		0xF6CF8A518989F2A6ULL,
		0x9FE4750B5D53D58BULL,
		0x0D57CDBF3A91271EULL,
		0xCC37652F641D26A7ULL,
		0x1806B00C57F72DF0ULL,
		0xE75A61E94B3F78D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF32F10A5DC7CA3E3ULL,
		0x0CB828C3D8C4FE8DULL,
		0xA131C6B824011931ULL,
		0xD983F86D4D95ADC1ULL,
		0xBEEE5BAAB72734B9ULL,
		0x90916322A76AE51DULL,
		0x09366969D9F6E8C4ULL,
		0xCD5B7626B8E990AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A6BA5FF42B718A2ULL,
		0x54B7E7F9BF9A9783ULL,
		0x57FE4CE9AD88EB97ULL,
		0x46678D6610C6784AULL,
		0xB3B996158DB613A7ULL,
		0x5CA6060DC377C3BAULL,
		0x1130D9658E01C534ULL,
		0x2A0117CFF3D6E872ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED487CF8EBCC78CCULL,
		0x82329A2F1B33D897ULL,
		0xA314F5623702380CULL,
		0x09ECC158D0A6AB33ULL,
		0xE4B49455621B28AEULL,
		0x3DE44B2477DECA23ULL,
		0x9E6BB7B274FD08DEULL,
		0x7CC5174690F46002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA769090C2915DCD1ULL,
		0xBB953E0AD51A3700ULL,
		0x4126A67C7320999FULL,
		0xDCD236AF7A1A839BULL,
		0xC82A4A60F5E21E9FULL,
		0x74DA2DE4AD4CE9ABULL,
		0xA4AF9DFB22DC4C55ULL,
		0x46508C6392FC37EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A2175F4C2D9A41DULL,
		0x39A7A425CE29EF97ULL,
		0xE232531E4422A193ULL,
		0xD53EF7F7AABC28A8ULL,
		0x2C9EDE3597F93631ULL,
		0x493E66C0DA922388ULL,
		0x3AC42A495621448BULL,
		0x3A959B25020857ECULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA34E7843070B196ULL,
		0x4EC877C6EA12DF08ULL,
		0x946CB99F502A6A54ULL,
		0xFA249E441DFF37DAULL,
		0x1CEB071BFA7B80C5ULL,
		0xC7D280E54BE0DF8AULL,
		0xEED9C8C02D79AACDULL,
		0xDB4F96ED5FFEFB1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E0D7F5A87F7A0DULL,
		0x693EADA29B17A6CBULL,
		0x135566BC44403CCAULL,
		0x21417BA2C61F54AFULL,
		0x29FE977065CB58CFULL,
		0xE8E0BB2B1684CAF4ULL,
		0x2619858CE76B641DULL,
		0xD635CC388758D151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBD43071980FCB9BULL,
		0x27F6DA64710579C3ULL,
		0x8739DF23146A569EULL,
		0xDB65E5E6DBE06375ULL,
		0x3515906B9FB0D80AULL,
		0x2F323BCE5D64157EULL,
		0xC8C04D4CCA12CED0ULL,
		0x0D7A5AD5D8A62A4AULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDE225DE94778FF4ULL,
		0x65938A7AEB5E1903ULL,
		0x55278E0189BBC996ULL,
		0x0460430059DB8E7EULL,
		0x90FCB97F9C4E39ECULL,
		0xE9C219F7325DF4FEULL,
		0x6A073117D2998A52ULL,
		0x601BFFDD22E463B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA23593C2EEF79B09ULL,
		0x11475EB66183C59AULL,
		0x6FFD5938C7FA6797ULL,
		0x4F3D2166A68E92F5ULL,
		0x797BA212D3CBC3CFULL,
		0x88346440F5D36F46ULL,
		0x1EDF2A4467919E9FULL,
		0xF0A34711BC2BD39DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FD7B61C7A8014FDULL,
		0x74D4D4CC8ADDDC99ULL,
		0x3ADAD7394E41AE01ULL,
		0x4B5D6266FF551C8BULL,
		0xE9871B6D4F85FA23ULL,
		0x61F67DB7C78E9BB8ULL,
		0x74D81B53B50814CDULL,
		0x90B8B8CC9ECFB02DULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5B210F432834096ULL,
		0x200C87C1A7219573ULL,
		0xFD30929E758C462DULL,
		0x39F12B33387A2D24ULL,
		0x7E9EAB53CE5D3BB8ULL,
		0xE1AEFCBEF2F9D7BFULL,
		0x3453C9B144C14E3EULL,
		0x5CA01A5033F03D95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41896D1F33A651E7ULL,
		0x572081E2136E05DCULL,
		0x33DF376A96CF58D8ULL,
		0xF00F934AEBDA38ECULL,
		0x21C87C5A7A057DA5ULL,
		0xD77FC53B309221CEULL,
		0x1DA4DD2673EE3A83ULL,
		0xF99EDC89B0786411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF43B7DEB01251171ULL,
		0x772C0623B44F90AFULL,
		0xCEEFA5F4E3431EF5ULL,
		0xC9FEB879D3A015C8ULL,
		0x5F56D709B458461DULL,
		0x36D13985C26BF671ULL,
		0x29F71497372F74BDULL,
		0xA53EC6D983885984ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3B12801C39F2D5CULL,
		0x987EDC03696E6970ULL,
		0xAEC484D13A265DBBULL,
		0x35D515320954B5E0ULL,
		0x6145D3619637806FULL,
		0x756EBD3A824E99CDULL,
		0x00C389B5337CE3DEULL,
		0x2A68E16CD269382BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF1B2975F89DC39ULL,
		0xC1B34A9BFEBABC4CULL,
		0x0A729AC899E889DFULL,
		0x910366B9EDE990DCULL,
		0xF2EDE2024BA5489BULL,
		0x6D0EDD74AA49F28AULL,
		0xF94DD1A782ED4E3FULL,
		0xB9F388194D2AFA7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F409A969C16F165ULL,
		0x59CD969897D4D53CULL,
		0xA4B61E19A3CED464ULL,
		0xA4D6738BE4BD253CULL,
		0x93A83163DD92C8F4ULL,
		0x1860604E28076B47ULL,
		0xF98E5812B191ADE1ULL,
		0x939B69759F43C254ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x713B995E92FFB63FULL,
		0xE2E5B5A4CE9BB0FEULL,
		0xAF64009092953605ULL,
		0x774C84CA1762DCBEULL,
		0xC573A4401FB5C38CULL,
		0x11D6B5B9D47AE94AULL,
		0x595590D58662EC71ULL,
		0x498799AFCB1E694BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB1633D40D525C0ULL,
		0x45939A975BF348AEULL,
		0xEB628253F74D32C5ULL,
		0x82624B2656A06C4AULL,
		0xA05EB5D1E96C228FULL,
		0x8FA90A70A1FCFED6ULL,
		0x8DCFEAED4A80E8ECULL,
		0x4CE8E4BA73FF6B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E8AFA63D22A93FFULL,
		0xA7762F339568F850ULL,
		0x440682C365D804C0ULL,
		0xF52ECFEC41C2B0F4ULL,
		0x652D1191F6D9E103ULL,
		0x9E7FBFC97586179CULL,
		0xD49A7A38CCE2049DULL,
		0x056F7D15B8E10220ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9328E31D6E56EF8ULL,
		0x1C006A46F0CAAC4FULL,
		0xC61C8FBDA42C8EDEULL,
		0xA3CF73203E645C6EULL,
		0x145BFB65FCDAA3F3ULL,
		0x3ED1C6B5A6F0A6A9ULL,
		0xBF1B85F5BE491495ULL,
		0x751310D8DE5FF1BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E24F679F5BB8B2EULL,
		0x635EB842AF1D627DULL,
		0xB6B1456CB52C6A14ULL,
		0x86A99F9B008105ACULL,
		0x68BB7235A9ED6505ULL,
		0xF31E84DD48675FF7ULL,
		0x19B47F9F05C629BFULL,
		0x61438199B778CF34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7167848235EE5D6ULL,
		0x7F5ED2045FD7CE32ULL,
		0x70ADCAD11100E4CAULL,
		0x2566ECBB3EE559C2ULL,
		0x7CE089505537C6F6ULL,
		0xCDCF4268EE97F95EULL,
		0xA6AFFA6ABB8F3D2AULL,
		0x1450914169273E88ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51F66BCB9686AD56ULL,
		0x5125CA8C52753DC3ULL,
		0x3C53B08F5C278C91ULL,
		0x663CB8697E636703ULL,
		0x03793CED8B8DC4C4ULL,
		0x2510CC7E52D416B7ULL,
		0xCE279B3F1F38FAFDULL,
		0x683AD54E2F52CCE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10BEBB3C133A2780ULL,
		0x4B2807AE97FE7036ULL,
		0x8E53B21039B4E030ULL,
		0xA02C92D3951DF0FAULL,
		0x19E47ECD54B5B3AEULL,
		0x0245C1041F17F70CULL,
		0xC5E90414E313046CULL,
		0x6DBC22B06265EA55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4148D0F785BC8AD6ULL,
		0x1A0DCD22C58B4DF5ULL,
		0xB200029F65936CA1ULL,
		0xC6102ABAEB7E97F9ULL,
		0x1A9D4220DF38776AULL,
		0x27550D7A4DC3E1BBULL,
		0x0BCE9F2BFC2BFE91ULL,
		0x0586F7FE4D3726B3ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FCF220D2CCC4FDDULL,
		0xC32AE9D9A1F9F453ULL,
		0x95C59A93CEAE4AA9ULL,
		0xE3DC8AD1FDEB5927ULL,
		0x2DEE1FC4F7781D81ULL,
		0x6083C301D898281DULL,
		0x32FEE65EC72BB497ULL,
		0xF342933D8AE058D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C84CC57C0DEF3BULL,
		0x5F8D4D49B573BD95ULL,
		0x62B0AD9D01624D36ULL,
		0xDA144A4519EF0527ULL,
		0xFE785D12010147A3ULL,
		0x7AC21728B7F64755ULL,
		0x0E1522C74B2C2EF0ULL,
		0x9852BB3CA258CCCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F076EC850C1A0E6ULL,
		0x9CA7A490148A49C6ULL,
		0xF775370ECFCC079FULL,
		0x39C8C094E4045C00ULL,
		0xD39642D6F6795A22ULL,
		0x1A41D4296F6E6F48ULL,
		0x3CEBC4998C079A67ULL,
		0x6B10280128B89414ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC02F0E21D3C6CECDULL,
		0x80A53FECCFA08F13ULL,
		0x28782F11E2A39EA3ULL,
		0x3DE13DAB83BB132AULL,
		0x83B61C5029D8F4F0ULL,
		0x78F4CE169A23BC4CULL,
		0x8EF82FFF808408D1ULL,
		0x3FEFC9AEEDA72EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE53608A05FB6054ULL,
		0x257E91EAF450568CULL,
		0xDE4BC3125E2302D8ULL,
		0xB9C05536ECFA1DF2ULL,
		0xB15425CACC39252CULL,
		0x71285A2A43DB9466ULL,
		0x916EBB117670CB8CULL,
		0x604679B0BBFB1CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E7C6EABD63DAE99ULL,
		0xA5DBAE063BF0D99FULL,
		0xF633EC03BC809C7BULL,
		0x8421689D6F410ED8ULL,
		0x32E2399AE5E1D1DCULL,
		0x09DC943CD9F8282AULL,
		0x1F9694EEF6F4C35DULL,
		0x5FA9B01E565C326FULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CF088A243EDB755ULL,
		0xE7ECB3E634014EE0ULL,
		0x5E8E2E867416B1EFULL,
		0x6FF4F6BF31962A31ULL,
		0x2022751DC837FBB6ULL,
		0x33B455C004C3B1CDULL,
		0xDFFE9030797732FBULL,
		0xD00B03BD47CC2A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474FF37B25641D59ULL,
		0x437C3D7F89150E71ULL,
		0x0501389BC5D5E2BDULL,
		0xEC501A12365FEC64ULL,
		0xB7EE3779767601AEULL,
		0xA494DDBA72B09C6DULL,
		0x08FAB68A9B928B7FULL,
		0xAC7EEB3748A39896ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BBF7BD96689AA0CULL,
		0xA4908E99BD144091ULL,
		0x5B8F161DB1C35352ULL,
		0x83A4ECAD07C9C655ULL,
		0x97CC4264BE41FA18ULL,
		0x9720887A76732DA0ULL,
		0xD70426BAE2E5B984ULL,
		0x7C75E88A0F6FB2D2ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE8453B951F243EFULL,
		0x252D78345C88B72AULL,
		0x822A2D7AE8985E8CULL,
		0x18852C4373B24885ULL,
		0xCA8E9C612D1A2F6BULL,
		0x3EEB31CA23A1F222ULL,
		0x404FB0BDB608AF90ULL,
		0x3D2898CA48FF0036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE575994AC333EFULL,
		0xD0953D33CF9983EDULL,
		0x2B6022F895901900ULL,
		0x7FAB7F462E87EE5DULL,
		0x03CE44FBA69C3E44ULL,
		0x13804B8DD4103BF6ULL,
		0x0845DF66AD9607C8ULL,
		0xA74D5B1FEB2E85A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x936126201B317000ULL,
		0xF5B84507931134C7ULL,
		0xA94A0F827D08478CULL,
		0x672E53055D35A6D8ULL,
		0xC940D89A8B86112FULL,
		0x2D6B7A47F7B1C9D4ULL,
		0x480A6FDB1B9EA858ULL,
		0x9A65C3D5A3D1859FULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3A68FF3528E5FBCULL,
		0xBF6441755E20655AULL,
		0x9686D1A7C9323F83ULL,
		0x0C3B67564FD38F86ULL,
		0xFC5C7B0250FA3EE7ULL,
		0x3DA2D8BE77E6C36EULL,
		0xA1E782CC005D4C29ULL,
		0xDAD8075C7CADD553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB12689A1C334F3C4ULL,
		0xFD66B6989D8C233DULL,
		0x79990F0B2A75A775ULL,
		0x24DEDBE72816621DULL,
		0x17F9C283E7168DFFULL,
		0xF28EA022F8E36B21ULL,
		0x11719F2EEB7E322CULL,
		0xD32A2D17D1B888A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4280065291BAAC78ULL,
		0x4202F7EDC3AC4667ULL,
		0xEF1FDEACE34798F6ULL,
		0x28E5BCB167C5ED9BULL,
		0xEBA5B981B7ECB318ULL,
		0xCF2C789C8F05A84FULL,
		0xB0961DE2EB237E05ULL,
		0x09F22A4BAD155DF4ULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFC4428D4A3E4FE6ULL,
		0x2C74D51D26D1864FULL,
		0x77F5C84E37035B3EULL,
		0x6A6DF40C91204B68ULL,
		0x0C5FD94042123C1FULL,
		0x8AC3E238FD308CBDULL,
		0xF5293177D62E4187ULL,
		0x18F0EFB7482081E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330832F90B1E8F03ULL,
		0x62A412F9A4EA5FBFULL,
		0xE509A802E094C7C0ULL,
		0x410DB0D54F34742CULL,
		0x21A7687964CCFBF7ULL,
		0xCEAAABBEC27A5853ULL,
		0xA851B68C554490F0ULL,
		0x0287C8B0FC4F2127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECCC70744120C0E5ULL,
		0x4ED0C7E4823BD9F0ULL,
		0x92FC604CD7979CFEULL,
		0x2B6044D9DE143F44ULL,
		0x2DF8B13926DEC7E8ULL,
		0x446949863F4AD4EEULL,
		0x5D7887FB836AD177ULL,
		0x1A772707B46FA0C2ULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4ABF5E75C25EDB30ULL,
		0xFB1779921D5467F5ULL,
		0xFE6020E773D47264ULL,
		0xAE6B95A4512DE66CULL,
		0x389D276E0372909FULL,
		0xBA7EA832C9A6F20CULL,
		0xD5C44DCD9D91CDECULL,
		0x029839EECA3868B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F3986D1CF3DF22ULL,
		0x07EDA8691E9ABEB2ULL,
		0xE925B6CF0A65EC11ULL,
		0x6560808CE6D038C1ULL,
		0x8FCA77470275A8C8ULL,
		0x5258C3ACACBF16BAULL,
		0x178348719430C2D6ULL,
		0x685807F042D0DFB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434CC618DEAD0412ULL,
		0xFCFAD1FB03CED947ULL,
		0x1745962879B19E75ULL,
		0xCB0B1528B7FDDEADULL,
		0xB757502901073857ULL,
		0xE8266B9E6519E4B6ULL,
		0xC24705BC09A10F3AULL,
		0x6AC03E1E88E8B703ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB11BC2D5043F5B9EULL,
		0xBBCA34A18EB3CB2BULL,
		0xEC5F6A2FF7467BE2ULL,
		0x7AE1819603BFCDB9ULL,
		0x7CF1017B6D1860AEULL,
		0xC86D7D9A34128B99ULL,
		0x741CC0DEABC85A92ULL,
		0xD34010B3AB0D2885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E64CFA169FDA0A3ULL,
		0x6FE58FC3D920AA9CULL,
		0xDEAA0E9A23F4B096ULL,
		0x891D6BE05F17C203ULL,
		0x3E38D6047A494992ULL,
		0xC89A0B2AE29960F9ULL,
		0x99473B4D5669C841ULL,
		0x8BEC1EFFDCFE93BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F7F0D746DC2FB3DULL,
		0xD42FBB62579361B7ULL,
		0x32F564B5D4B2CB74ULL,
		0xF3FCEA765CA80FBAULL,
		0x42C9D77F1751293CULL,
		0x00F776B0D68BEB60ULL,
		0xED5BFB93FDA192D3ULL,
		0x58AC0E4C77F3BB3AULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA06FAA6897ED7612ULL,
		0xF9F5315950C8BACDULL,
		0xB040E5F6A51E89F9ULL,
		0xC9648E24049A921AULL,
		0xFA30C98F5CD5B1C1ULL,
		0x53F884A758C0B4B2ULL,
		0x936F86743379DE37ULL,
		0x3E8021944EEE8B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0160B6FBEA16BF71ULL,
		0x921F75A29D37C4B0ULL,
		0x7BC4138DA5D86397ULL,
		0x58B6B27C46F479B5ULL,
		0xE56962327989F1ABULL,
		0x0F4972E6A249AA5EULL,
		0xCA79F61F87E92466ULL,
		0x57C3C00253A2AB87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA10F1C937DFBC963ULL,
		0x6BEA44FBCDFF7E7DULL,
		0xCB84F67B00C6EA6EULL,
		0x91D23C58426EEBAFULL,
		0x1F59ABBD255C406AULL,
		0x5CB1F641FA891EECULL,
		0x5916706BB490FA51ULL,
		0x6943E1961D4C2092ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BF4FB60B67D30F0ULL,
		0x60EEEFC11FDC2577ULL,
		0x5C494959AD720E1DULL,
		0x8B651C369DD0E99FULL,
		0x5A0F9CC8CAF909CBULL,
		0xEC6B992A44F26A37ULL,
		0x66508EEC70C08740ULL,
		0xDA0978910D81589CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x325236AC246FAE15ULL,
		0xC6557D014B6D2527ULL,
		0x55C3B2332242892DULL,
		0x4FED4B1570C8D1CBULL,
		0x2F047597AB2A019CULL,
		0x7835E6FF7579B1D5ULL,
		0x9FAF01E9DD4660E9ULL,
		0xE4D4B2EC98EE3533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19A6CDCC92129EE5ULL,
		0xA6BB92C054B10050ULL,
		0x098AFB6A8F308730ULL,
		0xC4885723ED183854ULL,
		0x750BE95F61D30857ULL,
		0x945E7FD5318BDBE2ULL,
		0xF9FF8F05AD86E7A9ULL,
		0x3EDDCA7D956F6DAFULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27A7DCF0FCD2B1EFULL,
		0x712E88E77C04E0A2ULL,
		0x8256B4757B341085ULL,
		0x8FB0DAB5BF0622B8ULL,
		0x37EF2D4B73AD5B9BULL,
		0x760D7C55350447BFULL,
		0x52B1FCB06288131AULL,
		0x34AB5D81104AC1CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD373DFB07B084C60ULL,
		0x78913350E4892E7EULL,
		0x407A81F3E15AE1C7ULL,
		0x34A6C91000031CEFULL,
		0xE2B32A80C89610B9ULL,
		0xA86B55F60C60C025ULL,
		0x694084697FEBF4FDULL,
		0x8FBD783C1E759C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4D4034087DAFD8FULL,
		0x09BFBBB7988DCEDCULL,
		0xC22C35869A6EF142ULL,
		0xBB1613A5BF053E57ULL,
		0xD55C07CBBB3B4B22ULL,
		0xDE6629A33964879AULL,
		0x3BF178D91D63E7E7ULL,
		0xBB1625BD0E3F5DA9ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8D419408E86A428ULL,
		0xFC05050FEBADD1D8ULL,
		0x60F99CBEE63140ECULL,
		0x42B018924306B82BULL,
		0x47B5FA3C027DEAD1ULL,
		0x6B97532074229B53ULL,
		0x5A13E61238CBE3FCULL,
		0x33FE4C1ECF04CFE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDDA2AE3262BE86AULL,
		0x559B68C03C94BE17ULL,
		0x2AAED0B1BA687928ULL,
		0x54F028C098F8A6AEULL,
		0x6C746DEF1472CB84ULL,
		0xC8D781F63029C9B4ULL,
		0xB0D476F3F1FBEE5EULL,
		0x406603E9EE2CCBB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050E33A3A8AD4C42ULL,
		0xA99E6DCFD7396FCFULL,
		0x4A574C0F5C5939C4ULL,
		0x16403052DBFE1E85ULL,
		0x2BC197D3160F2155ULL,
		0xA340D2D6440B52E7ULL,
		0xEAC790E1C9300DA2ULL,
		0x73984FF72128045EULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5FC911542B82E37ULL,
		0x274CB698D689BDC8ULL,
		0x396BAA6F8E7DF5F0ULL,
		0xD184FFE55F6E589FULL,
		0x9D8A153E7FA53BA6ULL,
		0x0A1434EF92FCE6C1ULL,
		0x0B52CCCDB70BCCB4ULL,
		0xDED3A8B402A4D31AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA376FEF7F191F3FULL,
		0x0F4371F2071E123FULL,
		0x1B2B341483B2A4DCULL,
		0xF1C0FD314FBF5899ULL,
		0x43BA4D363FEC36EBULL,
		0xA0A38BAC1A589AC8ULL,
		0x0391F2128C21326AULL,
		0x3C38F36F8377B01FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FCBFEFA3DA13108ULL,
		0x280FC76AD197AFF7ULL,
		0x22409E7B0DCF512CULL,
		0x204402D410D10006ULL,
		0xDE30580840490D4DULL,
		0xAAB7BF4388A47C09ULL,
		0x08C33EDF3B2AFEDEULL,
		0xE2EB5BDB81D36305ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7125C3FA42B2A0B2ULL,
		0xBC9773A6C499FB81ULL,
		0x82C3BA848115E5EBULL,
		0x8C1B7540DDDBB558ULL,
		0xA440C9DDA1F3CD0DULL,
		0x09346D2DAC67B16EULL,
		0x6CC4779ED7640F5CULL,
		0x142822B641ECF205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2A3958FBCC669CULL,
		0xBEA07E4A11B4B12AULL,
		0xE6DD4CA7725DCE6BULL,
		0xCDADCF5CB85E77C0ULL,
		0x864331D85D71857AULL,
		0xBA2E64A4C7FF2D61ULL,
		0xEE58868E4036B4F3ULL,
		0x2ADE1037438960F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F0FFAA2B97EC62EULL,
		0x02370DECD52D4AABULL,
		0x641EF623F3482B80ULL,
		0x41B6BA1C6585C298ULL,
		0x2203F805FC824877ULL,
		0xB31A09896B989C0FULL,
		0x829CF1109752BBAFULL,
		0x3EF63281026592F0ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18DF5B4B65E2F88EULL,
		0xEC4A72F77C08B657ULL,
		0xC18C0586230383B9ULL,
		0xF706ED2C46749ADAULL,
		0x051DBCC100499E0CULL,
		0x8D333290D86D6E1AULL,
		0x1F4FAF8CD178E020ULL,
		0x1DC109C20EB29DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58441383167BA28BULL,
		0x54FF068D39141D47ULL,
		0x84463591F7AADFBBULL,
		0xEF1EFB32064C76CEULL,
		0x77DE88B84EE798BAULL,
		0x3E72B69B74572398ULL,
		0x0E793B354C17F4D4ULL,
		0x86F64628F0538AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x409B48C873995A05ULL,
		0xB8B5747A451CAB10ULL,
		0x45CA3017D4A95C02ULL,
		0x1818161E4038EC14ULL,
		0x72C334794EAE06B6ULL,
		0xB341840BAC3A4D82ULL,
		0x113694B99D6F14F4ULL,
		0x9B374FEAFEE1171CULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2698CC658D8CFD81ULL,
		0xC5D771A0E51C47D6ULL,
		0xCE7E4DA4122F5E76ULL,
		0xE30D60EFA2488052ULL,
		0x6A29E7C3912B0AF1ULL,
		0x4D396FCF7552605BULL,
		0x78206C042F81A004ULL,
		0x5DCFD2CE916129BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD099FDDDDD960CFCULL,
		0xC0D1D0D97D084978ULL,
		0x4C0F332D2028B119ULL,
		0xE78C0C3AEC310283ULL,
		0xB43C4C286F50BF30ULL,
		0xB48A0062B3B1E0CDULL,
		0x88532AC08083FECAULL,
		0xBAE44F41D3A598EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF60131B8501AF17DULL,
		0x0506A17998140EAEULL,
		0x82717E893207EF6FULL,
		0x04816CD54E7982D1ULL,
		0xDE15ABEBFE7BB5C1ULL,
		0xF9B36FADC6E38096ULL,
		0xF07346C4AF025ECEULL,
		0xE72B9D8F42C4B150ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAB079FB13DE952AULL,
		0x9782261D8A7A829EULL,
		0x3EEC4421B76A856DULL,
		0xE8617BA9E5DB73B0ULL,
		0x0ECA25557029A15DULL,
		0xEF3343B2D4909059ULL,
		0x1DC865A3EA39EF76ULL,
		0x382F7C3B622350CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0760CF883A611F68ULL,
		0x4682C2B7E2D30020ULL,
		0xAD2F29842A6D800EULL,
		0xC827BC8DF0528D05ULL,
		0x914292837C40E294ULL,
		0x52810142259F786FULL,
		0xB155CC18C6B6ACBBULL,
		0x209E4D6C652555DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADD0B67329BF8A42ULL,
		0xD100E4AA68A982BEULL,
		0x93C36DA59D070563ULL,
		0x2046C7241589FEB5ULL,
		0x9F88B7D60C6943C9ULL,
		0xBDB242F0F10FE836ULL,
		0xAC9DA9BB2C8F43CDULL,
		0x18B1315707060516ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CC1B7913DDE5E14ULL,
		0x333B401EC54CF6FAULL,
		0xB636965F58DC9FABULL,
		0x3F2AEDA132671523ULL,
		0x877F9AFB843D5FC5ULL,
		0xFE49C18D301A0512ULL,
		0x375699E1BA505A22ULL,
		0x1D6F044AA871500AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3192BCC7D30A6CE9ULL,
		0x1813520CB567CF98ULL,
		0x3A59B8B8478C7C5BULL,
		0x16B4831E1788D1BFULL,
		0x1EDBECDAB12EAB16ULL,
		0x14760E8B747B88AEULL,
		0xA3A72001B6C8C647ULL,
		0x0196204260558437ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D530B56EED432FDULL,
		0x2B281212702B3962ULL,
		0x8C6F2EE71F50E3F0ULL,
		0x299E6EBF25EFC49CULL,
		0x99A476213513F4D3ULL,
		0xEA3FCF0644618DBCULL,
		0x94F1B9E00C989C65ULL,
		0x1CF92408C824D43DULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA9569031C549BD4ULL,
		0x16CA011D8908F9D2ULL,
		0x644BC4AE32A6ABBCULL,
		0xDD90B43BB667E4CFULL,
		0x6249BA46C8622655ULL,
		0xBFF2351CCE46B66BULL,
		0xBAD6E11B2D01A0E8ULL,
		0x11D8654AF1B4E90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9571185476986A22ULL,
		0xFDA67745AFE84070ULL,
		0x1F530E6BDB3DBC57ULL,
		0xDC506F3CA943ABCCULL,
		0xDA4D62CBCCD38EBEULL,
		0x6680C561B30C3F22ULL,
		0x79EB2194D3B0BBC5ULL,
		0x5BAF84EC7DE74E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FE471576ACCF1F6ULL,
		0xEB6C765826E0B9A2ULL,
		0x7B18CAC5E99B17EBULL,
		0x01C0DB071F244F03ULL,
		0xB804D88D04B1A8EBULL,
		0xD972F07D7D4A8949ULL,
		0xC33DC08FFEB11B2DULL,
		0x4A77E1A68C53A75FULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7FC762192754512ULL,
		0x49456EA68FFB63BCULL,
		0xB81201F0544C10BBULL,
		0x7D6F1AB52444DF36ULL,
		0x1675A2FD5521756EULL,
		0x9296B6BE192CBD0CULL,
		0xF5CF376B36A0298AULL,
		0xB904D4C0353AA742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAECEB1741D5E25AULL,
		0xDA0B9F33C8A8A563ULL,
		0xF866AB8FFA1819DCULL,
		0xAD5B8A89DF53C02CULL,
		0xA3AD404037AEEDE3ULL,
		0xCB5B6961302B489BULL,
		0x64B5554A0A57327DULL,
		0xAE1BCEF8BB8183D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D109D36D3A0A748ULL,
		0x934EF1954753C6DFULL,
		0x4074AA7FAE540967ULL,
		0xD034903CFB171F1AULL,
		0xB5D8E2BD628F988DULL,
		0x59CDDFDF2907F597ULL,
		0x917A62213CF71BF7ULL,
		0x171F1A388EBB2490ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8D1A79BF682FEEDULL,
		0xACD0E41DD0944D91ULL,
		0x4A74D9DDD4DE0915ULL,
		0x2FE53566D3B7660EULL,
		0x631552F6E6D6B3C7ULL,
		0xC93BE5E26953F997ULL,
		0xFC27E3930202206CULL,
		0x753057D775B77499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE55633B9860012ULL,
		0xFDF2419F90CE0864ULL,
		0x5A4F9E7F354740C4ULL,
		0xC16D692D1AA30FAAULL,
		0x6AD4BF004236A3CAULL,
		0x4D05A91FB1BF908DULL,
		0xB60E1BBE24BAFA4FULL,
		0x11848DC3AC7CB75AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6634F1A84F04FEFFULL,
		0x5122A582405A45F5ULL,
		0x103B47A2E19949D1ULL,
		0xEE885C4BC91469A4ULL,
		0x09C1EDF6A4E0100DULL,
		0x843E4CFDD8EC691AULL,
		0x4A29F82D26B8DA23ULL,
		0x64B4DA14D9CBC3C3ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF910CAD6D3A66BFEULL,
		0xE67F06C138EE55A1ULL,
		0x8DC4A842EB7ABDE2ULL,
		0xC757393D53F1313AULL,
		0xE70D54CC3A417A7AULL,
		0xC1DA1429178AEE3FULL,
		0xE48E247D7040BEB3ULL,
		0x58DF781EF8378208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8405B3E522628688ULL,
		0x3FA2C608C1978BD0ULL,
		0xA2523DBC9D905724ULL,
		0x88F0BD394777244EULL,
		0xB93F496569D0553EULL,
		0x4230F11587CFA4D0ULL,
		0x3BDE60618077623CULL,
		0x73322454AB9A45FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D157933F1C4ED76ULL,
		0xD9DDC0C9F979DE71ULL,
		0x2F9695FE76EAEAC6ULL,
		0x4FA7840414861574ULL,
		0x5E321DA953912F44ULL,
		0x83EAE53C90454AEFULL,
		0xDF50441CF037DC8FULL,
		0x2BED5C4A53ADC7F6ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4641E93A355EECA8ULL,
		0x916E635D71EDD077ULL,
		0x77781A3FAAE1F21FULL,
		0x455DBC3AB521E9D7ULL,
		0x0310F8246FE49D4AULL,
		0xDCB3DED3F91A19E5ULL,
		0x05D494A5A6C1A3A3ULL,
		0xCD1322E02121C994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00561E248EB8D73ULL,
		0xDA25C28C418BC5E9ULL,
		0x27C698F62A32B98FULL,
		0x41A34764744EA506ULL,
		0x7FABEB80BB92692BULL,
		0xB038CD636D77ADBCULL,
		0x075E64B2DCCAAFC2ULL,
		0x52372F08A091FBEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB64488D87DB561DBULL,
		0x4B4BA1D13066159EULL,
		0x50BE82C980D34B90ULL,
		0x04FEFB5EC16F4CD1ULL,
		0x7CBB13A4D476F461ULL,
		0x6C8B13B0946DB459ULL,
		0x028AF0177A0B0C61ULL,
		0x9F240DE881B03279ULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8386A16B7C1C47EAULL,
		0xA28A6B04CE7E4625ULL,
		0x4723EB7F600A5745ULL,
		0x9B44DD57DF61783AULL,
		0x52A56596430CAC14ULL,
		0x43D667FD5BAA09ADULL,
		0xB97A595B9A184653ULL,
		0x32B99919A8B4DA35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C09D1248FF6DE3ULL,
		0x588C85BD0229B9A5ULL,
		0x5ADCFC9A13D2B127ULL,
		0x82BEAB16550B6079ULL,
		0xDB76ED4792042104ULL,
		0x3B3958D580A4658FULL,
		0xBA6873E7CD3E5D86ULL,
		0xE99B73FDDC9D42B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4463C7934E32A09ULL,
		0xFA06EEB9CC57FF80ULL,
		0x1DFF17E573D8E662ULL,
		0x19FA76418A6A1843ULL,
		0x89D388D1D1088D10ULL,
		0x78EF3F28DB0E6C22ULL,
		0x03122ABC57261BD5ULL,
		0xDB22EAE474299885ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23A653D321C91782ULL,
		0xF1691684F6AF6C40ULL,
		0xF44E1FFF118B887CULL,
		0xE1B3E76DFED82E0EULL,
		0x6B9ACD9016E72095ULL,
		0xBB6C48A82C70723EULL,
		0x32539EEDB0A10635ULL,
		0x24C52B7393EC5603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9357C5FE003E26CCULL,
		0x39F915E38D6F4F4AULL,
		0xF8727604C7A3F21BULL,
		0x42FCBAC3B57A8BDDULL,
		0x1B14D720CC0E888FULL,
		0xC2A08CF302554662ULL,
		0xED6ABE5C265049A6ULL,
		0x8DDCFF6020543786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0F1962D21F7314EULL,
		0xC89003677BC0230AULL,
		0x0C3C69FBD6287A67ULL,
		0xA34F5DAE4BA2A5D3ULL,
		0x708E1AB0DAE9A81AULL,
		0x79CCC45B2E25345CULL,
		0xDF3920B196F14F93ULL,
		0xA919D413B3B86185ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x140E766AF27507A8ULL,
		0xB692429E405DF451ULL,
		0xCDA28348F031F70AULL,
		0xD7C1D287158E214EULL,
		0x45E1FD08AB0C4377ULL,
		0xFB57F541C7F52EE1ULL,
		0x20EE0FDB0CE89EEBULL,
		0xB0F5BB86A81FF0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43EF43E566F48D8ULL,
		0x554C51DFED09595CULL,
		0xE28856B2EE89A19CULL,
		0x847CD366B274B62EULL,
		0x28AE078C640FF458ULL,
		0x8A114A4A3B79C9A9ULL,
		0xB899C992951FB508ULL,
		0x993640EB39514B78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0308254A41A4F70ULL,
		0xE3DE1341AD54AD0DULL,
		0x2F2AD5FA1EB85696ULL,
		0x53BD01E1A7FA9760ULL,
		0x6D4FFA84CF03B72FULL,
		0x7146BF0BFC8CE748ULL,
		0x9877C64999F72BE3ULL,
		0x29C3FB6D914EBBD7ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2792940D163B0661ULL,
		0x30DA6FB44E90E4A3ULL,
		0x80861D99C33D88D2ULL,
		0xF9DE0FFC2C759B49ULL,
		0x3623D56C55D5C8D2ULL,
		0x46EAA3B88BA8D550ULL,
		0xA7F14032049D9186ULL,
		0x489E4A44375E3DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41279A8F1A0B2A5AULL,
		0xFFB2C21A41A00649ULL,
		0x0B1FF3EC82C8D0CBULL,
		0xAEB6490317102A62ULL,
		0x16DFB44167D2E7C8ULL,
		0x1ECD12C23B5F4888ULL,
		0x6AE4CE8BCC22B446ULL,
		0x03210D07B0AB5D6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66B50E820C302C3BULL,
		0xCF68ADAE0F30E2EAULL,
		0x8B99EE7541F55819ULL,
		0x576846FF3B65B12BULL,
		0x20FC612D32072F1AULL,
		0x5827B17AB0F79DD8ULL,
		0xCD158EB9C8BF25C0ULL,
		0x4BBF474387F5609AULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A0EF4DB0124F57BULL,
		0x889D50D67512EBEEULL,
		0x6A492D0C50950C5BULL,
		0x777D1F34B2BADBDDULL,
		0xBCB4E421F52AFA4FULL,
		0xF7B40DB29DB4913DULL,
		0x08BC93ACDE31B631ULL,
		0x4D5B174750CEDC9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9C35AC33E42D9AULL,
		0x0F4B85373BC18AF9ULL,
		0xB32E0402D7118874ULL,
		0x1E30A46370E8D4EEULL,
		0x3A937667E7A07F0CULL,
		0x3A0D99B933A529F3ULL,
		0xEF8C379F1535AD26ULL,
		0xD6BB2C7C21DD7D7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD192C17732C0D8E1ULL,
		0x87D6D5E14ED36117ULL,
		0xD967290E8784842FULL,
		0x694DBB57C2520F33ULL,
		0x86279246128A8543ULL,
		0xCDB9940BAE11B8CEULL,
		0xE730A433CB041B17ULL,
		0x9BE03B3B7113A1E7ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67A0165806990FFULL,
		0xD870543B119D995EULL,
		0x928E4B3D3DFDA053ULL,
		0x8B33D71D330780BEULL,
		0x09C4D7D1956A5BDDULL,
		0x9C88B40656713DA7ULL,
		0x1AA0CB026EB641EBULL,
		0x2ABA8A3310F7B61BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CE1927D73F6E964ULL,
		0x004BECE25C647E4DULL,
		0x5525D149D8FCEE77ULL,
		0x776C5828BF7B6089ULL,
		0x755BA0C9C0AFD0E6ULL,
		0x6A9E44559EFEB0EBULL,
		0x2B205F150BA4A736ULL,
		0xD23631E23A7A6CCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA9B9318F39F799BULL,
		0xD83BB8D94DF9E713ULL,
		0xC7AB9A74E5014E24ULL,
		0xFC5F8F358C7CE037ULL,
		0x7C9F771855C58B3BULL,
		0xF616F053C88F8D4CULL,
		0x318094176512E6DDULL,
		0xF88CBBD12A8DDAD5ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A1193623C797094ULL,
		0x3B6537F178A070B3ULL,
		0xF79FCB571C585CDDULL,
		0xA02C65CE13640361ULL,
		0x01DF126D4E32EB8FULL,
		0x33EBCD953B016354ULL,
		0xFB7A85B0C3075BA0ULL,
		0x9666FC2781D7D826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DEE20FF5834D858ULL,
		0xC6EC6C9FDD8290DBULL,
		0xF79692927CBE30BCULL,
		0x68F8568529DBF69FULL,
		0xA3AB8800338D21BCULL,
		0x38E82029A1576F7BULL,
		0x22505C92B653FDB9ULL,
		0x99B96A066D9D5A9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67FFB39D644DA8CCULL,
		0xFD895B6EA522E068ULL,
		0x000959C560E66C61ULL,
		0xC8D4334B3ABFF5FEULL,
		0xA2749A6D7DBFCA33ULL,
		0x0B03EDBC9A560C2FULL,
		0xD92AD9227554A619ULL,
		0x0FDF9621EC4A82B9ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9D03313C85CFBC4ULL,
		0xFB2F4EAEF5E7180FULL,
		0xE8030D4436A548DCULL,
		0xE463975812EADC09ULL,
		0x387C4D23B7F3575DULL,
		0x2985F7BC8345C8E8ULL,
		0xBBD6A08F4AACD581ULL,
		0x29D3692550E94F52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27046080780D05FCULL,
		0x706A523F3967D220ULL,
		0x7078C9C4C1A442CBULL,
		0x11975511870C6E8BULL,
		0xDE71E003258F97AFULL,
		0x86357626A1518306ULL,
		0x7B4D0CA68025F311ULL,
		0x4434227D85E99A18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDED45393B051FE38ULL,
		0x8B451C91CC80CA2FULL,
		0x987BC480F7010A17ULL,
		0xF5F4C24995E6B282ULL,
		0xE60DAD20927CC0F2ULL,
		0xAFB0819A22144BEEULL,
		0xC09BAC29CA892690ULL,
		0x6DE74B58D500D54AULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDBB5AE050B7D193ULL,
		0x08995A8F2CBD95E7ULL,
		0xFECF0A10DB90D11AULL,
		0xB3AB36F143B98C87ULL,
		0x3B16456B51103151ULL,
		0x123515F8D887B548ULL,
		0x389DF69557040B1DULL,
		0x714CF80B70E30FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5D5993D9CFEABFULL,
		0xC961C66CF88EE64DULL,
		0x884B38A1515F0A26ULL,
		0xC2B785F0B1383311ULL,
		0x0CE60C4CB53A6978ULL,
		0x61760EEA03BEA926ULL,
		0xE4535AFA228C4F43ULL,
		0xC6F8EDB05A632543ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67E6037389783B2CULL,
		0xC1F89CE3D43373AAULL,
		0x768432B18ACFDB3CULL,
		0x711CB301F281BF96ULL,
		0x37F04927E42A5829ULL,
		0x73431B12DB391C6EULL,
		0xDCCEAC6F7588445EULL,
		0xB7B415BB2A802AF0ULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F8B75821A97F5DULL,
		0x730069ED7C3AA7C1ULL,
		0x27C2C0C474F117F3ULL,
		0x51C187FEE25A474CULL,
		0x86CD5E3102D1EA78ULL,
		0x855498D0019E829BULL,
		0x8D9EC49AFCF3C2FEULL,
		0xA45CE9497261917CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF59FDE1504B5709DULL,
		0x8A3B21D316D3E9C7ULL,
		0x2C9A74E636F00097ULL,
		0xDED423738F98DDC9ULL,
		0x002FBF0A9F26FDB6ULL,
		0x4596E03C8C636B98ULL,
		0x2365765805BF335FULL,
		0x5D2547B805A7C230ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5467694D251C0FC0ULL,
		0xF93B483E6AE94E06ULL,
		0x0B58B42242011764ULL,
		0x8F15A48D6DC29A85ULL,
		0x86E2E13B9DF717CEULL,
		0xC0C278EC8DFDE903ULL,
		0xAEFBB2C2F94CF1A1ULL,
		0xF979AEF177C6534CULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC65801F607AD443ULL,
		0x3310DB55D099D7B8ULL,
		0x6C40953CC57F8777ULL,
		0xC7739C1B0E6BB3C3ULL,
		0xF2EAD26822B8787BULL,
		0x1F8460F03502301CULL,
		0x4EB6AC953F29CDA2ULL,
		0x06A99C70E9A87061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8652BD206099BF2ULL,
		0x23349DE903082513ULL,
		0xE076CF1652C0DDC4ULL,
		0xD4830FD648A09EE8ULL,
		0xC1BB46C131CA421AULL,
		0xFC8C63E92B0540C8ULL,
		0x30B9301F721899D6ULL,
		0xFBAA0F6E6BCC7112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0400ABCD66734FB1ULL,
		0x102446BCD391F2ABULL,
		0x8C365A2A97BF5AB3ULL,
		0x13F093CD46CB2D2BULL,
		0x335194A913723A61ULL,
		0xE30803191E0770D4ULL,
		0x7E0F9C8A4D315474ULL,
		0xFD03931E82640173ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F611B9FE5B28B17ULL,
		0x90C24123C8A2DABEULL,
		0xD4398D4A8B9DDEFFULL,
		0xFD8B5714308703EAULL,
		0x073268B9295706ACULL,
		0xB4B54D802D28E1ABULL,
		0x588EB20635E252E1ULL,
		0x52BDC2E331E59FE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E1225775A8BEC8ULL,
		0x4DDB57628A9246D6ULL,
		0x176830FA0BF2E723ULL,
		0x7BF5ED99D341C26AULL,
		0x5E1D555DB6108BA9ULL,
		0x877BCBC84B09DA64ULL,
		0x5476EF349D9A67A3ULL,
		0x7CC73B9F1CE8EAD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D8039C8901A35DFULL,
		0xDD19164142309C68ULL,
		0xC351BDB0806F39DCULL,
		0x867EBA8DE3C6C180ULL,
		0x592F3DE49F478D05ULL,
		0x33CE864866213BCFULL,
		0x0CF85D32A8783542ULL,
		0x2E7AF97C2D0D7532ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A0D7013570174C8ULL,
		0xFF0BB76EDB551378ULL,
		0x63798DA9A8BC8343ULL,
		0x8C4CE74D9D920BEFULL,
		0x79F55C52CB4ED157ULL,
		0xD9E99F0808636420ULL,
		0x495F38A6B8CD9FB0ULL,
		0x734B8E7331DED3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5FD1A10892A66C2ULL,
		0xA38484E398D6FA16ULL,
		0x8FF50B03286E135AULL,
		0x839753C6BED8FA97ULL,
		0x0A91B744AC3630F7ULL,
		0x2228ABF26CB52A28ULL,
		0x08AAF496951468BBULL,
		0xB8A07F0FAF1DC02DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FF06A03DE2B120AULL,
		0x5C8F338D4383E96EULL,
		0xEC8C86AA80D29019ULL,
		0x0FDBB48B234AF178ULL,
		0x7364EB166778E1A0ULL,
		0xFBC134FA64D64E08ULL,
		0x41F5CC302DD9F70BULL,
		0xCBEBF17C9EC31382ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C3B015D67AE3F1EULL,
		0x2948B5D2BB0DF2AEULL,
		0xF8356C5E626F01DAULL,
		0xA7E4B8B9CBEDED91ULL,
		0xFD3BC072456D7D0BULL,
		0xF3191A874B8B781FULL,
		0xB13B37999D54F429ULL,
		0x36203698A7F36FBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9F62CF38E1844F8ULL,
		0x6BDA2024065D4A41ULL,
		0x19D894D9662B1367ULL,
		0xFFCA9F84360ECC1BULL,
		0xEEC6539B4E8A2847ULL,
		0xB0C816B663245BF4ULL,
		0x3838F1AB553A27F7ULL,
		0x8D1CF7BFC7CBFA29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95CD2DAEE9B67BE6ULL,
		0x429295F6BD50B8EFULL,
		0xE1EDF887044412BDULL,
		0x582E273DFDE3218AULL,
		0x13FD93E90BE7554CULL,
		0x43D10C3128AF23EBULL,
		0x8903C632C86ED3DEULL,
		0xBB3CC12760389596ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C29629BE2593C01ULL,
		0xC0BCA3208228C6E6ULL,
		0xDF9998B785022BF9ULL,
		0x3810A8D6E13907B2ULL,
		0x4C436D7B47DD8A05ULL,
		0xDB8864F9363016CEULL,
		0x630536693215F3CDULL,
		0x8A8CBBA998003747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73634E78156A9E3AULL,
		0xB07CD4639DC89AFDULL,
		0x8CAB4E785F31281AULL,
		0x7A0C57470B40ADD3ULL,
		0x48F36309414121E0ULL,
		0x491D315FFD4B8E1FULL,
		0xDA3C5A644E461F10ULL,
		0xEDD767E6DF53C8A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F4A2CE3F733A23BULL,
		0x70C077431FE05C1BULL,
		0x5332D6CFDA3303E3ULL,
		0x421CFF91EA79AA61ULL,
		0x04B00E72069CABE5ULL,
		0x929555A6CB7B98D1ULL,
		0xB9396C0D7C53ECDDULL,
		0x675BDC4F4753FFEFULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96E01ED68FF7EF0CULL,
		0xAC3F0FFDD7EBFED5ULL,
		0x5F812CE606F5A92CULL,
		0x29B4869F62A36415ULL,
		0xE117F59C2362561EULL,
		0x5AF21C7D3166BD2BULL,
		0xBC3399395F8F6F73ULL,
		0x98D01CA640843CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC35946B52A9B7D32ULL,
		0x13D1B2EC07994605ULL,
		0xEFCDA14E23EB1904ULL,
		0xA19E8F851B27098AULL,
		0x19DD354B4EC657FBULL,
		0xE42A67AD759F10BEULL,
		0xA91702C3E38FB69AULL,
		0x8A07B5B68D719DA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55B95863A56C923EULL,
		0xBFEEBD11D072B8D0ULL,
		0xB04C8DA8251EB028ULL,
		0x882A091A79846D9FULL,
		0xF8CAC0D76DA401E5ULL,
		0xBED87BD044F9AD95ULL,
		0x15249BFABC00D9E9ULL,
		0x12D7A910CDF5A17CULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2990D712C5245B71ULL,
		0x79E12E626EEC8A64ULL,
		0xE41F06343816BE68ULL,
		0x319676AEBAF70BF6ULL,
		0xFEF3E66E01F1A094ULL,
		0x43425A68819B53F3ULL,
		0x8BAFEF47EAD4DAC4ULL,
		0x8084184CA1AC3ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB00CF03DD9BD5685ULL,
		0x30106B25EA812063ULL,
		0x32F8517C7C9FC9F5ULL,
		0x1D7553CF10AE9DF9ULL,
		0xF176B61A8956D44CULL,
		0xF7091B82E35F7B8EULL,
		0x961FA4FD7BF26B30ULL,
		0x1DA21EA183EF2566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x999C272F1C990DF4ULL,
		0x49F14547846DAA07ULL,
		0xD6E757484489779DULL,
		0x2CE32561AA59960FULL,
		0x0F85507488A774D8ULL,
		0xB44B41EA62C4287DULL,
		0x1DB04BBA9126B1F4ULL,
		0x9D2606ED22431BB7ULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67802C1B5E7FB35BULL,
		0x886E0DCC322E7BCBULL,
		0x0695F373F64EAEAAULL,
		0xBD026442FFF11956ULL,
		0x046657B14AB05653ULL,
		0x78DABA5ADE0987A3ULL,
		0xC598A6111BE70B3CULL,
		0x663D91AC251C4207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8AEF82440ED2483ULL,
		0xBA866F0642514761ULL,
		0x8A89E4106466F4C2ULL,
		0x1E804C21F5B2C175ULL,
		0x1D6D7E7C6CB33B60ULL,
		0xFD3DFDFF65B30475ULL,
		0x99AD9320E6ACC162ULL,
		0xB487EB7967F60F2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF2ED43F1E9297D8ULL,
		0x32E862CA707F3CAAULL,
		0x8C1C176392285A68ULL,
		0xA38228630A43D823ULL,
		0x190B29CD26036D33ULL,
		0x85E747A5BBBA83D6ULL,
		0x5C353531FD4BCA5EULL,
		0xD2BA7AD542EA4D2DULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB1F1CF5113D1D45ULL,
		0xF962A403CBF91F8AULL,
		0xF86ADDCCD55F9ACDULL,
		0x532F9FF6191E98DFULL,
		0x8298853CB0766F4CULL,
		0xEEECBE12778F4119ULL,
		0x7EEC539FFCA591DEULL,
		0xE30F9F2C95927D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2076121973A3E5ULL,
		0x758B5B53474C70D5ULL,
		0xD357B728BFE287EEULL,
		0x83DB5FF9E0D1069FULL,
		0x972C886097E254A8ULL,
		0x8C99B18BCFE4BCEBULL,
		0x0E0B8B83B5E3514AULL,
		0x7FCA359A6BD4C478ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC13F6AE7084EBEA0ULL,
		0x8CE9FF508CB56F5FULL,
		0x2B3D6AE46ABD1D23ULL,
		0xD0F4C00FF9CF9E40ULL,
		0x15B40D5C27943BE4ULL,
		0x62750F99B86BFDF2ULL,
		0x70E7D81C4946C094ULL,
		0x9CC5AAB6FE46B9FDULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59F551953A99D7F7ULL,
		0xD27FB99F346B27BFULL,
		0x415299FA2E177056ULL,
		0xDC84EC6A2843683AULL,
		0x543E2FFDCB544517ULL,
		0x962A633FDFEE2F1AULL,
		0x333BD3525BDB1F2BULL,
		0xF36F6D27B0C68C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE05B204C6DBEE4BULL,
		0x06E41352387801A5ULL,
		0x729BCABDE7242B74ULL,
		0x65309EEF6AFA7FB6ULL,
		0xBADE85F5267D2177ULL,
		0xE50F0793F27BE170ULL,
		0x20D3453DBAADC189ULL,
		0xBC537D4D8B3906ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7F0E391FC4239BCULL,
		0xD49BAACD0C13261AULL,
		0x33C95347C9335B22ULL,
		0xB9B4728542B9178CULL,
		0xEEE0AA08ED296460ULL,
		0x732564AC2D95CE6AULL,
		0x13E8966FE176DEA2ULL,
		0x4F3C106A3BFF8A25ULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x847A7FA39B12A089ULL,
		0x301CF192D8249E28ULL,
		0x16DBDACFE2E9BFF6ULL,
		0x9E447D52A1064B14ULL,
		0x124945E21ADF88E0ULL,
		0xDAD7A88813A3CF2CULL,
		0x0AB0975AB29F552CULL,
		0x9A19D34B9DBD346AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2549AE329A9A5E9ULL,
		0xFCA54E91707C52A9ULL,
		0x980D090997680B22ULL,
		0xAD462F6368A1AF3AULL,
		0x0D6CB6D254E8B1AEULL,
		0xD8CDBD98E13897C1ULL,
		0xBEFE69FEAC53B642ULL,
		0x46CD20AB497D7C33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x362EE540B2BB0560ULL,
		0xCCB9BF03A858CC81ULL,
		0x8ED6D3C67581B4D4ULL,
		0x33025231C9A7E42EULL,
		0x1F25F3304E37394EULL,
		0x021A1510F29B58EDULL,
		0xB44EFEA41ECCE36EULL,
		0xDCD4F3E0D4C04859ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x776591035F7B702EULL,
		0xA95493FB73C70087ULL,
		0x6CCA7B96A68E7C3EULL,
		0x9A9E10D8F6EDE68AULL,
		0xC7F965F0FF02A123ULL,
		0x6A3E78AD593EDA70ULL,
		0x8A7C62D43680A581ULL,
		0xCFAFE9306196D4FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C026DD211DB252ULL,
		0x669EF38DD78402BFULL,
		0xA5017AD0DD1235F4ULL,
		0x24986F2A3FF179FBULL,
		0xDDB552E02F6D8CB1ULL,
		0xEC3310140FBF1FA8ULL,
		0x2EC67FA875341788ULL,
		0x372C0A624DBC6223ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72A5B7DE7E66C27CULL,
		0xCFCA6076A4430238ULL,
		0xC9CB01467B9C49CAULL,
		0xBE067FF2C91C9F71ULL,
		0x1A4C3710D06F2D92ULL,
		0x860D68B95681C5D8ULL,
		0xA4BA1D7C43B4B209ULL,
		0xF883E3522C2AB6DFULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x348246D3DE855192ULL,
		0x0243D9B791587B83ULL,
		0x48979893402DCD24ULL,
		0x451C3BBBAA2D4B05ULL,
		0x917AC69801A2A134ULL,
		0xDF8B458A68DF1322ULL,
		0xB040A3BD29C98C38ULL,
		0xED7B9BF96717DC9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2332EB39EDEF4EB3ULL,
		0x403A9ED43A556546ULL,
		0x36114204FCA43B96ULL,
		0x3D52B9B97D492406ULL,
		0x8D28EE1D795F5198ULL,
		0x1F8083BA209C230DULL,
		0x71A821E3C0D11326ULL,
		0x7A3C329A5AAF5CFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17B0ADEA336A1F21ULL,
		0x42794763AB0D1EC5ULL,
		0x7E86DA97BC89F6B2ULL,
		0x784E8202D7646F03ULL,
		0x1C52288578FDF0ACULL,
		0xC00BC6304843302FULL,
		0xC1E8825EE9189F1EULL,
		0x9747A9633DB88063ULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x932E6C2CD55FE932ULL,
		0x45643F1D9211B0C8ULL,
		0x9A1FC90BEC60A372ULL,
		0x0540C3235ACCEB37ULL,
		0xAF9D98430EA599E1ULL,
		0xCA09804D03E48CCAULL,
		0xE917A0F33262669AULL,
		0x153AD326402E58DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x287A9A38541CA787ULL,
		0x842F051781F6BD28ULL,
		0xF9A7F69A6A5D38E6ULL,
		0x4A3C13D67959358BULL,
		0xDF58E12C2306A4CCULL,
		0x934B5F5598658A2DULL,
		0x206CD3DC8060A25EULL,
		0x955838EB8538A146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB54F61481434EB5ULL,
		0xC14B3A0A13E70DE0ULL,
		0x63B83F91863D9B94ULL,
		0x4F7CD0F52395DEBCULL,
		0x70C5796F2DA33D2DULL,
		0x5942DF189B8106E7ULL,
		0xC97B732FB202C4C4ULL,
		0x8062EBCDC516F99BULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF3FD416A3161D93ULL,
		0x4AE904A6AC193DB4ULL,
		0x2DCAF811D32AD05CULL,
		0xB5287148F4371AEDULL,
		0x8C6FD3BCA6B1A292ULL,
		0x0750A9DEC460FD07ULL,
		0xE6EE525C46388951ULL,
		0x634D016D68714619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E4DBA559D650F6ULL,
		0x6730B3E2C044A0E1ULL,
		0x1625A9839806A241ULL,
		0xF320EF905F83F8EFULL,
		0xBC43BE9D7B6BDAB8ULL,
		0x7FACD64DF6E576AAULL,
		0xCEB62B6E72776BEFULL,
		0x995C355B79E599C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07DB0FB3FAC04D65ULL,
		0x2DD9B7446C5D9D55ULL,
		0x3BEF51924B2C721DULL,
		0x46089ED8ABB4E202ULL,
		0x302C6D21DDDA782AULL,
		0x78FC7F9332858BADULL,
		0x28587932344FE2BEULL,
		0xFA1134361194DFDEULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFD34C892079DFFEULL,
		0x3079693059B3CF05ULL,
		0x43143A9374B5D11FULL,
		0xF399725A073F30E4ULL,
		0xD35361AF280872DBULL,
		0x07E94584EA86A265ULL,
		0x94B989B53E3DD5BBULL,
		0xA06C8CE013B92F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD923886D34B7FC7AULL,
		0x2B25D25547BF6294ULL,
		0x2EC2056A42F46636ULL,
		0x8719D511B139C894ULL,
		0x1276E9FCBBE3F5C1ULL,
		0xC4E38D9833C7EA89ULL,
		0xB57EBFED5C7ABE82ULL,
		0xC7D61FADCAF27407ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36F0C4E414CE2384ULL,
		0x1B5CBB651E0CAD91ULL,
		0x6DD63FF93641B729ULL,
		0x7480A74BB606F870ULL,
		0xC125885393EB871AULL,
		0xC30AC81CD94148ECULL,
		0x21C7365862476B39ULL,
		0x67BA934DD94B5B7EULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78D9DFA62345F012ULL,
		0xC2BF6FBEFAAF7351ULL,
		0x361CC11642C97D21ULL,
		0xD286AC1D347DAA82ULL,
		0x20AE555FBFC09BE2ULL,
		0x51D4A2E1A3311507ULL,
		0x3D9B1E323DD8CB4EULL,
		0x07A3381CBC7B02D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16F8A908E175623ULL,
		0x9A13F3CAA7E62C3EULL,
		0x64DB76143C854C06ULL,
		0xA56F8EF62177DD96ULL,
		0x5CE97F27722F7347ULL,
		0x775B1E2BAE7AD2DAULL,
		0xB41D055D7EDBEF49ULL,
		0x8153CA00136AFFE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9B65536AD52A631ULL,
		0x58AC9C745D495F6FULL,
		0x52C7B7027E4C3127ULL,
		0x77E922EB150A7714ULL,
		0x7C472A78CDEFE8A5ULL,
		0x268FBCCA0D4BC7DDULL,
		0x89861B6F43032407ULL,
		0x86F0F21CAF11FD34ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66BB3AF8C35B393FULL,
		0x083F40DABF72A69EULL,
		0x1A2F0C47430A5012ULL,
		0x2DB57247034A08FDULL,
		0xC2C0D2CC7229B8B5ULL,
		0x2AF92965FD26869FULL,
		0x663D577A36F2F8B6ULL,
		0xC09613B8DBC9ED77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F9E9DFE913ABBCULL,
		0x1BB3725922F88C2EULL,
		0x5B9AAE249844973FULL,
		0x2F6287A3A3AEF09EULL,
		0x54C5CC9E22656BC4ULL,
		0xE255A66F35DE29F6ULL,
		0x843E92CC1D6C620BULL,
		0xE7A0AE91DEC00F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7042D3272A489283ULL,
		0x138C32839D8A2AB0ULL,
		0x41B5A263DB4EC72DULL,
		0x02D7F5E4A0E4F863ULL,
		0x96051E52504CD371ULL,
		0xC8AC8F0AC8F8AF69ULL,
		0xE203C5B62B9E9ABDULL,
		0x2736BD290509E209ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9056EA8797C39F33ULL,
		0xD5D534B496DF36FCULL,
		0x410C765AB6A620EAULL,
		0x2AC670B71625C680ULL,
		0x7E2715552CB1C43BULL,
		0x39FB1E24D357D178ULL,
		0xAB74FE86C239ACF7ULL,
		0xA48E82108D392EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D77802ADE36D20ULL,
		0xD70E1B71B5B17128ULL,
		0xEAD093CEF39632D2ULL,
		0x76EE0E24E9277824ULL,
		0x9B34F9FD609A41BEULL,
		0xDC49EB5088315982ULL,
		0x63036E3C3DE7444AULL,
		0xE2DD33E388FFA9C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x218192853A20F213ULL,
		0x02DB2FC5236E47D4ULL,
		0xABDCE59445301238ULL,
		0x5C287E93FF02BEA4ULL,
		0xE513ECA84C2B8585ULL,
		0xE5B2F5745B6688FAULL,
		0xC87790BAFFDEE8BDULL,
		0x4653B1F305C6872AULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39A46095A3F5F1DDULL,
		0x4930CF63213B2E40ULL,
		0x08FF0B3D036504CAULL,
		0xD451B8C4A658CB52ULL,
		0xC329004D603A2D78ULL,
		0xCEF107F86DE4E820ULL,
		0x2A37433DDEFA6A78ULL,
		0x6FC41B9CBE2DE9DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5881927D7C190CA8ULL,
		0x6B67694CD4E7BA16ULL,
		0x6EDC9C084739BC2DULL,
		0xAFC5026406400869ULL,
		0x79D0BBC7203DD12FULL,
		0xBFF39907B30318ACULL,
		0x02022E6FBF422452ULL,
		0xB46C0A7826823797ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6125F2E8DFECFD75ULL,
		0x2257A62FF5DC9456ULL,
		0x66239735445CB8E7ULL,
		0x7B94BAA0A018C33BULL,
		0xBAF9BB8A4007FC57ULL,
		0x71029EFFDEE7F08CULL,
		0x28356D5261B84E2AULL,
		0xDBA811E498AFDE4CULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F0F173DD16D04BEULL,
		0xD500D09F8A8F0D24ULL,
		0x6B5BF8FAC9FD61DDULL,
		0xB817895B3CD2818BULL,
		0x9A445E5131335157ULL,
		0x5B859A01F264E00FULL,
		0xC630D00F7ED71E49ULL,
		0x79D0C4C2B1F23238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB803F3436BF2C6ULL,
		0xF073A1D9739F9CC6ULL,
		0x5EC088897DDA973BULL,
		0x7350A49953A24C06ULL,
		0xD048A7B60FB182E5ULL,
		0x4941D5D19A579EDAULL,
		0x608218DAC43949EFULL,
		0x3C736142662C982AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04B714CE9206F678ULL,
		0x25737146F91091E2ULL,
		0x359B7073B427F6E6ULL,
		0xCB472DC26F70CD8DULL,
		0x4A0CF9E73E82D3B2ULL,
		0x12C44FD068337ED5ULL,
		0xA6B2C8D5BAEE57A6ULL,
		0x45A3A580D7DEAA12ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50A5BA9814EA8103ULL,
		0x6FADDCDB8DB74C93ULL,
		0x9EFDE6D044147105ULL,
		0xBD8464E8ECBD58C8ULL,
		0x90F8CE0D703FAFC8ULL,
		0xA2CD92AF3B62A251ULL,
		0xFA07DD28D56945E0ULL,
		0xD0A85C71B7CA3E2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x116D5681DA530572ULL,
		0x523C8AF38C53D7FCULL,
		0x68F0490001255EAEULL,
		0x0220940AD3FC3C37ULL,
		0xECB1BE76A8960EF8ULL,
		0xB4DAA41CE8BA614FULL,
		0x2F138E725E420F25ULL,
		0x8FDD8388BA16F37AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C8EC19CEB98471ULL,
		0x3D91562801E49B6FULL,
		0xF60DAFD045312FABULL,
		0xBFA4F0E23F4164FFULL,
		0x7C49707BD8A9A130ULL,
		0x161736B3D3D8C31EULL,
		0xD514535A8B2B4AC5ULL,
		0x5F75DFF90DDCCD55ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBF326DAE211C230ULL,
		0x764363D97E638F5CULL,
		0x64F7C28417C90E39ULL,
		0x9D589A19F2ED5D8DULL,
		0x60E305988CD37EDBULL,
		0x4FE5305F41A9536AULL,
		0x5C4A02A3E41CEF6BULL,
		0x1A47D29F516FC43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9514D9A4C77A2EACULL,
		0x8385F81FE34576A3ULL,
		0x4933D60246E2E73DULL,
		0xA05CFCB47D600A2DULL,
		0xA8DCB39A12776D90ULL,
		0xE5EB03B44612937AULL,
		0xECF64EA48F9BC3E5ULL,
		0xAC2BECA9C86A027BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EE7FF7E256BEC9CULL,
		0xF5C69BC69D26F9FFULL,
		0x2DC41486512BE904ULL,
		0x3D0466AD8F8D57A0ULL,
		0xC83FB6029EA4134BULL,
		0xAA0E33EB07BBC010ULL,
		0xB0BC4C076B872C8EULL,
		0xB66C3E369905C644ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F2C40526174A828ULL,
		0x766CAC274F52C12CULL,
		0x7FBB839109EB5634ULL,
		0x28B8F646D128F3A9ULL,
		0xCB750CD74AADE2AFULL,
		0x48F1B332FD4E4EE4ULL,
		0xFC0AB3E4A93694E2ULL,
		0x360E9B7961C12DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68565DEBB9B3C1B0ULL,
		0xA2AF8158391BCABCULL,
		0xE74DDEEA8F9D3AC4ULL,
		0x4DAA347DAAD04D5AULL,
		0x2FBA564DB8A713B7ULL,
		0xA2803D81A5785677ULL,
		0xB2B479C33659DADFULL,
		0x8BCCC7BC29E0D0C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x677A1DB9D8C76998ULL,
		0xD4C32D7F76490B90ULL,
		0x98F65D7B86766CF0ULL,
		0x6512C23B7BF8BEF3ULL,
		0xE4CF5A9AF20AF118ULL,
		0xEA718EB358361893ULL,
		0x4EBECA279F6F4E3DULL,
		0xBDC25CC54821FD18ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31CDE84C9D048E4BULL,
		0x1DBCE4ED585A9D7CULL,
		0x39376507EBAF2EDDULL,
		0x499EA66F1B1211F3ULL,
		0x0C56A2DC54D3CA22ULL,
		0x95A887552137A4EBULL,
		0xF038276654330C8CULL,
		0xED9F34554CE49A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE40A90B5D0E1D81ULL,
		0x606759E97BEA46D7ULL,
		0xA789CB25E8EDDF10ULL,
		0x288970A6D33F3A83ULL,
		0xF266359CFE10E0A3ULL,
		0x4304EBD40BB99BB5ULL,
		0xBE64D5EE3AF6F401ULL,
		0x9C1B49D55DDC650DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F8D4147C00A93CAULL,
		0x7DDBBD0423B0DBABULL,
		0x9EBEAE220342F1CDULL,
		0x6117D6C9C82D2B70ULL,
		0xFE309740AAC32A81ULL,
		0xD6AC6C812A8E3F5EULL,
		0x4E5CF2886EC5F88DULL,
		0x71847D801138FF66ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB574EEA2E3DA08C4ULL,
		0x2FCB444E09F39F40ULL,
		0x3796E9CFE6BF3723ULL,
		0xE38AD24D0E55FC6CULL,
		0xAFD3EF180B706512ULL,
		0xD6C801D925BF80B3ULL,
		0x2D27D9527257A38AULL,
		0x432260E4E59A5A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A95DF663A543CBCULL,
		0x4BC6E0967BADFC1CULL,
		0x5C1AA927EF069CEFULL,
		0xF07EDA5CF2A8EAF4ULL,
		0xC75F8F3056F0F1E6ULL,
		0x90DC31D7B976E1D7ULL,
		0xB204A59BBB607E3EULL,
		0xAFCE3D7C1D18FE72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE131C4D98E3478ULL,
		0x640DA4D8725E635CULL,
		0x6B8C40E809B9ABCCULL,
		0x13F40811FCFD1698ULL,
		0x688C60285D8094F4ULL,
		0x4614300E9CC96164ULL,
		0x9F237CC9C937DDB4ULL,
		0xECEC5D98F882A45CULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C42E406D4EDF511ULL,
		0x68E9C9BAFA4ABB5FULL,
		0x97B23B8BA325CD1DULL,
		0x0F625887D2E6675FULL,
		0xBF7318F4D2289C22ULL,
		0x6A626408E9D53485ULL,
		0xB221CD16E6C2950AULL,
		0xB6549331C01D8DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52AAB95A6E9B142BULL,
		0x77822B92CB1C7081ULL,
		0xE06F0CE1A411B4FBULL,
		0xEB1CA89B3AA3CD75ULL,
		0x19EB2A9A3C478BFAULL,
		0x456D1FD9F89689CFULL,
		0x65088DC789FE64FEULL,
		0x1308B91C4C97490FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEE85D5CBA76E13AULL,
		0x1F6BE2283156CBDEULL,
		0x77DD376A073479E6ULL,
		0xE47EF01CE845AA2AULL,
		0xA698326EEE6F17D8ULL,
		0x2F0F7BD11143BD4AULL,
		0xD72940D16F3CF1F4ULL,
		0xA55C2A2D8C8AC4A1ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03001D04342BBC6BULL,
		0x908036E84EDE5DC7ULL,
		0xE8F84FF5929832C8ULL,
		0xFE2DED0FC5E5646FULL,
		0x2E9D6FD43531EF7AULL,
		0x79E0FA0E7B12A18BULL,
		0x72E50BCDC87D35F3ULL,
		0xE99C22D71B727D10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2709DC3CD7EE9AA8ULL,
		0xFA85BAB923007ED2ULL,
		0x688EF14E234815A4ULL,
		0x8E65FE3C7E532A8FULL,
		0xE583F373D8474A2CULL,
		0xDF33A937DEB1503CULL,
		0xA3BB71D86F25A77FULL,
		0x5F9324D048075FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2409C138E3C526C3ULL,
		0x6A058C516DDE2315ULL,
		0x8076BEBBB1D0276CULL,
		0x70481333BBB64EE0ULL,
		0xCB1E9CA7ED76A556ULL,
		0xA6D35339A5A3F1B7ULL,
		0xD15E7A15A758928CULL,
		0xB60F0607537522A7ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x904401FAD661FEE6ULL,
		0x90F4F18FAEA51FE6ULL,
		0x75BDE5046B1CFD81ULL,
		0x95E6FC98BC14E33BULL,
		0xFD215FA612BE0E9CULL,
		0x2510081A28C181AFULL,
		0x9993E4EBD44F3B60ULL,
		0x7303F492C9A28540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA45CA6D868DD226AULL,
		0x13310B4A0F3DED14ULL,
		0xE93DA27BA98080A4ULL,
		0x13EF117D031483DCULL,
		0xF6A1215092195643ULL,
		0x6DDCEE044B88A87AULL,
		0xC6CAE38693A32B7CULL,
		0x41B8BA6575C041A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3418A722BEBCDC8CULL,
		0x83C5FAC5A198F2F2ULL,
		0x9C80477FC29C7D25ULL,
		0x8609EDE5BF0060E7ULL,
		0x0B807EF680A758DFULL,
		0x48CCE61E634929D5ULL,
		0x5F59076D47EC101CULL,
		0x32BB4EF7BC62C4E4ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x404C86F1D685E0DCULL,
		0x83AEDE41BE584B15ULL,
		0x5E11208DDBC53853ULL,
		0x3B527C22B69358FCULL,
		0x0F8C20EB0B72DC44ULL,
		0x5368236DF969287DULL,
		0xFAF20204AA972488ULL,
		0x1ABB77EDDC4089DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774FB1E78EC8141DULL,
		0xB7B0757196C11F7DULL,
		0x7EDCC06688409844ULL,
		0xEDEDEA5C52DDF1E8ULL,
		0xDD32B6DB549CF898ULL,
		0xDC5577546417FAB1ULL,
		0x174ABAA7AD4650CEULL,
		0xDE9295EF49FE8317ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37033716584DF4C1ULL,
		0x341EAB3028995468ULL,
		0x20CDE0EB5385A017ULL,
		0xD6BF967EE44EA914ULL,
		0xD2BE96305FEE24DCULL,
		0x8F3D54399D7ED2CCULL,
		0xEDB8B8A307D17446ULL,
		0xC429E20295BE0ACDULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CACF8D8DC26D162ULL,
		0x96616BD802C2C686ULL,
		0xD36E782A56F75468ULL,
		0x6B8239E4CB9C588BULL,
		0x61601CF56F924856ULL,
		0xE16B537565946818ULL,
		0xD8E3E9B95B823B8AULL,
		0x342F7C5C6B04B20AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E5A7A37279B7DCULL,
		0xC841B24275606BBCULL,
		0x1CD4975E06925F08ULL,
		0xD349AF0911A25E2DULL,
		0x15A02959FB77A72AULL,
		0x2CDD4AF9216516DFULL,
		0x2CBAC342A4CC6475ULL,
		0xA8E0053B341E34C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A495F7BAE5F66BEULL,
		0x5E20D99A77A2AD3AULL,
		0xCFBAEF7450650B60ULL,
		0xB8CB96EDDA3E06A6ULL,
		0x74C035AC94E5EF7CULL,
		0xCDB6198C44F17EC7ULL,
		0xF4592AFBFF4E5FFFULL,
		0x9CCF79675F1A86C8ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE667AD0765E2C3C9ULL,
		0xD9AE67705BEE5B68ULL,
		0x8DEB32D3BDFED3C1ULL,
		0x7AE644F314E9D4BEULL,
		0x541EBDD33BDC963BULL,
		0x0CF51D406B9EAA2AULL,
		0xF3F8F9FED3B98B6BULL,
		0xDCA26438BA1EC72CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7FEC27FD10885CULL,
		0x4E739E09F3C263D8ULL,
		0xFE0A63A1DEDC5DF7ULL,
		0x8B91C26195D64CFBULL,
		0x2950309BFDFD9D5BULL,
		0x8F03FA0B10D4DF85ULL,
		0x7C41C56F8C452482ULL,
		0x38A13E7087E7D636ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9918412098F24B95ULL,
		0x97DDF979A82C38B0ULL,
		0x73E1517263228E36ULL,
		0xF1778692813F9845ULL,
		0x7D4E8D48C6210B60ULL,
		0x83F6E74B7B4A75AFULL,
		0x8FB93C915FFCAFE9ULL,
		0xE4035A483DF9111AULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB288BFF10B60D415ULL,
		0xC9ED0DD6A4D0340AULL,
		0xC4586480CF5E37E8ULL,
		0x25EBF1D14A7CCA5CULL,
		0x8DC654D44865E558ULL,
		0xEFC35C7EA72E95C9ULL,
		0x6AA0F69691BA6B4FULL,
		0x28CCB71767C11ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BBB08012DC3E56ULL,
		0x5006729D319B7A68ULL,
		0x50573C694C114001ULL,
		0xDDE1983B010AAFDCULL,
		0x59BB7FA0CE52E82EULL,
		0x461BC05DC03B1EEAULL,
		0x9186FA00A503777CULL,
		0x36E1F15781F946AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91330F7119BCEA43ULL,
		0x99EB7F4B954B4E62ULL,
		0x940F58E9834F77E9ULL,
		0xF80A69EA4B766580ULL,
		0xD47D2B7486370D76ULL,
		0xA9D89C2367158B23ULL,
		0xFB260C9634B91C33ULL,
		0x1E2D4640E638587BULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BC301670A471F51ULL,
		0x36DF60E5655498D4ULL,
		0x26C94CD192D0CA52ULL,
		0xBF15BD571B7474F8ULL,
		0xC2FBB842E55A70CCULL,
		0xB0E6017BBB348991ULL,
		0xE86974EE531E1FCCULL,
		0x928CC73240E12D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCF2E005712A5A78ULL,
		0xF55CB058FEB2DA4FULL,
		0x3C2073F7E6AF952AULL,
		0x2DB9CBC702D3CD0EULL,
		0xE4636C43471601E5ULL,
		0xBB8B26EF74D6DBECULL,
		0x713AF1AFDA6F7648ULL,
		0x0A72B2D5EB23005CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE731E1627B6D4529ULL,
		0xC383D0BD9BE6429BULL,
		0x1AE93F26747F5F78ULL,
		0x92AC769019A7B9F6ULL,
		0x2698D401A24C7129ULL,
		0x0B6D2794CFE2527DULL,
		0x9953854189716984ULL,
		0x98FE75E7ABC22D6AULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67A937B840EA4038ULL,
		0x7580FE21906C101BULL,
		0x59F4CE4ABBE730F1ULL,
		0xDD4A0EC450243B6DULL,
		0xE64E78852FC722F5ULL,
		0x1149D414A1B0F7BBULL,
		0x23B519FDA9BB87F5ULL,
		0x26419D8C3BD8774FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF01DCF82281D92AULL,
		0xC35DA05426663F77ULL,
		0xF0D06F3ABA5B2E8AULL,
		0x8FEDC3E8456E1F1DULL,
		0xD58B7D1BAEE316A8ULL,
		0x2DF94210FC538847ULL,
		0x509576F78D0EEE94ULL,
		0xBA04CA15B3D629FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A8EB40626B9912ULL,
		0xB6DD5E75B60A2F6CULL,
		0xA924A17001BC1E7BULL,
		0x52A7CD2C154A2470ULL,
		0x33C5059E8124345DULL,
		0x3CB096045DE37FFCULL,
		0x73206F0A24B56961ULL,
		0x9C455799880E5EB5ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE18365E20699AEC2ULL,
		0x53F4314F0F0EF9B9ULL,
		0x8DEA0491B74CEE9CULL,
		0xEAD48966152D3F52ULL,
		0xDBD4C0BE64BB3AFCULL,
		0xAE83C5140092FADCULL,
		0x62D369FF624A1DA5ULL,
		0x17B7E73FD17D362DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B137B91D1F3723BULL,
		0x34CFC767E4D21AAEULL,
		0x87918CF805DB39F8ULL,
		0x14932420EDE555A1ULL,
		0x9A79BEEBBB6A101DULL,
		0xB556E4C57218774AULL,
		0xCD90BA51C6E1F0EAULL,
		0x07D6087BDDBA23E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA901E73D76ADCF9ULL,
		0x673BF628EBDCE317ULL,
		0x0A7B8869B297D764ULL,
		0xFE47AD46F8C86AF3ULL,
		0x41AD7E55DFD12AE1ULL,
		0x1BD521D1728A8D96ULL,
		0xAF43D3AEA4ABED4FULL,
		0x1061EF440CC715CAULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF54DE7ED23BF177EULL,
		0xC519F92137401CFCULL,
		0x6AA411465FFB7E0DULL,
		0x8179E81AC70F80B6ULL,
		0x041D59FD46FD62B1ULL,
		0x5F55F9BB51CD6F72ULL,
		0xD86A11A1EE534D78ULL,
		0xE798EB7F5476C280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE13956F2962F2CBULL,
		0x597EE0D11319C1AFULL,
		0xF928FC19A1EB3028ULL,
		0x80BEB0ED66AF606AULL,
		0x1899CA12A01E4EA1ULL,
		0x1E820553E76AF899ULL,
		0x78E0510E9E8CC947ULL,
		0x98CC3C1982BB3461ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B5E72820ADDE5B5ULL,
		0x9C6719F02459DD53ULL,
		0x938CED5FFE104E25ULL,
		0x01C758F7A1A0E0DCULL,
		0x1C8493EFE6E32C10ULL,
		0x41D7FCE8B6A797EBULL,
		0xA08A40AF70DF843FULL,
		0x7F54D766D6CDF6E1ULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C9EF007A3838CACULL,
		0x92FA068B9DF6322CULL,
		0x8FB2B4A060BB9B3CULL,
		0x21C08D4BE3B1D918ULL,
		0x244CA4364857FBF3ULL,
		0x7EAFFFF8EF613E68ULL,
		0xF210B55792B72921ULL,
		0x53A9F4210710885EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB346827C995627ULL,
		0x85F0FC5F8D7A57E0ULL,
		0x70C53E5840F87421ULL,
		0x23ADD40C53F1A82DULL,
		0xBC0F1B99BC780F1BULL,
		0xD2555F1EAAE7F886ULL,
		0xAC4D2F4E087E70C3ULL,
		0x473E3EEC946C5D8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402DB685DF1ADA8BULL,
		0x170AFAD4108C65CCULL,
		0xFF778AF82043EF1DULL,
		0x026D5947B0407135ULL,
		0x9843BFAFF42FF4E8ULL,
		0xACFAA0E64586C6EEULL,
		0x5E5D9A199AC959E2ULL,
		0x1497CACD937CD5D2ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF4A607CBB947172ULL,
		0x5CF6E7571D9913BCULL,
		0x8B6322742761957BULL,
		0x6F15AFB7BAA3E6F5ULL,
		0xBE92226708D0E54CULL,
		0x3F7E8B039DB08387ULL,
		0xBEA1F253D8ADCDC8ULL,
		0x2279138B0194CEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x214A737EAA05E5FFULL,
		0xAFF63A2C88517653ULL,
		0xF6EF22F189C21589ULL,
		0x4A0C3FF835D2E740ULL,
		0x830844A087F7E45DULL,
		0x55F43D73847F9FF1ULL,
		0x52FE38271CE5F52EULL,
		0xBFA71D64E2F8D803ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE0013021191948DULL,
		0xF300DD7B95C865EFULL,
		0x7D8C0085AEA380F2ULL,
		0x2519904F8F7101B5ULL,
		0x3D9A66C78F270111ULL,
		0x6A8AB67019CF1C76ULL,
		0xEC5FCA74C44838E6ULL,
		0x9DDE0EEFE36C16B1ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0F8A4EFA1ABD032ULL,
		0xE729B47F4A380B15ULL,
		0x0BD64777DD347F48ULL,
		0x53ED611DB420C32FULL,
		0x56744E68EA6BA45CULL,
		0xCCA974634349FA8DULL,
		0xFBB0B03560B3B477ULL,
		0x80B23B7604A50DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2F23CD702D05775ULL,
		0x054AFAE26111824FULL,
		0xEB35065C21309D7DULL,
		0x644E805BEEE0DB0BULL,
		0x12E035A471C8ED27ULL,
		0x19842025AE317ABFULL,
		0x0341301692FB7D71ULL,
		0xF39C439C53235081ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x420A9838A37B8747ULL,
		0xE2634E9D2B29895AULL,
		0xE0E3412BFC04E235ULL,
		0x37A3E1465AC01824ULL,
		0x44947BCC9BA3497BULL,
		0xD52D5446ED788032ULL,
		0xF8F18023F248C906ULL,
		0x732E78EA57865D57ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07195A0BC245873EULL,
		0xD48688CEA1534B19ULL,
		0x8066B46FFC02DE02ULL,
		0x8AAFB9C0A7D3FC89ULL,
		0x7F3B5545ACF44E8CULL,
		0x3AE3365B913AC015ULL,
		0x792AB18695D1443CULL,
		0x4AD777E26C0094EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D5DF84A6AA690FULL,
		0x0E3075BED6667990ULL,
		0x699D17B7DBE560B7ULL,
		0xEB711E7E303331CEULL,
		0x97E8BE44C5A5C106ULL,
		0x34C689CC67F0015BULL,
		0x3E0940BCF3F0D033ULL,
		0x53BFB44FC3913804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4CC858F64EFEE31ULL,
		0xDAB6FD7077353289ULL,
		0xE9FBA3D827E7BEB5ULL,
		0x61DEA7BE97E0CD47ULL,
		0xE8D3EB0169518F8AULL,
		0x0E25BF97F6CAC14EULL,
		0x4723F13A6621940FULL,
		0x1968C3ADAF91ACE9ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF882C6C063E868F6ULL,
		0xF29C0F5F14D4320BULL,
		0xCC37E6200A539D11ULL,
		0x3909176498577ADCULL,
		0xDFF34D68C0C07E2AULL,
		0x874109CE37CD3870ULL,
		0x69F323DD7B8525E5ULL,
		0xD7BC482E04D23C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E78A345A8126DCEULL,
		0x8307246E617DD66EULL,
		0xCEDA2D0A4AEC5C1FULL,
		0x04C9F619431D7A6AULL,
		0x13A2EB2E5B847676ULL,
		0x86D46E93836E389BULL,
		0x21CA9B5A619DC3CFULL,
		0x577D8B3198B4518DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76FA6585CBFA0538ULL,
		0x719B2B3175A9E465ULL,
		0x02EDCB2A40BFC10EULL,
		0x3DC0E17DDB4A00B6ULL,
		0xCC51A6469B44085CULL,
		0x0195675DB4A300EBULL,
		0x4839B8871A18E62AULL,
		0x80C1C31F9C666D00ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE228D3E2092D98FULL,
		0xC5EE3154F481084BULL,
		0x0FAB8E6A58E3B81DULL,
		0xE96BF99A2E1599EFULL,
		0x516E87F47A8F3CDEULL,
		0xC70917982245C2ECULL,
		0xB23FF6072B84576FULL,
		0xC5CD513EDC4672B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED586C58C571259BULL,
		0xA648013B409CC72BULL,
		0x641E01AC283994A4ULL,
		0x79B4DFE10C367A24ULL,
		0x1028CA80F9610CC1ULL,
		0xC8A58F303715688FULL,
		0x144F690679AFF9EDULL,
		0x38B74D91CC125820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x237AE166E5E3FC14ULL,
		0x63A6306FB41DCF60ULL,
		0x6BB58FC670DA2CB9ULL,
		0x90DF267B2223E3CBULL,
		0x41464D7483EE301FULL,
		0x0FAC98A81550AA63ULL,
		0xA6709F01522BAE82ULL,
		0xFD7A1CAF10542A94ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x306413244156C71FULL,
		0x8223DB48DED86348ULL,
		0x91497F09ECCF7E51ULL,
		0xBA57BC29F18E5706ULL,
		0x812613A1241CB1B0ULL,
		0x70F9F4D40ABE7D72ULL,
		0x522B0E93A1160388ULL,
		0x7324AB69FCD2D23DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B1EA848AE9DADEULL,
		0x5D7868563C9919B7ULL,
		0xC6D247CFA9CDB0F4ULL,
		0x6A75A8C47519B1CCULL,
		0xECE7BD2BA5143EFBULL,
		0x79B5940BFB8007B4ULL,
		0xFB7EEFB5F01070CDULL,
		0x6AF9C1BBB41431A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0D5F9A0CBBF1DC1ULL,
		0xDF5BB31EE2417AFFULL,
		0x579B38C64502CEA5ULL,
		0xD02214ED8497E6CAULL,
		0x6DC1AE8A81088F4BULL,
		0x094C60DFF13E7AC6ULL,
		0xA955E12651067345ULL,
		0x19DD6AD248C6E39BULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC352F404561BCA74ULL,
		0x7B9D20FE1153C286ULL,
		0x45754763490B05C1ULL,
		0xAAD0AFF54B9DAC90ULL,
		0x48134B9DB88509E6ULL,
		0x743471FC3C6592E8ULL,
		0x7F4CEA9783861876ULL,
		0x4509DD1ECFCBA541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF54E3757EE605B3DULL,
		0x5C75F85AC874CD41ULL,
		0xFD4EE8519D880C59ULL,
		0xB4290B72C2714461ULL,
		0x7CB1121378ADE734ULL,
		0x46335E8F1B99F8F4ULL,
		0x2BB2B97784EF0D25ULL,
		0xC94C71DB6A554008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x361CC353B87B9149ULL,
		0x27E8D8A4D9270FC7ULL,
		0xB83BAF32D4830998ULL,
		0x1EF9A48789ECE8F1ULL,
		0x34A2598EC028EED2ULL,
		0x32072F7327FC6A1CULL,
		0x54FE53E007691553ULL,
		0x8C45ACC5A59EE549ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAEFBE97B0579A69ULL,
		0xA6F66C3DE734561DULL,
		0xBBB04499AAF50E43ULL,
		0xB5FA02392721BA43ULL,
		0x694D0002EE07FD9EULL,
		0x4901E4CBCC43F592ULL,
		0x949C651FBA61F61FULL,
		0x0C34C532D2E76FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAF33536CE23781ULL,
		0xA60DB45E22059A54ULL,
		0x58CB12062348450DULL,
		0x38C4459CFE17A372ULL,
		0x779199E1AA493305ULL,
		0xC6DF5B831804E57BULL,
		0xE1E4C54A0BCA2696ULL,
		0xE394D93D385A8503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47408DC4DCB5ADE8ULL,
		0x00FBD863C531CC49ULL,
		0xE37B569F89BD4B4EULL,
		0x8D3E47A5D9361931ULL,
		0x1EDC99E3444ECE9BULL,
		0x8FDEBF48D44710E9ULL,
		0x7578A055B1ABD089ULL,
		0xEFA01C0FEABDEAA8ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x982FF615C83D346FULL,
		0x7373A2F206A2349CULL,
		0xF8F4930894330F20ULL,
		0x73405B29D882E7BBULL,
		0x02241892B80610BAULL,
		0x47BB79610DBE0401ULL,
		0x4A4F881074F10DCBULL,
		0x6289C140337A60F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5C1C904103E17BULL,
		0x80D565436D55EC22ULL,
		0x98298643D9618D5FULL,
		0xE7D5505F85CAC7C9ULL,
		0xB59AE3B251A8734BULL,
		0x39C705D2A2540B2FULL,
		0xABBCE2732E08396DULL,
		0xF7659236397C0843ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3573EA85893ED514ULL,
		0xF3A6C7B16BF7D8BEULL,
		0x60DD154B4D52827FULL,
		0x94950B765D482072ULL,
		0xB7BEFB20E9AE63F1ULL,
		0x7E7C7CB3AFEA0F2EULL,
		0xE1F36A635AF934A6ULL,
		0x95EC53760A0668BBULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EF77C7D071F7337ULL,
		0x6EA6FF3D8CFA9A49ULL,
		0x23AE95EB02FD5784ULL,
		0xA5318E5923AF1296ULL,
		0x5C30C0F065494CEDULL,
		0x05399724C567ACC6ULL,
		0x11DE2B7725A677B0ULL,
		0x969EFCD0BBA7C290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x079CF0A42DFF3BCFULL,
		0x605D7A91B5E94E74ULL,
		0x238CFA3C8A69111EULL,
		0x90645B8EBC596D94ULL,
		0xC21C8D4A6EF34AD2ULL,
		0x4FC38D2F16B47420ULL,
		0x6E891091DAF04D85ULL,
		0xAE1EBB6FA4269814ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x196B8CD92AE048F8ULL,
		0x0EFB85AC3913D43DULL,
		0x00226FD78894469AULL,
		0x3555D5D79FF67F02ULL,
		0x9E2C4DBA0BBA063FULL,
		0x4AFA1A0BD3D3D8E6ULL,
		0x7F573BE6FF563A35ULL,
		0x388047BF1F815A84ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BC630F5036C59C2ULL,
		0xE6332DE2EF5C7D34ULL,
		0x49FDD5C4F6ACD118ULL,
		0x4366277E9A9AFE1DULL,
		0x278D2C66A9514D05ULL,
		0xFEAE937BAE8334FFULL,
		0xEA9DC10786B4EA6AULL,
		0x547D6CACADE776A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF11F5B586856BF1ULL,
		0x3D1532171DA92D7EULL,
		0x8FA0037534FFA369ULL,
		0x254CD9F24C4B1346ULL,
		0x2DF0C302271C46FFULL,
		0x495CDC963F877B98ULL,
		0xD183968C1AFA0E6DULL,
		0x330F503505D6537BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84D7C54085E93233ULL,
		0xDB261FF5F2F5504AULL,
		0xC65DD6B1C2537271ULL,
		0x662AFE8CD6D1ED5BULL,
		0x0A7DEF648E4D0BFAULL,
		0xB7F24FED91044F67ULL,
		0x3B1E578B9C4EE407ULL,
		0x67723C99A83125D9ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1FFCFF900CA4800ULL,
		0xF59DA4E6B60D4F2AULL,
		0x798AAC668B5AA7C8ULL,
		0xA76D69A814798462ULL,
		0x8F04F83857FF9D74ULL,
		0x51DB4E048E417030ULL,
		0x468D1E23D5EB5166ULL,
		0xADE8E8481327963FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6745E7A684A005D0ULL,
		0xAB281EEEC7EFE696ULL,
		0xCAD61CC61A596BA0ULL,
		0xC38B3E583B0076EBULL,
		0x7666F407E910FCB0ULL,
		0x8CFD8ADADB5DFE45ULL,
		0x6942EEF64FCB72F8ULL,
		0xF7F15F5B1FE8A2C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6BA285F846A4DD0ULL,
		0x5EB5BA0871E2A9BCULL,
		0xB35CB0A09103CC68ULL,
		0x64E657F02F79F289ULL,
		0xF9620C3FBEEF61C4ULL,
		0xDD26C4DE551C8E75ULL,
		0x2FCFF0D59A20239EULL,
		0x5A19B7130CCF34FEULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE68350F6B3C64220ULL,
		0x42B4C1B1FC6C7D47ULL,
		0xCD8A7BFE66767655ULL,
		0x3BBBDAB741C1729DULL,
		0x19D0169B568774A2ULL,
		0x1C29C89E5658564DULL,
		0xDE8DD095755F86C0ULL,
		0x00794ACB23444233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D3977465C5ECA7ULL,
		0xB346522317A82B4EULL,
		0xC6ECAEE89F73F8A9ULL,
		0x43A722416BD9585BULL,
		0xD457D0B9FC422801ULL,
		0xCB546EA08D8FF60DULL,
		0x35C2DD784DB462B6ULL,
		0x27B45AA8E378DF30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8750C782D603AE87ULL,
		0xF1F29392EBC45609ULL,
		0x0B66D516F9058EFCULL,
		0x781CF8F62A182AC6ULL,
		0xCD87C622AAC55CA3ULL,
		0xD77DA63EDBD7A040ULL,
		0xEB4F0DED38EBE476ULL,
		0x27CD1063C03C9D03ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2967716EF4456987ULL,
		0xBF67D50B2A4F521CULL,
		0xDCC471ED6B95D8E4ULL,
		0x50430EC8364CC288ULL,
		0xCB66583F93B67E74ULL,
		0xA75C1C507D1CF36AULL,
		0xF7D0DF6B06C35D9FULL,
		0xA3B0BF142D60EB85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE4EF5576E300DCULL,
		0x9B1269BE0ADC187DULL,
		0x75189EBBE5077C0EULL,
		0x1E9AA77D94523EC6ULL,
		0xE79BC6D3BC8B5FFBULL,
		0x45F2A7B3BE29DBB5ULL,
		0x1E6912582F01A829ULL,
		0x4BAB3BC42C7E538EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2839E3B82A6695BULL,
		0x2475BCB520934A61ULL,
		0xA9DCEF568E92A4EAULL,
		0x4ED9A9B5A21EFC4EULL,
		0x2CFD9EEC2F3D218FULL,
		0xE2AEBBE3C33528DFULL,
		0xE9B9CD3329C2F5B6ULL,
		0xE81B84D0011EB80BULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF49CBC8461BB2E3ULL,
		0xDAC99D45D575B5D2ULL,
		0x1B665B46974B38C0ULL,
		0x4185E08B87EB1652ULL,
		0xD68F285AB18E8371ULL,
		0xD4868469B92BBD20ULL,
		0x989A66CE7D2C526AULL,
		0xAB67D9F7C22221B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDA912D230753BBULL,
		0x085EB514B38D08F5ULL,
		0x62B69A2AD28BE6EBULL,
		0x5B9CCE3CD24C91CEULL,
		0x41A08A310DBE2B6CULL,
		0xA41C55D5107D0993ULL,
		0x423F2CF2A61DE2B1ULL,
		0x2183039D6685461DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0935AE5651CE158ULL,
		0xD297285166F8BD27ULL,
		0x79D0C16C45C0DE2BULL,
		0x1A192EB755A7879CULL,
		0x972FA26BBC30A81DULL,
		0x709AD1BCA956B4B3ULL,
		0xDAA54A3CDB31B0DBULL,
		0x8AE4DA6AA4A767A9ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5D3985065AC3ACDULL,
		0x9F7722F410D617E3ULL,
		0x499278443ED7295DULL,
		0xB23806B220BF5E15ULL,
		0x42E26346A7095A9AULL,
		0x725243CFA81EC8B8ULL,
		0xE1908740A5BCCA8DULL,
		0x6AC3F78F553215A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD3A45B8642EDF3ULL,
		0x8B7A5CE1D2FE39F4ULL,
		0x9DDB4BFABD5E8C02ULL,
		0x360963077B18F7B2ULL,
		0x06DA086FF0442C1AULL,
		0x872401ACDD9F7227ULL,
		0x078E52C54544130DULL,
		0x26976646415D01B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9003C0BE3EED73EULL,
		0x140D7E15C2282E17ULL,
		0xD44933BE8389A55FULL,
		0x843165B55BA7A9A7ULL,
		0x44386B29574D7680ULL,
		0xF57642637581BA9FULL,
		0xE61ED585E0F8D980ULL,
		0x4C5491C9146F1414ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ABE2E444A9DB4EEULL,
		0x71283EFDA91C9860ULL,
		0x7086B3F57F51D95AULL,
		0xAC02A6B3A4341950ULL,
		0x6D7AAE4A93E52185ULL,
		0x7186AFBC5B964CC7ULL,
		0xEC5DC5CFC981B53CULL,
		0x395E2B756DA10F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53414C5D06F5E0FCULL,
		0x583036DBD21893A8ULL,
		0xF069E658DA1659BAULL,
		0xB2572F314EE4A95FULL,
		0x7E961C5B4C0EAA39ULL,
		0x2D0B3577CEA29665ULL,
		0x9FD91E8B90BD5187ULL,
		0x3AC8E768F943B02FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79FF62194C685412ULL,
		0x291808267B040BC8ULL,
		0x80EF55ADA54780E0ULL,
		0x1E558982EAD0B00FULL,
		0x13ECB211DFEB8BBCULL,
		0x5C8D9ACB9534DAA2ULL,
		0x7384DB44593CE4BBULL,
		0x0396CC1D94E2BF2EULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39BBCA3E308FC4FAULL,
		0xB7ED1C6CB8C64EF3ULL,
		0xF4172DC32CB673EEULL,
		0xAAF2C8AC80FBE5D2ULL,
		0xC5B5AD30A761CA50ULL,
		0xDACA308311D4E653ULL,
		0xD1FE2124A07A2441ULL,
		0xDF52E2D2E2212456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D9C772FFE3D1CEULL,
		0xDA8E94CAAB928EA4ULL,
		0x210C52E40FBF50E0ULL,
		0x8547A249B292E4D4ULL,
		0xB230245180C89052ULL,
		0x4194DD2B89951C73ULL,
		0x1BBE895190BE6605ULL,
		0xD39D44BDB9848DACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00620D4CCF6C1534ULL,
		0x6D6388A61354C057ULL,
		0xD51B7F272309230EULL,
		0x2FB56AE532690106ULL,
		0x7785896127A95A02ULL,
		0x9B5EEDA89841FA20ULL,
		0xCA40A87530C44244ULL,
		0x0CCFA66F5BA5A9FAULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FED3E4846D7ABA5ULL,
		0xCBF9E265877927EFULL,
		0x5F7F4C9F0F9078C2ULL,
		0xE82B708E92851088ULL,
		0x09249354DC66BB4EULL,
		0xD8BAF0D7F0C061FAULL,
		0xD6FDFDB8D22B8568ULL,
		0x818B87584AFF4D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2040E40E337230CCULL,
		0x5011B5F57E00E0E8ULL,
		0x28A585F70B3DE61EULL,
		0xF62E08870AB418D4ULL,
		0x28849CD25A5CD27FULL,
		0x91F8054C17AF1AF1ULL,
		0x2A83E27F0EB72F53ULL,
		0x068DA469227941DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFADDA4675A59B69ULL,
		0x9BE85790F979C707ULL,
		0x77DAC96804AD9EDCULL,
		0x1E0578099831085CULL,
		0x21A00F86863A6931ULL,
		0x4942F59BE76F7B0BULL,
		0xFC7E1FC7DC9CAA3BULL,
		0x8706233168860C86ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B082C89C6DC7A3ULL,
		0x9EFF5EA1AEFC9A00ULL,
		0x949AAD52CCF1F31EULL,
		0xA65B771C67AEEA0DULL,
		0xD25792A773EE3FE3ULL,
		0x00156D68ABEB0BA6ULL,
		0x82195AD617E3A279ULL,
		0x727D384A9764951CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C63325E4AC1B5D1ULL,
		0x773F2E885065EB30ULL,
		0x9456DADFA7DB0FA0ULL,
		0xC4B814AEC3A088A3ULL,
		0xF249348ADAD82A8DULL,
		0x08D9655F508551E7ULL,
		0x7D8D6DEF1FCE852BULL,
		0x1F5E197A17E8640CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CD3B096D6AC7272ULL,
		0xE9C07029FE997130ULL,
		0x00CC778D6B2AFCBEULL,
		0x62E363B2A40E62AEULL,
		0x201EA62DA936156EULL,
		0x08CC0837FB6E5A41ULL,
		0xFF943739082D2752ULL,
		0x6D232130808CF110ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA919564B0BFCA661ULL,
		0x6D97DD06A77CF37BULL,
		0x3D192FD3EBD29EE6ULL,
		0x9FEE6F2ABD3FBFE0ULL,
		0x0937FEE8C9185E2BULL,
		0x50A1927AA7FA26A1ULL,
		0xE9E27E02D530B8AFULL,
		0x3A3F6FC56226B508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00857DB86AA2AA1FULL,
		0xCC722B3A99B4EF46ULL,
		0x0BAF46F21BE79114ULL,
		0x27766738058D8D6AULL,
		0x0B0E0CB7241DFA40ULL,
		0x8A24B0BD3951A822ULL,
		0x5B83AC293ADA77E6ULL,
		0xAACE27B317F23F57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA99C2BF3615E0C7EULL,
		0xA1E5F63C3EC81C3DULL,
		0x36B66921F0350FF2ULL,
		0xB8980812B8B2328AULL,
		0x0239F25FED05A46BULL,
		0xDA8522C79EAB8E83ULL,
		0xB261D22BEFEACF49ULL,
		0x90F1487675D48A5FULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A8CA3F7F4C81205ULL,
		0x4E20437C4A17FF3AULL,
		0xC0CE196C7C6AB041ULL,
		0x498A029A114CB300ULL,
		0xDC2811B2D184E139ULL,
		0x040853374846E0D9ULL,
		0xF7ADE9AC915E904DULL,
		0x0AD808C99806D434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB302FD1A0DB26A6BULL,
		0xE1F65306CE7012CCULL,
		0x8FC190181A930A8DULL,
		0x8352594C26F30BCAULL,
		0x31A23A91A546DB1AULL,
		0x9CD13ADA470F4DA9ULL,
		0xE6E9FFC98BA69E56ULL,
		0x71F9FE5AE6B28215ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE98E5EEDF97A786EULL,
		0xAFD6107A8467EDF6ULL,
		0x4F0F897466F9BACCULL,
		0xCAD85BD637BFB8CAULL,
		0xED8A2B2374C23A23ULL,
		0x98D969ED0F49AD70ULL,
		0x114416651AF80E1BULL,
		0x7B21F6937EB45621ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32A3801970F1A7B9ULL,
		0x3C98436E3CCF3357ULL,
		0x7B35E37A6D234884ULL,
		0x72F32EEAE0BF87D7ULL,
		0x1624562098A6B91FULL,
		0x0AA21657DA4996D9ULL,
		0x16E45B76152649E1ULL,
		0x27CE065EB8825C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F82A45D585BED42ULL,
		0xE0E87ADB19265BC3ULL,
		0x816F933430FEF9CFULL,
		0x5B609600CE2A5DEFULL,
		0xF701DBFC951A04C9ULL,
		0x591A0F866FE6E4F3ULL,
		0xB1583B8ADB81EBA9ULL,
		0x8232A4FC365F961BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD21244428AA4AFBULL,
		0xDC7039B525E96894ULL,
		0xFA5A704E5DDDB14BULL,
		0x2993B8EA2E95DA38ULL,
		0xE1258DDC0DBCBDD6ULL,
		0x53B819D1B5AF722AULL,
		0xA7BC60FCCEA7A248ULL,
		0xA5FCA2A28EDDCA79ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09520DA13761DF1AULL,
		0x41576D0731F5E809ULL,
		0x3B3ED5B7F7F3EE00ULL,
		0x59EEE57E9C2496EBULL,
		0xB909023F589CBF90ULL,
		0x8429A1A2493BF1EEULL,
		0x407BCCA574A87CE3ULL,
		0x7810B94D6BFC8A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C2E305E909BA825ULL,
		0x0BA8C8B00F780F2BULL,
		0x4D7A65C5A30ED68EULL,
		0x9B5330DC920D95B4ULL,
		0xE87E8DCE00880F3EULL,
		0xFAAFC8D69497A12CULL,
		0xADAF307D260BC738ULL,
		0x06F33AFE89EC9D28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x457C3DFFA7FA773FULL,
		0x4AFFA5B73E8DE722ULL,
		0x7644B07254FD388EULL,
		0xC2BDD5A20E29035FULL,
		0x51778FF15814B0AEULL,
		0x7E866974DDAC50C2ULL,
		0xEDD4FCD852A3BBDBULL,
		0x7EE383B3E21017B4ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE93C9EB676B39B9FULL,
		0xB6C902BEA1CEDDBDULL,
		0x435724C366C90C3EULL,
		0xA7BD196991A9C172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF210C017A494991ULL,
		0x8AE0863A679E413BULL,
		0xB2D9674BB98AF43CULL,
		0x50BEF61C5CA3088EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF210C017A494991ULL,
		0x8AE0863A679E413BULL,
		0xB2D9674BB98AF43CULL,
		0x50BEF61C5CA3088EULL,
		0xE93C9EB676B39B9FULL,
		0xB6C902BEA1CEDDBDULL,
		0x435724C366C90C3EULL,
		0xA7BD196991A9C172ULL
	}};
	printf("Test Case 501\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50281F2B4444B3DDULL,
		0x5ECBD6FCBDC97794ULL,
		0xA3D6C047E1A4FD49ULL,
		0x3F69D8074130567BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EED6C2C2FB8E5F4ULL,
		0x1F7F265057E68F5DULL,
		0x25C9F4E999B387FDULL,
		0xD6F992A6BB890535ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EED6C2C2FB8E5F4ULL,
		0x1F7F265057E68F5DULL,
		0x25C9F4E999B387FDULL,
		0xD6F992A6BB890535ULL,
		0x50281F2B4444B3DDULL,
		0x5ECBD6FCBDC97794ULL,
		0xA3D6C047E1A4FD49ULL,
		0x3F69D8074130567BULL
	}};
	printf("Test Case 502\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 502 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31E420BC1DE44593ULL,
		0x967A530D553B1A90ULL,
		0x23A7F81D6B48009CULL,
		0xD5F8FD4E2EFF3648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D5B5FFC47F789FULL,
		0x96C34A8AA00D6B7DULL,
		0xC03FBE1DA4FC5D5EULL,
		0x54E037A3327293EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74D5B5FFC47F789FULL,
		0x96C34A8AA00D6B7DULL,
		0xC03FBE1DA4FC5D5EULL,
		0x54E037A3327293EEULL,
		0x31E420BC1DE44593ULL,
		0x967A530D553B1A90ULL,
		0x23A7F81D6B48009CULL,
		0xD5F8FD4E2EFF3648ULL
	}};
	printf("Test Case 503\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 503 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C9A9F282DD0951BULL,
		0x231FFFD6F35320A2ULL,
		0x9FB13A7FBA38B146ULL,
		0x221E2E7579418D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE88B763128DB6B8ULL,
		0x3DE70753F295F6D8ULL,
		0x0E110E4E488C7A3BULL,
		0x9D21E7ED55DC1222ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE88B763128DB6B8ULL,
		0x3DE70753F295F6D8ULL,
		0x0E110E4E488C7A3BULL,
		0x9D21E7ED55DC1222ULL,
		0x5C9A9F282DD0951BULL,
		0x231FFFD6F35320A2ULL,
		0x9FB13A7FBA38B146ULL,
		0x221E2E7579418D41ULL
	}};
	printf("Test Case 504\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 504 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x677C7A3106AFED76ULL,
		0xFCF7A6D8F64BCB72ULL,
		0xA266EB51657855F2ULL,
		0x4FC04A9D03E7F6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB83EFC6CE95508EULL,
		0xEC5E8B80348094EBULL,
		0x8FF6AAAFFA4A85ADULL,
		0x67F2AD0A5693390DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB83EFC6CE95508EULL,
		0xEC5E8B80348094EBULL,
		0x8FF6AAAFFA4A85ADULL,
		0x67F2AD0A5693390DULL,
		0x677C7A3106AFED76ULL,
		0xFCF7A6D8F64BCB72ULL,
		0xA266EB51657855F2ULL,
		0x4FC04A9D03E7F6DBULL
	}};
	printf("Test Case 505\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 505 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82D8D39B7B5072DBULL,
		0x9FCE2F6D94AE433EULL,
		0xBCB5490100BC2913ULL,
		0x7CAA2AFA608E984EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14947D8447182F7ULL,
		0xD4BBC4962F68D5DFULL,
		0x5D28BB85AE130F80ULL,
		0x21199082E431C5F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF14947D8447182F7ULL,
		0xD4BBC4962F68D5DFULL,
		0x5D28BB85AE130F80ULL,
		0x21199082E431C5F3ULL,
		0x82D8D39B7B5072DBULL,
		0x9FCE2F6D94AE433EULL,
		0xBCB5490100BC2913ULL,
		0x7CAA2AFA608E984EULL
	}};
	printf("Test Case 506\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 506 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5BE7AB2536432249ULL,
		0xE627EE3849C84238ULL,
		0x7C2FC35DA9660C07ULL,
		0x99994B7FC6C69B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5418CC278770883ULL,
		0x66E3ABAE321EFC4CULL,
		0x70FFE6E32D3430F8ULL,
		0x382618DA79F84989ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5418CC278770883ULL,
		0x66E3ABAE321EFC4CULL,
		0x70FFE6E32D3430F8ULL,
		0x382618DA79F84989ULL,
		0x5BE7AB2536432249ULL,
		0xE627EE3849C84238ULL,
		0x7C2FC35DA9660C07ULL,
		0x99994B7FC6C69B44ULL
	}};
	printf("Test Case 507\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 507 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FFAE9E5F3089537ULL,
		0x90A7DDC15B65A104ULL,
		0x1421E02EBA5FBD9DULL,
		0xE295699C3671BF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF93FDDACFE35F2CULL,
		0x2E97B81030C7021AULL,
		0x6D3782A86AE3D94DULL,
		0x5B202E8C1422034DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF93FDDACFE35F2CULL,
		0x2E97B81030C7021AULL,
		0x6D3782A86AE3D94DULL,
		0x5B202E8C1422034DULL,
		0x4FFAE9E5F3089537ULL,
		0x90A7DDC15B65A104ULL,
		0x1421E02EBA5FBD9DULL,
		0xE295699C3671BF4FULL
	}};
	printf("Test Case 508\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 508 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4635AD5DD6DB1015ULL,
		0x9D9461583D6E2829ULL,
		0xA9B96D05AF3FABB6ULL,
		0x52293548783F47E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE812F00A578C6ED6ULL,
		0xD1E9E195B38BF10BULL,
		0xFA6A1F15CCF954C8ULL,
		0x6DE2FF5398F1FA3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE812F00A578C6ED6ULL,
		0xD1E9E195B38BF10BULL,
		0xFA6A1F15CCF954C8ULL,
		0x6DE2FF5398F1FA3EULL,
		0x4635AD5DD6DB1015ULL,
		0x9D9461583D6E2829ULL,
		0xA9B96D05AF3FABB6ULL,
		0x52293548783F47E7ULL
	}};
	printf("Test Case 509\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 509 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1513034370E3D0D6ULL,
		0x6888B4788C99AB5AULL,
		0x163894A0FCE0352BULL,
		0xE3D5068A27C40109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE18FB11A34437D4FULL,
		0x08BC0E010EAEA986ULL,
		0xCB7AA4C843C77188ULL,
		0x10E50CDE2F710749ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE18FB11A34437D4FULL,
		0x08BC0E010EAEA986ULL,
		0xCB7AA4C843C77188ULL,
		0x10E50CDE2F710749ULL,
		0x1513034370E3D0D6ULL,
		0x6888B4788C99AB5AULL,
		0x163894A0FCE0352BULL,
		0xE3D5068A27C40109ULL
	}};
	printf("Test Case 510\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 510 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}