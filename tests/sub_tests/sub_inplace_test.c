#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0xB2660B97BD066C7EULL,
		0xD9D20A1D85649C47ULL,
		0x0765A962C4A09D72ULL,
		0x034232DC7F77F22AULL,
		0x1781BA924E99F89AULL,
		0x76CBC6B3FCD2EE00ULL,
		0x9395551C61378AC3ULL,
		0xF8E664B3B46A52F5ULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0x56018DB786891D9BULL,
		0x320677488D67B72DULL,
		0x7C873E986B5C2C74ULL,
		0x32F7747308E35A59ULL,
		0xC89764885C185D7DULL,
		0x09D57C267630175AULL,
		0x6EA37005EA277128ULL,
		0xC0C349F80ECB3856ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x5C647DE0367D4EE3ULL,
		0xA7CB92D4F7FCE51AULL,
		0x8ADE6ACA594470FEULL,
		0xD04ABE69769497D0ULL,
		0x4EEA5609F2819B1CULL,
		0x6CF64A8D86A2D6A5ULL,
		0x24F1E5167710199BULL,
		0x38231ABBA59F1A9FULL
	}};
	int sign = 0;
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
		0xD17321296DD0ABAAULL,
		0x98945532B056BC4EULL,
		0xF0B6DC41669C2B95ULL,
		0x7BA1177A362394E3ULL,
		0x0A17F6683AA72599ULL,
		0x69B584CBC270B437ULL,
		0x3619B95E1C119586ULL,
		0x222833B4538F8BD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAF8B375FC29E18ULL,
		0x9B90BFC30D17BC56ULL,
		0x07E32F3115FC609FULL,
		0x26520327B11C2A97ULL,
		0xF8C2306B3E11A542ULL,
		0xFF58F9743C7B3B61ULL,
		0x97BE52CDF3190603ULL,
		0xB59949545C3AC17FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6C395F20E0E0D92ULL,
		0xFD03956FA33EFFF7ULL,
		0xE8D3AD10509FCAF5ULL,
		0x554F145285076A4CULL,
		0x1155C5FCFC958057ULL,
		0x6A5C8B5785F578D5ULL,
		0x9E5B669028F88F82ULL,
		0x6C8EEA5FF754CA54ULL
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
		0x190BC9F3066296A6ULL,
		0xF7F5DED02E452E4BULL,
		0x07EBD67E9233CBF8ULL,
		0x7E9B3D145CA71E2EULL,
		0xB3E201BC738E17BBULL,
		0x1DB2316AF5297075ULL,
		0x39D7CF4411D313F9ULL,
		0xBB65C72DE2F15335ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9455C45E8C27EDC9ULL,
		0xE2A987D4902BBAA8ULL,
		0xB583ED397A749406ULL,
		0xAF5B0BA614BECC0EULL,
		0x2CC978F608082C84ULL,
		0x91D69CFC50BC79D0ULL,
		0x8976DCF8EA1C0C9BULL,
		0x11DA404CAD34D6F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84B605947A3AA8DDULL,
		0x154C56FB9E1973A2ULL,
		0x5267E94517BF37F2ULL,
		0xCF40316E47E8521FULL,
		0x871888C66B85EB36ULL,
		0x8BDB946EA46CF6A5ULL,
		0xB060F24B27B7075DULL,
		0xA98B86E135BC7C3DULL
	}};
	sign = 0;
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
		0x4F6036DDBEFF8391ULL,
		0x8968D9991FA654E6ULL,
		0xEBD3AF0BFE725F06ULL,
		0x844B92E607C3D787ULL,
		0xAB66C01A2CA264FFULL,
		0x81E8135861A870E7ULL,
		0xA4D56BCBE16154F5ULL,
		0x41F09DF6A2009916ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63E170A6BF58BA0ULL,
		0x3B7D6EFC8E98F332ULL,
		0xC68441A4107B9A1BULL,
		0x10FA3CCF09C38B75ULL,
		0xCEACA99D74338D7DULL,
		0xC3C1EF3DCB43A2DCULL,
		0x82B94B88453B9066ULL,
		0xFE39B0AE509B85D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9221FD35309F7F1ULL,
		0x4DEB6A9C910D61B3ULL,
		0x254F6D67EDF6C4EBULL,
		0x73515616FE004C12ULL,
		0xDCBA167CB86ED782ULL,
		0xBE26241A9664CE0AULL,
		0x221C20439C25C48EULL,
		0x43B6ED4851651346ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x059CF97DF53CE135ULL,
		0xB8B3D7CB8538D19FULL,
		0x021B5B23E839007BULL,
		0x72D94BAB125F61FDULL,
		0x0F3ECB33B5005B7CULL,
		0xF000E15F744110F8ULL,
		0x57F9679DFAC6DB4AULL,
		0x5888A56E832F1D51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCCA883DAEFC2035ULL,
		0x8E21AA31D2749BE3ULL,
		0x939332D9162F0B16ULL,
		0x6B43F75EC1E6B318ULL,
		0xB3EAE159990D8A62ULL,
		0x79A7C379C2F76B2FULL,
		0xE8C2EC4556979076ULL,
		0x9C0A8E023DD3B930ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08D271404640C100ULL,
		0x2A922D99B2C435BBULL,
		0x6E88284AD209F565ULL,
		0x0795544C5078AEE4ULL,
		0x5B53E9DA1BF2D11AULL,
		0x76591DE5B149A5C8ULL,
		0x6F367B58A42F4AD4ULL,
		0xBC7E176C455B6420ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x25FBD18DCF0A9BA4ULL,
		0x1AF131B133E83050ULL,
		0x2D67ACCC37223BD7ULL,
		0x71989BA955B21A61ULL,
		0x333B4147F142A4F3ULL,
		0xB0F80FEFBAC28AD0ULL,
		0xCA54FF2900AD1E10ULL,
		0xCAE0A9B70C05E05FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB817D16559187F13ULL,
		0x8C5DDB4BA99B0F34ULL,
		0xFA9D567E8BF5F30CULL,
		0x0A5E7D960B7472C3ULL,
		0xCF7B5D2678706242ULL,
		0x824638B19D2568DAULL,
		0xA5AB46A2059F1B81ULL,
		0x8F07CB9EC3E0605CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DE4002875F21C91ULL,
		0x8E9356658A4D211BULL,
		0x32CA564DAB2C48CAULL,
		0x673A1E134A3DA79DULL,
		0x63BFE42178D242B1ULL,
		0x2EB1D73E1D9D21F5ULL,
		0x24A9B886FB0E028FULL,
		0x3BD8DE1848258003ULL
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
		0xC9DEF241F1FBF220ULL,
		0x0516FBFE16252213ULL,
		0x2D18326B8881A8E5ULL,
		0x5A8E87976D81DADAULL,
		0x059F245D0D890C55ULL,
		0x3D33F2964ABADF9AULL,
		0x87C264422A545F08ULL,
		0x3FA55450FB40F9D7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x019C95553521062CULL,
		0xEE2D5B8EBB1F1BD0ULL,
		0xBD95EAFD55F4B91BULL,
		0x5CD3A6940BA39FE8ULL,
		0x257181FB77D412A5ULL,
		0xDD25996490366A86ULL,
		0xC404C7EDFD139DC1ULL,
		0xC142F49258505D87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8425CECBCDAEBF4ULL,
		0x16E9A06F5B060643ULL,
		0x6F82476E328CEFC9ULL,
		0xFDBAE10361DE3AF1ULL,
		0xE02DA26195B4F9AFULL,
		0x600E5931BA847513ULL,
		0xC3BD9C542D40C146ULL,
		0x7E625FBEA2F09C4FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4C47A88616F4BA86ULL,
		0x689C216F0F24A2A1ULL,
		0x73D3387650B158DCULL,
		0x44440FA3D088EFB4ULL,
		0x79172237D79420D4ULL,
		0x2F52931E999143F0ULL,
		0x4C858C761DE4D4B2ULL,
		0x06C8EFEAB966E755ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76799D50A3A1A21ULL,
		0x3519D863E2325343ULL,
		0xE4A816D75DAF9F59ULL,
		0xF21B9385C41F80CFULL,
		0x5BFC0C3669C1E61CULL,
		0x09A8AC5DF2C715E9ULL,
		0xA0C0BE894927D751ULL,
		0x87DB13EF3435861BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4E00EB10CBAA065ULL,
		0x3382490B2CF24F5DULL,
		0x8F2B219EF301B983ULL,
		0x52287C1E0C696EE4ULL,
		0x1D1B16016DD23AB7ULL,
		0x25A9E6C0A6CA2E07ULL,
		0xABC4CDECD4BCFD61ULL,
		0x7EEDDBFB85316139ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x13D9A43F0FDA0A01ULL,
		0x45E2FBA0462385B0ULL,
		0x6D87AFEB131F4B9EULL,
		0xE4994E52767B20D0ULL,
		0xCF171E551F8DB8E3ULL,
		0xC7974DFE264778F4ULL,
		0x25ED0DA737C6481EULL,
		0x227B9A58F2E250C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26536E1E9D3C1C3ULL,
		0x1B8E7879C1D079D4ULL,
		0x6AD3191571572401ULL,
		0xE267808ADB8006D3ULL,
		0x167CB91B6581C86CULL,
		0x375C7A15A310187FULL,
		0x7AAF13AC1E99F8F9ULL,
		0xDE2A5E3858FC6DDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71746D5D2606483EULL,
		0x2A54832684530BDBULL,
		0x02B496D5A1C8279DULL,
		0x0231CDC79AFB19FDULL,
		0xB89A6539BA0BF077ULL,
		0x903AD3E883376075ULL,
		0xAB3DF9FB192C4F25ULL,
		0x44513C2099E5E2E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7DEDB0E365A95B3AULL,
		0xCE33D16380B5DA3BULL,
		0x53D7B4AD2A40D959ULL,
		0x71C73FD00EA205E3ULL,
		0x24DAEC043B4D6D48ULL,
		0xFAAD1B58C186F8D8ULL,
		0x73D3A8AD52F7D401ULL,
		0xAEF231F0E16BB9A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABC20FC542E32915ULL,
		0x4ED2A0E2A65D007DULL,
		0xCC1A9C4832D39217ULL,
		0xA8D582C24A6FAD67ULL,
		0x5DF5C543293EF265ULL,
		0xA1B4C989C31023F3ULL,
		0x53F14D17FAF87D70ULL,
		0xCC9D791A96AA2572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD22BA11E22C63225ULL,
		0x7F613080DA58D9BDULL,
		0x87BD1864F76D4742ULL,
		0xC8F1BD0DC432587BULL,
		0xC6E526C1120E7AE2ULL,
		0x58F851CEFE76D4E4ULL,
		0x1FE25B9557FF5691ULL,
		0xE254B8D64AC19432ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF52221E2DAACEFA2ULL,
		0xFF107732C86F497BULL,
		0x339379CB8C9F11D7ULL,
		0xF2CDF6E4BA444D16ULL,
		0x95E6240D0FE64C37ULL,
		0x69EF689386E2EC52ULL,
		0x46171E84CB591B35ULL,
		0x41B73C896E5DF524ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A3305676D3B2AAULL,
		0x5BBA89407CF64E60ULL,
		0x0F9921A20FB6DB63ULL,
		0xDBFF12A1D8188E97ULL,
		0x500BEC1F5EC2A56EULL,
		0x0FB93593138B194DULL,
		0x75875D5734814D13ULL,
		0xB7CA1978B66ACC7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x017EF18C63D93CF8ULL,
		0xA355EDF24B78FB1BULL,
		0x23FA58297CE83674ULL,
		0x16CEE442E22BBE7FULL,
		0x45DA37EDB123A6C9ULL,
		0x5A3633007357D305ULL,
		0xD08FC12D96D7CE22ULL,
		0x89ED2310B7F328A9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2E054803F2177FEFULL,
		0x8EA8A00312A4696BULL,
		0x6C499D9975A2866BULL,
		0xD8886558599E4381ULL,
		0x74ACE653C9874D00ULL,
		0x5E29E76744CE3C62ULL,
		0xC3A0D2AA26D7DE22ULL,
		0xEE016824A3603E91ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x667C71D51A45C035ULL,
		0x5848B126B651E1E0ULL,
		0x308443AE49AB5A32ULL,
		0x0D78111D67B9C9B6ULL,
		0x7EC100D21B0F83EFULL,
		0x50BAF69CBCD64424ULL,
		0xEEFE9F78999BEBE7ULL,
		0xF37E24774A466A1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC788D62ED7D1BFBAULL,
		0x365FEEDC5C52878AULL,
		0x3BC559EB2BF72C39ULL,
		0xCB10543AF1E479CBULL,
		0xF5EBE581AE77C911ULL,
		0x0D6EF0CA87F7F83DULL,
		0xD4A233318D3BF23BULL,
		0xFA8343AD5919D473ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x61FD16149F48BB6BULL,
		0xC6E2B6E001369FE3ULL,
		0xB76A4CCB122FEB39ULL,
		0xCD815187502B69D3ULL,
		0xE5EC913B237C2D09ULL,
		0x789D211979909909ULL,
		0xF9EB46E8FF581C8AULL,
		0x4269FBFF70D4A6B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B254EFD3111B46ULL,
		0x0F3C25326D704259ULL,
		0xD639B1A9814B6D9EULL,
		0xCE99A6BDF633AFAEULL,
		0xD7F911C9C6CFAF5EULL,
		0xD174834F0A04027CULL,
		0x25E1188910D9BD1DULL,
		0x70EA830BC38A0739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F4AC124CC37A025ULL,
		0xB7A691AD93C65D8AULL,
		0xE1309B2190E47D9BULL,
		0xFEE7AAC959F7BA24ULL,
		0x0DF37F715CAC7DAAULL,
		0xA7289DCA6F8C968DULL,
		0xD40A2E5FEE7E5F6CULL,
		0xD17F78F3AD4A9F7FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF98E6F69DC5B0562ULL,
		0x2BFE22A5C7F9299AULL,
		0xBD08EB2C39FD2467ULL,
		0x087E44E9D83A5FFBULL,
		0x9F13F9F56CB2336DULL,
		0x0A2B694165B71A31ULL,
		0x8B59946F634897FDULL,
		0x1F64D1A359A16146ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55CD85962A66003DULL,
		0x41030F36E43DFA73ULL,
		0x09BC8CF90E11D2D8ULL,
		0x6B0A9BDA6291D888ULL,
		0xC6938B87E89077B3ULL,
		0xE71AE88A7623F4DAULL,
		0xD5473AEC6EDF74B2ULL,
		0x91142590460EFF99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3C0E9D3B1F50525ULL,
		0xEAFB136EE3BB2F27ULL,
		0xB34C5E332BEB518EULL,
		0x9D73A90F75A88773ULL,
		0xD8806E6D8421BBB9ULL,
		0x231080B6EF932556ULL,
		0xB6125982F469234AULL,
		0x8E50AC13139261ACULL
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
		0x81507DC33122C500ULL,
		0xEE8DC2C4390432FCULL,
		0xA6A3113E572E5E20ULL,
		0x4D3F221080A4A955ULL,
		0x98BD3A618C3E15C3ULL,
		0xC284FB0F3E28FDBAULL,
		0x8EFEC093094BA552ULL,
		0xCF7D353DDF7061CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF165F8FAE1EB391ULL,
		0x2F26A63C381DF0A2ULL,
		0xA4E1752DA9CB0FD3ULL,
		0x108409E764759582ULL,
		0x9AA753AE4A33DF5BULL,
		0xF3D829743A9FC04DULL,
		0x2864030967F4FB5EULL,
		0x5A8BCF6A90C77ABBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC23A1E338304116FULL,
		0xBF671C8800E64259ULL,
		0x01C19C10AD634E4DULL,
		0x3CBB18291C2F13D3ULL,
		0xFE15E6B3420A3668ULL,
		0xCEACD19B03893D6CULL,
		0x669ABD89A156A9F3ULL,
		0x74F165D34EA8E710ULL
	}};
	sign = 0;
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
		0x8C81989F6F8E5B49ULL,
		0x3F65B8C6CE5998F3ULL,
		0x7C2DD07B597B2075ULL,
		0xC6A99AD56D27F304ULL,
		0x241A6BE65DCA864AULL,
		0xB8D49F0719DE63F3ULL,
		0x66B317C16189BE74ULL,
		0x2DDB51CF2E5DAB08ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD16EB2D02EA9942ULL,
		0xA47D7F6CF48B596FULL,
		0x004E9AE890E3201DULL,
		0x7D98D928DC2C2E98ULL,
		0xBC574FC3AF8FA549ULL,
		0xF041CCB664B31572ULL,
		0x7BB9B2B1E34411D4ULL,
		0xC42246920A3E632CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF6AAD726CA3C207ULL,
		0x9AE83959D9CE3F83ULL,
		0x7BDF3592C8980057ULL,
		0x4910C1AC90FBC46CULL,
		0x67C31C22AE3AE101ULL,
		0xC892D250B52B4E80ULL,
		0xEAF9650F7E45AC9FULL,
		0x69B90B3D241F47DBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x41D9ABA4EFCAC52CULL,
		0x0A494A5DD70500F4ULL,
		0xC0368A7E60C90A96ULL,
		0x513F3F87FDC368A5ULL,
		0xD0A6774CC777E39DULL,
		0xAE9FB5609C1A1530ULL,
		0x1E7B626887CCC106ULL,
		0x4F116CDB74BFE5CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A34A0F40D13CF5ULL,
		0x6E58CB928E953058ULL,
		0x1143AAEE6AB93295ULL,
		0xCA7BEA2BD30A52DCULL,
		0xC5E7759A2494FCDCULL,
		0x66D7C250219EAB12ULL,
		0x5B5139B8A8A877F2ULL,
		0x5948593DB03F470BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E366195AEF98837ULL,
		0x9BF07ECB486FD09CULL,
		0xAEF2DF8FF60FD800ULL,
		0x86C3555C2AB915C9ULL,
		0x0ABF01B2A2E2E6C0ULL,
		0x47C7F3107A7B6A1EULL,
		0xC32A28AFDF244914ULL,
		0xF5C9139DC4809EBEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x037C0803DEF111EFULL,
		0xBD979F403C014029ULL,
		0xE6151FB0E4932FC3ULL,
		0xA30F48EEA40AAE4EULL,
		0x38908341353F5D9AULL,
		0x9559A12E5FCDCC0BULL,
		0x6A6CC8584F9CFDB7ULL,
		0x0F11810348065275ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E5BB6277430F2B7ULL,
		0x1A1A04DEADA197D3ULL,
		0x2875E9C54BF60BBEULL,
		0xB5FDA581654097AAULL,
		0x838A30C96A75DE6AULL,
		0xE6A9685E737F603EULL,
		0x2BC2CCB0A9FA9C3DULL,
		0x02ED94F19BFDFB96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC52051DC6AC01F38ULL,
		0xA37D9A618E5FA855ULL,
		0xBD9F35EB989D2405ULL,
		0xED11A36D3ECA16A4ULL,
		0xB5065277CAC97F2FULL,
		0xAEB038CFEC4E6BCCULL,
		0x3EA9FBA7A5A26179ULL,
		0x0C23EC11AC0856DFULL
	}};
	sign = 0;
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
		0x97CC881729529A4BULL,
		0x400B094327885CCEULL,
		0xE4F75D3F8E27BDC6ULL,
		0x8DE527AFD35D0660ULL,
		0x9FCD76B91779D570ULL,
		0x047E342F0EB2EAF5ULL,
		0xA656681261CCBFBCULL,
		0x628168B7707B2C07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03B06B0EEC042CDULL,
		0x48C408F26EF6973DULL,
		0x99F21A6E53BCB3CFULL,
		0xEB7EF48D239ABC12ULL,
		0xFC30803DBB16D334ULL,
		0xFDDCF89B2D266DB3ULL,
		0x6A483B5A77E9942EULL,
		0x26DD7A912415E462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA79181663A92577EULL,
		0xF7470050B891C590ULL,
		0x4B0542D13A6B09F6ULL,
		0xA2663322AFC24A4EULL,
		0xA39CF67B5C63023BULL,
		0x06A13B93E18C7D41ULL,
		0x3C0E2CB7E9E32B8DULL,
		0x3BA3EE264C6547A5ULL
	}};
	sign = 0;
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
		0xF0EBF1CBF09D90E7ULL,
		0x128727BD07282AAAULL,
		0xE9693B9A1964A962ULL,
		0x277CCE2236381B8AULL,
		0xE03DC16A15AF059FULL,
		0x595E02C78F290DB9ULL,
		0x50972A60048D9DDBULL,
		0x6B89A0A8546FE05BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F01B242628EE77FULL,
		0xCDB88B08C48D297BULL,
		0x2614FBBBA846AECFULL,
		0x22A728B26B83F152ULL,
		0x507876EF0400D357ULL,
		0x1A12A5E72AC9C720ULL,
		0xE2C25E7A780FDE88ULL,
		0x1B8B0D95847A4E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1EA3F898E0EA968ULL,
		0x44CE9CB4429B012FULL,
		0xC3543FDE711DFA92ULL,
		0x04D5A56FCAB42A38ULL,
		0x8FC54A7B11AE3248ULL,
		0x3F4B5CE0645F4699ULL,
		0x6DD4CBE58C7DBF53ULL,
		0x4FFE9312CFF591DAULL
	}};
	sign = 0;
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
		0xE0030DA84996E24FULL,
		0x180AF2AEF0CC1BEFULL,
		0xF09D657A3B61834EULL,
		0x49B721881BF17608ULL,
		0xBC5D76091DF26104ULL,
		0x858C31FB364515C7ULL,
		0x7BFE2C18B86ED9F5ULL,
		0x90F5C6FD227F7AF9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D762C9E597D571CULL,
		0xD4642A2450FC4B47ULL,
		0xD7D642FC3B2FF718ULL,
		0x8553FCD98FA5DCD6ULL,
		0xFA7E616F082E6FABULL,
		0x4A5F63884F8B7429ULL,
		0x7B1355CD741C9C01ULL,
		0x913BA2F660DE4C2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x428CE109F0198B33ULL,
		0x43A6C88A9FCFD0A8ULL,
		0x18C7227E00318C35ULL,
		0xC46324AE8C4B9932ULL,
		0xC1DF149A15C3F158ULL,
		0x3B2CCE72E6B9A19DULL,
		0x00EAD64B44523DF4ULL,
		0xFFBA2406C1A12ECCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x287B5F4DE41A5E3CULL,
		0xCEF4B005BDA70BEFULL,
		0x4221CE140603DB33ULL,
		0x1D75A855BC4ADFECULL,
		0x0B442C523E83D192ULL,
		0x5A0E792426D3733AULL,
		0xF2064C8068B27573ULL,
		0x83085494021C75B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE269BF35F728A21ULL,
		0x6C2FFCEEDAAEA89FULL,
		0x369D16418C62D990ULL,
		0x071DA083F000F965ULL,
		0x28A64DE9C8932993ULL,
		0x5BE4C4E194943260ULL,
		0xB3DD179923E8F125ULL,
		0x29653F9A20FA410FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A54C35A84A7D41BULL,
		0x62C4B316E2F8634FULL,
		0x0B84B7D279A101A3ULL,
		0x165807D1CC49E687ULL,
		0xE29DDE6875F0A7FFULL,
		0xFE29B442923F40D9ULL,
		0x3E2934E744C9844DULL,
		0x59A314F9E12234A1ULL
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
		0xCF008A9B422699FCULL,
		0xD5FA3459712792F7ULL,
		0x74ACBA9EF77B8744ULL,
		0x46041169C4DBDF58ULL,
		0xDC91611F9E682008ULL,
		0xA2C9A78405C8F609ULL,
		0xE4024ED9FC3A2BFCULL,
		0x231D7146497A58B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD826E7F91A43E9ULL,
		0x623795B81C3D7097ULL,
		0xF98F8CD50DA58177ULL,
		0x9BDA95B182C5D238ULL,
		0x9854DFC9412FEF11ULL,
		0x850C10FFB9BB6C78ULL,
		0xB379C8827258E0BFULL,
		0xEE8BAF498A742137ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x612863B3490C5613ULL,
		0x73C29EA154EA2260ULL,
		0x7B1D2DC9E9D605CDULL,
		0xAA297BB842160D1FULL,
		0x443C81565D3830F6ULL,
		0x1DBD96844C0D8991ULL,
		0x3088865789E14B3DULL,
		0x3491C1FCBF063781ULL
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
		0xF1E0C5D8CA9255B0ULL,
		0xC8D3F7E114D4EA7EULL,
		0x5CC0528E87055618ULL,
		0x2EFB382B83926813ULL,
		0xB55466CF199829C7ULL,
		0x404A4AC6CACCA7DDULL,
		0x321D5E83163E6FB0ULL,
		0x9ABB61AF4A36D693ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x303798C0FD54F767ULL,
		0xB1D2A0CFC8043D64ULL,
		0x9DF50BFC0B8A7DDEULL,
		0x2B2C14EEB03932C4ULL,
		0xB98F63C09D53D094ULL,
		0x53BC1A628E14E05FULL,
		0x9FFF7EC72C5BCE04ULL,
		0xE233D558EBBAE9ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1A92D17CD3D5E49ULL,
		0x170157114CD0AD1AULL,
		0xBECB46927B7AD83AULL,
		0x03CF233CD359354EULL,
		0xFBC5030E7C445933ULL,
		0xEC8E30643CB7C77DULL,
		0x921DDFBBE9E2A1ABULL,
		0xB8878C565E7BECE5ULL
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
		0x28626B23DCCD2218ULL,
		0x7AD66FA110C1168AULL,
		0xA3425E09B3B75726ULL,
		0x2027E0BE0E6AF1B1ULL,
		0x4F08888E0A320AA8ULL,
		0xA1B8EE9215F51A91ULL,
		0x6912DED78254FB8AULL,
		0x136572738A69672BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11F9BAFA14F0A29ULL,
		0xDCE33305B970565DULL,
		0x63E3C28539FAF40CULL,
		0xB69570771D9F1718ULL,
		0x541604866DCDCB66ULL,
		0xAF754CF7733A04D1ULL,
		0x8308F80CED30F5F0ULL,
		0x7071EBB54F3DBB35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4742CF743B7E17EFULL,
		0x9DF33C9B5750C02CULL,
		0x3F5E9B8479BC6319ULL,
		0x69927046F0CBDA99ULL,
		0xFAF284079C643F41ULL,
		0xF243A19AA2BB15BFULL,
		0xE609E6CA95240599ULL,
		0xA2F386BE3B2BABF5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEFFC20BFBDE49BC0ULL,
		0x6D2BEAA4C3F44D99ULL,
		0xD4F888D4D123ECC9ULL,
		0xB648987213399706ULL,
		0x852625BEAB7310EBULL,
		0x4F4D778E984426D7ULL,
		0x7B63F6D3AFB2BD42ULL,
		0xD5CE60139012D0DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF822DFD7BDBE7A3ULL,
		0x891C5A51154BD191ULL,
		0xC3E5E56D48AC5D43ULL,
		0x322F41F0C0262F50ULL,
		0x8BEF68DCF1F9DE71ULL,
		0xA09E6F1191216077ULL,
		0xF4EF59820B35F3A5ULL,
		0x38E58E16FFA7CCD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF079F2C24208B41DULL,
		0xE40F9053AEA87C07ULL,
		0x1112A36788778F85ULL,
		0x84195681531367B6ULL,
		0xF936BCE1B979327AULL,
		0xAEAF087D0722C65FULL,
		0x86749D51A47CC99CULL,
		0x9CE8D1FC906B040AULL
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
		0xECD0FC51CBEA152BULL,
		0x8804C172F4550A38ULL,
		0x5FCC675AF6BAA3DAULL,
		0x1888FAB1947EB6D3ULL,
		0x8146C499389AC275ULL,
		0x37A7DD1F06D5381EULL,
		0xD0777B673CA96170ULL,
		0x8E1E596B213F4E3EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DDC1835A73B0D2ULL,
		0xC7F05458C05A12B1ULL,
		0x0F8E13F0FE102CC7ULL,
		0x1E0730CED77B7B28ULL,
		0xB7F9C4CFA6CE8C7DULL,
		0xCE350DB6C14BB9E5ULL,
		0x53C1FCE41A45DE0BULL,
		0x516E040E1D40C71FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAF33ACE71766459ULL,
		0xC0146D1A33FAF786ULL,
		0x503E5369F8AA7712ULL,
		0xFA81C9E2BD033BABULL,
		0xC94CFFC991CC35F7ULL,
		0x6972CF6845897E38ULL,
		0x7CB57E8322638364ULL,
		0x3CB0555D03FE871FULL
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
		0xAF07F531D1475ED4ULL,
		0x1F30EA368DB97E82ULL,
		0x9CCC7D425AEFBCE4ULL,
		0x4FB2794C8EF56050ULL,
		0x5514A51D1049406BULL,
		0x0BD5C201021C49B9ULL,
		0x34A7403D91A6EF22ULL,
		0x5064BACC9DFD8AABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CA85C80B85256BULL,
		0xED7CA9F0DA154060ULL,
		0x5B0A869D0BF226B3ULL,
		0xA65C9A8DD63DCC08ULL,
		0x7D07218C4EEB967BULL,
		0xD7A3F6363B5E4997ULL,
		0x48ABAA55E0BDD0B1ULL,
		0x3F2A3ED793B3AD10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE83D6F69C5C23969ULL,
		0x31B44045B3A43E21ULL,
		0x41C1F6A54EFD9630ULL,
		0xA955DEBEB8B79448ULL,
		0xD80D8390C15DA9EFULL,
		0x3431CBCAC6BE0021ULL,
		0xEBFB95E7B0E91E70ULL,
		0x113A7BF50A49DD9AULL
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
		0xCD8BFEE1312FD47EULL,
		0xC836DC1D131A99B3ULL,
		0xA4A4EC3F812D69C1ULL,
		0x87F252C95DA6B951ULL,
		0x76A6F9CA7F936B73ULL,
		0xC7A865B737B3E985ULL,
		0xF89E201B14C0CCF0ULL,
		0x067ADBE95AF52143ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A640DC9B79305AULL,
		0x4FD562E567C08511ULL,
		0xEEB043346BF6BBE2ULL,
		0x9327FE0545F3FA40ULL,
		0xEBC242C0B49BDD90ULL,
		0x3165DAB0092F6D36ULL,
		0x8BF488C780F38990ULL,
		0xEA3A16C79216EABBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE5BE0495B6A424ULL,
		0x78617937AB5A14A2ULL,
		0xB5F4A90B1536ADDFULL,
		0xF4CA54C417B2BF10ULL,
		0x8AE4B709CAF78DE2ULL,
		0x96428B072E847C4EULL,
		0x6CA9975393CD4360ULL,
		0x1C40C521C8DE3688ULL
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
		0x28397A03DEA9731EULL,
		0xDE8D7947447EFDBEULL,
		0xCF18CACFF179566BULL,
		0xC6812AE601D7C8E9ULL,
		0x3D91501862B48ECEULL,
		0xD87561E80B48DE81ULL,
		0xE9BE2C314D13B14AULL,
		0x6446012753801388ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFDF9CA18A617394ULL,
		0x9076298315FA6504ULL,
		0xC2F9E26CF74F065CULL,
		0xCD223278A9A9A2FDULL,
		0xC1E109CD306E365EULL,
		0x85E1121379852C52ULL,
		0x94C39CBF1BCD18EFULL,
		0x33DE62D1736C8215ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5859DD625447FF8AULL,
		0x4E174FC42E8498B9ULL,
		0x0C1EE862FA2A500FULL,
		0xF95EF86D582E25ECULL,
		0x7BB0464B3246586FULL,
		0x52944FD491C3B22EULL,
		0x54FA8F723146985BULL,
		0x30679E55E0139173ULL
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
		0xD8826864DA577916ULL,
		0x4A823873F5858FDDULL,
		0xD9495458F02D4589ULL,
		0x69B901580B7695EEULL,
		0x462B4B236E6A876AULL,
		0xAD035D7112AD4409ULL,
		0xE571A4C29E4AC193ULL,
		0x15ED9671D65F5586ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x630E9ABC3AE848B6ULL,
		0x607FFD6C28EF44AEULL,
		0xB1B5A5327FCC9DF2ULL,
		0x5FCBAF3EE4CAC0B4ULL,
		0x1C57AE7E2C0AD376ULL,
		0x017A8CDC0729FED9ULL,
		0xC4B4C9930C2F2F09ULL,
		0xF27033DCBA023596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7573CDA89F6F3060ULL,
		0xEA023B07CC964B2FULL,
		0x2793AF267060A796ULL,
		0x09ED521926ABD53AULL,
		0x29D39CA5425FB3F4ULL,
		0xAB88D0950B834530ULL,
		0x20BCDB2F921B928AULL,
		0x237D62951C5D1FF0ULL
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
		0x39AD26126B936779ULL,
		0xDA1146CA4AA534AEULL,
		0xF829D09CABCCF886ULL,
		0xDA91C6F9643A51FBULL,
		0x401066AEE16099B0ULL,
		0x9BFA5D133C296F2DULL,
		0x11E2D39B81212DEEULL,
		0xCDFEAA7C652A2EABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B297D2C7E21B1A7ULL,
		0x0696B886712FA804ULL,
		0x494455B59226D3A9ULL,
		0xCD31AE553852A29AULL,
		0xF4F9C2FE433F8E92ULL,
		0xD9F3778E59034CC4ULL,
		0xC05B740F4D9A4F65ULL,
		0xF9CA078F11F53AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE83A8E5ED71B5D2ULL,
		0xD37A8E43D9758CA9ULL,
		0xAEE57AE719A624DDULL,
		0x0D6018A42BE7AF61ULL,
		0x4B16A3B09E210B1EULL,
		0xC206E584E3262268ULL,
		0x51875F8C3386DE88ULL,
		0xD434A2ED5334F3BEULL
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
		0x601928770D9BC549ULL,
		0xF975884BE5CAC0E5ULL,
		0xF80582F4BE060A5BULL,
		0xB9CF20C4D784BF0BULL,
		0x0E168D7365511B65ULL,
		0x63F243D7990959E2ULL,
		0x0A6D4D70436D15DDULL,
		0x2F8DCC3EBC19BDCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E54BD4B774ADD3ULL,
		0x3A2366D1D1FF61B2ULL,
		0xA07E402FBC7746B7ULL,
		0xBF6F44D352C6725CULL,
		0xD878FDE95BCA003EULL,
		0xCAB92BBFEB5747C2ULL,
		0xC0A8860279D05606ULL,
		0x622A10F95FCFF231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB733DCA256271776ULL,
		0xBF52217A13CB5F32ULL,
		0x578742C5018EC3A4ULL,
		0xFA5FDBF184BE4CAFULL,
		0x359D8F8A09871B26ULL,
		0x99391817ADB2121FULL,
		0x49C4C76DC99CBFD6ULL,
		0xCD63BB455C49CB98ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x77845266AF9F4B25ULL,
		0xF1DFA6080D3C8412ULL,
		0xD624EBB2FC519ABAULL,
		0x1F122FF29C25C0F6ULL,
		0x2206EE2D317F8927ULL,
		0x9BE9E92292B4E198ULL,
		0x42BB8FC14E423DC6ULL,
		0x261586328000A55CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x980DA625E5A01D19ULL,
		0xE2813692CB3BCD51ULL,
		0x93B8CABE7F7B5BE1ULL,
		0x9621C9E47D2542CBULL,
		0x14533EFAB00C76FEULL,
		0x625CFB9058062D19ULL,
		0x6EB69CD1E2A83C44ULL,
		0x75325914A4FBACF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF76AC40C9FF2E0CULL,
		0x0F5E6F754200B6C0ULL,
		0x426C20F47CD63ED9ULL,
		0x88F0660E1F007E2BULL,
		0x0DB3AF3281731228ULL,
		0x398CED923AAEB47FULL,
		0xD404F2EF6B9A0182ULL,
		0xB0E32D1DDB04F867ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF1C2DF641E92C715ULL,
		0x139561B9CCE5FD9FULL,
		0xB8CCB05006EF8148ULL,
		0xAAB6E6902B09905BULL,
		0x5A708A8450C94049ULL,
		0x427CF83E12260468ULL,
		0xA70A3A707320EC18ULL,
		0x5C1601D24E124F94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x317DD830323F04CDULL,
		0x78E08A67B7AB3D70ULL,
		0xBD2D9CC8F87DE494ULL,
		0x6E24EE13A85710C5ULL,
		0x6573B319333840A8ULL,
		0x724A4FD83BCD7CB9ULL,
		0x9AAA612C00CD8088ULL,
		0x37C100DB15F867BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0450733EC53C248ULL,
		0x9AB4D752153AC02FULL,
		0xFB9F13870E719CB3ULL,
		0x3C91F87C82B27F95ULL,
		0xF4FCD76B1D90FFA1ULL,
		0xD032A865D65887AEULL,
		0x0C5FD94472536B8FULL,
		0x245500F73819E7D8ULL
	}};
	sign = 0;
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
		0xC0E0EFEB8090E06FULL,
		0xABC75996E4589FF2ULL,
		0xF5F53D48406A8C24ULL,
		0x0338A691AD8BB7D5ULL,
		0x5FA7FF37AD6A6BA7ULL,
		0xC8BDE633239BAA00ULL,
		0x5F548BADCB05354DULL,
		0x8F7D75B972C2C2E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24F51C5005BB6372ULL,
		0x6924AC9F592D799BULL,
		0x1B0BB1C08643189CULL,
		0xF962B32E94F0B1C8ULL,
		0x4733EE6B43FDE5DCULL,
		0x1EF74F782634D8ABULL,
		0xCB7C6DD9D21283CFULL,
		0x65B936E2AAAA260CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BEBD39B7AD57CFDULL,
		0x42A2ACF78B2B2657ULL,
		0xDAE98B87BA277388ULL,
		0x09D5F363189B060DULL,
		0x187410CC696C85CAULL,
		0xA9C696BAFD66D155ULL,
		0x93D81DD3F8F2B17EULL,
		0x29C43ED6C8189CDCULL
	}};
	sign = 0;
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
		0xAF71315C7341DD10ULL,
		0x65ABE50327B899ECULL,
		0x3426D72752D04B2FULL,
		0x452F5DC26A2FB575ULL,
		0xC83203234C8C85D2ULL,
		0xD8CEFABC0979ADAAULL,
		0x9353D94CA23AB944ULL,
		0x703719EA6605C54AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB82E65C5BA8E493ULL,
		0x24C9CA8DCDAB0F47ULL,
		0xAC5E59CB8B57E690ULL,
		0xE26DBE3EA7E76878ULL,
		0xC5DEFD55F58AD042ULL,
		0xBD01A364A63D23CAULL,
		0x041B0E0F9718B09BULL,
		0x7714ED8DDA28D542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3EE4B001798F87DULL,
		0x40E21A755A0D8AA4ULL,
		0x87C87D5BC778649FULL,
		0x62C19F83C2484CFCULL,
		0x025305CD5701B58FULL,
		0x1BCD5757633C89E0ULL,
		0x8F38CB3D0B2208A9ULL,
		0xF9222C5C8BDCF008ULL
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
		0x416D8941A268018DULL,
		0x3BE9E851735F67DDULL,
		0xB5E43171BEB4F405ULL,
		0xE6D56AC561BC1E0AULL,
		0xA473181F25C39EE6ULL,
		0x2E67FC88885F3992ULL,
		0xCEE630A621E5F4B9ULL,
		0xDB16BD0B4A826B7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36820E27F41B5A23ULL,
		0x7200A46BDC7A58F4ULL,
		0xF2BB33E9A63ACC39ULL,
		0x27394A1869F048E4ULL,
		0x913DDD25E8949E16ULL,
		0x80322F16DEEF0CA6ULL,
		0xA0806B7F001A1D27ULL,
		0xE3D7804096E0E1B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AEB7B19AE4CA76AULL,
		0xC9E943E596E50EE9ULL,
		0xC328FD88187A27CBULL,
		0xBF9C20ACF7CBD525ULL,
		0x13353AF93D2F00D0ULL,
		0xAE35CD71A9702CECULL,
		0x2E65C52721CBD791ULL,
		0xF73F3CCAB3A189C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB37C84C0A45E6176ULL,
		0x2B6D6CD69C7035FDULL,
		0xF162A86C289238D4ULL,
		0xEA461F1523500B33ULL,
		0x8CDAB1772D07D60FULL,
		0x491CD70C9C76CDB6ULL,
		0x5848F946920432CFULL,
		0x2F7DE0191D5259E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x792BB152520979D9ULL,
		0x317A4C652E304601ULL,
		0xAE3A95C321A59B6FULL,
		0x7DDB806551A246BCULL,
		0x3C9008538B79E0C8ULL,
		0x98674A38E22A8BDBULL,
		0xEC1B1E6B5A21472AULL,
		0x1F525139D6C26CAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A50D36E5254E79DULL,
		0xF9F320716E3FEFFCULL,
		0x432812A906EC9D64ULL,
		0x6C6A9EAFD1ADC477ULL,
		0x504AA923A18DF547ULL,
		0xB0B58CD3BA4C41DBULL,
		0x6C2DDADB37E2EBA4ULL,
		0x102B8EDF468FED34ULL
	}};
	sign = 0;
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
		0x8622527CA51C0856ULL,
		0xD36D851BA2E281BFULL,
		0xBDC54FBF29664EB7ULL,
		0xDAF49AC55C6DC089ULL,
		0x0D31DEA63C9A4BA2ULL,
		0x9B86C45528A1F8A7ULL,
		0x9944DEF7AA97A7B6ULL,
		0xBF565A4685E8822AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE442CD32BD4B4724ULL,
		0xB30CDACF169E4465ULL,
		0xCA2AE23D2BACB2E8ULL,
		0x098591BE2B51A23FULL,
		0x55ABEA2C1D07867EULL,
		0xF13428F6510A864FULL,
		0xC32638249CF93933ULL,
		0x7A26869A97C3FD81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1DF8549E7D0C132ULL,
		0x2060AA4C8C443D59ULL,
		0xF39A6D81FDB99BCFULL,
		0xD16F0907311C1E49ULL,
		0xB785F47A1F92C524ULL,
		0xAA529B5ED7977257ULL,
		0xD61EA6D30D9E6E82ULL,
		0x452FD3ABEE2484A8ULL
	}};
	sign = 0;
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
		0xDEAFA1D566F1FAB5ULL,
		0x6E410632C1988F82ULL,
		0xF1892960B2EF38F8ULL,
		0x94ECDE4541E52580ULL,
		0x1C1003DEE92A62C0ULL,
		0xE810BE7FD4F8C047ULL,
		0x5A9028552B0529A9ULL,
		0x039351AF7A77EB50ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB5CCBB784A5F14ULL,
		0x5BE8065BE1739A37ULL,
		0x80D39A54391A442EULL,
		0x095B70B955118CF2ULL,
		0x4A300680DA78CF4FULL,
		0x769A05346D425C66ULL,
		0x1EDABEBC8C47D5F6ULL,
		0xA3963FB5B185E0CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20F9D519EEA79BA1ULL,
		0x1258FFD6E024F54BULL,
		0x70B58F0C79D4F4CAULL,
		0x8B916D8BECD3988EULL,
		0xD1DFFD5E0EB19371ULL,
		0x7176B94B67B663E0ULL,
		0x3BB569989EBD53B3ULL,
		0x5FFD11F9C8F20A83ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x739C0E7E3B41CD11ULL,
		0x78B65691A6BCC745ULL,
		0x705B1C0BD4FF2258ULL,
		0xEBD6AF54773AF930ULL,
		0xF0CD09013FA01722ULL,
		0x7362618CBDEF5B03ULL,
		0x1B4A9BA230DD5418ULL,
		0xFE84F68B0F39F407ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA75E9F1820F433E2ULL,
		0xB9C30AB606327E08ULL,
		0x5535EB60702ED6FEULL,
		0xD73D880D7F4D66B1ULL,
		0x4BD72F58BEBECEB8ULL,
		0xEF46940788275D88ULL,
		0xB80C95F372C6D958ULL,
		0x6C2C39EE756967D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC3D6F661A4D992FULL,
		0xBEF34BDBA08A493CULL,
		0x1B2530AB64D04B59ULL,
		0x14992746F7ED927FULL,
		0xA4F5D9A880E1486AULL,
		0x841BCD8535C7FD7BULL,
		0x633E05AEBE167ABFULL,
		0x9258BC9C99D08C2DULL
	}};
	sign = 0;
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
		0x4B557A9203601DD6ULL,
		0x002F04CF6665BF68ULL,
		0xC5BDBBC65F6DE99AULL,
		0xA99CC83D56D34EB0ULL,
		0xE183005CB647F103ULL,
		0x20F3CBDC471C170FULL,
		0x80D1EB8779B1C4D5ULL,
		0x90D9553024300FA5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x235D04A2A43974EFULL,
		0x66059431EB1E0E42ULL,
		0x6F8C98C13BF854CCULL,
		0xC93281996A63A58DULL,
		0xB5687FD0C8581110ULL,
		0x972DC837387F4E4AULL,
		0x55D2A3DD4F2C446EULL,
		0xE8CEE5E11FBD59A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27F875EF5F26A8E7ULL,
		0x9A29709D7B47B126ULL,
		0x56312305237594CDULL,
		0xE06A46A3EC6FA923ULL,
		0x2C1A808BEDEFDFF2ULL,
		0x89C603A50E9CC8C5ULL,
		0x2AFF47AA2A858066ULL,
		0xA80A6F4F0472B602ULL
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
		0xE0BB4A7A0DEE875BULL,
		0xF0845A3639966B74ULL,
		0xA7D606126DA997EAULL,
		0x6EF1CFC7B62EF7B0ULL,
		0x39F661A7F68CDCD5ULL,
		0x80CAC583054D9E95ULL,
		0xFAD35D68A25BF925ULL,
		0x7A0C6D1C8A586DF3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D1962502EA6AA6CULL,
		0xDB16FCD01A56ABB1ULL,
		0xC5765CA581001299ULL,
		0xB35230CA829ACFCBULL,
		0x7AB17C925966AD6AULL,
		0x2F583BF003230D5AULL,
		0x2BAA3B7EB78B8749ULL,
		0xEFE4F650ECD324C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A1E829DF47DCEFULL,
		0x156D5D661F3FBFC3ULL,
		0xE25FA96CECA98551ULL,
		0xBB9F9EFD339427E4ULL,
		0xBF44E5159D262F6AULL,
		0x51728993022A913AULL,
		0xCF2921E9EAD071DCULL,
		0x8A2776CB9D85492EULL
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
		0x770537007E9B6C12ULL,
		0x3F6347768CF07C2AULL,
		0x8BDA394A00AC9C06ULL,
		0x4F7F053D48C52EF3ULL,
		0x9AF609176C0F4F0AULL,
		0x175CD81F25A87446ULL,
		0x3C97FC5DA9BC468BULL,
		0x4F8C6C7615D094B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F633DB745124FFBULL,
		0xE18F660F30D5D3C5ULL,
		0x926127DF403BE0B5ULL,
		0xD6C3B5950F3C99D4ULL,
		0xECA358536DCD0B8FULL,
		0x540B06AFC49AF59EULL,
		0x173B517C5AF1EE5AULL,
		0x64C758B33BD2A617ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7A1F94939891C17ULL,
		0x5DD3E1675C1AA864ULL,
		0xF979116AC070BB50ULL,
		0x78BB4FA83988951EULL,
		0xAE52B0C3FE42437AULL,
		0xC351D16F610D7EA7ULL,
		0x255CAAE14ECA5830ULL,
		0xEAC513C2D9FDEEA1ULL
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
		0x7A02F568E44B834AULL,
		0x838DC27FC3916493ULL,
		0x91FD4D7227832E35ULL,
		0xDF0FD5F489B49E1DULL,
		0x801279758AC9EF1CULL,
		0xDCA54AD34DDC58E8ULL,
		0x639EB2D9128EFDB7ULL,
		0xE9CABEDDC7171D59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F69ABBB4409E4A4ULL,
		0x9A64CCB1E0840BD7ULL,
		0x4896674E326A46DFULL,
		0x2006C9EE48F7FDC6ULL,
		0xFFA2B929FE11C3ADULL,
		0xBBE49A0B13529B75ULL,
		0x53A6ED89797DE215ULL,
		0xD866705518C36E67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A9949ADA0419EA6ULL,
		0xE928F5CDE30D58BCULL,
		0x4966E623F518E755ULL,
		0xBF090C0640BCA057ULL,
		0x806FC04B8CB82B6FULL,
		0x20C0B0C83A89BD72ULL,
		0x0FF7C54F99111BA2ULL,
		0x11644E88AE53AEF2ULL
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
		0x049195E05E6D6445ULL,
		0x8ADBAF8F868B2C9DULL,
		0x282FECBE7CA6955DULL,
		0x1CD060BD40209EE6ULL,
		0x5B0F484AF78010BFULL,
		0x5E694E9AF2B02309ULL,
		0xEB6899B22FEE271BULL,
		0x9E871EB0ACACF4F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91F5EE144493ACCULL,
		0xFB5C630790885BCCULL,
		0x9142486D18B5363EULL,
		0xAC8C0D5C9F77CC81ULL,
		0xA39F3C5AA08CB4B8ULL,
		0xE83EAE55116A4AFFULL,
		0x8574C5F347F0D879ULL,
		0x1BDC3EF6DB096053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B7236FF1A242979ULL,
		0x8F7F4C87F602D0D0ULL,
		0x96EDA45163F15F1EULL,
		0x70445360A0A8D264ULL,
		0xB7700BF056F35C06ULL,
		0x762AA045E145D809ULL,
		0x65F3D3BEE7FD4EA1ULL,
		0x82AADFB9D1A394A2ULL
	}};
	sign = 0;
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
		0x7FF065BFCF30A8D5ULL,
		0x76D9DD58344E00DEULL,
		0x3C4AD8BCC6480F4AULL,
		0x818D73C97D9CCA81ULL,
		0x494D8143E63E77E2ULL,
		0x14338C49EE6781C1ULL,
		0x61B654EA3CBAEA0BULL,
		0x233DEAFDE28F145FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A45D0A6E11075FDULL,
		0x5BBE93AC83A1D7E2ULL,
		0x3891221AD89AF2FBULL,
		0x0A26F76AB69C69DCULL,
		0x27F78F76D6F71065ULL,
		0x53852C990F1DBB0FULL,
		0xA24D89DA0D6FC000ULL,
		0x01CA5CD746D78C95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25AA9518EE2032D8ULL,
		0x1B1B49ABB0AC28FCULL,
		0x03B9B6A1EDAD1C4FULL,
		0x77667C5EC70060A5ULL,
		0x2155F1CD0F47677DULL,
		0xC0AE5FB0DF49C6B2ULL,
		0xBF68CB102F4B2A0AULL,
		0x21738E269BB787C9ULL
	}};
	sign = 0;
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
		0x8B6FB8479AA17BD1ULL,
		0xB04FDA9DD7FF0B6EULL,
		0xA8FA7C4A8CEA29EFULL,
		0x7CE808CFFEAEAB71ULL,
		0xC4221F084E2C238EULL,
		0xEBDD4AA291E397A4ULL,
		0x1B8CCD4D6C5177BBULL,
		0x23330AF0C4E56A09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x359484BC6CC0CA4FULL,
		0x2DD87DBA59E94122ULL,
		0xABC941717CF0B537ULL,
		0xB69B41EB0F572E79ULL,
		0x8B10D4068F75FA07ULL,
		0xD5D604E53EAD919AULL,
		0xCAEF168EB5CD0E71ULL,
		0xEE78C2B8CBA29CA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55DB338B2DE0B182ULL,
		0x82775CE37E15CA4CULL,
		0xFD313AD90FF974B8ULL,
		0xC64CC6E4EF577CF7ULL,
		0x39114B01BEB62986ULL,
		0x160745BD5336060AULL,
		0x509DB6BEB684694AULL,
		0x34BA4837F942CD63ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x06DF82C0AB04131AULL,
		0x9524E4403D7F9BBCULL,
		0x1969B469B46598B7ULL,
		0xE9563D3F863269D0ULL,
		0xDFD20C604E6A48A9ULL,
		0x68A64CB59A3C25A0ULL,
		0x0D66AE3F81298571ULL,
		0xA46814A271CFE100ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A702922C99412BDULL,
		0xF445BCB11CE9A2DCULL,
		0x5D59048ABA364634ULL,
		0x7BC4E3F20D019BA2ULL,
		0x18C2E4BDB4BCDE50ULL,
		0x0DD573333FA8FE2EULL,
		0x5ED4C3A85D183BCAULL,
		0x6BD6BA1F532CA57BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC6F599DE170005DULL,
		0xA0DF278F2095F8DFULL,
		0xBC10AFDEFA2F5282ULL,
		0x6D91594D7930CE2DULL,
		0xC70F27A299AD6A59ULL,
		0x5AD0D9825A932772ULL,
		0xAE91EA97241149A7ULL,
		0x38915A831EA33B84ULL
	}};
	sign = 0;
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
		0xDB7DCA9914371A12ULL,
		0xA138CD2EBF1D7E6CULL,
		0xC8A79F321316C7FEULL,
		0x988C0ED0A5657761ULL,
		0xCADC73C5A0907EFFULL,
		0x44C6B38FD7015233ULL,
		0x471C134394E31B3DULL,
		0x01BAFF1A80F0922DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CCC0FDCA11BE3E6ULL,
		0x726DE924445DCB2FULL,
		0xD96B770D1842ADCDULL,
		0xD2A02E855DECC549ULL,
		0xFA589D6192898FC6ULL,
		0x6A8D4EC30C1C7BAFULL,
		0x471E5FE5B40FA945ULL,
		0x06E055C407C2C8DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB1BABC731B362CULL,
		0x2ECAE40A7ABFB33DULL,
		0xEF3C2824FAD41A31ULL,
		0xC5EBE04B4778B217ULL,
		0xD083D6640E06EF38ULL,
		0xDA3964CCCAE4D683ULL,
		0xFFFDB35DE0D371F7ULL,
		0xFADAA956792DC94EULL
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
		0xEA2A1BD5C8C81E9CULL,
		0x8A3062A8C45DC8EFULL,
		0xA29DD53F2C867B12ULL,
		0x2A846CE2FDC5DD13ULL,
		0x67E7A979FE3B7E9BULL,
		0x5B004C08DB6AFC41ULL,
		0xA57CCF7BFF579633ULL,
		0x800F53794B1E8EB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E2BEFFF610BFCDULL,
		0x5272F907D0C44066ULL,
		0xC44593141FF10FE0ULL,
		0x228F55407F87CB16ULL,
		0xA89A67EDC9BD4BD3ULL,
		0x01AD06DD39671E60ULL,
		0xFD10D6D3D0EFA875ULL,
		0xABB546C5ABD88FF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91475CD5D2B75ECFULL,
		0x37BD69A0F3998889ULL,
		0xDE58422B0C956B32ULL,
		0x07F517A27E3E11FCULL,
		0xBF4D418C347E32C8ULL,
		0x5953452BA203DDE0ULL,
		0xA86BF8A82E67EDBEULL,
		0xD45A0CB39F45FEBBULL
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
		0x550B934E4BE77AB4ULL,
		0xFF058C856F50DA3AULL,
		0x06D4AABDA0ABFBDAULL,
		0x47DF0C44B7A03AF0ULL,
		0x6A47A8E3069E5091ULL,
		0xBF7FDAC85D4D1DACULL,
		0x95FBEC806B6610BCULL,
		0xFC3693B1A2666D9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x572BDAF102B019D8ULL,
		0x11704AAD364DAC8AULL,
		0x8ACBBF7B6715F679ULL,
		0xEAE63B09E2BD1E55ULL,
		0x4E1726EDE98BC016ULL,
		0xCEF7CD3FAB63AD92ULL,
		0x38778612F4040DB7ULL,
		0x752E1A30A636C22DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDDFB85D493760DCULL,
		0xED9541D839032DAFULL,
		0x7C08EB4239960561ULL,
		0x5CF8D13AD4E31C9AULL,
		0x1C3081F51D12907AULL,
		0xF0880D88B1E9701AULL,
		0x5D84666D77620304ULL,
		0x87087980FC2FAB6DULL
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
		0xED1E3C569EC91741ULL,
		0x621DE48656FF0D23ULL,
		0x1E73C4E2E6EC1B1EULL,
		0x57007AC3AD6F9C1DULL,
		0x3B3A0CE5FC62E893ULL,
		0xA532EAAD0697766FULL,
		0xCB1D9F0744F95109ULL,
		0x203B48F63B6C61F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6602DDC447A35343ULL,
		0xB2650EB76158C6E9ULL,
		0xAD9548CED59CE379ULL,
		0xBD95898BBBA03866ULL,
		0x8DCCD01FE8541C24ULL,
		0xE38F3D5955A04F07ULL,
		0x5D6AA6BE3E71AB31ULL,
		0xAEB2A3C11FD08D05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x871B5E925725C3FEULL,
		0xAFB8D5CEF5A6463AULL,
		0x70DE7C14114F37A4ULL,
		0x996AF137F1CF63B6ULL,
		0xAD6D3CC6140ECC6EULL,
		0xC1A3AD53B0F72767ULL,
		0x6DB2F8490687A5D7ULL,
		0x7188A5351B9BD4F2ULL
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
		0x29B72578D7A302B1ULL,
		0xE25C4E0B3AD1495AULL,
		0x1E4C767F5C26F44BULL,
		0xBC10FB2697102E2EULL,
		0x1EB5AEA7A5D7CFF0ULL,
		0x5A8341192BE7F53FULL,
		0xF6F38605DC663303ULL,
		0xDF0D574A8716939CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B272A2BC985888ULL,
		0x55C21B56971F0786ULL,
		0xBA3CCF57B5AA4607ULL,
		0x6B05366B65C82F97ULL,
		0x89175B84D48DD8F2ULL,
		0xBDD33D233C4D15FEULL,
		0x044537FC577BC169ULL,
		0x162F72DE61F547FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5904B2D61B0AAA29ULL,
		0x8C9A32B4A3B241D3ULL,
		0x640FA727A67CAE44ULL,
		0x510BC4BB3147FE96ULL,
		0x959E5322D149F6FEULL,
		0x9CB003F5EF9ADF40ULL,
		0xF2AE4E0984EA7199ULL,
		0xC8DDE46C25214B9DULL
	}};
	sign = 0;
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
		0x8E677D51882E70B4ULL,
		0x2703893F9A92C1A3ULL,
		0xD3927D0F6E021A1DULL,
		0xC27CA81B3119E1F3ULL,
		0x98C593F81C273227ULL,
		0x7A4AD0BBEB20981FULL,
		0x954DB95C05C74172ULL,
		0xADF1D733E732BF5FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x535107653191BFC3ULL,
		0x35DEB705074CC59BULL,
		0x5F29EAED84E3193FULL,
		0x87B2DCDFB6622819ULL,
		0xD66B67851C9EC8BAULL,
		0x1D2733BF0D270883ULL,
		0xBC629AC584A0986FULL,
		0xB7AA9EDD522CFE28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B1675EC569CB0F1ULL,
		0xF124D23A9345FC08ULL,
		0x74689221E91F00DDULL,
		0x3AC9CB3B7AB7B9DAULL,
		0xC25A2C72FF88696DULL,
		0x5D239CFCDDF98F9BULL,
		0xD8EB1E968126A903ULL,
		0xF64738569505C136ULL
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
		0x27E410E253A97981ULL,
		0xA70EC37AB5DEAD07ULL,
		0xA1AB894046559E8CULL,
		0x49854C169F84F9B3ULL,
		0x9B37DAF37F74C37FULL,
		0x144CB4874E620EA9ULL,
		0xAEBFFC2DFF4DE383ULL,
		0x13DD05CEC51C0FFFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21BA08185EB632C6ULL,
		0x37C428FD1E5B14F2ULL,
		0xDBB97C33B380055AULL,
		0x0802C4F296AC84FAULL,
		0x298D5E03F5B8D6F3ULL,
		0xCCDBDB60C55B539DULL,
		0x44C15C138D64A59BULL,
		0x250B2A559D856340ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x062A08C9F4F346BBULL,
		0x6F4A9A7D97839815ULL,
		0xC5F20D0C92D59932ULL,
		0x4182872408D874B8ULL,
		0x71AA7CEF89BBEC8CULL,
		0x4770D9268906BB0CULL,
		0x69FEA01A71E93DE7ULL,
		0xEED1DB792796ACBFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF76C1657B574B943ULL,
		0x2DFF2B7B7C032E16ULL,
		0xDEC96B55C9F33859ULL,
		0x50BF7C842456ED57ULL,
		0xCF1A407909D4DE12ULL,
		0xC70F01C804C4BF86ULL,
		0x62D6C80FDF4EF787ULL,
		0xB0D1DB08FBA24D4CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38777875BD428952ULL,
		0xDD790CCFDE055AB3ULL,
		0x810B7700CC4F89AFULL,
		0x4FADD2582EF78DC0ULL,
		0x8C0D8CA443BE28D8ULL,
		0x51CAA5B1F2D9E1B7ULL,
		0x95427F63B34BAD8FULL,
		0xE94D7C78F1EF3931ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEF49DE1F8322FF1ULL,
		0x50861EAB9DFDD363ULL,
		0x5DBDF454FDA3AEA9ULL,
		0x0111AA2BF55F5F97ULL,
		0x430CB3D4C616B53AULL,
		0x75445C1611EADDCFULL,
		0xCD9448AC2C0349F8ULL,
		0xC7845E9009B3141AULL
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
		0x4A76697CA9BA2289ULL,
		0x3B7BAA73DD916FC5ULL,
		0x1ABE3674FD8C705AULL,
		0x93D0650539BC304BULL,
		0x14F31FFF2A1F5C2DULL,
		0x89DC767AD6AA18F0ULL,
		0x54D4B6A10EEC8D84ULL,
		0x3A5206F3F3878156ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x190B7A3EFE574802ULL,
		0x3C4296AE08A1D9B2ULL,
		0x0DB6F873D2611DB8ULL,
		0x3982D0776E2EBC2CULL,
		0xA48605512E9F3FD7ULL,
		0x7E00C4751C56D3E5ULL,
		0xB528ED9286E4ECE8ULL,
		0xC9950790196DABADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x316AEF3DAB62DA87ULL,
		0xFF3913C5D4EF9613ULL,
		0x0D073E012B2B52A1ULL,
		0x5A4D948DCB8D741FULL,
		0x706D1AADFB801C56ULL,
		0x0BDBB205BA53450AULL,
		0x9FABC90E8807A09CULL,
		0x70BCFF63DA19D5A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x71E83C517956501AULL,
		0xD243201C6E020DAEULL,
		0xF8BA3375B4CBCEA5ULL,
		0x344AA6F403822F8BULL,
		0x240BA3152765D9BBULL,
		0xA66603A0E9212166ULL,
		0xE79D36292AE070B5ULL,
		0xF53EA6EE8692BC7AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B95F9FF24123D1ULL,
		0x8217831054FB8A9AULL,
		0x4A0CA06FCFAF36D1ULL,
		0x9362C7A1BA714052ULL,
		0x69E53A7FA5285727ULL,
		0x5A012540ED0D9147ULL,
		0x5A56EF30CAE6D1A0ULL,
		0x506F90E70A69F134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x802EDCB187152C49ULL,
		0x502B9D0C19068313ULL,
		0xAEAD9305E51C97D4ULL,
		0xA0E7DF524910EF39ULL,
		0xBA266895823D8293ULL,
		0x4C64DE5FFC13901EULL,
		0x8D4646F85FF99F15ULL,
		0xA4CF16077C28CB46ULL
	}};
	sign = 0;
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
		0x017702083F7FD6F2ULL,
		0xA041F09E606DCA39ULL,
		0x8F289A0D7CD5DD14ULL,
		0x38CE043E8FDEAA08ULL,
		0x85842D75F86AF662ULL,
		0x910FC4327BB35926ULL,
		0x1D5EBFCB4CBD0D01ULL,
		0x5BD6322B1D7D9B16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D782B8724FFA9F3ULL,
		0x9605955919C74FD7ULL,
		0xE39F7CEE4FBA72E4ULL,
		0x103EEEF49C99D2D1ULL,
		0x1F5C622CD2205473ULL,
		0x8DE655D6A1B3E528ULL,
		0x372CFC003DCFEEA7ULL,
		0xCB6CDE59D528C9ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3FED6811A802CFFULL,
		0x0A3C5B4546A67A61ULL,
		0xAB891D1F2D1B6A30ULL,
		0x288F1549F344D736ULL,
		0x6627CB49264AA1EFULL,
		0x03296E5BD9FF73FEULL,
		0xE631C3CB0EED1E5AULL,
		0x906953D14854D169ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7762C9EBB493032EULL,
		0x5FB48DC732AA2724ULL,
		0xE32D9B141A0EFFC0ULL,
		0x44033240BD90F799ULL,
		0x072E20E81204A2FBULL,
		0x9CB32E5453F337FCULL,
		0x4C21514F72A5945BULL,
		0x6F9550F8BDB470E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB7BAC5698DF170ULL,
		0x6D9376E3FE34392FULL,
		0x5FE5D93A1DF159AFULL,
		0xC0D844DB55787ED5ULL,
		0xE6E9E9727AE5BB36ULL,
		0x10D4DDB181F49527ULL,
		0xF9752FA4BC29FFD2ULL,
		0x10CAF37CE37106C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BAB0F264B0511BEULL,
		0xF22116E33475EDF5ULL,
		0x8347C1D9FC1DA610ULL,
		0x832AED65681878C4ULL,
		0x20443775971EE7C4ULL,
		0x8BDE50A2D1FEA2D4ULL,
		0x52AC21AAB67B9489ULL,
		0x5ECA5D7BDA436A24ULL
	}};
	sign = 0;
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
		0x09DB46F631635486ULL,
		0x548C66055533C8C1ULL,
		0x288B82A61CC150E9ULL,
		0x4EF0976B371F8192ULL,
		0x24A371F79846663FULL,
		0x9888719E6AED09C1ULL,
		0x8772E864013333D8ULL,
		0xAC0FF4598E742394ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AEA1BA8F3850CC4ULL,
		0x905F71F0746122D5ULL,
		0x49BD97FA62594514ULL,
		0xCCD026080DC26FFFULL,
		0x660877298AA349ABULL,
		0x83F89E3347DC0715ULL,
		0x1B9F869658AF80DAULL,
		0x227AB07B4E545B6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EF12B4D3DDE47C2ULL,
		0xC42CF414E0D2A5EBULL,
		0xDECDEAABBA680BD4ULL,
		0x82207163295D1192ULL,
		0xBE9AFACE0DA31C93ULL,
		0x148FD36B231102ABULL,
		0x6BD361CDA883B2FEULL,
		0x899543DE401FC828ULL
	}};
	sign = 0;
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
		0x25A4FC588B2EBB54ULL,
		0x020560C60C8EF05EULL,
		0xC430BF8A8E66A537ULL,
		0x2E8760A8AE60CAAEULL,
		0x2DE3376381AE3DDEULL,
		0xC2E4E4C7FAFFA412ULL,
		0x53A5DA608AC8760FULL,
		0xD23AE94D14AC9A2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2337C3FBF88A809ULL,
		0x5DDB554B601041A3ULL,
		0x46D479793E77BA7CULL,
		0x2B907C539B83B01DULL,
		0x00FC03B183A7C028ULL,
		0xA54DCDBCC0313D53ULL,
		0x20AA5307817AD182ULL,
		0x938555F5BBBD697AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83718018CBA6134BULL,
		0xA42A0B7AAC7EAEBAULL,
		0x7D5C46114FEEEABAULL,
		0x02F6E45512DD1A91ULL,
		0x2CE733B1FE067DB6ULL,
		0x1D97170B3ACE66BFULL,
		0x32FB8759094DA48DULL,
		0x3EB5935758EF30B1ULL
	}};
	sign = 0;
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
		0x857E23CFE13416D0ULL,
		0x58B576AE34C84D5AULL,
		0xF8EB66E1860DFA6CULL,
		0x3728B291D02FFD5DULL,
		0xFF084095A7CB6D21ULL,
		0x8F70EF010D1BAB7BULL,
		0x5AEFE4BDFAFC1E90ULL,
		0x3FC50689048CF169ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB80FB8795DC319ULL,
		0x9C2E47A30385F6DAULL,
		0xA266D2DA611D6EA0ULL,
		0xC7F7D15FD38406E2ULL,
		0xBD66C92B7A8C1919ULL,
		0x0ED1D740C2993368ULL,
		0x8EE54DF6CCBA115FULL,
		0x0191C7235A713981ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AC6141767D653B7ULL,
		0xBC872F0B3142567FULL,
		0x5684940724F08BCBULL,
		0x6F30E131FCABF67BULL,
		0x41A1776A2D3F5407ULL,
		0x809F17C04A827813ULL,
		0xCC0A96C72E420D31ULL,
		0x3E333F65AA1BB7E7ULL
	}};
	sign = 0;
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
		0x8C4F976B315B6D5CULL,
		0xC193F9A82F4D30ECULL,
		0xCC34C091E462D5C5ULL,
		0x9EAEBEC641A18DF2ULL,
		0x919F1DD3BDEF4C80ULL,
		0xD7DB8DF9CD761455ULL,
		0x639B611EF70DD6F9ULL,
		0x57BF57BF97E1969AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9615736DB612A03BULL,
		0x7234E66933167B37ULL,
		0x36E2A8D58689A3C4ULL,
		0x0BFE48B0718D2310ULL,
		0x18CA324E5B1C9794ULL,
		0x074DCE9AB7A41F7EULL,
		0x6147D6CEDE85C72CULL,
		0xFA28C6FD59DD354AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF63A23FD7B48CD21ULL,
		0x4F5F133EFC36B5B4ULL,
		0x955217BC5DD93201ULL,
		0x92B07615D0146AE2ULL,
		0x78D4EB8562D2B4ECULL,
		0xD08DBF5F15D1F4D7ULL,
		0x02538A5018880FCDULL,
		0x5D9690C23E046150ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7742F651D0D9B274ULL,
		0xC6CF167C7482A774ULL,
		0x820696014F59FDEAULL,
		0x895C5E0438C7E10BULL,
		0xDA8C37DAFDD0B531ULL,
		0x358EF8830AB1F7E7ULL,
		0xC29984803CF0FEFCULL,
		0xED4E6892C90DF173ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3716C7BDE1B0EF0AULL,
		0x2DCCEA1793136692ULL,
		0xFFEB66645C5576B3ULL,
		0xE13323001A26B100ULL,
		0x98E481DBE711D3E9ULL,
		0xBD439FA6F4C06BABULL,
		0xCFFD32852352DA18ULL,
		0xE4C765FD90EBEA63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402C2E93EF28C36AULL,
		0x99022C64E16F40E2ULL,
		0x821B2F9CF3048737ULL,
		0xA8293B041EA1300AULL,
		0x41A7B5FF16BEE147ULL,
		0x784B58DC15F18C3CULL,
		0xF29C51FB199E24E3ULL,
		0x088702953822070FULL
	}};
	sign = 0;
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
		0x34C94599B6191AF8ULL,
		0x9EAF89A828D769E1ULL,
		0x9FF83E68EBEF7678ULL,
		0xF5121989408AEA9DULL,
		0x594A73C9E68C96A8ULL,
		0x1639589B2895555DULL,
		0xAC7AEA44669AB556ULL,
		0x7BE3D22A0251C7F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF824394825E98CE1ULL,
		0x6F25AB2FDB38C8D7ULL,
		0x42D3F2B64B07D16BULL,
		0x9B2AABCB7AC32D9BULL,
		0xB1FD756676939BE4ULL,
		0xBA73F1F066DD7E26ULL,
		0xA5D705A933D16558ULL,
		0xE4CACD9919FAFCCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CA50C51902F8E17ULL,
		0x2F89DE784D9EA109ULL,
		0x5D244BB2A0E7A50DULL,
		0x59E76DBDC5C7BD02ULL,
		0xA74CFE636FF8FAC4ULL,
		0x5BC566AAC1B7D736ULL,
		0x06A3E49B32C94FFDULL,
		0x97190490E856CB28ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAC5FFD14A8771E33ULL,
		0x2C0685878CA9C5CEULL,
		0xA42D281ADDF4164FULL,
		0x1E6DB3FC167218D0ULL,
		0xA2F8131B5A7A2BE9ULL,
		0xC935907FC35C6F5FULL,
		0x729159C27DC48108ULL,
		0x28DE1FA1C0FC0C54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16545DE6B0BBD212ULL,
		0x1BEE5EBFEFB8A57EULL,
		0xD92DD48E5B7F4B2EULL,
		0xE195F2A6DD67D4A2ULL,
		0xC2A0E63D232C6B8BULL,
		0x2B9AC47DCAB99D44ULL,
		0x636AFAB016B1DA57ULL,
		0x30402DED10497A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x960B9F2DF7BB4C21ULL,
		0x101826C79CF12050ULL,
		0xCAFF538C8274CB21ULL,
		0x3CD7C155390A442DULL,
		0xE0572CDE374DC05DULL,
		0x9D9ACC01F8A2D21AULL,
		0x0F265F126712A6B1ULL,
		0xF89DF1B4B0B29251ULL
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
		0x895CB73949307DEAULL,
		0xDF51825F4DF84CE0ULL,
		0x0EE12AC4CC428B7EULL,
		0x0C6585F6B99B9648ULL,
		0xB25D7C6983E40D32ULL,
		0xE8F94D5671DCE44AULL,
		0x40F0E2D78FE41468ULL,
		0xEAFFE364EFB304A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7382FCFC6AB73CB6ULL,
		0x3475E52C4CA3E6C2ULL,
		0xE5CDA5A27547AA0EULL,
		0xBF6D4DF470E8942DULL,
		0x0636823B391822A3ULL,
		0xE5DE397FE666507AULL,
		0x1B906D4EE820A1A8ULL,
		0xA9A8314BC80D7B3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15D9BA3CDE794134ULL,
		0xAADB9D330154661EULL,
		0x2913852256FAE170ULL,
		0x4CF8380248B3021AULL,
		0xAC26FA2E4ACBEA8EULL,
		0x031B13D68B7693D0ULL,
		0x25607588A7C372C0ULL,
		0x4157B21927A58968ULL
	}};
	sign = 0;
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
		0x294CA3B6D49AB8E0ULL,
		0xA188B1531986DCD2ULL,
		0x9D9364C921D4282FULL,
		0x5896C9702B4E4EC2ULL,
		0xE34CCDB125CE5E87ULL,
		0x1440CB0640D9C90FULL,
		0x1FEDB0416021DECBULL,
		0x1848B831F0160A0CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF913F4F13DF271D3ULL,
		0xCC98755DC133C49DULL,
		0xE71D5C989C7BE961ULL,
		0x4B70B7BEA34EBC46ULL,
		0xE2E8CFCA3AB79E21ULL,
		0xA048B0E98C3248DFULL,
		0x13C68F5CA5E485ACULL,
		0xCDD56684159E04B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3038AEC596A8470DULL,
		0xD4F03BF558531834ULL,
		0xB676083085583ECDULL,
		0x0D2611B187FF927BULL,
		0x0063FDE6EB16C066ULL,
		0x73F81A1CB4A78030ULL,
		0x0C2720E4BA3D591EULL,
		0x4A7351ADDA780557ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x92926CDA0D101DCAULL,
		0xFCCB90A1046A4203ULL,
		0x44DEA6E43A6DFC49ULL,
		0x4FFC19CE5997559EULL,
		0x1E006A8A38C3F587ULL,
		0x565F8EE3DA14F24CULL,
		0x668783DD9040BF05ULL,
		0xA41B59063F2FA84BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x486DFB26B7C31DF0ULL,
		0x3F13923B67669803ULL,
		0x7951A7E344F035AEULL,
		0x938F371F1B27A478ULL,
		0x764DB72F3A36E43EULL,
		0x6B33F44DB7AD5202ULL,
		0x36624C1733C3A6B4ULL,
		0x5C72B19EA95D85FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A2471B3554CFFDAULL,
		0xBDB7FE659D03AA00ULL,
		0xCB8CFF00F57DC69BULL,
		0xBC6CE2AF3E6FB125ULL,
		0xA7B2B35AFE8D1148ULL,
		0xEB2B9A962267A049ULL,
		0x302537C65C7D1850ULL,
		0x47A8A76795D2224EULL
	}};
	sign = 0;
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
		0xBD63B489179EE0F5ULL,
		0xEFDEC023D017C87AULL,
		0xF6F87C3565A033B4ULL,
		0x7B8FC74D955C8043ULL,
		0x576FCE2D0FB732C5ULL,
		0xE607BAE8D980A585ULL,
		0xB0E716E126C80088ULL,
		0x869A9B6C7D0F0D78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B6EE088A17E9FCULL,
		0x36DA4D527E9B83B6ULL,
		0x2ADF222FCE460C0FULL,
		0x71F7605760FEB59AULL,
		0x2EB92AF190387DFFULL,
		0xBF252341F3FF4F00ULL,
		0x47095DC34B568049ULL,
		0xBAA477B1626B9EE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37ACC6808D86F6F9ULL,
		0xB90472D1517C44C4ULL,
		0xCC195A05975A27A5ULL,
		0x099866F6345DCAA9ULL,
		0x28B6A33B7F7EB4C6ULL,
		0x26E297A6E5815685ULL,
		0x69DDB91DDB71803FULL,
		0xCBF623BB1AA36E92ULL
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
		0x792E5FE94AF7AF00ULL,
		0xE862D2D507CCB45AULL,
		0x04B444F70FF01168ULL,
		0xA267F9FD74C30541ULL,
		0x8A5CD95ADC4E746CULL,
		0xD376B0C7F4F07A7BULL,
		0xCC579F66D6A81521ULL,
		0x482AD96FA86CA28DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B0403867CDD59DBULL,
		0x3A53F8D3064D4C1CULL,
		0x66E926990A11890AULL,
		0x2DB84D83E7B4BA18ULL,
		0xC389DC41E3442003ULL,
		0x617921B76BC6E621ULL,
		0x0960ECE6CD13053AULL,
		0xACE07EEA5CF517CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E2A5C62CE1A5525ULL,
		0xAE0EDA02017F683EULL,
		0x9DCB1E5E05DE885EULL,
		0x74AFAC798D0E4B28ULL,
		0xC6D2FD18F90A5469ULL,
		0x71FD8F1089299459ULL,
		0xC2F6B28009950FE7ULL,
		0x9B4A5A854B778ABEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2263B2E8DCDAE1C2ULL,
		0x9C4F5C9B1DED5524ULL,
		0xA28D9C0C374C94DDULL,
		0xDF200CAAB05F3CC1ULL,
		0x95874BE8875E01A8ULL,
		0x67738405F726A5EFULL,
		0x549A5056E5DE0B93ULL,
		0x667891F1D43C73B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC96632308E7CA8E8ULL,
		0xA14DE846B5A73C04ULL,
		0x123C94450580AF5DULL,
		0xADD53BC8F49735C8ULL,
		0x5D1E60C71626B866ULL,
		0xB1B82AEFDC3A2012ULL,
		0xC78011F850B777BAULL,
		0xD750CC6B1077C1DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58FD80B84E5E38DAULL,
		0xFB0174546846191FULL,
		0x905107C731CBE57FULL,
		0x314AD0E1BBC806F9ULL,
		0x3868EB2171374942ULL,
		0xB5BB59161AEC85DDULL,
		0x8D1A3E5E952693D8ULL,
		0x8F27C586C3C4B1D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAEFB766290C4183CULL,
		0x4B424E742ACBBFA0ULL,
		0x8DA7524478A85F7AULL,
		0xCCBBE5DB9439B9D1ULL,
		0xAD1BC36F0CDD8EE9ULL,
		0xFB512EC03994C8B0ULL,
		0xD887C171E7DBD8B4ULL,
		0x64524918C08A7302ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB208BD22AAAF2C8ULL,
		0x1E308F358E589A55ULL,
		0x029330D4EB69FABCULL,
		0x8A18ECEF2563C3E7ULL,
		0xF35768BF35DEC964ULL,
		0x16BC9CC700AEF722ULL,
		0x710180F68EA0AB35ULL,
		0x65AD79AC9068065DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3DAEA9066192574ULL,
		0x2D11BF3E9C73254AULL,
		0x8B14216F8D3E64BEULL,
		0x42A2F8EC6ED5F5EAULL,
		0xB9C45AAFD6FEC585ULL,
		0xE49491F938E5D18DULL,
		0x6786407B593B2D7FULL,
		0xFEA4CF6C30226CA5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5B7A6D343D72F08DULL,
		0xEC8E2CD86D3CBC7DULL,
		0x5905B87E1628F583ULL,
		0xA01675AC6D0B2479ULL,
		0xB251E056C537AA01ULL,
		0x080E5C292FFF6CBBULL,
		0x1689A286C9E8799CULL,
		0x3BACA3BC2C365D67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD77CD1FEAE269DCULL,
		0xE74A66D21D169AD5ULL,
		0xE1E77A7B879D7648ULL,
		0x835915336B4F9B3EULL,
		0x38CDD4BF6BB5F223ULL,
		0x619D94E12AA5050AULL,
		0xC989DE1A2591CE0FULL,
		0x10FE1957281469DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E02A014529086B1ULL,
		0x0543C606502621A7ULL,
		0x771E3E028E8B7F3BULL,
		0x1CBD607901BB893AULL,
		0x79840B975981B7DEULL,
		0xA670C748055A67B1ULL,
		0x4CFFC46CA456AB8CULL,
		0x2AAE8A650421F38CULL
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
		0x21CE6E1DB9AC33BCULL,
		0x45BDB9BEEC3AF9A7ULL,
		0x1640215D11195682ULL,
		0x88DC33B6610A2D6AULL,
		0x8D973CFD5D411FA7ULL,
		0xC1D6D26F2E2C09B6ULL,
		0xFC79E14BD4B414DFULL,
		0x97882BDBE4A67CEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x61735F0C0E6CD191ULL,
		0xB03A197DF2E38CC4ULL,
		0x6D712CD6A6A0EFB0ULL,
		0xB50BB5A1C3DBDF7CULL,
		0x924A27636686E15FULL,
		0x10292B104B97BCC1ULL,
		0x31A121E9639FDB5DULL,
		0x19AD81FC982D564AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC05B0F11AB3F622BULL,
		0x9583A040F9576CE2ULL,
		0xA8CEF4866A7866D1ULL,
		0xD3D07E149D2E4DEDULL,
		0xFB4D1599F6BA3E47ULL,
		0xB1ADA75EE2944CF4ULL,
		0xCAD8BF6271143982ULL,
		0x7DDAA9DF4C7926A0ULL
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
		0x718894FD7143E18AULL,
		0xDB2AF4D40BB4A30AULL,
		0x0ABC5BA55321B1F0ULL,
		0xE8AE4EC135E5E821ULL,
		0x4C30068FAC844383ULL,
		0xEB0806D4E574D69FULL,
		0x4A62A863B70FC1ECULL,
		0xDBBF6E5441B04CA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEFB66C4723B361ULL,
		0x2FE45ABB8A83F9E6ULL,
		0xC475DFB218EE9D6BULL,
		0x20AD0941BE7A4B5BULL,
		0x316BBFB522AB41D6ULL,
		0x9FD2044823B5F704ULL,
		0xCC33778ABAF87265ULL,
		0x8B6EA2365DB12934ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2398DE912A202E29ULL,
		0xAB469A188130A924ULL,
		0x46467BF33A331485ULL,
		0xC801457F776B9CC5ULL,
		0x1AC446DA89D901ADULL,
		0x4B36028CC1BEDF9BULL,
		0x7E2F30D8FC174F87ULL,
		0x5050CC1DE3FF236DULL
	}};
	sign = 0;
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
		0x9A24FAB82C8AA715ULL,
		0x92850FAEA2FC1AB7ULL,
		0xE3D3972570EB32D4ULL,
		0x613F34E5C3C3C6D8ULL,
		0xD7669186E1DC3D36ULL,
		0x046025FC1E28E28DULL,
		0xA7F52A4F82D7CED1ULL,
		0x644B40B740A56C3EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D60AD6EFC1B542ULL,
		0xB7552FFCBE668DDDULL,
		0x92BBA18149F60572ULL,
		0x38CD4991C3B18107ULL,
		0x0E58A81FD085CAFAULL,
		0x0BBA08C1504B7109ULL,
		0x9EEC7F69951EA81FULL,
		0x5BB06516943B0E69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE94EEFE13CC8F1D3ULL,
		0xDB2FDFB1E4958CD9ULL,
		0x5117F5A426F52D61ULL,
		0x2871EB54001245D1ULL,
		0xC90DE9671156723CULL,
		0xF8A61D3ACDDD7184ULL,
		0x0908AAE5EDB926B1ULL,
		0x089ADBA0AC6A5DD5ULL
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
		0xA2F4B6DBEE0EA6E7ULL,
		0x56F2D8049F2D47F6ULL,
		0x69D508E764F60F92ULL,
		0xA79417CCDD3C6376ULL,
		0x233E725583F1DE52ULL,
		0xF72CFB5E86FA1704ULL,
		0x992F26FF359ADE8EULL,
		0x7ABC7CE856151217ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FCAFF237102F6EAULL,
		0x45385BC3580D4DBAULL,
		0x2805E3F96ADF87DFULL,
		0x477FD5ECB8DA19D1ULL,
		0x48529528F239AEB5ULL,
		0x4640F1BB35F84666ULL,
		0x68F95CA2834F89DAULL,
		0x85B3865B61BCE148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9329B7B87D0BAFFDULL,
		0x11BA7C41471FFA3CULL,
		0x41CF24EDFA1687B3ULL,
		0x601441E0246249A5ULL,
		0xDAEBDD2C91B82F9DULL,
		0xB0EC09A35101D09DULL,
		0x3035CA5CB24B54B4ULL,
		0xF508F68CF45830CFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCE00CDEADD86D082ULL,
		0x0F5C6E8A8D4554C9ULL,
		0x4923351215C348A1ULL,
		0x1CE0D878558D9894ULL,
		0xFE5EF42548F97EF5ULL,
		0x68D1336E9FD6C41CULL,
		0xA016DF243D86601DULL,
		0x1F17798770787EA9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A915D306DFC687ULL,
		0x87BF807DF367C4A5ULL,
		0xA297CAA28AB8C785ULL,
		0xB1E57E9AF6EF7F4CULL,
		0x873A2957FE05D3ADULL,
		0xD095A0497E2B9CA0ULL,
		0x0B10359CD4B69F38ULL,
		0xDAFB313266D67150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2757B817D6A709FBULL,
		0x879CEE0C99DD9024ULL,
		0xA68B6A6F8B0A811BULL,
		0x6AFB59DD5E9E1947ULL,
		0x7724CACD4AF3AB47ULL,
		0x983B932521AB277CULL,
		0x9506A98768CFC0E4ULL,
		0x441C485509A20D59ULL
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
		0x086C097FB0AE9F73ULL,
		0x2A152D809A11F941ULL,
		0xF4D1BFA1BB20F49EULL,
		0x0433951DE0B0F65FULL,
		0xFCAF9005484689E0ULL,
		0x790644A74D4C8B80ULL,
		0xC780CF0951F7D565ULL,
		0xAF1C16C36DE74E5FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF781AA8FE61738ULL,
		0x2B4898678E862707ULL,
		0x0F8A5273CC63E0C1ULL,
		0xE5866FD474F14041ULL,
		0x9F9F294EB623727CULL,
		0x5B1820829F804B7FULL,
		0x144D28D361087E65ULL,
		0xA82CB9A32CEC793BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB7487D520C8883BULL,
		0xFECC95190B8BD239ULL,
		0xE5476D2DEEBD13DCULL,
		0x1EAD25496BBFB61EULL,
		0x5D1066B692231763ULL,
		0x1DEE2424ADCC4001ULL,
		0xB333A635F0EF5700ULL,
		0x06EF5D2040FAD524ULL
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
		0xBB84BCFCE6EC0394ULL,
		0x7D5EB77F4CC5FFA8ULL,
		0x7B706FD093A48F2CULL,
		0x126B14B373333DACULL,
		0x234CC487FB0AF0BAULL,
		0xF607AB235C76744AULL,
		0x9314A50B908FAC37ULL,
		0x1CCA8B933CD9AC96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5D58A629582A70CULL,
		0x3C283D105A860B77ULL,
		0xF769C4285FFC4D10ULL,
		0xB21B18C9DEA043C5ULL,
		0x237D706C6D2C1322ULL,
		0x0E9AD2BF1AFE4074ULL,
		0x389B692022D4FFF3ULL,
		0x7444655D837974E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5AF329A51695C88ULL,
		0x41367A6EF23FF430ULL,
		0x8406ABA833A8421CULL,
		0x604FFBE99492F9E6ULL,
		0xFFCF541B8DDEDD97ULL,
		0xE76CD864417833D5ULL,
		0x5A793BEB6DBAAC44ULL,
		0xA8862635B96037B2ULL
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
		0x8D2542029A9097D7ULL,
		0xCE5B8CF228DEDA42ULL,
		0xF037122CC888CCE4ULL,
		0xE0B4D0FD7D866F61ULL,
		0xC5A0216EB790B3D9ULL,
		0x071FF10151B1D297ULL,
		0x0394255FF131707AULL,
		0xDD5E33E903E0A5C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C06DE51065C939ULL,
		0xEEC28A94DBCAAD2DULL,
		0x666D03AA51F39AABULL,
		0xF03CC26314D605B0ULL,
		0x6777709A5901D010ULL,
		0x18E19292BC829F4DULL,
		0x0E90F9F8C321F3C5ULL,
		0xB6CE305F626282AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5864D41D8A2ACE9EULL,
		0xDF99025D4D142D15ULL,
		0x89CA0E8276953238ULL,
		0xF0780E9A68B069B1ULL,
		0x5E28B0D45E8EE3C8ULL,
		0xEE3E5E6E952F334AULL,
		0xF5032B672E0F7CB4ULL,
		0x26900389A17E231DULL
	}};
	sign = 0;
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
		0x98DDC446C81C59BBULL,
		0x3E662AF060B4DBC8ULL,
		0xD32476575D40B439ULL,
		0x2D444F49EF893852ULL,
		0x375AF40529CB810FULL,
		0x89DFB3D37AB528EAULL,
		0x738F0FFFEF44CCDDULL,
		0xBF9CC520C3734D31ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C9F09F08598D6DULL,
		0xEAB8621924A646FCULL,
		0xBB1E4E9C2DEB0064ULL,
		0x41A22A13139B8A04ULL,
		0x76DD265EBDB86874ULL,
		0x0EDB422AA77DFF0CULL,
		0x340F5F72DA4656EDULL,
		0xB651437CEE52B4C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD413D3A7BFC2CC4EULL,
		0x53ADC8D73C0E94CBULL,
		0x180627BB2F55B3D4ULL,
		0xEBA22536DBEDAE4EULL,
		0xC07DCDA66C13189AULL,
		0x7B0471A8D33729DDULL,
		0x3F7FB08D14FE75F0ULL,
		0x094B81A3D5209870ULL
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
		0xCAE5B84A3091E4D7ULL,
		0xFDC94A16C6264D9FULL,
		0x516F3DD7ADA9EB5DULL,
		0x1940F4E836082F62ULL,
		0x9640297C0CF1879CULL,
		0x2FFC56D83D4BC603ULL,
		0xE464DA3BF443903BULL,
		0x7C96377E13376A06ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x636BA027EDEB945DULL,
		0x08C42A02A1E6861DULL,
		0x2C6B0C8866C28351ULL,
		0x51CA3438587D1710ULL,
		0xD67AA28079753836ULL,
		0x705E88B4C0D6BC5DULL,
		0x3F03F1AA0B0E482EULL,
		0xDC31E9101712084BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x677A182242A6507AULL,
		0xF5052014243FC782ULL,
		0x2504314F46E7680CULL,
		0xC776C0AFDD8B1852ULL,
		0xBFC586FB937C4F65ULL,
		0xBF9DCE237C7509A5ULL,
		0xA560E891E935480CULL,
		0xA0644E6DFC2561BBULL
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
		0xA78159CBF579C325ULL,
		0x17D2C48C87EC66BBULL,
		0x9F94B68D31FAB6D0ULL,
		0xD71FF048B8D5C54DULL,
		0x2DF17D84ACBA2439ULL,
		0x5AA5E098D216BC1AULL,
		0x579952444CFD1F82ULL,
		0x03FF95C9600E794AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADF221ECEE0F8CDULL,
		0xD82B55F0F8643A9DULL,
		0x69B71E72825FEDC7ULL,
		0x8CAA08709D778E23ULL,
		0x16C1A8DA125AB9FCULL,
		0xAD7A1F506A81030AULL,
		0x7843A6B48F4B5FDDULL,
		0xBD32A112B5D2A214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCA237AD2698CA58ULL,
		0x3FA76E9B8F882C1DULL,
		0x35DD981AAF9AC908ULL,
		0x4A75E7D81B5E372AULL,
		0x172FD4AA9A5F6A3DULL,
		0xAD2BC1486795B910ULL,
		0xDF55AB8FBDB1BFA4ULL,
		0x46CCF4B6AA3BD735ULL
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
		0x417E8230570A96EEULL,
		0x4C8F067840D78A20ULL,
		0xE9BD3583618F062BULL,
		0xB74D01A2CD5B7EE3ULL,
		0x448B33A0EC6E724BULL,
		0x97682F65376C645FULL,
		0xE6639470308C7B6DULL,
		0x76752CB22F43BA7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA74CB2C244E384CULL,
		0x74159F82E5600856ULL,
		0x5BDEEE5591DED1B0ULL,
		0xEE289884715BB23AULL,
		0xF9B1F88CE3D44F0DULL,
		0x6E4C7D7E981E4219ULL,
		0xEB6856140C8DBF46ULL,
		0x95A6EDF8DE3C1BCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6709B70432BC5EA2ULL,
		0xD87966F55B7781C9ULL,
		0x8DDE472DCFB0347AULL,
		0xC924691E5BFFCCA9ULL,
		0x4AD93B14089A233DULL,
		0x291BB1E69F4E2245ULL,
		0xFAFB3E5C23FEBC27ULL,
		0xE0CE3EB951079EAEULL
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
		0x9FD0182DE96C780DULL,
		0x3AF0138B76701701ULL,
		0x8D854826B08CFD6FULL,
		0x0818022B39EAB1A8ULL,
		0xA1718A1EB88055A7ULL,
		0x0D4CBD725EC356ECULL,
		0x6482BDA55F0DE5B8ULL,
		0x8069D6610AC03D86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6DE6AD3325FF92ULL,
		0x77DFF8D2DEE62A65ULL,
		0x1AA5044761876260ULL,
		0x27298CE9BBACA6B4ULL,
		0xCA243A61E7C39F19ULL,
		0x4E63BFCDA8D91E08ULL,
		0x13848673F83D87FBULL,
		0xA702797076D18968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82623180B646787BULL,
		0xC3101AB89789EC9CULL,
		0x72E043DF4F059B0EULL,
		0xE0EE75417E3E0AF4ULL,
		0xD74D4FBCD0BCB68DULL,
		0xBEE8FDA4B5EA38E3ULL,
		0x50FE373166D05DBCULL,
		0xD9675CF093EEB41EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4CE98F1293C43462ULL,
		0xDCA902B3EFB362F0ULL,
		0xA0705EC6C2D8B08DULL,
		0xE2F9AF7494115254ULL,
		0x2C4B9E12D4A7B6D4ULL,
		0xABF7A7AF4E095316ULL,
		0x11DAC601C924F28BULL,
		0xC47497CED5468002ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB60D0B4B81D433FULL,
		0x5BF8597B4B610D70ULL,
		0x9AB9C6453AE16FCFULL,
		0x3C42E5E47357D2DEULL,
		0xFFB239A53EA45517ULL,
		0x2EA4FE43219BAC93ULL,
		0x0066205B65066485ULL,
		0xD9228C47C0075918ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7188BE5DDBA6F123ULL,
		0x80B0A938A452557FULL,
		0x05B6988187F740BEULL,
		0xA6B6C99020B97F76ULL,
		0x2C99646D960361BDULL,
		0x7D52A96C2C6DA682ULL,
		0x1174A5A6641E8E06ULL,
		0xEB520B87153F26EAULL
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
		0x9A1E46D00D1528D4ULL,
		0x32948B1FEB9D04DDULL,
		0x3CC9025F5ACAE6E2ULL,
		0x27DA5BE0C5BEAFBCULL,
		0xBBF56C007E911C92ULL,
		0x7BD244EBE220F211ULL,
		0x56D2B953D5FF9137ULL,
		0x43026AFF21FE8B78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB80C48CCF0AB8038ULL,
		0xF08AD16CA2A1F1B5ULL,
		0x56DE4CAB025BD50FULL,
		0x3EA851E970CE2840ULL,
		0xC01F20300F8A5CE1ULL,
		0xFC23B14553188617ULL,
		0xB846EEE8402D0569ULL,
		0xFF8465100F7EFA90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE211FE031C69A89CULL,
		0x4209B9B348FB1327ULL,
		0xE5EAB5B4586F11D2ULL,
		0xE93209F754F0877BULL,
		0xFBD64BD06F06BFB0ULL,
		0x7FAE93A68F086BF9ULL,
		0x9E8BCA6B95D28BCDULL,
		0x437E05EF127F90E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x24168C76B6E0C916ULL,
		0x3857CAAF310208DEULL,
		0xFC40E3673A9B89D2ULL,
		0xC6FD37274F4F802FULL,
		0xDC1C05C11FBA7556ULL,
		0xC8FDD50C67ECFBA7ULL,
		0xEAB2079C47DC6E64ULL,
		0xE5B05DFEDF041BA0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1402BF3050679A1DULL,
		0x4F94B0D4DB36B92CULL,
		0x3FC62515D6687713ULL,
		0x2D095C23E8AD0667ULL,
		0x41A2CCE98B236E35ULL,
		0x4D8444FE446AB8A5ULL,
		0x89834031BA9F2AFEULL,
		0xF809C408136559B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1013CD4666792EF9ULL,
		0xE8C319DA55CB4FB2ULL,
		0xBC7ABE51643312BEULL,
		0x99F3DB0366A279C8ULL,
		0x9A7938D794970721ULL,
		0x7B79900E23824302ULL,
		0x612EC76A8D3D4366ULL,
		0xEDA699F6CB9EC1E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1E076FD36FD634E7ULL,
		0x41C25CC4E9919E6FULL,
		0xC8F952923C54A7FEULL,
		0xAEE2062FE22C77D9ULL,
		0x29FAB7BFC76E338FULL,
		0xEDB539724FD625F9ULL,
		0x1E45723974209E72ULL,
		0x02A3FBF9C1E83334ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x938CD6C7A6F30BA6ULL,
		0xC72E93EB758C3DB5ULL,
		0xB6343E02A86C4171ULL,
		0xB7B89AF07881A66BULL,
		0x5D9286B1958D40BCULL,
		0x0C2305118EFD9959ULL,
		0x533A433482A3C90EULL,
		0x8CD084EBE186047CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A7A990BC8E32941ULL,
		0x7A93C8D9740560B9ULL,
		0x12C5148F93E8668CULL,
		0xF7296B3F69AAD16EULL,
		0xCC68310E31E0F2D2ULL,
		0xE1923460C0D88C9FULL,
		0xCB0B2F04F17CD564ULL,
		0x75D3770DE0622EB7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDFC71EC1C520F756ULL,
		0xFF8EBBC649BA0938ULL,
		0x1C93081B8C50FE93ULL,
		0xF1B554BD398A9F4DULL,
		0x7145B9A7622C076AULL,
		0xAB14D1D959EBD0F5ULL,
		0xA3ED3205853D43BBULL,
		0xE51BDFF44B5AD5F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7110364DC4D47830ULL,
		0x8EA89C77C9627575ULL,
		0x16A80FC86A1A06B0ULL,
		0x57F9BE8872E38978ULL,
		0x8EA0FCFCA390F0AFULL,
		0xBDD8E7745B9865FFULL,
		0xFA5C4EAD4B3E100DULL,
		0x777BD029265DC1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EB6E874004C7F26ULL,
		0x70E61F4E805793C3ULL,
		0x05EAF8532236F7E3ULL,
		0x99BB9634C6A715D5ULL,
		0xE2A4BCAABE9B16BBULL,
		0xED3BEA64FE536AF5ULL,
		0xA990E35839FF33ADULL,
		0x6DA00FCB24FD1421ULL
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
		0x17BC86AE28B7AC84ULL,
		0xD0589BC09CB33427ULL,
		0x02B9722406BB17F9ULL,
		0x7A84462011A94E45ULL,
		0x0B3381F4E2515084ULL,
		0x07AEDCFCEDA6D6E5ULL,
		0xED0172272F54CA8CULL,
		0x5FAB4B0C26C7A2ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2B9921A43A32D3CULL,
		0x0CEDBF6978DE7825ULL,
		0xBF3BED9DBB89298CULL,
		0x2671B5B4BF3B1E94ULL,
		0xFFA2A66FE523C242ULL,
		0x84D4DFF74762400AULL,
		0xD6DD621C1AD45AC7ULL,
		0x6BFA0360D3E5717FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2502F493E5147F48ULL,
		0xC36ADC5723D4BC01ULL,
		0x437D84864B31EE6DULL,
		0x5412906B526E2FB0ULL,
		0x0B90DB84FD2D8E42ULL,
		0x82D9FD05A64496DAULL,
		0x1624100B14806FC4ULL,
		0xF3B147AB52E2312EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA4292F83CEB46B8BULL,
		0x08DBA2770791A6F5ULL,
		0x15C94310D0647F08ULL,
		0xC01524AE23E20334ULL,
		0xE0459D9BFE774DD5ULL,
		0xEBBF0F546E8DFC4DULL,
		0xACBC0E5CED1CA670ULL,
		0xC72B4DD33EB9E73BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4579734A2349F3ULL,
		0x0D1FBD374826F113ULL,
		0x85E36E306DFB2CE7ULL,
		0xC240D32AA80E52EFULL,
		0x103075442DD8E254ULL,
		0x027A1F4773A9390DULL,
		0xB37A6AC105A006A3ULL,
		0xC1EC354347B996E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6E3B61084912198ULL,
		0xFBBBE53FBF6AB5E1ULL,
		0x8FE5D4E062695220ULL,
		0xFDD451837BD3B044ULL,
		0xD0152857D09E6B80ULL,
		0xE944F00CFAE4C340ULL,
		0xF941A39BE77C9FCDULL,
		0x053F188FF7005053ULL
	}};
	sign = 0;
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
		0x669A9D0DF3369CBEULL,
		0x93A053776554FAD5ULL,
		0x8A03399095214225ULL,
		0x7654DC51A3711CBDULL,
		0x41E66C727D6EE170ULL,
		0x7D3BC4A7B83CBF81ULL,
		0xED8026DD33269A00ULL,
		0x7BD48113D6643EC0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D5859503C65640ULL,
		0xB8A9DD8E7C1CDD5BULL,
		0x4D387F0391FB7B5EULL,
		0x26C1741697D0BDCDULL,
		0x0B381EED4AC9B858ULL,
		0x38C88B5B3C1E2B31ULL,
		0x0B20B9DA984561E5ULL,
		0x191FA297B81AAE38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EC51778EF70467EULL,
		0xDAF675E8E9381D79ULL,
		0x3CCABA8D0325C6C6ULL,
		0x4F93683B0BA05EF0ULL,
		0x36AE4D8532A52918ULL,
		0x4473394C7C1E9450ULL,
		0xE25F6D029AE1381BULL,
		0x62B4DE7C1E499088ULL
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
		0xC42A3179DF6CA0D2ULL,
		0xFFCC0DCADB1721A2ULL,
		0x1C86CF70E77FA71FULL,
		0x0B9FDE400E825C2FULL,
		0x0FE9EFD4FD22675BULL,
		0x399B37FDC58E1FABULL,
		0xF669A966E7922D93ULL,
		0x4C45CC82487BC47EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12174BCF49EEFCC4ULL,
		0xF2B2FB00231B86BEULL,
		0xF06FC35B6E63FEFFULL,
		0xCDAD9412DDEF64E0ULL,
		0x3F2CFDB26F902517ULL,
		0x085AB3277AA16B99ULL,
		0x2B0503DB7299E1C8ULL,
		0x880409F3BDBD44B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB212E5AA957DA40EULL,
		0x0D1912CAB7FB9AE4ULL,
		0x2C170C15791BA820ULL,
		0x3DF24A2D3092F74EULL,
		0xD0BCF2228D924243ULL,
		0x314084D64AECB411ULL,
		0xCB64A58B74F84BCBULL,
		0xC441C28E8ABE7FCEULL
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
		0x3B7B62FA5D5A0957ULL,
		0x20CA86DB323EFF2AULL,
		0xE19ABCCDB62DD6E6ULL,
		0x2918B3D695592ABDULL,
		0x4AAE571A1166CDAAULL,
		0xC60C84DE47F33BB3ULL,
		0x482A1C25F79BC280ULL,
		0xA4E79451F8D64932ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3400697627AB6269ULL,
		0x586A4FC080D09B33ULL,
		0xDB336A38219C1F9EULL,
		0xB54C6C44554C8136ULL,
		0x262C021A65B72A44ULL,
		0xC4F1B97CD382058BULL,
		0xA68BB21DA4178D97ULL,
		0x08DC5BBB9D04A574ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077AF98435AEA6EEULL,
		0xC860371AB16E63F7ULL,
		0x066752959491B747ULL,
		0x73CC4792400CA987ULL,
		0x248254FFABAFA365ULL,
		0x011ACB6174713628ULL,
		0xA19E6A08538434E9ULL,
		0x9C0B38965BD1A3BDULL
	}};
	sign = 0;
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
		0xA4C2408B59F01E05ULL,
		0xE11381E2A23923CBULL,
		0xE98A09136B03FA6EULL,
		0x7EAB87D5A191AA09ULL,
		0x9CCE09EDE7E28283ULL,
		0x43E4732002AA75E8ULL,
		0x856B020548AB29A5ULL,
		0x7D3BB705FD06564CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F66D35BD3A8F3BEULL,
		0xD3ACE4595A957B53ULL,
		0xDB92584090D9113FULL,
		0x1E6ACA55226C951BULL,
		0xFB6D7A6D014ACFCDULL,
		0x844EFB3BF5964A56ULL,
		0x922377BC8AAE75E7ULL,
		0x9CE7B44E2FE57708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x655B6D2F86472A47ULL,
		0x0D669D8947A3A878ULL,
		0x0DF7B0D2DA2AE92FULL,
		0x6040BD807F2514EEULL,
		0xA1608F80E697B2B6ULL,
		0xBF9577E40D142B91ULL,
		0xF3478A48BDFCB3BDULL,
		0xE05402B7CD20DF43ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1B82DBC34078E598ULL,
		0x078B08E04C4CD5CCULL,
		0x13AF764FA9F206C6ULL,
		0x96F6D2650093E0F9ULL,
		0x237F10E5B13FF635ULL,
		0x06C06E1BD5DE8E91ULL,
		0xFC3BD4B355C1FF2AULL,
		0x7FC670A9E1D021AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D6B8305FD051B8ULL,
		0x7AACFA4CE397F9DCULL,
		0x645C05C377EA26B0ULL,
		0xE0BF35A132928878ULL,
		0x1E03CAE93F8B4EDEULL,
		0x93408D5E2391B761ULL,
		0x322549CA17ED68D2ULL,
		0x71F2C1D7F8C27CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7AC2392E0A893E0ULL,
		0x8CDE0E9368B4DBEFULL,
		0xAF53708C3207E015ULL,
		0xB6379CC3CE015880ULL,
		0x057B45FC71B4A756ULL,
		0x737FE0BDB24CD730ULL,
		0xCA168AE93DD49657ULL,
		0x0DD3AED1E90DA4B5ULL
	}};
	sign = 0;
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
		0xCC7005C7277D6027ULL,
		0x4D8DDD2FD84D6AB7ULL,
		0x365B182A32CDE37AULL,
		0x320DC82E61269185ULL,
		0x2A81A64966433147ULL,
		0x700BBB8897017763ULL,
		0x4C5F12D25DB8A7FFULL,
		0xF9E61EBE9F370E47ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB36EFC4A69E2FAULL,
		0x84EDCD04B8A62EDBULL,
		0x23C7A6531A8F04D8ULL,
		0xE62D909016401996ULL,
		0xB6C5588026AAB8D3ULL,
		0x5354FB9C723D963FULL,
		0x711EF44534E67090ULL,
		0x5FB413A98B3B921CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECBC96CADD137D2DULL,
		0xC8A0102B1FA73BDBULL,
		0x129371D7183EDEA1ULL,
		0x4BE0379E4AE677EFULL,
		0x73BC4DC93F987873ULL,
		0x1CB6BFEC24C3E123ULL,
		0xDB401E8D28D2376FULL,
		0x9A320B1513FB7C2AULL
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
		0x82591E7BB2DF161EULL,
		0xBE39431F7AAA1AB9ULL,
		0x075770FBD44466A8ULL,
		0xEFE84C9FAE98F549ULL,
		0x4AFAFF9E9C01D1FBULL,
		0xF6FBB09C0E63CEB6ULL,
		0xD0FAA00406D1563DULL,
		0xF8BF522812861C3CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x637BA53164F12963ULL,
		0x2F2C1E5393A5DE42ULL,
		0xED7DE0458FCCCA81ULL,
		0xB40C78C43B43F0C8ULL,
		0x0D828431217A4E95ULL,
		0xBE80B850BA99D1B6ULL,
		0xF0E2D20ED719EF9AULL,
		0xEFA892B1EE280B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EDD794A4DEDECBBULL,
		0x8F0D24CBE7043C77ULL,
		0x19D990B644779C27ULL,
		0x3BDBD3DB73550480ULL,
		0x3D787B6D7A878366ULL,
		0x387AF84B53C9FD00ULL,
		0xE017CDF52FB766A3ULL,
		0x0916BF76245E10AFULL
	}};
	sign = 0;
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
		0x809BBF0085B09710ULL,
		0x500866DAF4B3FCCFULL,
		0x900913C93B25FE73ULL,
		0x239598A0461AD566ULL,
		0x421690DBE3EC33C1ULL,
		0x93488F76FF741CCCULL,
		0x9EEBF7ADEC0EFA6FULL,
		0xF807F016B370558AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2730A2E6C2E975ULL,
		0x5E5668D0D677C08FULL,
		0x437BEA1332B5614BULL,
		0x453E23D8D6803541ULL,
		0x934CC34021434C34ULL,
		0x6DCD5E5605BFDD1BULL,
		0x291CC9C7D472E5B1ULL,
		0x9C880EE29FC21373ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73748E5D9EEDAD9BULL,
		0xF1B1FE0A1E3C3C40ULL,
		0x4C8D29B608709D27ULL,
		0xDE5774C76F9AA025ULL,
		0xAEC9CD9BC2A8E78CULL,
		0x257B3120F9B43FB0ULL,
		0x75CF2DE6179C14BEULL,
		0x5B7FE13413AE4217ULL
	}};
	sign = 0;
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
		0xBE69084726CACE7FULL,
		0xBD56785393AB74E8ULL,
		0x4B00FA5677FECC28ULL,
		0x08F7FBF05DCB04B6ULL,
		0xB8FF5B5084CA2CD7ULL,
		0xEA0B9AE6F95F273EULL,
		0x738FD58876FDB1A0ULL,
		0x041328838E064027ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD200BEA5F5D5A92ULL,
		0x77C8EBDFAE27C2E1ULL,
		0x56B867EFAF8C4426ULL,
		0xAA0325B7A516BBB5ULL,
		0xD0732226CFE32687ULL,
		0xD1D4619AC68F04C0ULL,
		0x4C5714C898F9381FULL,
		0x030896B6B1C7BDADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF148FC5CC76D73EDULL,
		0x458D8C73E583B206ULL,
		0xF4489266C8728802ULL,
		0x5EF4D638B8B44900ULL,
		0xE88C3929B4E7064FULL,
		0x1837394C32D0227DULL,
		0x2738C0BFDE047981ULL,
		0x010A91CCDC3E827AULL
	}};
	sign = 0;
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
		0x3FED2A16DE3FFFABULL,
		0x63B953DF2AA7CCCBULL,
		0xA85938F449B29901ULL,
		0x58C746A965704259ULL,
		0xAA907B7B43DD4F1AULL,
		0x23CD287FEC681552ULL,
		0x860699807F42689DULL,
		0xF7DED42502BC8AB5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA7CA477C3D54BCULL,
		0xCF1AF9DB38255A94ULL,
		0xFD8C2DD897EA5138ULL,
		0xD21E41355134EE90ULL,
		0x511714E61EEFDC33ULL,
		0x04EEB90C7DAD5C6DULL,
		0xEF9A9F20931F314EULL,
		0x54DF7C160A74D88FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1455FCF6202AAEFULL,
		0x949E5A03F2827236ULL,
		0xAACD0B1BB1C847C8ULL,
		0x86A90574143B53C8ULL,
		0x5979669524ED72E6ULL,
		0x1EDE6F736EBAB8E5ULL,
		0x966BFA5FEC23374FULL,
		0xA2FF580EF847B225ULL
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
		0xE40F987494463ABAULL,
		0xB46197C93DB24ED4ULL,
		0xDD65B523E8532129ULL,
		0x94C4C3AAF91F1385ULL,
		0x20A36E10D4808864ULL,
		0x5213E5714B404461ULL,
		0x63E9720853E31A3DULL,
		0x828713B82D05EF7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x734D48DDBB257D61ULL,
		0x547A9827CF3FB0A0ULL,
		0xCB8FB48F72833ED4ULL,
		0x4A70573D2083A7A3ULL,
		0xB96E3350D9B03C40ULL,
		0x2955AFED13B9C1BEULL,
		0xB5211EA4D4590A1DULL,
		0xAA5410B6C32D1BB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70C24F96D920BD59ULL,
		0x5FE6FFA16E729E34ULL,
		0x11D6009475CFE255ULL,
		0x4A546C6DD89B6BE2ULL,
		0x67353ABFFAD04C24ULL,
		0x28BE3584378682A2ULL,
		0xAEC853637F8A1020ULL,
		0xD833030169D8D3C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x188BF69D850F40EFULL,
		0x43D11B1837AC5E1FULL,
		0xA44221F9D6306937ULL,
		0xEE3450CB5BF60FF8ULL,
		0x9049F3405BE86A67ULL,
		0xF14201588F762B7AULL,
		0xB8DAB3B07E3FD51BULL,
		0x52BD1F173012D6EEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CC73EE5D7F595ECULL,
		0xBBAF51012F76D297ULL,
		0x622B2793A15740F3ULL,
		0x7E468D91452609B1ULL,
		0x0CF9A7059E132FB8ULL,
		0x3EFE5E37C2BC9F38ULL,
		0x99BECBF1F0C3A25BULL,
		0x4084252C52107AF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BC4B7B7AD19AB03ULL,
		0x8821CA1708358B87ULL,
		0x4216FA6634D92843ULL,
		0x6FEDC33A16D00647ULL,
		0x83504C3ABDD53AAFULL,
		0xB243A320CCB98C42ULL,
		0x1F1BE7BE8D7C32C0ULL,
		0x1238F9EADE025BF7ULL
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
		0x4091FC4A8BDEEACFULL,
		0xCD34C7F563BC5E96ULL,
		0x8CEC0E7065CC4216ULL,
		0x3C3BFEBA80F69169ULL,
		0x9690EEBECC7B1AD6ULL,
		0xEE42B2BDF814CC8BULL,
		0x657CB4920A881ECBULL,
		0x6FA172B99FB15177ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6EE2CF6B801E9D1ULL,
		0xF879A2A36896E46EULL,
		0x46BAFEF41AEF5046ULL,
		0x0C599DD39CC1706AULL,
		0x8FF66FF8FFDDCE9CULL,
		0xF5EF09AA0930397EULL,
		0x6D6ABF83B0CD05F9ULL,
		0x2961582448BD6F86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59A3CF53D3DD00FEULL,
		0xD4BB2551FB257A27ULL,
		0x46310F7C4ADCF1CFULL,
		0x2FE260E6E43520FFULL,
		0x069A7EC5CC9D4C3AULL,
		0xF853A913EEE4930DULL,
		0xF811F50E59BB18D1ULL,
		0x46401A9556F3E1F0ULL
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
		0x30268E4625005E3DULL,
		0x8FEAD428817B4298ULL,
		0x7C7409824A5DC4CFULL,
		0x887971784F08E260ULL,
		0x68D80BE34F8984E1ULL,
		0x0821BB112265A8C0ULL,
		0x95EE3899659621ADULL,
		0xC4E262709091D5C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0996A6FF2AF7833ULL,
		0xF5BFB4512F3E9DDCULL,
		0x552B6101BB93B9B4ULL,
		0xD0C9115B4083FC7AULL,
		0x32DA46EB1225B6E4ULL,
		0xA7BA7848F7B5B5ACULL,
		0x9997F9362120C0AAULL,
		0x5E3DC21301CE875CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F8D23D63250E60AULL,
		0x9A2B1FD7523CA4BBULL,
		0x2748A8808ECA0B1AULL,
		0xB7B0601D0E84E5E6ULL,
		0x35FDC4F83D63CDFCULL,
		0x606742C82AAFF314ULL,
		0xFC563F6344756102ULL,
		0x66A4A05D8EC34E64ULL
	}};
	sign = 0;
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
		0xCF5F8A1FAE9DE736ULL,
		0xCD96FEDCDB816DD5ULL,
		0xDD00D05A0863F4B0ULL,
		0xCD228CB3161E68BEULL,
		0xF592A4AC4F4C548AULL,
		0x6CBAC225D13F526CULL,
		0xA3BFD3D0783E3724ULL,
		0x2C3F91B49C2B68DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8693AA745B8B2DC5ULL,
		0x952A6B35F4E03DF2ULL,
		0x194D47BFC2F785E4ULL,
		0x8E538E677D1CC74EULL,
		0x5BDCA771429B17C1ULL,
		0x7CDB205BCE2C9E45ULL,
		0x2C27F90DF70C5D81ULL,
		0x2CE21D972BEE8C5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48CBDFAB5312B971ULL,
		0x386C93A6E6A12FE3ULL,
		0xC3B3889A456C6ECCULL,
		0x3ECEFE4B9901A170ULL,
		0x99B5FD3B0CB13CC9ULL,
		0xEFDFA1CA0312B427ULL,
		0x7797DAC28131D9A2ULL,
		0xFF5D741D703CDC81ULL
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
		0xF24CC2E952245358ULL,
		0x60592B96E8E9FB6BULL,
		0x1C690D77D9A6E88FULL,
		0x804F9FB3EB456B6EULL,
		0x51311E97D2DC6768ULL,
		0xEF8655210A489550ULL,
		0x5DBEF931D0251147ULL,
		0xBBD8D1E030E28490ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8929666094CD99B8ULL,
		0x0235017D0FC2F464ULL,
		0x1DF84876307DADEBULL,
		0xAB29846C4F5EB6F1ULL,
		0x66E3440727C77510ULL,
		0x98972E67A41357B5ULL,
		0xE7A589E4E379FC30ULL,
		0x6AD34451A523F54FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69235C88BD56B9A0ULL,
		0x5E242A19D9270707ULL,
		0xFE70C501A9293AA4ULL,
		0xD5261B479BE6B47CULL,
		0xEA4DDA90AB14F257ULL,
		0x56EF26B966353D9AULL,
		0x76196F4CECAB1517ULL,
		0x51058D8E8BBE8F40ULL
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
		0xE4EB58445AA86165ULL,
		0xEF539EC52D37C429ULL,
		0x149D2FA0129E694DULL,
		0x23096480970070FEULL,
		0x9ECA4D0DBA1D21CFULL,
		0xE94FF8EDE7DD1B6AULL,
		0x113C1149D476E6F6ULL,
		0x0AAF1369FC77CCF7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3313BB4D56B55C3ULL,
		0x494676E1333F5B06ULL,
		0xF98E9EE084391ABFULL,
		0x2649FFA9F5EE770EULL,
		0x1087C932E07385DCULL,
		0x21C38ACB44348978ULL,
		0xC76E8D83B30149D5ULL,
		0xABE9AFF88230922BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1BA1C8F853D0BA2ULL,
		0xA60D27E3F9F86922ULL,
		0x1B0E90BF8E654E8EULL,
		0xFCBF64D6A111F9EFULL,
		0x8E4283DAD9A99BF2ULL,
		0xC78C6E22A3A891F2ULL,
		0x49CD83C621759D21ULL,
		0x5EC563717A473ACBULL
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
		0x8D4CB397DF08A640ULL,
		0x1E13CEFD5F13A102ULL,
		0xAA5BD1CE98864FAEULL,
		0x63F95F26E8F208D6ULL,
		0xD5409017999D4BFEULL,
		0x10705DF0895AA04CULL,
		0x2CDB5CAE2F468C3DULL,
		0x1D38D29F52715E52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1BD7B57998903DULL,
		0x48322A06716BD861ULL,
		0x13A80B5245EE09F9ULL,
		0x88B5B051159D7117ULL,
		0xBFDB97B3ABB2211CULL,
		0x243E17CF7F485138ULL,
		0xFB756B0334A5CD51ULL,
		0x8437F5EC49632013ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F30DBE265701603ULL,
		0xD5E1A4F6EDA7C8A1ULL,
		0x96B3C67C529845B4ULL,
		0xDB43AED5D35497BFULL,
		0x1564F863EDEB2AE1ULL,
		0xEC3246210A124F14ULL,
		0x3165F1AAFAA0BEEBULL,
		0x9900DCB3090E3E3EULL
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
		0x0809CBBD5362DD6EULL,
		0x358AB6F97A44EE1BULL,
		0x0FF59C24E165C846ULL,
		0xA0CC1CC408CBDFCAULL,
		0x40A3554492CFF410ULL,
		0x58D458118083D1CEULL,
		0x13EDCF1F37C8ECFCULL,
		0xF7A907A49CD7A63BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE77181B77DE601FBULL,
		0x23563C45C060DBC0ULL,
		0x2CAB73CFA0EC5F17ULL,
		0x22631C534FC5EE8EULL,
		0x6CB65CEBBA51A3C8ULL,
		0x88E2095FF37D78C2ULL,
		0x2E60804C036C1FD0ULL,
		0xAF1C64D1C7E5FA3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20984A05D57CDB73ULL,
		0x12347AB3B9E4125AULL,
		0xE34A28554079692FULL,
		0x7E690070B905F13BULL,
		0xD3ECF858D87E5048ULL,
		0xCFF24EB18D06590BULL,
		0xE58D4ED3345CCD2BULL,
		0x488CA2D2D4F1ABFDULL
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
		0xCCFF6841F8D3A572ULL,
		0x2818C8FBFC321C70ULL,
		0x30104F0B2EFA1074ULL,
		0x5A5271E01550ECB1ULL,
		0x49436837F3E47916ULL,
		0x77CB671FD3A89EF2ULL,
		0x066F85988AE0EF6DULL,
		0xCC7096C5C22F2273ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD01B535D83F1C7A4ULL,
		0x3F07D7AFCF0C249DULL,
		0x293E567438F607B1ULL,
		0x9525F128BA52A3CBULL,
		0xCE1998D2D71C1111ULL,
		0x78C6B47E22C1F688ULL,
		0x238B97753186D6B3ULL,
		0x980DFD989EC9F059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCE414E474E1DDCEULL,
		0xE910F14C2D25F7D2ULL,
		0x06D1F896F60408C2ULL,
		0xC52C80B75AFE48E6ULL,
		0x7B29CF651CC86804ULL,
		0xFF04B2A1B0E6A869ULL,
		0xE2E3EE23595A18B9ULL,
		0x3462992D23653219ULL
	}};
	sign = 0;
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
		0xAA8E23244AAA7043ULL,
		0x4E67A37425AB1E8DULL,
		0xE232EF5F40B99507ULL,
		0x55F4FB999F76D215ULL,
		0x9AC2C8897AB22EE2ULL,
		0x3E8E465A292D63D9ULL,
		0x3D85E2A73AB1D339ULL,
		0x3A101D88EBA5B0D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E5CDD4883B0D4BEULL,
		0xB715437463107ED0ULL,
		0xB41B005B047C0F3EULL,
		0x10CC9BAA0C3CB8EBULL,
		0x35F6C643DEA4BC75ULL,
		0x95A675B6CC751B30ULL,
		0x23AFA6D3C0F38D1FULL,
		0x9A0894FF35C6F7DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C3145DBC6F99B85ULL,
		0x97525FFFC29A9FBDULL,
		0x2E17EF043C3D85C8ULL,
		0x45285FEF933A192AULL,
		0x64CC02459C0D726DULL,
		0xA8E7D0A35CB848A9ULL,
		0x19D63BD379BE4619ULL,
		0xA0078889B5DEB8F3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x647A904493D1D9CBULL,
		0xFB4D7931BE72259FULL,
		0xFD1D5C36D3DA229EULL,
		0xD65215CCB7E39AF4ULL,
		0xAFDD455FA82D5D24ULL,
		0x3AE43B9E35B3864FULL,
		0xD4016645FDC1B3FCULL,
		0xBD9EFC4518CEB641ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA574EEB79169C9ULL,
		0x37B6B23C74D0D8BBULL,
		0x5626CA76A796E8A0ULL,
		0x329A81C6BEB0591BULL,
		0x30A9A58D9FA6089DULL,
		0xF03A4813B5F77A29ULL,
		0x1D86F0ECFF12A095ULL,
		0x35BC4D651F0ABE1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35D51B55DC407002ULL,
		0xC396C6F549A14CE4ULL,
		0xA6F691C02C4339FEULL,
		0xA3B79405F93341D9ULL,
		0x7F339FD208875487ULL,
		0x4AA9F38A7FBC0C26ULL,
		0xB67A7558FEAF1366ULL,
		0x87E2AEDFF9C3F826ULL
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
		0x2E6A64352672D423ULL,
		0xBAC63EDC04A69AA2ULL,
		0x9976947E947A481EULL,
		0xBD7AD525DFB24127ULL,
		0x59CBF2F145C68FDDULL,
		0x6194683ABF1D4447ULL,
		0x3B60200908245D84ULL,
		0x5E5CDFECA054DE5AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AED6EF1B729BB89ULL,
		0xD41A8513F28276E5ULL,
		0x2AA4D002E7E7CD62ULL,
		0x8FED763BB197DC6AULL,
		0xFADBF1B16CF7A393ULL,
		0x85EE54D482783EDDULL,
		0xA31B03B1158BBCB2ULL,
		0x3690FFE060F8F499ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE37CF5436F49189AULL,
		0xE6ABB9C8122423BCULL,
		0x6ED1C47BAC927ABBULL,
		0x2D8D5EEA2E1A64BDULL,
		0x5EF0013FD8CEEC4AULL,
		0xDBA613663CA50569ULL,
		0x98451C57F298A0D1ULL,
		0x27CBE00C3F5BE9C0ULL
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
		0x6C060C7D94430E95ULL,
		0xABDCA7FC38D6C140ULL,
		0xA68C1D4EC2814F8CULL,
		0xA2EC675EDAB5A49BULL,
		0x6C90CC0AFE4E9ACFULL,
		0xC3D3451AA29421F3ULL,
		0xE219B82365469774ULL,
		0x8C03EBA89CC151F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C935F28ED172812ULL,
		0x73FB93F390372487ULL,
		0x30EBBEDD8BD86095ULL,
		0xFFC720B4B2B147F0ULL,
		0x474DAA9CFDF71F63ULL,
		0xC8ED6E565B539FFAULL,
		0xE6350CDCFE929F60ULL,
		0xAB6FA8A1B9B6CF7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F72AD54A72BE683ULL,
		0x37E11408A89F9CB9ULL,
		0x75A05E7136A8EEF7ULL,
		0xA32546AA28045CABULL,
		0x2543216E00577B6BULL,
		0xFAE5D6C4474081F9ULL,
		0xFBE4AB4666B3F813ULL,
		0xE0944306E30A827AULL
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
		0x7DC0F442AE0ED0F9ULL,
		0x9437F9AA17EEEB4AULL,
		0xE7502D350BC27C17ULL,
		0x70D69824DDBF1951ULL,
		0xFCA646085BF87352ULL,
		0x45FE777BB89D89F1ULL,
		0x921C42F04F8DB18CULL,
		0x35419709585369EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EB2C6F7518903AULL,
		0x13E42D06DA52C02AULL,
		0x386BFFC7448B2ECFULL,
		0xB128B563D12DE757ULL,
		0x9E65F278EE752F58ULL,
		0xDF62602031F7F80DULL,
		0x4D21A9E74CC2AF9EULL,
		0x2D36FE4CE7B3F3C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAD5C7D338F640BFULL,
		0x8053CCA33D9C2B1FULL,
		0xAEE42D6DC7374D48ULL,
		0xBFADE2C10C9131FAULL,
		0x5E40538F6D8343F9ULL,
		0x669C175B86A591E4ULL,
		0x44FA990902CB01EDULL,
		0x080A98BC709F7627ULL
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
		0x3653D66F1FA56FF6ULL,
		0xAE668A9B33B1D69BULL,
		0xE62FC6826DAFF84CULL,
		0x2D130AEEABEA212CULL,
		0xE7C30D503F9346E5ULL,
		0xB10E8A7456DBF3ECULL,
		0x2955C21B5849F2B6ULL,
		0x610D6C59FE0F6285ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC9447CD4EA78E8ULL,
		0x9F67898E1B145BCAULL,
		0xA3E060DEF694A190ULL,
		0x6DB88BFFF6A34BCAULL,
		0x6E0749E9E46C7F6EULL,
		0x7096AFB4ACFCB1E5ULL,
		0x950EBD19AFB8FFFCULL,
		0xE0498AF66E76A739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A8A91F24ABAF70EULL,
		0x0EFF010D189D7AD0ULL,
		0x424F65A3771B56BCULL,
		0xBF5A7EEEB546D562ULL,
		0x79BBC3665B26C776ULL,
		0x4077DABFA9DF4207ULL,
		0x94470501A890F2BAULL,
		0x80C3E1638F98BB4BULL
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
		0xFDFAD466791612A6ULL,
		0x1D43B42F7021E89BULL,
		0x292DD23B9937D43EULL,
		0xDF28CAEC1B6FBF05ULL,
		0xCDB5B449A2F28912ULL,
		0x78C076B8C199B5A3ULL,
		0xECF588A6B8C52ECDULL,
		0x8F15A82EE0616298ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A6BF601B5ED18EULL,
		0xEAB0DC6059CF6B8FULL,
		0xDE16AFE22D7FA721ULL,
		0xFE467F00DB6BC29FULL,
		0x3AFCF628C6D83822ULL,
		0xD9A22B080B053F3BULL,
		0x1E2E90984781777FULL,
		0x26E17F01D6225D0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA75415065DB74118ULL,
		0x3292D7CF16527D0CULL,
		0x4B1722596BB82D1CULL,
		0xE0E24BEB4003FC65ULL,
		0x92B8BE20DC1A50EFULL,
		0x9F1E4BB0B6947668ULL,
		0xCEC6F80E7143B74DULL,
		0x6834292D0A3F058CULL
	}};
	sign = 0;
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
		0xA691950F95F87BDCULL,
		0xF19391FE2B3A4AFEULL,
		0xD0CB3BE55FA0F249ULL,
		0x601EF355331DA0A1ULL,
		0xFB81ED5B28573F86ULL,
		0xFB8DBAF2021B25B0ULL,
		0x56BBB3F417D33F44ULL,
		0xACD2114E43F03DE5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A00E117903E061ULL,
		0xBD0D33737DF5B33BULL,
		0x214C96A5449B9632ULL,
		0xEBBA6B7D80F5E32AULL,
		0x3196963C0AA5EC83ULL,
		0xC2329DD6E1606EF3ULL,
		0xDE0092B775DB4A3DULL,
		0xBBC9917A14DB55A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3F186FE1CF49B7BULL,
		0x34865E8AAD4497C2ULL,
		0xAF7EA5401B055C17ULL,
		0x746487D7B227BD77ULL,
		0xC9EB571F1DB15302ULL,
		0x395B1D1B20BAB6BDULL,
		0x78BB213CA1F7F507ULL,
		0xF1087FD42F14E841ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAFF0A8AE5C4D8DFAULL,
		0x9CB369F86EC5FB9AULL,
		0x89F2884E25B15C1FULL,
		0xCBFED3E88F938E5DULL,
		0x89E3A24C387F3FBAULL,
		0xCDD436437C5E9931ULL,
		0x41CD26BED9CC5B3CULL,
		0xBCF29BEBF7455ECCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x926D6F58D54178EAULL,
		0xF9F346A73B44142BULL,
		0x5BFC4AFB70F1D28AULL,
		0x794B29A18F791043ULL,
		0x1A8E77306A1BB856ULL,
		0xC78654736D4D2775ULL,
		0xCF50F0443910DBA3ULL,
		0x1DE5A478458CB05EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D833955870C1510ULL,
		0xA2C023513381E76FULL,
		0x2DF63D52B4BF8994ULL,
		0x52B3AA47001A7E1AULL,
		0x6F552B1BCE638764ULL,
		0x064DE1D00F1171BCULL,
		0x727C367AA0BB7F99ULL,
		0x9F0CF773B1B8AE6DULL
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
		0x0725171E3C8BBC91ULL,
		0xFD6FE805869E21E3ULL,
		0x13B4220144C87B00ULL,
		0x1010318984BAB253ULL,
		0x563D8347261D3335ULL,
		0xBCE97B125D6549B0ULL,
		0x3E590D9F824872BBULL,
		0x23ED10631DEE7EBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BE56B5D40563E2ULL,
		0x4B00B114016A0109ULL,
		0xBCF7831982A45417ULL,
		0x101B2A76BAB33C7DULL,
		0x389C0C7963617D6FULL,
		0x4CA53DA54471E166ULL,
		0x76000955A2D6BB02ULL,
		0x12AEA9E656AE4881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2166C068688658AFULL,
		0xB26F36F1853420D9ULL,
		0x56BC9EE7C22426E9ULL,
		0xFFF50712CA0775D5ULL,
		0x1DA176CDC2BBB5C5ULL,
		0x70443D6D18F3684AULL,
		0xC8590449DF71B7B9ULL,
		0x113E667CC740363BULL
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
		0x110985DBA0737DA5ULL,
		0x2D87ACDED08439F0ULL,
		0xABC2A7CD0560CC12ULL,
		0x96CD83C0024B3240ULL,
		0xEF551F4B717693BCULL,
		0xD6A7BAF95A5AE7AFULL,
		0xA45DC83E3DAEEDFAULL,
		0xF1F7BEC7F03CA979ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14A5F25FE3814DDAULL,
		0x3AE6EA3A7947FF46ULL,
		0xF5C08571E418753EULL,
		0x781B676BCA2D0CECULL,
		0x77E17B372824D28EULL,
		0x4667F1CDF9E47FB8ULL,
		0x8B90FE3F006C415EULL,
		0x0A5C561B1685B010ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC63937BBCF22FCBULL,
		0xF2A0C2A4573C3AA9ULL,
		0xB602225B214856D3ULL,
		0x1EB21C54381E2553ULL,
		0x7773A4144951C12EULL,
		0x903FC92B607667F7ULL,
		0x18CCC9FF3D42AC9CULL,
		0xE79B68ACD9B6F969ULL
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
		0x85FFFC4D3A7E176DULL,
		0x5ED9A456555A5059ULL,
		0xEEC3E57DE64B296CULL,
		0x3EDB2D0646235166ULL,
		0xFA39D7F23A58E4AAULL,
		0x85F4666D1F09CB17ULL,
		0x80D38C1B59B67C03ULL,
		0x0DD4C906F132F4C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x891E978B5EB04B25ULL,
		0x1362081F6340019CULL,
		0x55133B19D9509DADULL,
		0x3E9B01E6DFE35E94ULL,
		0x9DF179EE3BCA0B6BULL,
		0xA12B0AFB8E2D423DULL,
		0x775356298FD0F1B3ULL,
		0xBEDE24B11BBC91FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCE164C1DBCDCC48ULL,
		0x4B779C36F21A4EBCULL,
		0x99B0AA640CFA8BBFULL,
		0x00402B1F663FF2D2ULL,
		0x5C485E03FE8ED93FULL,
		0xE4C95B7190DC88DAULL,
		0x098035F1C9E58A4FULL,
		0x4EF6A455D57662C8ULL
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
		0x841AA4C906C7C0F8ULL,
		0xF4F836565105225EULL,
		0x2E1AFB955B673B46ULL,
		0xF4295E58A1495772ULL,
		0x7EAB902C5BC83BF0ULL,
		0xBA1856ABAADF707CULL,
		0x6720DC4F2E6DAC5EULL,
		0x8F5344C7D034F34DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE853E7F187204C28ULL,
		0x456776EED4344E7EULL,
		0x684782061B01AF88ULL,
		0x4BBFF0D2CF95B8C8ULL,
		0x75AD8F65833EE00AULL,
		0x01156A5441963838ULL,
		0x00AD3B43B09DDD77ULL,
		0xE8DCBD2047E00E84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BC6BCD77FA774D0ULL,
		0xAF90BF677CD0D3DFULL,
		0xC5D3798F40658BBEULL,
		0xA8696D85D1B39EA9ULL,
		0x08FE00C6D8895BE6ULL,
		0xB902EC5769493844ULL,
		0x6673A10B7DCFCEE7ULL,
		0xA67687A78854E4C9ULL
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
		0x448A170625400E6EULL,
		0xCC7BA05503E6EE4BULL,
		0xB801ED773830BAB8ULL,
		0x2E83CCECC03F6984ULL,
		0xA887679F06501CC3ULL,
		0xB928D315D08B5D1EULL,
		0x3187A3F3F998222BULL,
		0x110A33FF4B4C20DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAEB5F15457DF23ULL,
		0x02E704B432DF7889ULL,
		0xAD4E0C73835ABD12ULL,
		0x22DDF325407020A4ULL,
		0x10ABBEF75A45B212ULL,
		0x171D700638F942EAULL,
		0x16381F9792C44C79ULL,
		0xC59FA3ABA4EC208FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85DB6114D0E82F4BULL,
		0xC9949BA0D10775C1ULL,
		0x0AB3E103B4D5FDA6ULL,
		0x0BA5D9C77FCF48E0ULL,
		0x97DBA8A7AC0A6AB1ULL,
		0xA20B630F97921A34ULL,
		0x1B4F845C66D3D5B2ULL,
		0x4B6A9053A660004DULL
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
		0xE12A602B22F92E45ULL,
		0x043FF141F2B350EAULL,
		0x44961D51161660D8ULL,
		0xA8A3E0B35374337EULL,
		0xA750A2D5D47C038BULL,
		0x80893510567FCD72ULL,
		0xECFA8153B62B0633ULL,
		0x55F558659282776FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA0BE192EEBCE5DULL,
		0xDD1B9F94F4C6FE8BULL,
		0x84BDBD3FDE107C02ULL,
		0xAD1F05352D2775E0ULL,
		0xED81C316ED25E15BULL,
		0x46F63CB018DB50C5ULL,
		0x851CCEF1342920B5ULL,
		0xB6F7A47330A99B7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC189A211F40D5FE8ULL,
		0x272451ACFDEC525FULL,
		0xBFD860113805E4D5ULL,
		0xFB84DB7E264CBD9DULL,
		0xB9CEDFBEE756222FULL,
		0x3992F8603DA47CACULL,
		0x67DDB2628201E57EULL,
		0x9EFDB3F261D8DBF4ULL
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
		0x6FBF55B00BCC0D51ULL,
		0xE7660ECABD78B967ULL,
		0x8E1C0DF6031EE411ULL,
		0xA2E8DBF9147CB518ULL,
		0x68BBD1C68C746A30ULL,
		0x908ACE70F5E89D85ULL,
		0xB92467AC0E9FAF9CULL,
		0x55E11210E1068B45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F2319AEAF23407ULL,
		0x7DEC1CB435EF0F64ULL,
		0xC7914C01FCDF353EULL,
		0xFC62F34301B20B5FULL,
		0x0E2571538E6E4700ULL,
		0x066F47375F21ECE4ULL,
		0xA7BE94BC77592746ULL,
		0x348EB98145B659D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89CD241520D9D94AULL,
		0x6979F2168789AA02ULL,
		0xC68AC1F4063FAED3ULL,
		0xA685E8B612CAA9B8ULL,
		0x5A966072FE06232FULL,
		0x8A1B873996C6B0A1ULL,
		0x1165D2EF97468856ULL,
		0x2152588F9B50316EULL
	}};
	sign = 0;
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
		0xB4A377B19BCC3ADFULL,
		0xB926992B24EAB463ULL,
		0x0C79CE69E02A7E5CULL,
		0xEDF42AE6E72F3948ULL,
		0x2C9FE9202D19AFE3ULL,
		0x3B0736F07FAA32B3ULL,
		0x00340E77E22CE46FULL,
		0xA70386E165EA1A1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE2971E6B5E65612ULL,
		0x0B22F465144A8576ULL,
		0xB4E30D9ED625F3FFULL,
		0xD9C3650B43D864CEULL,
		0x9565A74CE62EB6CCULL,
		0x1E5B58D75E9FB968ULL,
		0x8BBD933B595DDBC5ULL,
		0x5264F4C3A82D3A2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD67A05CAE5E5E4CDULL,
		0xAE03A4C610A02EECULL,
		0x5796C0CB0A048A5DULL,
		0x1430C5DBA356D479ULL,
		0x973A41D346EAF917ULL,
		0x1CABDE19210A794AULL,
		0x74767B3C88CF08AAULL,
		0x549E921DBDBCDFEAULL
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
		0x2DF7988A3CEBDB36ULL,
		0xB8E9820B02EA643BULL,
		0x0F56A83C2EEBE1FFULL,
		0x2D0FBFF1E7F84A7FULL,
		0x9B12DEAA9F0B92D4ULL,
		0x33187F1B9C60BE0BULL,
		0xAD3373906E82E051ULL,
		0x1F4F39509D245A29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5756D866FC91A25BULL,
		0x5F56BF20AB636426ULL,
		0xBB3B886C7E51734EULL,
		0x403069ECD17A022FULL,
		0x153A6F176A005937ULL,
		0xE62E0542526243E7ULL,
		0x79F90BF1FC831054ULL,
		0x82FA9B73C7678863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6A0C023405A38DBULL,
		0x5992C2EA57870014ULL,
		0x541B1FCFB09A6EB1ULL,
		0xECDF5605167E484FULL,
		0x85D86F93350B399CULL,
		0x4CEA79D949FE7A24ULL,
		0x333A679E71FFCFFCULL,
		0x9C549DDCD5BCD1C6ULL
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
		0xBE244E9DD2C5D9D6ULL,
		0xFE8E818E924B4E56ULL,
		0x2B4019E96A86B7E8ULL,
		0x054C82033E97F3A9ULL,
		0xFB90F944CFEE6A1CULL,
		0xF42B6D3AF3E6A773ULL,
		0xBE67A2E7388902FDULL,
		0x1A34F0C098B2D67EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEAEAF9E8B7B7ECEULL,
		0x9FA8D34F96CD93FEULL,
		0xDEF30342DEC01772ULL,
		0xE0443D96E0498F26ULL,
		0xC08EDD0A8AEE5D5CULL,
		0xC1A5065A93C58E87ULL,
		0x0D1902C54D36AF1EULL,
		0x578BB540DE80C6F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F759EFF474A5B08ULL,
		0x5EE5AE3EFB7DBA58ULL,
		0x4C4D16A68BC6A076ULL,
		0x2508446C5E4E6482ULL,
		0x3B021C3A45000CBFULL,
		0x328666E0602118ECULL,
		0xB14EA021EB5253DFULL,
		0xC2A93B7FBA320F8AULL
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
		0x967FECA0D0056DD8ULL,
		0xC59840A082390B76ULL,
		0x8C44F3288543A642ULL,
		0x5F03C8FD9DDD2B26ULL,
		0xFE17B3B9D2A69159ULL,
		0x8BCD5618232EDA37ULL,
		0x647C25A8A23EF84BULL,
		0x4A889C536BDF1E9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C000A733A1B5B4BULL,
		0xFCDB2D4BD27E47F3ULL,
		0x29077BD6319EEEABULL,
		0xE1999889C701CD4CULL,
		0xF76566BD131712C7ULL,
		0xC5EE8F7D81D16FBCULL,
		0x0BFD36F70F2C16A6ULL,
		0xA139B7B73F1C2D50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A7FE22D95EA128DULL,
		0xC8BD1354AFBAC383ULL,
		0x633D775253A4B796ULL,
		0x7D6A3073D6DB5DDAULL,
		0x06B24CFCBF8F7E91ULL,
		0xC5DEC69AA15D6A7BULL,
		0x587EEEB19312E1A4ULL,
		0xA94EE49C2CC2F14EULL
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
		0xE87D136973418C5EULL,
		0x49F3EF5B05F7E83BULL,
		0xB3E3E6B8FA10DB4EULL,
		0x6C759F4763138003ULL,
		0xC3810174C305DBA9ULL,
		0xA14C561C68ADE0C8ULL,
		0xD7B32847CC6170F3ULL,
		0xA480737B4B8E5E8BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB30FC4BBF54906AULL,
		0x1CAD0B6015C4E9BDULL,
		0xAC1010F509BB8085ULL,
		0x17929F3EC4D5E45DULL,
		0xBD5BB2BF191D6B7AULL,
		0x9E29B10686FEA97EULL,
		0x5BEDCBDF3E3DB8F9ULL,
		0xA09A1EF1FA2A6A5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED4C171DB3ECFBF4ULL,
		0x2D46E3FAF032FE7DULL,
		0x07D3D5C3F0555AC9ULL,
		0x54E300089E3D9BA6ULL,
		0x06254EB5A9E8702FULL,
		0x0322A515E1AF374AULL,
		0x7BC55C688E23B7FAULL,
		0x03E654895163F431ULL
	}};
	sign = 0;
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
		0x1142FBAAF729E9B0ULL,
		0x320CEED3D05D783AULL,
		0x239652381F71B8CBULL,
		0x83DDDA590E473826ULL,
		0x5E8D1BE31B1642EBULL,
		0x064B0CEEF1AC3CF7ULL,
		0x95E32070030AB145ULL,
		0xD7CD3D558C0F16B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x998CADE0C33CF4B5ULL,
		0x4B44A1B6D00F486DULL,
		0x58E7FE268EE3EB98ULL,
		0x87F7D964B9DF1211ULL,
		0x9C8B8C4B081FB9DFULL,
		0x34936CF9F30FCA17ULL,
		0x0E901FB0F31FC799ULL,
		0x995A25415C21B7B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77B64DCA33ECF4FBULL,
		0xE6C84D1D004E2FCCULL,
		0xCAAE5411908DCD32ULL,
		0xFBE600F454682614ULL,
		0xC2018F9812F6890BULL,
		0xD1B79FF4FE9C72DFULL,
		0x875300BF0FEAE9ABULL,
		0x3E7318142FED5F03ULL
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
		0xD463B62BE538785DULL,
		0x5A7C32F96CD83AFBULL,
		0x41CD8AC40520FFCBULL,
		0xC629F5C2D9B0DB9FULL,
		0xB68D770C6E0566FAULL,
		0x7127FD8CE0716D01ULL,
		0xDCC7E85DDAE1152BULL,
		0x691D62FEDDF3B50CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF5D476061A20733ULL,
		0xC93E1F2BC9E2C61CULL,
		0x5FD0D170609D13F7ULL,
		0x4DC2CB9ED4A14855ULL,
		0xC428BE5B80A07FDAULL,
		0x90E1FBB8AC6A2436ULL,
		0xB9E7AA3E6F20A000ULL,
		0x92983714C2E4BA41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5066ECB8396712AULL,
		0x913E13CDA2F574DEULL,
		0xE1FCB953A483EBD3ULL,
		0x78672A24050F9349ULL,
		0xF264B8B0ED64E720ULL,
		0xE04601D4340748CAULL,
		0x22E03E1F6BC0752AULL,
		0xD6852BEA1B0EFACBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x23CA35C4EE6E2FCEULL,
		0x52601145C157F778ULL,
		0xB13AA4F050805B43ULL,
		0x7E83193002C19C79ULL,
		0x3C65828DE43B8D57ULL,
		0x3C5E1F997C1E4CA3ULL,
		0xA60BC4D9C406E8A7ULL,
		0x7E4237008ACB1277ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF48B455A57A2228BULL,
		0xA5FC74A7D354A92EULL,
		0x0BCDCD411F3686D8ULL,
		0x02F89D1E24F599D8ULL,
		0xD05C330D363A79F8ULL,
		0x7B06AC388E3297BCULL,
		0x44085C71F1B965C9ULL,
		0xF7693EBFE25A4BF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F3EF06A96CC0D43ULL,
		0xAC639C9DEE034E49ULL,
		0xA56CD7AF3149D46AULL,
		0x7B8A7C11DDCC02A1ULL,
		0x6C094F80AE01135FULL,
		0xC1577360EDEBB4E6ULL,
		0x62036867D24D82DDULL,
		0x86D8F840A870C685ULL
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
		0x9AC96049696F32A5ULL,
		0x1692C2577EF9B6DBULL,
		0x9849EE1DB8C0C520ULL,
		0x286FAE35C247B874ULL,
		0x42205078C7EBFDEAULL,
		0xCB262541F912DD0AULL,
		0x03D4A13A9F5EDE67ULL,
		0x3E1765BBA4B49579ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F938A7F88CCCBD2ULL,
		0x4D30C329CF03C80BULL,
		0xEDFED0A3D9E3640FULL,
		0x501ABC1C00B895C7ULL,
		0xC17434C8006A14E8ULL,
		0x5E258F6C69DDC805ULL,
		0xA72944FFCCEBACC4ULL,
		0x1187AC350CF48179ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB35D5C9E0A266D3ULL,
		0xC961FF2DAFF5EECFULL,
		0xAA4B1D79DEDD6110ULL,
		0xD854F219C18F22ACULL,
		0x80AC1BB0C781E901ULL,
		0x6D0095D58F351504ULL,
		0x5CAB5C3AD27331A3ULL,
		0x2C8FB98697C013FFULL
	}};
	sign = 0;
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
		0x3DA6F994097C8F17ULL,
		0x6FB895D321218427ULL,
		0x39CAC707AC8F67A4ULL,
		0x17B5B6DEDE5EC5B2ULL,
		0x992076E000D3A239ULL,
		0xCA4605FF848BBFFAULL,
		0x72D92527806E6A5FULL,
		0xE477FE3A0216B0C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF615E62824B6FBULL,
		0xEE9B770623685AE8ULL,
		0x8632EBE75C91B660ULL,
		0x2060118DF5D82B89ULL,
		0xFE8C1B35DF0889AEULL,
		0x5EB1D5353A99CA2CULL,
		0x4E40E1EF202FAD66ULL,
		0xEE35983283F25EB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0B0E3ADE157D81CULL,
		0x811D1ECCFDB9293EULL,
		0xB397DB204FFDB143ULL,
		0xF755A550E8869A28ULL,
		0x9A945BAA21CB188AULL,
		0x6B9430CA49F1F5CDULL,
		0x24984338603EBCF9ULL,
		0xF64266077E245214ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF95FD9B48D5FB2B9ULL,
		0x555D8731194531DCULL,
		0xAF25CB53318FB0AFULL,
		0x798F2DF253909463ULL,
		0xAB29C4E68F6D8A69ULL,
		0x7E130CFBA4CF75F7ULL,
		0x859CE6D9AC635D24ULL,
		0xC53F33137D1E09F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D6324491E11B13ULL,
		0x3FDB60AB089F3E9BULL,
		0xB10C45D5FD82F838ULL,
		0xB2CEC53FC6B5D7B0ULL,
		0xACC908A5F393E86EULL,
		0xEDDF496423FC9B11ULL,
		0x24A0E16519DC9ABEULL,
		0x2A0FC8BE0549BEE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9089A76FFB7E97A6ULL,
		0x1582268610A5F341ULL,
		0xFE19857D340CB877ULL,
		0xC6C068B28CDABCB2ULL,
		0xFE60BC409BD9A1FAULL,
		0x9033C39780D2DAE5ULL,
		0x60FC05749286C265ULL,
		0x9B2F6A5577D44B10ULL
	}};
	sign = 0;
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
		0x5585F0558F810AF4ULL,
		0xF5A12B6CC52EF9E3ULL,
		0xA2E045B50E138D40ULL,
		0x1AA7C9BF5AD2879AULL,
		0x7844700A2696BA89ULL,
		0x90281407551D4679ULL,
		0xCAEAB01ABE6BF41CULL,
		0xAD45BD8E6E2D0F49ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF284A81C80B0FDE7ULL,
		0xE95786DA217EC06EULL,
		0x1014A71C62278397ULL,
		0x80B2A61C90BF3D2FULL,
		0xD18C7ED142D33316ULL,
		0xA827D51ABAAA2E22ULL,
		0xD35968D9670BDB44ULL,
		0x5E6CBFF9BE0A23ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x630148390ED00D0DULL,
		0x0C49A492A3B03974ULL,
		0x92CB9E98ABEC09A9ULL,
		0x99F523A2CA134A6BULL,
		0xA6B7F138E3C38772ULL,
		0xE8003EEC9A731856ULL,
		0xF7914741576018D7ULL,
		0x4ED8FD94B022EB5CULL
	}};
	sign = 0;
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
		0xD26184FCE8A9122FULL,
		0x6089D3CA4C9D8D5DULL,
		0x4653547EF8A7EED1ULL,
		0x807FAF29D0DAC416ULL,
		0x26AAA58E452D379FULL,
		0x6FC76CECB56554F7ULL,
		0xC7C8D9F9CF293A42ULL,
		0xA1830CFE7589A1DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00C924A70B1C9964ULL,
		0xEA0EC760B9104D84ULL,
		0x45788C87B8F85A82ULL,
		0x059B789F7C6DF7FAULL,
		0x4E5798C7D57EF36DULL,
		0x8E3B9902E40CB6C7ULL,
		0x378C631D50B71E00ULL,
		0x10654CF65CCC0BEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1986055DD8C78CBULL,
		0x767B0C69938D3FD9ULL,
		0x00DAC7F73FAF944EULL,
		0x7AE4368A546CCC1CULL,
		0xD8530CC66FAE4432ULL,
		0xE18BD3E9D1589E2FULL,
		0x903C76DC7E721C41ULL,
		0x911DC00818BD95F3ULL
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
		0xE440EDC059A94913ULL,
		0xD098B7A37458EFA2ULL,
		0x2925B6AC14B3590DULL,
		0x767AC94FEF6041CFULL,
		0x466BCD9D91CEAA6BULL,
		0x6234B4A4F9404C5EULL,
		0xC263D6D911A041EDULL,
		0x47F301BA1FC3C1D3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB50828D3E14F63B3ULL,
		0x8B600BA6C313D662ULL,
		0x8E337A0174949F05ULL,
		0x36A419C9D524F7D4ULL,
		0xD0285DABE60F48C8ULL,
		0x13E32E0236A893A5ULL,
		0xB9113653FE26280CULL,
		0x61BC55BA68C6286CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F38C4EC7859E560ULL,
		0x4538ABFCB1451940ULL,
		0x9AF23CAAA01EBA08ULL,
		0x3FD6AF861A3B49FAULL,
		0x76436FF1ABBF61A3ULL,
		0x4E5186A2C297B8B8ULL,
		0x0952A085137A19E1ULL,
		0xE636ABFFB6FD9967ULL
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
		0xD1A22BDB84C8034EULL,
		0xF4E3D638ECAC8F51ULL,
		0x221A6958B88FBA1CULL,
		0x7856E9BC1CEEC710ULL,
		0xF9940745E12CC71BULL,
		0x0F0CE67864922FD7ULL,
		0x0C58C62A8B6400A9ULL,
		0x4B586E40E951219CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07AF7269840A6E40ULL,
		0xA972A8C0F33EB5AFULL,
		0x8133F1099D71A102ULL,
		0x482DEB00B42DCD8BULL,
		0x5CF1A1BABA719DD9ULL,
		0xB7A5A0611D812801ULL,
		0xCCE636C5F0591192ULL,
		0x2244AA7BCB150C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9F2B97200BD950EULL,
		0x4B712D77F96DD9A2ULL,
		0xA0E6784F1B1E191AULL,
		0x3028FEBB68C0F984ULL,
		0x9CA2658B26BB2942ULL,
		0x57674617471107D6ULL,
		0x3F728F649B0AEF16ULL,
		0x2913C3C51E3C150FULL
	}};
	sign = 0;
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
		0xE9F914BC0E89B07EULL,
		0x21C92930F333280AULL,
		0xF793793732DFE822ULL,
		0xBE1E57527CCA9AA8ULL,
		0x50A394DFB940B8DFULL,
		0x8E6AB769A65610A3ULL,
		0x93E0C83E81369803ULL,
		0xF49D5473668A4A29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF4C86FBE109D6CULL,
		0xCE90094A38693990ULL,
		0x74B5117668ED3E20ULL,
		0x8F4D27A503703590ULL,
		0x4C253B45E57074C3ULL,
		0x0ECA40AB531DA98BULL,
		0xF8F7DFEF16BD2239ULL,
		0xAC59FA18B748627EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B044C4C50791312ULL,
		0x53391FE6BAC9EE7AULL,
		0x82DE67C0C9F2AA01ULL,
		0x2ED12FAD795A6518ULL,
		0x047E5999D3D0441CULL,
		0x7FA076BE53386718ULL,
		0x9AE8E84F6A7975CAULL,
		0x48435A5AAF41E7AAULL
	}};
	sign = 0;
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
		0x10A0C7156E93C123ULL,
		0x5E49CB3734568E13ULL,
		0x21D828CFA3EDE284ULL,
		0x628925072A5D8DBDULL,
		0xF902ED0BC37D312DULL,
		0x2FA9054F0D312137ULL,
		0x1D74CB3B00EB406FULL,
		0x191CD7558F5D32F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21BC36BD941D1684ULL,
		0xD0BE2ACE7FB261AEULL,
		0x181A6D78360C4A6AULL,
		0x1C71087AC463CF1EULL,
		0x5D952D4D339E0DD3ULL,
		0xABD7ABFF0A93105EULL,
		0x036EFC96D899A1F9ULL,
		0x4EF35E4AAF91BFE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEE49057DA76AA9FULL,
		0x8D8BA068B4A42C64ULL,
		0x09BDBB576DE19819ULL,
		0x46181C8C65F9BE9FULL,
		0x9B6DBFBE8FDF235AULL,
		0x83D15950029E10D9ULL,
		0x1A05CEA428519E75ULL,
		0xCA29790ADFCB730FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x68D706ACA06E5680ULL,
		0x1FFE7CBAFFD73F0CULL,
		0x36410E412CE76203ULL,
		0xAF7A90DA40EACE5CULL,
		0xE85CFCB34F60EE25ULL,
		0xEDBA43F11339DDFFULL,
		0xAA11CAD36223DFE8ULL,
		0x04E42DF1FADA00E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF034F942E83D86EULL,
		0x12F8A97293D1CF0FULL,
		0xF0DA8ED2388DE821ULL,
		0xD889CF3017CB5E6BULL,
		0x72190FADAD01B25FULL,
		0x68BFC27012C62B24ULL,
		0x814CCB9A72988E0EULL,
		0x88E7D08A24339993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9D3B71871EA7E12ULL,
		0x0D05D3486C056FFCULL,
		0x45667F6EF45979E2ULL,
		0xD6F0C1AA291F6FF0ULL,
		0x7643ED05A25F3BC5ULL,
		0x84FA81810073B2DBULL,
		0x28C4FF38EF8B51DAULL,
		0x7BFC5D67D6A66753ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCBEE801D22E93506ULL,
		0x85E24C2F91540681ULL,
		0x6090B2D12F62F1ADULL,
		0xD268869E5F7F5F2BULL,
		0xF0D4CFEBBDC8768DULL,
		0xBC7A9264BAD8432FULL,
		0x59EA2FE554856161ULL,
		0x616879C49C177726ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5A55AF7A0FA3871ULL,
		0x7A6D51F26322F15EULL,
		0xB6319C7EB79C9222ULL,
		0x3D890CE31C43B2FEULL,
		0x9391A512CCC30DDDULL,
		0xCE6AEAE5A79E1B37ULL,
		0xE180206A99B2C425ULL,
		0x9694ECBEC340C13EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2649252581EEFC95ULL,
		0x0B74FA3D2E311523ULL,
		0xAA5F165277C65F8BULL,
		0x94DF79BB433BAC2CULL,
		0x5D432AD8F10568B0ULL,
		0xEE0FA77F133A27F8ULL,
		0x786A0F7ABAD29D3BULL,
		0xCAD38D05D8D6B5E7ULL
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
		0xF02094A954CCA186ULL,
		0xBFCB77FA746C3017ULL,
		0xED9ACC45EA05B81EULL,
		0x99FB1542EEC177FCULL,
		0x7DE68E867FBA02A0ULL,
		0x4F20591DD7E9309AULL,
		0x565064E7D78BB3AFULL,
		0x15CC0BED90C7F4B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFDD68EEA7B0BDA2ULL,
		0xA3DC85FFDCF01093ULL,
		0xD967D51897054F66ULL,
		0xF675923302076426ULL,
		0xE326B2C4B241B4C3ULL,
		0x2E639AD8528EDD02ULL,
		0xD4EE360639944BC3ULL,
		0x55118F55320009DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40432BBAAD1BE3E4ULL,
		0x1BEEF1FA977C1F84ULL,
		0x1432F72D530068B8ULL,
		0xA385830FECBA13D6ULL,
		0x9ABFDBC1CD784DDCULL,
		0x20BCBE45855A5397ULL,
		0x81622EE19DF767ECULL,
		0xC0BA7C985EC7EAD7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB4DFBD94C589E5AAULL,
		0xAFCE8A31186D3CE2ULL,
		0xA237396CB0C84131ULL,
		0x495F781553BD4217ULL,
		0x297B63A7F4AA6585ULL,
		0xF7B9E4F66A4AC4EAULL,
		0x2E5FF88BCE3F972BULL,
		0x34FB76F473E50134ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A992FCC05CAA641ULL,
		0xCB06780A3E2630DEULL,
		0xF64077FF91212C6DULL,
		0x51FC09547EAC1545ULL,
		0x10FD3BA2ADDEC204ULL,
		0x4C4F96A94C156BCBULL,
		0x36BF20598A1ED248ULL,
		0xAA118E7ED4AE8050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A468DC8BFBF3F69ULL,
		0xE4C81226DA470C04ULL,
		0xABF6C16D1FA714C3ULL,
		0xF7636EC0D5112CD1ULL,
		0x187E280546CBA380ULL,
		0xAB6A4E4D1E35591FULL,
		0xF7A0D8324420C4E3ULL,
		0x8AE9E8759F3680E3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDF074A2A62642A97ULL,
		0x5719601ECE90374BULL,
		0x9485B623AE701AB7ULL,
		0xA9FAD25AF1D19384ULL,
		0x5A1A80D2BC014FB2ULL,
		0xC07DD0BC607434D9ULL,
		0x9260777F1A9E21C9ULL,
		0xBEF257F6AEFAC2A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94078B36C5FABA1ULL,
		0x14FB6C983FAC052BULL,
		0x4D51B07BE1132E1AULL,
		0x0475F270286F4866ULL,
		0x14931DA8606417C5ULL,
		0x44CDE490A2A475BAULL,
		0x812463813E252230ULL,
		0x36728A10D6012727ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15C6D176F6047EF6ULL,
		0x421DF3868EE43220ULL,
		0x473405A7CD5CEC9DULL,
		0xA584DFEAC9624B1EULL,
		0x4587632A5B9D37EDULL,
		0x7BAFEC2BBDCFBF1FULL,
		0x113C13FDDC78FF99ULL,
		0x887FCDE5D8F99B7CULL
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
		0x5442C13F269BB649ULL,
		0xE191AB59A781F818ULL,
		0x41AD477EC575B860ULL,
		0x015382F2CE1D848FULL,
		0x254F4472EA7E6098ULL,
		0x9F25DBAFEB0F2086ULL,
		0xB92B3AD6244F49E5ULL,
		0x7A9D8B0C03E8B991ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A09F1F81AF90BBULL,
		0x70C2FC98C8AFC755ULL,
		0x500644AA3EF29C32ULL,
		0x4EBDCC05D7B68DDDULL,
		0x60F5AC46F08E2E2FULL,
		0xC379F16A264C7A19ULL,
		0xFA6239A03274374AULL,
		0x2201D4B08A1FEFEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEA2221FA4EC258EULL,
		0x70CEAEC0DED230C2ULL,
		0xF1A702D486831C2EULL,
		0xB295B6ECF666F6B1ULL,
		0xC459982BF9F03268ULL,
		0xDBABEA45C4C2A66CULL,
		0xBEC90135F1DB129AULL,
		0x589BB65B79C8C9A1ULL
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
		0xC679CBCDD23C766DULL,
		0xCE4A7C3ACBA9579AULL,
		0xDDDD6B376DDE2541ULL,
		0x69A65B97BBCC3BE1ULL,
		0x68089F857271C897ULL,
		0xD0659354DC9D5401ULL,
		0x0FDA35065A638A9EULL,
		0x7E12B61679AC563BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9559E539F05229CULL,
		0x72C2F81F2E9998AEULL,
		0x2F677D7131FFC78DULL,
		0x5A2B299EC67F2C9AULL,
		0x48F8DCC0BF706C21ULL,
		0x90410958F30BE80AULL,
		0x4C51EA9338312778ULL,
		0x687C9FDFA1D1B093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D242D7A333753D1ULL,
		0x5B87841B9D0FBEECULL,
		0xAE75EDC63BDE5DB4ULL,
		0x0F7B31F8F54D0F47ULL,
		0x1F0FC2C4B3015C76ULL,
		0x402489FBE9916BF7ULL,
		0xC3884A7322326326ULL,
		0x15961636D7DAA5A7ULL
	}};
	sign = 0;
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
		0x4AEF14933EA79367ULL,
		0x3D7BA8708FFFD8ECULL,
		0xCF1A54C2B766A5B1ULL,
		0x1F66B53D08E90092ULL,
		0x49179803026695FCULL,
		0xB11B57808FE8A7F1ULL,
		0x1E171595639979D0ULL,
		0x00CB31EF6F1A6DF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x29606E172AE93CD9ULL,
		0x62DBA47ACCDE7AD7ULL,
		0x7A1D2567C9E8BB49ULL,
		0x63D7D560B6C281E2ULL,
		0x01BFABF12B09FB4FULL,
		0x544D950FE52B1BE6ULL,
		0xE92CC2C5B3F7281BULL,
		0x4D72FF49F9BD9EAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x218EA67C13BE568EULL,
		0xDAA003F5C3215E15ULL,
		0x54FD2F5AED7DEA67ULL,
		0xBB8EDFDC52267EB0ULL,
		0x4757EC11D75C9AACULL,
		0x5CCDC270AABD8C0BULL,
		0x34EA52CFAFA251B5ULL,
		0xB35832A5755CCF47ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6170FA3D45572AD4ULL,
		0x222AD9269C34F5CDULL,
		0x1B70A3BB12E5B2D9ULL,
		0xDCFB64A79B8FB3B8ULL,
		0xDBE2652FCE673498ULL,
		0xCD2717D0AF947C4FULL,
		0x89C493F48C040E9CULL,
		0xECC2DE70C002E931ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3CDF83F872FB50DULL,
		0x93AF9E6C6788A686ULL,
		0x143313EA4104A344ULL,
		0xF3D8414E0249BDDFULL,
		0x4976687D509BD40AULL,
		0xF14002FD208BAA01ULL,
		0xEB54007410413350ULL,
		0x85BDB84B0D45BF7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DA301FDBE2775C7ULL,
		0x8E7B3ABA34AC4F46ULL,
		0x073D8FD0D1E10F94ULL,
		0xE92323599945F5D9ULL,
		0x926BFCB27DCB608DULL,
		0xDBE714D38F08D24EULL,
		0x9E7093807BC2DB4BULL,
		0x67052625B2BD29B5ULL
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
		0x9D9F60F24E59B807ULL,
		0x1CB44270E81769E5ULL,
		0x6833F4FE4BC1F813ULL,
		0x013BD1A83B7ED669ULL,
		0x4C7711C766B8DD65ULL,
		0xBE381F2498164FB0ULL,
		0xC1129911BCEC4D27ULL,
		0xFF2186EF0C8FF9E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C55EE23A7A2CF6ULL,
		0x70B2D7136D469728ULL,
		0x939ADD6DE59F13A1ULL,
		0x5833478EF0BEE326ULL,
		0xE136C9711FDD9235ULL,
		0xB089B122ACA3AD41ULL,
		0x2DDD9EBD40CD1853ULL,
		0x080AF19CE0634C59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ADA021013DF8B11ULL,
		0xAC016B5D7AD0D2BDULL,
		0xD49917906622E471ULL,
		0xA9088A194ABFF342ULL,
		0x6B40485646DB4B2FULL,
		0x0DAE6E01EB72A26EULL,
		0x9334FA547C1F34D4ULL,
		0xF71695522C2CAD8DULL
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
		0x70E40B5884A25760ULL,
		0x93380085025E1523ULL,
		0x7D8921E079E8D0C9ULL,
		0xBF08657A77374F96ULL,
		0xDA083662C4CAB297ULL,
		0x919A4C93665836E8ULL,
		0x03696B59B4391E8EULL,
		0x07E8D9E8B4140CEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x833D45B986D0B85CULL,
		0x32949A1E9366602AULL,
		0x958EC7060E413274ULL,
		0x376AE7F7F9477A44ULL,
		0x77D4373CA5E3AA26ULL,
		0x646035FA7C40BCB6ULL,
		0xA0F7CE908BC1C903ULL,
		0xBE6AF3E5700CF46FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA6C59EFDD19F04ULL,
		0x60A366666EF7B4F8ULL,
		0xE7FA5ADA6BA79E55ULL,
		0x879D7D827DEFD551ULL,
		0x6233FF261EE70871ULL,
		0x2D3A1698EA177A32ULL,
		0x62719CC92877558BULL,
		0x497DE6034407187FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6B6AD7CD792774FBULL,
		0x0050A6E1AA370A4CULL,
		0x35C41B2A22E8A0F6ULL,
		0xE2B13F7E0D65F345ULL,
		0x36DC82B7098D4322ULL,
		0x8C3C248B6074E042ULL,
		0x01B8A9C1F289712CULL,
		0xA10A19887486E9E1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4112BEE4E262650ULL,
		0x0274C2E14F1901D2ULL,
		0xDB226C5A009D8677ULL,
		0xFCCBD92A0AC20B06ULL,
		0x70BCA53EBA7658AFULL,
		0x6AC0214EEB085ED1ULL,
		0xE0472DA3C2D9F0B2ULL,
		0xF8617158D1174BB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7759ABDF2B014EABULL,
		0xFDDBE4005B1E0879ULL,
		0x5AA1AED0224B1A7EULL,
		0xE5E5665402A3E83EULL,
		0xC61FDD784F16EA72ULL,
		0x217C033C756C8170ULL,
		0x21717C1E2FAF807AULL,
		0xA8A8A82FA36F9E2BULL
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
		0xBD76CD2ABCB97F4BULL,
		0xACF21571C09539F9ULL,
		0x2A9718AB4DB19AB6ULL,
		0xD6452FD3548ECF94ULL,
		0x6A8EBA271901B3D7ULL,
		0xE44F1DABA9174DEFULL,
		0x12A2C543410A199CULL,
		0x4839E38F907A4467ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFFC815B4ECB7956ULL,
		0x48F34D8A71C58C20ULL,
		0xB52E99B6B2E1974BULL,
		0x2D85F5FFB7A910CAULL,
		0xA7EDDBE0273E723BULL,
		0xD3BD45B460F6E6A1ULL,
		0x72A19CB4FEE150D5ULL,
		0x304905F9A9637FC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD7A4BCF6DEE05F5ULL,
		0x63FEC7E74ECFADD8ULL,
		0x75687EF49AD0036BULL,
		0xA8BF39D39CE5BEC9ULL,
		0xC2A0DE46F1C3419CULL,
		0x1091D7F74820674DULL,
		0xA001288E4228C8C7ULL,
		0x17F0DD95E716C4A4ULL
	}};
	sign = 0;
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
		0x13EF7ACDA008D20BULL,
		0x9341519EE3F4F36AULL,
		0x884144677298B7BEULL,
		0x2D482AE89639AAA9ULL,
		0x806B057FDD436A52ULL,
		0xB79DA7C8D485E916ULL,
		0x7277ECA6AA73EA7DULL,
		0xC83BAACBA958940CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB923AA5C2D9E61ULL,
		0x8597D25A46C33220ULL,
		0x48865577EEB90D27ULL,
		0x8A15F9E1F3F1AF11ULL,
		0x5CACEE31269CB98BULL,
		0xAB19303125B1DA77ULL,
		0x23FAB39E291DADE9ULL,
		0x2CACC93370313AA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7536572343DB33AAULL,
		0x0DA97F449D31C149ULL,
		0x3FBAEEEF83DFAA97ULL,
		0xA3323106A247FB98ULL,
		0x23BE174EB6A6B0C6ULL,
		0x0C847797AED40E9FULL,
		0x4E7D390881563C94ULL,
		0x9B8EE1983927596AULL
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
		0xC95F37A1A71E975EULL,
		0x54CCD4BB93147E82ULL,
		0xD9B5D4B79246C23CULL,
		0xB8F75F047986F657ULL,
		0xBC93D881A1BA46B3ULL,
		0x09BD8280739B354BULL,
		0x66B157591A67D651ULL,
		0x98DEF2434E4F24E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EAD7F6BDD99310DULL,
		0x22A13FFE5C8DBB0AULL,
		0x949CC99EB1A19252ULL,
		0x00DCFA27900B12D5ULL,
		0xAF8C87AF9A749726ULL,
		0xBEAF3AE238B11D77ULL,
		0x87F8F00C12AE2EB9ULL,
		0xBAA4FA1721E6EAE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB1B835C9856651ULL,
		0x322B94BD3686C378ULL,
		0x45190B18E0A52FEAULL,
		0xB81A64DCE97BE382ULL,
		0x0D0750D20745AF8DULL,
		0x4B0E479E3AEA17D4ULL,
		0xDEB8674D07B9A797ULL,
		0xDE39F82C2C683A00ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3F823B8C5FF2AD31ULL,
		0x44063DDE64300661ULL,
		0xB6181376EDC2C3BDULL,
		0x85312DFC7ACEFAEAULL,
		0xD39A975F42B524E3ULL,
		0xE5A7923E437DBF00ULL,
		0xB05B9499434349F8ULL,
		0x58DEE8561A669FB7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x222B85E163E0F715ULL,
		0x9CFC35A97287F963ULL,
		0xE3E84A1C49CBC4C5ULL,
		0x1C4DF71AC89923C0ULL,
		0x0F2F53488C7A2F72ULL,
		0x787ABDB0CDF83092ULL,
		0xE98A5390A8EF937BULL,
		0x24DB3ECFF6EF4FFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D56B5AAFC11B61CULL,
		0xA70A0834F1A80CFEULL,
		0xD22FC95AA3F6FEF7ULL,
		0x68E336E1B235D729ULL,
		0xC46B4416B63AF571ULL,
		0x6D2CD48D75858E6EULL,
		0xC6D141089A53B67DULL,
		0x3403A98623774FBAULL
	}};
	sign = 0;
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
		0x9C92949405FC7D56ULL,
		0x3333EE4DB04AFC09ULL,
		0x409027CAC2AA4FF0ULL,
		0xF291CB6B0AE655D4ULL,
		0xE4518F65D38A73C9ULL,
		0x6A0A94CBB2A381FAULL,
		0xB8E06BE391A88F7BULL,
		0xD31A8FAD1C4E915AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBABD92D764BA262BULL,
		0x1C5F17E968E2169FULL,
		0xE3D9FC5A5CB2DD59ULL,
		0x9DA8F34DCA9E1F45ULL,
		0xD41BEDB639C57623ULL,
		0x31F441CE75E172E7ULL,
		0x48A6BCED7EB81445ULL,
		0x83858AE9F0DD6FB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1D501BCA142572BULL,
		0x16D4D6644768E569ULL,
		0x5CB62B7065F77297ULL,
		0x54E8D81D4048368EULL,
		0x1035A1AF99C4FDA6ULL,
		0x381652FD3CC20F13ULL,
		0x7039AEF612F07B36ULL,
		0x4F9504C32B7121A5ULL
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
		0x0FC1BE48FD7DA69DULL,
		0x6FE86E545F268019ULL,
		0xE9DF2ACAB44B76D8ULL,
		0x52E172E9CA4C8A9DULL,
		0xDEED8A101DA0C329ULL,
		0x294AAB7C95C8C90EULL,
		0x44C0912A10CE7B2DULL,
		0x7EF7559A02E801BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE344384E700AB7ULL,
		0x3CBDB484DFDBFA8CULL,
		0x88DF40893608DE5DULL,
		0xAB3F84E511B36EB4ULL,
		0x14A31026E512069AULL,
		0x58040DB10604685CULL,
		0x2AFDC01C15F0BD1FULL,
		0xBB4E711D54AE0D2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1DE7A10AF0D9BE6ULL,
		0x332AB9CF7F4A858CULL,
		0x60FFEA417E42987BULL,
		0xA7A1EE04B8991BE9ULL,
		0xCA4A79E9388EBC8EULL,
		0xD1469DCB8FC460B2ULL,
		0x19C2D10DFADDBE0DULL,
		0xC3A8E47CAE39F490ULL
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
		0xC148237BA2C1D174ULL,
		0xD50DE93C8951DADCULL,
		0xA21996A8DA664963ULL,
		0x262FC2C82624E58EULL,
		0x3F5FA52468425C24ULL,
		0x0131620F80586208ULL,
		0x756C7E9BB96B2533ULL,
		0xBC8C5B6781FE5BB5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D308FE425A60AEULL,
		0xEA2802E51D35D195ULL,
		0x94C8697A5546CAEEULL,
		0xCA5F48BE328CCC04ULL,
		0xB3995DE4E6DCAF09ULL,
		0xF68EDEFB84A39C6BULL,
		0x9BB7A32C347DCBBDULL,
		0xF1BF256A513203BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B751A7D606770C6ULL,
		0xEAE5E6576C1C0947ULL,
		0x0D512D2E851F7E74ULL,
		0x5BD07A09F398198AULL,
		0x8BC6473F8165AD1AULL,
		0x0AA28313FBB4C59CULL,
		0xD9B4DB6F84ED5975ULL,
		0xCACD35FD30CC57F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x878BA4FA26EF37E0ULL,
		0xCB8F1932700B913BULL,
		0x695FED083933514DULL,
		0xB3FBE8BE9D89C71CULL,
		0xB0A4962AF7C06FA3ULL,
		0x4E08383A09D14D7AULL,
		0xC63168AC900D1EA8ULL,
		0x0AC330E3444E3B99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA22E642367433EULL,
		0xB566BFA019DA6E5CULL,
		0xDA4BD070D06F825EULL,
		0x6746819CA6E56A8DULL,
		0x0F1BBE3E9009DAADULL,
		0xEC97FB61EF302994ULL,
		0x8E15D6315E1FF53EULL,
		0xFCF61D7EEA6AB8ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69E976960387F4A2ULL,
		0x16285992563122DFULL,
		0x8F141C9768C3CEEFULL,
		0x4CB56721F6A45C8EULL,
		0xA188D7EC67B694F6ULL,
		0x61703CD81AA123E6ULL,
		0x381B927B31ED2969ULL,
		0x0DCD136459E382ADULL
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
		0x10DDF89033B52BDBULL,
		0x233E014761B1E328ULL,
		0x9AA704B22D1B1502ULL,
		0x846F234C3AEC16B5ULL,
		0xB1FDF1D2A88A7849ULL,
		0xCD88DA7D02F0F8E9ULL,
		0xD759246EF3D73C34ULL,
		0xA9AFCC1DD6AD9F54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C78381D451A5DCULL,
		0x32A410F097922B03ULL,
		0x494C7DF0C569A82DULL,
		0x0C2A44BC4E156DF1ULL,
		0x96A3C4C980A16B11ULL,
		0xDBCE2CFFE4CEE06AULL,
		0x40ED96B81AB6A6B8ULL,
		0x24B9976766C8560AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA16750E5F6385FFULL,
		0xF099F056CA1FB824ULL,
		0x515A86C167B16CD4ULL,
		0x7844DE8FECD6A8C4ULL,
		0x1B5A2D0927E90D38ULL,
		0xF1BAAD7D1E22187FULL,
		0x966B8DB6D920957BULL,
		0x84F634B66FE5494AULL
	}};
	sign = 0;
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
		0xAA6F1D7E67D2AB92ULL,
		0xF24C59E1C607F924ULL,
		0x7CE4E609DA8C4265ULL,
		0x308C6CB878281E02ULL,
		0x876231CF16B78F45ULL,
		0x8654DB65C9BA8761ULL,
		0x637A300470863248ULL,
		0x839B727DF191BCC6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F72632DFF3CF863ULL,
		0xBADEEC5383A15898ULL,
		0xA7F632F2C81F84DFULL,
		0x5C20235CE94E0CD2ULL,
		0x796827743A3D2240ULL,
		0x409F86B392EC3BC8ULL,
		0x9DD4086522E8E08FULL,
		0xCA1743304FA1F127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AFCBA506895B32FULL,
		0x376D6D8E4266A08CULL,
		0xD4EEB317126CBD86ULL,
		0xD46C495B8EDA112FULL,
		0x0DFA0A5ADC7A6D04ULL,
		0x45B554B236CE4B99ULL,
		0xC5A6279F4D9D51B9ULL,
		0xB9842F4DA1EFCB9EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDA685B5E341A1938ULL,
		0xE094EB32D468F720ULL,
		0x6ACABE4CB299992AULL,
		0xD303E1AD2AF84D7FULL,
		0xC98C2FE302305A3AULL,
		0x87898BB6523F55D6ULL,
		0xF570C52DCF78FCB9ULL,
		0x16105381CE197199ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17761DCFD363998FULL,
		0x6E59777368E9C43AULL,
		0xA9EA8D8D0E905E7FULL,
		0x8FF205953E81B897ULL,
		0x35026F9A41EB8A20ULL,
		0x4C63316F2F388602ULL,
		0x1B21DA820C2A3A4EULL,
		0xD4F6B3242C7AB09CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2F23D8E60B67FA9ULL,
		0x723B73BF6B7F32E6ULL,
		0xC0E030BFA4093AABULL,
		0x4311DC17EC7694E7ULL,
		0x9489C048C044D01AULL,
		0x3B265A472306CFD4ULL,
		0xDA4EEAABC34EC26BULL,
		0x4119A05DA19EC0FDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x89233A64518EB5A4ULL,
		0xCA7FE3E4B235FB98ULL,
		0xD667D975536E6ED5ULL,
		0xCC3C91655600441DULL,
		0xAB8FF06963C1F590ULL,
		0x52543A19B262750AULL,
		0x06975FC3C9F16F76ULL,
		0x444477CED4C980CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA467A4E78C0E55A4ULL,
		0xCAD27DE4652DB985ULL,
		0x0F8B71F4939F119EULL,
		0xF049BFF70719642AULL,
		0x4408CECBC079AA98ULL,
		0x144B37775A51EF6BULL,
		0x74A4B6315FCD6A39ULL,
		0x0142FE60685F7B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4BB957CC5806000ULL,
		0xFFAD66004D084212ULL,
		0xC6DC6780BFCF5D36ULL,
		0xDBF2D16E4EE6DFF3ULL,
		0x6787219DA3484AF7ULL,
		0x3E0902A25810859FULL,
		0x91F2A9926A24053DULL,
		0x4301796E6C6A05CDULL
	}};
	sign = 0;
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
		0x31316AAE33749FA8ULL,
		0x403917630E8CA1B1ULL,
		0x05940ACBD610306BULL,
		0x15D1F9198DF3D624ULL,
		0xAB58D891B52D90B0ULL,
		0xC10BFBD631480D5BULL,
		0xAEA1474748C82B34ULL,
		0xCFD71F9517EA8612ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B34199EB00F90DULL,
		0x23626D64179D3E57ULL,
		0x94F573C380A774EAULL,
		0x396B040F3AC55DC9ULL,
		0xA8AFFC910465783EULL,
		0xACD889138E41BF40ULL,
		0x0F1D9B266514764CULL,
		0x7C249E4B530A8D67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C7E29144873A69BULL,
		0x1CD6A9FEF6EF635AULL,
		0x709E97085568BB81ULL,
		0xDC66F50A532E785AULL,
		0x02A8DC00B0C81871ULL,
		0x143372C2A3064E1BULL,
		0x9F83AC20E3B3B4E8ULL,
		0x53B28149C4DFF8ABULL
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
		0x84049E3FA752838CULL,
		0x5E69C61918AF01B1ULL,
		0x12B379752DBB38D2ULL,
		0xE2A04F54D1196F6CULL,
		0xCD6A8618401748D6ULL,
		0x51171A5A359E4BFEULL,
		0xC672187F4D75237BULL,
		0xA78AEE33F9906B76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9236B1FF6FA16488ULL,
		0xAC7249BF919CCABEULL,
		0x89086FDA47278E63ULL,
		0x6F1E0EBD0881B279ULL,
		0xA59311D0D28D7BE8ULL,
		0x9C067E3C9254FC5AULL,
		0x1EF45F9F70C84A48ULL,
		0x6B75FED8B259FF87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1CDEC4037B11F04ULL,
		0xB1F77C59871236F2ULL,
		0x89AB099AE693AA6EULL,
		0x73824097C897BCF2ULL,
		0x27D774476D89CCEEULL,
		0xB5109C1DA3494FA4ULL,
		0xA77DB8DFDCACD932ULL,
		0x3C14EF5B47366BEFULL
	}};
	sign = 0;
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
		0xA75EB7A42AE381B3ULL,
		0x3E417DFB2990BDBFULL,
		0xDD3080FE4C900568ULL,
		0xE529CFBC738238F2ULL,
		0x931BCB95ADF35395ULL,
		0xF04072B04BD11010ULL,
		0xD47AAFA36DD71C75ULL,
		0xD085F16DD1262D11ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C8437889512529ULL,
		0x67760E0E570068CDULL,
		0x1C96C65B40B64BA3ULL,
		0xECEDBE8C3F4CFD58ULL,
		0xF6691C6B4CBCF427ULL,
		0xDB9035501E2053A6ULL,
		0x8028044801943095ULL,
		0x593B570675C0C5D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F96742BA1925C8AULL,
		0xD6CB6FECD29054F2ULL,
		0xC099BAA30BD9B9C4ULL,
		0xF83C113034353B9AULL,
		0x9CB2AF2A61365F6DULL,
		0x14B03D602DB0BC69ULL,
		0x5452AB5B6C42EBE0ULL,
		0x774A9A675B65673EULL
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
		0x8E3028439BECD0A8ULL,
		0x9AA8FC8C779F058BULL,
		0xE93E83A2DBE92FADULL,
		0x558EB2A16042B212ULL,
		0xEF5F4EC6A3A7BABDULL,
		0xFA88D73A80FB322EULL,
		0xA92F133C4C209362ULL,
		0x7FDEC2B69A01499CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D202D9EE1C960BAULL,
		0x769C9B16E1AC0A82ULL,
		0x8E36464EDD068602ULL,
		0x13CA7E4511FA20E2ULL,
		0xC328D8A226D7CF74ULL,
		0x431BDD38341DDCBDULL,
		0x3761D459C3D71D5FULL,
		0xBA6FA0243380E105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x610FFAA4BA236FEEULL,
		0x240C617595F2FB09ULL,
		0x5B083D53FEE2A9ABULL,
		0x41C4345C4E489130ULL,
		0x2C3676247CCFEB49ULL,
		0xB76CFA024CDD5571ULL,
		0x71CD3EE288497603ULL,
		0xC56F229266806897ULL
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
		0x08B89E6DE7026C25ULL,
		0x16F65A504F3A844DULL,
		0xC98F8069C61861D9ULL,
		0xA378B50E0919E0A1ULL,
		0x1A022A1094C5E911ULL,
		0x12089083400F668EULL,
		0x567A76043AEA0BBDULL,
		0xBEA490489C3E8D24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6ADB1B08C00ED50ULL,
		0x4D86397C4D5BC36AULL,
		0xB44EC1F13EA5A4A1ULL,
		0xF013F8796E1D9D59ULL,
		0x776D87894F31BD2EULL,
		0x12C1C93862D3C97CULL,
		0x2AA72CB13E561751ULL,
		0xD4CA017A1274275AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x320AECBD5B017ED5ULL,
		0xC97020D401DEC0E2ULL,
		0x1540BE788772BD37ULL,
		0xB364BC949AFC4348ULL,
		0xA294A28745942BE2ULL,
		0xFF46C74ADD3B9D11ULL,
		0x2BD34952FC93F46BULL,
		0xE9DA8ECE89CA65CAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9A236B72A2674B29ULL,
		0x1026B4D4C2A14942ULL,
		0x9D95EA9B01E084F0ULL,
		0xD4273AE494F2EB23ULL,
		0x8D8E4A9F64EC885BULL,
		0x7A5CD811D4F2BB98ULL,
		0x248EC21A733ABB2BULL,
		0x9EB1C3EF16D666E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8B0E6730128785ULL,
		0x78C1D8FEE2439939ULL,
		0xB129BAEEF4C09AE3ULL,
		0xB2EBACBAF3F35945ULL,
		0xFFEAC2F2E241725EULL,
		0xD95080877E17C59FULL,
		0xBDDD1F878FCCB428ULL,
		0x1DC7DF888CE169C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB985D0B7254C3A4ULL,
		0x9764DBD5E05DB008ULL,
		0xEC6C2FAC0D1FEA0CULL,
		0x213B8E29A0FF91DDULL,
		0x8DA387AC82AB15FDULL,
		0xA10C578A56DAF5F8ULL,
		0x66B1A292E36E0702ULL,
		0x80E9E46689F4FD20ULL
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
		0x42A240DAA9EA190BULL,
		0x769F5D929BF8E77AULL,
		0x0D13531B6CD29E23ULL,
		0xC4ED0A53E7FE619BULL,
		0xC67958506CA7F2E1ULL,
		0x937F608687E1782AULL,
		0xA1C8C99F9FF2D229ULL,
		0x7D84DBB2FF1197FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07A01C3E85AB272ULL,
		0x8B591157FAFEC313ULL,
		0x513D9CC662D9AAA5ULL,
		0x56C625613F6962AAULL,
		0x08DBFB7C22CF7D25ULL,
		0x5B5E4B167BF12A92ULL,
		0x9905409742000717ULL,
		0x8872117A0BA18DA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72283F16C18F6699ULL,
		0xEB464C3AA0FA2466ULL,
		0xBBD5B65509F8F37DULL,
		0x6E26E4F2A894FEF0ULL,
		0xBD9D5CD449D875BCULL,
		0x382115700BF04D98ULL,
		0x08C389085DF2CB12ULL,
		0xF512CA38F3700A5DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x49DEFF6B2D4BC6F6ULL,
		0xFA1E7ADAF2DA6BF1ULL,
		0x508D0A231D46687AULL,
		0xBE68C8A5C9771775ULL,
		0x5EAC217353FC2799ULL,
		0x2CEF828BF859774DULL,
		0x3F6DCD2ABC8F3B3DULL,
		0x360270BD5429293EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C975123F5F71D69ULL,
		0xB78E5E43F1AAEB25ULL,
		0xC392BE86D339FCFCULL,
		0xB46AE6D29202DC9DULL,
		0xBA3973EA80B4D2D8ULL,
		0x5C171F4D05F0B575ULL,
		0x45F881D2CE2EDD04ULL,
		0x2D453D63E4D42390ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD47AE473754A98DULL,
		0x42901C97012F80CBULL,
		0x8CFA4B9C4A0C6B7EULL,
		0x09FDE1D337743AD7ULL,
		0xA472AD88D34754C1ULL,
		0xD0D8633EF268C1D7ULL,
		0xF9754B57EE605E38ULL,
		0x08BD33596F5505ADULL
	}};
	sign = 0;
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
		0x32DC697AAFFAC14DULL,
		0x5D643C38512D821BULL,
		0x96EE21F84E16EB85ULL,
		0x9A8B55E445EC1A37ULL,
		0x8272F4B1CB2992DEULL,
		0x23F34B9087A54F31ULL,
		0x50CB9CE6B71F5D8BULL,
		0x01536D362159DA7CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE355A948752BAACULL,
		0x045CBAB2B3E4D546ULL,
		0x7FF35F7696533E1DULL,
		0x4E5C623C91A23A96ULL,
		0x70AC6FA97DA4B903ULL,
		0x27B36BDE71A3E5C5ULL,
		0x109E9745964CC9FAULL,
		0xC9232D4E5B074797ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74A70EE628A806A1ULL,
		0x590781859D48ACD4ULL,
		0x16FAC281B7C3AD68ULL,
		0x4C2EF3A7B449DFA1ULL,
		0x11C685084D84D9DBULL,
		0xFC3FDFB21601696CULL,
		0x402D05A120D29390ULL,
		0x38303FE7C65292E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBB84083893A9FFCAULL,
		0x409F0028ADCC8E60ULL,
		0xC3FEC2DB78C8F66AULL,
		0x55FF5225FDE72CE9ULL,
		0xEAA146BE72874657ULL,
		0x7FBB08191355B7D1ULL,
		0x922749F3B144C6B2ULL,
		0x5F499E97B6220624ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E724021B28630CULL,
		0x607CB03DC8E3F7B0ULL,
		0x8DA3F2B707C977DCULL,
		0x6E43B779D581F66FULL,
		0x40B5EA79AE46587DULL,
		0x5F0728AD307A501EULL,
		0x08D2B061F2997224ULL,
		0x58974869A0D589F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x349CE43678819CBEULL,
		0xE0224FEAE4E896B0ULL,
		0x365AD02470FF7E8DULL,
		0xE7BB9AAC2865367AULL,
		0xA9EB5C44C440EDD9ULL,
		0x20B3DF6BE2DB67B3ULL,
		0x89549991BEAB548EULL,
		0x06B2562E154C7C32ULL
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
		0xD6BC1358A4C95059ULL,
		0xF7CDCD74E826B56AULL,
		0xED77AD9AF1FF98E5ULL,
		0xC608E981D0F89710ULL,
		0xAFD1A9D2C3441B53ULL,
		0x18A150BC58D69E5AULL,
		0x0ECC446E50E77551ULL,
		0xE152F418DB004DCEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00229EAB76F179AULL,
		0xC5B3048230A5078EULL,
		0x586F629E23120D6AULL,
		0x7A1D2463E13214A5ULL,
		0xD10B92F198775E42ULL,
		0x67EC3BAE43E6CA25ULL,
		0x8CCDF79ED7C6001EULL,
		0x4034131197497A15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16B9E96DED5A38BFULL,
		0x321AC8F2B781ADDCULL,
		0x95084AFCCEED8B7BULL,
		0x4BEBC51DEFC6826BULL,
		0xDEC616E12ACCBD11ULL,
		0xB0B5150E14EFD434ULL,
		0x81FE4CCF79217532ULL,
		0xA11EE10743B6D3B8ULL
	}};
	sign = 0;
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
		0x159CBFAA8E8E4457ULL,
		0xA9A54C5E336CAEAFULL,
		0x6F98A85F6B2D867BULL,
		0x1CA6484010F88397ULL,
		0xC6DCABA6CFE82971ULL,
		0x30184C86B6948822ULL,
		0xFAB1C0C2C92956A3ULL,
		0x0989C478DB5EB023ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x43F7F61B58389505ULL,
		0xE5144971EFA57508ULL,
		0x60A19AE279032D65ULL,
		0x5C372219D39FB4DDULL,
		0x2A35DB3354521E8EULL,
		0x6AD3859E0BACB1F2ULL,
		0x304CA6BF6EFE2289ULL,
		0xA1984E601DB6EF90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1A4C98F3655AF52ULL,
		0xC49102EC43C739A6ULL,
		0x0EF70D7CF22A5915ULL,
		0xC06F26263D58CEBAULL,
		0x9CA6D0737B960AE2ULL,
		0xC544C6E8AAE7D630ULL,
		0xCA651A035A2B3419ULL,
		0x67F17618BDA7C093ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA1E6042DC848037FULL,
		0xD1990FAC9218A531ULL,
		0x5314035E3AC6881DULL,
		0x19542A74F20C1AC4ULL,
		0x9075180D76161023ULL,
		0x59450F4D7CA37ADCULL,
		0xDDFC709A794611CFULL,
		0xDF49F91F082BC4C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4E9760F7EF9157ULL,
		0x2C4288BD5224A39DULL,
		0x9A06DAAF245E7C85ULL,
		0x98AF06D113BD4549ULL,
		0xFB20304FB51D2DF6ULL,
		0x01F930BF25304512ULL,
		0x33F4432E747171D0ULL,
		0xE2311E4BDE7FD8D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27976CCCD0587228ULL,
		0xA55686EF3FF40194ULL,
		0xB90D28AF16680B98ULL,
		0x80A523A3DE4ED57AULL,
		0x9554E7BDC0F8E22CULL,
		0x574BDE8E577335C9ULL,
		0xAA082D6C04D49FFFULL,
		0xFD18DAD329ABEBEBULL
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
		0x4DFAE3BDC2BEF7FFULL,
		0x99BB29308244B834ULL,
		0x158745891C28CBA7ULL,
		0xAEA4C4D154755FF4ULL,
		0x7954F2D6A483B278ULL,
		0xCDB26B1C9ED97D06ULL,
		0x292C7FD9435D9488ULL,
		0x430EBDBD09ACCD1CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F24A6FEF67CBDA6ULL,
		0x88183C564E6D04B7ULL,
		0x758FB70CB5821B63ULL,
		0x6CFA527EA2AC8E4BULL,
		0x448F8D954C545225ULL,
		0x7C7F4234B8814A58ULL,
		0x3473A15E454DA9F9ULL,
		0x942ED3C9540163E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ED63CBECC423A59ULL,
		0x11A2ECDA33D7B37DULL,
		0x9FF78E7C66A6B044ULL,
		0x41AA7252B1C8D1A8ULL,
		0x34C56541582F6053ULL,
		0x513328E7E65832AEULL,
		0xF4B8DE7AFE0FEA8FULL,
		0xAEDFE9F3B5AB6938ULL
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
		0x37A08884261C9F14ULL,
		0xB03FC3B4FF35295CULL,
		0xAECD1567CDA0E850ULL,
		0xAE7522692A240EC9ULL,
		0xE8DCB17EF119DA47ULL,
		0xD88ACE95F593FFF7ULL,
		0x6E2504E9AAF78EC5ULL,
		0xC2B15A1670AB7858ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9A944E9904623CULL,
		0xDEE4D86D99F44FA1ULL,
		0x6C1B21F65EDDEBDEULL,
		0x6495CCFE9A54725CULL,
		0xF6B923B495B2D6CFULL,
		0x694FA87A2958B842ULL,
		0x52BA402BD6AC5916ULL,
		0x616E0AE70DA2A6C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D05F4358D183CD8ULL,
		0xD15AEB476540D9BBULL,
		0x42B1F3716EC2FC71ULL,
		0x49DF556A8FCF9C6DULL,
		0xF2238DCA5B670378ULL,
		0x6F3B261BCC3B47B4ULL,
		0x1B6AC4BDD44B35AFULL,
		0x61434F2F6308D18FULL
	}};
	sign = 0;
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
		0x20EB2E0ADD35272EULL,
		0x527C144E47E5A7BEULL,
		0xD9DD99F48F398DF2ULL,
		0xB2D6F76B0FEB80B4ULL,
		0xBB7038BC61F5BEC2ULL,
		0xAEB276A4B179AE3AULL,
		0x96EAC290D4E2A386ULL,
		0x0780AFB78858409BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2DACCA06FE7EF8ULL,
		0xA2C3F8A3237E0179ULL,
		0xBBD9DACE43250554ULL,
		0xA341F7E51FBE08A1ULL,
		0x6B6A98075416F219ULL,
		0xB770CEDF90F744D9ULL,
		0xB725C992BA3CB9D1ULL,
		0xF77429D0E499B5AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04BD8140D636A836ULL,
		0xAFB81BAB2467A645ULL,
		0x1E03BF264C14889DULL,
		0x0F94FF85F02D7813ULL,
		0x5005A0B50DDECCA9ULL,
		0xF741A7C520826961ULL,
		0xDFC4F8FE1AA5E9B4ULL,
		0x100C85E6A3BE8AEBULL
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
		0xF1BAA6C271534E2EULL,
		0xB2FD93AD9D6F0231ULL,
		0xA646FBF12358511EULL,
		0x4C9E32A35EF89CA3ULL,
		0xDEB9E99B0090AFB9ULL,
		0x4EFEE94AED937038ULL,
		0xEC8816B3F700571EULL,
		0xE8D3452DE1DDD0E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92D29BC1A267C08ULL,
		0x0D98B80ABBAC1CDEULL,
		0xF7F7F87196AB1089ULL,
		0x57089E98704680BEULL,
		0xA632048D5ACFEAA7ULL,
		0x919F78FF05F039A4ULL,
		0xA47D48878F612C28ULL,
		0xD399A5FB5D3E85AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088D7D06572CD226ULL,
		0xA564DBA2E1C2E553ULL,
		0xAE4F037F8CAD4095ULL,
		0xF595940AEEB21BE4ULL,
		0x3887E50DA5C0C511ULL,
		0xBD5F704BE7A33694ULL,
		0x480ACE2C679F2AF5ULL,
		0x15399F32849F4B36ULL
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
		0x8C84F797E5407274ULL,
		0x2CCD487D9C712122ULL,
		0x6FB65AC78C0BBCFBULL,
		0x8515D731DDD8C8DBULL,
		0x1B4F03CD6F88D832ULL,
		0x2780AE71CB45D1D1ULL,
		0x7A57765D5B35C763ULL,
		0xCF2F553CD217978BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08D7C1EF6E44CEE7ULL,
		0xE9AD6EA59AE233F6ULL,
		0xE5769413B6B25BB9ULL,
		0x61651D2C2F047890ULL,
		0x4E3E3EC3CC9B2963ULL,
		0xA8379968C2691F1DULL,
		0xCB38B994120A3700ULL,
		0x77175E080072FD42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83AD35A876FBA38DULL,
		0x431FD9D8018EED2CULL,
		0x8A3FC6B3D5596141ULL,
		0x23B0BA05AED4504AULL,
		0xCD10C509A2EDAECFULL,
		0x7F49150908DCB2B3ULL,
		0xAF1EBCC9492B9062ULL,
		0x5817F734D1A49A48ULL
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
		0x620FA844D3B8E8CAULL,
		0x5F27DF59A22384A6ULL,
		0x7CC6DE575D3B76F1ULL,
		0x913E61527DCC5230ULL,
		0xF97F8E100C6A6007ULL,
		0x16E187D86E4AF800ULL,
		0xF7E470766FA9AA17ULL,
		0x922741430CDF24FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89FEFF080434AF3CULL,
		0xBC5C909B445A4371ULL,
		0xE1981B09C1D8CCAFULL,
		0x2FD99663836A195BULL,
		0x41D70D4F30AC4324ULL,
		0x96F0C02302B1D6B7ULL,
		0xBE5ACE78CF328188ULL,
		0xE7003265E01354C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD810A93CCF84398EULL,
		0xA2CB4EBE5DC94134ULL,
		0x9B2EC34D9B62AA41ULL,
		0x6164CAEEFA6238D4ULL,
		0xB7A880C0DBBE1CE3ULL,
		0x7FF0C7B56B992149ULL,
		0x3989A1FDA077288EULL,
		0xAB270EDD2CCBD033ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x07E6DDAA313FC8D5ULL,
		0x9F8425396F670E77ULL,
		0xCA2AAD8278F68EE2ULL,
		0x253EB669BF2359F9ULL,
		0xED73BC24239DF591ULL,
		0xD60D230945E89D29ULL,
		0x9FC662477B96E630ULL,
		0x1FC93C96165A6F92ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC601A2C2BD9B363BULL,
		0x278EFE782CD3EA46ULL,
		0x8FFEEF0ECBFFD75BULL,
		0x75113FA2981EB795ULL,
		0x3C012E62CBCB863FULL,
		0x2C3A56BC9DA58759ULL,
		0x4355657F949C515EULL,
		0x68E04652B49093D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41E53AE773A4929AULL,
		0x77F526C142932430ULL,
		0x3A2BBE73ACF6B787ULL,
		0xB02D76C72704A264ULL,
		0xB1728DC157D26F51ULL,
		0xA9D2CC4CA84315D0ULL,
		0x5C70FCC7E6FA94D2ULL,
		0xB6E8F64361C9DBBDULL
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
		0x698F04F27110FE8DULL,
		0xC91D4FB68E2D5A92ULL,
		0x8FA59BB95DED7147ULL,
		0x48CEDE84260663FCULL,
		0xE4D45CFDBB837C9CULL,
		0x6B0BD65E20F99F14ULL,
		0xFA40B4FB5E4FFA69ULL,
		0x425AD5E59EC86FE3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB98CF95FEDE8D73ULL,
		0x238BA94C22FDD889ULL,
		0xEE241CF94C5C8DC5ULL,
		0xE7E0621BE4FAB4D9ULL,
		0xF8D7BFD9994D5354ULL,
		0x093007A6C7A6DA66ULL,
		0x341D07760454D192ULL,
		0xFD18B515C72E5B48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DF6355C7232711AULL,
		0xA591A66A6B2F8208ULL,
		0xA1817EC01190E382ULL,
		0x60EE7C68410BAF22ULL,
		0xEBFC9D2422362947ULL,
		0x61DBCEB75952C4ADULL,
		0xC623AD8559FB28D7ULL,
		0x454220CFD79A149BULL
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
		0x274EC955D6848FDAULL,
		0xB4551CD3A2783284ULL,
		0x40D63F819302E360ULL,
		0x9BAC2AB66F7CA259ULL,
		0x7C5566F2A3BBA760ULL,
		0xFABE3A5A93F96CD4ULL,
		0x0A934DFF27FCA627ULL,
		0x71E3C80C641932F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52F5E145BE3AF28ULL,
		0xB44D734818D9ED79ULL,
		0x6EF164E960C16CC8ULL,
		0xD8966E7852A2E8CEULL,
		0xB585C1DA90709D85ULL,
		0x2C4EEE7935000282ULL,
		0x52D22B45D8036804ULL,
		0xEF11A987793C1FC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x521F6B417AA0E0B2ULL,
		0x0007A98B899E450AULL,
		0xD1E4DA9832417698ULL,
		0xC315BC3E1CD9B98AULL,
		0xC6CFA518134B09DAULL,
		0xCE6F4BE15EF96A51ULL,
		0xB7C122B94FF93E23ULL,
		0x82D21E84EADD1332ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD821CC6F023647CDULL,
		0x9E8D7B8701AE98B7ULL,
		0x3E8C1528565D0E98ULL,
		0x535F896FF9D064F7ULL,
		0x91A284B1BE5A99E4ULL,
		0x8C9C74A911B46620ULL,
		0xDECBD147792C0A8AULL,
		0x9A78FFC939BFA3C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68B135017066385ULL,
		0xEAC269D5E7382643ULL,
		0x8AB57E8AE1AE4355ULL,
		0xDF5BFE614143366BULL,
		0x33D05BFB67FA330EULL,
		0x396EB1F23203C379ULL,
		0xDD77707E1F2A646CULL,
		0x2865D46ADEAA1F00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1196B91EEB2FE448ULL,
		0xB3CB11B11A767274ULL,
		0xB3D6969D74AECB42ULL,
		0x74038B0EB88D2E8BULL,
		0x5DD228B6566066D5ULL,
		0x532DC2B6DFB0A2A7ULL,
		0x015460C95A01A61EULL,
		0x72132B5E5B1584C3ULL
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
		0x8267AD240D5F14AEULL,
		0x42BFBFFD9B3E7DDAULL,
		0x1827142D1351FC59ULL,
		0x133C7B6E62EF9732ULL,
		0xDA2DEC82A9774140ULL,
		0x3016888447DCAB0CULL,
		0xADDF9AD0361B7F33ULL,
		0xAC3832621006346BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7288FF3061A64B19ULL,
		0x98F0941B9E1B2E29ULL,
		0x3F71D55A010ACA30ULL,
		0x5AFBCD8DC9A566A4ULL,
		0xDCF011956540EE94ULL,
		0x756B820DA0AB1C79ULL,
		0x821D658AB4E35574ULL,
		0xECC092A100588E77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FDEADF3ABB8C995ULL,
		0xA9CF2BE1FD234FB1ULL,
		0xD8B53ED312473228ULL,
		0xB840ADE0994A308DULL,
		0xFD3DDAED443652ABULL,
		0xBAAB0676A7318E92ULL,
		0x2BC23545813829BEULL,
		0xBF779FC10FADA5F4ULL
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
		0xC0B1929A31C85E6EULL,
		0xEDAF3082FEC59EE2ULL,
		0x89B507F57CFE5031ULL,
		0xF8C14E3873FE5586ULL,
		0xD3395387CE66AB1AULL,
		0x408F3BD806E8A443ULL,
		0x59896008C098A234ULL,
		0x37AA019CE2FA4042ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x532573B29FA8955FULL,
		0xEBAC8DD9D7B11E35ULL,
		0xECEBB9F22F525371ULL,
		0x017BB3B2C6826E91ULL,
		0x7C79D754C41ED5B7ULL,
		0xC18F2094CF0A7474ULL,
		0x14499AF5EBDF1E67ULL,
		0x4516F20E0990A6A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D8C1EE7921FC90FULL,
		0x0202A2A9271480ADULL,
		0x9CC94E034DABFCC0ULL,
		0xF7459A85AD7BE6F4ULL,
		0x56BF7C330A47D563ULL,
		0x7F001B4337DE2FCFULL,
		0x453FC512D4B983CCULL,
		0xF2930F8ED9699999ULL
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
		0xA4449992AED4634DULL,
		0xF10B3206523685A7ULL,
		0xDCF9B0C5D615B259ULL,
		0x8EE703A8EE6DE642ULL,
		0xADA65AEEEF81C402ULL,
		0x9F5F8EAE834DFF2EULL,
		0x0EC2AD94E2AD2C9CULL,
		0x8BC8F6F7C39C42BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x73223AC6CC694A2CULL,
		0xC4A0B852C07A0DC7ULL,
		0xF936591828259FD8ULL,
		0x52096CBFED284172ULL,
		0xC76B057B4A5021D5ULL,
		0xF15F89BBAAEA2143ULL,
		0x4FC0C83F1EB5E668ULL,
		0xA6BCC6D963668BEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31225ECBE26B1921ULL,
		0x2C6A79B391BC77E0ULL,
		0xE3C357ADADF01281ULL,
		0x3CDD96E90145A4CFULL,
		0xE63B5573A531A22DULL,
		0xAE0004F2D863DDEAULL,
		0xBF01E555C3F74633ULL,
		0xE50C301E6035B6CBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5C70B94F8B5D59DEULL,
		0xDA2F0FD8B01B2B6AULL,
		0x17CDFAE582EDEDA5ULL,
		0x527C5B0BB15302E4ULL,
		0xAD0D0B8C6AB52980ULL,
		0xB2F89FC3F42BFC8CULL,
		0x680A21B55803C2DAULL,
		0x6627BBC75C6294E8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x43FE2098169E739FULL,
		0x22659BD8C0DCC974ULL,
		0x8877CCB294DAEC3DULL,
		0x6BDF6A2993DFCD33ULL,
		0x76EB890C0C0335D4ULL,
		0x17493E907B6741AEULL,
		0x4021F66B063C089CULL,
		0x0F7537E709B40C01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x187298B774BEE63FULL,
		0xB7C973FFEF3E61F6ULL,
		0x8F562E32EE130168ULL,
		0xE69CF0E21D7335B0ULL,
		0x362182805EB1F3ABULL,
		0x9BAF613378C4BADEULL,
		0x27E82B4A51C7BA3EULL,
		0x56B283E052AE88E7ULL
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
		0x8B3353135EC7DA98ULL,
		0x7565C240E610E177ULL,
		0x1B8B26B57D3B8B27ULL,
		0x9AAA24ACD73D8893ULL,
		0xFFC62FC8D33DAE64ULL,
		0x69D8EBC415D888ACULL,
		0x92B8B796413914D0ULL,
		0x126490FA1C728950ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7A9827AB881666ULL,
		0x39F015F1E06D45D1ULL,
		0xBF00AB501F37C85FULL,
		0x65ED52A39E176E08ULL,
		0xE00E3688EEB45F8BULL,
		0x125BD8B7E3174ED9ULL,
		0x2EEDD4E827B2AC23ULL,
		0x7D53DE6F2E43E04BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DB8BAEBB33FC432ULL,
		0x3B75AC4F05A39BA6ULL,
		0x5C8A7B655E03C2C8ULL,
		0x34BCD20939261A8AULL,
		0x1FB7F93FE4894ED9ULL,
		0x577D130C32C139D3ULL,
		0x63CAE2AE198668ADULL,
		0x9510B28AEE2EA905ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE58B62FEAD9C2A93ULL,
		0xBF0F583C15359B8CULL,
		0x745E35F24D5F5314ULL,
		0x2BB886FB979CB17DULL,
		0x81A9F933AB778961ULL,
		0x57280179D4A984EEULL,
		0x47AFA4EA9FF24F2AULL,
		0x278DD6E2C37B2F61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F8B3E5E0175482AULL,
		0x23B1D110EBE29202ULL,
		0x879E276081F6EE79ULL,
		0x9765C1DA4CF96F01ULL,
		0x9ABE970278610F8FULL,
		0xDE88E38A9FA6A98FULL,
		0xD4A2463CF7DFEE38ULL,
		0xCD61FB768246A550ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x560024A0AC26E269ULL,
		0x9B5D872B2953098AULL,
		0xECC00E91CB68649BULL,
		0x9452C5214AA3427BULL,
		0xE6EB6231331679D1ULL,
		0x789F1DEF3502DB5EULL,
		0x730D5EADA81260F1ULL,
		0x5A2BDB6C41348A10ULL
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
		0x6CCD98784FDA3753ULL,
		0x301C2C99874DEF01ULL,
		0x6498D4F4B32D6B83ULL,
		0xF5D7668C2B2E98DBULL,
		0xA07F5C9C34762AF5ULL,
		0x847410AEA7C0A7B7ULL,
		0x5E0021A7C576FDEEULL,
		0xF3953918C1DB0C97ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x635E8A0A66F0F1F2ULL,
		0x672589404258E50BULL,
		0x88B2F0FFC5661C41ULL,
		0xD6E1EE8E18A4198DULL,
		0xC844BC9475AB5C97ULL,
		0x138E13EE69B188D8ULL,
		0xDB4F50647214E86DULL,
		0xAE9830298174E8D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x096F0E6DE8E94561ULL,
		0xC8F6A35944F509F6ULL,
		0xDBE5E3F4EDC74F41ULL,
		0x1EF577FE128A7F4DULL,
		0xD83AA007BECACE5EULL,
		0x70E5FCC03E0F1EDEULL,
		0x82B0D14353621581ULL,
		0x44FD08EF406623C4ULL
	}};
	sign = 0;
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
		0xCA040371058C3235ULL,
		0x95B08C8B41D2F839ULL,
		0x039A808EC97ED1A9ULL,
		0xE43A9D25698A1142ULL,
		0x60041AAF6A66D724ULL,
		0x1CE2FA5B35DF56BCULL,
		0xF50B799A70C5F067ULL,
		0xE866D31FF601FD8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA00A811BCC851BE9ULL,
		0x442EA0235B304432ULL,
		0xC9F8E50CF848C81CULL,
		0xA294EF52ED29D699ULL,
		0x6BA65D2734B66BAAULL,
		0x80E47DC9BE4021AAULL,
		0x86996B8F8F4C3684ULL,
		0x05188D06E0DB40ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29F982553907164CULL,
		0x5181EC67E6A2B407ULL,
		0x39A19B81D136098DULL,
		0x41A5ADD27C603AA8ULL,
		0xF45DBD8835B06B7AULL,
		0x9BFE7C91779F3511ULL,
		0x6E720E0AE179B9E2ULL,
		0xE34E46191526BCA3ULL
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
		0xC327D4D1B42FA2F5ULL,
		0xDF474056455F8DDCULL,
		0x91EE49B5132E82D1ULL,
		0x4EBEE8A52E31DFEFULL,
		0x2283A95C047D7491ULL,
		0x01DEC9EF3D42F84DULL,
		0xF7332442B893E072ULL,
		0x53A5E70D0E121AFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB3428BDBF543BDULL,
		0x8052F8F76F1CFAD4ULL,
		0x9771F9AF0EC32BC6ULL,
		0x66A22E5EC78B6DC9ULL,
		0xE6E17C3A3CDF17F7ULL,
		0xE1D56BC39CDE5D55ULL,
		0x84C79522912143F9ULL,
		0x232406467438FBDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5749245D83A5F38ULL,
		0x5EF4475ED6429307ULL,
		0xFA7C5006046B570BULL,
		0xE81CBA4666A67225ULL,
		0x3BA22D21C79E5C99ULL,
		0x20095E2BA0649AF7ULL,
		0x726B8F2027729C78ULL,
		0x3081E0C699D91F1DULL
	}};
	sign = 0;
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
		0xCDA7892E47A89634ULL,
		0xC71727748E291D1EULL,
		0x801EAD370A2B10D7ULL,
		0xDBBF3D2B953752BDULL,
		0x18353D32CA956694ULL,
		0x7B05B30C30A47151ULL,
		0xB14FA1038E2A2124ULL,
		0x7E4E3C0C7E2E3451ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BD06E102781352ULL,
		0x3CF1CC559145F732ULL,
		0xF17ABCB309D66946ULL,
		0x2C55D221185B7199ULL,
		0x89F50C5459CE07A7ULL,
		0xF38BF84C55D18838ULL,
		0xD05B2594C6068E20ULL,
		0xF3BFB17649A079F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06EA824D453082E2ULL,
		0x8A255B1EFCE325ECULL,
		0x8EA3F0840054A791ULL,
		0xAF696B0A7CDBE123ULL,
		0x8E4030DE70C75EEDULL,
		0x8779BABFDAD2E918ULL,
		0xE0F47B6EC8239303ULL,
		0x8A8E8A96348DBA5EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x48CE96DAD7B00631ULL,
		0x65D38CF5932905DDULL,
		0x0ECABAE727444B75ULL,
		0x3B4C7A1C43C85D01ULL,
		0x3C078F8DE5552598ULL,
		0xF9DE2CC6F51661CDULL,
		0x1A5364A3E6DEDFD9ULL,
		0x18499D4143B83D3BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32DC004F98F3063DULL,
		0xFCE7BDD4EF71F7C6ULL,
		0xDCCEDC502C38444AULL,
		0xCCE1FC3AA3F7970FULL,
		0x6FCA17BF79BC106DULL,
		0x73433171F4D2E938ULL,
		0x15EEF4B59764B396ULL,
		0xA82CE92FFE779D02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15F2968B3EBCFFF4ULL,
		0x68EBCF20A3B70E17ULL,
		0x31FBDE96FB0C072AULL,
		0x6E6A7DE19FD0C5F1ULL,
		0xCC3D77CE6B99152AULL,
		0x869AFB5500437894ULL,
		0x04646FEE4F7A2C43ULL,
		0x701CB4114540A039ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4CFE89F460635846ULL,
		0x8814FC112C9FE8BEULL,
		0x4F9D24792880DA87ULL,
		0x9F3282B4EF7B5AEAULL,
		0xE72B0DD5980E5890ULL,
		0x89C3568C34BDFE7DULL,
		0x2D819C2AD62A0EB1ULL,
		0xD86C573D5DDAC29AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F14E9362D6C1DCULL,
		0x98A415FA4CE94638ULL,
		0xE6E6011DBFD62F8DULL,
		0x9D17E30123C3DE5BULL,
		0xE41D7DF1442753E0ULL,
		0x4310123D7AB9EEBBULL,
		0xC295A3F6BC1CCFD0ULL,
		0xBA911041D2E48A73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA40D3B60FD8C966AULL,
		0xEF70E616DFB6A285ULL,
		0x68B7235B68AAAAF9ULL,
		0x021A9FB3CBB77C8EULL,
		0x030D8FE453E704B0ULL,
		0x46B3444EBA040FC2ULL,
		0x6AEBF8341A0D3EE1ULL,
		0x1DDB46FB8AF63826ULL
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
		0x61904BA5E86EB5A1ULL,
		0x3C2BC1706CD616C7ULL,
		0x8BB63F420BCC7A3AULL,
		0x9DE951B7B3170CA9ULL,
		0xC84E2FFB72F1B53EULL,
		0x5C0CAA909C60BA4CULL,
		0x8E78811776C0D74DULL,
		0xD2103CA6FA8B0157ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x039B00256DE9CA2DULL,
		0x166CC4414095542DULL,
		0x4E364EF02F8FB226ULL,
		0x4526188AC0D04D43ULL,
		0xFE3066547DE5DBA4ULL,
		0x05861019208D8C1AULL,
		0xB716532AEF4B0DBEULL,
		0x0EE1383E38F0D491ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DF54B807A84EB74ULL,
		0x25BEFD2F2C40C29AULL,
		0x3D7FF051DC3CC814ULL,
		0x58C3392CF246BF66ULL,
		0xCA1DC9A6F50BD99AULL,
		0x56869A777BD32E31ULL,
		0xD7622DEC8775C98FULL,
		0xC32F0468C19A2CC5ULL
	}};
	sign = 0;
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
		0x28126ED61959A179ULL,
		0x14C0068D97193C17ULL,
		0x7EA596EC67B71960ULL,
		0xD0FD887D4D69F7A0ULL,
		0xD3775BE89A139D96ULL,
		0xA0672140FAB6EF18ULL,
		0x12D7DBC2CA6D92D4ULL,
		0x50C5B41074125430ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64317E3BA1908CD1ULL,
		0xA6EC8700F53D1DDCULL,
		0x52AFD7A06255E25DULL,
		0xE039D5B7369A7B15ULL,
		0x2AA971C70B47C244ULL,
		0xC6EF2458FF2DF375ULL,
		0xAC5B29A51E5AD83EULL,
		0x10DC12AD37ECB44DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3E0F09A77C914A8ULL,
		0x6DD37F8CA1DC1E3AULL,
		0x2BF5BF4C05613702ULL,
		0xF0C3B2C616CF7C8BULL,
		0xA8CDEA218ECBDB51ULL,
		0xD977FCE7FB88FBA3ULL,
		0x667CB21DAC12BA95ULL,
		0x3FE9A1633C259FE2ULL
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
		0x095344B565E0EAA2ULL,
		0xF8CFC66668B04F0DULL,
		0x19CB769E49542482ULL,
		0xE6A0663CDC1F611AULL,
		0xA3D5F5D6BD913DE3ULL,
		0xE10459F46F07CA51ULL,
		0xD11144A01761C312ULL,
		0x70BD4222CBD03F31ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1364CE0855C5980AULL,
		0xC9EDE7AC817B0910ULL,
		0x350BDC944F0F56A0ULL,
		0xD3F8963E46AB3205ULL,
		0xA6C8D128E5BE07FAULL,
		0x7267FFA08953E9DAULL,
		0x1E9EEB7BA1270880ULL,
		0x41687E5593806E3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5EE76AD101B5298ULL,
		0x2EE1DEB9E73545FCULL,
		0xE4BF9A09FA44CDE2ULL,
		0x12A7CFFE95742F14ULL,
		0xFD0D24ADD7D335E9ULL,
		0x6E9C5A53E5B3E076ULL,
		0xB2725924763ABA92ULL,
		0x2F54C3CD384FD0F5ULL
	}};
	sign = 0;
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
		0xC83F5A26941EA91CULL,
		0x42D5F5678CBA44E1ULL,
		0x6948DA59A825732FULL,
		0x7C33DF516BACE6E6ULL,
		0xC492FFC3C2CB9F61ULL,
		0xA54514FD000C194FULL,
		0x89E85201C8679A92ULL,
		0x1A57DB47FBEA6EB9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D50ED7BC6B9A780ULL,
		0x55D4E8D33CCC1CF2ULL,
		0x1096A727A29B878CULL,
		0x11ED5A7F86B93A17ULL,
		0xC29ECB2C62FB8E38ULL,
		0x3F1CAB64A34361AAULL,
		0x1860487898EF2CE2ULL,
		0xE173A603DD32A048ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AEE6CAACD65019CULL,
		0xED010C944FEE27EFULL,
		0x58B233320589EBA2ULL,
		0x6A4684D1E4F3ACCFULL,
		0x01F434975FD01129ULL,
		0x662869985CC8B7A5ULL,
		0x718809892F786DB0ULL,
		0x38E435441EB7CE71ULL
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
		0x3C3290AD0DA72E5BULL,
		0x5FDE0BFB9E37160FULL,
		0x8B6DE54F14CEC54CULL,
		0x94D82904D5715E57ULL,
		0x96C98E5AB8566B14ULL,
		0xEA40BD94A844638CULL,
		0x4375FBD401FFE915ULL,
		0xB7BA4E64C327ABB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8236D39B29B9D97FULL,
		0xD80C4E9844610576ULL,
		0x57C9CEEFFBDE14D8ULL,
		0xCB82EDEDCA499A60ULL,
		0x45D830A57730DFC5ULL,
		0x7FB0510C59570C2FULL,
		0x292C5226D430B399ULL,
		0x3CF8D8FD3C42D5C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9FBBD11E3ED54DCULL,
		0x87D1BD6359D61098ULL,
		0x33A4165F18F0B073ULL,
		0xC9553B170B27C3F7ULL,
		0x50F15DB541258B4EULL,
		0x6A906C884EED575DULL,
		0x1A49A9AD2DCF357CULL,
		0x7AC1756786E4D5EAULL
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
		0xE33C6387C0F923C5ULL,
		0x8157BD28E134D9CAULL,
		0x089F3C031ED8CCE7ULL,
		0x06A3984FAB51CA64ULL,
		0x335FA06A5C3017AFULL,
		0xCAB992A93E33D47FULL,
		0x22ECB4FB2C1732F1ULL,
		0x0EEA8429CA2C51D3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x84CA056A9E3D047BULL,
		0x8D6DDDC3E5124B74ULL,
		0x4A0B36924497B24EULL,
		0x0B3EEBCC7C2EAE88ULL,
		0x6A5109F3169F0BF7ULL,
		0xF1C3C4D7AE1BFBBEULL,
		0x8F66EA26944DFA33ULL,
		0x2194E38B3F980034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E725E1D22BC1F4AULL,
		0xF3E9DF64FC228E56ULL,
		0xBE940570DA411A98ULL,
		0xFB64AC832F231BDBULL,
		0xC90E967745910BB7ULL,
		0xD8F5CDD19017D8C0ULL,
		0x9385CAD497C938BDULL,
		0xED55A09E8A94519EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEAEFC90A0ABE330EULL,
		0xC72FF7E9C7DBBC76ULL,
		0xAAAA7BC9241E8C6FULL,
		0x48B6DA06B9D0E90EULL,
		0x08811475269611EFULL,
		0xD90B339A57724FD8ULL,
		0xBA429CC52DE47CDEULL,
		0x6EA153338AAC7AFFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4292BC26D4FA6687ULL,
		0x863CC1E8BFAE3C96ULL,
		0x2373705F98429A73ULL,
		0x8A80B028EA0A7EC4ULL,
		0x058702E53DBB73E6ULL,
		0xA19170AD05AF5A21ULL,
		0xDFF5783E23727759ULL,
		0xA606EB749BDCE82CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA85D0CE335C3CC87ULL,
		0x40F33601082D7FE0ULL,
		0x87370B698BDBF1FCULL,
		0xBE3629DDCFC66A4AULL,
		0x02FA118FE8DA9E08ULL,
		0x3779C2ED51C2F5B7ULL,
		0xDA4D24870A720585ULL,
		0xC89A67BEEECF92D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAFCC0EF649BBF98DULL,
		0x1FF92D12237166CBULL,
		0x55A3A747F089E830ULL,
		0x8118A4BEE0595F77ULL,
		0xF817709C711F4BAFULL,
		0x6B123E5CEED45AECULL,
		0xEBC79B70853DF7F6ULL,
		0xE25CF09F78CFA510ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x419B6759EACC13A4ULL,
		0x7E5A33C7AD36750FULL,
		0x9668E6160E018351ULL,
		0xAE2C97C98B5741D6ULL,
		0x22783454B60ABDBBULL,
		0xEE5D4B5048A559EAULL,
		0xEC46BF9D7D8902E0ULL,
		0x64045AD507069046ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E30A79C5EEFE5E9ULL,
		0xA19EF94A763AF1BCULL,
		0xBF3AC131E28864DEULL,
		0xD2EC0CF555021DA0ULL,
		0xD59F3C47BB148DF3ULL,
		0x7CB4F30CA62F0102ULL,
		0xFF80DBD307B4F515ULL,
		0x7E5895CA71C914C9ULL
	}};
	sign = 0;
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
		0x7981DC93988998CDULL,
		0x38BD05F09AE86DEFULL,
		0xF9FA9C89DE764AC5ULL,
		0x271E03A8A6C47E1CULL,
		0xE57FA605656A5E42ULL,
		0x86F13788AF28F8AAULL,
		0xD93F4DC3DAE74F03ULL,
		0xEF0B62CAFD092693ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB80CC35E544DE3F6ULL,
		0x7C3CDDBD612FB097ULL,
		0x59DBBB5024404DA2ULL,
		0x47A4A7A02F03C836ULL,
		0xEC75965BF6ACE80DULL,
		0x6D679645CD0FC28EULL,
		0xE4682193D53DED97ULL,
		0x498B99D06C6AC00BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1751935443BB4D7ULL,
		0xBC80283339B8BD57ULL,
		0xA01EE139BA35FD22ULL,
		0xDF795C0877C0B5E6ULL,
		0xF90A0FA96EBD7634ULL,
		0x1989A142E219361BULL,
		0xF4D72C3005A9616CULL,
		0xA57FC8FA909E6687ULL
	}};
	sign = 0;
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
		0x5485B8720B1A1A41ULL,
		0xA7FAFF360C6E0298ULL,
		0xF87F28E6B0BE9BAAULL,
		0xDE488A54DFEB6F59ULL,
		0x63E8D5F5698D9E2AULL,
		0x05CAA5BDDB82FCCFULL,
		0x3ECE9D05C2BA7BBEULL,
		0x23BA031189F897E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x862B2C5A76ECE097ULL,
		0x7A4DF04F3924132FULL,
		0x8953B1B628C38A95ULL,
		0x598DD471910A45DDULL,
		0xBE12BE950821AADDULL,
		0xEB2276CF1176DB28ULL,
		0xFE88D802FE029908ULL,
		0x2A4CDB41F3AA9491ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE5A8C17942D39AAULL,
		0x2DAD0EE6D349EF68ULL,
		0x6F2B773087FB1115ULL,
		0x84BAB5E34EE1297CULL,
		0xA5D61760616BF34DULL,
		0x1AA82EEECA0C21A6ULL,
		0x4045C502C4B7E2B5ULL,
		0xF96D27CF964E0355ULL
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
		0x911324346ACEE4E8ULL,
		0x39081CF1B5C18E0BULL,
		0x18A785B3F9BEC5E5ULL,
		0x3B1D3E0173D66879ULL,
		0x5477B0AC3ECA88E0ULL,
		0xE8803451E2055B2AULL,
		0x3CC5C72FDD29C58AULL,
		0x9E5C8791FAFBFC60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E66996CCE31F557ULL,
		0x66B82C8F159E30DCULL,
		0x93445901F8C17E14ULL,
		0x01478AE4765277B1ULL,
		0x20FA478D907106B9ULL,
		0xBDA1B24A39A47493ULL,
		0x65EE6DF931EB72A3ULL,
		0x0F3C3E0ACCE6573DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42AC8AC79C9CEF91ULL,
		0xD24FF062A0235D2FULL,
		0x85632CB200FD47D0ULL,
		0x39D5B31CFD83F0C7ULL,
		0x337D691EAE598227ULL,
		0x2ADE8207A860E697ULL,
		0xD6D75936AB3E52E7ULL,
		0x8F2049872E15A522ULL
	}};
	sign = 0;
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
		0x63A156C4AA4E4500ULL,
		0x5BBFEAD14F793461ULL,
		0xDBC457D8E3DA59C0ULL,
		0x3CE5B465FCD4AED6ULL,
		0x3892621DF0C51C7EULL,
		0x5F16328D2E36CA9EULL,
		0x590294A29E2692D9ULL,
		0x37A9BF1D0929C69AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1EE0EF3A3192EE0ULL,
		0xE603CDACD2B909A1ULL,
		0x72475618F5B1BED8ULL,
		0xFB95041657986DFEULL,
		0xD6647A4F7AB6E1ECULL,
		0xB84E9E9C8322EB9CULL,
		0xCBC57EADADA80F25ULL,
		0x5CC7AEE62FFA37EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1B347D107351620ULL,
		0x75BC1D247CC02ABFULL,
		0x697D01BFEE289AE7ULL,
		0x4150B04FA53C40D8ULL,
		0x622DE7CE760E3A91ULL,
		0xA6C793F0AB13DF01ULL,
		0x8D3D15F4F07E83B3ULL,
		0xDAE21036D92F8EAAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4781D01B4A257D18ULL,
		0x69AC8AD9862BBACFULL,
		0xF11BED0E103FEC46ULL,
		0xF2D3CC76301895DEULL,
		0x864F7F2DD1E5D891ULL,
		0x7A281D0E36BB8750ULL,
		0x5FC46D2FF4D0DFA9ULL,
		0x3B7B9F9951F43827ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02B513B3686792FULL,
		0x775AAEC331986DCAULL,
		0x021FC933FE4616FBULL,
		0xBDB130D919869BB3ULL,
		0x18F4CB1534F1B1C0ULL,
		0x3016D6F774CEF2A9ULL,
		0xAF4939F55AA16A46ULL,
		0xE627AA1B962F52ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67567EE0139F03E9ULL,
		0xF251DC1654934D04ULL,
		0xEEFC23DA11F9D54AULL,
		0x35229B9D1691FA2BULL,
		0x6D5AB4189CF426D1ULL,
		0x4A114616C1EC94A7ULL,
		0xB07B333A9A2F7563ULL,
		0x5553F57DBBC4E53AULL
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
		0xB0209E6EBC140524ULL,
		0xCAF6651E1E4B7D82ULL,
		0x1777CECBBAC1DF82ULL,
		0x42D48D9F81FD349CULL,
		0x06774D1D1D7447A8ULL,
		0x5F3762E930C2A60FULL,
		0x01469DBC1A4D6C4CULL,
		0xFC3F86F339C8E63DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FDB5502B25C2FA7ULL,
		0xF3749CC0144DAD0EULL,
		0xAD957510D998888DULL,
		0xE0C9EFA503611103ULL,
		0xDA06D16D902B3341ULL,
		0x4BD604E45D49048AULL,
		0x62E8C5C01C41E30EULL,
		0x14791F3C647E9E68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8045496C09B7D57DULL,
		0xD781C85E09FDD074ULL,
		0x69E259BAE12956F4ULL,
		0x620A9DFA7E9C2398ULL,
		0x2C707BAF8D491466ULL,
		0x13615E04D379A184ULL,
		0x9E5DD7FBFE0B893EULL,
		0xE7C667B6D54A47D4ULL
	}};
	sign = 0;
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
		0xFB721AC0DE40F134ULL,
		0x548EAC4C039C0A16ULL,
		0x5F181F036341407CULL,
		0xA5E900D653FE9E08ULL,
		0xB80B7870758AE94FULL,
		0xB28AEC7756D92EC1ULL,
		0x7B351A1374DA387DULL,
		0x64B683BFF2AA817CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61A128AC76E21EBULL,
		0xB9BE0B03E1582824ULL,
		0xC6EEF72009FE2D74ULL,
		0x0EA5A8E6FB20BD05ULL,
		0x684A8434CE8C0DB1ULL,
		0x881F51957F2870B0ULL,
		0xD85B695BAFCE541CULL,
		0x4EF9AA58B2956961ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1558083616D2CF49ULL,
		0x9AD0A1482243E1F2ULL,
		0x982927E359431307ULL,
		0x974357EF58DDE102ULL,
		0x4FC0F43BA6FEDB9EULL,
		0x2A6B9AE1D7B0BE11ULL,
		0xA2D9B0B7C50BE461ULL,
		0x15BCD9674015181AULL
	}};
	sign = 0;
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
		0xDF6467E854FDA17FULL,
		0x134315F1A8BB796EULL,
		0xF3B500D84F9E3364ULL,
		0x0DD44CAEC4A204CCULL,
		0xADA277585E57324CULL,
		0x99991E1563D5952BULL,
		0xF33CB20B72310E82ULL,
		0x7F27DC0CB1C8B92FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6CF1CF66189406ULL,
		0xD936872501CE7631ULL,
		0xD0C89B56B98F5110ULL,
		0x5E178870D8061CFFULL,
		0xDC07EA394798C477ULL,
		0xCB8DC0A7085A61DAULL,
		0x5A1762BD651F5946ULL,
		0x6140FF619B23FE6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44F77618EEE50D79ULL,
		0x3A0C8ECCA6ED033DULL,
		0x22EC6581960EE253ULL,
		0xAFBCC43DEC9BE7CDULL,
		0xD19A8D1F16BE6DD4ULL,
		0xCE0B5D6E5B7B3350ULL,
		0x99254F4E0D11B53BULL,
		0x1DE6DCAB16A4BAC0ULL
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
		0x5C1F0D166E48E028ULL,
		0xDDBCA6539078DB1DULL,
		0xBD61A80EAECC8150ULL,
		0xDCFCE99358C973C8ULL,
		0x535669C7BB6FFA63ULL,
		0xC929499B59C76FECULL,
		0x2182A5673C7F3CD9ULL,
		0xE6AC919D3BAC79EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D31AA71EEE79EEULL,
		0x02F394B7D39DB800ULL,
		0xAE8C24745E15C584ULL,
		0xA41AFAB2E9292074ULL,
		0x84D9F75C6E1E783AULL,
		0x205A5D5D6F9B8B1BULL,
		0x1F9FB9FFDE13343DULL,
		0x9207FAEF8677ECDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x064BF26F4F5A663AULL,
		0xDAC9119BBCDB231DULL,
		0x0ED5839A50B6BBCCULL,
		0x38E1EEE06FA05354ULL,
		0xCE7C726B4D518229ULL,
		0xA8CEEC3DEA2BE4D0ULL,
		0x01E2EB675E6C089CULL,
		0x54A496ADB5348D0EULL
	}};
	sign = 0;
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
		0x96681C903D9F22E0ULL,
		0x38747C565B145EE3ULL,
		0xBE82A3951EB08BA3ULL,
		0xFAE4B8D9C915816CULL,
		0x2715E2EF79D8F7F1ULL,
		0x1FD4427EF98E103BULL,
		0xA8B318CADCAA7ADAULL,
		0xC7DC8F99DE4E6E27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21ADEAB7EEBD7CCCULL,
		0x8AB2EC2534AAF2E5ULL,
		0x0F044C434023665EULL,
		0x8148FF5051F8DFB1ULL,
		0x0F7B67BF2749400DULL,
		0x59708B0702935A40ULL,
		0x57C0F9E9E11EEB2FULL,
		0xE102F6D93464FC1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74BA31D84EE1A614ULL,
		0xADC1903126696BFEULL,
		0xAF7E5751DE8D2544ULL,
		0x799BB989771CA1BBULL,
		0x179A7B30528FB7E4ULL,
		0xC663B777F6FAB5FBULL,
		0x50F21EE0FB8B8FAAULL,
		0xE6D998C0A9E9720CULL
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
		0xBD20A9C1C929A9FDULL,
		0x3DDEC30FC15900ECULL,
		0x06CB503D13B392F8ULL,
		0xE7D98A08DCBD6C10ULL,
		0xFB9B114A0C2D800DULL,
		0x250E53EBAAEE4F77ULL,
		0x6557D98006A464F7ULL,
		0x5B55C363BE312256ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F24DA0B2B7F3EAULL,
		0x73087B779D032AF4ULL,
		0xF106299DA6C23C3EULL,
		0x4DDF7E030C36F99DULL,
		0x7AB2CB9DB4980D29ULL,
		0x3D7D81432CD1B6B9ULL,
		0x524ECC316BC4CE02ULL,
		0x4BFEF70D83BE3C3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC92E5C211671B613ULL,
		0xCAD647982455D5F7ULL,
		0x15C5269F6CF156B9ULL,
		0x99FA0C05D0867272ULL,
		0x80E845AC579572E4ULL,
		0xE790D2A87E1C98BEULL,
		0x13090D4E9ADF96F4ULL,
		0x0F56CC563A72E61CULL
	}};
	sign = 0;
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
		0x5749168B3E532D16ULL,
		0xB3D58A1125F1FD82ULL,
		0xF88593B846DE3057ULL,
		0xBC9C7E5ABA9E4D37ULL,
		0xEDF6AAA632E79743ULL,
		0x4EB69AEE4E7FFE61ULL,
		0xA60C19D1B4EE1BA5ULL,
		0x1DAE1BE24CDC43C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1F6AF1701340333ULL,
		0xE25A603CC50F8EF0ULL,
		0xEA92D23E6A8CE1CCULL,
		0x90F36C5E9600E9FAULL,
		0x2E918DDCB31546CCULL,
		0x1386C023D76EE52EULL,
		0xC6BBC9C76A5753F0ULL,
		0xC630D00920CB0B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA55267743D1F29E3ULL,
		0xD17B29D460E26E91ULL,
		0x0DF2C179DC514E8AULL,
		0x2BA911FC249D633DULL,
		0xBF651CC97FD25077ULL,
		0x3B2FDACA77111933ULL,
		0xDF50500A4A96C7B5ULL,
		0x577D4BD92C1138AFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2675DCFEB464AF9FULL,
		0xA5CF5BB9115D83A8ULL,
		0xE7FBD5DCA8BCCBB7ULL,
		0x24B9DA7BAE10FD4FULL,
		0xE91815B0C049A3E8ULL,
		0x83CF3779AA9BE330ULL,
		0xFCA1F101E29887D8ULL,
		0x2F90DB6CC9A36E46ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F5F853ED3C7502ULL,
		0x5126967FE9E51A52ULL,
		0xE5B55F8D78BAF538ULL,
		0x43E8E2510B606C64ULL,
		0x9DA713281636546BULL,
		0xA764DF75B5FBDF4CULL,
		0xAC40841B0715A11BULL,
		0x5084AF253884E060ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE7FE4AAC7283A9DULL,
		0x54A8C53927786955ULL,
		0x0246764F3001D67FULL,
		0xE0D0F82AA2B090EBULL,
		0x4B710288AA134F7CULL,
		0xDC6A5803F4A003E4ULL,
		0x50616CE6DB82E6BCULL,
		0xDF0C2C47911E8DE6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x478C021D922AF2E2ULL,
		0xC2F7EE344C4952ADULL,
		0xD02509615A5A6686ULL,
		0x4BE07A17741BCBBCULL,
		0xEF277AE1384FC220ULL,
		0x76BA3B1E93E10A2CULL,
		0x9FE7F89C96552B37ULL,
		0x336E24FD3C98E03EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C650956DFBB5D49ULL,
		0x1836CDDFE4E9BF8BULL,
		0xE74D72A6F95E942DULL,
		0x855786DD6BC97554ULL,
		0x13B0DEA00DF196FFULL,
		0xDC7CDAE8D31AE213ULL,
		0xF7EB05223E74C580ULL,
		0xC2C5206AA142D584ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB26F8C6B26F9599ULL,
		0xAAC12054675F9321ULL,
		0xE8D796BA60FBD259ULL,
		0xC688F33A08525667ULL,
		0xDB769C412A5E2B20ULL,
		0x9A3D6035C0C62819ULL,
		0xA7FCF37A57E065B6ULL,
		0x70A904929B560AB9ULL
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
		0xC4EBB1D94BFF3C9AULL,
		0x7425A671ABC5F975ULL,
		0x760796D615BB1D7DULL,
		0x5979F99EBCAF5F6AULL,
		0x0A57667FC40880B3ULL,
		0xDA6493645C43C517ULL,
		0x603285BCA3623786ULL,
		0x3DC07FB349F9E983ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5064E3630EA11138ULL,
		0x38CEB3E929094FEEULL,
		0xE93B134AEDA8ACFBULL,
		0x3D2CF3114615A0CAULL,
		0x8B9C80F683C5246FULL,
		0xAE692A8E9B119BAEULL,
		0x3967757499B7FFA8ULL,
		0x8122A2DE84FF9C5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7486CE763D5E2B62ULL,
		0x3B56F28882BCA987ULL,
		0x8CCC838B28127082ULL,
		0x1C4D068D7699BE9FULL,
		0x7EBAE58940435C44ULL,
		0x2BFB68D5C1322968ULL,
		0x26CB104809AA37DEULL,
		0xBC9DDCD4C4FA4D28ULL
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
		0x12F250F2024BF534ULL,
		0x6D78AAB8CD7E1674ULL,
		0x9D9DCCB1FDBC347FULL,
		0xDF6077F8D1510B6AULL,
		0x61B685AA4F6B7CC0ULL,
		0x3AB64B39DA32B2B1ULL,
		0x95FF5660D47C773DULL,
		0xACFD17A99BF87289ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D0777DB08653FFULL,
		0x5E64343398C08100ULL,
		0x2BF08617A568A043ULL,
		0x27B6992C9BD1B866ULL,
		0x0A34793DBB6D59B1ULL,
		0xCB1BFD4EDB84329EULL,
		0x9F39F3C6F2DEAA50ULL,
		0x42744BA5AAF0FBFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D21D97451C5A135ULL,
		0x0F14768534BD9573ULL,
		0x71AD469A5853943CULL,
		0xB7A9DECC357F5304ULL,
		0x57820C6C93FE230FULL,
		0x6F9A4DEAFEAE8013ULL,
		0xF6C56299E19DCCECULL,
		0x6A88CC03F107768DULL
	}};
	sign = 0;
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
		0x07918A5BE371BACFULL,
		0x233CCCD64FE02052ULL,
		0x47F9646865347DC0ULL,
		0x0E971BA72B1E764AULL,
		0x7E703D08469D0CF2ULL,
		0x45CDBEFECA1EAB97ULL,
		0xFA70686FE888C47EULL,
		0x2F25464D076FAA38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x078D69549EA8BDA1ULL,
		0xF660BE5A8657F94CULL,
		0xF9061DD651F6B5FAULL,
		0x3C5371D3CAB7BC5EULL,
		0xDBA89955592482D5ULL,
		0x07FDA9DA50FAEFB6ULL,
		0x97991AAE4A2F38CAULL,
		0x67AAF33100564F0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004210744C8FD2EULL,
		0x2CDC0E7BC9882706ULL,
		0x4EF34692133DC7C5ULL,
		0xD243A9D36066B9EBULL,
		0xA2C7A3B2ED788A1CULL,
		0x3DD015247923BBE0ULL,
		0x62D74DC19E598BB4ULL,
		0xC77A531C07195B2AULL
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
		0x9871E206BABE11D3ULL,
		0xF705DA4AC22DF017ULL,
		0x428E381814A115A9ULL,
		0x2AE5DACC46A3C991ULL,
		0xDE0488A20FB2A210ULL,
		0xA0390C98C2E376D5ULL,
		0x8C5435B005F717EEULL,
		0x7C532ADA9687737EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D95E65972385CCULL,
		0xCC18F6F5A93A1469ULL,
		0xD600D24062F8ECDAULL,
		0x00DCDC5580B10B4CULL,
		0xE014EE9703C47E0EULL,
		0x658C9E36E679774FULL,
		0xCD0762AFB3269592ULL,
		0x4A9A768032C4F769ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x179883A1239A8C07ULL,
		0x2AECE35518F3DBAEULL,
		0x6C8D65D7B1A828CFULL,
		0x2A08FE76C5F2BE44ULL,
		0xFDEF9A0B0BEE2402ULL,
		0x3AAC6E61DC69FF85ULL,
		0xBF4CD30052D0825CULL,
		0x31B8B45A63C27C14ULL
	}};
	sign = 0;
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
		0x8E6B9EF8AADD84D4ULL,
		0xD91FA77DE716408DULL,
		0x4A25D5D41902B998ULL,
		0x14A1BA8C9F1A3D2FULL,
		0xFB04753D3560954AULL,
		0x5CEDF2431CF93F2EULL,
		0x5ECF89E0BA7E4865ULL,
		0x8B7E6C399428D073ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB41C500EFB402EULL,
		0xEB04D736A8FE4F89ULL,
		0x512B60092C41ADE4ULL,
		0xC234CD5FC75DC248ULL,
		0x076E894D6BB88431ULL,
		0x759F907284598A71ULL,
		0xEF6C8B368C6DE0AAULL,
		0xDDF1DA1BE19A98A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61B782A89BE244A6ULL,
		0xEE1AD0473E17F104ULL,
		0xF8FA75CAECC10BB3ULL,
		0x526CED2CD7BC7AE6ULL,
		0xF395EBEFC9A81118ULL,
		0xE74E61D0989FB4BDULL,
		0x6F62FEAA2E1067BAULL,
		0xAD8C921DB28E37D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x961DCC45E124C336ULL,
		0x29605CF6921C3223ULL,
		0x3D3E59F15E40C235ULL,
		0x0C9253A90C24EA2BULL,
		0x1CA7F18A082A1584ULL,
		0x4BF76F46B87181A3ULL,
		0x5AD9D6235BA25A58ULL,
		0x4600BD00A077BE34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5347CD5C883D119FULL,
		0x27912D05743EC8E1ULL,
		0xF021ABFCB75A518AULL,
		0x91047D928B729C1DULL,
		0xE2C467BDECECC6F6ULL,
		0xBE347B7F2C0AAAFAULL,
		0x0AC6FD629C9BCFA1ULL,
		0x80B5B7885AECD9DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42D5FEE958E7B197ULL,
		0x01CF2FF11DDD6942ULL,
		0x4D1CADF4A6E670ABULL,
		0x7B8DD61680B24E0DULL,
		0x39E389CC1B3D4E8DULL,
		0x8DC2F3C78C66D6A8ULL,
		0x5012D8C0BF068AB6ULL,
		0xC54B0578458AE45AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x598C194CC5619DBDULL,
		0x5066CCA893410744ULL,
		0x4D921BE9968AA94FULL,
		0x38DAA83C598276C4ULL,
		0x7205639D927C9ED4ULL,
		0x5DDF0328CAFCD9DEULL,
		0xBCEDDD6E9D316A60ULL,
		0xF8A4E841A5A9A683ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27D873A617DB78FAULL,
		0x7E6D6FBEFD1B4C04ULL,
		0x9CEE051B026968A0ULL,
		0xF93FB31868DE2BCFULL,
		0xD4E316498A4DBBE8ULL,
		0xA3AD09A9BAEC1FDDULL,
		0xC6752C8DC9028CD7ULL,
		0xAE31D6078DD143F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B3A5A6AD8624C3ULL,
		0xD1F95CE99625BB40ULL,
		0xB0A416CE942140AEULL,
		0x3F9AF523F0A44AF4ULL,
		0x9D224D54082EE2EBULL,
		0xBA31F97F1010BA00ULL,
		0xF678B0E0D42EDD88ULL,
		0x4A73123A17D8628DULL
	}};
	sign = 0;
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
		0x2B0C756D4D48D962ULL,
		0xA7881BDCD47332E0ULL,
		0xCEB595266C922AB6ULL,
		0x783B127E0D9F5D96ULL,
		0xE4248EFBB72D5F1DULL,
		0x980E31BF7D2BF749ULL,
		0x6760A322A3848292ULL,
		0xEB7CBB25300EB597ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26655F19A43F2887ULL,
		0x9BB4293835207812ULL,
		0x4A4B4C78547C9261ULL,
		0xF0B669DCCAAEF3DBULL,
		0x9D676F03501B76D3ULL,
		0x13CE1C44C072F73EULL,
		0x7BA1776D5689563CULL,
		0xF1F3121400B185F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A71653A909B0DBULL,
		0x0BD3F2A49F52BACEULL,
		0x846A48AE18159855ULL,
		0x8784A8A142F069BBULL,
		0x46BD1FF86711E849ULL,
		0x8440157ABCB9000BULL,
		0xEBBF2BB54CFB2C56ULL,
		0xF989A9112F5D2FA4ULL
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
		0xF6D4D6CCD2D317A3ULL,
		0x02A5895462F13DB3ULL,
		0x8343CCE091E1EF97ULL,
		0x81326607695C63ABULL,
		0xCAED0C78BA16AE4AULL,
		0x4128D47CDE4D24EBULL,
		0x8F4741A74AA995ACULL,
		0x7DAD2E40379CD298ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADBE744EC8A33A68ULL,
		0xD121E3C4224A12D2ULL,
		0x71757E15363A0F53ULL,
		0x0D532BAAF139974AULL,
		0x01B94FFC6B378C7AULL,
		0x15D27CB6ECBDE94AULL,
		0xAD8B2C3C42FAC7B6ULL,
		0x231B14B284822A13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4916627E0A2FDD3BULL,
		0x3183A59040A72AE1ULL,
		0x11CE4ECB5BA7E043ULL,
		0x73DF3A5C7822CC61ULL,
		0xC933BC7C4EDF21D0ULL,
		0x2B5657C5F18F3BA1ULL,
		0xE1BC156B07AECDF6ULL,
		0x5A92198DB31AA884ULL
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
		0x6FFF35FF0CEB3D3FULL,
		0xD723CE4868C4B21FULL,
		0x40A5CEC62F00257BULL,
		0xEAC551DC72078C68ULL,
		0x2FAF92852C33F9B8ULL,
		0xED87D09AA4EEBDF7ULL,
		0xB8EA582BD48DA499ULL,
		0x1D3BDFD30F69257CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C12D7134E4E7F7ULL,
		0x01155E2AB030D018ULL,
		0xA44DC926C6B0E1BFULL,
		0x1099BE9C99C96D51ULL,
		0x4B3564C111517055ULL,
		0x02CE3568CDE1F834ULL,
		0xAB4ED3F65BB264F5ULL,
		0xA512CD8BA6B938E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x863E088DD8065548ULL,
		0xD60E701DB893E206ULL,
		0x9C58059F684F43BCULL,
		0xDA2B933FD83E1F16ULL,
		0xE47A2DC41AE28963ULL,
		0xEAB99B31D70CC5C2ULL,
		0x0D9B843578DB3FA4ULL,
		0x7829124768AFEC94ULL
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
		0x0F2CC04F5C0AF092ULL,
		0xB2575FDCE6BAEFBFULL,
		0xB230D6797BF1533CULL,
		0xF2591A206465E941ULL,
		0xBB9D30DAE9C63C5EULL,
		0xE6891FA9BC28AE86ULL,
		0x00AA517D9BF9390EULL,
		0x15E72EBA58614A8EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x923CCB581425531FULL,
		0xDEA0F6FC524F9705ULL,
		0xD8334FD36D9DC53FULL,
		0x0FE01FEF9C18E4E0ULL,
		0x7EB0995AFB0E8A0AULL,
		0x5B95C8B516D62A45ULL,
		0xC269EEE50D34C269ULL,
		0xE39B196C2E0C2D28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CEFF4F747E59D73ULL,
		0xD3B668E0946B58B9ULL,
		0xD9FD86A60E538DFCULL,
		0xE278FA30C84D0460ULL,
		0x3CEC977FEEB7B254ULL,
		0x8AF356F4A5528441ULL,
		0x3E4062988EC476A5ULL,
		0x324C154E2A551D65ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5B42C90F7DD209A9ULL,
		0xAECC172C6D150A2DULL,
		0xB55D5D7B86A60EB1ULL,
		0x8650B06065B9F316ULL,
		0xDE82D0A5BF38372CULL,
		0xCAA2887CE0DEA8DBULL,
		0x953B2325E6064040ULL,
		0x07572D7D459B718FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF557045DC2646C8DULL,
		0x91E737F686C24A21ULL,
		0x0FC63EFCA284FFB7ULL,
		0x73B23C07EB5CFFBFULL,
		0x63F1DE5155F2D686ULL,
		0x220DF43913E48C01ULL,
		0xCED3B3B85E16FDB5ULL,
		0x40C102D0931AC01AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65EBC4B1BB6D9D1CULL,
		0x1CE4DF35E652C00BULL,
		0xA5971E7EE4210EFAULL,
		0x129E74587A5CF357ULL,
		0x7A90F254694560A6ULL,
		0xA8949443CCFA1CDAULL,
		0xC6676F6D87EF428BULL,
		0xC6962AACB280B174ULL
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
		0x33E56DCFCC75023FULL,
		0x249E505465A7BFB8ULL,
		0xD28532A39B297DCCULL,
		0xC9D729104B41E019ULL,
		0xBF71788A9AF03691ULL,
		0x2C3E7AB61DE65FF4ULL,
		0xF68D94B7669EE4ABULL,
		0x5A6B4543B14F21D2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBA7CA7B667E954ULL,
		0xF0121F153F39439EULL,
		0x18496547A48243F7ULL,
		0x844A4EABDE05604DULL,
		0xEF58E3310BF9625BULL,
		0xD6B540E79896DF0FULL,
		0x0BD39CE20541283EULL,
		0xD88DF8642836EE5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE72AF128160D18EBULL,
		0x348C313F266E7C19ULL,
		0xBA3BCD5BF6A739D4ULL,
		0x458CDA646D3C7FCCULL,
		0xD01895598EF6D436ULL,
		0x558939CE854F80E4ULL,
		0xEAB9F7D5615DBC6CULL,
		0x81DD4CDF89183375ULL
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
		0xE54408D8565A01A6ULL,
		0xED6854C648868530ULL,
		0xEEB530C604C300ADULL,
		0x935A86B3FF7DA09DULL,
		0x2E062BC3AAB055F4ULL,
		0xCDE4DC3B0C254D21ULL,
		0xF821E5B3C59AF866ULL,
		0xECC4B209855B2AD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE606A7910745F00ULL,
		0xC0FF00827657CE63ULL,
		0x6613A4BBB9921756ULL,
		0x8F528DB2F987DD5BULL,
		0x3D82C7161D9B5F4FULL,
		0xF58B4C7A4002A1B6ULL,
		0x24ADB6C469D10E46ULL,
		0x3E656E2D6003B590ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26E39E5F45E5A2A6ULL,
		0x2C695443D22EB6CDULL,
		0x88A18C0A4B30E957ULL,
		0x0407F90105F5C342ULL,
		0xF08364AD8D14F6A5ULL,
		0xD8598FC0CC22AB6AULL,
		0xD3742EEF5BC9EA1FULL,
		0xAE5F43DC25577541ULL
	}};
	sign = 0;
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
		0x86CB4BC9C372FEE5ULL,
		0x4FF5C5C47CB80860ULL,
		0x9A3774A77EB2E760ULL,
		0xF12871462B9FE94AULL,
		0xA3DFA338BD3EAF38ULL,
		0xA988952845DE4762ULL,
		0x6C2DB0A1DED28E03ULL,
		0xFD3F9776726928D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1486D1CD016D2FAULL,
		0x6B147C8AF106B45EULL,
		0xC70D20047C9322FEULL,
		0xD3CB868F47719070ULL,
		0x4D78044B5C2421BFULL,
		0x15E03D5535B3EFD1ULL,
		0xE5656AE827583436ULL,
		0xE6087424E34366D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD582DEACF35C2BEBULL,
		0xE4E149398BB15401ULL,
		0xD32A54A3021FC461ULL,
		0x1D5CEAB6E42E58D9ULL,
		0x56679EED611A8D79ULL,
		0x93A857D3102A5791ULL,
		0x86C845B9B77A59CDULL,
		0x173723518F25C207ULL
	}};
	sign = 0;
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
		0x40A06E9811E57CDBULL,
		0x66179439CAAFAE8EULL,
		0xF4562C3DD1349875ULL,
		0xBA32144CE3739E20ULL,
		0xE1BED5E10076665DULL,
		0x7021AD73EF6392B7ULL,
		0x5598EB5611BCBDA9ULL,
		0x61E5CA2D8DA85119ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4C6D3140D73147ULL,
		0x85D7E73F28FC4128ULL,
		0xBD5BF549E1BD5B00ULL,
		0x934DA60D83985315ULL,
		0xD2EFDC59740B819CULL,
		0x9A38D716D8761BB7ULL,
		0x89D3027CD2185B77ULL,
		0x6142513BCB35CC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26540166D10E4B94ULL,
		0xE03FACFAA1B36D66ULL,
		0x36FA36F3EF773D74ULL,
		0x26E46E3F5FDB4B0BULL,
		0x0ECEF9878C6AE4C1ULL,
		0xD5E8D65D16ED7700ULL,
		0xCBC5E8D93FA46231ULL,
		0x00A378F1C27284C4ULL
	}};
	sign = 0;
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
		0x7BBCFE068F709C65ULL,
		0x7C7B4A5CF4A25FC6ULL,
		0xE651C8F2555691F2ULL,
		0x4082DA15175315EEULL,
		0x4A6C1DF431C7010FULL,
		0xFC1A6E42A55C8034ULL,
		0x05095BEDAEDD2341ULL,
		0x875401AE7FB4FA6FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ADCE3EE2A5A896BULL,
		0x72339EB283C8121DULL,
		0x7E4C6306941275C0ULL,
		0x4A8AA68519C1D8A8ULL,
		0x77AE08FE84E50868ULL,
		0xC5D37BBA5F309917ULL,
		0xC96D19E1DF774D78ULL,
		0xF36512FFA724C75FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70E01A18651612FAULL,
		0x0A47ABAA70DA4DA9ULL,
		0x680565EBC1441C32ULL,
		0xF5F8338FFD913D46ULL,
		0xD2BE14F5ACE1F8A6ULL,
		0x3646F288462BE71CULL,
		0x3B9C420BCF65D5C9ULL,
		0x93EEEEAED890330FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x026F578DB7CA18ABULL,
		0x5E27F46E38423B43ULL,
		0x0B537B3130AB9F63ULL,
		0xFF79E75A35FCC287ULL,
		0x2CD05B1FE85C1FDEULL,
		0xC8F13CA88CCD822DULL,
		0xE71AA4168E6AF9D3ULL,
		0x04927E17A9803DE9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x841536E53EF0CC9AULL,
		0x96E0B22BD3E096DEULL,
		0x4E17EBB628331B4AULL,
		0x60ED731ECC46BBE6ULL,
		0x689258899FC83456ULL,
		0xD0BA5791EAFFCDEDULL,
		0x58434B3ED6C27C12ULL,
		0x64A1CE6A71CA5F2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E5A20A878D94C11ULL,
		0xC74742426461A464ULL,
		0xBD3B8F7B08788418ULL,
		0x9E8C743B69B606A0ULL,
		0xC43E02964893EB88ULL,
		0xF836E516A1CDB43FULL,
		0x8ED758D7B7A87DC0ULL,
		0x9FF0AFAD37B5DEBAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x04A69F5703D245DCULL,
		0x82EFD3248AE54FA8ULL,
		0x0E15DDFA142F84EDULL,
		0xDECB9C90AAFFB2FCULL,
		0x4927D8E106810EA5ULL,
		0x14702D584DE3D0DAULL,
		0x68BECDA3CA473798ULL,
		0x74AB17DFF2544F8AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E55532A341FAA5AULL,
		0x1F4AB287F5BEFEC3ULL,
		0x039479E082D00A41ULL,
		0x06D2C932E66407A1ULL,
		0xDB0C84884EC5C628ULL,
		0xE23581EF6CCCD1C9ULL,
		0x4F097DFFBA3EAB99ULL,
		0x06AF8241E771D8F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6514C2CCFB29B82ULL,
		0x63A5209C952650E4ULL,
		0x0A816419915F7AACULL,
		0xD7F8D35DC49BAB5BULL,
		0x6E1B5458B7BB487DULL,
		0x323AAB68E116FF10ULL,
		0x19B54FA410088BFEULL,
		0x6DFB959E0AE27695ULL
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
		0x9DF5D9F0E72DC869ULL,
		0x67346152A2142B0CULL,
		0x17B7A82694DB49B3ULL,
		0xC50E350D4AA5F81EULL,
		0x285986F53BF1A191ULL,
		0x787A9B3495BE1531ULL,
		0x425F96B938AD2458ULL,
		0xED65BD6E3BAF36B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97ACA0A8A6AF8D47ULL,
		0x7B6472DDBDC8285EULL,
		0x0A7913E7D946E9B3ULL,
		0xFA8A40ED913355F4ULL,
		0xB2C5B3BE8F82CA40ULL,
		0x2687332BF3E289B6ULL,
		0x0C7D5A8BA8D7D00AULL,
		0x68BA4B4120B2808EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06493948407E3B22ULL,
		0xEBCFEE74E44C02AEULL,
		0x0D3E943EBB945FFFULL,
		0xCA83F41FB972A22AULL,
		0x7593D336AC6ED750ULL,
		0x51F36808A1DB8B7AULL,
		0x35E23C2D8FD5544EULL,
		0x84AB722D1AFCB628ULL
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
		0xE704C30E7F0273A2ULL,
		0x928A3F1A59A3270BULL,
		0xB36AC7E504C53073ULL,
		0x835C86859A1FF6FFULL,
		0x2808C63C98D88D5CULL,
		0x726F0B284AFCA019ULL,
		0xBCF9E6A4E1A919B7ULL,
		0xFA7664CE253F578FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B34571F40162550ULL,
		0xF433F2D03829A641ULL,
		0x60B019C510E1C1B2ULL,
		0x76F9D781D3C0F914ULL,
		0x6FBC42C2169472F0ULL,
		0xCC6297E90B333E29ULL,
		0xC5B397215DB00355ULL,
		0x94757B40171D1A5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD06BEF3EEC4E52ULL,
		0x9E564C4A217980CAULL,
		0x52BAAE1FF3E36EC0ULL,
		0x0C62AF03C65EFDEBULL,
		0xB84C837A82441A6CULL,
		0xA60C733F3FC961EFULL,
		0xF7464F8383F91661ULL,
		0x6600E98E0E223D31ULL
	}};
	sign = 0;
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
		0x6AD07DF5C6D85654ULL,
		0x5B6F2D67BB273628ULL,
		0x8A990B6899791290ULL,
		0xFBCBF04247AE9FF2ULL,
		0x349F043C350B0EB0ULL,
		0x310F0BCE7627D741ULL,
		0x3ECF40C5F97B5F95ULL,
		0x7916423B2BACD43DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E17B2FE535CFB1ULL,
		0xAEBDFE56061A3ABAULL,
		0x53A576B96CD18531ULL,
		0xB5CAEB4294021A87ULL,
		0xBE4F73FEF208190FULL,
		0x80C0A9E19A260272ULL,
		0x52CE7B3FD4ABC0CFULL,
		0xEC766B38E659C679ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71EF02C5E1A286A3ULL,
		0xACB12F11B50CFB6DULL,
		0x36F394AF2CA78D5EULL,
		0x460104FFB3AC856BULL,
		0x764F903D4302F5A1ULL,
		0xB04E61ECDC01D4CEULL,
		0xEC00C58624CF9EC5ULL,
		0x8C9FD70245530DC3ULL
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
		0xF9FE985352432BF3ULL,
		0xEA48867A3160709FULL,
		0x89ADB0BE07CE2B48ULL,
		0x132412F6ABC509EEULL,
		0x8D134D35995AF828ULL,
		0x27FBCADE1F681501ULL,
		0x321933ED30E7FB5AULL,
		0x93F30ACDB9B52BF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x162467FD6443D4E4ULL,
		0x1CAFAE5976377CDCULL,
		0x19038D0B9A7280EAULL,
		0xA966B181DF8024D0ULL,
		0xE960D3DDFA2BD3C4ULL,
		0x8D8BE53C65BBF932ULL,
		0xDBC0A5F52B7B3567ULL,
		0x5120AABB07E81B05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3DA3055EDFF570FULL,
		0xCD98D820BB28F3C3ULL,
		0x70AA23B26D5BAA5EULL,
		0x69BD6174CC44E51EULL,
		0xA3B279579F2F2463ULL,
		0x9A6FE5A1B9AC1BCEULL,
		0x56588DF8056CC5F2ULL,
		0x42D26012B1CD10ECULL
	}};
	sign = 0;
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
		0x1073CC56F46643B1ULL,
		0x86A2286AA91A5D14ULL,
		0x696F604CCA2B04CAULL,
		0xC7C397E8B66F0E68ULL,
		0x7951BD46ED805086ULL,
		0x49AA3779E5E610EFULL,
		0xB3A7592FBE9924F7ULL,
		0x1556371B81864AB6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1326C23B5D6F1EBULL,
		0x124DAC820B37A6ABULL,
		0x2878F88C6B7CB821ULL,
		0xDFC42FBC017034B0ULL,
		0x48BB54FE2AE12ED3ULL,
		0x4F3635613C57C0C7ULL,
		0x5E9F4AC93CA8349FULL,
		0xE8AE8546621899F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F4160333E8F51C6ULL,
		0x74547BE89DE2B668ULL,
		0x40F667C05EAE4CA9ULL,
		0xE7FF682CB4FED9B8ULL,
		0x30966848C29F21B2ULL,
		0xFA740218A98E5028ULL,
		0x55080E6681F0F057ULL,
		0x2CA7B1D51F6DB0C4ULL
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
		0x08BEB3E24BBD9AE2ULL,
		0xA5F7F25EDC2FE75FULL,
		0xDF266BDCC4A53997ULL,
		0x21A714C61F73EE52ULL,
		0x7834A8CF36A4C0CEULL,
		0x63E145E02501720EULL,
		0x144610A5A3F8ECAAULL,
		0x0997D8537FF54B53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD20D3DA0E5E1A26ULL,
		0x1B56332845436CB4ULL,
		0x151F4E39A4F0ED4AULL,
		0x6748B79A93189A53ULL,
		0xF8392CE64D9C18C5ULL,
		0x73B70511BEE0B680ULL,
		0xAE743F9BEB7C4831ULL,
		0x537F75FCEAA02F57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B9DE0083D5F80BCULL,
		0x8AA1BF3696EC7AAAULL,
		0xCA071DA31FB44C4DULL,
		0xBA5E5D2B8C5B53FFULL,
		0x7FFB7BE8E908A808ULL,
		0xF02A40CE6620BB8DULL,
		0x65D1D109B87CA478ULL,
		0xB618625695551BFBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1B838383C67BC136ULL,
		0x1AE068BE21415522ULL,
		0x0CD62104BC34D2C0ULL,
		0x1342AA905C8C49DCULL,
		0xB5F14C8A986C96E2ULL,
		0xF98811AD7022749AULL,
		0xB6282491FC9ADEA7ULL,
		0xAFFCE1C42523A39EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C9B3A76523A093ULL,
		0x9D4E0A718A0E486EULL,
		0x694115E7A6A8A15AULL,
		0xE403AB59A2501B0DULL,
		0xDDAFD1EA39165887ULL,
		0xC8D9DD70F2E84BD3ULL,
		0x7C8D9F2406577FB4ULL,
		0xD9484CC24257DAC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49B9CFDC615820A3ULL,
		0x7D925E4C97330CB3ULL,
		0xA3950B1D158C3165ULL,
		0x2F3EFF36BA3C2ECEULL,
		0xD8417AA05F563E5AULL,
		0x30AE343C7D3A28C6ULL,
		0x399A856DF6435EF3ULL,
		0xD6B49501E2CBC8DBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2D2C0343DFFB70EBULL,
		0x2C4F422C32981E1EULL,
		0x72C77BC4B09D1EF3ULL,
		0xD6143C34F35CF723ULL,
		0x9E0D594EC95A7265ULL,
		0x38282EA53398C889ULL,
		0x31F1596B3F6D49B0ULL,
		0x193F4524BFA7C18FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC23E9ABFCBAEF57ULL,
		0xD285394DB7E4BF51ULL,
		0x4D2E7216A8BE7CE9ULL,
		0x7B229888F6681EEFULL,
		0x7044B96835A8EE23ULL,
		0x1E3687D4F8A7F3F1ULL,
		0xD17AB8DABDB404D6ULL,
		0xB2E7E30BBD6D29ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71081997E3408194ULL,
		0x59CA08DE7AB35ECCULL,
		0x259909AE07DEA209ULL,
		0x5AF1A3ABFCF4D834ULL,
		0x2DC89FE693B18442ULL,
		0x19F1A6D03AF0D498ULL,
		0x6076A09081B944DAULL,
		0x66576219023A97E2ULL
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
		0x8F76C5520867D0CDULL,
		0x95CE826765D8CFFAULL,
		0x07480C09E65C81E4ULL,
		0x6C758E7585654C59ULL,
		0x664937B2760F4611ULL,
		0x6C6EA1774E5CB45EULL,
		0x8B6EF25BC274DC68ULL,
		0x721DC91118149E82ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xED1E96C098223327ULL,
		0xB2BDA5CD78B40889ULL,
		0x473F2D3313238F02ULL,
		0x9123B06513FD0D8FULL,
		0xBE75E28C45AC9F23ULL,
		0xD5A9C03C0410A4A0ULL,
		0xA99204FE175D2508ULL,
		0x4AFC47EF26738871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2582E9170459DA6ULL,
		0xE310DC99ED24C770ULL,
		0xC008DED6D338F2E1ULL,
		0xDB51DE1071683EC9ULL,
		0xA7D355263062A6EDULL,
		0x96C4E13B4A4C0FBDULL,
		0xE1DCED5DAB17B75FULL,
		0x27218121F1A11610ULL
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
		0x1FBA0554A1E6C9E4ULL,
		0x046072D4257B088CULL,
		0xD6076CABACE53815ULL,
		0xFF2FCD9EA3A66FE3ULL,
		0x144E8E312B23E04FULL,
		0x4B51EFEBBC5F788FULL,
		0xD5B896FFCB9FEDD3ULL,
		0xD8023CC0D79A7418ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x84ADA26AD3BAEC98ULL,
		0x54442D39790DDFFDULL,
		0x2791E2EC6F7F7D36ULL,
		0xCAD2ADA20243CCD6ULL,
		0x0AEC465A5506376FULL,
		0x16855138D8408C54ULL,
		0x15E39B50ACBE680AULL,
		0xA1054C0A325DB901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B0C62E9CE2BDD4CULL,
		0xB01C459AAC6D288EULL,
		0xAE7589BF3D65BADEULL,
		0x345D1FFCA162A30DULL,
		0x096247D6D61DA8E0ULL,
		0x34CC9EB2E41EEC3BULL,
		0xBFD4FBAF1EE185C9ULL,
		0x36FCF0B6A53CBB17ULL
	}};
	sign = 0;
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
		0x19E957D6943EA143ULL,
		0x1BE0A01BB1BFEABDULL,
		0xE2595C4964F5624BULL,
		0xC56E81A0BE5A62A3ULL,
		0x610E8FFA762E3558ULL,
		0x1398129D0E388ED5ULL,
		0x607DD3E78C808DCAULL,
		0xC8F907DCF0A39CAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6DBB628EC11D1E4ULL,
		0xDE0EF9DEAC58CCC3ULL,
		0xBAAE769FF2BCEBA8ULL,
		0x3C4883B3AFF63C54ULL,
		0xC81AD5B981DA0963ULL,
		0x207EC3E02BE5F7ADULL,
		0xE67B87402D676AFEULL,
		0x74348C3F67921A9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x730DA1ADA82CCF5FULL,
		0x3DD1A63D05671DF9ULL,
		0x27AAE5A9723876A2ULL,
		0x8925FDED0E64264FULL,
		0x98F3BA40F4542BF5ULL,
		0xF3194EBCE2529727ULL,
		0x7A024CA75F1922CBULL,
		0x54C47B9D89118213ULL
	}};
	sign = 0;
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
		0x8B129C70CC165762ULL,
		0xE301680D44459A48ULL,
		0xF1C8861AE60ACDAEULL,
		0x632C64AFAA9ADDE6ULL,
		0xE72DA48970FDCD9AULL,
		0x1823447C48A09A51ULL,
		0xEA8008A36A95BE01ULL,
		0xF742FDE6B9002E5FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB0C8CA0A6D1665DULL,
		0xE79463BE895F0B96ULL,
		0x954ABD41AF1A13F6ULL,
		0xEB92ACEB7B788335ULL,
		0x3B864B7BC1070558ULL,
		0xC5CFACF12F027BE7ULL,
		0x9B22412EF5691536ULL,
		0xD98526DE3DB042DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0060FD02544F105ULL,
		0xFB6D044EBAE68EB1ULL,
		0x5C7DC8D936F0B9B7ULL,
		0x7799B7C42F225AB1ULL,
		0xABA7590DAFF6C841ULL,
		0x5253978B199E1E6AULL,
		0x4F5DC774752CA8CAULL,
		0x1DBDD7087B4FEB82ULL
	}};
	sign = 0;
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
		0x5ECFE74F9FBEA605ULL,
		0xEF829DE63823AC2BULL,
		0x7F2E20628A5139D6ULL,
		0x579000278BC6F167ULL,
		0x61085CF98350439EULL,
		0xBF8E4ED53DEFC109ULL,
		0xD396DD8C706BBE97ULL,
		0x061DC08B0FB1EF84ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA2852E9A761B7BULL,
		0xCC0E13F8A316A28AULL,
		0x0D6C42D2E5225A5BULL,
		0xBC99CA06F9B12A2AULL,
		0xCE58A005186D6607ULL,
		0xFDF7DE109DEBFDAEULL,
		0x80ED7F8351CF4258ULL,
		0x12415011DFA906F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042D622105488A8AULL,
		0x237489ED950D09A1ULL,
		0x71C1DD8FA52EDF7BULL,
		0x9AF636209215C73DULL,
		0x92AFBCF46AE2DD96ULL,
		0xC19670C4A003C35AULL,
		0x52A95E091E9C7C3EULL,
		0xF3DC70793008E891ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x52BD66315C04A1CAULL,
		0x6D5A1E1C3B75CF7FULL,
		0x5EFD4562F3A27D61ULL,
		0x5B66874F22731D06ULL,
		0x57A2AA4B64294E88ULL,
		0x688F67ED4A4056F5ULL,
		0x3785035BA1FF8302ULL,
		0xB9AC1CBBCBA5CBC5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4367C7143D81D9ULL,
		0xFE7896825FF05A40ULL,
		0x89DAD7BA49C168D0ULL,
		0x3971384904524444ULL,
		0xC9CF7BB77B8211F6ULL,
		0x16FEA2B46683ACD8ULL,
		0xD7AE8681397E9C8AULL,
		0x15F5E6DBCF95D43FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7479FE6A47C71FF1ULL,
		0x6EE18799DB85753EULL,
		0xD5226DA8A9E11490ULL,
		0x21F54F061E20D8C1ULL,
		0x8DD32E93E8A73C92ULL,
		0x5190C538E3BCAA1CULL,
		0x5FD67CDA6880E678ULL,
		0xA3B635DFFC0FF785ULL
	}};
	sign = 0;
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
		0xC2B16E81A712063AULL,
		0x9663E7DD4B0D2804ULL,
		0xB2A7830C30DAB761ULL,
		0x28D2BCB47C0D188FULL,
		0x571F3E21CF66F85EULL,
		0xD56126BB174DF0EEULL,
		0x3C0F79A4018F2DD0ULL,
		0x64E5C1475A37EBF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8BA9E6F8ACD2B10ULL,
		0x05609C477CE99B0DULL,
		0x4ABA3890E5E85E4CULL,
		0x034BFEA66695A686ULL,
		0x570238FFB702D8BAULL,
		0xF50ECF1135135168ULL,
		0x6B4488E17F0007ECULL,
		0x1162415CAB1F52C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19F6D0121C44DB2AULL,
		0x91034B95CE238CF7ULL,
		0x67ED4A7B4AF25915ULL,
		0x2586BE0E15777209ULL,
		0x001D052218641FA4ULL,
		0xE05257A9E23A9F86ULL,
		0xD0CAF0C2828F25E3ULL,
		0x53837FEAAF189935ULL
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
		0xC21157BC98100EEEULL,
		0x02D8380FEDBB2372ULL,
		0x25797604D5910AC8ULL,
		0x29A451882D9E480DULL,
		0x9221B59617E966EBULL,
		0xB806C62A40016577ULL,
		0xB86726D0995038A5ULL,
		0x687BB773BE01DABFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF8702B2018CBDEULL,
		0x8709BBB83089726AULL,
		0x0C90FBFE9D221F12ULL,
		0xA81F57A4B8168A07ULL,
		0x28287B44DC2B1CB1ULL,
		0xB9218D6370D8F92FULL,
		0xEC174E11F7105684ULL,
		0x3C6D36B496F1F989ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8218E79177F74310ULL,
		0x7BCE7C57BD31B108ULL,
		0x18E87A06386EEBB5ULL,
		0x8184F9E37587BE06ULL,
		0x69F93A513BBE4A39ULL,
		0xFEE538C6CF286C48ULL,
		0xCC4FD8BEA23FE220ULL,
		0x2C0E80BF270FE135ULL
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
		0x28D51EDAE2419E12ULL,
		0xDBE6CA5AFA784D22ULL,
		0x84C345DBF96F2167ULL,
		0x0437F9EE05938647ULL,
		0x1AF8EAA8152D45D9ULL,
		0x9F8E7395A3A01338ULL,
		0x2E4C724E37B8C381ULL,
		0xE621F5202BA57EEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BD886F2C7EC0BAULL,
		0x844F67BF707839B6ULL,
		0x9BF7B6976D6BEC61ULL,
		0xCE538E4221A2781AULL,
		0xDA0003FE4163506EULL,
		0xB288623EC846D4A5ULL,
		0x344D705F7484281EULL,
		0xEC89B1F0C57B493AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD817966BB5C2DD58ULL,
		0x5797629B8A00136BULL,
		0xE8CB8F448C033506ULL,
		0x35E46BABE3F10E2CULL,
		0x40F8E6A9D3C9F56AULL,
		0xED061156DB593E92ULL,
		0xF9FF01EEC3349B62ULL,
		0xF998432F662A35AFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCA4752F9F4A9A7EEULL,
		0x6E0953E55DF9BFAAULL,
		0xDBCEFE04FCF0559AULL,
		0xEA0E74548AC322C9ULL,
		0x311BC7970084DE7DULL,
		0x852EBD8A41F3E129ULL,
		0x97E5FA69D4518EB9ULL,
		0x64F9D938F069B4F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD856F8FBB800DEBAULL,
		0xE76BBF97443B8CDFULL,
		0xF73714AD12C17E9CULL,
		0x9E2567634E26C5DFULL,
		0xAB627D37ED8E6382ULL,
		0x74D2BC0CE198C3C4ULL,
		0xCC0585D10001DD57ULL,
		0xEAF9A64359F18EDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1F059FE3CA8C934ULL,
		0x869D944E19BE32CAULL,
		0xE497E957EA2ED6FDULL,
		0x4BE90CF13C9C5CE9ULL,
		0x85B94A5F12F67AFBULL,
		0x105C017D605B1D64ULL,
		0xCBE07498D44FB162ULL,
		0x7A0032F596782617ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEA94B400E3DEA090ULL,
		0xB6C690F5A1976317ULL,
		0x6AA9C848B6FF43D2ULL,
		0x8BD7B60B81EB792CULL,
		0xC686BC81C638A3F0ULL,
		0x92E96C07648C1958ULL,
		0x1DC8DBE52BD770A0ULL,
		0x327B17E7D003CD55ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE31CA69DAB929FULL,
		0x6F803833F67794EDULL,
		0x7A451EF843617844ULL,
		0x4941CCA2F113FB0EULL,
		0xAB493E68325359D3ULL,
		0x54B4C2F074A98E07ULL,
		0x7E6533F111CF9E66ULL,
		0xF14C67981AA2D659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DB1975A46330DF1ULL,
		0x474658C1AB1FCE2AULL,
		0xF064A950739DCB8EULL,
		0x4295E96890D77E1DULL,
		0x1B3D7E1993E54A1DULL,
		0x3E34A916EFE28B51ULL,
		0x9F63A7F41A07D23AULL,
		0x412EB04FB560F6FBULL
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
		0xD971A672DB7FF0A6ULL,
		0xDBF9BF2EA49D1672ULL,
		0x141FB4382106A57FULL,
		0x27B8696983BF1663ULL,
		0x1C71583E6C479814ULL,
		0xBBA24AA9387F4AA4ULL,
		0xE5776FFBDC8BE9C7ULL,
		0x1222E31D7E9E12ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA939748C67726F2ULL,
		0x4BA0980CC26F1D51ULL,
		0x748CBABE5A2CD661ULL,
		0xF07624B120403B4CULL,
		0xB5AB3483D00AAB3AULL,
		0x066DC87E4FDB298AULL,
		0x43A3635245019D0DULL,
		0xAC9E43339A382938ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEDE0F2A1508C9B4ULL,
		0x90592721E22DF920ULL,
		0x9F92F979C6D9CF1EULL,
		0x374244B8637EDB16ULL,
		0x66C623BA9C3CECD9ULL,
		0xB534822AE8A42119ULL,
		0xA1D40CA9978A4CBAULL,
		0x65849FE9E465E975ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0ADBAC705EDCAF27ULL,
		0xB2F2584FA7E84A79ULL,
		0x66DFD980AE9DADC5ULL,
		0xDFE16AA140D41B98ULL,
		0xD6FCFE4B0E732A4FULL,
		0x813A725A17D729A6ULL,
		0xC9C31AC41924A569ULL,
		0xF7336D49D98CCF93ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF933F258F9CB8926ULL,
		0xDB80AF5EC45F621BULL,
		0x4E4BAA12D78EA8A2ULL,
		0x35CF7AE6502D2FF7ULL,
		0x6A7D2F1C71365757ULL,
		0xFE73F5241F3D238AULL,
		0x3CBE253759620A98ULL,
		0x027728EBD99C5DCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11A7BA1765112601ULL,
		0xD771A8F0E388E85DULL,
		0x18942F6DD70F0522ULL,
		0xAA11EFBAF0A6EBA1ULL,
		0x6C7FCF2E9D3CD2F8ULL,
		0x82C67D35F89A061CULL,
		0x8D04F58CBFC29AD0ULL,
		0xF4BC445DFFF071C7ULL
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
		0x95F3264385CF0B39ULL,
		0x1E22AA33856B5012ULL,
		0x2771F9A089C124E9ULL,
		0x30022CF455EFCAA8ULL,
		0xD2A8615DB27AC6EDULL,
		0x9C351F9FF4F810CFULL,
		0x6BBD049F0EE01F71ULL,
		0x168B63602CC357F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA199946A2D673E1EULL,
		0x830082845E72EA75ULL,
		0x9E88C0D9DB8567C7ULL,
		0xBB0661C75194976BULL,
		0x100C6E44B123E63BULL,
		0xC2D8F0A0A96D16A9ULL,
		0xAE8A2D6526B2DEA8ULL,
		0xB500265BE8C52E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF45991D95867CD1BULL,
		0x9B2227AF26F8659CULL,
		0x88E938C6AE3BBD21ULL,
		0x74FBCB2D045B333CULL,
		0xC29BF3190156E0B1ULL,
		0xD95C2EFF4B8AFA26ULL,
		0xBD32D739E82D40C8ULL,
		0x618B3D0443FE295EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBA0AD35075714827ULL,
		0x07D412142E20F830ULL,
		0xE6CEAAE578DFDC27ULL,
		0x57BC79C5E01EBAEFULL,
		0xB46160CF8B4A1FB7ULL,
		0x9F2DE76806CA4AFBULL,
		0xC17EE31F7A720C0DULL,
		0xFB3C12068FB4CA94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C2E6ECA6A6AE3FULL,
		0x6C11C141A1DA3626ULL,
		0x1F368DCAA02B8BF5ULL,
		0x5D785DBBB659447AULL,
		0x86594D701F977447ULL,
		0xA5B881A421C5090BULL,
		0x1E67258F137692E6ULL,
		0x8621047B97D9E8CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC847EC63CECA99E8ULL,
		0x9BC250D28C46C209ULL,
		0xC7981D1AD8B45031ULL,
		0xFA441C0A29C57675ULL,
		0x2E08135F6BB2AB6FULL,
		0xF97565C3E50541F0ULL,
		0xA317BD9066FB7926ULL,
		0x751B0D8AF7DAE1C8ULL
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
		0x20F1C5A8B61074AAULL,
		0x05023C302A436E4FULL,
		0x77B42BC9CCA692A3ULL,
		0x48167F57DC5C2711ULL,
		0x22FB6AB30D605231ULL,
		0xEC3EA801DB07388DULL,
		0xA83B01610529C59EULL,
		0xEABE36DD9ACFE435ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF41857AA8FA7DBULL,
		0xC9E372FDDC828FE9ULL,
		0xB63C1057D45AE4D4ULL,
		0xB8C8957A869D654EULL,
		0x8331F4BC27ACD9C1ULL,
		0xB3319D123CCD11E5ULL,
		0x74ED0E6D1EAD2CFFULL,
		0x013FABF61075976FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12FDAD510B80CCCFULL,
		0x3B1EC9324DC0DE66ULL,
		0xC1781B71F84BADCEULL,
		0x8F4DE9DD55BEC1C2ULL,
		0x9FC975F6E5B3786FULL,
		0x390D0AEF9E3A26A7ULL,
		0x334DF2F3E67C989FULL,
		0xE97E8AE78A5A4CC6ULL
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
		0x87099215881748BEULL,
		0x874AD7E9C70E9E10ULL,
		0x1C708CBE84371CACULL,
		0xFED8FFE5A0678851ULL,
		0x50B9527709A088BEULL,
		0x5D684CD569B3BBA4ULL,
		0x1EDAEB599B18CF69ULL,
		0xB6B4734652CAAE85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85CB54B0E73BEFF8ULL,
		0x0F255AAC687F8A01ULL,
		0x4DDECEA8A34AED76ULL,
		0xB3F849A1DCCCE3A0ULL,
		0x1462EA20E6E2AE70ULL,
		0x8ED8D934CFC39996ULL,
		0x0E0B7BF742FC208AULL,
		0x6388852D9879B2F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x013E3D64A0DB58C6ULL,
		0x78257D3D5E8F140FULL,
		0xCE91BE15E0EC2F36ULL,
		0x4AE0B643C39AA4B0ULL,
		0x3C56685622BDDA4EULL,
		0xCE8F73A099F0220EULL,
		0x10CF6F62581CAEDEULL,
		0x532BEE18BA50FB91ULL
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
		0x706C96065A4621C1ULL,
		0x474C23463B6000D2ULL,
		0x898BE6536553BA87ULL,
		0xA4432A2C9748DFB2ULL,
		0x68BD43E5F31A8A19ULL,
		0xE5EFABF209B3676CULL,
		0xEEB96CEABC6A7CF0ULL,
		0x1762AFD9D296A449ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BFD1193406EA3B4ULL,
		0x5E3D5895B650006EULL,
		0x2BD14472F7140703ULL,
		0xF5CCC49AF3835813ULL,
		0x46E4C63AD0D8F924ULL,
		0xA6864C66FD7172C0ULL,
		0x75E76EBF140371F7ULL,
		0x6D07DC307ABB55E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x046F847319D77E0DULL,
		0xE90ECAB085100064ULL,
		0x5DBAA1E06E3FB383ULL,
		0xAE766591A3C5879FULL,
		0x21D87DAB224190F4ULL,
		0x3F695F8B0C41F4ACULL,
		0x78D1FE2BA8670AF9ULL,
		0xAA5AD3A957DB4E62ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x208121AE80134F8FULL,
		0x173DBBCEC7293410ULL,
		0xE20E8F13CCBE691AULL,
		0xCCF250AADEDB9643ULL,
		0xD9CB430A31504E6BULL,
		0x5979D74260AFDE8FULL,
		0xD3A380F85BD97D5EULL,
		0xD7FB2DD176B7B5EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C71EE030A7C8574ULL,
		0xB79B43AADD55CCD6ULL,
		0x3B51EEADB67D4E89ULL,
		0xB845E2222E131CB1ULL,
		0x5A7AAB7C002EDCF9ULL,
		0xC3FC343275031C7BULL,
		0xBC6C2E9D8D16F5E7ULL,
		0x186F0B6308A5C7F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD40F33AB7596CA1BULL,
		0x5FA27823E9D36739ULL,
		0xA6BCA06616411A90ULL,
		0x14AC6E88B0C87992ULL,
		0x7F50978E31217172ULL,
		0x957DA30FEBACC214ULL,
		0x1737525ACEC28776ULL,
		0xBF8C226E6E11EDFDULL
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
		0x01D26E961B629EF3ULL,
		0x79FD69453AEF9959ULL,
		0xEAC135C9E65E07F6ULL,
		0x3DFE5DB047C33623ULL,
		0x13099D83EAC1D47BULL,
		0x9350815364D9E54AULL,
		0xBC9B4887C74D482CULL,
		0x44926E6ED6103980ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA619D2E2C3E8475ULL,
		0xE00C3AE7FAEEADFDULL,
		0x6EF7BE3192F1BA85ULL,
		0xCE6F6793AF0DF580ULL,
		0xAF94C6F4646D3F8BULL,
		0x801B0026545326B7ULL,
		0x3FE3B3777A426353ULL,
		0x0A3DA8519EA7B713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4770D167EF241A7EULL,
		0x99F12E5D4000EB5BULL,
		0x7BC97798536C4D70ULL,
		0x6F8EF61C98B540A3ULL,
		0x6374D68F865494EFULL,
		0x1335812D1086BE92ULL,
		0x7CB795104D0AE4D9ULL,
		0x3A54C61D3768826DULL
	}};
	sign = 0;
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
		0x0E609F280A65EACBULL,
		0xF48CA20C09DC6379ULL,
		0x7293B554E3D398B5ULL,
		0x9AAAA25E299D91C3ULL,
		0x93611590A4FA8EC3ULL,
		0x0326BA5C2CA384F7ULL,
		0xF2DF5DB99897401FULL,
		0xDA19CA8828C09943ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x968A8D0F890BC4A6ULL,
		0x31832CF8E39A16C2ULL,
		0xBB79B03205D78C25ULL,
		0xFD504FB891AD9F0CULL,
		0x3D1F43856445F37BULL,
		0x5AC4AB118A5E2B87ULL,
		0x97DA913206D47E7AULL,
		0x280779F77363E9AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77D61218815A2625ULL,
		0xC309751326424CB6ULL,
		0xB71A0522DDFC0C90ULL,
		0x9D5A52A597EFF2B6ULL,
		0x5641D20B40B49B47ULL,
		0xA8620F4AA2455970ULL,
		0x5B04CC8791C2C1A4ULL,
		0xB2125090B55CAF95ULL
	}};
	sign = 0;
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
		0x8C916F963D736D32ULL,
		0x68E1313EC6202E87ULL,
		0x26F20DA7AB67B7C6ULL,
		0x5C95CDA257520C3EULL,
		0x5B1DD80D001F7C28ULL,
		0x120BA47C5CCAD514ULL,
		0xF4B9C92CEA32B04FULL,
		0xBACC6F04A578BE51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6038F3D77AAB0C3CULL,
		0x768B7A0F4A1BA0B7ULL,
		0x27E7893AAF0483BBULL,
		0x35457B4E74FD568EULL,
		0xDD3B6CCF5B359B56ULL,
		0x8F8D3FB4A777818CULL,
		0x415DC0AE37F62DAEULL,
		0x667C42D467BC5354ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C587BBEC2C860F6ULL,
		0xF255B72F7C048DD0ULL,
		0xFF0A846CFC63340AULL,
		0x27505253E254B5AFULL,
		0x7DE26B3DA4E9E0D2ULL,
		0x827E64C7B5535387ULL,
		0xB35C087EB23C82A0ULL,
		0x54502C303DBC6AFDULL
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
		0x0F7F3D06D14A6942ULL,
		0xC4B0B708F4894ABFULL,
		0x2387FAE317A63C2EULL,
		0x0B4307D99E2454E9ULL,
		0x2D99B0CAFC643722ULL,
		0xDEB54A9E27FE5C92ULL,
		0xFF84989BA98677CAULL,
		0x4E7409F3F140AB47ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7944B872F22D65BEULL,
		0x823BDEE0900F9157ULL,
		0x39779D34633A46D0ULL,
		0xE5A29C71D4F187C2ULL,
		0xEAF3062917577365ULL,
		0x3368F2EBE84C3D61ULL,
		0x5987F831C2BE0857ULL,
		0x77FFC91FB6FA24B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x963A8493DF1D0384ULL,
		0x4274D8286479B967ULL,
		0xEA105DAEB46BF55EULL,
		0x25A06B67C932CD26ULL,
		0x42A6AAA1E50CC3BCULL,
		0xAB4C57B23FB21F30ULL,
		0xA5FCA069E6C86F73ULL,
		0xD67440D43A468695ULL
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
		0xB2787B4C9F115163ULL,
		0x2C83A4CAAFBB99BAULL,
		0x94F09CDAA0CD2664ULL,
		0x76B70B890FE54A4CULL,
		0xD1B050BE5DC00FD6ULL,
		0xE71F3E270672BAC7ULL,
		0x6CCA052B815EF934ULL,
		0x52881031E3C7E6E1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB49902A53000DDULL,
		0x59511D43C99C3E0FULL,
		0x9C59BB43BB61D9C7ULL,
		0xBD2D5E835E8D14E7ULL,
		0xC8C51D1BBA2EDDC9ULL,
		0x6BC9887513E21CBCULL,
		0x24BE98340E0BE04EULL,
		0x91A3A667FFE764FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73C3E249F9E15086ULL,
		0xD3328786E61F5BABULL,
		0xF896E196E56B4C9CULL,
		0xB989AD05B1583564ULL,
		0x08EB33A2A391320CULL,
		0x7B55B5B1F2909E0BULL,
		0x480B6CF7735318E6ULL,
		0xC0E469C9E3E081E4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4001F00D2F1C8EB8ULL,
		0x2C8CBC73976BB4A8ULL,
		0x09F197D5BE75104DULL,
		0x5FEFD46FA538A14BULL,
		0x3CADF868F27420ECULL,
		0xD9350347F819B4CCULL,
		0x73EC507E67725683ULL,
		0x402008470068EDDAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6407A4331D1205ULL,
		0x5C07C42AE498144BULL,
		0x0295C312A0214A03ULL,
		0x9FFF0331D65357C5ULL,
		0x18A279A947559D0BULL,
		0x0D07B3E460602E96ULL,
		0x1F072A820C587F48ULL,
		0xFDD7692053F3891AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC39DE868FBFF7CB3ULL,
		0xD084F848B2D3A05CULL,
		0x075BD4C31E53C649ULL,
		0xBFF0D13DCEE54986ULL,
		0x240B7EBFAB1E83E0ULL,
		0xCC2D4F6397B98636ULL,
		0x54E525FC5B19D73BULL,
		0x42489F26AC7564C0ULL
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
		0x1FF3D2229203CAADULL,
		0x03462F436A14CC7AULL,
		0x150BA379D1ED1613ULL,
		0x2C2FC67C179005AFULL,
		0x4E3E34C646D5A68EULL,
		0xD8FDFD637D754F8EULL,
		0xDBBEA26FD4F44170ULL,
		0x78A71FFEACCA727DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCDCED962F02AFAULL,
		0x9F795D171063CC55ULL,
		0x2FF5C7F1953E938BULL,
		0x25154E50ED622E54ULL,
		0x8998A28DA4252503ULL,
		0x8498F284440AD949ULL,
		0x2ABF886ECF8C3C92ULL,
		0x6C1201B77AF1EBCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x222603492F139FB3ULL,
		0x63CCD22C59B10024ULL,
		0xE515DB883CAE8287ULL,
		0x071A782B2A2DD75AULL,
		0xC4A59238A2B0818BULL,
		0x54650ADF396A7644ULL,
		0xB0FF1A01056804DEULL,
		0x0C951E4731D886AFULL
	}};
	sign = 0;
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
		0x60A4322B561EAB28ULL,
		0xF95C0D2ED43FC671ULL,
		0x21D728C650DFB703ULL,
		0x0A231AD439EF9B7BULL,
		0x3346595DAD9F5F41ULL,
		0x2FD5356194851A47ULL,
		0xADD54A4B4F181AD6ULL,
		0x9D3F724585E73235ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDD5774A08FB01EULL,
		0x7EC5661D8DD84C20ULL,
		0x10F1EE4F0A835A3BULL,
		0x750156B16273BA81ULL,
		0x43DFDC8646823923ULL,
		0xE3EB0D524D861BBCULL,
		0x0AA9731F3A0577B4ULL,
		0xFDDD8211FE0A651DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43C6DAB6B58EFB0AULL,
		0x7A96A71146677A51ULL,
		0x10E53A77465C5CC8ULL,
		0x9521C422D77BE0FAULL,
		0xEF667CD7671D261DULL,
		0x4BEA280F46FEFE8AULL,
		0xA32BD72C1512A321ULL,
		0x9F61F03387DCCD18ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEC66D1CED320E2EDULL,
		0x7EA52A1F3B48A0F8ULL,
		0x1C3F34804C6EC746ULL,
		0x89B78E7874E6A14EULL,
		0xFCD5B25DD3D6F422ULL,
		0xD4F7222917D5ED1DULL,
		0x1A639F5418FFC8FDULL,
		0xE5E7AC82B673421EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD9CC9B104B23E2ULL,
		0x043325762B308053ULL,
		0x3D3C5F73398CD932ULL,
		0xB0B2F0FC09D51315ULL,
		0x7143CEDF3B72E3BBULL,
		0xE7F28D61AB4A6D85ULL,
		0x7E5B590E5906332DULL,
		0x20705B412FD67801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF8D0533C2D5BF0BULL,
		0x7A7204A9101820A5ULL,
		0xDF02D50D12E1EE14ULL,
		0xD9049D7C6B118E38ULL,
		0x8B91E37E98641066ULL,
		0xED0494C76C8B7F98ULL,
		0x9C084645BFF995CFULL,
		0xC5775141869CCA1CULL
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
		0xA26FA739C9318DE1ULL,
		0x2222FDBBFA89C702ULL,
		0x402D2BBD231D4189ULL,
		0x3194E9A8D0806104ULL,
		0xEEFC7C0FACBF680BULL,
		0xAA97F49CC1FEE8B6ULL,
		0x3DE4686D64283866ULL,
		0x4D7D65FE3D195E51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF40C9E2F6D9D9218ULL,
		0x2127D3459483F964ULL,
		0x16E60BF49700B7A2ULL,
		0x48E61524F1E4BC36ULL,
		0x34A9CB71286BEE38ULL,
		0xD91E2F4AD5CFC805ULL,
		0x2DC68A1D58581316ULL,
		0xDE25964E811708D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE63090A5B93FBC9ULL,
		0x00FB2A766605CD9DULL,
		0x29471FC88C1C89E7ULL,
		0xE8AED483DE9BA4CEULL,
		0xBA52B09E845379D2ULL,
		0xD179C551EC2F20B1ULL,
		0x101DDE500BD0254FULL,
		0x6F57CFAFBC025579ULL
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
		0xC0B03576482A494DULL,
		0x9039CD080E78AAB3ULL,
		0xCE673AAFE8F11D1CULL,
		0x554CCDEDBF5DE44FULL,
		0xC1A25659B5507828ULL,
		0xC10BA3123211C058ULL,
		0x70C279C72018898BULL,
		0xBC05D21067CEB7FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CA9395A65215B5ULL,
		0x124E069927BC1C23ULL,
		0xFF2573B638CFACA8ULL,
		0x0D4309F189052BD0ULL,
		0x16745ED706094932ULL,
		0x7CA434BABEE923BDULL,
		0xB1E2A2E0B3487BCCULL,
		0x78E6A17BAC5CF193ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CE5A1E0A1D83398ULL,
		0x7DEBC66EE6BC8E90ULL,
		0xCF41C6F9B0217074ULL,
		0x4809C3FC3658B87EULL,
		0xAB2DF782AF472EF6ULL,
		0x44676E5773289C9BULL,
		0xBEDFD6E66CD00DBFULL,
		0x431F3094BB71C66AULL
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
		0xFD67BEEDC80B3A1DULL,
		0x1E113524B65BBC5FULL,
		0xAEC22AC1114AEBF4ULL,
		0x9325F1FD69F2B326ULL,
		0x6C17272F84203E33ULL,
		0xFD0F1AE630F024B6ULL,
		0x45B7DE0EF988D484ULL,
		0x22450E8EA6CB5377ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9396101F2F8C0124ULL,
		0xA6CBCE756CFD7A0DULL,
		0x2A6569FEE6D1CF0DULL,
		0xFCF368E140F42AA9ULL,
		0xEAD1422477336688ULL,
		0xE56FE962CAEB945BULL,
		0x75F096746B97B71CULL,
		0x11E115C30845A61CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D1AECE987F38F9ULL,
		0x774566AF495E4252ULL,
		0x845CC0C22A791CE6ULL,
		0x9632891C28FE887DULL,
		0x8145E50B0CECD7AAULL,
		0x179F31836604905AULL,
		0xCFC7479A8DF11D68ULL,
		0x1063F8CB9E85AD5AULL
	}};
	sign = 0;
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
		0xC7B559C523643634ULL,
		0x34D505F6EB60C4A5ULL,
		0xC8D13AA1424AE611ULL,
		0x0C41EA15EB9B7DA9ULL,
		0x52521CAF57198192ULL,
		0x9CCFCC2464C26716ULL,
		0x467AF10FC80FC554ULL,
		0x789DFC796972CB15ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x537B5D56CBCD4DDCULL,
		0x6D3BDE3D753AF6F1ULL,
		0x27D9680DC8EEE75DULL,
		0x80FE821DE16EE4D5ULL,
		0xB1F1398DED733558ULL,
		0x20E79D77CDF73BB9ULL,
		0x2CA03D5E8B63314AULL,
		0x788F399EF02725AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7439FC6E5796E858ULL,
		0xC79927B97625CDB4ULL,
		0xA0F7D293795BFEB3ULL,
		0x8B4367F80A2C98D4ULL,
		0xA060E32169A64C39ULL,
		0x7BE82EAC96CB2B5CULL,
		0x19DAB3B13CAC940AULL,
		0x000EC2DA794BA567ULL
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
		0xAFDA8BDF0AB619ADULL,
		0x5176C490A6405E9AULL,
		0xB3351ACCEBD386A3ULL,
		0xE437AF215C8B1373ULL,
		0x65806F00F7CA9481ULL,
		0x9F417BC2FD0FEE21ULL,
		0x865ED9182778EAD2ULL,
		0x45D9E09E4D0951A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17048FEE09A40F9ULL,
		0x1FAB67E931E7C2FAULL,
		0x044A727653D7D528ULL,
		0x717236286D5299AEULL,
		0x743842BAEEDC8080ULL,
		0xA97738733779F202ULL,
		0x375F8FB70ADFC42DULL,
		0x6EEEFFA9F3A2B9E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE6A42E02A1BD8B4ULL,
		0x31CB5CA774589B9FULL,
		0xAEEAA85697FBB17BULL,
		0x72C578F8EF3879C5ULL,
		0xF1482C4608EE1401ULL,
		0xF5CA434FC595FC1EULL,
		0x4EFF49611C9926A4ULL,
		0xD6EAE0F4596697C3ULL
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
		0xE55AEA908CCFABBDULL,
		0x0E8D5C1F29B350FDULL,
		0x589CE55EA61BD9B0ULL,
		0xD5A84FA76A9B9A95ULL,
		0x13B8E65EFF921BB4ULL,
		0x887F7CBB91A58CF7ULL,
		0xE1DEA4437AEA5995ULL,
		0xDEECE8D657034A19ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC764E200131E6F90ULL,
		0xA7CB818E896AF3A9ULL,
		0xDBD8F59D2EC09291ULL,
		0x8222CAA8F6D6AFC5ULL,
		0xF10B1EF275BE0437ULL,
		0xC180C0A2BBCF8D93ULL,
		0xFF723FFD34472D89ULL,
		0xE414B33233C8EA37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DF6089079B13C2DULL,
		0x66C1DA90A0485D54ULL,
		0x7CC3EFC1775B471EULL,
		0x538584FE73C4EACFULL,
		0x22ADC76C89D4177DULL,
		0xC6FEBC18D5D5FF63ULL,
		0xE26C644646A32C0BULL,
		0xFAD835A4233A5FE1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB1696DEDD850DAA6ULL,
		0xF4F8672414FE643BULL,
		0xAED09D21270687D5ULL,
		0x94D2F5718D2A2ACEULL,
		0xA2DF9DB430E7650CULL,
		0x4891B52E8931EABCULL,
		0x7E475D6492B4E807ULL,
		0xC9334CD0E783E0CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A301FE8878BEEADULL,
		0x7057DEE97A771C97ULL,
		0x2EC05DE59E02F23FULL,
		0x523C932AE879A904ULL,
		0x934276DFA3C0E88AULL,
		0x8B7CCD9BA64CFD44ULL,
		0x35EC8AEF41852E99ULL,
		0x59787CC7E6F442D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7394E0550C4EBF9ULL,
		0x84A0883A9A8747A4ULL,
		0x80103F3B89039596ULL,
		0x42966246A4B081CAULL,
		0x0F9D26D48D267C82ULL,
		0xBD14E792E2E4ED78ULL,
		0x485AD275512FB96DULL,
		0x6FBAD009008F9DFDULL
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
		0x6D8AF1FB09EB01F7ULL,
		0x1FD4A039AEAF0CBDULL,
		0xF1FF7FEB8E47C6DFULL,
		0xA2B301770E6CFB0CULL,
		0x3A0634075F81DA6EULL,
		0x39795899E3CEA518ULL,
		0x0C3F9BB691586A84ULL,
		0x534A596AAB11B828ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14CF82444825F936ULL,
		0xE9B3B0CAC33411B1ULL,
		0xEA8FF38A63F143C8ULL,
		0x4887F0A8D62FBA6EULL,
		0xCE3AC66C5D215B20ULL,
		0xB72B21B696214E92ULL,
		0x9BCA7E166B17B329ULL,
		0x3F30EC5775A9E69BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58BB6FB6C1C508C1ULL,
		0x3620EF6EEB7AFB0CULL,
		0x076F8C612A568316ULL,
		0x5A2B10CE383D409EULL,
		0x6BCB6D9B02607F4EULL,
		0x824E36E34DAD5685ULL,
		0x70751DA02640B75AULL,
		0x14196D133567D18CULL
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
		0x1D52370F5FCB5CFFULL,
		0x29065AD4E5B44D58ULL,
		0x0DDD119A59802815ULL,
		0x301010C06888B44BULL,
		0x4F5714FEACE01992ULL,
		0x8D3B436835FD5D49ULL,
		0xB57513745328F381ULL,
		0x42200BE4B61B74B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3CB3072754D925ULL,
		0xCCA85F6B6E112FD6ULL,
		0xAF2A5B360F3CA3B9ULL,
		0x528FF897CB7D2902ULL,
		0xB544D640E219A89CULL,
		0xE7DC203241A30684ULL,
		0xF1AC94539D3186A4ULL,
		0x03219288D038BF94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3158408387683DAULL,
		0x5C5DFB6977A31D81ULL,
		0x5EB2B6644A43845BULL,
		0xDD8018289D0B8B48ULL,
		0x9A123EBDCAC670F5ULL,
		0xA55F2335F45A56C4ULL,
		0xC3C87F20B5F76CDCULL,
		0x3EFE795BE5E2B523ULL
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
		0x69957FD5BD177D6BULL,
		0xE1FA1C829C31AE0AULL,
		0x4B662DA9C77BE3E0ULL,
		0x9C58EAB913ED12EFULL,
		0x9FF298210077FF24ULL,
		0x08DCBAB7A5979F72ULL,
		0x372FF0A5650DED0AULL,
		0x6FECD3510CB76C39ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B4584CAD8C1147ULL,
		0x595C1CCA21E1F127ULL,
		0x1F823E21E392E69FULL,
		0x7F34E5ABBA5F9D1BULL,
		0x4BB53762D98366F2ULL,
		0x186275C1CBE515E3ULL,
		0x4F8DA46B4FA4B571ULL,
		0xFC7E5C9AE2DE9810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62E127890F8B6C24ULL,
		0x889DFFB87A4FBCE3ULL,
		0x2BE3EF87E3E8FD41ULL,
		0x1D24050D598D75D4ULL,
		0x543D60BE26F49832ULL,
		0xF07A44F5D9B2898FULL,
		0xE7A24C3A15693798ULL,
		0x736E76B629D8D428ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5CB50E218138E540ULL,
		0xAF90344BA6204B5CULL,
		0x646BD4F41F31A398ULL,
		0x4A93B6DE120613D2ULL,
		0x8A595CCDFCA1C485ULL,
		0xEECD397F19092928ULL,
		0x8E8CEB29EF1552BDULL,
		0x2FDB4D3DAB761B76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBD554CDABE610D0ULL,
		0xD0EFB92D16A8C5A0ULL,
		0x0EA8FA75A49A4E1BULL,
		0xA9DC18B495A20DF5ULL,
		0x973D1A7F8367FDC2ULL,
		0xFFA2D0D3DB805288ULL,
		0x996BFCD5C304DEA0ULL,
		0x4C0DCEE5CEE31C9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80DFB953D552D470ULL,
		0xDEA07B1E8F7785BBULL,
		0x55C2DA7E7A97557CULL,
		0xA0B79E297C6405DDULL,
		0xF31C424E7939C6C2ULL,
		0xEF2A68AB3D88D69FULL,
		0xF520EE542C10741CULL,
		0xE3CD7E57DC92FEDBULL
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
		0x8A26F6445FCD95DEULL,
		0xEB6F17CE2F27C14FULL,
		0xADAC8380B0383FE1ULL,
		0x54D11E2B4C4EBC93ULL,
		0x60D5183C9ED1037DULL,
		0x3911C91668B21410ULL,
		0x5E17F77374B2B4CBULL,
		0xA0342BA88B009E3DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D29E1E33CE740A7ULL,
		0xC5C3A9CF5CE4C086ULL,
		0xD33A5E9FFDA7F333ULL,
		0x5CB80D04F6F4F78DULL,
		0x3B5BCB4A046D6F92ULL,
		0xBE4B2B3816F9A289ULL,
		0x1965CCFC59196DBCULL,
		0x704CC5B2E2970045ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CFD146122E65537ULL,
		0x25AB6DFED24300C9ULL,
		0xDA7224E0B2904CAEULL,
		0xF81911265559C505ULL,
		0x25794CF29A6393EAULL,
		0x7AC69DDE51B87187ULL,
		0x44B22A771B99470EULL,
		0x2FE765F5A8699DF8ULL
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
		0x7173520D5A0E1CBCULL,
		0xB4823706130481D6ULL,
		0x871EDF258862D2E1ULL,
		0x974B3851E50C6789ULL,
		0x1B3AC67508F967A6ULL,
		0x4F8359972A4793C5ULL,
		0x307ED6F318CC8FE1ULL,
		0xD9150C9405064ED7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD248050C66F80F53ULL,
		0xC9CD272253D71F9BULL,
		0x34AE7DE407C9F4E6ULL,
		0xB10422B7B14DBDE5ULL,
		0x62D5371FFD142BCBULL,
		0xE7F2A04CE26DEA0DULL,
		0x9802AF275727CDF8ULL,
		0x2570504615044DD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F2B4D00F3160D69ULL,
		0xEAB50FE3BF2D623AULL,
		0x527061418098DDFAULL,
		0xE647159A33BEA9A4ULL,
		0xB8658F550BE53BDAULL,
		0x6790B94A47D9A9B7ULL,
		0x987C27CBC1A4C1E8ULL,
		0xB3A4BC4DF0020105ULL
	}};
	sign = 0;
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
		0xE4EEFFEF15EFF1BFULL,
		0xB42B5C4CF6E04D19ULL,
		0x1CBE8FB311C5402EULL,
		0x874DF883A617ED50ULL,
		0x76B021099B60A884ULL,
		0x38C043EC59437DFEULL,
		0xC30E04E720F29C4AULL,
		0xD98790432872253AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6FA0A1DFE5EF64EULL,
		0x8024772CE9420EDEULL,
		0xC07D53A50403E5E5ULL,
		0x0BF12AD7806E0023ULL,
		0xD10FF4AF821FC204ULL,
		0x686E693D47204434ULL,
		0xEA91C038C8EC6F09ULL,
		0x089CFD05B105D7B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DF4F5D11790FB71ULL,
		0x3406E5200D9E3E3BULL,
		0x5C413C0E0DC15A49ULL,
		0x7B5CCDAC25A9ED2CULL,
		0xA5A02C5A1940E680ULL,
		0xD051DAAF122339C9ULL,
		0xD87C44AE58062D40ULL,
		0xD0EA933D776C4D87ULL
	}};
	sign = 0;
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
		0x0D5EF790D23EC8CAULL,
		0x903ED844F4016467ULL,
		0x438AD30B8D81780DULL,
		0x1E487584FC267B40ULL,
		0x7B996C018D29FBD4ULL,
		0x6B60F72A48BEBDE5ULL,
		0x4E38CBE3BAEC225CULL,
		0x12A9F8EB9D06A3F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E61415E6B6FDD0BULL,
		0xBA8BA23F37D9EF3BULL,
		0xB4F9E5D8457B6613ULL,
		0x36F5A613D3613C6CULL,
		0x1B7F751EBEAC3522ULL,
		0x4DFB9E2E7C27D339ULL,
		0x637C98CD50561FF2ULL,
		0xBC360320CA033875ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EFDB63266CEEBBFULL,
		0xD5B33605BC27752BULL,
		0x8E90ED33480611F9ULL,
		0xE752CF7128C53ED3ULL,
		0x6019F6E2CE7DC6B1ULL,
		0x1D6558FBCC96EAACULL,
		0xEABC33166A96026AULL,
		0x5673F5CAD3036B80ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x22F2383010D11E47ULL,
		0xAF1EFE851E58D10FULL,
		0xE1F39CEBF6DE23CFULL,
		0x356F1A0FE92F7773ULL,
		0xBAFA9DF596F5E845ULL,
		0xB6FB4ABBFF2A3EC4ULL,
		0xAC9597910563FF77ULL,
		0x1444086C3A8C5B0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FDD17B9B2CB1694ULL,
		0xE6C7D7E0F3422814ULL,
		0xFBB66FFD315BF203ULL,
		0x968762E652DAFC3DULL,
		0xA92BC472FA8B1076ULL,
		0x41F80742D45D0326ULL,
		0x0C0AC6471E81DBB3ULL,
		0x9CCD393A49973647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE31520765E0607B3ULL,
		0xC85726A42B16A8FAULL,
		0xE63D2CEEC58231CBULL,
		0x9EE7B72996547B35ULL,
		0x11CED9829C6AD7CEULL,
		0x750343792ACD3B9EULL,
		0xA08AD149E6E223C4ULL,
		0x7776CF31F0F524C4ULL
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
		0x8267C4F508B9AB08ULL,
		0x4AD80414235DCE8BULL,
		0xB19C20094D8ADAC9ULL,
		0x9111D0DCA8F4AD26ULL,
		0x28A426FAD612A03DULL,
		0x000CD495C7522D69ULL,
		0x5B22C2E530AB5596ULL,
		0x36AF27B4FFB21906ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7E83451051B6347ULL,
		0x6BED7CA23E2E6121ULL,
		0x59E60A8ABD5A5C23ULL,
		0xFA8C5785F1ACAD8DULL,
		0x2306D2AD64929648ULL,
		0xF1F06788BA7D6457ULL,
		0x4BD4BDC10D6599DFULL,
		0xD60A4EF01FD4A107ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7F90A4039E47C1ULL,
		0xDEEA8771E52F6D69ULL,
		0x57B6157E90307EA5ULL,
		0x96857956B747FF99ULL,
		0x059D544D718009F4ULL,
		0x0E1C6D0D0CD4C912ULL,
		0x0F4E05242345BBB6ULL,
		0x60A4D8C4DFDD77FFULL
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
		0x1CDBA7BE0B2B2517ULL,
		0xE0A1420D67F0D75DULL,
		0x998FDA78CA7CCC95ULL,
		0x32F6FB253088000EULL,
		0xAEE9680C7DE78A22ULL,
		0xF179BC0BD4004562ULL,
		0xFC9A633C84868E5AULL,
		0x214EE2F5F5BDEB73ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB594B8F108030A42ULL,
		0x46BB625467693AEDULL,
		0xC568AE99FC4D14FBULL,
		0x2D8CDFCDA3EEE98AULL,
		0x41342BAA65AAAB73ULL,
		0xFF727706889E7FE7ULL,
		0x5D657EDED7152223ULL,
		0x96F42A8281ED2545ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6746EECD03281AD5ULL,
		0x99E5DFB900879C6FULL,
		0xD4272BDECE2FB79AULL,
		0x056A1B578C991683ULL,
		0x6DB53C62183CDEAFULL,
		0xF20745054B61C57BULL,
		0x9F34E45DAD716C36ULL,
		0x8A5AB87373D0C62EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAD58665FDA4D74FDULL,
		0xE4EDC6D2F0D3E14DULL,
		0xC5A30FA039A7C614ULL,
		0x3404DF2646461075ULL,
		0xCFBD5808FC7298C6ULL,
		0xFDDCCA64CE94CA6EULL,
		0x2BD7F90F09BCF7FCULL,
		0x3794331971945C04ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ACEC1DB7AFB9EE3ULL,
		0x907534ED9E8C0614ULL,
		0x0EFF62B26BDF2459ULL,
		0xF50651F90FAF681EULL,
		0xD483E62D1272F079ULL,
		0xEC4757307DD91E9FULL,
		0x4EB5B692626EB5A8ULL,
		0x338898E01CEB40E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2289A4845F51D61AULL,
		0x547891E55247DB39ULL,
		0xB6A3ACEDCDC8A1BBULL,
		0x3EFE8D2D3696A857ULL,
		0xFB3971DBE9FFA84CULL,
		0x1195733450BBABCEULL,
		0xDD22427CA74E4254ULL,
		0x040B9A3954A91B1FULL
	}};
	sign = 0;
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
		0x5BDFBBD1C48F8459ULL,
		0x037BC04073914BF8ULL,
		0x9479A5F0FBF855B1ULL,
		0x48AF38E8A55D6919ULL,
		0x986C2EBA52F9D792ULL,
		0x86FB0F9017A0922CULL,
		0xCE09EE2CB5B36A9BULL,
		0xBAC0E4BDF6BE2B36ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD748EE947F04BF35ULL,
		0xB2B21A2F8C77DADCULL,
		0x0B8E6A1F4E21D24DULL,
		0x600F0585F11E0AB0ULL,
		0x0C28EE9870FC2328ULL,
		0x6E0146B837E1C052ULL,
		0xB033E698E9ADB602ULL,
		0xCE9E52E9A0E3D7D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8496CD3D458AC524ULL,
		0x50C9A610E719711BULL,
		0x88EB3BD1ADD68363ULL,
		0xE8A03362B43F5E69ULL,
		0x8C434021E1FDB469ULL,
		0x18F9C8D7DFBED1DAULL,
		0x1DD60793CC05B499ULL,
		0xEC2291D455DA5365ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7E697D614E2D823AULL,
		0xD20F91F6BCCF0FE6ULL,
		0x166304DE489937DDULL,
		0xF397576262CD0F3BULL,
		0x6C077CEF2119827EULL,
		0xFBDB2763CE598700ULL,
		0xBCF000D5A46DD941ULL,
		0x7D24D75C269BC559ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADE2ECC10812600DULL,
		0x8AB9E5AE9477E375ULL,
		0xF97D5E542106E6F9ULL,
		0xCB2174DAC152F3E7ULL,
		0x5361E78E46BFB804ULL,
		0x6112FB41C5D884F5ULL,
		0x91EBD289E70C435DULL,
		0xB8C890198E42CA7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD08690A0461B222DULL,
		0x4755AC4828572C70ULL,
		0x1CE5A68A279250E4ULL,
		0x2875E287A17A1B53ULL,
		0x18A59560DA59CA7AULL,
		0x9AC82C220881020BULL,
		0x2B042E4BBD6195E4ULL,
		0xC45C47429858FADBULL
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
		0xA0757D41B6102622ULL,
		0xFC0AC383EDEC1095ULL,
		0x783A52A8AB8345D8ULL,
		0x4DABC05F15357416ULL,
		0x8E961566A3E29634ULL,
		0x8D474089A4E3DF6EULL,
		0x340C3BC29F69E338ULL,
		0xDE3E9AA721F1EAAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x513CDD15111671F2ULL,
		0x209604EF7B068699ULL,
		0xB1CECE935594375BULL,
		0xE13D2C5F442C3A0CULL,
		0x3DF4E64531AF8751ULL,
		0x432B46B0F1D34C48ULL,
		0xBAF14EAE4746FD61ULL,
		0xE364F2D4CE8C183CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F38A02CA4F9B430ULL,
		0xDB74BE9472E589FCULL,
		0xC66B841555EF0E7DULL,
		0x6C6E93FFD1093A09ULL,
		0x50A12F2172330EE2ULL,
		0x4A1BF9D8B3109326ULL,
		0x791AED145822E5D7ULL,
		0xFAD9A7D25365D272ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2DB628C842DC6311ULL,
		0xC23208AA631D4380ULL,
		0x0C8238BA1089FCDDULL,
		0x804B0781924DDA36ULL,
		0xF6456ED0B72AC45CULL,
		0xAC2FB906C37CE3D7ULL,
		0xA331DA84F4288BC5ULL,
		0x95F2DD6527F87FAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x338CCE7CEEC2EE59ULL,
		0xB1A9B8844244894DULL,
		0x07D1121EDC9AAE62ULL,
		0xD4FA1441F75B930CULL,
		0xAD60F54078DEB2B3ULL,
		0x93F6510B4E9811E3ULL,
		0x0F4C2D062C1D447EULL,
		0x6ABBC5A3A9C3D9E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA295A4B541974B8ULL,
		0x1088502620D8BA32ULL,
		0x04B1269B33EF4E7BULL,
		0xAB50F33F9AF2472AULL,
		0x48E479903E4C11A8ULL,
		0x183967FB74E4D1F4ULL,
		0x93E5AD7EC80B4747ULL,
		0x2B3717C17E34A5CCULL
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
		0xE74AF0A6E982EEA8ULL,
		0x3DA840362E2B5EB3ULL,
		0x7CBE43FDDC68EA02ULL,
		0xEEB874072DD0910EULL,
		0x782BF93ABDDF20E8ULL,
		0xF3574425C5148BB3ULL,
		0x753511AA7CB13544ULL,
		0xE9E5FB0CC2E63AB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D5597F3557FB926ULL,
		0xDF9A6B45FE1AB9F6ULL,
		0xA66824115FF5605FULL,
		0x0FD68DB0995F8218ULL,
		0x30DB2DE1BB36110EULL,
		0xE2805203B072EFB3ULL,
		0x1480F75BF9F29997ULL,
		0xC5485732A414F205ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69F558B394033582ULL,
		0x5E0DD4F03010A4BDULL,
		0xD6561FEC7C7389A2ULL,
		0xDEE1E65694710EF5ULL,
		0x4750CB5902A90FDAULL,
		0x10D6F22214A19C00ULL,
		0x60B41A4E82BE9BADULL,
		0x249DA3DA1ED148ACULL
	}};
	sign = 0;
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
		0x57F5548E890C97A6ULL,
		0x62CA5F8879882098ULL,
		0x9C8D947FC2F825CDULL,
		0x3BF215E4899F5078ULL,
		0x27AC5A60C2BC8E6EULL,
		0xAC4479878C1B8140ULL,
		0x4839606952795B51ULL,
		0x7BAD811EF1651FCCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4D8CCEF2FE78C6ULL,
		0x83FBDD27C72719B1ULL,
		0xAE4F3134576950FBULL,
		0x45003C8012C38E25ULL,
		0x70632CA6F82729DBULL,
		0x3D1EF709058F86D6ULL,
		0xB53E5E6AA17450A0ULL,
		0x2A5D5D1A85B8AA0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDA7C7BF960E1EE0ULL,
		0xDECE8260B26106E6ULL,
		0xEE3E634B6B8ED4D1ULL,
		0xF6F1D96476DBC252ULL,
		0xB7492DB9CA956492ULL,
		0x6F25827E868BFA69ULL,
		0x92FB01FEB1050AB1ULL,
		0x515024046BAC75C0ULL
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
		0x871BC5883C5C8E75ULL,
		0xC280835713BEC2EEULL,
		0x6A8B47AA29DC5E0BULL,
		0x1261410044D14684ULL,
		0x909E793AD9056098ULL,
		0x2CED18ADAC13648BULL,
		0xFBFE705FE29C7B10ULL,
		0x064D7B900BA19F20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEE5CF137F89D44AULL,
		0x9548324C0FBE149EULL,
		0xEFA27F9DEF3453E6ULL,
		0xA1B41A5094B56CBFULL,
		0x0631B201A668F2D6ULL,
		0x1862BC287C2EE0B6ULL,
		0xBEB3AB938C8A995CULL,
		0x1B483D864479E771ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD835F674BCD2BA2BULL,
		0x2D38510B0400AE4FULL,
		0x7AE8C80C3AA80A25ULL,
		0x70AD26AFB01BD9C4ULL,
		0x8A6CC739329C6DC1ULL,
		0x148A5C852FE483D5ULL,
		0x3D4AC4CC5611E1B4ULL,
		0xEB053E09C727B7AFULL
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
		0xCF8720F31C3120C8ULL,
		0xE853A871132E4CB7ULL,
		0xCE563CCD80B29360ULL,
		0x99FBE4C5DB6CFCD7ULL,
		0x97B1CF401A118EADULL,
		0xA10D4813EF2A37ABULL,
		0xBF4629AAE38F1688ULL,
		0x28785826F67122BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC824F29BCEC54A5AULL,
		0xA241FE0A5533FDA7ULL,
		0x9516A50F9E123808ULL,
		0xC1A276EA6F923803ULL,
		0x2F3B2B0CCC766722ULL,
		0x1BA9FF5D9E5D55FBULL,
		0x85E7C9EC652EE18CULL,
		0x34D819004B9DD04AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07622E574D6BD66EULL,
		0x4611AA66BDFA4F10ULL,
		0x393F97BDE2A05B58ULL,
		0xD8596DDB6BDAC4D4ULL,
		0x6876A4334D9B278AULL,
		0x856348B650CCE1B0ULL,
		0x395E5FBE7E6034FCULL,
		0xF3A03F26AAD35274ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA17C9A0801A97485ULL,
		0x18C2771BE99CB7FAULL,
		0x55CC7E5D3A84E08EULL,
		0x02844E277ED44BC4ULL,
		0x691C298B6921CC36ULL,
		0xA7010E0E181223F4ULL,
		0x6B0CDAA400D6A7E0ULL,
		0x9394C5300B172E5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1D33298678D1AE7ULL,
		0x63CD58802812EF1BULL,
		0x2001A11CDFB2B52AULL,
		0x7E06C0ECC982CA02ULL,
		0xE4668A782806815FULL,
		0xE6DC4630D165CBD8ULL,
		0xD495B4F06A568BDEULL,
		0x6FAA350C9296465FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFA9676F9A1C599EULL,
		0xB4F51E9BC189C8DEULL,
		0x35CADD405AD22B63ULL,
		0x847D8D3AB55181C2ULL,
		0x84B59F13411B4AD6ULL,
		0xC024C7DD46AC581BULL,
		0x967725B396801C01ULL,
		0x23EA90237880E7FDULL
	}};
	sign = 0;
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
		0xFD0E58045BE7D4CEULL,
		0xF2EB7AA74D96AB2EULL,
		0xA77DDA9FCCDAB65DULL,
		0x1DE3A4CD3565DF8BULL,
		0x56C203D4B029AC2DULL,
		0x64F5DA4C16668B0EULL,
		0xBCA9F83103F1BB6AULL,
		0x913B403B42FFAA47ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3415BF9C137D398FULL,
		0x09C946132D76890BULL,
		0x1B6AC5C1C609BB60ULL,
		0xC09E548C1AE92567ULL,
		0x258509E4DEB8DFE0ULL,
		0x2D969F7213DEB9EEULL,
		0xF3806B1FAF0FB085ULL,
		0x651434AE1B00C926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8F89868486A9B3FULL,
		0xE922349420202223ULL,
		0x8C1314DE06D0FAFDULL,
		0x5D4550411A7CBA24ULL,
		0x313CF9EFD170CC4CULL,
		0x375F3ADA0287D120ULL,
		0xC9298D1154E20AE5ULL,
		0x2C270B8D27FEE120ULL
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
		0xC48C469AEB0EFB28ULL,
		0xA9FB0A250EEDC9B8ULL,
		0x92A3C729EF4A819EULL,
		0x4633B0F357449C0DULL,
		0x776CE13AD539DDD3ULL,
		0x7473568FC351AFA2ULL,
		0xC14D6F815304290DULL,
		0xC3CDA53B1336330BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5A9464D4F7DFBAULL,
		0x277F1B1C8CC64876ULL,
		0x580C25FF43ED985AULL,
		0xF046C48A510C4E10ULL,
		0xA1029CE6BA2C63C5ULL,
		0x40D58144EDA5AA70ULL,
		0xC95CB54E69648084ULL,
		0xDAE399DCE5742A47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF831B23616171B6EULL,
		0x827BEF0882278141ULL,
		0x3A97A12AAB5CE944ULL,
		0x55ECEC6906384DFDULL,
		0xD66A44541B0D7A0DULL,
		0x339DD54AD5AC0531ULL,
		0xF7F0BA32E99FA889ULL,
		0xE8EA0B5E2DC208C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x31E79F6F102D428BULL,
		0xBAD571EAB22B708CULL,
		0x84CAB04C38DE3B25ULL,
		0x86A2A3B4D2B1A718ULL,
		0x1708B58C0B1EADCDULL,
		0x8E7F63706D874F95ULL,
		0x1DAF628C604513A6ULL,
		0x0766C3E7BB12C147ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B6DBA67EBF686EULL,
		0xB202D0CE1A5AE160ULL,
		0x0C3067F5C456204FULL,
		0xAB2A0A05FD3A56EBULL,
		0x97165EDDC21A9D49ULL,
		0x0C3BE4B7A92A1326ULL,
		0x9D6A728220823145ULL,
		0xAEF99B5305BB235FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC30C3C8916DDA1DULL,
		0x08D2A11C97D08F2BULL,
		0x789A485674881AD6ULL,
		0xDB7899AED577502DULL,
		0x7FF256AE49041083ULL,
		0x82437EB8C45D3C6EULL,
		0x8044F00A3FC2E261ULL,
		0x586D2894B5579DE7ULL
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
		0x06AC29FDD3043DAEULL,
		0x56B687ACA5668EA6ULL,
		0xC6C466536FE65BE2ULL,
		0x5FFCB588B04BBBF4ULL,
		0x7896D261F0A508BBULL,
		0xCA5E4D2BA1279984ULL,
		0xEDE23D4EB90591D8ULL,
		0xFCA15838E6784F98ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA505F8D681991420ULL,
		0x9FC4D2FD9AB86881ULL,
		0x78CB29AF1F08EA6EULL,
		0xAE31B8612DB438B5ULL,
		0xFB4F2DECE00E4E39ULL,
		0x6688EB50FF068AFAULL,
		0xE1E3FD868D4092D1ULL,
		0xE3BE876DBF2D8BE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61A63127516B298EULL,
		0xB6F1B4AF0AAE2624ULL,
		0x4DF93CA450DD7173ULL,
		0xB1CAFD278297833FULL,
		0x7D47A4751096BA81ULL,
		0x63D561DAA2210E89ULL,
		0x0BFE3FC82BC4FF07ULL,
		0x18E2D0CB274AC3B4ULL
	}};
	sign = 0;
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
		0x579842B4B76723B3ULL,
		0x6B12F165B5AF840EULL,
		0xEE4D58C9D9BDFB86ULL,
		0xFFB8951CC675B891ULL,
		0x26A292D38E045495ULL,
		0xE430AF8DFC918F2DULL,
		0xE4B776EAFB6C4E95ULL,
		0x7DEA97AF5E036C1BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56766D0C500C0CC9ULL,
		0x3926520E28899902ULL,
		0x5720F593F525B8ADULL,
		0x3CAB352F78D0B182ULL,
		0x78685E96B34EAAFDULL,
		0x926B7D243964BAC3ULL,
		0xD3D4955B283FAA90ULL,
		0xCE3BB95C3B496F73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0121D5A8675B16EAULL,
		0x31EC9F578D25EB0CULL,
		0x972C6335E49842D9ULL,
		0xC30D5FED4DA5070FULL,
		0xAE3A343CDAB5A998ULL,
		0x51C53269C32CD469ULL,
		0x10E2E18FD32CA405ULL,
		0xAFAEDE5322B9FCA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBF29E262F3B93689ULL,
		0x98A9EADCD4C499FEULL,
		0x370A8CEBD1D5FA3AULL,
		0xCA657054CD66C8A0ULL,
		0xED4673EA50CF1754ULL,
		0xDA31DCBC788A79C3ULL,
		0x6F6163C9AEFE195DULL,
		0x9A3B4787E1A6BA61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7132D61D96A79D38ULL,
		0x300EA11E758501BCULL,
		0xC93F1D898471D83AULL,
		0x5AC1C0F359AF2933ULL,
		0x78171A87EEA31B51ULL,
		0x196B4DD63BC39742ULL,
		0x41132DB3120C7137ULL,
		0xED15546A47DF2620ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DF70C455D119951ULL,
		0x689B49BE5F3F9842ULL,
		0x6DCB6F624D642200ULL,
		0x6FA3AF6173B79F6CULL,
		0x752F5962622BFC03ULL,
		0xC0C68EE63CC6E281ULL,
		0x2E4E36169CF1A826ULL,
		0xAD25F31D99C79441ULL
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
		0xB9F7D9BF9B2B85F5ULL,
		0xC6958FAC878D2392ULL,
		0x3F84FE6FD8D48CD8ULL,
		0x0E6F35F9967C3DAAULL,
		0xEAE65199D75C6210ULL,
		0x2FE981B759D7CA5BULL,
		0x5E237F0B7751BFD8ULL,
		0xED77F83876810538ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB0ADB1F1CCC552ULL,
		0x816430617DEBC48EULL,
		0xD18CEEA9B5702172ULL,
		0x1351C9A778605588ULL,
		0x11DEBD12088C825AULL,
		0x58CB9EF20BFA0F51ULL,
		0x509C7C3BEC337B37ULL,
		0xECF83EE62B76DBEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC472C0DA95EC0A3ULL,
		0x45315F4B09A15F03ULL,
		0x6DF80FC623646B66ULL,
		0xFB1D6C521E1BE821ULL,
		0xD9079487CECFDFB5ULL,
		0xD71DE2C54DDDBB0AULL,
		0x0D8702CF8B1E44A0ULL,
		0x007FB9524B0A294BULL
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
		0xE58E60FBD23828FCULL,
		0x7A7AC38A60F020FBULL,
		0x3E21C346B141279FULL,
		0xE0201F093EFE4E88ULL,
		0x8257451F53C1C9E5ULL,
		0xAE0F616DB68D1DC1ULL,
		0x796D0A5D50F9C4F1ULL,
		0x5059E7DA0516B839ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F380E305B4E809ULL,
		0x2BF5CEF1B62F6A2FULL,
		0xCF7096C7DB074EA6ULL,
		0x1E8C8BDD32D243D0ULL,
		0x3FE72F3A63C10C0BULL,
		0xE24A11023942F079ULL,
		0x016043FDA322BE52ULL,
		0x899DFD28FF1E1B1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F9AE018CC8340F3ULL,
		0x4E84F498AAC0B6CCULL,
		0x6EB12C7ED639D8F9ULL,
		0xC193932C0C2C0AB7ULL,
		0x427015E4F000BDDAULL,
		0xCBC5506B7D4A2D48ULL,
		0x780CC65FADD7069EULL,
		0xC6BBEAB105F89D1AULL
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
		0x89FDF24C4E16006FULL,
		0x912EA15A14E6AFBEULL,
		0x73F532C4A2914DA4ULL,
		0x893F53FC12798C9FULL,
		0x6BC7D300A40C6BFDULL,
		0xEF4FEAC47B733A10ULL,
		0x8DEFD3F4EAA1DCD3ULL,
		0x673CE2AD9037DBEEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37DC552140B0BFBAULL,
		0xF8B3AB2E2E960A3FULL,
		0x6A1EAB9F9B735B63ULL,
		0x01E236B4C2803DAFULL,
		0x6B5C60357D15E0E2ULL,
		0x9999405554C718C0ULL,
		0x81465F46370646A3ULL,
		0x5A30CDB9F6262562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52219D2B0D6540B5ULL,
		0x987AF62BE650A57FULL,
		0x09D68725071DF240ULL,
		0x875D1D474FF94EF0ULL,
		0x006B72CB26F68B1BULL,
		0x55B6AA6F26AC2150ULL,
		0x0CA974AEB39B9630ULL,
		0x0D0C14F39A11B68CULL
	}};
	sign = 0;
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
		0xEC95D464181C7B9DULL,
		0xF5A6435466CDA6E3ULL,
		0xCC7873E0FA11B2B3ULL,
		0x7B2883DD10CDCDF2ULL,
		0xBA54E3C1AEAC2BAFULL,
		0x637290EC596251E0ULL,
		0xA1AB66C881C1653DULL,
		0xBBAD48A2CACDCD4AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1742ADE65796E38FULL,
		0x7BC3B04F820A4508ULL,
		0xD2C0AAB421D569DAULL,
		0xDDBB0159C3F65929ULL,
		0xC7BDA126F10261C3ULL,
		0x699089A27AA0202EULL,
		0x747FE94AB039D26BULL,
		0x844AED19C0CEF5F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD553267DC085980EULL,
		0x79E29304E4C361DBULL,
		0xF9B7C92CD83C48D9ULL,
		0x9D6D82834CD774C8ULL,
		0xF297429ABDA9C9EBULL,
		0xF9E20749DEC231B1ULL,
		0x2D2B7D7DD18792D1ULL,
		0x37625B8909FED756ULL
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
		0x7198634C0222A9ADULL,
		0x538F7E12E9F73EE8ULL,
		0xFA99A4AAAB5AD346ULL,
		0xC8D9C456219B803BULL,
		0x59188C5D65BB1303ULL,
		0xC1FBEBFCDDCADE1CULL,
		0x56B7720F092EA419ULL,
		0xBFAE164FD7F200C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA59321F8EEA71EULL,
		0x60B9BD462CD9A9E9ULL,
		0xF8D814F7666031F8ULL,
		0xEDD2AB0793E6811DULL,
		0x22E2D4CB30DF37BAULL,
		0x522A9C8BB187211BULL,
		0x16FDBF883E009BE8ULL,
		0x1D400EE2C55C52AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F2D02A0934028FULL,
		0xF2D5C0CCBD1D94FFULL,
		0x01C18FB344FAA14DULL,
		0xDB07194E8DB4FF1EULL,
		0x3635B79234DBDB48ULL,
		0x6FD14F712C43BD01ULL,
		0x3FB9B286CB2E0831ULL,
		0xA26E076D1295AE17ULL
	}};
	sign = 0;
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
		0x4F841B6EE334C110ULL,
		0xBC6E90D3200FAC00ULL,
		0x58CDB9EDD1F86A52ULL,
		0x61037AABEBE63E1BULL,
		0x5550C74441176156ULL,
		0x37E0849844318C2BULL,
		0xDC7220A13D3C547EULL,
		0x697EEE8975AEEACDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF5E142FB6601AABULL,
		0x8724F73ECDC7C117ULL,
		0x3DD777911B117A3FULL,
		0x59108FF5168178ADULL,
		0x91A974173D55F030ULL,
		0x599BA9ACA2E1DB37ULL,
		0x9E61BDF4C03A3F36ULL,
		0x4B2976587AD60641ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5026073F2CD4A665ULL,
		0x354999945247EAE8ULL,
		0x1AF6425CB6E6F013ULL,
		0x07F2EAB6D564C56EULL,
		0xC3A7532D03C17126ULL,
		0xDE44DAEBA14FB0F3ULL,
		0x3E1062AC7D021547ULL,
		0x1E557830FAD8E48CULL
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
		0x81556F890E2658F2ULL,
		0xAEB47A96BD5F0605ULL,
		0xFA266A1689DF7F1AULL,
		0x71D79B66EF6D50A4ULL,
		0xB9551AE48050D85FULL,
		0x682601A13CD28872ULL,
		0x77F7A2224BF068B7ULL,
		0x868D7F12E2B07000ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B4091BA9D97880ULL,
		0x8567B71D5333DE8CULL,
		0xF1C439888CC4E6B3ULL,
		0x298C486A98E1DAB6ULL,
		0x35B409D71D9C2300ULL,
		0xFD57C55DEECE281CULL,
		0xC7F098AEB339236CULL,
		0xB1722EF321418801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8A1666D644CE072ULL,
		0x294CC3796A2B2778ULL,
		0x0862308DFD1A9867ULL,
		0x484B52FC568B75EEULL,
		0x83A1110D62B4B55FULL,
		0x6ACE3C434E046056ULL,
		0xB007097398B7454AULL,
		0xD51B501FC16EE7FEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC96588EBEE6CE308ULL,
		0x7DACA0CBE0A461E3ULL,
		0x0FC075C27090A296ULL,
		0x9D7AC1E731073C40ULL,
		0x5F9F6F850848CB00ULL,
		0x96E6FD6FB626AC56ULL,
		0xBD617630C3553A35ULL,
		0x6956E80AA5E7323BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4CCB2877512DC5ULL,
		0x8748EC05BB3A2D71ULL,
		0xAAD60753530FFB53ULL,
		0x072A1CAF173A17B6ULL,
		0x4779A68305A60243ULL,
		0x63D1D22AFB60CEA4ULL,
		0x1A0A04459776759CULL,
		0xDC5D90D120030DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A18BDC3771BB543ULL,
		0xF663B4C6256A3472ULL,
		0x64EA6E6F1D80A742ULL,
		0x9650A53819CD2489ULL,
		0x1825C90202A2C8BDULL,
		0x33152B44BAC5DDB2ULL,
		0xA35771EB2BDEC499ULL,
		0x8CF9573985E42476ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9DD41AE24D071FD2ULL,
		0x2F49DF4B11E2271EULL,
		0x251407264B16BA28ULL,
		0xBD2A868E27DAB99DULL,
		0xA93C8E53ACAF8CE9ULL,
		0xBAC9285BDE3657F7ULL,
		0xE427612B01D667D5ULL,
		0x95277AABAFF9EFD6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1910ACADA17705E1ULL,
		0xC9B6F1858C05772AULL,
		0xFAA928B3114A8724ULL,
		0x240FB36BC60C4F52ULL,
		0xC20F1F1C89D138F7ULL,
		0xE50475C78F1EFA88ULL,
		0x49B3E941A1814259ULL,
		0x24BCA0807F95AB8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84C36E34AB9019F1ULL,
		0x6592EDC585DCAFF4ULL,
		0x2A6ADE7339CC3303ULL,
		0x991AD32261CE6A4AULL,
		0xE72D6F3722DE53F2ULL,
		0xD5C4B2944F175D6EULL,
		0x9A7377E96055257BULL,
		0x706ADA2B30644447ULL
	}};
	sign = 0;
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
		0x0EB7784D470E6AFCULL,
		0x5C84D79A9F350B5AULL,
		0x8AB06BCCF8ABA81CULL,
		0xF377C3B534E92B00ULL,
		0x870E549CF1EA0221ULL,
		0x41AA8CE8C992AB0FULL,
		0xE1D4E4708C747A58ULL,
		0x992EC382B36C03B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x388DD23D0F592F20ULL,
		0x5990CF8B0F1A42F0ULL,
		0x8E036B9C9FBFF397ULL,
		0x10B8E3F8D1C4E8FFULL,
		0x826CED37D9B8EE73ULL,
		0xEE5A3216C6A50BAEULL,
		0x39CF0241279E26BFULL,
		0x80FD7521E2D71975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD629A61037B53BDCULL,
		0x02F4080F901AC869ULL,
		0xFCAD003058EBB485ULL,
		0xE2BEDFBC63244200ULL,
		0x04A16765183113AEULL,
		0x53505AD202ED9F61ULL,
		0xA805E22F64D65398ULL,
		0x18314E60D094EA40ULL
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
		0x6EAC5E3523C842C2ULL,
		0x57A8A2A0A9535BCDULL,
		0xE823455239596584ULL,
		0x0569A74D62140058ULL,
		0xA58F6E38BFBCDACEULL,
		0x69293B70CACB174BULL,
		0xB28557EB21D540BAULL,
		0x18108E317CF2A8C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE255279F5D79070ULL,
		0xF5F22961ECA0595AULL,
		0x5646B7C32C0298FBULL,
		0x816BFED905DF6904ULL,
		0x8B9B787C6D00CE8AULL,
		0xA739185668B8C052ULL,
		0x0562813AD47F7FCFULL,
		0x6FF7684C5C6BCC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80870BBB2DF0B252ULL,
		0x61B6793EBCB30272ULL,
		0x91DC8D8F0D56CC88ULL,
		0x83FDA8745C349754ULL,
		0x19F3F5BC52BC0C43ULL,
		0xC1F0231A621256F9ULL,
		0xAD22D6B04D55C0EAULL,
		0xA81925E52086DC6FULL
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
		0x901A4370794D30D3ULL,
		0xAAF29F4C07345680ULL,
		0x81CBE4AEA45B9C0FULL,
		0x9455E02333DF8711ULL,
		0x0C846CABC2883228ULL,
		0x9986B9FA1F4EA0ABULL,
		0xBC9704BCFD239FC5ULL,
		0xC998A39FBF50BCFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF65E69350B0BE87ULL,
		0x9F16B6469736EC1BULL,
		0x4654D74CB600E6A4ULL,
		0xED5AFF62410F8DFFULL,
		0x69E181ECFD0BC9D5ULL,
		0x84C2B548EC480F49ULL,
		0xFBF5F496E59DDAE9ULL,
		0xA8105A59FD954731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90B45CDD289C724CULL,
		0x0BDBE9056FFD6A64ULL,
		0x3B770D61EE5AB56BULL,
		0xA6FAE0C0F2CFF912ULL,
		0xA2A2EABEC57C6852ULL,
		0x14C404B133069161ULL,
		0xC0A110261785C4DCULL,
		0x21884945C1BB75CAULL
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
		0x97887FE3CB34197AULL,
		0x9A86B1BA1D24C136ULL,
		0xE527D579C9E76A53ULL,
		0x750E44B062C871F2ULL,
		0x184E778EA33FF2B9ULL,
		0xCDCCFA8AFB17387CULL,
		0x61E66D484D3C3055ULL,
		0x3A91F622C3566B67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF803DF1BB97DB8ULL,
		0x704175F488D786B6ULL,
		0xB9A1CA767CEB48D5ULL,
		0x70F496790605D1B5ULL,
		0x90A3E29443FFD5B4ULL,
		0x2024248F057EAFC0ULL,
		0x78DC5FF403D1DC33ULL,
		0xD4F5FA87334C96B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C907C04AF7A9BC2ULL,
		0x2A453BC5944D3A80ULL,
		0x2B860B034CFC217EULL,
		0x0419AE375CC2A03DULL,
		0x87AA94FA5F401D05ULL,
		0xADA8D5FBF59888BBULL,
		0xE90A0D54496A5422ULL,
		0x659BFB9B9009D4B3ULL
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
		0x2BA5D01B96ACD4F8ULL,
		0x43B1EE3DB58BD509ULL,
		0xF6FBA514C1E53B62ULL,
		0x08AC9A20EC147CC8ULL,
		0x79CDCA8C3DAD7A04ULL,
		0xCF8BF3CCFECAC6A2ULL,
		0x8FE27C0A281AAB1DULL,
		0xA7EE9F6B0E0036DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x038924AB442E39FEULL,
		0xF64C5510FA75E662ULL,
		0x14CD129AC4A576F6ULL,
		0xEE36C295598CC9F4ULL,
		0xD1158A4078B3DCAEULL,
		0x8BAC6B8E32DAD347ULL,
		0x34B82AB4221B5638ULL,
		0x8C81E62A9DD0874FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x281CAB70527E9AFAULL,
		0x4D65992CBB15EEA7ULL,
		0xE22E9279FD3FC46BULL,
		0x1A75D78B9287B2D4ULL,
		0xA8B8404BC4F99D55ULL,
		0x43DF883ECBEFF35AULL,
		0x5B2A515605FF54E5ULL,
		0x1B6CB940702FAF8CULL
	}};
	sign = 0;
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
		0xD288351185F65523ULL,
		0x1432206E799686BAULL,
		0x326A44B7A53496B2ULL,
		0xB320229415138071ULL,
		0x39C9D1F6C82BC53AULL,
		0x4DB39314F0DB600DULL,
		0x10ED9B97C92A3C17ULL,
		0x9A021455AD9168CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E642C5377133330ULL,
		0xD4574922AC777DAFULL,
		0x4518F65E1A8D73D8ULL,
		0x0B13C913BB339B2DULL,
		0x89F5A23E83726B0AULL,
		0xDB175A098EE5DFD5ULL,
		0x3F9540B3632EA1B6ULL,
		0xA5D68DB72E2F7BB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x342408BE0EE321F3ULL,
		0x3FDAD74BCD1F090BULL,
		0xED514E598AA722D9ULL,
		0xA80C598059DFE543ULL,
		0xAFD42FB844B95A30ULL,
		0x729C390B61F58037ULL,
		0xD1585AE465FB9A60ULL,
		0xF42B869E7F61ED1CULL
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
		0xBC34BBE2B45CF5A0ULL,
		0xA8F3EABF7895F50BULL,
		0x23223247FB78B2FEULL,
		0x13C40E728EB48FB9ULL,
		0x8BA3EB0657DBBD0FULL,
		0x511AEBAAA27435A1ULL,
		0x625FE0A97DA69CB9ULL,
		0x707F2DB6A013A05FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA0A98A77AE1C8BULL,
		0x7C4BB9EE9F9D7723ULL,
		0x69D73FCD98074C9EULL,
		0x45B05056494295B6ULL,
		0xC1FD0C9DB44C72ADULL,
		0x599CC4FF0156D6C3ULL,
		0xC5DA0A716D29DFE6ULL,
		0x7B6E9F429CD5D265ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E9412583CAED915ULL,
		0x2CA830D0D8F87DE8ULL,
		0xB94AF27A63716660ULL,
		0xCE13BE1C4571FA02ULL,
		0xC9A6DE68A38F4A61ULL,
		0xF77E26ABA11D5EDDULL,
		0x9C85D638107CBCD2ULL,
		0xF5108E74033DCDF9ULL
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
		0x0475BB0CD42D6CCAULL,
		0x677EEB8491D13735ULL,
		0x728498ED8D9376B8ULL,
		0x11F24024DAF8F7A2ULL,
		0xF86088DD023AE52BULL,
		0x80387BA79EFE674BULL,
		0xBF4CDEA9B6170636ULL,
		0xCAA5169BEB40B22DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB85DAF95C5A1FF1ULL,
		0x3A6E26A00B5A5B16ULL,
		0xFDE6CC3C268F86CCULL,
		0xC40E8EFB2113BD50ULL,
		0xB7D678DDD46CDF6CULL,
		0xC2A3A670B2A74CE8ULL,
		0xC357E518DAC720CFULL,
		0x2313AC3F6A16E48DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48EFE01377D34CD9ULL,
		0x2D10C4E48676DC1EULL,
		0x749DCCB16703EFECULL,
		0x4DE3B129B9E53A51ULL,
		0x408A0FFF2DCE05BEULL,
		0xBD94D536EC571A63ULL,
		0xFBF4F990DB4FE566ULL,
		0xA7916A5C8129CD9FULL
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
		0x7FC030E7CA1893BFULL,
		0xC44F64F59BB19D3DULL,
		0x7122D57447F35FA5ULL,
		0x118A582D3DB12890ULL,
		0x09F4F9B465598253ULL,
		0x298B328A0CF6359AULL,
		0xA3BB23896CB3C308ULL,
		0xE1ACEF11E02C2670ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06961BA8E7153DA6ULL,
		0x8A8CE45BBC944FC9ULL,
		0xFEB9D85A87C87866ULL,
		0xD21DD9F61D707AB8ULL,
		0x8E3866F02FE998D5ULL,
		0xAA7003B821739DDFULL,
		0x91D0D24CEFA44219ULL,
		0xA1035E75D04B54A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x792A153EE3035619ULL,
		0x39C28099DF1D4D74ULL,
		0x7268FD19C02AE73FULL,
		0x3F6C7E372040ADD7ULL,
		0x7BBC92C4356FE97DULL,
		0x7F1B2ED1EB8297BAULL,
		0x11EA513C7D0F80EEULL,
		0x40A9909C0FE0D1D0ULL
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
		0x6A07405F32EFB4D1ULL,
		0x865161AFEDAF5739ULL,
		0xAC9C9378D279C24CULL,
		0x53823E27FD3C36FDULL,
		0xE731CCE76EDEDE2DULL,
		0x8A52F591D318E5E6ULL,
		0x444D9BB24B374410ULL,
		0x8DA43F17E74D57A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD071E0938701848DULL,
		0x8FAE8AEE8E8369A2ULL,
		0x061BE9EC7BCF3A24ULL,
		0xE3B60BBA1C82F3CCULL,
		0x1DFAF172E109D606ULL,
		0xAD8CFC05E7E3D19DULL,
		0x5C3B62512DC0DDE5ULL,
		0x08D7ECFA08C893C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99955FCBABEE3044ULL,
		0xF6A2D6C15F2BED96ULL,
		0xA680A98C56AA8827ULL,
		0x6FCC326DE0B94331ULL,
		0xC936DB748DD50826ULL,
		0xDCC5F98BEB351449ULL,
		0xE81239611D76662AULL,
		0x84CC521DDE84C3D9ULL
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
		0x20E73E0A18CA9D31ULL,
		0x207F96BB5DA054FBULL,
		0xACEAF3A005E4BD1BULL,
		0xAF12FFD2FD86739BULL,
		0xE26024C832439728ULL,
		0xB9837685B58F651FULL,
		0x418A0DB975B77A82ULL,
		0x15CB4F7EC40D26ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51B1EC50ADDFCE7ULL,
		0xF2D803D656E91278ULL,
		0x69694ACA05ECEC14ULL,
		0x54ABEDAF5A212994ULL,
		0xAB151D66A640B01EULL,
		0xDFE9F7FEC3A49B82ULL,
		0xEA003C5308DFA543ULL,
		0xEB8A27BC3D36BB39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BCC1F450DECA04AULL,
		0x2DA792E506B74282ULL,
		0x4381A8D5FFF7D106ULL,
		0x5A671223A3654A07ULL,
		0x374B07618C02E70AULL,
		0xD9997E86F1EAC99DULL,
		0x5789D1666CD7D53EULL,
		0x2A4127C286D66B73ULL
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
		0x8AA1FD7B57010A2DULL,
		0x9E5FD95378DC00D8ULL,
		0x040A6DE84A21959FULL,
		0x3500AF6E9DE09699ULL,
		0x8D0A2B983230649DULL,
		0x24EF25C055C4AC53ULL,
		0x765A1557760B2D3AULL,
		0xB2D74A5E54CBA3F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD1307BC5E83009EULL,
		0xB0E5D0EBFD6CA241ULL,
		0x42CF851790D2D79AULL,
		0xF6FD24E390D3EA3EULL,
		0xC18A6F44AD0EEEAFULL,
		0x3301E2AC30DA69D9ULL,
		0xA969215C467DF150ULL,
		0x2C65AD5C1289C521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D8EF5BEF87E098FULL,
		0xED7A08677B6F5E96ULL,
		0xC13AE8D0B94EBE04ULL,
		0x3E038A8B0D0CAC5AULL,
		0xCB7FBC53852175EDULL,
		0xF1ED431424EA4279ULL,
		0xCCF0F3FB2F8D3BE9ULL,
		0x86719D024241DECEULL
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
		0x19F9B9DE6686B734ULL,
		0x3CBEFE82E7DDCAB2ULL,
		0x4B64F4B48A44156FULL,
		0x612FE4402A84A135ULL,
		0xBB8F29CB96EE387EULL,
		0xB6F9600A1124AF94ULL,
		0xE17F974175D77F2AULL,
		0x684EB072701E0218ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF292CE3557F4E2AULL,
		0x5A4BCAE60DB6C239ULL,
		0xC8EE5580001F65D8ULL,
		0x7C71A3D1793C9661ULL,
		0x833B36494C6D4CBBULL,
		0x5DD94614DB59704AULL,
		0x58BB983A694CB6DEULL,
		0x7829953CA064B4ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AD08CFB1107690AULL,
		0xE273339CDA270878ULL,
		0x82769F348A24AF96ULL,
		0xE4BE406EB1480AD3ULL,
		0x3853F3824A80EBC2ULL,
		0x592019F535CB3F4AULL,
		0x88C3FF070C8AC84CULL,
		0xF0251B35CFB94D6BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF10FFD7DC08BB3D6ULL,
		0x871A0A6EBB6F0018ULL,
		0xBD8EA30AE397B086ULL,
		0x573EFAB52BBBE00BULL,
		0xC87144B07E71F5ABULL,
		0x881522843FD34FE7ULL,
		0x3E1AD3469D5861BAULL,
		0xDAC6EF2C4B25EDFFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5532AA7A03757D3ULL,
		0xCFD1D94FD12B17BDULL,
		0xE9E1DE1CA0F18B21ULL,
		0x8C504889A6A0A41FULL,
		0x545FDD2DDECA21A0ULL,
		0xDDADBB3325A7004BULL,
		0x112E716190C29703ULL,
		0xD612929DACDDAF82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BBCD2D620545C03ULL,
		0xB748311EEA43E85BULL,
		0xD3ACC4EE42A62564ULL,
		0xCAEEB22B851B3BEBULL,
		0x741167829FA7D40AULL,
		0xAA6767511A2C4F9CULL,
		0x2CEC61E50C95CAB6ULL,
		0x04B45C8E9E483E7DULL
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
		0x8CA7517513946679ULL,
		0x842954950E485894ULL,
		0xB81AA9E4FE36CB9EULL,
		0x6C7FF58B7BE98F33ULL,
		0x38DBF1E9C95A6E3EULL,
		0x0905219665F4B00FULL,
		0xBBDF886905FA78D1ULL,
		0x18BD104E3A60C6BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE681E31EC74D62F5ULL,
		0x88E6E75F1F435F93ULL,
		0x5320BC667C75F24AULL,
		0x18C1352922A516EBULL,
		0x2B0D92E09714BF4DULL,
		0x9117899BEFAEDC1BULL,
		0xE2CB2F2DCDF2684CULL,
		0x2A9CEC4263CFFBF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6256E564C470384ULL,
		0xFB426D35EF04F900ULL,
		0x64F9ED7E81C0D953ULL,
		0x53BEC06259447848ULL,
		0x0DCE5F093245AEF1ULL,
		0x77ED97FA7645D3F4ULL,
		0xD914593B38081084ULL,
		0xEE20240BD690CAC3ULL
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
		0x03A0EF064717284CULL,
		0x2A2AA783B66703D6ULL,
		0xB5DBBD5540863A16ULL,
		0x723F8E50685A3B09ULL,
		0xF22B1402152A4BC6ULL,
		0x3371C5ED3F2537C6ULL,
		0x22FA87EEA46AF741ULL,
		0xC2A1146BF8C2BBC8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x454428A22F85D048ULL,
		0x8DF20109249E24F0ULL,
		0x46974BB8B1304167ULL,
		0xA410799039FD6132ULL,
		0x5A1BCC316EBA441BULL,
		0x4179C2A972C7ED70ULL,
		0x4AFA4027F933E8E5ULL,
		0x8EC02D19090A648DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE5CC66417915804ULL,
		0x9C38A67A91C8DEE5ULL,
		0x6F44719C8F55F8AEULL,
		0xCE2F14C02E5CD9D7ULL,
		0x980F47D0A67007AAULL,
		0xF1F80343CC5D4A56ULL,
		0xD80047C6AB370E5BULL,
		0x33E0E752EFB8573AULL
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
		0x4DC6463977565758ULL,
		0x878EEE7D2DC40BFFULL,
		0x1CE4B4ADDED03D51ULL,
		0x1267A1F067408C3AULL,
		0x69827E9C87DAD99EULL,
		0x92DA7FF90F958647ULL,
		0x9E531287F02A1D17ULL,
		0x73E21B58193D92CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D24BD12C55FBC51ULL,
		0xD2FA934CD625B8E3ULL,
		0x60ED4F0FAD97D065ULL,
		0x83129DBF80B92E62ULL,
		0x049D32A16B0AB1F9ULL,
		0xB82C18E3261F5F04ULL,
		0x9490C01743C66CD2ULL,
		0xA5496B3C1063A52FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A18926B1F69B07ULL,
		0xB4945B30579E531CULL,
		0xBBF7659E31386CEBULL,
		0x8F550430E6875DD7ULL,
		0x64E54BFB1CD027A4ULL,
		0xDAAE6715E9762743ULL,
		0x09C25270AC63B044ULL,
		0xCE98B01C08D9ED9BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC27C810368B9EA23ULL,
		0xABE0B3BA2F52EA70ULL,
		0xF104755C0EBEBE69ULL,
		0xF0E47EE19C266DA0ULL,
		0xD69FEC03D8DB1538ULL,
		0x1AA572405E0B3E90ULL,
		0xFF1B83D272F600C4ULL,
		0x90D72B535C44922AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB357D0691F91D35ULL,
		0xA9C3A7F9D10F499FULL,
		0x7F6D75100638D0DDULL,
		0x20BEC5495966836CULL,
		0xBBF704CEEAE31BD0ULL,
		0xF347CD6679886A45ULL,
		0x6B956CAFDDBFF478ULL,
		0xEB6B21E6AFA7A702ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE74703FCD6C0CCEEULL,
		0x021D0BC05E43A0D0ULL,
		0x7197004C0885ED8CULL,
		0xD025B99842BFEA34ULL,
		0x1AA8E734EDF7F968ULL,
		0x275DA4D9E482D44BULL,
		0x9386172295360C4BULL,
		0xA56C096CAC9CEB28ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD74ECDB8116DA97CULL,
		0xD200B8A511792A2BULL,
		0x3EC5046243AE7502ULL,
		0xAE32E58EF259B5A0ULL,
		0x5DF216EA9083E624ULL,
		0x36037DF1E4309E84ULL,
		0xFD6455D95AEE0EC2ULL,
		0xF8F159442D9085FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06C1FA310DF57FDULL,
		0x161C8AC608F05F92ULL,
		0xF979C3B125C30E79ULL,
		0x0BCA87749DEBFE4AULL,
		0xEF1CD9705A74D437ULL,
		0xD24DAAAF5C264028ULL,
		0xDC816D9299DC0889ULL,
		0x05EECF2315703C41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06E2AE15008E517FULL,
		0xBBE42DDF0888CA99ULL,
		0x454B40B11DEB6689ULL,
		0xA2685E1A546DB755ULL,
		0x6ED53D7A360F11EDULL,
		0x63B5D342880A5E5BULL,
		0x20E2E846C1120638ULL,
		0xF3028A21182049BBULL
	}};
	sign = 0;
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
		0x3E5C998809749126ULL,
		0xAE514C7358A97CD2ULL,
		0x7C7A123A9D26E2ECULL,
		0x89C6980E138CE533ULL,
		0xD0E082CBE913DB6FULL,
		0x9E28A31357C6EE39ULL,
		0x2E8E62CBE7F5AA03ULL,
		0xAF9719E5E373BD36ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F745F0086864B4FULL,
		0xA9C7B79F4258D66AULL,
		0x72119704EBF4842DULL,
		0x90ABBF5182425B50ULL,
		0xF50F81180733FC51ULL,
		0x1EC3D0BB097ED053ULL,
		0x33AC04404B6D9E57ULL,
		0x1708D7FD77DE6E31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EE83A8782EE45D7ULL,
		0x048994D41650A668ULL,
		0x0A687B35B1325EBFULL,
		0xF91AD8BC914A89E3ULL,
		0xDBD101B3E1DFDF1DULL,
		0x7F64D2584E481DE5ULL,
		0xFAE25E8B9C880BACULL,
		0x988E41E86B954F04ULL
	}};
	sign = 0;
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
		0x1534F4E2AD159B97ULL,
		0x13E07130422D7BC3ULL,
		0x7A51AAD9DA0E83FAULL,
		0x5964D7741594FDEFULL,
		0x42B2468AB3247A3FULL,
		0x36AF7179BD3671BEULL,
		0x2F00AB33C250CCA1ULL,
		0x4FA27C1C54A92FEDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAFD1D853B65A2BULL,
		0x376A6624D07AE6A6ULL,
		0x0399EF765B032B57ULL,
		0x7E907B20D1102834ULL,
		0xDAFEA0FD797DF81FULL,
		0x135BA76393809360ULL,
		0x0284DAF500D0F062ULL,
		0xEC05EAB91492E026ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF885230A595F416CULL,
		0xDC760B0B71B2951CULL,
		0x76B7BB637F0B58A2ULL,
		0xDAD45C534484D5BBULL,
		0x67B3A58D39A6821FULL,
		0x2353CA1629B5DE5DULL,
		0x2C7BD03EC17FDC3FULL,
		0x639C916340164FC7ULL
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
		0x8ED18AB8861A9C54ULL,
		0xBA5159357D7E9708ULL,
		0x30F60A8B4AFFF003ULL,
		0xDD610C67954EBF4DULL,
		0x691D2EF9BF3121E3ULL,
		0x815C381E7E40D881ULL,
		0x23321D995A1D64A0ULL,
		0x09F919D8BFD52CF3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x796459D34107D8E4ULL,
		0xAAD4C75FEF500B4DULL,
		0x54E824437FE11228ULL,
		0x74DE04EC592EA97FULL,
		0x2539CDF9F800C1EBULL,
		0xF404768F9F5BCA8BULL,
		0xBFB91CC3747781FBULL,
		0x017FD3B3CCD78A57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x156D30E54512C370ULL,
		0x0F7C91D58E2E8BBBULL,
		0xDC0DE647CB1EDDDBULL,
		0x6883077B3C2015CDULL,
		0x43E360FFC7305FF8ULL,
		0x8D57C18EDEE50DF6ULL,
		0x637900D5E5A5E2A4ULL,
		0x08794624F2FDA29BULL
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
		0x869BD3C7760BB638ULL,
		0xD5B3F53E12DFEA53ULL,
		0x277F844E84096C89ULL,
		0xB4DEF98B64A50E73ULL,
		0xC92A3DB89EABCA0AULL,
		0x3732064ED56524F3ULL,
		0x2F674FB5BA2C0EBFULL,
		0x430843CB48E3032EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A21B66BC34AD1DULL,
		0x8AAC5D97D181EAA7ULL,
		0xB6E064CFD5FE23DDULL,
		0x82CF686AE514BE40ULL,
		0xD4DAD5678E9AD17CULL,
		0x606812A2F9E85652ULL,
		0x9B1D431645649D36ULL,
		0x7927F582177A0AEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31F9B860B9D7091BULL,
		0x4B0797A6415DFFACULL,
		0x709F1F7EAE0B48ACULL,
		0x320F91207F905032ULL,
		0xF44F68511010F88EULL,
		0xD6C9F3ABDB7CCEA0ULL,
		0x944A0C9F74C77188ULL,
		0xC9E04E493168F843ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFA3E5F88FF96058CULL,
		0x48457FE2FB5428C7ULL,
		0x79F3FBE80A6BA05DULL,
		0x11C79CF127D79249ULL,
		0xA838ED6B6FA7B36AULL,
		0x1D6100931E06952BULL,
		0x8811F296D403F494ULL,
		0xF687C59CB7792885ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x911A743605C7E59BULL,
		0x2C64B21BE9BB03AFULL,
		0x881EDDCBCA14AD42ULL,
		0x3F97E2DB93D6EFC2ULL,
		0xD06A02DEBEC95A70ULL,
		0x686C5024752E49A7ULL,
		0xFED4D2120615B433ULL,
		0x89E9822A204741B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6923EB52F9CE1FF1ULL,
		0x1BE0CDC711992518ULL,
		0xF1D51E1C4056F31BULL,
		0xD22FBA159400A286ULL,
		0xD7CEEA8CB0DE58F9ULL,
		0xB4F4B06EA8D84B83ULL,
		0x893D2084CDEE4060ULL,
		0x6C9E43729731E6D3ULL
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
		0x76064D0928DB9828ULL,
		0x64961F07441567EAULL,
		0xDB5C2831D0AD936AULL,
		0x08B8AB601FDA7371ULL,
		0x7CD56624D3B583B2ULL,
		0xC939939FCD392C64ULL,
		0x099757AA8F205868ULL,
		0x0E47E50EED95ED89ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DF382A6433E901ULL,
		0x0EB3ED91FC067A56ULL,
		0xC1A43726B814BDD1ULL,
		0x5E91716FC4C37BDEULL,
		0xDF52F575EC1D0A47ULL,
		0x06E112BE8BC333AAULL,
		0xB2BF44946A05432DULL,
		0xB781448D6EEBE627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE2714DEC4A7AF27ULL,
		0x55E23175480EED93ULL,
		0x19B7F10B1898D599ULL,
		0xAA2739F05B16F793ULL,
		0x9D8270AEE798796AULL,
		0xC25880E14175F8B9ULL,
		0x56D81316251B153BULL,
		0x56C6A0817EAA0761ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEE7830AC774ACBB4ULL,
		0x92F89AADF11861E8ULL,
		0xF86892DF08F6CDDAULL,
		0x4767F112C6C1D8F7ULL,
		0x70107204234FF3E1ULL,
		0x44ABF2D0821269E0ULL,
		0xAFFB38EB02F02648ULL,
		0x909F5DC521381ADEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x143EE2C9FF3F06F8ULL,
		0x7C4902C882CF7203ULL,
		0x7B12C529A581CB16ULL,
		0x4CA8DC1F9F9CAD27ULL,
		0x7FDE8559526B7402ULL,
		0x25AC2B6085CCA203ULL,
		0xC6D9967A53CC07DBULL,
		0x8F8B55ACBE45B470ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA394DE2780BC4BCULL,
		0x16AF97E56E48EFE5ULL,
		0x7D55CDB5637502C4ULL,
		0xFABF14F327252BD0ULL,
		0xF031ECAAD0E47FDEULL,
		0x1EFFC76FFC45C7DCULL,
		0xE921A270AF241E6DULL,
		0x0114081862F2666DULL
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
		0xAD085E74670B2481ULL,
		0xB417DBB8FC561F33ULL,
		0x96D1753F260B6141ULL,
		0x0CF0518FBDD5248FULL,
		0xC6EA9EA124697786ULL,
		0x6019E732599B341CULL,
		0x020F80AA754102A9ULL,
		0x5B46ACC67D8C4A3FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x918B58688A1D67EEULL,
		0xD77D55969ACC595EULL,
		0xF48E0B18EE17307EULL,
		0xC670B4DE543D6B84ULL,
		0x5298721CB6B73946ULL,
		0x9E41D65D0C1A28A0ULL,
		0x34D18606B042613FULL,
		0x68A38B1732D54527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B7D060BDCEDBC93ULL,
		0xDC9A86226189C5D5ULL,
		0xA2436A2637F430C2ULL,
		0x467F9CB16997B90AULL,
		0x74522C846DB23E3FULL,
		0xC1D810D54D810B7CULL,
		0xCD3DFAA3C4FEA169ULL,
		0xF2A321AF4AB70517ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF14EC63C725AEA31ULL,
		0x97A92B4FEF7E0474ULL,
		0xFE01CB420C66FA54ULL,
		0xC8C01AFB00715628ULL,
		0xE3D895557BBD1D7FULL,
		0x3A1D1B871B3EEDC7ULL,
		0xA918DEF8A71F110EULL,
		0xF6F7281DF6E28FD7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E0629E152802BBULL,
		0x445E19F49264981EULL,
		0x0100E94FEA1610A1ULL,
		0x22034C9CA3645CC0ULL,
		0xA01DF3AD3479CF2AULL,
		0xA400FF1BFCEFFFCBULL,
		0x2EC08FCD62F8728FULL,
		0xC29DAF499BF1B274ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE6E639E5D32E776ULL,
		0x534B115B5D196C56ULL,
		0xFD00E1F22250E9B3ULL,
		0xA6BCCE5E5D0CF968ULL,
		0x43BAA1A847434E55ULL,
		0x961C1C6B1E4EEDFCULL,
		0x7A584F2B44269E7EULL,
		0x345978D45AF0DD63ULL
	}};
	sign = 0;
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
		0x366E34A6C25CC685ULL,
		0x4C46324019D05DF9ULL,
		0xB87A34F2ED1FC9F8ULL,
		0x2A7A4875E571C405ULL,
		0x1DA8C23C88BF5BA6ULL,
		0x2ECD4564B35A4A7BULL,
		0xC88969EA145693FEULL,
		0x1480B3B2F5CF6629ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x274B7D34DFD6BA4FULL,
		0x3E7F08D3CF95A49EULL,
		0xE7B8612EA85D0472ULL,
		0xFC42348DEC69071AULL,
		0x829ABF02A48F5F46ULL,
		0x9126658C535607CCULL,
		0xEAA37C4C07150862ULL,
		0x2C51E15D070E8CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F22B771E2860C36ULL,
		0x0DC7296C4A3AB95BULL,
		0xD0C1D3C444C2C586ULL,
		0x2E3813E7F908BCEAULL,
		0x9B0E0339E42FFC5FULL,
		0x9DA6DFD8600442AEULL,
		0xDDE5ED9E0D418B9BULL,
		0xE82ED255EEC0D96DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x20DBC19C3E4F0270ULL,
		0xF496C47DAC13CD2AULL,
		0x6780613B2FFBC063ULL,
		0x592168A8BF2A56BAULL,
		0x6A6015F91AA42477ULL,
		0x62C14E53D961D0D7ULL,
		0xC393E1BDAA6D3F4FULL,
		0xF92CE677A68AC487ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x004F740C64C0EA85ULL,
		0x2EA4CF086B337ADEULL,
		0xE6ACFD916A8E8969ULL,
		0x50D67602C9D822C1ULL,
		0x1ED3ECC6DED664EAULL,
		0x12B81C436D2A33E8ULL,
		0x53084BF47466722CULL,
		0x463C76C82C16A5BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x208C4D8FD98E17EBULL,
		0xC5F1F57540E0524CULL,
		0x80D363A9C56D36FAULL,
		0x084AF2A5F55233F8ULL,
		0x4B8C29323BCDBF8DULL,
		0x500932106C379CEFULL,
		0x708B95C93606CD23ULL,
		0xB2F06FAF7A741ECCULL
	}};
	sign = 0;
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
		0x1276F8C87D70A38CULL,
		0x269CE9F07741B1ABULL,
		0xC4D428E09CAECA64ULL,
		0x81877AA8951C60FFULL,
		0xA5779F94111132C1ULL,
		0x62F2EBCCC69D9D6CULL,
		0x8338F55E875CF11BULL,
		0xFD37FD26B8FCA792ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07C23F31E88B950ULL,
		0x7C3588E553BCF7F9ULL,
		0x79DCF24FD7F56B78ULL,
		0x0C0A8C8DBD85CEF4ULL,
		0xC55EEE711265CBB8ULL,
		0x26E71D6E2E066C02ULL,
		0x5F93A8E9E4ED1BDFULL,
		0x4E91600D1D60339BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51FAD4D55EE7EA3CULL,
		0xAA67610B2384B9B1ULL,
		0x4AF73690C4B95EEBULL,
		0x757CEE1AD796920BULL,
		0xE018B122FEAB6709ULL,
		0x3C0BCE5E98973169ULL,
		0x23A54C74A26FD53CULL,
		0xAEA69D199B9C73F7ULL
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
		0xAD9768C816E34863ULL,
		0x1D7B8517BF429020ULL,
		0x4886834B34F8FE64ULL,
		0xD0345DF320E7D7B5ULL,
		0x08D1C8CDB6D58009ULL,
		0x5C4594A039949C54ULL,
		0x662DA6A09F2A9AD8ULL,
		0x187BFAFDCE32703FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF5261DA54E6226FULL,
		0xC364A6AB7A89C9ABULL,
		0x9753504924444ABAULL,
		0xDBC0FA8663C62809ULL,
		0xC1C9AF7B78E3D2E3ULL,
		0xD43B80A10C5D7B4FULL,
		0x34133691520A442CULL,
		0xD6A269B71CE3AC07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE4506EDC1FD25F4ULL,
		0x5A16DE6C44B8C674ULL,
		0xB133330210B4B3A9ULL,
		0xF473636CBD21AFABULL,
		0x470819523DF1AD25ULL,
		0x880A13FF2D372104ULL,
		0x321A700F4D2056ABULL,
		0x41D99146B14EC438ULL
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
		0x578DDDD458A4488FULL,
		0xD7B804A79713BF93ULL,
		0xF27AF9EE4A64B3FFULL,
		0x2675D4E3EECB4A87ULL,
		0x3E406099A9140C03ULL,
		0x1CE2AB0CBD44EAE2ULL,
		0x6AA0E5DF637D619CULL,
		0xE2B777EA6547A7F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE65BAA8A1899668ULL,
		0x8006E5C7EBA03EDEULL,
		0xEC1E50CC03439962ULL,
		0x6941F5B45EBFF401ULL,
		0xC6B93FA7460B5839ULL,
		0x41E66A975D8A5857ULL,
		0xE4BEDD0DED59FF98ULL,
		0xE238E1C9BD5024D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9928232BB71AB227ULL,
		0x57B11EDFAB7380B4ULL,
		0x065CA92247211A9DULL,
		0xBD33DF2F900B5686ULL,
		0x778720F26308B3C9ULL,
		0xDAFC40755FBA928AULL,
		0x85E208D176236203ULL,
		0x007E9620A7F78327ULL
	}};
	sign = 0;
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
		0xA4357ED786038E3CULL,
		0x8C4EAA9E743D92DCULL,
		0xA4D6D74121564318ULL,
		0x253DBB4C0C088531ULL,
		0xB35B3E743F00B7D6ULL,
		0xD2F47F78559740B3ULL,
		0xF26F04B2B4ADF025ULL,
		0xC831ECF25E3B0A3FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF33EA314C12937ULL,
		0x9675EB7436274891ULL,
		0xF4A70F294BC980C0ULL,
		0xC0200DC7C75A569CULL,
		0x56A1631A5E348B99ULL,
		0x8EB9425275975C0CULL,
		0xEC96889843A2809DULL,
		0x0E2A7BFFE790AE10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8442403471426505ULL,
		0xF5D8BF2A3E164A4BULL,
		0xB02FC817D58CC257ULL,
		0x651DAD8444AE2E94ULL,
		0x5CB9DB59E0CC2C3CULL,
		0x443B3D25DFFFE4A7ULL,
		0x05D87C1A710B6F88ULL,
		0xBA0770F276AA5C2FULL
	}};
	sign = 0;
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
		0x8C29233005DE4A9AULL,
		0x949085A17DB66028ULL,
		0x4AF967FDC685B619ULL,
		0x90F6B034E2D5CBDCULL,
		0x6EBD972A69FD0A6CULL,
		0xBEDA4DBE379C8643ULL,
		0xFABEB1EB4BC7A414ULL,
		0x05A1306CAA4A55A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x029DC1664E83E969ULL,
		0x79B4214709582132ULL,
		0x9F94EE2D9AF5A04AULL,
		0x622034EAA784FDADULL,
		0xB7ADE43566A744E2ULL,
		0xD635791D6402008DULL,
		0xED1AC54A4CCEDB31ULL,
		0x6AB70041D53861F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x898B61C9B75A6131ULL,
		0x1ADC645A745E3EF6ULL,
		0xAB6479D02B9015CFULL,
		0x2ED67B4A3B50CE2EULL,
		0xB70FB2F50355C58AULL,
		0xE8A4D4A0D39A85B5ULL,
		0x0DA3ECA0FEF8C8E2ULL,
		0x9AEA302AD511F3ACULL
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
		0x83CE22196A0CDEC7ULL,
		0x2086A066D4F186A8ULL,
		0x98B26E0EC4A2805BULL,
		0x056A443620FCF16DULL,
		0x511D94F7EA3F15B1ULL,
		0xF5BEA7F228046918ULL,
		0x3426490391FE196CULL,
		0xBE4E9D7E2F8F4A20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x635C624A3A6DFABEULL,
		0xBF9DBE6F3288B87FULL,
		0xD56D9055C42C7927ULL,
		0xA902601185FC8CC7ULL,
		0x266C4A83E843B8E7ULL,
		0x4F98C504A37BAA6DULL,
		0x4EC9CBA9356F6CB6ULL,
		0x9759AB724E67398CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2071BFCF2F9EE409ULL,
		0x60E8E1F7A268CE29ULL,
		0xC344DDB900760733ULL,
		0x5C67E4249B0064A5ULL,
		0x2AB14A7401FB5CC9ULL,
		0xA625E2ED8488BEABULL,
		0xE55C7D5A5C8EACB6ULL,
		0x26F4F20BE1281093ULL
	}};
	sign = 0;
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
		0xBDE9E97E0B4727D8ULL,
		0x6CA97E00A7F8ECCEULL,
		0x5CD3B275CB2FC8B2ULL,
		0x7480EFE057E9CEDFULL,
		0x2DD5D98422205D59ULL,
		0x491AF300699092B9ULL,
		0xEDAD60BF26DBCDC7ULL,
		0xFD8726BA03A33BF5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA2F61FC8B0DEBBULL,
		0x5344C80713B6C0F0ULL,
		0x5C058F4E8FC21621ULL,
		0xC7B5A76948FAC3F3ULL,
		0x718409966F685A32ULL,
		0xC6AC85C11DB4C76EULL,
		0xB3742A22D466D028ULL,
		0xB2577A8CE018FED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB246F35E4296491DULL,
		0x1964B5F994422BDEULL,
		0x00CE23273B6DB291ULL,
		0xACCB48770EEF0AECULL,
		0xBC51CFEDB2B80326ULL,
		0x826E6D3F4BDBCB4AULL,
		0x3A39369C5274FD9EULL,
		0x4B2FAC2D238A3D1DULL
	}};
	sign = 0;
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
		0xE3365D9D2D7F7405ULL,
		0x3A9F7B577657FC56ULL,
		0xAC47A0B0FAB2675CULL,
		0x24C8F98030AF0606ULL,
		0x0D0E80613B667B9CULL,
		0xF4B45AAABD6615C2ULL,
		0xB4138A33C6ED2CD7ULL,
		0x090EB895A3C01B1EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC0E1EE11E24054ULL,
		0x9BE7F2BF5304B9F8ULL,
		0x19FF6C723578CF9BULL,
		0xCF058D4644493432ULL,
		0x8C1A241E35D08407ULL,
		0xD81B1C12BF10F17AULL,
		0xEED03F7B5D51087BULL,
		0x5462EE99051C2F65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85757BAF1B9D33B1ULL,
		0x9EB788982353425EULL,
		0x9248343EC53997C0ULL,
		0x55C36C39EC65D1D4ULL,
		0x80F45C430595F794ULL,
		0x1C993E97FE552447ULL,
		0xC5434AB8699C245CULL,
		0xB4ABC9FC9EA3EBB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD7E49324E2042B19ULL,
		0x319AA2792FAD4FA2ULL,
		0x54010A68E770DD46ULL,
		0xCF82896F3E47AE9BULL,
		0xC5E3786D345DE0E6ULL,
		0x43D342FE2C35A0EDULL,
		0x31AC32DD65FF525FULL,
		0xE1ECB014530CE45EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA448E3DDEB76EB39ULL,
		0xFDE423BD07BDC276ULL,
		0x28DC0C9F74EC0CA7ULL,
		0x55BA1BD96EEF387FULL,
		0x8130C819C7F8D693ULL,
		0x654C61F785D0AB0EULL,
		0x963CE7A25D833194ULL,
		0x92AA78F38C700FB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339BAF46F68D3FE0ULL,
		0x33B67EBC27EF8D2CULL,
		0x2B24FDC97284D09EULL,
		0x79C86D95CF58761CULL,
		0x44B2B0536C650A53ULL,
		0xDE86E106A664F5DFULL,
		0x9B6F4B3B087C20CAULL,
		0x4F423720C69CD4AAULL
	}};
	sign = 0;
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
		0xA2CADDF3229E0A1CULL,
		0xD3D7D472D50D0B62ULL,
		0x5F07153FDB9F5B10ULL,
		0xDFF5F85C77139DF0ULL,
		0x1452C96E8B030D5DULL,
		0xF1262800CEFC6584ULL,
		0x734A91020C63B5CDULL,
		0x9A3C666CF89C0385ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x49DC9C32886BEC7AULL,
		0x92AD6914DC6732BAULL,
		0xEE28637950746A4AULL,
		0x6B2340C84E9DDFB7ULL,
		0xF44D384DDD9E7E3FULL,
		0x169BCA0EB0F84933ULL,
		0x182210D7417D52EFULL,
		0xCC61E135079031F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58EE41C09A321DA2ULL,
		0x412A6B5DF8A5D8A8ULL,
		0x70DEB1C68B2AF0C6ULL,
		0x74D2B7942875BE38ULL,
		0x20059120AD648F1EULL,
		0xDA8A5DF21E041C50ULL,
		0x5B28802ACAE662DEULL,
		0xCDDA8537F10BD195ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x40E95EE3A3353B56ULL,
		0x2CFAAAC0F5FD790EULL,
		0x692C52E9C8FFF62DULL,
		0x60476535C1B07FEAULL,
		0x814748EBAEDE5B2BULL,
		0x018200947C8AE4F2ULL,
		0x632E7F1C10B1BBEDULL,
		0x047EF678386D144BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6E488AA89248FE6ULL,
		0xAB3BDA9717B6FDCAULL,
		0x6F67164E86753619ULL,
		0xD2020865F80DD5FCULL,
		0x9A5E461522C35826ULL,
		0xD6ECEC356303CC22ULL,
		0xA5AB7D49D13AE85FULL,
		0xDB259EE7D7A9650CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A04D6391A10AB70ULL,
		0x81BED029DE467B43ULL,
		0xF9C53C9B428AC013ULL,
		0x8E455CCFC9A2A9EDULL,
		0xE6E902D68C1B0304ULL,
		0x2A95145F198718CFULL,
		0xBD8301D23F76D38DULL,
		0x2959579060C3AF3EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA78377516044E8E9ULL,
		0xEB8756ADD69596ECULL,
		0x0319B85093414016ULL,
		0xE4404CD40111F8ECULL,
		0x3340A91E1A389C56ULL,
		0x21823AC94B97C2ABULL,
		0xA51D26D2A0EF8121ULL,
		0x4E1C1C3F80E4D2C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0939664715C49E0CULL,
		0x5062DD9DF58CF8CEULL,
		0x9746D998F5AC7E22ULL,
		0x382A162DF35644A1ULL,
		0xED4E0F4AC0FF828EULL,
		0x30B44C7C084B4B31ULL,
		0xCA2933451018A3A7ULL,
		0x51F09976FC2EEF16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E4A110A4A804ADDULL,
		0x9B24790FE1089E1EULL,
		0x6BD2DEB79D94C1F4ULL,
		0xAC1636A60DBBB44AULL,
		0x45F299D3593919C8ULL,
		0xF0CDEE4D434C7779ULL,
		0xDAF3F38D90D6DD79ULL,
		0xFC2B82C884B5E3B0ULL
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
		0x083C7D5FB51710A7ULL,
		0x030BE7576C69A621ULL,
		0x39DD4A684B6E9C03ULL,
		0x7EB4367A7C5F077CULL,
		0x1012C142767B11D4ULL,
		0x6D619ED8C9F78B04ULL,
		0x50363D8E39A76871ULL,
		0xABAF328CD660DF69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF6B47E486FD21BULL,
		0x470EF00C2E125350ULL,
		0x3C6BCE50A528C41DULL,
		0x15A24C8CCB7B9A5FULL,
		0x24B0100843C77A44ULL,
		0x1A58D4E2B44D612EULL,
		0xC59B45B89CB77DB5ULL,
		0x654CB24BEF7C3C63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A45C8E16CA73E8CULL,
		0xBBFCF74B3E5752D0ULL,
		0xFD717C17A645D7E5ULL,
		0x6911E9EDB0E36D1CULL,
		0xEB62B13A32B39790ULL,
		0x5308C9F615AA29D5ULL,
		0x8A9AF7D59CEFEABCULL,
		0x46628040E6E4A305ULL
	}};
	sign = 0;
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
		0x318F3F9F9AD0CA97ULL,
		0x6E91F5C7BB01BC65ULL,
		0xF06B24385C65DFFBULL,
		0xA4231910B402267CULL,
		0x19401B4AF45FB234ULL,
		0x20E03FFB7D6E300DULL,
		0x71868D25ACE4C6DBULL,
		0xDBCCEB44E75DC9F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D090DE2E918D7DULL,
		0xF941A46E8C04314BULL,
		0xFE3D155812E013F5ULL,
		0xF8F270CB4BE41E41ULL,
		0x32BBCF3FB4F6B8F3ULL,
		0x85D2354C972D37E7ULL,
		0x9DE0E044DBB6D83DULL,
		0x4749F8EC21CD9FDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BBEAEC16C3F3D1AULL,
		0x755051592EFD8B1AULL,
		0xF22E0EE04985CC05ULL,
		0xAB30A845681E083AULL,
		0xE6844C0B3F68F940ULL,
		0x9B0E0AAEE640F825ULL,
		0xD3A5ACE0D12DEE9DULL,
		0x9482F258C5902A10ULL
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
		0xDB49722E393CD91EULL,
		0x72FF8A46ADA9A72DULL,
		0xF04A946F512AD634ULL,
		0xADB4BA3D10A7D27CULL,
		0xB21D2FCE6BE92D02ULL,
		0x2F4FBB40AF66C621ULL,
		0xB08CAD364F97081AULL,
		0x0D2EB9DDDD779D2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9275AF03469E334ULL,
		0xAF4251CFA1933C32ULL,
		0xEB90C7F726F7B801ULL,
		0x0C2970D6561BF42CULL,
		0x44449CCA427298D8ULL,
		0xF49D9A2EB40BCBB1ULL,
		0x432F36746972F18EULL,
		0xCE11DDF032B6E2C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2222173E04D2F5EAULL,
		0xC3BD38770C166AFBULL,
		0x04B9CC782A331E32ULL,
		0xA18B4966BA8BDE50ULL,
		0x6DD893042976942AULL,
		0x3AB22111FB5AFA70ULL,
		0x6D5D76C1E624168BULL,
		0x3F1CDBEDAAC0BA64ULL
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
		0x15D7AE0FF991ED81ULL,
		0x64B9E60D7AAFCA0EULL,
		0xBE791EB7FC61783AULL,
		0x97E9552C64E1BDFDULL,
		0xF91A57BD12AAAA5CULL,
		0x552C6C676D934567ULL,
		0xDB1D08970596EA96ULL,
		0xB3A889AB51C7ECDCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC790F595B755F70ULL,
		0x0116A049757A632FULL,
		0x8AB6CD0082C797B2ULL,
		0x82607E031777E9C9ULL,
		0xC1E69E000DC0E3DCULL,
		0x537E200EE21651E1ULL,
		0x8103D5947E18CACEULL,
		0xDA1A1FCF2E87DE87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x495E9EB69E1C8E11ULL,
		0x63A345C4053566DEULL,
		0x33C251B77999E088ULL,
		0x1588D7294D69D434ULL,
		0x3733B9BD04E9C680ULL,
		0x01AE4C588B7CF386ULL,
		0x5A193302877E1FC8ULL,
		0xD98E69DC23400E55ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3225469038B4A7CCULL,
		0xD2EC3A743B1CD2FAULL,
		0x8CF677D06ECE0C66ULL,
		0x5C24E84B32102B6BULL,
		0x0CE5FF5EC7B0F986ULL,
		0x8B76975E1D5BB418ULL,
		0xDF6F74E03F544AB6ULL,
		0x9500344F1C15635AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C16387F29120CAULL,
		0x176C1314BE54342DULL,
		0x60D56EC5CA03A36DULL,
		0x22094654F6A774B3ULL,
		0x82270C54B6866B43ULL,
		0x2524197C572D854BULL,
		0x5A7813641713820CULL,
		0xB1C53179CC581E6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D63E30846238702ULL,
		0xBB80275F7CC89ECDULL,
		0x2C21090AA4CA68F9ULL,
		0x3A1BA1F63B68B6B8ULL,
		0x8ABEF30A112A8E43ULL,
		0x66527DE1C62E2ECCULL,
		0x84F7617C2840C8AAULL,
		0xE33B02D54FBD44ECULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x84E94EAD619CE162ULL,
		0xA22AF24A66A4D735ULL,
		0xEC43612DF802659EULL,
		0xAA61D7D96A661C69ULL,
		0x60438BEE5E60DA6FULL,
		0xEA33860159BCF1CFULL,
		0x72620D0C4B120500ULL,
		0xC474241C9B979066ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BE56793B11CD84ULL,
		0xB77E74EFD1C1A7FFULL,
		0x3FBFA86D2AFD5293ULL,
		0x910F1A0A19691AFFULL,
		0x068605011DCE3DCFULL,
		0x9EB7F1C75D13990AULL,
		0xF2321143D23089EAULL,
		0xE5901A61FA674D97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x022AF834268B13DEULL,
		0xEAAC7D5A94E32F36ULL,
		0xAC83B8C0CD05130AULL,
		0x1952BDCF50FD016AULL,
		0x59BD86ED40929CA0ULL,
		0x4B7B9439FCA958C5ULL,
		0x802FFBC878E17B16ULL,
		0xDEE409BAA13042CEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x60802AF2A4EFFEEBULL,
		0xDEE6BC7A400CBFC2ULL,
		0x39AB33231D7D458EULL,
		0xAC1018F9F7011102ULL,
		0x1C26926D71CF8237ULL,
		0x954EA7D1816A243CULL,
		0x5D2908F1F627D77CULL,
		0x532A63E1891700C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1C1B2EBF257940ULL,
		0xF6A6065A7F76ED80ULL,
		0x61106818041098E9ULL,
		0x501CA6E8F9D87083ULL,
		0x382851B067FB4F0EULL,
		0x3AF443E6EFA54536ULL,
		0x22AD5E5A0FBC7E53ULL,
		0x26FA4FCC2782FDE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13640FC3E5CA85ABULL,
		0xE840B61FC095D242ULL,
		0xD89ACB0B196CACA4ULL,
		0x5BF37210FD28A07EULL,
		0xE3FE40BD09D43329ULL,
		0x5A5A63EA91C4DF05ULL,
		0x3A7BAA97E66B5929ULL,
		0x2C301415619402DBULL
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
		0xD36B504E04CB9F32ULL,
		0x4617C04B05BAE674ULL,
		0x7277717429161B88ULL,
		0x88C8F08566ADE2E5ULL,
		0x933800745742F8F6ULL,
		0x5E50944D9354CD7DULL,
		0x0223C32E32567E81ULL,
		0x7C9EC61E47A90340ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4729C48FE33D8F6FULL,
		0xB5D3EA1353139C01ULL,
		0x7C2FDC4A73B3DE45ULL,
		0xB3815BB576E0941AULL,
		0x01E0BB1596C7FA96ULL,
		0x5C6024CBFCF08629ULL,
		0x0D3042E7BDB7EDC8ULL,
		0xC6AD08CA00BCDEE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C418BBE218E0FC3ULL,
		0x9043D637B2A74A73ULL,
		0xF6479529B5623D42ULL,
		0xD54794CFEFCD4ECAULL,
		0x9157455EC07AFE5FULL,
		0x01F06F8196644754ULL,
		0xF4F38046749E90B9ULL,
		0xB5F1BD5446EC2458ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBFDF1C400B9406CDULL,
		0x67115BE51DD9CAD3ULL,
		0x0AD6259AC25F7977ULL,
		0x89EAB00120C8351FULL,
		0x4EF16BC1703F223EULL,
		0x47183697042A7BF0ULL,
		0x4F21E376583AB5D2ULL,
		0x5D630897AE98EDF1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F52EEB01FC79ADULL,
		0xED0E45FE0EC12F63ULL,
		0xD56B7C9FED73B2C3ULL,
		0x1E0A7E587434CE4CULL,
		0xAE8D970AE24BEB79ULL,
		0xEA12600A4D430576ULL,
		0x90C85B072ADF7E73ULL,
		0xBA975B179A3DD406ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DE9ED5509978D20ULL,
		0x7A0315E70F189B70ULL,
		0x356AA8FAD4EBC6B3ULL,
		0x6BE031A8AC9366D2ULL,
		0xA063D4B68DF336C5ULL,
		0x5D05D68CB6E77679ULL,
		0xBE59886F2D5B375EULL,
		0xA2CBAD80145B19EAULL
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
		0xD736FCECE09AD19DULL,
		0xA3F943F383004B0EULL,
		0xDEFE9F8417CA6BC9ULL,
		0x73852C32D660D8DAULL,
		0x519F6A1EDE0BE572ULL,
		0x3B9AED803C680D5DULL,
		0x237F88312F2C0541ULL,
		0x23AE15C710D1BF68ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B01445AC9257A87ULL,
		0xDCAD057F797D1964ULL,
		0x7A7BDF129431BA44ULL,
		0x3334BFD2530FDDE3ULL,
		0x47720B2626257617ULL,
		0x6D118A289FF70F3BULL,
		0x35A5C9C7C67BBE3EULL,
		0x0B43E3CEB90D5F29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C35B89217755716ULL,
		0xC74C3E74098331AAULL,
		0x6482C0718398B184ULL,
		0x40506C608350FAF7ULL,
		0x0A2D5EF8B7E66F5BULL,
		0xCE8963579C70FE22ULL,
		0xEDD9BE6968B04702ULL,
		0x186A31F857C4603EULL
	}};
	sign = 0;
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
		0x872BC0342B298AADULL,
		0x2171AEA9D9441E0FULL,
		0x03A699523EB514BBULL,
		0x47056BB7D98592F9ULL,
		0xB9ABC075DB3FA0A2ULL,
		0x7F4762C05C66B671ULL,
		0xD2182E07D6BD26C5ULL,
		0x7E004EAD5D53731BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2900B48D9FF41389ULL,
		0xD8C2FE3292048446ULL,
		0x0F95C70458AD4856ULL,
		0x2EB7306CE467B59DULL,
		0x6EC6FD87D1E37A04ULL,
		0xD872ACFE97210FF1ULL,
		0x82325E3919DCC913ULL,
		0xD3B4832F3921E866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E2B0BA68B357724ULL,
		0x48AEB077473F99C9ULL,
		0xF410D24DE607CC64ULL,
		0x184E3B4AF51DDD5BULL,
		0x4AE4C2EE095C269EULL,
		0xA6D4B5C1C545A680ULL,
		0x4FE5CFCEBCE05DB1ULL,
		0xAA4BCB7E24318AB5ULL
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
		0xC700026A80B2E9DEULL,
		0x77A3A4D98A3AF4F3ULL,
		0x45FE7B2E87F6F2E4ULL,
		0x3B6C874D3E009B21ULL,
		0x0CC42963535502A8ULL,
		0xD6435DC982C2C745ULL,
		0x6E114B79402BF8F3ULL,
		0x000839D719ECB282ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x90450EAC9E3FE829ULL,
		0x5F58712D074141DDULL,
		0x2B16908921F5A8ABULL,
		0xADA9164E49AF6EE0ULL,
		0xDD7252947B1F7A7CULL,
		0x687B4B87886B8881ULL,
		0xEBDED96E2F44E4E7ULL,
		0xCC5F8CB28DFDEAC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36BAF3BDE27301B5ULL,
		0x184B33AC82F9B316ULL,
		0x1AE7EAA566014A39ULL,
		0x8DC370FEF4512C41ULL,
		0x2F51D6CED835882BULL,
		0x6DC81241FA573EC3ULL,
		0x8232720B10E7140CULL,
		0x33A8AD248BEEC7B9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC26A8019F0268953ULL,
		0x5F34E53A9ACAB9E6ULL,
		0xEB5F8F6D222173FBULL,
		0x309389DF2EEF0A83ULL,
		0x9453BB2B9ED2ECE6ULL,
		0xFEFD96C9C35D4FDEULL,
		0x4CDB270270E22489ULL,
		0xE12D5CAD02DB084DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F21C353B7D26BEULL,
		0x412B223AD4CC45D1ULL,
		0xE3C18356E7A2B6E6ULL,
		0xCEBA64D4E2C5CF7EULL,
		0xCDF8AF5EFABAA03DULL,
		0x9178B1E206C0A2BEULL,
		0x612466264C453534ULL,
		0x002F6E3FBD866C74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x687863E4B4A96295ULL,
		0x1E09C2FFC5FE7415ULL,
		0x079E0C163A7EBD15ULL,
		0x61D9250A4C293B05ULL,
		0xC65B0BCCA4184CA8ULL,
		0x6D84E4E7BC9CAD1FULL,
		0xEBB6C0DC249CEF55ULL,
		0xE0FDEE6D45549BD8ULL
	}};
	sign = 0;
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
		0x302E302BDCAB22EBULL,
		0xA97505D2B4D973BEULL,
		0x137B448ACEC8472EULL,
		0x9F066CE251E18ED3ULL,
		0x1EEF33A9341E808BULL,
		0xE1569AEE3F03BA85ULL,
		0xC65950F303BB880EULL,
		0x4B1C0AF6A16E91C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0640D8C5BF7B072EULL,
		0x8F1CB4329C2EAA35ULL,
		0xCD36908B57C5BF78ULL,
		0x793CF90A3471AAC6ULL,
		0xED88F1F0D27164B1ULL,
		0xFE3AB70642608354ULL,
		0x46EB97ABE0D1BF64ULL,
		0xDE2CECF5474E51ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29ED57661D301BBDULL,
		0x1A5851A018AAC989ULL,
		0x4644B3FF770287B6ULL,
		0x25C973D81D6FE40CULL,
		0x316641B861AD1BDAULL,
		0xE31BE3E7FCA33730ULL,
		0x7F6DB94722E9C8A9ULL,
		0x6CEF1E015A203FD6ULL
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
		0x826B469B25A93820ULL,
		0x591913A72D80C3B0ULL,
		0xE6C13245721285F7ULL,
		0xE38271D94C43FDD5ULL,
		0x83884E2431D836A4ULL,
		0x14D5F6CBEDF6AB7FULL,
		0x50827E2EF870D150ULL,
		0x473788F4C3F73C68ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C54A33842C8405ULL,
		0xF1C2DB287AEAD432ULL,
		0x0ED72726B7887537ULL,
		0x49819B2BBBFBBD40ULL,
		0xA5B5B9429F48ED82ULL,
		0x0AB20A3DA4AA2C7CULL,
		0x8C61FA7A4983C21FULL,
		0xC8480EE84A3849B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAA5FC67A17CB41BULL,
		0x6756387EB295EF7DULL,
		0xD7EA0B1EBA8A10BFULL,
		0x9A00D6AD90484095ULL,
		0xDDD294E1928F4922ULL,
		0x0A23EC8E494C7F02ULL,
		0xC42083B4AEED0F31ULL,
		0x7EEF7A0C79BEF2B1ULL
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
		0x4400F5147A9D01C3ULL,
		0x35AEAC283E381805ULL,
		0x7D62DD24463C6337ULL,
		0x5B56B205244F40F8ULL,
		0xFD0F40B16D5F7BF4ULL,
		0x905B293916F7D285ULL,
		0x7479AD3C0E6FBD08ULL,
		0x279B12BFD6B32F7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD9860C184965CBULL,
		0x2908255DCD515E54ULL,
		0x979D4C7899602233ULL,
		0x41433377AA9BDDD5ULL,
		0x503C6ABE2A8A57E4ULL,
		0x3426337282A425BFULL,
		0x2AD0619CAE2CA5F9ULL,
		0xE6ED5C8DBD08DD72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26276F0862539BF8ULL,
		0x0CA686CA70E6B9B1ULL,
		0xE5C590ABACDC4104ULL,
		0x1A137E8D79B36322ULL,
		0xACD2D5F342D52410ULL,
		0x5C34F5C69453ACC6ULL,
		0x49A94B9F6043170FULL,
		0x40ADB63219AA520BULL
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
		0x39F759781CB70CBFULL,
		0x38D98A4330C193A9ULL,
		0x13C68FDD0768E3AFULL,
		0x911F408AE0548CCAULL,
		0x88EE96C44941FB01ULL,
		0xDEE89E796597E9ADULL,
		0x703301DCF037DF6BULL,
		0x28870936A849D318ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF44D311F92B2AEA2ULL,
		0x3C82799C290333A6ULL,
		0xC259FAB716E03E94ULL,
		0x15889DED8545BC95ULL,
		0x343DC3F278ACA51AULL,
		0x5A06727CFBA862D8ULL,
		0x19CB58E529D6F72EULL,
		0xCBF4426DAD7F8282ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45AA28588A045E1DULL,
		0xFC5710A707BE6002ULL,
		0x516C9525F088A51AULL,
		0x7B96A29D5B0ED034ULL,
		0x54B0D2D1D09555E7ULL,
		0x84E22BFC69EF86D5ULL,
		0x5667A8F7C660E83DULL,
		0x5C92C6C8FACA5096ULL
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
		0x4E497DA0F1E75BFCULL,
		0xB9C371B55BF5C9B5ULL,
		0x10AB1B35C7D635FBULL,
		0x5373AA2FFDEDE1C7ULL,
		0xAEF8DCE0FF52A409ULL,
		0xECA5201CACC2DE92ULL,
		0x13ABB8886C5FEBA7ULL,
		0x3743D3B79C569A52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA1D11F2A5AA33BULL,
		0x00E0078C0BA87EB8ULL,
		0xD7B7D36959F4A461ULL,
		0x956F666800723F8CULL,
		0x79AC9B0768479364ULL,
		0x902E309EC85CE1E5ULL,
		0xD11187557EAC9FB6ULL,
		0x9C92221E79AC86FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1A7AC81C78CB8C1ULL,
		0xB8E36A29504D4AFCULL,
		0x38F347CC6DE1919AULL,
		0xBE0443C7FD7BA23AULL,
		0x354C41D9970B10A4ULL,
		0x5C76EF7DE465FCADULL,
		0x429A3132EDB34BF1ULL,
		0x9AB1B19922AA1357ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEE118879A7A9BA5FULL,
		0x60B93B1E2F1AA521ULL,
		0xAFF480F69254D434ULL,
		0x06725F4EB196472FULL,
		0x39DE9D6E17317F5CULL,
		0x6C66472C9BC67769ULL,
		0x19E0A537F24E4159ULL,
		0x6605B5044A2D720CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C09DB5640F93692ULL,
		0x03FE4CBADAC77D0BULL,
		0x0FCB97ABCE9EE0D1ULL,
		0xB2F7F5075F513ACDULL,
		0xB695A889D7E78CD2ULL,
		0xD286C01724C82502ULL,
		0x5E54F9F1014C7258ULL,
		0x2406038038433455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8207AD2366B083CDULL,
		0x5CBAEE6354532816ULL,
		0xA028E94AC3B5F363ULL,
		0x537A6A4752450C62ULL,
		0x8348F4E43F49F289ULL,
		0x99DF871576FE5266ULL,
		0xBB8BAB46F101CF00ULL,
		0x41FFB18411EA3DB6ULL
	}};
	sign = 0;
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
		0x9722C7E98ED58721ULL,
		0x0A6F336C91F5BE5AULL,
		0x61F6A613F4F41693ULL,
		0x3145777344F2C618ULL,
		0x75970545C36CBB2DULL,
		0x2EDEDB75CD5A778CULL,
		0x5178F3508A266D91ULL,
		0x5A9BC8662667A6EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7606726E00448AC4ULL,
		0x29CB8436C835E061ULL,
		0x8FAE32B545599CD0ULL,
		0x4255093EB6818BB2ULL,
		0xCF17B1BF53399C4BULL,
		0xBCF506A2181AF3BCULL,
		0xFCE6F50FA796348DULL,
		0x115D173B4E7433D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x211C557B8E90FC5DULL,
		0xE0A3AF35C9BFDDF9ULL,
		0xD248735EAF9A79C2ULL,
		0xEEF06E348E713A65ULL,
		0xA67F538670331EE1ULL,
		0x71E9D4D3B53F83CFULL,
		0x5491FE40E2903903ULL,
		0x493EB12AD7F37317ULL
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
		0x232852B533BA8A89ULL,
		0xBF50397E85796E4DULL,
		0xDAEEBC337F744691ULL,
		0x7394D063880F507EULL,
		0xB257E8291AB7D622ULL,
		0xFBE33A382480E370ULL,
		0xEA80E13B05506FE0ULL,
		0xFB263DB1EADE8980ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8EF53B014B455FFULL,
		0x35942C2D6F36CC0DULL,
		0x103704C4A9B777A9ULL,
		0xA387F87050891FDBULL,
		0xFE01DA7175D8F4BDULL,
		0xCCDEB82231BB7543ULL,
		0x7AAF5CB4BEEAFC8AULL,
		0xE8956A596383B373ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A38FF051F06348AULL,
		0x89BC0D511642A23FULL,
		0xCAB7B76ED5BCCEE8ULL,
		0xD00CD7F3378630A3ULL,
		0xB4560DB7A4DEE164ULL,
		0x2F048215F2C56E2CULL,
		0x6FD1848646657356ULL,
		0x1290D358875AD60DULL
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
		0x0F045A5B8ACE55BEULL,
		0xD3C07F5C30E317D9ULL,
		0xF7DB0A33138D3700ULL,
		0xC6B093B8BC9F107DULL,
		0x41D47EA6DF0899BFULL,
		0xDA854F1B48788872ULL,
		0x9B01141456DA80A7ULL,
		0xE5551CB85D065DA0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E50DCE2A203DDF0ULL,
		0xF744E46048538958ULL,
		0x1183C5CB63C0C305ULL,
		0xE34887FBCE3CC87FULL,
		0xA75165DF435E10E9ULL,
		0xF9F3F15AAB7DAA54ULL,
		0xA430106BA659493AULL,
		0x1BC4281952F264E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70B37D78E8CA77CEULL,
		0xDC7B9AFBE88F8E80ULL,
		0xE6574467AFCC73FAULL,
		0xE3680BBCEE6247FEULL,
		0x9A8318C79BAA88D5ULL,
		0xE0915DC09CFADE1DULL,
		0xF6D103A8B081376CULL,
		0xC990F49F0A13F8B9ULL
	}};
	sign = 0;
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
		0x963CE11C9A4649EFULL,
		0xC77B9B64E9B1CB10ULL,
		0x866A7B0D0CAEFD76ULL,
		0xBAAE09312A08B266ULL,
		0x7096AA57F406ED50ULL,
		0x54BFA1AC71BFDE32ULL,
		0x59078F0BC275D1F0ULL,
		0xDABE388ED8F30460ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87DD3DCCF740AC2ULL,
		0x3AB6532CAEA5A7A1ULL,
		0x41BF6B04B9F55FD3ULL,
		0x83E24E687091BED0ULL,
		0x8B985A54B379F835ULL,
		0x7600BCB62A59896EULL,
		0xF7DCCDF785230198ULL,
		0xF0AD5FCFF15DF585ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDBF0D3FCAD23F2DULL,
		0x8CC548383B0C236EULL,
		0x44AB100852B99DA3ULL,
		0x36CBBAC8B976F396ULL,
		0xE4FE5003408CF51BULL,
		0xDEBEE4F6476654C3ULL,
		0x612AC1143D52D057ULL,
		0xEA10D8BEE7950EDAULL
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
		0x3CAC2B2AE320294AULL,
		0xA224985AAECF1F83ULL,
		0x71C570E2EDA087B2ULL,
		0x9E819C83299FA59FULL,
		0x9D5B2B72D81C031EULL,
		0x4F7DC02A81939FC8ULL,
		0x47254212927DCAC3ULL,
		0x24F033A39577E87AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E0B26CBA27B215ULL,
		0x30E70DD48E9A3616ULL,
		0xC36A430BD010DE77ULL,
		0x11D596A55A759A49ULL,
		0x009EC08D7ED7C72EULL,
		0x0846E351056C569CULL,
		0x1D7009C83D4E0CF3ULL,
		0x624AA7370948DAA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BCB78BE28F87735ULL,
		0x713D8A862034E96DULL,
		0xAE5B2DD71D8FA93BULL,
		0x8CAC05DDCF2A0B55ULL,
		0x9CBC6AE559443BF0ULL,
		0x4736DCD97C27492CULL,
		0x29B5384A552FBDD0ULL,
		0xC2A58C6C8C2F0DD9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAFFC36B796D4C3B9ULL,
		0x6D6FED68B2BC93D1ULL,
		0xE9EFD077A90FC309ULL,
		0xEDE2F1CE21A0C546ULL,
		0xF9FCDDCAF888775AULL,
		0xF3DCC187386340F8ULL,
		0x38E8B124ACB0A20FULL,
		0xA0B2C55E4745C460ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C03F40968A05441ULL,
		0x72B4FD4F2BDC89F0ULL,
		0xF7277EE32698A686ULL,
		0xCF9BBAC1886D7E06ULL,
		0x7F33EEC5CC4B61E9ULL,
		0x89E804A4046A4866ULL,
		0x1A570EE6E028D0ACULL,
		0xDB14077841046E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83F842AE2E346F78ULL,
		0xFABAF01986E009E1ULL,
		0xF2C8519482771C82ULL,
		0x1E47370C9933473FULL,
		0x7AC8EF052C3D1571ULL,
		0x69F4BCE333F8F892ULL,
		0x1E91A23DCC87D163ULL,
		0xC59EBDE60641564CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4892D7FB693C72FCULL,
		0xB1CC1AD0E3BB5D4CULL,
		0x608531D4F481E8D5ULL,
		0x2B931F5269A4963DULL,
		0xE96B52FEC1986474ULL,
		0x65D5B19F91D18913ULL,
		0xF2BB4078CAB333DBULL,
		0x9BBDC4CD4C28EAB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66B6ABC3C3436B3FULL,
		0xA9E46CB421B4B1C9ULL,
		0xF03DD15450463AA1ULL,
		0x6EDA16E2E2DB304DULL,
		0x3DB2EC8FE871BDF7ULL,
		0xD2F4B0E53B80B69BULL,
		0xC36579E2D2F0A7C4ULL,
		0x18E6DF36BE445D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1DC2C37A5F907BDULL,
		0x07E7AE1CC206AB82ULL,
		0x70476080A43BAE34ULL,
		0xBCB9086F86C965EFULL,
		0xABB8666ED926A67CULL,
		0x92E100BA5650D278ULL,
		0x2F55C695F7C28C16ULL,
		0x82D6E5968DE48D79ULL
	}};
	sign = 0;
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
		0xC35D46FC71C0CE60ULL,
		0x8E4947F9D324AA38ULL,
		0xB22E8C9672BFD3A0ULL,
		0x1BADBA3DB4285C4AULL,
		0x0CC8ABF0DD8CCA50ULL,
		0x699DC24FBDE6D37FULL,
		0xC06A0F4329F5A565ULL,
		0xDDE9B76209E83848ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D468F2F6060685CULL,
		0x6E6EC8E82DC6999FULL,
		0x7087B723FC8FBE78ULL,
		0x0103B2D5076D3E4DULL,
		0xFEB6502223D1F23EULL,
		0x7D187E803CE6D677ULL,
		0x162184AE9258FBF6ULL,
		0x538F6F12771C3484ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6616B7CD11606604ULL,
		0x1FDA7F11A55E1099ULL,
		0x41A6D57276301528ULL,
		0x1AAA0768ACBB1DFDULL,
		0x0E125BCEB9BAD812ULL,
		0xEC8543CF80FFFD07ULL,
		0xAA488A94979CA96EULL,
		0x8A5A484F92CC03C4ULL
	}};
	sign = 0;
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
		0x04E1211CDDCCB3EEULL,
		0x4DF37C0FE555B04AULL,
		0xA3C49EFA1C0019D6ULL,
		0xAE6321CEAC022609ULL,
		0xB5D7B38BD0B24F1BULL,
		0x07F5396087577533ULL,
		0xEDDC8E4397B78944ULL,
		0x029264047AA7FE99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x952939EFA21DF24EULL,
		0xF7AE6480A039776FULL,
		0xFFDE4AA8D35D370BULL,
		0xD93ED8D3E89D6E92ULL,
		0xD6723F98CBDF6609ULL,
		0x92C73CDD5E807590ULL,
		0x0005FA8E284BEF75ULL,
		0x32ED42AB488C4711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FB7E72D3BAEC1A0ULL,
		0x5645178F451C38DAULL,
		0xA3E6545148A2E2CAULL,
		0xD52448FAC364B776ULL,
		0xDF6573F304D2E911ULL,
		0x752DFC8328D6FFA2ULL,
		0xEDD693B56F6B99CEULL,
		0xCFA52159321BB788ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x678D30D96920FE9CULL,
		0x9EB0D1AEED3A8C65ULL,
		0x8F4EF49B1E02ABB8ULL,
		0xE7E76E66BE2B2C4BULL,
		0xB4604598410024D8ULL,
		0x9FC602EE3552A387ULL,
		0xCD7E5037DA28DFCAULL,
		0x72D664F096B55F07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38E500BF82301E88ULL,
		0x99BF1D8B643D3D6DULL,
		0x4611ACE9144E53F1ULL,
		0xFED6E4715BE243E0ULL,
		0x4A59D9856CC259E7ULL,
		0x47BA36154A7C8585ULL,
		0x57321DE97A3FAB73ULL,
		0x0FA0F6A3713041B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EA83019E6F0E014ULL,
		0x04F1B42388FD4EF8ULL,
		0x493D47B209B457C7ULL,
		0xE91089F56248E86BULL,
		0x6A066C12D43DCAF0ULL,
		0x580BCCD8EAD61E02ULL,
		0x764C324E5FE93457ULL,
		0x63356E4D25851D52ULL
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
		0xD818A901B24B4D71ULL,
		0x80E305ABB2978E67ULL,
		0x0A138A2118804375ULL,
		0xB6D309A6480B51BEULL,
		0x5B9FDEA915B2BB4FULL,
		0x883688C52107BE6DULL,
		0x5B6134B0D69A9D4AULL,
		0x610FD594007CD4DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x271E3A3403C8C18EULL,
		0x4AF636E034941877ULL,
		0xA2E487B424F725AAULL,
		0x244C5F82F5F4150EULL,
		0x12957BAC858588C5ULL,
		0x36670847EA585B87ULL,
		0xC5393151892982B1ULL,
		0xA343DA73869E140EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0FA6ECDAE828BE3ULL,
		0x35ECCECB7E0375F0ULL,
		0x672F026CF3891DCBULL,
		0x9286AA2352173CAFULL,
		0x490A62FC902D328AULL,
		0x51CF807D36AF62E6ULL,
		0x9628035F4D711A99ULL,
		0xBDCBFB2079DEC0CBULL
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
		0xAD1EA3364FC0789FULL,
		0x9679A6625D3E102AULL,
		0xA2F82E85307ED22EULL,
		0x4DCE15973D4AA768ULL,
		0xAA193C22B1C4EB30ULL,
		0xB8C1259BC5F52AE6ULL,
		0xC27A75A52962E12FULL,
		0x7BEAE8DFAF600605ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x375043C42342FF17ULL,
		0xDD70A60C74979762ULL,
		0xC19267C4780E7076ULL,
		0x27AF55E6F391C90BULL,
		0xD5164262D34E46ABULL,
		0x22C3ED5E82E5E74CULL,
		0x7709D97078A36BBCULL,
		0x1692885705FA7CDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75CE5F722C7D7988ULL,
		0xB9090055E8A678C8ULL,
		0xE165C6C0B87061B7ULL,
		0x261EBFB049B8DE5CULL,
		0xD502F9BFDE76A485ULL,
		0x95FD383D430F4399ULL,
		0x4B709C34B0BF7573ULL,
		0x65586088A9658928ULL
	}};
	sign = 0;
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
		0x4FE14A4D9C75B197ULL,
		0x417B13B9E0057D50ULL,
		0x250EDDF18B4BB6F5ULL,
		0x5E74404AAE2FDF63ULL,
		0xA95336F7B6FE8557ULL,
		0x475D62B4D4FCC64CULL,
		0xC8CAD5C94E1010F4ULL,
		0xF047BB1F3F70643EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7187D37AEF820936ULL,
		0xCAF6BDAD8C7DAAD6ULL,
		0xB4B8B7FCF5707408ULL,
		0x060F9F8A17397A11ULL,
		0x7A564805956E51E7ULL,
		0x3B944C06828220BCULL,
		0x0FE9D23B3B44BD8BULL,
		0xD71BA459028078C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE5976D2ACF3A861ULL,
		0x7684560C5387D279ULL,
		0x705625F495DB42ECULL,
		0x5864A0C096F66551ULL,
		0x2EFCEEF221903370ULL,
		0x0BC916AE527AA590ULL,
		0xB8E1038E12CB5369ULL,
		0x192C16C63CEFEB7AULL
	}};
	sign = 0;
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
		0x3C0A71A654A3FD76ULL,
		0x80919BD97B05AA44ULL,
		0x9A1F3C4BAABE8E6AULL,
		0xE48D72162F4D4A4DULL,
		0xAD3A625495534AB1ULL,
		0xF8A3D068023232E4ULL,
		0x02003C648CB24D7FULL,
		0x984EFDC401C2C7C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F1AD8F5AB1A923ULL,
		0x3B024A61A66C1DBEULL,
		0x490E6E725909C44FULL,
		0xF9DA3700D4AD3EB7ULL,
		0x61746E0DDA11901FULL,
		0xB03657962C2A8E8AULL,
		0xC0B990D93A9724B4ULL,
		0x306CE252336CA8DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0318C416F9F25453ULL,
		0x458F5177D4998C86ULL,
		0x5110CDD951B4CA1BULL,
		0xEAB33B155AA00B96ULL,
		0x4BC5F446BB41BA91ULL,
		0x486D78D1D607A45AULL,
		0x4146AB8B521B28CBULL,
		0x67E21B71CE561EEDULL
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
		0xA92386B413FD8167ULL,
		0x972022DCE665F62CULL,
		0x6E48220E6A8899A3ULL,
		0x5E8659F87B61AD18ULL,
		0xFA017726C5ACD0BFULL,
		0xED5F84853622D51AULL,
		0x5884E7F8BF096048ULL,
		0x1E6160A5C56B0C04ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10266E530BD7AEECULL,
		0x72975C98494D48FBULL,
		0xDA7C425347095106ULL,
		0x5D826A9B6F218067ULL,
		0x58E9B464F228916BULL,
		0x7FD2C398BD2419A3ULL,
		0x1FBA5DAA70BB926FULL,
		0xFE2FF3EC7935DF57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98FD18610825D27BULL,
		0x2488C6449D18AD31ULL,
		0x93CBDFBB237F489DULL,
		0x0103EF5D0C402CB0ULL,
		0xA117C2C1D3843F54ULL,
		0x6D8CC0EC78FEBB77ULL,
		0x38CA8A4E4E4DCDD9ULL,
		0x20316CB94C352CADULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA67C90D17CAB5D6DULL,
		0x37A06516B645A485ULL,
		0x1D7D2A1F72F97F5AULL,
		0x9E9A48580141DB46ULL,
		0x129A5E84CFF0B169ULL,
		0x11097FC3060BDE95ULL,
		0xECC2DB03DE951D6AULL,
		0xFA6D91C91938C967ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14DBAE0395E1E746ULL,
		0xF7B02730012291C0ULL,
		0x4FECB0AF1CB2B2FEULL,
		0xC2955EA159992965ULL,
		0xBBC50891E5B78F4BULL,
		0x022E8FFC9F5FF355ULL,
		0x96E00BE90CB10CF0ULL,
		0xABC4FF73EB9CDB67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91A0E2CDE6C97627ULL,
		0x3FF03DE6B52312C5ULL,
		0xCD9079705646CC5BULL,
		0xDC04E9B6A7A8B1E0ULL,
		0x56D555F2EA39221DULL,
		0x0EDAEFC666ABEB3FULL,
		0x55E2CF1AD1E4107AULL,
		0x4EA892552D9BEE00ULL
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
		0x8336837F8F1A903DULL,
		0xBEC8F1934E362FD2ULL,
		0xF20CD998FBAB3396ULL,
		0x880B2450C4C03F61ULL,
		0x583452C7D1F10565ULL,
		0xA6E793D1FA2A4AE8ULL,
		0x77EAC6310B1A17D2ULL,
		0x668511A8FD7A3013ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ADBFB907204B52BULL,
		0x83A15296308F8B1CULL,
		0xAACD9437C2AD32BBULL,
		0xE95F391457818D22ULL,
		0x15364D783C342096ULL,
		0x6320F22C32E8D35FULL,
		0x362226974FFE2204ULL,
		0x0D122776CEBB2557ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x585A87EF1D15DB12ULL,
		0x3B279EFD1DA6A4B6ULL,
		0x473F456138FE00DBULL,
		0x9EABEB3C6D3EB23FULL,
		0x42FE054F95BCE4CEULL,
		0x43C6A1A5C7417789ULL,
		0x41C89F99BB1BF5CEULL,
		0x5972EA322EBF0ABCULL
	}};
	sign = 0;
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
		0x5442AD9A3A1F81A4ULL,
		0xC138053B64D32F68ULL,
		0x60B9D047C689B6BCULL,
		0x0CE077B5E4F38461ULL,
		0xDA1682E9E18D9FB1ULL,
		0xDE20568F9F6D2CF7ULL,
		0x1637320F808542E4ULL,
		0xE947B57670E8AABAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BC7BCE331B9537ULL,
		0xCE75242FC25503E0ULL,
		0xA5FA2B3BCD9CEADBULL,
		0xB7D119CDE089DFC6ULL,
		0x9B551CF7A8727E77ULL,
		0x6E266675F4098B49ULL,
		0xE81FA13C2635657CULL,
		0x7487A04CDEB231C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118631CC0703EC6DULL,
		0xF2C2E10BA27E2B88ULL,
		0xBABFA50BF8ECCBE0ULL,
		0x550F5DE80469A49AULL,
		0x3EC165F2391B2139ULL,
		0x6FF9F019AB63A1AEULL,
		0x2E1790D35A4FDD68ULL,
		0x74C01529923678F1ULL
	}};
	sign = 0;
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
		0x6A8BD0EB0C06D3C5ULL,
		0x0188E24AC30EACBAULL,
		0x8A2E8B6F75D3920EULL,
		0xC67D831D7F025165ULL,
		0x2420B44BF607200CULL,
		0x30307B4AD2743D73ULL,
		0x11BA82B450326A29ULL,
		0x4ABB7D43D7447067ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B1A2CBC677F018ULL,
		0x4DEF41E525BA22D3ULL,
		0x671923ED2747A7CDULL,
		0xBEB0D891B93871BEULL,
		0x8ED69A962FC9719EULL,
		0xA514C0112D84817FULL,
		0xA8825C566C974C65ULL,
		0x11EECBB9375DEA72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16DA2E1F458EE3ADULL,
		0xB399A0659D5489E7ULL,
		0x231567824E8BEA40ULL,
		0x07CCAA8BC5C9DFA7ULL,
		0x954A19B5C63DAE6EULL,
		0x8B1BBB39A4EFBBF3ULL,
		0x6938265DE39B1DC3ULL,
		0x38CCB18A9FE685F4ULL
	}};
	sign = 0;
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
		0xA3E8494DDD3006D4ULL,
		0x42C7B200E7717604ULL,
		0x0F2C611F97B88237ULL,
		0x67DDECCCD55963A5ULL,
		0x674DF723DC6D683FULL,
		0xFA188FAB8265F5DCULL,
		0x65D1932C00427281ULL,
		0x866FD5A13B6BADF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19665C21676C7239ULL,
		0xC414AACDAE0ABCFEULL,
		0xF02A4218909FAD8BULL,
		0x400EB465FE0E4582ULL,
		0x6870732EB06EE790ULL,
		0x9D7CE52648A0D4C0ULL,
		0xDBD848DAC704801FULL,
		0xF569DE2A9F5BBA55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A81ED2C75C3949BULL,
		0x7EB307333966B906ULL,
		0x1F021F070718D4ABULL,
		0x27CF3866D74B1E22ULL,
		0xFEDD83F52BFE80AFULL,
		0x5C9BAA8539C5211BULL,
		0x89F94A51393DF262ULL,
		0x9105F7769C0FF39AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBEA3A7FAE98E50DCULL,
		0xABCBB0A61C5540A8ULL,
		0x2E216884D51016CFULL,
		0x6EB6AF2304D97EDEULL,
		0xB01BAE8CB170EB2DULL,
		0x958DC97B51988E5CULL,
		0x31591FD9D3B6156CULL,
		0x6709D82BB493C69BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58A7C7900BDB2EEDULL,
		0x0A10C0AD869ED9A5ULL,
		0x4871770EEC8B289CULL,
		0x928B1F28C68332C2ULL,
		0x2F4CB42E40A8A345ULL,
		0x3F09664A4893A932ULL,
		0xA4B898F54EFD99ABULL,
		0xC73ED27EA1210E6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65FBE06ADDB321EFULL,
		0xA1BAEFF895B66703ULL,
		0xE5AFF175E884EE33ULL,
		0xDC2B8FFA3E564C1BULL,
		0x80CEFA5E70C847E7ULL,
		0x568463310904E52AULL,
		0x8CA086E484B87BC1ULL,
		0x9FCB05AD1372B82BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x11E06ED1293C56BDULL,
		0xAD85711B4AAEBC46ULL,
		0x4E90D0E43D9033BCULL,
		0x6636BEA9C777DAC1ULL,
		0x1D37615B715C8B73ULL,
		0x04F21039B6C99668ULL,
		0x82BABC7CAD0C3363ULL,
		0xD6EF20F703080A2EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B8F4C0FA68870EULL,
		0xF1715174BB3DD06DULL,
		0xCA5B765AF1FD49CEULL,
		0xAABA00145FEA03CDULL,
		0xD53EFAD668E84D5FULL,
		0x6FF998D79FAE8A4DULL,
		0xA382F673BBC3F58DULL,
		0x930E0C3A91CEE6E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1277A102ED3CFAFULL,
		0xBC141FA68F70EBD8ULL,
		0x84355A894B92E9EDULL,
		0xBB7CBE95678DD6F3ULL,
		0x47F8668508743E13ULL,
		0x94F87762171B0C1AULL,
		0xDF37C608F1483DD5ULL,
		0x43E114BC7139234DULL
	}};
	sign = 0;
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
		0x63B7455177ED6784ULL,
		0x76546F68739BF019ULL,
		0x715D94BB096D1300ULL,
		0x7B04A5F3C2A1BACBULL,
		0x6828D4D0F00042CCULL,
		0x85FD3ABC0198C18BULL,
		0xD43113FFE1D10725ULL,
		0xF6697D6AA14EA9EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ED54D22E280BE1AULL,
		0x401998566D9198A2ULL,
		0x0735F537C011B3BAULL,
		0x058A3D91EC8C83FBULL,
		0xC37C0EFB704BF8FFULL,
		0xA6AC167BF50A89C7ULL,
		0x5C3C9AEAC2335F80ULL,
		0xACC388EAEBE39ADFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4E1F82E956CA96AULL,
		0x363AD712060A5776ULL,
		0x6A279F83495B5F46ULL,
		0x757A6861D61536D0ULL,
		0xA4ACC5D57FB449CDULL,
		0xDF5124400C8E37C3ULL,
		0x77F479151F9DA7A4ULL,
		0x49A5F47FB56B0F10ULL
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
		0x437BE213B68CAFD3ULL,
		0x2B81684CEEB255E7ULL,
		0x58FC1353542373CFULL,
		0x47D83B769E083FA2ULL,
		0x3EF8BC133EA6FA6BULL,
		0xBB436EE89B6E3D92ULL,
		0x405D21551475EC9EULL,
		0x766DB587C1079792ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0E7F5F1C333BCEULL,
		0x9082E767A6DB6D16ULL,
		0x53DE3834C84771BEULL,
		0xFA28971F6593DE4BULL,
		0xEFDB15E231E33DEEULL,
		0xF435F0B84D6371E8ULL,
		0x60279DF6DAD883AEULL,
		0x037ADA6BBD3FDD24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x766D62B49A597405ULL,
		0x9AFE80E547D6E8D0ULL,
		0x051DDB1E8BDC0210ULL,
		0x4DAFA45738746157ULL,
		0x4F1DA6310CC3BC7CULL,
		0xC70D7E304E0ACBA9ULL,
		0xE035835E399D68EFULL,
		0x72F2DB1C03C7BA6DULL
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
		0x83D5859DB77D4EEAULL,
		0x4371D606815F089AULL,
		0x7D690F25B9DC2E1CULL,
		0xEC3C549C84CEE92EULL,
		0x61A30A5F1EA9525FULL,
		0x1A9AC8A417EC849FULL,
		0xC69F4A32690E592CULL,
		0xBD41EADA808E57B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36466C677CC37616ULL,
		0x2AF1E221D6146D7BULL,
		0x1A61CFB33DF0901BULL,
		0x7159681F17DC8FD7ULL,
		0x5985BBBC9C86CCB7ULL,
		0x9D505F6EEE092D03ULL,
		0x5E28D210F9461E7CULL,
		0x886F519EB516AFC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D8F19363AB9D8D4ULL,
		0x187FF3E4AB4A9B1FULL,
		0x63073F727BEB9E01ULL,
		0x7AE2EC7D6CF25957ULL,
		0x081D4EA2822285A8ULL,
		0x7D4A693529E3579CULL,
		0x687678216FC83AAFULL,
		0x34D2993BCB77A7EDULL
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
		0xB82D082CC4B435D2ULL,
		0xC8FF2822500A7457ULL,
		0x3AA8CCD467C83AAEULL,
		0x349DE2A983B66F96ULL,
		0x17A832F13480E949ULL,
		0x4B585288C3F4A490ULL,
		0xE6F13A388B4AF221ULL,
		0xD445A6E463973A3DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E67797DA2E877EULL,
		0xD22242B727AAA0DFULL,
		0xE5D894A82D43A184ULL,
		0x95DFA5E2D044549DULL,
		0x7C343AC7F4984F16ULL,
		0x18D2546A3597C3E4ULL,
		0xA3D7B3B4F4640FD1ULL,
		0xB1C58F0631BA1CABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3469094EA85AE54ULL,
		0xF6DCE56B285FD377ULL,
		0x54D0382C3A849929ULL,
		0x9EBE3CC6B3721AF8ULL,
		0x9B73F8293FE89A32ULL,
		0x3285FE1E8E5CE0ABULL,
		0x4319868396E6E250ULL,
		0x228017DE31DD1D92ULL
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
		0xDF94E5921B38300FULL,
		0x073ADE47E3BA1043ULL,
		0x9CF2F0596A98F97CULL,
		0xB65FC4320825F312ULL,
		0x0EE735B7F72D762EULL,
		0xF0AEA3FAEA144CDBULL,
		0x4527D5D95926E5ADULL,
		0xC601FB502B1F63E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66018C30A371B00ULL,
		0x2DD0E6D1800B5ECDULL,
		0xC406CEDD7253E6EBULL,
		0x463F8A7A5B9D66C4ULL,
		0x6A061F030B83CD5AULL,
		0x5BB24EEBDD65A262ULL,
		0x1512D235C44CE684ULL,
		0xCBBA7F5B1833D530ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE934CCCF1101150FULL,
		0xD969F77663AEB175ULL,
		0xD8EC217BF8451290ULL,
		0x702039B7AC888C4DULL,
		0xA4E116B4EBA9A8D4ULL,
		0x94FC550F0CAEAA78ULL,
		0x301503A394D9FF29ULL,
		0xFA477BF512EB8EB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC161DD2CAA9C0534ULL,
		0xC5A23AF3EFBACDE7ULL,
		0x4F037B7FD09DFC3DULL,
		0xA825112EF7CF7BADULL,
		0x31594E99821EE0C5ULL,
		0x976ED51A0CC42395ULL,
		0xCC44CD4ADD6A3CC3ULL,
		0x07CAB234626BC073ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD9BD4F57BF4A3BULL,
		0x1CAC11DBDAA9E973ULL,
		0xF405A3C75735BFB1ULL,
		0xBF156C20C2EE6239ULL,
		0x9CC1B7A163DA5A52ULL,
		0x2E66B3AB985E8493ULL,
		0x6C745C13DE104AAAULL,
		0x2876A8644A77B40CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35881FDD52DCBAF9ULL,
		0xA8F629181510E474ULL,
		0x5AFDD7B879683C8CULL,
		0xE90FA50E34E11973ULL,
		0x949796F81E448672ULL,
		0x6908216E74659F01ULL,
		0x5FD07136FF59F219ULL,
		0xDF5409D017F40C67ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4A37E35A4390F364ULL,
		0x28A7A235832B970EULL,
		0x3FDD060048CA37F4ULL,
		0x049AAA0148951A11ULL,
		0x7023CA0CB022EB4AULL,
		0x85983D31F6DE0FA5ULL,
		0x63D3C53768F955E6ULL,
		0x650693425D92A569ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4FAD5CEA0A5B9AFULL,
		0x83581617C3CF5E3EULL,
		0xDE8818A065301F4FULL,
		0xB2DEB2034CE04556ULL,
		0x068D563D77D69830ULL,
		0x0C59A59ADB8C6B16ULL,
		0x5D962F16ED864805ULL,
		0xCB4F22E56E8640A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x653D0D8BA2EB39B5ULL,
		0xA54F8C1DBF5C38CFULL,
		0x6154ED5FE39A18A4ULL,
		0x51BBF7FDFBB4D4BAULL,
		0x699673CF384C5319ULL,
		0x793E97971B51A48FULL,
		0x063D96207B730DE1ULL,
		0x99B7705CEF0C64C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x269841844114BD5CULL,
		0x622A7104AD62E753ULL,
		0x01695760A484D36BULL,
		0xDF66C7600D2BB81CULL,
		0x2F645BFE0F88DF0EULL,
		0x07150DBEAF35DFC2ULL,
		0x29A16C708422C280ULL,
		0x329B0E8F0FD2C71BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5342A1C4994E2EE3ULL,
		0x6A521E8D666B5A2AULL,
		0x94AEBF7AF2C84E7EULL,
		0x8732D5A37B23D558ULL,
		0x34AE67E54B96C6F1ULL,
		0x8F9DAA7CD00B6D95ULL,
		0x52B20E428753438DULL,
		0x12758366C46368AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3559FBFA7C68E79ULL,
		0xF7D8527746F78D28ULL,
		0x6CBA97E5B1BC84ECULL,
		0x5833F1BC9207E2C3ULL,
		0xFAB5F418C3F2181DULL,
		0x77776341DF2A722CULL,
		0xD6EF5E2DFCCF7EF2ULL,
		0x20258B284B6F5E70ULL
	}};
	sign = 0;
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
		0x1CE5F9377E57D749ULL,
		0x6A100B7F9B25A27DULL,
		0x7A898D5955A5042BULL,
		0xECF2E029500C8CEEULL,
		0x07204D202ABCD007ULL,
		0x2D7E3220761EC068ULL,
		0x2689407F67AEDAC0ULL,
		0xAB495A6F0CA567C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF896364D98646F23ULL,
		0xFE3D955C12441073ULL,
		0x26901599CB265108ULL,
		0x7D8D4F2C3BD4F7C0ULL,
		0x260F07A12A7C5147ULL,
		0xBA22C22C84224588ULL,
		0xFCF41E2369227A01ULL,
		0x07374BBF8361BF3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x244FC2E9E5F36826ULL,
		0x6BD2762388E19209ULL,
		0x53F977BF8A7EB322ULL,
		0x6F6590FD1437952EULL,
		0xE111457F00407EC0ULL,
		0x735B6FF3F1FC7ADFULL,
		0x2995225BFE8C60BEULL,
		0xA4120EAF8943A889ULL
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
		0xCF8735697899B8D1ULL,
		0x19FD6F30EB712988ULL,
		0x5DCE9C893D233CB9ULL,
		0x6A70EA82012549D5ULL,
		0xC236936310B49348ULL,
		0x74C242468E9CC743ULL,
		0x2AEBFDCFA6FC2018ULL,
		0xE56491F3568A14D0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1174871D658AF99ULL,
		0x6F9791100B82CA10ULL,
		0xFD1470869B9AD480ULL,
		0xDD82113A06214277ULL,
		0x18CE896A4B2A5D70ULL,
		0x578AA3CCB1B79955ULL,
		0xFC44B1A8F4AB6A83ULL,
		0xE0EDE1B4AF0D04B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE6FECF7A2410938ULL,
		0xAA65DE20DFEE5F77ULL,
		0x60BA2C02A1886838ULL,
		0x8CEED947FB04075DULL,
		0xA96809F8C58A35D7ULL,
		0x1D379E79DCE52DEEULL,
		0x2EA74C26B250B595ULL,
		0x0476B03EA77D1018ULL
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
		0xD82A202251055296ULL,
		0x151B70131BBA76E3ULL,
		0x477E4EECFD2F6085ULL,
		0xB5DA19740E42F6C9ULL,
		0x057A4B2B9627E8BFULL,
		0x67D925FBE22FEEB4ULL,
		0x2D306F5A16DB5F44ULL,
		0x4D73F749D310F995ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51CC89D375F1801ULL,
		0xD8F0C4EB989DE025ULL,
		0x00696C60605AEEDEULL,
		0xD0517072526BAA7FULL,
		0x90DD458FB90C36D9ULL,
		0xE507489806A3B354ULL,
		0xBE751BC9A80F28BBULL,
		0xD9E84FFC6A2A70FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x130D578519A63A95ULL,
		0x3C2AAB27831C96BEULL,
		0x4714E28C9CD471A6ULL,
		0xE588A901BBD74C4AULL,
		0x749D059BDD1BB1E5ULL,
		0x82D1DD63DB8C3B5FULL,
		0x6EBB53906ECC3688ULL,
		0x738BA74D68E68895ULL
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
		0xBD950CF2697CC94EULL,
		0x180A2DCC2AF483DAULL,
		0x38DBC655E79DF9C8ULL,
		0x18D43262041087B6ULL,
		0xD63F331D97CB08F6ULL,
		0xE0F8C293B92D6BAAULL,
		0x561DE490B8F6D588ULL,
		0x74C44819D52538B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA832E9B581210FA6ULL,
		0x67DCF4F36F9497BFULL,
		0x1FA3D0C755EC9CA7ULL,
		0x0B172819DD1DC98EULL,
		0x014A38B8DE650516ULL,
		0x326D0464ACD9CEE3ULL,
		0x09175C51665830B8ULL,
		0xA48ED9B1F98FB8BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1562233CE85BB9A8ULL,
		0xB02D38D8BB5FEC1BULL,
		0x1937F58E91B15D20ULL,
		0x0DBD0A4826F2BE28ULL,
		0xD4F4FA64B96603E0ULL,
		0xAE8BBE2F0C539CC7ULL,
		0x4D06883F529EA4D0ULL,
		0xD0356E67DB957FFBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9128A76B34402E85ULL,
		0x7DAE74D398E3339AULL,
		0x52FEB3E8387EE80DULL,
		0x261C1A64330AB02DULL,
		0xC3B2800E0C8D7A7AULL,
		0xB1F11B5EDB7F7ACEULL,
		0x422A94231D88ACC6ULL,
		0x47695FE9F49A1214ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F665ABAEE11C8F8ULL,
		0x1EE2909E5C7DAD26ULL,
		0x3B7E790D336555C0ULL,
		0x8C5F1828350E51CCULL,
		0xB20CF44A140D6B1DULL,
		0xA7643A9324346221ULL,
		0x20E0A568264CC5DBULL,
		0xAF026F38673622D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81C24CB0462E658DULL,
		0x5ECBE4353C658674ULL,
		0x17803ADB0519924DULL,
		0x99BD023BFDFC5E61ULL,
		0x11A58BC3F8800F5CULL,
		0x0A8CE0CBB74B18ADULL,
		0x2149EEBAF73BE6EBULL,
		0x9866F0B18D63EF3EULL
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
		0x07E15AE4A3390253ULL,
		0x878A39420B9998F1ULL,
		0x06BD492AE27B18AAULL,
		0xB7F8DAAB6B69D18DULL,
		0x96FAE74B8BA07566ULL,
		0x8C4D16BF2F729A80ULL,
		0x968FD238D2D21491ULL,
		0x5AB85C4BA33A3ED8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B568737A1031D93ULL,
		0x09689D2B83D738EFULL,
		0xC026B8E55B073935ULL,
		0x30DCF6F8CF99928EULL,
		0xE72D4D14C06DD8B5ULL,
		0x54D6DF7AF4076681ULL,
		0xE135C61745AA7BD1ULL,
		0x2FD644C4BE092D4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8AD3AD0235E4C0ULL,
		0x7E219C1687C26001ULL,
		0x469690458773DF75ULL,
		0x871BE3B29BD03EFEULL,
		0xAFCD9A36CB329CB1ULL,
		0x377637443B6B33FEULL,
		0xB55A0C218D2798C0ULL,
		0x2AE21786E531118DULL
	}};
	sign = 0;
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
		0x2AAB2ABE5C9D4B0EULL,
		0xE146104099CA92FBULL,
		0x5DF02796417A7377ULL,
		0xBF6753D7A95DB2B8ULL,
		0xEF44B6355F7549BDULL,
		0xB6046019EDF587B6ULL,
		0x11C467429AA206C0ULL,
		0x79D752AC0D5011B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A98A2237CDC267ULL,
		0x1F678966CC8583BBULL,
		0x1E323A9B3B3467ADULL,
		0x89CD229F8D84C937ULL,
		0x41961763B904F726ULL,
		0x8AED568D2AF47AD8ULL,
		0x20672ACE3ED24B72ULL,
		0x19C721D9F752CF55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD401A09C24CF88A7ULL,
		0xC1DE86D9CD450F3FULL,
		0x3FBDECFB06460BCAULL,
		0x359A31381BD8E981ULL,
		0xADAE9ED1A6705297ULL,
		0x2B17098CC3010CDEULL,
		0xF15D3C745BCFBB4EULL,
		0x601030D215FD4260ULL
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
		0xD65C88DF87E676E7ULL,
		0xBD9EE6655633752EULL,
		0x75F7C6725489DB4EULL,
		0x085401A22AECAD1CULL,
		0x51EFB23AAB692CB0ULL,
		0x87078418B846B6FAULL,
		0x57C6D22C92D1C901ULL,
		0xD0B37B2CF68EA32AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0942EB94D668FE0ULL,
		0xDE6BE59DF2BD3506ULL,
		0x90E9CB834D1236DEULL,
		0x3919774810535706ULL,
		0xC30A61C997FA17A2ULL,
		0x9BE66B7357CC2F9FULL,
		0x5AE53D6289918EE2ULL,
		0x451F05C5415BC70DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5C85A263A7FE707ULL,
		0xDF3300C763764027ULL,
		0xE50DFAEF0777A46FULL,
		0xCF3A8A5A1A995615ULL,
		0x8EE55071136F150DULL,
		0xEB2118A5607A875AULL,
		0xFCE194CA09403A1EULL,
		0x8B947567B532DC1CULL
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
		0x51840651E7C23F74ULL,
		0x709568DC772DDB76ULL,
		0x1ACB461E7251AFC9ULL,
		0x28D49DF2071FAB1FULL,
		0x6E1FC7DD98C84CD0ULL,
		0x1D6F6B9E745219E9ULL,
		0x96BCAE9004A2847DULL,
		0x0BC7A2D3BC68B244ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58B2EB5FFFD60D8ULL,
		0xAC88B6817314BC3EULL,
		0x47C5BBF1493BB759ULL,
		0xD3BF201B301510ADULL,
		0xAC32F3116223497AULL,
		0x2D20ACB37528DF8FULL,
		0x6B75E3B974084377ULL,
		0xC9E8FDEB62DE8D4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABF8D79BE7C4DE9CULL,
		0xC40CB25B04191F37ULL,
		0xD3058A2D2915F86FULL,
		0x55157DD6D70A9A71ULL,
		0xC1ECD4CC36A50355ULL,
		0xF04EBEEAFF293A59ULL,
		0x2B46CAD6909A4105ULL,
		0x41DEA4E8598A24F7ULL
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
		0xD1A50DA37B69A15FULL,
		0x2CD9E037F9F5DA16ULL,
		0x7C377240017EF8B7ULL,
		0x52C26E7BF4FD03D9ULL,
		0x5F8D6C871A1021AEULL,
		0x3B6F3BCBF540542EULL,
		0x0C405B2EE28544C2ULL,
		0xD77C82FBC5C6758DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1798F360C7105032ULL,
		0x20B74CFEC7390DF1ULL,
		0xD644E12EEB153399ULL,
		0xD0CEDD030BE55EA0ULL,
		0x80560A24712B44BCULL,
		0xE97F7245F9365D6EULL,
		0x8AAAFD00D38F4815ULL,
		0x8FA346D47F9BD68BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA0C1A42B459512DULL,
		0x0C22933932BCCC25ULL,
		0xA5F291111669C51EULL,
		0x81F39178E917A538ULL,
		0xDF376262A8E4DCF1ULL,
		0x51EFC985FC09F6BFULL,
		0x81955E2E0EF5FCACULL,
		0x47D93C27462A9F01ULL
	}};
	sign = 0;
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
		0x8F08E07F30BA9CE6ULL,
		0x945BC711B15FC9CCULL,
		0x237D5889CD66338EULL,
		0x9E27129869B5CCE6ULL,
		0xF329F73A8E7AE943ULL,
		0xE49AD428ED7ADBCDULL,
		0x59733C27B72F2774ULL,
		0x2406E04DA8F3ED09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F66915A04DFCD34ULL,
		0x0BDF077587CF102FULL,
		0xE3980432774AEFCBULL,
		0xE4F4673A7F66E84FULL,
		0x9AB0A4418AE5431DULL,
		0x3076EFCB7FF75CE3ULL,
		0xB566F4FA9BC164F3ULL,
		0x8EE4E614DB0430D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA24F252BDACFB2ULL,
		0x887CBF9C2990B99DULL,
		0x3FE55457561B43C3ULL,
		0xB932AB5DEA4EE496ULL,
		0x587952F90395A625ULL,
		0xB423E45D6D837EEAULL,
		0xA40C472D1B6DC281ULL,
		0x9521FA38CDEFBC37ULL
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
		0xEE536A9CB1083FA1ULL,
		0x4F1513817624138FULL,
		0xA7CB1B8BABAC3AACULL,
		0x6603AD60360D5FE6ULL,
		0x000683BDA760784AULL,
		0x45542DBBE0D88201ULL,
		0xBCDBD3E7AD32256EULL,
		0xD9AEC8795547FF06ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x751F0C8314564262ULL,
		0x90F32B2D94E99A7EULL,
		0xF25F7B5F0044714DULL,
		0x0D46542E37915E92ULL,
		0xDCDB520FC72C15F4ULL,
		0x2B6C5A64E6C3DFAEULL,
		0x560E53714870456CULL,
		0xFCCF49EF42749FAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79345E199CB1FD3FULL,
		0xBE21E853E13A7911ULL,
		0xB56BA02CAB67C95EULL,
		0x58BD5931FE7C0153ULL,
		0x232B31ADE0346256ULL,
		0x19E7D356FA14A252ULL,
		0x66CD807664C1E002ULL,
		0xDCDF7E8A12D35F57ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x57384BFF75F500A6ULL,
		0xCCFB60B53CB74EB4ULL,
		0x2AC9F8C9BCA06780ULL,
		0xF558231D2A3EC5DFULL,
		0xC965A20CFD0061D7ULL,
		0x28BD7E6E9690B919ULL,
		0x847A49913A700692ULL,
		0x46B06CB13DF89FBFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x44A900D99C34EDF9ULL,
		0x4BEB858ABACE2949ULL,
		0xB546E41291B63370ULL,
		0x1D03F79C1B2179B0ULL,
		0x052B088F4ACC5F80ULL,
		0xB605712E967EA605ULL,
		0xE748E57B08DC6B80ULL,
		0x1849C24872C707F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128F4B25D9C012ADULL,
		0x810FDB2A81E9256BULL,
		0x758314B72AEA3410ULL,
		0xD8542B810F1D4C2EULL,
		0xC43A997DB2340257ULL,
		0x72B80D4000121314ULL,
		0x9D31641631939B11ULL,
		0x2E66AA68CB3197CEULL
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
		0x7DCC97EBA8B22231ULL,
		0xF4D05C43A5E9A361ULL,
		0xA67DC208C5A617DCULL,
		0x3176923F5FC2FB22ULL,
		0x534011673392AE04ULL,
		0xF7A2A84D1BF50420ULL,
		0x9B158EB263920A3FULL,
		0xEA19C6346626340BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E549451D8910AEAULL,
		0x737BEBBF432B8BFEULL,
		0x71D238E9B1400627ULL,
		0xD855A8CF3B982619ULL,
		0x01CC26DE92A9682FULL,
		0x4FD547ACE9E5885DULL,
		0xC5063FAE72F9367BULL,
		0x2F68B20F6105EE32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F780399D0211747ULL,
		0x8154708462BE1763ULL,
		0x34AB891F146611B5ULL,
		0x5920E970242AD509ULL,
		0x5173EA88A0E945D4ULL,
		0xA7CD60A0320F7BC3ULL,
		0xD60F4F03F098D3C4ULL,
		0xBAB11425052045D8ULL
	}};
	sign = 0;
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
		0xD33FD7B1CAA15D04ULL,
		0x5EF2A39856A0C30EULL,
		0x8DF70ECF8399C4B2ULL,
		0x7005C226443A5268ULL,
		0x0DC82FD5D0A5B9C1ULL,
		0x89531D684CAA2000ULL,
		0x48C33FD4A1285D0FULL,
		0xE8E6C833441E9915ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3091428EF81E9640ULL,
		0xF11831185DC42576ULL,
		0x4EA0417CA6BD438CULL,
		0x7AE5A41EAB666E99ULL,
		0xA9900A004EF65600ULL,
		0x74148EA9AF7FB237ULL,
		0xCA2C78C2D44B84DBULL,
		0x1503AC7CA056246CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2AE9522D282C6C4ULL,
		0x6DDA727FF8DC9D98ULL,
		0x3F56CD52DCDC8125ULL,
		0xF5201E0798D3E3CFULL,
		0x643825D581AF63C0ULL,
		0x153E8EBE9D2A6DC8ULL,
		0x7E96C711CCDCD834ULL,
		0xD3E31BB6A3C874A8ULL
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
		0xF939D0CFCDEAC13FULL,
		0x486321BFC95CE543ULL,
		0x832EF730FDA0DB7EULL,
		0x10098247C16054E2ULL,
		0xA3D1B0656A3EED0FULL,
		0xE4CA7AB4D7F74BDCULL,
		0x342E10D4FFD98B05ULL,
		0x5D1E9932B0F0EC82ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF896EE358841CACULL,
		0xD56ABA5952574E7AULL,
		0xF5F5D482435B05F3ULL,
		0xE401B5EC0F3423FCULL,
		0x914A1655A0E0CDF6ULL,
		0xD1A6B0206FF9C1EBULL,
		0x5C6D098F37BAC6F2ULL,
		0x3C2749B3852657DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09B061EC7566A493ULL,
		0x72F86766770596C9ULL,
		0x8D3922AEBA45D58AULL,
		0x2C07CC5BB22C30E5ULL,
		0x12879A0FC95E1F18ULL,
		0x1323CA9467FD89F1ULL,
		0xD7C10745C81EC413ULL,
		0x20F74F7F2BCA94A7ULL
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
		0x1CB7E939231997CFULL,
		0x7A38B4BDA413D907ULL,
		0xF5E49C8A522927AEULL,
		0xE0794BAB0DD6AD87ULL,
		0x6C3B83B5025BDAD3ULL,
		0xB5F4F115ACD85C3EULL,
		0xCAE4FF59D5378C98ULL,
		0x3132F66FC792BA27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9524EFB849CFE1F7ULL,
		0x40BF441DB9DC0D17ULL,
		0x4A9C4D7E02719ACCULL,
		0xF1EA4587D8FE86BFULL,
		0x86B644A6EB0E8B92ULL,
		0xBB3037B674764944ULL,
		0x9691B2B3D98D82F6ULL,
		0x96FF83A34A4372E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8792F980D949B5D8ULL,
		0x3979709FEA37CBEFULL,
		0xAB484F0C4FB78CE2ULL,
		0xEE8F062334D826C8ULL,
		0xE5853F0E174D4F40ULL,
		0xFAC4B95F386212F9ULL,
		0x34534CA5FBAA09A1ULL,
		0x9A3372CC7D4F473EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC2469719AF4877E4ULL,
		0xE490B49BA256AF98ULL,
		0x85C0CD2AEF590688ULL,
		0x2C22038DA4E0338DULL,
		0x6E03BD49938E6DF4ULL,
		0xA7B6416E93F24174ULL,
		0xF952DC861BD57A4BULL,
		0xC078FE2820158877ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6360A04699BDA13FULL,
		0xC64B9EF28165CD52ULL,
		0xDD1D5AC86AE75501ULL,
		0x17ABC4D2206131C9ULL,
		0xA55A16004D30C59AULL,
		0xFC205809AD6F4EB7ULL,
		0xE018D617548329ECULL,
		0xC6550F9C860FA794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EE5F6D3158AD6A5ULL,
		0x1E4515A920F0E246ULL,
		0xA8A372628471B187ULL,
		0x14763EBB847F01C3ULL,
		0xC8A9A749465DA85AULL,
		0xAB95E964E682F2BCULL,
		0x193A066EC752505EULL,
		0xFA23EE8B9A05E0E3ULL
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
		0xA9588A602A0A4C10ULL,
		0xB95FCB3C75FF06BBULL,
		0xA392C11C14CAD672ULL,
		0x4359C67AAC7A9C49ULL,
		0x096BF6CCF87F1760ULL,
		0xE43A082E6B365C6BULL,
		0x1BDE0488EC1B9843ULL,
		0x6686254F4FA97FD6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98B57B9805A251FULL,
		0xEBF9C5650658AAC3ULL,
		0x4F04F1E76A603908ULL,
		0xCD8B15481F4BA996ULL,
		0x04F55CC5E0AC7E30ULL,
		0x962AC538439AFD64ULL,
		0x406C58FB5317C6F0ULL,
		0x7CF6B55CC9261EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFCD32A6A9B026F1ULL,
		0xCD6605D76FA65BF7ULL,
		0x548DCF34AA6A9D69ULL,
		0x75CEB1328D2EF2B3ULL,
		0x04769A0717D2992FULL,
		0x4E0F42F6279B5F07ULL,
		0xDB71AB8D9903D153ULL,
		0xE98F6FF2868360EAULL
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
		0x47E55313F995B254ULL,
		0x1DB812D31A72560CULL,
		0x26A8C9FB97D902AFULL,
		0x8CD60497241CCC32ULL,
		0xDB53C5C67375EA41ULL,
		0xFD25E4B2F94F755CULL,
		0xFDD0B6D93CCFAB91ULL,
		0x24430539F75C03E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE0BD2A8173B654ULL,
		0xDDA625BCCCDC1A17ULL,
		0xF754BA5084A9A5E4ULL,
		0x07E253B1E6AA7359ULL,
		0xB562B05EF8F4E90AULL,
		0xF36CADF4C4FC75D5ULL,
		0xAD9BF7C5C4C71C13ULL,
		0x25B008C644032DF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE80495E97821FC00ULL,
		0x4011ED164D963BF4ULL,
		0x2F540FAB132F5CCAULL,
		0x84F3B0E53D7258D8ULL,
		0x25F115677A810137ULL,
		0x09B936BE3452FF87ULL,
		0x5034BF1378088F7EULL,
		0xFE92FC73B358D5EAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x76953415EE1E2E53ULL,
		0xE89153990D86D3DBULL,
		0x2CB345A4EC9B90E0ULL,
		0xD5299F5AE8C817EBULL,
		0xEFE41022CF2F8284ULL,
		0x2C147CC827E4C8C9ULL,
		0xF30EA82D29E08F89ULL,
		0x0D9BDF061270FDC9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x950C0122D2F1EAC6ULL,
		0x74A4E45FBB3BC252ULL,
		0xE09E62DD75FA668EULL,
		0x2EB4C661F1A963CDULL,
		0x4748A7161887DF82ULL,
		0xE1BC39F949EBFE9BULL,
		0xE86CD4067014BC52ULL,
		0xB339BF85C8A2CFEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE18932F31B2C438DULL,
		0x73EC6F39524B1188ULL,
		0x4C14E2C776A12A52ULL,
		0xA674D8F8F71EB41DULL,
		0xA89B690CB6A7A302ULL,
		0x4A5842CEDDF8CA2EULL,
		0x0AA1D426B9CBD336ULL,
		0x5A621F8049CE2DDCULL
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
		0x2D4AA5596210A171ULL,
		0x11950B7A3EBBBB08ULL,
		0x78C534A8FB507FC2ULL,
		0x04E2AE3137F7BE74ULL,
		0x324DD96902B9CBB9ULL,
		0x8D404D2C542999BAULL,
		0x47BC3D36B6EC4A00ULL,
		0x86D7E25B08769026ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EDD5FAA675E3727ULL,
		0x2F6A7DFAAA79C237ULL,
		0xBB4912394D77CBE7ULL,
		0x63C60C804DAAD1FCULL,
		0x340B5AD4BD0DB0A4ULL,
		0xA6EA28B72F85DB49ULL,
		0xBDD1A474E15D2FB8ULL,
		0xA41167A6980062E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE6D45AEFAB26A4AULL,
		0xE22A8D7F9441F8D0ULL,
		0xBD7C226FADD8B3DAULL,
		0xA11CA1B0EA4CEC77ULL,
		0xFE427E9445AC1B14ULL,
		0xE656247524A3BE70ULL,
		0x89EA98C1D58F1A47ULL,
		0xE2C67AB470762D3FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7B60F120CBEC70DFULL,
		0xA847933017B11532ULL,
		0xE3EA29DC3B5B4AEAULL,
		0xB658E14DD485687CULL,
		0xEB3B6F43F56C367CULL,
		0x561A9A13C2365A64ULL,
		0x356D7B009779E72CULL,
		0xAC4B9229CFC2F87CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x256E21DFD581FCB4ULL,
		0x85B4377E23E0E2EAULL,
		0x3E94EFDAC0916C9DULL,
		0x7335DE6A885D82FFULL,
		0xFA9AE427B581B61FULL,
		0xC60CE4D70A66FA63ULL,
		0x385C2FFC3FBE75EAULL,
		0x4559343DB1431FC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55F2CF40F66A742BULL,
		0x22935BB1F3D03248ULL,
		0xA5553A017AC9DE4DULL,
		0x432302E34C27E57DULL,
		0xF0A08B1C3FEA805DULL,
		0x900DB53CB7CF6000ULL,
		0xFD114B0457BB7141ULL,
		0x66F25DEC1E7FD8B7ULL
	}};
	sign = 0;
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
		0x071DF0B0ADE01870ULL,
		0x5E6F6C35E1FA4946ULL,
		0xF118F6289C189E0CULL,
		0x8DED5D91A804205CULL,
		0x9138F85F8D2C7304ULL,
		0x0934851FF220D682ULL,
		0x889B820206B0E654ULL,
		0x9BAD1EFD96E07050ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF1352561CDF364EULL,
		0xE69368E0E04B9BEDULL,
		0x0805B39F89AECEF1ULL,
		0x37395F72ACD12E37ULL,
		0x8F58C457C10ADA23ULL,
		0x5CD99AB5EBCD4556ULL,
		0xDF62EDD172233397ULL,
		0xDDB0274761555FBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x180A9E5A9100E222ULL,
		0x77DC035501AEAD58ULL,
		0xE91342891269CF1AULL,
		0x56B3FE1EFB32F225ULL,
		0x01E03407CC2198E1ULL,
		0xAC5AEA6A0653912CULL,
		0xA9389430948DB2BCULL,
		0xBDFCF7B6358B1090ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC7D47599437706F2ULL,
		0xED637AEB57F064BAULL,
		0x87B55C2E681DF2E6ULL,
		0x02975A3D21F7A0D4ULL,
		0xB37E9FB5AB436FE7ULL,
		0xCF920CD77F4F9B3AULL,
		0x8DBF3FAACD5D9736ULL,
		0xECF102C583048377ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66AE7112DEBD3DF3ULL,
		0xCC92FC27D007DE67ULL,
		0x2321A0E1DC9AFFF3ULL,
		0x32C1DC067F9ABE6CULL,
		0x74E2EC0EB662E964ULL,
		0xBAC0C1343FB43D03ULL,
		0xBA3F45E800C98069ULL,
		0x34EEFFDE66D097CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6126048664B9C8FFULL,
		0x20D07EC387E88653ULL,
		0x6493BB4C8B82F2F3ULL,
		0xCFD57E36A25CE268ULL,
		0x3E9BB3A6F4E08682ULL,
		0x14D14BA33F9B5E37ULL,
		0xD37FF9C2CC9416CDULL,
		0xB80202E71C33EBA8ULL
	}};
	sign = 0;
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
		0xD6223B120FF60CD4ULL,
		0x773EB1A78140F8E8ULL,
		0xF71BAEB6D6D8E8F6ULL,
		0x1328DF14746294D4ULL,
		0x74DB67A1167143CBULL,
		0xEAC3FF1B9A4E7191ULL,
		0x559D37EC5210DEF6ULL,
		0x55573044E9C095C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF453DE658606B6F4ULL,
		0x4D6F4F86722CC564ULL,
		0x99BD588DD20B6DACULL,
		0x49C886D2BB996EFAULL,
		0xAAFB4A5F68221295ULL,
		0xAE7D65B0B5AF498DULL,
		0x4942CE23215B08F7ULL,
		0x0269852CF57F6FC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1CE5CAC89EF55E0ULL,
		0x29CF62210F143383ULL,
		0x5D5E562904CD7B4AULL,
		0xC9605841B8C925DAULL,
		0xC9E01D41AE4F3135ULL,
		0x3C46996AE49F2803ULL,
		0x0C5A69C930B5D5FFULL,
		0x52EDAB17F4412600ULL
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
		0x49AF174D1B2AE1EEULL,
		0xEC820EE8328A6C5CULL,
		0x7058F964252B30EBULL,
		0x33303EE6D56F9990ULL,
		0x3067C85EE3AABAB8ULL,
		0x30F5E942FA6A7BEAULL,
		0x26E9EEFC761ABF76ULL,
		0xE57626B99F7E07F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x283279A1A7D4AEFCULL,
		0x4993AF1372E1E1D9ULL,
		0xCE7CD5E5B86FDDC7ULL,
		0x32CAC680827EAB18ULL,
		0x774B03948C1B47E3ULL,
		0x088B6E8FF6EDE95EULL,
		0x94A6FB8E1E8B7943ULL,
		0xE5F256421038A7E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x217C9DAB735632F2ULL,
		0xA2EE5FD4BFA88A83ULL,
		0xA1DC237E6CBB5324ULL,
		0x0065786652F0EE77ULL,
		0xB91CC4CA578F72D5ULL,
		0x286A7AB3037C928BULL,
		0x9242F36E578F4633ULL,
		0xFF83D0778F456007ULL
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
		0x32E0299D777B3A7AULL,
		0x49F4A4ADCE6CFAF2ULL,
		0x5BECFE0184F7B311ULL,
		0xCA7C403EB2D16D47ULL,
		0x94250CE68261F31CULL,
		0xD6B47321D7AF0CF7ULL,
		0x6CAD457621F8E288ULL,
		0x5AB0B11FA5F42138ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF32CB798C0B7C6ULL,
		0xDAE4442DF7E547A5ULL,
		0xAD2226B80DC8AE45ULL,
		0x926387D0B5181B5AULL,
		0xB8B2BBFCF2F049A2ULL,
		0x4EF428BDF2B85640ULL,
		0x29B0FDA26F698541ULL,
		0x173EB68241281C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42ECFCE5DEBA82B4ULL,
		0x6F10607FD687B34CULL,
		0xAECAD749772F04CBULL,
		0x3818B86DFDB951ECULL,
		0xDB7250E98F71A97AULL,
		0x87C04A63E4F6B6B6ULL,
		0x42FC47D3B28F5D47ULL,
		0x4371FA9D64CC0534ULL
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
		0x616CA923464429A7ULL,
		0x14EFDECCACA86B39ULL,
		0xB3833E12D28A4FA9ULL,
		0x1E3A47A8DB685BF6ULL,
		0xC772F2777A737D4BULL,
		0x25BAD003E33698F9ULL,
		0x899298A967C469B9ULL,
		0x265BF0AF58A25BDCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E47477181CC6BBULL,
		0x0EFCBC72410E9324ULL,
		0x6CE3802BA545AAAAULL,
		0x6B3F996014F15EB9ULL,
		0xD75D9E7E580B1B12ULL,
		0x9C0D3E153B6A116AULL,
		0xD5CBFAA4B0745A54ULL,
		0x1C2788D4CCEAF5ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE8834AC2E2762ECULL,
		0x05F3225A6B99D814ULL,
		0x469FBDE72D44A4FFULL,
		0xB2FAAE48C676FD3DULL,
		0xF01553F922686238ULL,
		0x89AD91EEA7CC878EULL,
		0xB3C69E04B7500F64ULL,
		0x0A3467DA8BB765EFULL
	}};
	sign = 0;
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
		0x33CBFBCB80C324BAULL,
		0x6BF65C3EFFBEC7E4ULL,
		0xA5D2768F3880530EULL,
		0x4E29C64D2E9E8A1EULL,
		0xED49EA1785C0DC47ULL,
		0x9C4CAFCF43317C9AULL,
		0x4550E64B08AC50F3ULL,
		0xA82345D7285E7A1CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5126BC8151F44EB8ULL,
		0x424819A4E88753D9ULL,
		0x956A24CD851A6120ULL,
		0x1B332A5BDDAC0AF9ULL,
		0xDCA33600E8064386ULL,
		0xC36EF672451431ACULL,
		0xFEB2498CFC6A992FULL,
		0x81A449E45F2B3271ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2A53F4A2ECED602ULL,
		0x29AE429A1737740AULL,
		0x106851C1B365F1EEULL,
		0x32F69BF150F27F25ULL,
		0x10A6B4169DBA98C1ULL,
		0xD8DDB95CFE1D4AEEULL,
		0x469E9CBE0C41B7C3ULL,
		0x267EFBF2C93347AAULL
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
		0x1019DA7C4EB0AC8FULL,
		0xDDE9593EE346FFFBULL,
		0xA38C4790E5EEE366ULL,
		0xA643494894C98516ULL,
		0xCBBD09F4A341BA88ULL,
		0x0484D0AFE61B4307ULL,
		0x9CA6CA2B3B51F6D4ULL,
		0x245CBFDE02C8793FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x972EA3E962B58544ULL,
		0xBECFF260F12E957FULL,
		0x1ADBE072E96AF6B4ULL,
		0x2A7AAA4DBB954898ULL,
		0xBF558F44C60C798AULL,
		0x2EC63B08AA778A9FULL,
		0x3D166542C6A33C01ULL,
		0xD1C54515D06F1758ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78EB3692EBFB274BULL,
		0x1F1966DDF2186A7BULL,
		0x88B0671DFC83ECB2ULL,
		0x7BC89EFAD9343C7EULL,
		0x0C677AAFDD3540FEULL,
		0xD5BE95A73BA3B868ULL,
		0x5F9064E874AEBAD2ULL,
		0x52977AC8325961E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1A0ACFCA26C3FF12ULL,
		0x19D7A8BD58C83098ULL,
		0x326D89E64053879CULL,
		0x3F490DA54505068DULL,
		0xE7FCB2908654828AULL,
		0xDBF0D13AB9CB843CULL,
		0x6E1B9476AD02529AULL,
		0x5AC968FE6358A98BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEB58C0B3253354ULL,
		0xC2C736B9C5EB34CFULL,
		0x83392C49F2AE91EFULL,
		0x59F2216B94F30093ULL,
		0x1C4230CDDEA662EAULL,
		0xFB19FFBD0D088CDDULL,
		0x97DF9A702C24CFB8ULL,
		0xC2D4E8946197AC2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A1F7709739ECBBEULL,
		0x5710720392DCFBC8ULL,
		0xAF345D9C4DA4F5ACULL,
		0xE556EC39B01205F9ULL,
		0xCBBA81C2A7AE1F9FULL,
		0xE0D6D17DACC2F75FULL,
		0xD63BFA0680DD82E1ULL,
		0x97F4806A01C0FD5BULL
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
		0x9543D457A40F965DULL,
		0x5D27A3E75720A5DCULL,
		0x4459FF5BDAF4F90FULL,
		0x2B6F488B82AD94E4ULL,
		0x5B81BA6170BA8FB5ULL,
		0xEC60045473CEB5F3ULL,
		0x23207763156519DAULL,
		0x04DEEA0B9104C20EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11DD9F42D4FAA2B0ULL,
		0x3D708633CB725AB6ULL,
		0x3094426ADB3A65B4ULL,
		0x63CDFDE44D3E1823ULL,
		0x02D101CFAEE7CF09ULL,
		0x4407043146988694ULL,
		0x3A4E1C34A706A0DBULL,
		0x5B60B99E9237B87BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83663514CF14F3ADULL,
		0x1FB71DB38BAE4B26ULL,
		0x13C5BCF0FFBA935BULL,
		0xC7A14AA7356F7CC1ULL,
		0x58B0B891C1D2C0ABULL,
		0xA85900232D362F5FULL,
		0xE8D25B2E6E5E78FFULL,
		0xA97E306CFECD0992ULL
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
		0xCBD235B9A171CECDULL,
		0x684200869974201BULL,
		0x83B69CE50074C77CULL,
		0x51DB5F9CF36127B4ULL,
		0x82238918C2001AADULL,
		0x9DF5210D18D6AA73ULL,
		0xA3137F043390035DULL,
		0xBD61537E4046FCC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEF8840BF98B751BULL,
		0x76257DAA283193B3ULL,
		0x68259F5BBCA07395ULL,
		0x2B2747E165F262D8ULL,
		0x0BE3D86AC5F3C895ULL,
		0x5619EFC8C8EC2A97ULL,
		0xEA937B810A06267CULL,
		0x607F031D0897C244ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCD9B1ADA7E659B2ULL,
		0xF21C82DC71428C67ULL,
		0x1B90FD8943D453E6ULL,
		0x26B417BB8D6EC4DCULL,
		0x763FB0ADFC0C5218ULL,
		0x47DB31444FEA7FDCULL,
		0xB88003832989DCE1ULL,
		0x5CE2506137AF3A7FULL
	}};
	sign = 0;
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
		0xA18BB3470E8452D3ULL,
		0xF86F846E4BAEFBB3ULL,
		0xA8D00434A70AC5C4ULL,
		0x2DA6239278CD7C70ULL,
		0x70633C56CD25D281ULL,
		0xB353A2BDBAF0A982ULL,
		0x2485DF086E392705ULL,
		0x03ACA27F4E0D19D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF8E4B821B47479ULL,
		0xB865C864ECFF99D6ULL,
		0x4A39760F06B821D8ULL,
		0x2BC0694E624E4D2CULL,
		0xECFE4F3A79C4DB89ULL,
		0x73CF7A1DD6EFD6B0ULL,
		0x7F8538D0A3DD3341ULL,
		0x2C9F44F3EECC7AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4492CE8EECCFDE5AULL,
		0x4009BC095EAF61DDULL,
		0x5E968E25A052A3ECULL,
		0x01E5BA44167F2F44ULL,
		0x8364ED1C5360F6F8ULL,
		0x3F84289FE400D2D1ULL,
		0xA500A637CA5BF3C4ULL,
		0xD70D5D8B5F409F0EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF1F8848794EBCD7DULL,
		0x1178DFBAF0EE7D7EULL,
		0xDCB19E2EAEC933F5ULL,
		0xB7BB558238FC2ABEULL,
		0x152C7564A7F703CCULL,
		0x6B868CF1C4C6D63AULL,
		0xAC51B4A951ECA8D3ULL,
		0x567ACA1285D2A28DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ADC5ACBE7E9A474ULL,
		0x1F0117EED439B5EEULL,
		0xB9A413BE17C5844FULL,
		0x935CAE0778628006ULL,
		0x5512E00C70AF92ECULL,
		0xF8806FD3FCF7CAA6ULL,
		0x9BFEF92772BA7CBEULL,
		0xAD1AC5CD1D764B9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x871C29BBAD022909ULL,
		0xF277C7CC1CB4C790ULL,
		0x230D8A709703AFA5ULL,
		0x245EA77AC099AAB8ULL,
		0xC0199558374770E0ULL,
		0x73061D1DC7CF0B93ULL,
		0x1052BB81DF322C14ULL,
		0xA9600445685C56F3ULL
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
		0x5B9B4CC96DD878D1ULL,
		0x58DDCB952DA4222DULL,
		0x1E5187DFC72C6817ULL,
		0xD424918667BC3E92ULL,
		0x182999DFA4DEF1C0ULL,
		0xF20B1EBF47684169ULL,
		0x239CE8CDF8E3947FULL,
		0xDA5F47D4350186DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCC41BE8CEBE7E1ULL,
		0x9417B4EF50BBA5A7ULL,
		0x79D87794D1B8FE0BULL,
		0x3C1A0E2BFF65E6A4ULL,
		0x2DFD642977EBDF49ULL,
		0x84141E14BE85E2FEULL,
		0x1C72FB4C36CE4972ULL,
		0x5D9826FBA425853BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DCF0B0AE0EC90F0ULL,
		0xC4C616A5DCE87C86ULL,
		0xA479104AF5736A0BULL,
		0x980A835A685657EDULL,
		0xEA2C35B62CF31277ULL,
		0x6DF700AA88E25E6AULL,
		0x0729ED81C2154B0DULL,
		0x7CC720D890DC01A0ULL
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
		0x4C6C75AC39CAD4D4ULL,
		0x74FABC881323E2F5ULL,
		0x96502A16EF73C7E8ULL,
		0x75A44CD6E188FABAULL,
		0x36D7666742EE35E3ULL,
		0x5FB32AD29AC4C0E0ULL,
		0x5E765E9E269761F6ULL,
		0x142F2F8BC2238B0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE136BA2ECF85EEEULL,
		0x3EF77EBD18133AB8ULL,
		0x11E68326A661A746ULL,
		0x5C1DE7DF48620D9DULL,
		0x7778A439C4A30827ULL,
		0x682727ABB6EFDDF8ULL,
		0xA923E41D68678677ULL,
		0xF51E522A4C760453ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E590A094CD275E6ULL,
		0x36033DCAFB10A83CULL,
		0x8469A6F0491220A2ULL,
		0x198664F79926ED1DULL,
		0xBF5EC22D7E4B2DBCULL,
		0xF78C0326E3D4E2E7ULL,
		0xB5527A80BE2FDB7EULL,
		0x1F10DD6175AD86B7ULL
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
		0x1CEBD1DA3DBA580DULL,
		0xBDC7AC1B9E67EDF0ULL,
		0x44C6F1B962F1A967ULL,
		0x5ADE53BB32DA39EBULL,
		0x8B0A234F35AE8FA3ULL,
		0x82E592B5C407BAE6ULL,
		0x87AAB57561775A0BULL,
		0x51F687FFC9AE6D94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EC5B2A4D38922E7ULL,
		0xC9D5CA042538309CULL,
		0x1A5FD9B10A0CC498ULL,
		0x571166CEAB54578CULL,
		0x710828E33CF36BFBULL,
		0x8D198CD4F6A16ECBULL,
		0x10266C8580A11A63ULL,
		0x85A2FB94413DAA29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE261F356A313526ULL,
		0xF3F1E217792FBD53ULL,
		0x2A67180858E4E4CEULL,
		0x03CCECEC8785E25FULL,
		0x1A01FA6BF8BB23A8ULL,
		0xF5CC05E0CD664C1BULL,
		0x778448EFE0D63FA7ULL,
		0xCC538C6B8870C36BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7FFBF72481EE2B5CULL,
		0x439D8917B5A2E963ULL,
		0x911C78A3B5770B91ULL,
		0x81EBE9931556A89FULL,
		0x38BBA094A903CB0EULL,
		0x6C13568E64A87A2DULL,
		0x07710AA0B001B359ULL,
		0xA7489FF233578E85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9C5D3CA454AE66ULL,
		0xD16C07B62636CE66ULL,
		0x1F382D0807261DB8ULL,
		0xE6CB16E6E455B43BULL,
		0x456FE3E6E4083660ULL,
		0xEC8C146213F68B4CULL,
		0x94106E959F188003ULL,
		0x80085AA5A3EF1EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD45F99E7DD997CF6ULL,
		0x723181618F6C1AFCULL,
		0x71E44B9BAE50EDD8ULL,
		0x9B20D2AC3100F464ULL,
		0xF34BBCADC4FB94ADULL,
		0x7F87422C50B1EEE0ULL,
		0x73609C0B10E93355ULL,
		0x2740454C8F686FD2ULL
	}};
	sign = 0;
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
		0xC32D7F730F4FEE4DULL,
		0x90B5560D69DA4142ULL,
		0x78442B0D367B1B2EULL,
		0x527AA2A7961B28F6ULL,
		0xC20EC5DF2403DF6AULL,
		0xC7E0AB776EE7E051ULL,
		0x218B5ECF01AD2EFCULL,
		0xCF08E888D7865FBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF55E59A11DBF13AULL,
		0x1CE9FC0192F4BAD4ULL,
		0xA7D5FC87FDBC19D6ULL,
		0xC893EED2B279AE30ULL,
		0xD8F0A7C04D47007EULL,
		0x1E6E54266D907C72ULL,
		0x1E2B7AFBC38C3D14ULL,
		0x0180DAACAFBB49D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03D799D8FD73FD13ULL,
		0x73CB5A0BD6E5866EULL,
		0xD06E2E8538BF0158ULL,
		0x89E6B3D4E3A17AC5ULL,
		0xE91E1E1ED6BCDEEBULL,
		0xA9725751015763DEULL,
		0x035FE3D33E20F1E8ULL,
		0xCD880DDC27CB15E6ULL
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
		0xC1B10C1959F0D017ULL,
		0x416E54BD03CDFDA8ULL,
		0xD7214D12BA453301ULL,
		0x3D50A0285618998BULL,
		0x55986238E2AF1D89ULL,
		0x2D7DEDE9894A6B6FULL,
		0x460658055BA1B326ULL,
		0xF441FCC062311934ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63F5B72D3AC3C77ULL,
		0xC113360755A2D665ULL,
		0xBBB257EB255B6E8AULL,
		0x32C295DCFB1FAA17ULL,
		0xFA78935C1A1D8980ULL,
		0xE834220C8FDD978AULL,
		0xFF1A0D42300CF7EBULL,
		0x261283D827830A1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB71B0A6864493A0ULL,
		0x805B1EB5AE2B2742ULL,
		0x1B6EF52794E9C476ULL,
		0x0A8E0A4B5AF8EF74ULL,
		0x5B1FCEDCC8919409ULL,
		0x4549CBDCF96CD3E4ULL,
		0x46EC4AC32B94BB3AULL,
		0xCE2F78E83AAE0F19ULL
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
		0x304A3CE19D16E07FULL,
		0xC80AAD10558EA037ULL,
		0xF4D094050040205FULL,
		0x5E76BFA56FB3289BULL,
		0x949694105EF906F5ULL,
		0x20A33E5B6B805D26ULL,
		0xB4DA36F7D3FDD9ACULL,
		0x868B11C7BC725379ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6240BA56425D686ULL,
		0x3B105A063C39D19CULL,
		0x4F24A34774BCF4ADULL,
		0x738D51F374025F92ULL,
		0x279F373566166E1AULL,
		0xAC647F6B3CA292D1ULL,
		0xCEAF94C459FE3A25ULL,
		0x8849A6FE05861C50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A26313C38F109F9ULL,
		0x8CFA530A1954CE9AULL,
		0xA5ABF0BD8B832BB2ULL,
		0xEAE96DB1FBB0C909ULL,
		0x6CF75CDAF8E298DAULL,
		0x743EBEF02EDDCA55ULL,
		0xE62AA23379FF9F86ULL,
		0xFE416AC9B6EC3728ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB00139B1C7993E77ULL,
		0x64C9285820CA1F1BULL,
		0xCB9CF9E21D5B357FULL,
		0x7203082CF8F3B289ULL,
		0xEC61EAF7D97A50DCULL,
		0xB318067E590A34CCULL,
		0x8DAAA8ACCBAD3533ULL,
		0x89812AF0631CCF66ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x863F167E30F00269ULL,
		0x0660FC3AE68D71B0ULL,
		0xCFCA5E6F92FB4D1BULL,
		0xE0DC3D0994FA3D98ULL,
		0xF6DDEBB7EC10869AULL,
		0x807508DEF0054E75ULL,
		0x38C52A7C4D163678ULL,
		0xAE002A26D442CABDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29C2233396A93C0EULL,
		0x5E682C1D3A3CAD6BULL,
		0xFBD29B728A5FE864ULL,
		0x9126CB2363F974F0ULL,
		0xF583FF3FED69CA41ULL,
		0x32A2FD9F6904E656ULL,
		0x54E57E307E96FEBBULL,
		0xDB8100C98EDA04A9ULL
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
		0x644A8CDADA042784ULL,
		0xA08756E40A333450ULL,
		0xE9A13959D7CEAF10ULL,
		0xEDCF98393BDF6A9AULL,
		0x10B4334B3843E1C0ULL,
		0x5BFEC74A6F5889E2ULL,
		0xF5CA809E9F038061ULL,
		0x2869D8D4ECCAB377ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E1A3510A791432AULL,
		0xEAAE61DB548DA4DEULL,
		0xB02EF018F93AFBD0ULL,
		0x271C11F2192C6F24ULL,
		0x1E0AA64F347C32CBULL,
		0xCE4AA66D203B878AULL,
		0x6F01F01B47DE3995ULL,
		0xFE4E404E7910D52EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF63057CA3272E45AULL,
		0xB5D8F508B5A58F71ULL,
		0x39724940DE93B33FULL,
		0xC6B3864722B2FB76ULL,
		0xF2A98CFC03C7AEF5ULL,
		0x8DB420DD4F1D0257ULL,
		0x86C89083572546CBULL,
		0x2A1B988673B9DE49ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA0ACDF1B77A65E44ULL,
		0x1CFB60034C16C746ULL,
		0xD2BE5BC8D65F6486ULL,
		0xFED85A2A1B3BE7F4ULL,
		0x53737F3BFF9CA216ULL,
		0x1B3CD95E323C121DULL,
		0xAC5D2C3F1AD28089ULL,
		0x505B6CD265840436ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA991AD2D46BC4E23ULL,
		0xC42926D6AA980689ULL,
		0x4C45EC661A0A40E7ULL,
		0x333D9F7D5D05FEA5ULL,
		0x826AF632CF853F24ULL,
		0xEFF5E70B2B06F6B4ULL,
		0x21CF62C77A9A5D6DULL,
		0xE37B2151E98E364AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71B31EE30EA1021ULL,
		0x58D2392CA17EC0BCULL,
		0x86786F62BC55239EULL,
		0xCB9ABAACBE35E94FULL,
		0xD1088909301762F2ULL,
		0x2B46F25307351B68ULL,
		0x8A8DC977A038231BULL,
		0x6CE04B807BF5CDECULL
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
		0xA3F0C1236986027BULL,
		0xEB5CBD1E029C7920ULL,
		0x165EC59FE4266B27ULL,
		0x77C3900E5D0EE72AULL,
		0x4FA69858F772FF9BULL,
		0xDF6BA4EDF7829E56ULL,
		0x267A97A30CA41E49ULL,
		0xA7054C4AF63D0A1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D44A18E01848A8ULL,
		0x0811902846A6C8E1ULL,
		0x79B5F0F6AFB3C183ULL,
		0x741789B695FDF2CBULL,
		0x9A9AA74F18DE348FULL,
		0xDD2CA59BF327C492ULL,
		0x27886678683E72DCULL,
		0x79258CF7BD981F3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C1C770A896DB9D3ULL,
		0xE34B2CF5BBF5B03FULL,
		0x9CA8D4A93472A9A4ULL,
		0x03AC0657C710F45EULL,
		0xB50BF109DE94CB0CULL,
		0x023EFF52045AD9C3ULL,
		0xFEF2312AA465AB6DULL,
		0x2DDFBF5338A4EADBULL
	}};
	sign = 0;
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
		0x9902B8275C31A7F8ULL,
		0x8C4B209EF4575BF8ULL,
		0x3C534A2EEC020E40ULL,
		0x58C9AAC416BB2363ULL,
		0xAF242A4EA21EF63AULL,
		0x11F1199B8F0AC87BULL,
		0xFEAF06AD4B0838B0ULL,
		0x38C8313E925143B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F01A01C9B86A1B9ULL,
		0x045CA91EFDA05419ULL,
		0x535BF52946F7BB42ULL,
		0xCCEF24E0C32DE263ULL,
		0x0E4FDC274D2B3A64ULL,
		0x422AFEC8E0E5F139ULL,
		0xA86E16F77025149AULL,
		0xB318B9269F7A31F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A01180AC0AB063FULL,
		0x87EE777FF6B707DFULL,
		0xE8F75505A50A52FEULL,
		0x8BDA85E3538D40FFULL,
		0xA0D44E2754F3BBD5ULL,
		0xCFC61AD2AE24D742ULL,
		0x5640EFB5DAE32415ULL,
		0x85AF7817F2D711BEULL
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
		0x5C5A9815A6A59C76ULL,
		0xD981B87FA7F5FD97ULL,
		0xBA863F78FCA97F5FULL,
		0x4D591907C030FCFDULL,
		0x14843FBD1185E12FULL,
		0x3C9521636F86A8DFULL,
		0x37FA1228782D2E77ULL,
		0x1E380085267EA8CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x400C4D7EF647E3C9ULL,
		0x4528AB88E6DD1E8FULL,
		0x7061D3898E28324AULL,
		0xF24B9D5C4A5EAFF7ULL,
		0xF347DEE3213FE8AAULL,
		0xEEF07C9E0F6C3E90ULL,
		0x533AB876B1BD9FE2ULL,
		0xC2C5F77BA04D0774ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C4E4A96B05DB8ADULL,
		0x94590CF6C118DF08ULL,
		0x4A246BEF6E814D15ULL,
		0x5B0D7BAB75D24D06ULL,
		0x213C60D9F045F884ULL,
		0x4DA4A4C5601A6A4EULL,
		0xE4BF59B1C66F8E94ULL,
		0x5B7209098631A159ULL
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
		0xF266F79F021B5666ULL,
		0xC742CF597071DF5BULL,
		0xC126FF54E48D9992ULL,
		0xE427B10C60EBC1EAULL,
		0x1B113D877D017EE5ULL,
		0xFE71508D51CE0216ULL,
		0xFBF9A725335F8EF2ULL,
		0x99DFFC7537DD9B4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B6B754DA3F0BBAULL,
		0xEBE26870EF6CAD9CULL,
		0x54E3C7F1C1AC593EULL,
		0x06A7E04E3B9DDE49ULL,
		0xF02216D381A469AAULL,
		0xF48CB6BC29119B5AULL,
		0x01F5E002EFA1E672ULL,
		0xAB31456B80D5EA2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CB0404A27DC4AACULL,
		0xDB6066E8810531BFULL,
		0x6C43376322E14053ULL,
		0xDD7FD0BE254DE3A1ULL,
		0x2AEF26B3FB5D153BULL,
		0x09E499D128BC66BBULL,
		0xFA03C72243BDA880ULL,
		0xEEAEB709B707B121ULL
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
		0xED29EAA804D0EDCAULL,
		0xD570B07369F024B9ULL,
		0x139248FAEFE5EC2AULL,
		0xED5F0D3ACFAF9361ULL,
		0x0AB78BD0A1ADE22FULL,
		0xB21E51D8D55BE0AFULL,
		0x82E5E356AE29EEA6ULL,
		0x000CD40A80743E5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8200CCF4048A6B09ULL,
		0x7741B8417E6F2526ULL,
		0x40A9779625348142ULL,
		0xAFA47603479150BDULL,
		0xDAF4EABC7BD89A55ULL,
		0x5E77E26E7D6D1806ULL,
		0xB69C723D7E467269ULL,
		0x1B343C3769029CA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B291DB4004682C1ULL,
		0x5E2EF831EB80FF93ULL,
		0xD2E8D164CAB16AE8ULL,
		0x3DBA9737881E42A3ULL,
		0x2FC2A11425D547DAULL,
		0x53A66F6A57EEC8A8ULL,
		0xCC4971192FE37C3DULL,
		0xE4D897D31771A1B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEA8DDFDD5A7B0887ULL,
		0x3B67CD37E57C6EB4ULL,
		0x11343CCF0C2AC408ULL,
		0xBDCA3AB934A30DA6ULL,
		0xB38B9FC9BCB2B7FAULL,
		0xEF4DBA1B91B0CE12ULL,
		0x19735ECD7390B581ULL,
		0xD07CCCD8402150A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7FF790D58211CFULL,
		0x403AA4D024B4FD7DULL,
		0x2B35859EF4820099ULL,
		0x72A3D43B0C123815ULL,
		0x1A617B773A73D1C6ULL,
		0xB8A49F7C272F5F58ULL,
		0xC64729BBDD7734CCULL,
		0x887A203BE7929485ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F0DE84C84F8F6B8ULL,
		0xFB2D2867C0C77137ULL,
		0xE5FEB73017A8C36EULL,
		0x4B26667E2890D590ULL,
		0x992A2452823EE634ULL,
		0x36A91A9F6A816EBAULL,
		0x532C3511961980B5ULL,
		0x4802AC9C588EBC1EULL
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
		0x5E7BF0416D4F851BULL,
		0x67EF2F6BE41AAEE5ULL,
		0xB99D73DBA1A5C9BEULL,
		0x5CA09861C078C068ULL,
		0x5C13F1276E8288BAULL,
		0x356645ECFF579CD1ULL,
		0x21F8E5177722A3F5ULL,
		0x6AE9BEC683EFF949ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE0E805B42D58C5ULL,
		0xA9A66E159F12A282ULL,
		0xAF2BD3539D772B59ULL,
		0x31197675AAB9354EULL,
		0x858D8F2476CA520DULL,
		0x1CFC952F1E54DE56ULL,
		0xDDB2A83383DCF8F6ULL,
		0xBCD1B503BC1E4462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x939B083BB9222C56ULL,
		0xBE48C15645080C62ULL,
		0x0A71A088042E9E64ULL,
		0x2B8721EC15BF8B1AULL,
		0xD6866202F7B836ADULL,
		0x1869B0BDE102BE7AULL,
		0x44463CE3F345AAFFULL,
		0xAE1809C2C7D1B4E6ULL
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
		0xB14E742C1429AC6DULL,
		0xCB7EDC92FDBE6B78ULL,
		0xB751D5C8788E61D5ULL,
		0x764DEB09F3C280E4ULL,
		0x00DC0041BCFEF3B7ULL,
		0xA2D4E5CCF62B899AULL,
		0xD2FE9A3072F98B94ULL,
		0xF0BA55771B9E58D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CC3C540510C2EACULL,
		0x52F9C6DA35125DFCULL,
		0x398856CB8AB67E40ULL,
		0x13B6BB2F75BB52B6ULL,
		0x83772C3FAEDA91C3ULL,
		0xC93F4B3B0D9BBDE8ULL,
		0x1D774EEBE667AE6DULL,
		0xDA64B0093F783C0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x948AAEEBC31D7DC1ULL,
		0x788515B8C8AC0D7CULL,
		0x7DC97EFCEDD7E395ULL,
		0x62972FDA7E072E2EULL,
		0x7D64D4020E2461F4ULL,
		0xD9959A91E88FCBB1ULL,
		0xB5874B448C91DD26ULL,
		0x1655A56DDC261CC4ULL
	}};
	sign = 0;
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
		0xB1F8005BB1BD5BB6ULL,
		0x5D28AA05213A548EULL,
		0x4B1AC67DB62601EEULL,
		0x2CE42085A0CE77E0ULL,
		0x132CB343C3A56E91ULL,
		0x6910F1EB31CF3A72ULL,
		0xA8AF68E6436D3BCDULL,
		0xFC0105D8AB11E5C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85AF17A9C25D49ADULL,
		0x6B26F53B31E0F2CFULL,
		0x9461892092ACDE3FULL,
		0xB705EB2F3385D497ULL,
		0xCDAEF2867D1B3A27ULL,
		0x54509F27388856F1ULL,
		0xB11F2DB23A6853B0ULL,
		0x191D74DAA30B1D0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C48E8B1EF601209ULL,
		0xF201B4C9EF5961BFULL,
		0xB6B93D5D237923AEULL,
		0x75DE35566D48A348ULL,
		0x457DC0BD468A3469ULL,
		0x14C052C3F946E380ULL,
		0xF7903B340904E81DULL,
		0xE2E390FE0806C8B9ULL
	}};
	sign = 0;
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
		0x53E92FEB698ACEF9ULL,
		0x89123AC4FDD12B03ULL,
		0x4B238C2DCE7022FDULL,
		0xA4A26AB7E6AE1395ULL,
		0x7C08B8B7A3B71390ULL,
		0x7044CD571F6D79B3ULL,
		0xFDC6BBEC1862F221ULL,
		0x08279F2F9A5DAA1DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A383B348CF4B83CULL,
		0xBEF6A80B3E8B5BB1ULL,
		0xCD89AFEDD654980DULL,
		0x8498415D337BE59BULL,
		0x43095C72B9E5AE0BULL,
		0xF222EDC7BA44E648ULL,
		0xD93D5F403EF1951BULL,
		0x508B844BE217B7C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29B0F4B6DC9616BDULL,
		0xCA1B92B9BF45CF52ULL,
		0x7D99DC3FF81B8AEFULL,
		0x200A295AB3322DF9ULL,
		0x38FF5C44E9D16585ULL,
		0x7E21DF8F6528936BULL,
		0x24895CABD9715D05ULL,
		0xB79C1AE3B845F257ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3590BA87537A5509ULL,
		0xF3EC3669CE819156ULL,
		0x9A7BA16E017F5261ULL,
		0x773B85AF02494284ULL,
		0x80C66A8EB78700D7ULL,
		0x0749871E0A3BF143ULL,
		0x352D14FE5496444EULL,
		0xC6EE22046B90287BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x997EBBF43C257D00ULL,
		0xA631E7A3C977D504ULL,
		0x2C331D6E4573216DULL,
		0xAAC8D002334D3B44ULL,
		0x71DB8BB083F1E615ULL,
		0xC021F922B926C9F8ULL,
		0xC955EB030544BA82ULL,
		0x29F1910E202936D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C11FE931754D809ULL,
		0x4DBA4EC60509BC51ULL,
		0x6E4883FFBC0C30F4ULL,
		0xCC72B5ACCEFC0740ULL,
		0x0EEADEDE33951AC1ULL,
		0x47278DFB5115274BULL,
		0x6BD729FB4F5189CBULL,
		0x9CFC90F64B66F1A5ULL
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
		0x566B6CDBA6256865ULL,
		0x2320C390654D5B3DULL,
		0xEA6A4ADD5F2FF046ULL,
		0xE367124D07E59DF3ULL,
		0x91384C250F654AF4ULL,
		0x4C750EEEE1BEF853ULL,
		0xB33E765881897B75ULL,
		0x30A34F3C7D1A2CEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A7A08E09210341BULL,
		0x6A2929C51A909ED1ULL,
		0x1097517678EBA20AULL,
		0x5FEC3BD9862832D4ULL,
		0xE1CE3050B2850A9BULL,
		0xFA29DBCB4E60433DULL,
		0x0ED2A39F8EECB035ULL,
		0x290418B2955CF9E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBF163FB1415344AULL,
		0xB8F799CB4ABCBC6BULL,
		0xD9D2F966E6444E3BULL,
		0x837AD67381BD6B1FULL,
		0xAF6A1BD45CE04059ULL,
		0x524B3323935EB515ULL,
		0xA46BD2B8F29CCB3FULL,
		0x079F3689E7BD330AULL
	}};
	sign = 0;
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
		0x4CE8FDB6EB5E0BCEULL,
		0xF18EB0FEC7671E12ULL,
		0x2F4FC39DC559723BULL,
		0x7C3DAEE7EFBF0104ULL,
		0x4D2417FFF7981774ULL,
		0xFAB00B9F0610A706ULL,
		0x89D2D9F0F63B9BE3ULL,
		0xF9232E37E713E872ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF587EA41C8D77F00ULL,
		0x0F80852949AC5A54ULL,
		0xB55A2A2A89DAE04BULL,
		0x95F2B9E2BC5D277DULL,
		0x3E90B1BF29B67EE3ULL,
		0xCE4D5725244807C4ULL,
		0x9BB7701F21D6AD24ULL,
		0x362131604FB724E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5761137522868CCEULL,
		0xE20E2BD57DBAC3BDULL,
		0x79F599733B7E91F0ULL,
		0xE64AF5053361D986ULL,
		0x0E936640CDE19890ULL,
		0x2C62B479E1C89F42ULL,
		0xEE1B69D1D464EEBFULL,
		0xC301FCD7975CC390ULL
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
		0x1E5191C0F5FD4A78ULL,
		0xE04A9422F872A9C6ULL,
		0xE15320A04694D299ULL,
		0x847C4AB06505ED7BULL,
		0x2D05F0AF3D2873A1ULL,
		0xD307A5798CF4CB94ULL,
		0x3A3006EC8BBA700CULL,
		0xB3D5D4CE048EA84CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92959D8D67483F67ULL,
		0x2BA4D87F3BA31B84ULL,
		0xC50EBBF470584C6CULL,
		0xD68ECA12592F256BULL,
		0x56D75AE8FC91E813ULL,
		0xD0E43C4454A2239CULL,
		0x189F2A8356F119EDULL,
		0xD01792EB3D9D751BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BBBF4338EB50B11ULL,
		0xB4A5BBA3BCCF8E41ULL,
		0x1C4464ABD63C862DULL,
		0xADED809E0BD6C810ULL,
		0xD62E95C640968B8DULL,
		0x022369353852A7F7ULL,
		0x2190DC6934C9561FULL,
		0xE3BE41E2C6F13331ULL
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
		0x12C9CDEA71E48288ULL,
		0xB0D39A4F205CD634ULL,
		0xE5DB85B6734727DEULL,
		0x2EF4941C20F0358AULL,
		0xFB5FF4C87034D1EFULL,
		0x9DC8758873585B9BULL,
		0x44E5ED3CBE4FED1DULL,
		0x9569E98568178B1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x878120F2B53920BBULL,
		0x968720CF49E460D3ULL,
		0xDC2D00F5F3357650ULL,
		0x16298376387ED6C5ULL,
		0xED06E80E60192E80ULL,
		0x88CCEE685A457788ULL,
		0x33288BD144DF5817ULL,
		0xDA8E8019CD13DED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B48ACF7BCAB61CDULL,
		0x1A4C797FD6787560ULL,
		0x09AE84C08011B18EULL,
		0x18CB10A5E8715EC5ULL,
		0x0E590CBA101BA36FULL,
		0x14FB87201912E413ULL,
		0x11BD616B79709506ULL,
		0xBADB696B9B03AC42ULL
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
		0x9E97C1F9A8D5CFBDULL,
		0x12BDB59848A2F210ULL,
		0x39B6798C53E2659EULL,
		0x5D539D70F8EA96C3ULL,
		0x3715B568EBEB1D69ULL,
		0xBCA974A61EE40045ULL,
		0xE565276C0A8F5820ULL,
		0x3D1A0B4D0A216C40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x627BD839CEF9A083ULL,
		0x13245C144575F5C5ULL,
		0x5E73D8193C6ED448ULL,
		0x048003D119B3B182ULL,
		0x10B35B700F004F6BULL,
		0x8A1C50C65F1FA399ULL,
		0x1DAD8D833E6193D5ULL,
		0x93B60A892B13F4CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C1BE9BFD9DC2F3AULL,
		0xFF995984032CFC4BULL,
		0xDB42A17317739155ULL,
		0x58D3999FDF36E540ULL,
		0x266259F8DCEACDFEULL,
		0x328D23DFBFC45CACULL,
		0xC7B799E8CC2DC44BULL,
		0xA96400C3DF0D7774ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3A59F092EC0422E2ULL,
		0x3D96CFBFF46A802FULL,
		0xBBA3EA1F90B5B3B2ULL,
		0xD18E5B0D3E5520D4ULL,
		0x3CE6E2F2CE1A068AULL,
		0xDA8E0F73835380BBULL,
		0x7F30037CC539E9C5ULL,
		0xF017DEFD3D79256EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA8C03413E246FDULL,
		0x19C92C27B794A5BFULL,
		0xC775AED43DD53A0DULL,
		0xA409975B28D9FB9FULL,
		0xBE98236DFC77C7ECULL,
		0x5E98B571072258EFULL,
		0xE8D2D17D7A076652ULL,
		0x87015C44A1DC5970ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CB1305ED821DBE5ULL,
		0x23CDA3983CD5DA6FULL,
		0xF42E3B4B52E079A5ULL,
		0x2D84C3B2157B2534ULL,
		0x7E4EBF84D1A23E9EULL,
		0x7BF55A027C3127CBULL,
		0x965D31FF4B328373ULL,
		0x691682B89B9CCBFDULL
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
		0x01170FCF2F8EA554ULL,
		0xA7BC95AA90667768ULL,
		0x39905C082ACACEDFULL,
		0x0F286ABB4F588312ULL,
		0xA95ECC7B1ABABF17ULL,
		0xC70EB662376B111AULL,
		0x9C81E27B88B5CBF4ULL,
		0xA412C4E4D8AF0CFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85AB68D22A9029F5ULL,
		0x5D0830FAEE895376ULL,
		0x9011482B372DA8F1ULL,
		0x944B438298A1BC6BULL,
		0xEA5B9C524528451BULL,
		0x32F851C78C35296EULL,
		0x6E6F5C01573A70B7ULL,
		0x16E73A8D4D540298ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B6BA6FD04FE7B5FULL,
		0x4AB464AFA1DD23F1ULL,
		0xA97F13DCF39D25EEULL,
		0x7ADD2738B6B6C6A6ULL,
		0xBF033028D59279FBULL,
		0x9416649AAB35E7ABULL,
		0x2E12867A317B5B3DULL,
		0x8D2B8A578B5B0A65ULL
	}};
	sign = 0;
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
		0xBA6A95FBA7A7C274ULL,
		0x81E2B392DAAF0928ULL,
		0xDC90383D5C9A24AEULL,
		0x99B97E4034B9E72CULL,
		0xE46B03D256E66458ULL,
		0x7C485A8E1318EC24ULL,
		0x59DB3E36BE793391ULL,
		0x1CEB34BB40ED6766ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6E929A1E546A9AULL,
		0xDEB3EBFB955BB89CULL,
		0x6CF93F5623E650F4ULL,
		0x85B45AACA8604E99ULL,
		0xCD400BC7CADD8BD7ULL,
		0xAE5163F0CAFBE05DULL,
		0x10FD2FF1BD7739A3ULL,
		0x4899CF6E7930A326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFFC0361895357DAULL,
		0xA32EC7974553508BULL,
		0x6F96F8E738B3D3B9ULL,
		0x140523938C599893ULL,
		0x172AF80A8C08D881ULL,
		0xCDF6F69D481D0BC7ULL,
		0x48DE0E450101F9EDULL,
		0xD451654CC7BCC440ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0C4BE0770DBDC5E9ULL,
		0x0045FE338EB21AF8ULL,
		0x4FEEB1C2B2329532ULL,
		0x8027210FA3D3D479ULL,
		0xAC9352B5BDF2A466ULL,
		0xE12563FE2F1FBC9DULL,
		0x77459507F9F377D9ULL,
		0xF9A145C16BEEE2CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B165D0AE7DF134ULL,
		0xAA1D4725581AC094ULL,
		0x4B1CCFC5068763CCULL,
		0x3E8A9D7CA621C177ULL,
		0x85D6C00D1898DD8BULL,
		0x7D71E82B0ABA3A6BULL,
		0xA073F840C38539EDULL,
		0x242C68C4B1BFBADCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B9A7AA65F3FD4B5ULL,
		0x5628B70E36975A63ULL,
		0x04D1E1FDABAB3165ULL,
		0x419C8392FDB21302ULL,
		0x26BC92A8A559C6DBULL,
		0x63B37BD324658232ULL,
		0xD6D19CC7366E3DECULL,
		0xD574DCFCBA2F27F2ULL
	}};
	sign = 0;
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
		0xE9C1E491A366029DULL,
		0x70C7A7C1B708D13CULL,
		0xC78920E2134AB442ULL,
		0xC647C7F1C98D58CAULL,
		0x0D783F89D19E3427ULL,
		0x375E84DC4B61D156ULL,
		0x9134C0C852A7BC0AULL,
		0x8D28419BC75791FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x568BC3B2BF4A5141ULL,
		0x37C961E796413D6DULL,
		0x63578F9F17FF8783ULL,
		0x9A57C1B8BC08CB26ULL,
		0xCAABED5FE7F5F249ULL,
		0xE4C432F6B71D0545ULL,
		0xC90D2A2E7FDC58E0ULL,
		0xF1962798B0837ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x933620DEE41BB15CULL,
		0x38FE45DA20C793CFULL,
		0x64319142FB4B2CBFULL,
		0x2BF006390D848DA4ULL,
		0x42CC5229E9A841DEULL,
		0x529A51E59444CC10ULL,
		0xC8279699D2CB6329ULL,
		0x9B921A0316D4171FULL
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
		0x324B3F165F00938AULL,
		0x9750739A739C1B04ULL,
		0x395DC469322EBDA5ULL,
		0xC78E02B202D7BCAAULL,
		0x70B0851A68ECF168ULL,
		0xE0DFA015628C35EAULL,
		0x51FA856ED6440DB1ULL,
		0x59585BF744C3A473ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0285A3E3A536E4ULL,
		0xEBFF7F39BBDE00E7ULL,
		0x1E75DA46E66E6425ULL,
		0xCB8EDB5957AA74A5ULL,
		0xA150E4910B580D66ULL,
		0xDC0A84BAB2B7F9BBULL,
		0x7CCE5AC2239B748BULL,
		0xF2428E9C1A177CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6548B9727B5B5CA6ULL,
		0xAB50F460B7BE1A1CULL,
		0x1AE7EA224BC0597FULL,
		0xFBFF2758AB2D4805ULL,
		0xCF5FA0895D94E401ULL,
		0x04D51B5AAFD43C2EULL,
		0xD52C2AACB2A89926ULL,
		0x6715CD5B2AAC27A0ULL
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
		0x3EE6E8F02A21DE6DULL,
		0xED6E737AAD48F009ULL,
		0xDF2FD14311B941BAULL,
		0x06E499ED8C493342ULL,
		0x70910FF1B77672ECULL,
		0x0F34BCD8F6E409C5ULL,
		0x840E1DC5C41EF3F6ULL,
		0x7BB50257E183F089ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE70C93738AD341DULL,
		0xA3B367C9C0294B05ULL,
		0x3419A43FF547FF38ULL,
		0xE8DF18F66184A5FEULL,
		0xEACDBF2FF0A11ECCULL,
		0x831E843EAA292EFAULL,
		0xC4EC633B8709E6B3ULL,
		0x3BE9616D42098F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60761FB8F174AA50ULL,
		0x49BB0BB0ED1FA503ULL,
		0xAB162D031C714282ULL,
		0x1E0580F72AC48D44ULL,
		0x85C350C1C6D5541FULL,
		0x8C16389A4CBADACAULL,
		0xBF21BA8A3D150D42ULL,
		0x3FCBA0EA9F7A6146ULL
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
		0x85D4A59E4D5521A8ULL,
		0x78D5463CB5E70A59ULL,
		0x1172ADF7752FCF22ULL,
		0x028A3655991C4FAEULL,
		0x8BB880A0EBC32AE3ULL,
		0xD98C8922E418832EULL,
		0xFAC18B59B8710E28ULL,
		0x6D895D5FDAF22436ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AAA36B899737FD4ULL,
		0xE7DB1193ADDEE2D8ULL,
		0x7004B1D75C290E92ULL,
		0x0DAF1778F9FFB65CULL,
		0xC57FA3036F993D11ULL,
		0x5E5244F38AC1D786ULL,
		0x63DDAB787B247F7CULL,
		0xE4885C24302931D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B2A6EE5B3E1A1D4ULL,
		0x90FA34A908082781ULL,
		0xA16DFC201906C08FULL,
		0xF4DB1EDC9F1C9951ULL,
		0xC638DD9D7C29EDD1ULL,
		0x7B3A442F5956ABA7ULL,
		0x96E3DFE13D4C8EACULL,
		0x8901013BAAC8F266ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5344F5C8827A75A4ULL,
		0xBC67E469283A344BULL,
		0xF2356E59B4F12921ULL,
		0xE9F961CB9D0CCD73ULL,
		0x4DF37556A85FE372ULL,
		0x6AA83CA629581057ULL,
		0x9D6B61A8D57E983EULL,
		0x8D81B4BC5DEAB126ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAF6A6171FBA6D8AULL,
		0x5A7D16CF0760744FULL,
		0x1BBE1AB5934351A9ULL,
		0x70A3C0F9D49A9DF2ULL,
		0xBE99081358BB1E1DULL,
		0x1FD37E574DF5C509ULL,
		0xD19B621A335C021BULL,
		0xE212466A8A9D127DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684E4FB162C0081AULL,
		0x61EACD9A20D9BFFBULL,
		0xD67753A421ADD778ULL,
		0x7955A0D1C8722F81ULL,
		0x8F5A6D434FA4C555ULL,
		0x4AD4BE4EDB624B4DULL,
		0xCBCFFF8EA2229623ULL,
		0xAB6F6E51D34D9EA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8A3A5D6B0739DD33ULL,
		0x5DDF7B3F5BB0937EULL,
		0x31304A07C18E386BULL,
		0xAD5DA3F205F2A756ULL,
		0xE4DA7CBD61D3F05AULL,
		0x61667979DA41961DULL,
		0xC76BF7C8D28A8AFFULL,
		0xD17CF77428EC67F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48287666F9AC654DULL,
		0xEDDBF352A0A8A4E3ULL,
		0xCF8D1EDBC3874F3EULL,
		0x714B49525CD9FC85ULL,
		0xD4FD1475E6871351ULL,
		0xBBFBE5C08FB87135ULL,
		0x055586A68309C3E8ULL,
		0x3D9707B5B29F7EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4211E7040D8D77E6ULL,
		0x700387ECBB07EE9BULL,
		0x61A32B2BFE06E92CULL,
		0x3C125A9FA918AAD0ULL,
		0x0FDD68477B4CDD09ULL,
		0xA56A93B94A8924E8ULL,
		0xC21671224F80C716ULL,
		0x93E5EFBE764CE941ULL
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
		0x1A50A8DD639A5336ULL,
		0xD78D7467C0DFD241ULL,
		0xE0D4F691EBDFF4D7ULL,
		0xFFA0EC4905876E9AULL,
		0x52A3D4044F53570EULL,
		0x86A133BB67E280BFULL,
		0x4193EBCC2EB54853ULL,
		0x169CE171D6AD5B8EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38632CAE9CB26B4CULL,
		0x76D58565252AE1CCULL,
		0x7854938D672E9939ULL,
		0xF7EDC49BCB7780B2ULL,
		0x179833112EA81E5AULL,
		0xEC1BB6F7BC51727FULL,
		0xED35F45AA7629E27ULL,
		0x86F7F94FF5A28AF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1ED7C2EC6E7E7EAULL,
		0x60B7EF029BB4F074ULL,
		0x6880630484B15B9EULL,
		0x07B327AD3A0FEDE8ULL,
		0x3B0BA0F320AB38B4ULL,
		0x9A857CC3AB910E40ULL,
		0x545DF7718752AA2BULL,
		0x8FA4E821E10AD09AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x960D6225DC31CF21ULL,
		0x1519CD7DB9FE6ACBULL,
		0xA17B074C4DA03CD4ULL,
		0x2B070F62CFCEA762ULL,
		0x1393908AF657472DULL,
		0xCD3885F428D0C8A7ULL,
		0x082659E7CDBB13ABULL,
		0xA8456D1E1978E81DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6098D66E4C150DULL,
		0xA68A78C283C76D47ULL,
		0xB8D84DE2B2DA9C3BULL,
		0x97ACC1E2361BCC04ULL,
		0xFD776039AC4E52D4ULL,
		0xFA04253EFA1B30F5ULL,
		0x12B6AAE990454BC2ULL,
		0xF7A48AE3CAFA9015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBACC94F6DE5BA14ULL,
		0x6E8F54BB3636FD83ULL,
		0xE8A2B9699AC5A098ULL,
		0x935A4D8099B2DB5DULL,
		0x161C30514A08F458ULL,
		0xD33460B52EB597B1ULL,
		0xF56FAEFE3D75C7E8ULL,
		0xB0A0E23A4E7E5807ULL
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
		0xF72C19AB60BD7EEAULL,
		0x1C59DB1620CB18B6ULL,
		0xCEB610BCA05DC18FULL,
		0xD6ACBB3CFC0466F1ULL,
		0xEB726B237713EE4CULL,
		0x178288A6024F8F52ULL,
		0x42A0F64713924068ULL,
		0xE1556EF862643CB5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60761AA5798FA3F2ULL,
		0x388D70DECA6B537BULL,
		0xBDD9CCB00B87B779ULL,
		0x102AB94ADA5B175FULL,
		0x1B0EC0B81E7CC4DEULL,
		0x48C54BDDE64A3C42ULL,
		0x025CE60DA7A97768ULL,
		0xAD4CAFB7C665D07BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96B5FF05E72DDAF8ULL,
		0xE3CC6A37565FC53BULL,
		0x10DC440C94D60A15ULL,
		0xC68201F221A94F92ULL,
		0xD063AA6B5897296EULL,
		0xCEBD3CC81C055310ULL,
		0x404410396BE8C8FFULL,
		0x3408BF409BFE6C3AULL
	}};
	sign = 0;
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
		0x29012B972A39EE6BULL,
		0xD08A0742C8ECAE6CULL,
		0xA9C9A182F2FEC138ULL,
		0xEEB8778A02F19129ULL,
		0x0E7563E1FD8553B1ULL,
		0xAD4DB0F13A835ADAULL,
		0x2F1D88DAE34CFE41ULL,
		0xAFC9496116569FBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C09EA596E862456ULL,
		0xC2507B7438AAE610ULL,
		0x7BC7143C79D15F27ULL,
		0x3CDCC30C979C9EB2ULL,
		0x85003479658598C7ULL,
		0x9CB580F5206AD8BDULL,
		0xC68C295CBAEBBFF5ULL,
		0x3D84841DBE131A2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCF7413DBBB3CA15ULL,
		0x0E398BCE9041C85BULL,
		0x2E028D46792D6211ULL,
		0xB1DBB47D6B54F277ULL,
		0x89752F6897FFBAEAULL,
		0x10982FFC1A18821CULL,
		0x68915F7E28613E4CULL,
		0x7244C54358438591ULL
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
		0x441E092BEB996EF3ULL,
		0xB578ABFBBA9A8FE6ULL,
		0xFDB3130E9F0D3099ULL,
		0xD550C9400E28DF92ULL,
		0xEC1B6D77C5462299ULL,
		0xC92F2B71AA7F6534ULL,
		0x5CFCF2F147650ABCULL,
		0x7BD5327EF21212FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA9249D00AE1AEF8ULL,
		0xD875DD1338B8ACF6ULL,
		0xB946297BBF560224ULL,
		0xC6073086E24075F6ULL,
		0xDF95D2D828DAAB15ULL,
		0xDC1AD9BAC1FBF654ULL,
		0x4BE4B65BE08057BEULL,
		0x634974E8709EABCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x698BBF5BE0B7BFFBULL,
		0xDD02CEE881E1E2EFULL,
		0x446CE992DFB72E74ULL,
		0x0F4998B92BE8699CULL,
		0x0C859A9F9C6B7784ULL,
		0xED1451B6E8836EE0ULL,
		0x11183C9566E4B2FDULL,
		0x188BBD9681736732ULL
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
		0x72565035B9BA5E17ULL,
		0xA7A9AEC80E525BBCULL,
		0x04636372DC5CDD2EULL,
		0xA1FFB3FFCFDBE617ULL,
		0x109A1A4DE8979169ULL,
		0x8B70C3FE1C5A0B0AULL,
		0x0D2F8EDA15621BA7ULL,
		0xDE45E63C614E2BE6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBB47971B8BC31FULL,
		0xD41F87959E5E260CULL,
		0x9DCA021972AA75A7ULL,
		0x71F158CCACEC5ED6ULL,
		0x3555030992C6C279ULL,
		0x9888112EDD30488DULL,
		0x262E8FED3F6CE1E5ULL,
		0x492F0214D2002D95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD69B089E9E2E9AF8ULL,
		0xD38A27326FF435AFULL,
		0x6699615969B26786ULL,
		0x300E5B3322EF8740ULL,
		0xDB45174455D0CEF0ULL,
		0xF2E8B2CF3F29C27CULL,
		0xE700FEECD5F539C1ULL,
		0x9516E4278F4DFE50ULL
	}};
	sign = 0;
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
		0x7D0426449AE0D354ULL,
		0x007990BDFCD212FEULL,
		0x5CD40E129185D073ULL,
		0xA523EFCE2966D897ULL,
		0xA43E688766062407ULL,
		0x068CCF65511E0339ULL,
		0xD7134FCFDC7A3025ULL,
		0xC13D54516E4CDCC7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D014DE3AEF1E6CDULL,
		0xEED34C0CBAFFB78CULL,
		0x085E7843CDA93335ULL,
		0xE5FEB55C5696A196ULL,
		0x41B187CB784CB75CULL,
		0x132DEA8394C301A5ULL,
		0xA80455ADB870C62FULL,
		0x8017087C97E0EB52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0002D860EBEEEC87ULL,
		0x11A644B141D25B72ULL,
		0x547595CEC3DC9D3DULL,
		0xBF253A71D2D03701ULL,
		0x628CE0BBEDB96CAAULL,
		0xF35EE4E1BC5B0194ULL,
		0x2F0EFA22240969F5ULL,
		0x41264BD4D66BF175ULL
	}};
	sign = 0;
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
		0xC2CFB1165BAAD0C4ULL,
		0xEC7D913BD39FA5B5ULL,
		0x47C82214D48F06B8ULL,
		0x196D9B69AACB8DE7ULL,
		0x4BF49E155EAFDEA8ULL,
		0xC5A21293F05A0380ULL,
		0x16ACE99BC2574F6BULL,
		0xDC4927D482EC0D16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE76C320A4C96236ULL,
		0xA4554C7B1D01046BULL,
		0xE0B276B8F18B25FDULL,
		0xB57EB3DC05AD9E2BULL,
		0x5DD2F7FD7A8B86BCULL,
		0xA34EFDE4A46DC586ULL,
		0x123021E1C55E0DABULL,
		0x3C4EB61FFAF040E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC458EDF5B6E16E8EULL,
		0x482844C0B69EA149ULL,
		0x6715AB5BE303E0BBULL,
		0x63EEE78DA51DEFBBULL,
		0xEE21A617E42457EBULL,
		0x225314AF4BEC3DF9ULL,
		0x047CC7B9FCF941C0ULL,
		0x9FFA71B487FBCC34ULL
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