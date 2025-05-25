#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0x1E1DBB060B9A1013ULL,
		0x5F5B28C7C1EF7C4CULL,
		0xB1E5BC0D051F1D54ULL,
		0x1220CA6BB885A11FULL,
		0x68F992B2B1EC2C7FULL,
		0x7A6078D1B94ED562ULL,
		0xC581AF8D4F55DC5DULL,
		0xBBFF0A06286F314DULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0xECEFB83DEB1B905EULL,
		0xDBDA48A3EFB35AACULL,
		0xBDAA737B53BE4475ULL,
		0x124222034BDD347DULL,
		0xD0F1DC7D940F94EEULL,
		0xA6E45BD3D9B89D7FULL,
		0x3BC689D6D8DA65FEULL,
		0xC43A4E51093F1F22ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x312E02C8207E7FB5ULL,
		0x8380E023D23C219FULL,
		0xF43B4891B160D8DEULL,
		0xFFDEA8686CA86CA1ULL,
		0x9807B6351DDC9790ULL,
		0xD37C1CFDDF9637E2ULL,
		0x89BB25B6767B765EULL,
		0xF7C4BBB51F30122BULL
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
		0xAD6A78A4178CC88FULL,
		0xD621B0EEDA51638FULL,
		0x1970AF7DA79BCACAULL,
		0x2490A34CC051A3B6ULL,
		0x436B8DD89A6FCB8CULL,
		0xF3B8A36875414D7EULL,
		0x326B047F3D123A2FULL,
		0x4B43C3A6CAB6D239ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x331F523AE897FD0CULL,
		0x0774A0BC2EDDB717ULL,
		0x49F8A0D1B4EFB62BULL,
		0xB16382383E92F474ULL,
		0xD3ADFE361EB4A587ULL,
		0x4463BA8F581631B8ULL,
		0x67D20CC77D46E967ULL,
		0xDC21E3E6672FC073ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A4B26692EF4CB83ULL,
		0xCEAD1032AB73AC78ULL,
		0xCF780EABF2AC149FULL,
		0x732D211481BEAF41ULL,
		0x6FBD8FA27BBB2604ULL,
		0xAF54E8D91D2B1BC5ULL,
		0xCA98F7B7BFCB50C8ULL,
		0x6F21DFC0638711C5ULL
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
		0xBE355642CB397044ULL,
		0xE8DF759041490902ULL,
		0xD214292392844291ULL,
		0xBE3DF55F0B2642B8ULL,
		0x0EDE24168AB2322EULL,
		0x3D923B6043A4FE28ULL,
		0x2E444A3C01DA7900ULL,
		0x020E62D84A7D3138ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA8E81A9DC78E60DULL,
		0x5158EA904D46A959ULL,
		0x704B61B0A56EA6E6ULL,
		0xEB93213E86FE4495ULL,
		0xB0B78BDB2EBABE26ULL,
		0x979192E15B00AF10ULL,
		0xD5270289501B3F02ULL,
		0x6869B9E71E79A056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3A6D498EEC08A37ULL,
		0x97868AFFF4025FA8ULL,
		0x61C8C772ED159BABULL,
		0xD2AAD4208427FE23ULL,
		0x5E26983B5BF77407ULL,
		0xA600A87EE8A44F17ULL,
		0x591D47B2B1BF39FDULL,
		0x99A4A8F12C0390E1ULL
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
		0xCE1D86129C0E2D14ULL,
		0xBEAC433BD5B74DCAULL,
		0x12D5152CD48E79A5ULL,
		0xD2B5739D313529BBULL,
		0x46CC86BCDF3A40C3ULL,
		0xE09B0CD6E3F40B83ULL,
		0xF7E55702577B6835ULL,
		0x7E2E9DE550E58CD5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x072F57D8BD86E082ULL,
		0x0A4C2ECDAC7C926BULL,
		0xDA3DB04CE7A0C249ULL,
		0x96B680C01115B109ULL,
		0xFD07468C2A3CA4CBULL,
		0xF2A1C563E52A38ADULL,
		0x503F2F690B5F2F1EULL,
		0xEE12192943213FDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6EE2E39DE874C92ULL,
		0xB460146E293ABB5FULL,
		0x389764DFECEDB75CULL,
		0x3BFEF2DD201F78B1ULL,
		0x49C54030B4FD9BF8ULL,
		0xEDF94772FEC9D2D5ULL,
		0xA7A627994C1C3916ULL,
		0x901C84BC0DC44CFBULL
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
		0x55B9177CD1583D44ULL,
		0x18EF10254162E863ULL,
		0x435DE89100EE92CAULL,
		0xA40B277C34FF51EBULL,
		0x49AEBE54FEDA9398ULL,
		0xCED379D6EC7849A7ULL,
		0x42F0AA2E38C895C6ULL,
		0x7D0861FAC9BC6766ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE06DF9078E1F9FULL,
		0x19CC2F134BD8C54DULL,
		0x247A48623D797D20ULL,
		0x5651990603F03DF8ULL,
		0xF1397424F8A91211ULL,
		0x0CFF5BEE878E725BULL,
		0xDF49B07B7FEF99CBULL,
		0xEBD7CB5F37BBDA7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65D8A983C9CA1DA5ULL,
		0xFF22E111F58A2315ULL,
		0x1EE3A02EC37515A9ULL,
		0x4DB98E76310F13F3ULL,
		0x58754A3006318187ULL,
		0xC1D41DE864E9D74BULL,
		0x63A6F9B2B8D8FBFBULL,
		0x9130969B92008CE8ULL
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
		0xAA22AE5FB73CA6B1ULL,
		0x8CF14F0F1CEDC57BULL,
		0xDC782EE843D65D43ULL,
		0xC91D2250257E092DULL,
		0x08E264FB84554937ULL,
		0xA958F6EBD116FA7FULL,
		0xF06528058C944B3FULL,
		0xE5E03FE9785F37DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8492407CA25718DEULL,
		0xFBB2C19C9031140AULL,
		0xC42C5F901A5CC211ULL,
		0x2912A2E42C3B6BB9ULL,
		0xCB0D167CA50A3180ULL,
		0xD186FF6FBD539CDFULL,
		0x3712EEC4AF984864ULL,
		0xD5E005E3C342A4D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25906DE314E58DD3ULL,
		0x913E8D728CBCB171ULL,
		0x184BCF5829799B31ULL,
		0xA00A7F6BF9429D74ULL,
		0x3DD54E7EDF4B17B7ULL,
		0xD7D1F77C13C35D9FULL,
		0xB9523940DCFC02DAULL,
		0x10003A05B51C930BULL
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
		0xD09FD4BB7BF8361AULL,
		0x4B03EC156D915431ULL,
		0xA018C1CA3B51F8DCULL,
		0xC0444C00E5E2BCAAULL,
		0x4AEF7E97B2CB0313ULL,
		0xD85C7E32C8852A1BULL,
		0xAD2A2AF81054F448ULL,
		0x84DD29CDAD8F13B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A48AF67BA9F1477ULL,
		0x946BC2ED017C8F3AULL,
		0x751D6E8A4D545742ULL,
		0xE142A8B4DE40FE25ULL,
		0x1113ED454A3CAA36ULL,
		0x56EB73D023D318E0ULL,
		0xDDBDBC9DC3308E2EULL,
		0xB73E4328EF1D1A82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6572553C15921A3ULL,
		0xB69829286C14C4F7ULL,
		0x2AFB533FEDFDA199ULL,
		0xDF01A34C07A1BE85ULL,
		0x39DB9152688E58DCULL,
		0x81710A62A4B2113BULL,
		0xCF6C6E5A4D24661AULL,
		0xCD9EE6A4BE71F92FULL
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
		0x56EF577F8AAA8AD3ULL,
		0x43CA430F35E34E6CULL,
		0x68CC77041194735DULL,
		0x6F6B8B66265A864FULL,
		0x1613830069FD3722ULL,
		0x5D12D8AEEC905A4FULL,
		0x2A490AC46ED55A91ULL,
		0x255BA45126B1923BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E44F70811D5123ULL,
		0xBE41FF0CCBDCF920ULL,
		0x13535C8DE3A98752ULL,
		0x30CA65D1722CB77BULL,
		0xA7ED5F0D5DD35328ULL,
		0x430FD745A001A89BULL,
		0x8BDB80C8F461DA32ULL,
		0xB86B2E3D6C7D10D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D0B080F098D39B0ULL,
		0x858844026A06554CULL,
		0x55791A762DEAEC0AULL,
		0x3EA12594B42DCED4ULL,
		0x6E2623F30C29E3FAULL,
		0x1A0301694C8EB1B3ULL,
		0x9E6D89FB7A73805FULL,
		0x6CF07613BA348167ULL
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
		0x115B4DCB834B88CCULL,
		0xC06C6EECFFE93772ULL,
		0xAFD43955DC4E42E2ULL,
		0x66F8AEC813E886B2ULL,
		0x3CADE3050B680B1AULL,
		0x96EFA90D1A60A99EULL,
		0x1F8DB2226B321AF6ULL,
		0xC96457FDD3BC5944ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00DC65D9454DF22ULL,
		0xC326FFAC9276E4ECULL,
		0x485B17017B8D5AEFULL,
		0x387BD6C9B904F49BULL,
		0x0144E54813AC4A60ULL,
		0x784698CDEB5FC37EULL,
		0xCC62AC98A0FEA727ULL,
		0xA977B62273492656ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x314D876DEEF6A9AAULL,
		0xFD456F406D725285ULL,
		0x6779225460C0E7F2ULL,
		0x2E7CD7FE5AE39217ULL,
		0x3B68FDBCF7BBC0BAULL,
		0x1EA9103F2F00E620ULL,
		0x532B0589CA3373CFULL,
		0x1FECA1DB607332EDULL
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
		0x0F0D058F83365564ULL,
		0x0330165F33D7C197ULL,
		0xC037879E52691B57ULL,
		0x04D3B11FD96884E6ULL,
		0x91431CD5D4B9EAB2ULL,
		0xC19145553058BC92ULL,
		0xB2D677D855AE528DULL,
		0x73BC0340E6CE5562ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB45919EF78E076ULL,
		0x2A510C9A98C0280CULL,
		0xD02E1B01FA9955A6ULL,
		0x7134BE6C8F6DBFDFULL,
		0x305289DE60507D2EULL,
		0x5B5E38C85077C7ABULL,
		0xA4745756B01B983AULL,
		0xEBF099EF44666158ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC258AC7593BD74EEULL,
		0xD8DF09C49B17998AULL,
		0xF0096C9C57CFC5B0ULL,
		0x939EF2B349FAC506ULL,
		0x60F092F774696D83ULL,
		0x66330C8CDFE0F4E7ULL,
		0x0E622081A592BA53ULL,
		0x87CB6951A267F40AULL
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
		0xAB4680BF6D1D6FF9ULL,
		0x53AC940E643006BEULL,
		0xD688E33DFFC42A78ULL,
		0x7F8D446C818650EBULL,
		0xB60F1E475E9B3A29ULL,
		0x7A45E481CDD04D05ULL,
		0x1F00EC4F6E70283EULL,
		0x589D01C3824B7D69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16CDC06ED68BB731ULL,
		0xD42D645CA3F408F4ULL,
		0x28726751C6653EB2ULL,
		0x3E71163E46901554ULL,
		0x71630162BAE87478ULL,
		0x5CCDB5E479704067ULL,
		0xD4D90CDA07E66B4BULL,
		0xB753E437E20436FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9478C0509691B8C8ULL,
		0x7F7F2FB1C03BFDCAULL,
		0xAE167BEC395EEBC5ULL,
		0x411C2E2E3AF63B97ULL,
		0x44AC1CE4A3B2C5B1ULL,
		0x1D782E9D54600C9EULL,
		0x4A27DF756689BCF3ULL,
		0xA1491D8BA047466DULL
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
		0x7497651761A1C4B6ULL,
		0xE2E6E6E58EE7E41AULL,
		0x56193D5DD4003FDCULL,
		0x59CC42A4D70039E6ULL,
		0x2F049050A0978DC6ULL,
		0x5FE11CA19D6D3711ULL,
		0x95739B8388E31503ULL,
		0xB490BD3D16D52AB7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5B2792EFF464B6ULL,
		0x6B2AB05B9CE2EAE8ULL,
		0x4EA02F8606F4F6A4ULL,
		0xF5B2441092B279B6ULL,
		0xF2A52ABAC31E41D9ULL,
		0x4E19AF21A2415B82ULL,
		0xCBE4F4054BAD8168ULL,
		0x2347FD2E348E805FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x273C3D8471AD6000ULL,
		0x77BC3689F204F932ULL,
		0x07790DD7CD0B4938ULL,
		0x6419FE94444DC030ULL,
		0x3C5F6595DD794BECULL,
		0x11C76D7FFB2BDB8EULL,
		0xC98EA77E3D35939BULL,
		0x9148C00EE246AA57ULL
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
		0x64B47593858FD373ULL,
		0xB78F52CC4155CC4AULL,
		0x824DA99F6AC6FA41ULL,
		0x62A0D07A2C6E3947ULL,
		0xAA914011C74756A6ULL,
		0x19EF34EB0579AC70ULL,
		0x206657A35DC17868ULL,
		0xB1211D9C8CFF6E81ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E0472ABFC3C59BULL,
		0x8E00C2514587A69EULL,
		0x9B15AD0D16C21423ULL,
		0x0E8FC4F79BAE07D0ULL,
		0x00719CAA1901CE63ULL,
		0x18258BDCD6F4D657ULL,
		0x52C63BC7BCACAA73ULL,
		0x0371A25F5DD4FF62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD42E68C5CC0DD8ULL,
		0x298E907AFBCE25ACULL,
		0xE737FC925404E61EULL,
		0x54110B8290C03176ULL,
		0xAA1FA367AE458843ULL,
		0x01C9A90E2E84D619ULL,
		0xCDA01BDBA114CDF5ULL,
		0xADAF7B3D2F2A6F1EULL
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
		0xF9BC2D68791FE0C0ULL,
		0x20EFE35F8415CA72ULL,
		0xC8C3C20160A0BF83ULL,
		0x107047C31776CE6BULL,
		0x7EB1E28AFC9E6632ULL,
		0x00834C7EF485C82BULL,
		0xAE9FC6D2AB193CABULL,
		0x35243ED03B60E4B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6FC3BD336448F29ULL,
		0xE216758D2B3E0B95ULL,
		0xA11E3CCB73BD5D0DULL,
		0x663C1752F255A3C2ULL,
		0x5FA7725801BEB657ULL,
		0x69CCCEE566E87534ULL,
		0x513896C2CB105994ULL,
		0x807F7C8EDDC18C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02BFF19542DB5197ULL,
		0x3ED96DD258D7BEDDULL,
		0x27A58535ECE36275ULL,
		0xAA34307025212AA9ULL,
		0x1F0A7032FADFAFDAULL,
		0x96B67D998D9D52F7ULL,
		0x5D67300FE008E316ULL,
		0xB4A4C2415D9F5838ULL
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
		0x6B03F1412A996DEBULL,
		0x2E34B4CF42C9D63AULL,
		0xE32A20F46B1D1247ULL,
		0x28E33357A4DE0DE2ULL,
		0x0381A91ED9AF4BE5ULL,
		0x3F8384BC1AC39CA7ULL,
		0x8FEB15F98DB47FC5ULL,
		0xF043371D12614A24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B40F01460A7802ULL,
		0x6B81E82F74E61864ULL,
		0x95CDEA74C4EED713ULL,
		0x7A7FEEE54E35BDBAULL,
		0x25CFE46A1854D6CEULL,
		0x4889A6D0FD73D73AULL,
		0x5A6D22D3BEA9080BULL,
		0x82E89B9896371812ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF64FE23FE48EF5E9ULL,
		0xC2B2CC9FCDE3BDD5ULL,
		0x4D5C367FA62E3B33ULL,
		0xAE63447256A85028ULL,
		0xDDB1C4B4C15A7516ULL,
		0xF6F9DDEB1D4FC56CULL,
		0x357DF325CF0B77B9ULL,
		0x6D5A9B847C2A3212ULL
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
		0xEF3612683AB44880ULL,
		0x0E1CD8114E87F692ULL,
		0x868D63AD31517F0FULL,
		0x78172CF4730093FAULL,
		0x758B9092D3D20A8AULL,
		0x627E5E38EAFCC896ULL,
		0x6B35815909985541ULL,
		0x571C9FE3C4D2783AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD66D9376C16870EULL,
		0x71B41AB92BEABF34ULL,
		0x979F4734EF54B80CULL,
		0xE534A1D35749DB3CULL,
		0x34CB606A5A48B159ULL,
		0x93E8ED1AB59FCB6DULL,
		0xE28F17548A2FC349ULL,
		0x1CF5849305705DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41CF3930CE9DC172ULL,
		0x9C68BD58229D375EULL,
		0xEEEE1C7841FCC702ULL,
		0x92E28B211BB6B8BDULL,
		0x40C0302879895930ULL,
		0xCE95711E355CFD29ULL,
		0x88A66A047F6891F7ULL,
		0x3A271B50BF621A3FULL
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
		0x951724D274AD7E0FULL,
		0xFFFE6A474F525D95ULL,
		0x4003606F1EFCDEF1ULL,
		0x9D9883D9AE317A19ULL,
		0xB53C2F35D5CB4F86ULL,
		0x835BFC7415984A77ULL,
		0x7D8674721C47DEA0ULL,
		0xEA25BF1ADEB6DECCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5277EEC2BEDEA04ULL,
		0xCCC961E1AE9804B9ULL,
		0x2E3B8D8B9528A148ULL,
		0xC8EB3535E35BC48BULL,
		0x66B2DD4EDD3C524EULL,
		0x7DB308AC796D0974ULL,
		0xD4D5F45EA0AB1EDFULL,
		0x7996C4D855F3EA4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFEFA5E648BF940BULL,
		0x33350865A0BA58DBULL,
		0x11C7D2E389D43DA9ULL,
		0xD4AD4EA3CAD5B58EULL,
		0x4E8951E6F88EFD37ULL,
		0x05A8F3C79C2B4103ULL,
		0xA8B080137B9CBFC1ULL,
		0x708EFA4288C2F480ULL
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
		0x911F135E66495B75ULL,
		0x1AFEF99037A32D92ULL,
		0x4F59AEA1D8A684F0ULL,
		0x67F9E220599D0D5EULL,
		0xE74D4688F555EF36ULL,
		0xD2E345FF0346CA92ULL,
		0xFB37EF349E7A9BB0ULL,
		0xEBADB3D299D833CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEC53E13ABD5575ULL,
		0xC2F5D8B6A1986606ULL,
		0x792E30E9DE2EED29ULL,
		0x48E712F2F2E40BEEULL,
		0x1A640C4E2726BABBULL,
		0x6D2B39A899494A50ULL,
		0x38F6E2710DDED73BULL,
		0xB25ACEC7D7226B87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4232BF7D2B8C0600ULL,
		0x580920D9960AC78CULL,
		0xD62B7DB7FA7797C6ULL,
		0x1F12CF2D66B9016FULL,
		0xCCE93A3ACE2F347BULL,
		0x65B80C5669FD8042ULL,
		0xC2410CC3909BC475ULL,
		0x3952E50AC2B5C848ULL
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
		0x4FA34CFEA7B0AD08ULL,
		0x82C867B6BDBE9771ULL,
		0x76D1B7D0078E6D96ULL,
		0xEB1784D73EEFAD93ULL,
		0x18CD86026F74C46BULL,
		0x0DC97274B2240E06ULL,
		0xD8B39D66C33446E7ULL,
		0x1819A609EC495FBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFABC3AE40783CE4ULL,
		0x5D095985CD93F3E6ULL,
		0xBFEEC2F8F82BC194ULL,
		0x6FE720B3B89769D1ULL,
		0x50115E5B7A922EE6ULL,
		0xD7FDFC07CF386650ULL,
		0xF086E2EE5AB2BB75ULL,
		0x2619EB7E0903E30FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FF7895067387024ULL,
		0x25BF0E30F02AA38AULL,
		0xB6E2F4D70F62AC02ULL,
		0x7B306423865843C1ULL,
		0xC8BC27A6F4E29585ULL,
		0x35CB766CE2EBA7B5ULL,
		0xE82CBA7868818B71ULL,
		0xF1FFBA8BE3457CADULL
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
		0x168A8E691195F9C5ULL,
		0x03BE85757C53B24CULL,
		0xD38A2C1E58385939ULL,
		0x61443D595B757D2DULL,
		0x1603C28900B4C97FULL,
		0x03336E68324B7F63ULL,
		0x27D9350669B6D24FULL,
		0x80A15B0A4A6005CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD458263A8DFD778CULL,
		0xFB927E46DF8D28B6ULL,
		0xC235D82465A8580BULL,
		0x23A2CD3072DD579EULL,
		0xD530D0E6D7E58E3EULL,
		0xF13EA6E136BFC99FULL,
		0xF40416C0C025AFC0ULL,
		0xD5B741793DE1D9D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4232682E83988239ULL,
		0x082C072E9CC68995ULL,
		0x115453F9F290012DULL,
		0x3DA17028E898258FULL,
		0x40D2F1A228CF3B41ULL,
		0x11F4C786FB8BB5C3ULL,
		0x33D51E45A991228EULL,
		0xAAEA19910C7E2BF5ULL
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
		0x5E9D1F10A9C7504DULL,
		0xE8BB1D2DD78C4843ULL,
		0xAB837252F0E72576ULL,
		0x1C2E211619BD2FCBULL,
		0x169CFFD95F06F6D9ULL,
		0x6D5B1BA73DC5B852ULL,
		0x1F89051E10ABD35FULL,
		0xE37BC44C90512225ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x330428E281C7997BULL,
		0x9C381D20F45D95BDULL,
		0x2F46ABDA3FE1E00DULL,
		0xACFA2CDE48E3C74DULL,
		0xB333C745754187DDULL,
		0xC478301AAABB0A30ULL,
		0x76A9F1278F39DB4DULL,
		0x776C28161807B2E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B98F62E27FFB6D2ULL,
		0x4C83000CE32EB286ULL,
		0x7C3CC678B1054569ULL,
		0x6F33F437D0D9687EULL,
		0x63693893E9C56EFBULL,
		0xA8E2EB8C930AAE21ULL,
		0xA8DF13F68171F811ULL,
		0x6C0F9C3678496F3FULL
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
		0x3A22969FFF9FDA1CULL,
		0x8640CF5574FD695EULL,
		0x3806C1613A2960D5ULL,
		0xAA2F7B9E6527693BULL,
		0x747867553D7C3206ULL,
		0x9666FBC52515A021ULL,
		0x48DA08FD86BCEE08ULL,
		0xD1D73C51E245B573ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DCB956609150C28ULL,
		0x165C530F34D7E82BULL,
		0x9266E8F5E9CD4F0CULL,
		0x69D801D6BA910503ULL,
		0x916A3804C19D71B9ULL,
		0x7D66AEB9EA37D1F5ULL,
		0x0BB3E7D0BA4B7F54ULL,
		0xB6F90656E3DD5CA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C570139F68ACDF4ULL,
		0x6FE47C4640258133ULL,
		0xA59FD86B505C11C9ULL,
		0x405779C7AA966437ULL,
		0xE30E2F507BDEC04DULL,
		0x19004D0B3ADDCE2BULL,
		0x3D26212CCC716EB4ULL,
		0x1ADE35FAFE6858D2ULL
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
		0x6B3E7A5417C228BDULL,
		0xCF847F52059821EEULL,
		0x1FB74D8212662E24ULL,
		0x21039496472B3331ULL,
		0xAF9E8C35D59C0C5BULL,
		0x2ACB3507277154A6ULL,
		0xC2D06179D63F86D6ULL,
		0x4340673C4BD80DA6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C652ECDB33E28D1ULL,
		0x84B2BAE400649875ULL,
		0xF89AB1DAFABFD504ULL,
		0x47D71DA36DFAF232ULL,
		0xAE697402408058B4ULL,
		0xC70F703D7B5AF579ULL,
		0xAE69EDAF9E4FE376ULL,
		0x00A10B9224169852ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ED94B866483FFECULL,
		0x4AD1C46E05338979ULL,
		0x271C9BA717A65920ULL,
		0xD92C76F2D93040FEULL,
		0x01351833951BB3A6ULL,
		0x63BBC4C9AC165F2DULL,
		0x146673CA37EFA35FULL,
		0x429F5BAA27C17554ULL
	}};
	sign = 0;
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
		0xA76174C4CC4B4665ULL,
		0x54F096C18C94A324ULL,
		0x65F1DC9BA349FAE4ULL,
		0x335646F06C8BB025ULL,
		0xE44D31B5E7A47169ULL,
		0x37C6B1A1B805F3D2ULL,
		0xA5D960274177035DULL,
		0x05AD98D36FF3DF48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA765E681316EA5FULL,
		0x588976ACCA00ECD5ULL,
		0xD0D7550980FA8A38ULL,
		0xF6AEE63EAE9C3682ULL,
		0x72C400B9C513CC9EULL,
		0x92D8A404A05092AAULL,
		0x572C9D69340B6560ULL,
		0x507CE59DCF19375AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCEB165CB9345C06ULL,
		0xFC672014C293B64EULL,
		0x951A8792224F70ABULL,
		0x3CA760B1BDEF79A2ULL,
		0x718930FC2290A4CAULL,
		0xA4EE0D9D17B56128ULL,
		0x4EACC2BE0D6B9DFCULL,
		0xB530B335A0DAA7EEULL
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
		0xFFD43296E52DF360ULL,
		0x073732DC45728751ULL,
		0x8D505CAC52208B66ULL,
		0x6EA413AD881FEAA8ULL,
		0xC461BAB4D108E0C9ULL,
		0xE391F0D6BB306D3AULL,
		0xFA4F5BD9537E3559ULL,
		0x5414645D9BC0C7E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66012850F0EBBA68ULL,
		0xD52EF083DE0CF12AULL,
		0xD274B30D7738F9A6ULL,
		0x925E42A4DBB9A667ULL,
		0x310E85C09330FC86ULL,
		0x84A5779F4C5470C0ULL,
		0x02C4A817CCC463A1ULL,
		0x0E2D7F222760F97BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99D30A45F44238F8ULL,
		0x3208425867659627ULL,
		0xBADBA99EDAE791BFULL,
		0xDC45D108AC664440ULL,
		0x935334F43DD7E442ULL,
		0x5EEC79376EDBFC7AULL,
		0xF78AB3C186B9D1B8ULL,
		0x45E6E53B745FCE67ULL
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
		0x117BC392CD2BBBAAULL,
		0x3DD7C85282A23408ULL,
		0xE1563DD05E54AE47ULL,
		0x88F172A84DD32820ULL,
		0x3111E220C93207B7ULL,
		0x6C4740AF4CB05C70ULL,
		0x417558137BFCAF4EULL,
		0x05648F4894CA9DF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1869E2446E6BAF4ULL,
		0xA87F28A88698BECAULL,
		0xD1BEC28439A4FBCBULL,
		0x48EC32354BB2932AULL,
		0x610C0A63D30A66D7ULL,
		0xF69D408B395DED06ULL,
		0xB1CE248C4EE7E0F6ULL,
		0x154301E16472BD50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FF5256E864500B6ULL,
		0x95589FA9FC09753DULL,
		0x0F977B4C24AFB27BULL,
		0x40054073022094F6ULL,
		0xD005D7BCF627A0E0ULL,
		0x75AA002413526F69ULL,
		0x8FA733872D14CE57ULL,
		0xF0218D673057E09FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8B192832DEA5E0DCULL,
		0x7072E67764668093ULL,
		0x66649D5BCC3D5062ULL,
		0x1EBFCDCD3F8EFB0BULL,
		0x20863B9226A18594ULL,
		0x7476B3BE757646A9ULL,
		0x984B614802837ED0ULL,
		0x2E55ABCBE6C8ACECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89B14B3D70F9951ULL,
		0x3B2B2DA5A66EF34EULL,
		0x202E04F234EE9005ULL,
		0xDAD6417309B2A790ULL,
		0x8942F4452332D76EULL,
		0x3D01885C63E9C257ULL,
		0xAE3FB2FD66C6BCF9ULL,
		0x37B27397A2F7D019ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC27E137F0796478BULL,
		0x3547B8D1BDF78D44ULL,
		0x46369869974EC05DULL,
		0x43E98C5A35DC537BULL,
		0x9743474D036EAE25ULL,
		0x37752B62118C8451ULL,
		0xEA0BAE4A9BBCC1D7ULL,
		0xF6A3383443D0DCD2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6450FF9F44FE783AULL,
		0xA005E1E19F9A9EBCULL,
		0x18845279E52D7CD9ULL,
		0xAF0450E905244A7BULL,
		0x1EF1EA956910C40DULL,
		0x34D98272A4F7582AULL,
		0x1A5790197603EE28ULL,
		0xCDE9358061B7B14FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x970852FE239BEB94ULL,
		0x20C302CB9F3AE9E7ULL,
		0xDC161BC2A5D62C06ULL,
		0x6BF854A2E5BED033ULL,
		0xFCB8FC58D6F4BF68ULL,
		0x451C87571FCD3E81ULL,
		0x50889FE0CDFD5256ULL,
		0xB5EB506BDBEB6C2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD48ACA121628CA6ULL,
		0x7F42DF16005FB4D4ULL,
		0x3C6E36B73F5750D3ULL,
		0x430BFC461F657A47ULL,
		0x2238EE3C921C04A5ULL,
		0xEFBCFB1B852A19A8ULL,
		0xC9CEF038A8069BD1ULL,
		0x17FDE51485CC4522ULL
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
		0x1C98EFBAAF4FF8B8ULL,
		0x504852EF6C54302AULL,
		0x213925C2AEDA54EAULL,
		0x8A12BE1781AA3704ULL,
		0x6B1ADE209680FC0CULL,
		0x5CA529FC1891215FULL,
		0xEF15FBAACF4CB311ULL,
		0x6B9FA7D4A7B5D107ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11543786C155B8B8ULL,
		0xCE0AEB49842326A5ULL,
		0x957EB41F10140D18ULL,
		0xA196D7D4C9CD943EULL,
		0x6AA4484CD5646437ULL,
		0xFC34F1E9098B1A53ULL,
		0x49EEDB2BDB15AB24ULL,
		0x8562A003094420EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B44B833EDFA4000ULL,
		0x823D67A5E8310985ULL,
		0x8BBA71A39EC647D1ULL,
		0xE87BE642B7DCA2C5ULL,
		0x007695D3C11C97D4ULL,
		0x607038130F06070CULL,
		0xA527207EF43707ECULL,
		0xE63D07D19E71B018ULL
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
		0xFFB251A4036118B7ULL,
		0x6F031644CC074F27ULL,
		0x9605CA0BD674D74AULL,
		0x71859D8806B1E106ULL,
		0x5CDDB1972A46729BULL,
		0x003CEE2DEBE441A9ULL,
		0x82C275AAC0794D60ULL,
		0x124BF55DE54F33AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB65FA400981D5CULL,
		0x506B8FC9339F2239ULL,
		0x34D858D6B07C6B44ULL,
		0x5586FC846098BAA0ULL,
		0x728B23DFACB3997BULL,
		0xDFC80E37F6C3C8EEULL,
		0xC68928303725B31FULL,
		0xA1C6291D2AE76CFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70FBF20002C8FB5BULL,
		0x1E97867B98682CEEULL,
		0x612D713525F86C06ULL,
		0x1BFEA103A6192666ULL,
		0xEA528DB77D92D920ULL,
		0x2074DFF5F52078BAULL,
		0xBC394D7A89539A40ULL,
		0x7085CC40BA67C6B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xADF48A6EA38D8C31ULL,
		0x26BC46C42B6D0943ULL,
		0x4D7F786FA94CE5E0ULL,
		0x9DC03DEE5425A7ECULL,
		0x6CEA66A92F8E0C19ULL,
		0x462E959B26E2527FULL,
		0x3EDE1C90968D1DBAULL,
		0x3DE8C79553BD148EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x61C7A29DFBD31275ULL,
		0xA729F73E3D69ECCCULL,
		0xD854329A8F831AF1ULL,
		0xE37118EBD585BF0DULL,
		0x02F55074CDCC8E8EULL,
		0xFAB6342A9DDFD847ULL,
		0xD3705963B8B2F88BULL,
		0x9624C7C7733B2579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C2CE7D0A7BA79BCULL,
		0x7F924F85EE031C77ULL,
		0x752B45D519C9CAEEULL,
		0xBA4F25027E9FE8DEULL,
		0x69F5163461C17D8AULL,
		0x4B78617089027A38ULL,
		0x6B6DC32CDDDA252EULL,
		0xA7C3FFCDE081EF14ULL
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
		0x0479C223F5301E8CULL,
		0x8E7BF67986F8547DULL,
		0x466238D1EA58F52BULL,
		0xC972D0BDF5E6BA9FULL,
		0xCFF4D3120FC9068AULL,
		0x01965DEF2C7C01C1ULL,
		0xF047B110399EDBB5ULL,
		0x8E0DFF0D7A78A4DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x449AEEB2857A5FCBULL,
		0xD40CFF297410BA0BULL,
		0x642106C65404A157ULL,
		0x315626462B309FEDULL,
		0xA16627C77494F7E6ULL,
		0x53C63F37111DDF3CULL,
		0x435B6D15AC443486ULL,
		0x6F5053F8929F4AB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFDED3716FB5BEC1ULL,
		0xBA6EF75012E79A71ULL,
		0xE241320B965453D3ULL,
		0x981CAA77CAB61AB1ULL,
		0x2E8EAB4A9B340EA4ULL,
		0xADD01EB81B5E2285ULL,
		0xACEC43FA8D5AA72EULL,
		0x1EBDAB14E7D95A28ULL
	}};
	sign = 0;
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
		0xF7664B45967F3C79ULL,
		0x583907AEEB3162CDULL,
		0x5B36AB79A1EB5A52ULL,
		0x05B6746E072D7046ULL,
		0xD0E1061958AE253CULL,
		0x7B483D850073166BULL,
		0x52AADF746CBDBF70ULL,
		0x313F96345F2848BCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62AF28126665ECDDULL,
		0xCDF6832571A83EC9ULL,
		0x837B62A00B4B60CFULL,
		0x3164B031E5A59AB8ULL,
		0x8B881921A902BEF1ULL,
		0xB70018EA68E55CD1ULL,
		0x269E864144E488E3ULL,
		0xD5D9AB65902B04AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94B7233330194F9CULL,
		0x8A42848979892404ULL,
		0xD7BB48D9969FF982ULL,
		0xD451C43C2187D58DULL,
		0x4558ECF7AFAB664AULL,
		0xC448249A978DB99AULL,
		0x2C0C593327D9368CULL,
		0x5B65EACECEFD4412ULL
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
		0x1D21F729A826ED89ULL,
		0xF48CE76E6B4DADAFULL,
		0x5BACE043F5B0C997ULL,
		0xC446056024DC343BULL,
		0x28063C67E40B4358ULL,
		0x4AA82A777D149AECULL,
		0xE1FDFF8C259C8FDBULL,
		0x5A517F4B66FF1D14ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x94AC73317ECF3820ULL,
		0x74BB15FCE1BA4258ULL,
		0xCF333B7A835ED294ULL,
		0xB1D26E0DE5162A14ULL,
		0x6FBB839015B1A0EAULL,
		0xE4C2E0C6D52F076AULL,
		0x006985A05267794DULL,
		0x2E69FA12CB24845AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x887583F82957B569ULL,
		0x7FD1D17189936B56ULL,
		0x8C79A4C97251F703ULL,
		0x127397523FC60A26ULL,
		0xB84AB8D7CE59A26EULL,
		0x65E549B0A7E59381ULL,
		0xE19479EBD335168DULL,
		0x2BE785389BDA98BAULL
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
		0x221187CE546C8C7FULL,
		0x90AEE373412B8696ULL,
		0x34FF4EBEB2429911ULL,
		0x0FC4EF876359E0C2ULL,
		0x3C66A99899523589ULL,
		0x4A6C1742E18B70FAULL,
		0x6C9C6476DD588512ULL,
		0x03CF2C448AC7B8E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x458FF3516DF0052BULL,
		0x5E773982E8A03499ULL,
		0x7C4B0F6F8217F73EULL,
		0xDAF03170CF6CBC18ULL,
		0x1AE0BEB0D945A06EULL,
		0x5AEE0B74B5A99CECULL,
		0x197F5A2AFD3D54F3ULL,
		0xB80421EDD4263A42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC81947CE67C8754ULL,
		0x3237A9F0588B51FCULL,
		0xB8B43F4F302AA1D3ULL,
		0x34D4BE1693ED24A9ULL,
		0x2185EAE7C00C951AULL,
		0xEF7E0BCE2BE1D40EULL,
		0x531D0A4BE01B301EULL,
		0x4BCB0A56B6A17EA2ULL
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
		0xAFC75A40FC550129ULL,
		0x8C76309328939416ULL,
		0x212C28CA16AB489FULL,
		0x1E21AEB8F78D12D1ULL,
		0xC595D58E1FCAC8D2ULL,
		0x0AC08E34847B7434ULL,
		0xB5D5D8949225FF1DULL,
		0x48036A50B086BAA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7091701D67B30FAULL,
		0xA7589C1CA0C4D3DEULL,
		0xB30EC6E4DA0B51EFULL,
		0xD5C1695E9F8BA0B6ULL,
		0x360FE80685ACAD96ULL,
		0x2DD1FA82896ECE72ULL,
		0x547201DDEAA13904ULL,
		0x6221BD9FBA626675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8BE433F25D9D02FULL,
		0xE51D947687CEC037ULL,
		0x6E1D61E53C9FF6AFULL,
		0x4860455A5801721AULL,
		0x8F85ED879A1E1B3BULL,
		0xDCEE93B1FB0CA5C2ULL,
		0x6163D6B6A784C618ULL,
		0xE5E1ACB0F624542EULL
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
		0xB25F7C66D8C415F3ULL,
		0xCF9D690947E5F842ULL,
		0x459A736754894C61ULL,
		0xF97D5B01F8A7D1EAULL,
		0x085E00EAD1035472ULL,
		0xEAB6C49DCB7B9D9EULL,
		0xD46D09595CDF29E2ULL,
		0x55B305E881FF7B0AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB52B8955E46680EULL,
		0xFC476F478E481143ULL,
		0x3A47C193E2F23287ULL,
		0xC7B6A747AB47EC24ULL,
		0x934606FF9AA76D6DULL,
		0xB96DCB9BDA36160BULL,
		0xA19C4EEC658C92A2ULL,
		0x851546FE09209351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB70CC3D17A7DADE5ULL,
		0xD355F9C1B99DE6FEULL,
		0x0B52B1D3719719D9ULL,
		0x31C6B3BA4D5FE5C6ULL,
		0x7517F9EB365BE705ULL,
		0x3148F901F1458792ULL,
		0x32D0BA6CF7529740ULL,
		0xD09DBEEA78DEE7B9ULL
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
		0x5DA69B55973CDDB9ULL,
		0x8E50C297F3493C32ULL,
		0xE3425523CD99ADA4ULL,
		0x993BECC470B016ABULL,
		0x97D321900E227813ULL,
		0x5B4FBF46C532576AULL,
		0x13B841CEB52237FDULL,
		0xA5D3BF561FAFC693ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC12B3A3D64F19F6ULL,
		0xAE9B0C5D64026624ULL,
		0xC021DFC34D8465BFULL,
		0xB0E9C239E4DBE902ULL,
		0x94FEBFD4C306D816ULL,
		0xB00EA26BB35B20ABULL,
		0x0C1D92E974D91D93ULL,
		0xE067110A875C0FDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6193E7B1C0EDC3C3ULL,
		0xDFB5B63A8F46D60DULL,
		0x23207560801547E4ULL,
		0xE8522A8A8BD42DA9ULL,
		0x02D461BB4B1B9FFCULL,
		0xAB411CDB11D736BFULL,
		0x079AAEE540491A69ULL,
		0xC56CAE4B9853B6B5ULL
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
		0x2FAD27D420148C98ULL,
		0x27E2B0770D4482F5ULL,
		0xC9814C100FF303C9ULL,
		0xD1D1F3688E4A3B50ULL,
		0xCF882E02F42D84ADULL,
		0x2E89D93FA31D8793ULL,
		0xA7837710C6FB7ABFULL,
		0xDD5E74552B014F7FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36FF35573F5742B8ULL,
		0x9E211346C1911FEEULL,
		0x571BAE78F1E8F290ULL,
		0xD4B7641BE231756BULL,
		0xF83E9BDF641F5044ULL,
		0x6C2248133F64BB98ULL,
		0x72FF4CA609237AE7ULL,
		0xC9594E31D4533E8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8ADF27CE0BD49E0ULL,
		0x89C19D304BB36306ULL,
		0x72659D971E0A1138ULL,
		0xFD1A8F4CAC18C5E5ULL,
		0xD7499223900E3468ULL,
		0xC267912C63B8CBFAULL,
		0x34842A6ABDD7FFD7ULL,
		0x1405262356AE10F5ULL
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
		0x174E912C60E1F024ULL,
		0x263C9DD0EAEEAF0FULL,
		0xC9CA72EEA3F9773FULL,
		0xEC5AC51D1CFBD53BULL,
		0xCBC6AD6464796BB6ULL,
		0x3D2976B02EF21A68ULL,
		0xCE8BE6856056BADDULL,
		0x73C908B3C80EAE5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC41F17D514A249ULL,
		0xDB52EBBE912D9838ULL,
		0x8545FE203088BC42ULL,
		0x5A7C400EF5EB6E25ULL,
		0x0237100D63DDEF7FULL,
		0xE76DEED977FAE8E7ULL,
		0xB0D1C58425EE5B8FULL,
		0xBFED2A24E7EC0351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC8A72148BCD4DDBULL,
		0x4AE9B21259C116D6ULL,
		0x448474CE7370BAFCULL,
		0x91DE850E27106716ULL,
		0xC98F9D57009B7C37ULL,
		0x55BB87D6B6F73181ULL,
		0x1DBA21013A685F4DULL,
		0xB3DBDE8EE022AB0DULL
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
		0x5DC01E4CCADB52C8ULL,
		0x06C16C8AAF117409ULL,
		0xA59109E2127A843AULL,
		0x491B2ABB8E41822DULL,
		0x52E34932D030A269ULL,
		0xD0526786AAEC8A01ULL,
		0x5E11A41663D60CDCULL,
		0xFC8F17A26BA8BCD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F81A13B7D1BB17EULL,
		0xF3949999886A2DE7ULL,
		0x00FDDEB00C82BFC3ULL,
		0xD46178FE28B61A7CULL,
		0xAF2060624BD2C2EEULL,
		0x48234CD4F75E0580ULL,
		0x74C8442B873CA414ULL,
		0x5DF6C4DF9EA2734CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE3E7D114DBFA14AULL,
		0x132CD2F126A74621ULL,
		0xA4932B3205F7C476ULL,
		0x74B9B1BD658B67B1ULL,
		0xA3C2E8D0845DDF7AULL,
		0x882F1AB1B38E8480ULL,
		0xE9495FEADC9968C8ULL,
		0x9E9852C2CD06498BULL
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
		0x8525F59C2EB69554ULL,
		0x40CF4E287763E31CULL,
		0x9997B9E32099F85AULL,
		0x847E94B87DE768B8ULL,
		0xDD6BB3BBA68D718DULL,
		0x7C96D59B94EFE9BDULL,
		0xEFAF01914402081FULL,
		0x58B516C64FB52E89ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69AC653315F74EA1ULL,
		0xED643D109AE4F5DEULL,
		0xD8D1B538D5974BA0ULL,
		0xFF496CBE9721F03CULL,
		0xB282515E60C7FA6CULL,
		0x6E71F506A23AFDD8ULL,
		0xAB43C0FEFE2E2B6CULL,
		0xA06F4428CA6F6DA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B79906918BF46B3ULL,
		0x536B1117DC7EED3EULL,
		0xC0C604AA4B02ACB9ULL,
		0x853527F9E6C5787BULL,
		0x2AE9625D45C57720ULL,
		0x0E24E094F2B4EBE5ULL,
		0x446B409245D3DCB3ULL,
		0xB845D29D8545C0E7ULL
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
		0x4D3F49320BE56A2FULL,
		0x164F53F340CF223BULL,
		0x38DDB5A32D1D4008ULL,
		0xB1C4600EB152AC71ULL,
		0x32F31F99FAA900AEULL,
		0xF7E3DCA329DCAB71ULL,
		0x4112AD4C14842F90ULL,
		0x50CD08DC7EE67A60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6330D346720FF3ULL,
		0x79352AFB75E1ACDFULL,
		0xB97261F0453745F4ULL,
		0x69FB7953C6E75D68ULL,
		0xD140DC64BFC4BD4CULL,
		0xA800BA345E8C01A5ULL,
		0xAE1A08F5B77ACDFAULL,
		0x6CEC4B5A5A1147AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFDC185EC5735A3CULL,
		0x9D1A28F7CAED755BULL,
		0x7F6B53B2E7E5FA13ULL,
		0x47C8E6BAEA6B4F08ULL,
		0x61B243353AE44362ULL,
		0x4FE3226ECB50A9CBULL,
		0x92F8A4565D096196ULL,
		0xE3E0BD8224D532B1ULL
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
		0x4645031625F63686ULL,
		0xC35247953F93EE7DULL,
		0xF6B8B3C7083E7A29ULL,
		0x16CED69DA8CA8D1FULL,
		0x9C4F6D466FFA77FBULL,
		0xA44330DA36450416ULL,
		0x875DFC90B39242C8ULL,
		0x3B2BFDCAFBC0D881ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F73D0E2B429DAAULL,
		0xCB057B29C123084DULL,
		0x750B174DB14B3CA6ULL,
		0x0F2E637531898C7FULL,
		0x642D56CC00F3B6A1ULL,
		0x58E12CBFD9979D1FULL,
		0xC735F00BF22E29C9ULL,
		0xFB8AB7C3A37BA1B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x154DC607FAB398DCULL,
		0xF84CCC6B7E70E630ULL,
		0x81AD9C7956F33D82ULL,
		0x07A07328774100A0ULL,
		0x3822167A6F06C15AULL,
		0x4B62041A5CAD66F7ULL,
		0xC0280C84C16418FFULL,
		0x3FA14607584536CEULL
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
		0x663EE382983F7925ULL,
		0xF998AC247F9DBFF1ULL,
		0x0B9DCA031380AF14ULL,
		0xE4EC0E1548B3ECF6ULL,
		0x1B30BDA8B790915FULL,
		0x3D6C7888229B91BEULL,
		0xF44DFEED267DA561ULL,
		0x0A2DE44EADF4E1B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D13A55E48CEEE5ULL,
		0xE3A4E9AC58D10A45ULL,
		0x376CBA55938F3E8FULL,
		0x1EF1375F3AC6A400ULL,
		0x06037653350DD9F3ULL,
		0xA96B035C0FBAF8FBULL,
		0x827B954B3D172009ULL,
		0x1C8EF629DE1D0FEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x356DA92CB3B28A40ULL,
		0x15F3C27826CCB5ACULL,
		0xD4310FAD7FF17085ULL,
		0xC5FAD6B60DED48F5ULL,
		0x152D47558282B76CULL,
		0x9401752C12E098C3ULL,
		0x71D269A1E9668557ULL,
		0xED9EEE24CFD7D1C7ULL
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
		0x94A4C8DF21F026B9ULL,
		0x2F1948430D2A738BULL,
		0x6AD37F3A45A25EE2ULL,
		0x0A64DBAF274A7493ULL,
		0xF7C0A0DABA0F51E3ULL,
		0x75BF2CAEAB13CF07ULL,
		0xFE1A06BDD888327DULL,
		0xAC1323B69A13AF48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0477BDAEF930D8C6ULL,
		0x13D75427DB12E57AULL,
		0xA64991250C9D492EULL,
		0x9C00F7BD371311F2ULL,
		0x18BACE7AF8B4D08AULL,
		0x485F2D25E04636B6ULL,
		0x49F26C5B27508E60ULL,
		0xFA7AB4F8D7F27601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902D0B3028BF4DF3ULL,
		0x1B41F41B32178E11ULL,
		0xC489EE15390515B4ULL,
		0x6E63E3F1F03762A0ULL,
		0xDF05D25FC15A8158ULL,
		0x2D5FFF88CACD9851ULL,
		0xB4279A62B137A41DULL,
		0xB1986EBDC2213947ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x19FB75CA8A17E496ULL,
		0x8B79C9DDCB8A73BBULL,
		0xE53D564CE2606312ULL,
		0x13AA5C7A7CB6C111ULL,
		0x3F1439D60DCE0DA5ULL,
		0x1D2DA20E91FF5CFAULL,
		0x599D07A80EA8D94FULL,
		0xD23D16CCB436570AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBA57D79F645432ULL,
		0xFC79BB1249C19AC1ULL,
		0x597E167C8A9A152CULL,
		0xDA2AD98E8B555F62ULL,
		0xCA55BC811E88934EULL,
		0x8BC391E53F3BCFFDULL,
		0x5354A8940985F8A7ULL,
		0x42DFEF7A4AE57A46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE411DF2EAB39064ULL,
		0x8F000ECB81C8D8F9ULL,
		0x8BBF3FD057C64DE5ULL,
		0x397F82EBF16161AFULL,
		0x74BE7D54EF457A56ULL,
		0x916A102952C38CFCULL,
		0x06485F140522E0A7ULL,
		0x8F5D27526950DCC4ULL
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
		0x7CD36ACA06489EBCULL,
		0xA5E4377E676285BAULL,
		0x16EEAE915DB7CCBBULL,
		0x7307CC4FBF2270DCULL,
		0x31E16DFC65B805D3ULL,
		0x9ECE6902E8B14DD9ULL,
		0xE661D48001F56896ULL,
		0x1E9982FA5FBE4BFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A421DB49852C4C8ULL,
		0x48E9D6AC3509CEB4ULL,
		0x677E4415F12E4D56ULL,
		0x23C1B1C5DDC40DCDULL,
		0x7B3D34AAC32E60FEULL,
		0xA32C8830508306A5ULL,
		0x25C6F5D3385C4903ULL,
		0x2C9D53CAD112D8C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22914D156DF5D9F4ULL,
		0x5CFA60D23258B706ULL,
		0xAF706A7B6C897F65ULL,
		0x4F461A89E15E630EULL,
		0xB6A43951A289A4D5ULL,
		0xFBA1E0D2982E4733ULL,
		0xC09ADEACC9991F92ULL,
		0xF1FC2F2F8EAB733BULL
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
		0x6F1A85B4A399E99FULL,
		0x81A3DF5FC8BE4861ULL,
		0x41BC0CCD88AD3B17ULL,
		0x5CE5433BC40589CBULL,
		0xB8BCF9B6E5FC96CBULL,
		0x499209B3F467D6CCULL,
		0x1838F6571522B101ULL,
		0xA776507C85D3DFA7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BFA4D40FA73F68BULL,
		0xD70FCFFD1E87E088ULL,
		0xE863E4E34BE4FAE4ULL,
		0xCF667199EFAEA516ULL,
		0x06C5BDED7FAF67B7ULL,
		0x64A4184BDDBACEDAULL,
		0x21BDB00EA8A8EC90ULL,
		0xE8BBA9BD6C1289F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23203873A925F314ULL,
		0xAA940F62AA3667D9ULL,
		0x595827EA3CC84032ULL,
		0x8D7ED1A1D456E4B4ULL,
		0xB1F73BC9664D2F13ULL,
		0xE4EDF16816AD07F2ULL,
		0xF67B46486C79C470ULL,
		0xBEBAA6BF19C155B6ULL
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
		0x8657DC433792F98EULL,
		0xFF97005E239CFDFDULL,
		0x144D9291E97332D1ULL,
		0xC52E43A6E08896B9ULL,
		0x1559FF15210F5129ULL,
		0x756CC9B4BB032F1DULL,
		0x7D263C2DE2C1C3DCULL,
		0xAE8132B127166461ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6CA3CE289C8366ULL,
		0xA4821C563ED14C2EULL,
		0x8EF25229C14AEA41ULL,
		0x169BFB2B4D3DDA7FULL,
		0x2E651B6BF4F9089BULL,
		0x3B9424148B4807F7ULL,
		0x00DD7B087DF6971AULL,
		0x433966EA2AA7E72AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6EB38750EF67628ULL,
		0x5B14E407E4CBB1CEULL,
		0x855B406828284890ULL,
		0xAE92487B934ABC39ULL,
		0xE6F4E3A92C16488EULL,
		0x39D8A5A02FBB2725ULL,
		0x7C48C12564CB2CC2ULL,
		0x6B47CBC6FC6E7D37ULL
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
		0xF8E0FB5921FD1A33ULL,
		0x0FA1C4DBB677AF86ULL,
		0x20EDE0DD9499E16FULL,
		0x0FDF786FEABFF035ULL,
		0x8A9B36139365C7DDULL,
		0xF772334A01E9029EULL,
		0x48A81FFF0D80322AULL,
		0x07A5DB6CBB2057A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7653448D22445908ULL,
		0xAC7196F8F858AB6CULL,
		0x140107769DCBA7ECULL,
		0x373C16CEC3BBC57FULL,
		0x145F60ACBE37997CULL,
		0xC96F4FE62C0725FAULL,
		0xB188CB3AD62309C6ULL,
		0x2B2C25839AACD3EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x828DB6CBFFB8C12BULL,
		0x63302DE2BE1F041AULL,
		0x0CECD966F6CE3982ULL,
		0xD8A361A127042AB6ULL,
		0x763BD566D52E2E60ULL,
		0x2E02E363D5E1DCA4ULL,
		0x971F54C4375D2864ULL,
		0xDC79B5E9207383B9ULL
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
		0x0A956CC70EF7D8B1ULL,
		0xB7583D573A693F67ULL,
		0xF0A26BA76E5D1FFDULL,
		0x97073EDDC57A479CULL,
		0x7D5B70F1064E7E71ULL,
		0x85DDD7C7D76BB3DEULL,
		0x335B07848B67779CULL,
		0x3D26838D48DF48F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B6E4453D35BE966ULL,
		0x857692C6EE96E8F9ULL,
		0x737EF92863D51D4EULL,
		0x6E9AA8C860284647ULL,
		0xA02234420304061FULL,
		0xF9B1D87A17005148ULL,
		0x23EE549C8399475AULL,
		0x138B5545380AD6F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF2728733B9BEF4BULL,
		0x31E1AA904BD2566DULL,
		0x7D23727F0A8802AFULL,
		0x286C961565520155ULL,
		0xDD393CAF034A7852ULL,
		0x8C2BFF4DC06B6295ULL,
		0x0F6CB2E807CE3041ULL,
		0x299B2E4810D471F9ULL
	}};
	sign = 0;
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
		0xFAA11F50EF801A29ULL,
		0xADD891FD50467C7EULL,
		0x4CF4E654E053BC14ULL,
		0x07A7087BA6892C13ULL,
		0x8910C47160EAE5DCULL,
		0x4FBC81AB3CAC8408ULL,
		0xC129B890DC54944CULL,
		0x1784D73736BA02EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA50FF3781E3D2B8DULL,
		0x00BC80180B7E560BULL,
		0xF47FB127D93E0CE1ULL,
		0x12D1325962606E32ULL,
		0xFF992944338BB6E6ULL,
		0x42F8450E15EC09A1ULL,
		0xE94E6B286D8FB947ULL,
		0x0B4487251708DBDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55912BD8D142EE9CULL,
		0xAD1C11E544C82673ULL,
		0x5875352D0715AF33ULL,
		0xF4D5D6224428BDE0ULL,
		0x89779B2D2D5F2EF5ULL,
		0x0CC43C9D26C07A66ULL,
		0xD7DB4D686EC4DB05ULL,
		0x0C4050121FB1270FULL
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
		0x006FA63495F874D4ULL,
		0x8A50AD665DD92DF9ULL,
		0xEA0AD37AEF9DE188ULL,
		0x6A7E271F1E14F1FAULL,
		0x6326A2ECA49842D3ULL,
		0xE8C52244A09BB484ULL,
		0xED211C449874BE53ULL,
		0xDABDF9F8B3111145ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5A97C4A9A687539ULL,
		0x965299B6A2DE3D58ULL,
		0x73526D6F48EA67CAULL,
		0x5509AB2F3BECE14CULL,
		0x7B36E336F45ABB7CULL,
		0x5E9A1E2129AF668AULL,
		0x5C78FA0E4A1DD77BULL,
		0xDCB5224980C308BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AC629E9FB8FFF9BULL,
		0xF3FE13AFBAFAF0A0ULL,
		0x76B8660BA6B379BDULL,
		0x15747BEFE22810AEULL,
		0xE7EFBFB5B03D8757ULL,
		0x8A2B042376EC4DF9ULL,
		0x90A822364E56E6D8ULL,
		0xFE08D7AF324E0887ULL
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
		0x1504B3EFEA677B41ULL,
		0xE1970056C8ACAA60ULL,
		0x2A9681E61B6BC65AULL,
		0x676024D161AD748AULL,
		0xA3381BD0C5BCC641ULL,
		0xB001E8637793924DULL,
		0xEF783B4E4B463566ULL,
		0x24D8F3C3FDFF0F38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF68E776070A9D0E3ULL,
		0xE08811247E5BF28DULL,
		0xDA1EFB2111FC1F5BULL,
		0x1B79585350489D55ULL,
		0x06BE0C4FC3EC8784ULL,
		0xEE33E37319250D77ULL,
		0xE587956C6E504608ULL,
		0x91776DB2EC2CE691ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E763C8F79BDAA5EULL,
		0x010EEF324A50B7D2ULL,
		0x507786C5096FA6FFULL,
		0x4BE6CC7E1164D734ULL,
		0x9C7A0F8101D03EBDULL,
		0xC1CE04F05E6E84D6ULL,
		0x09F0A5E1DCF5EF5DULL,
		0x9361861111D228A7ULL
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
		0x7023D4BA11BFA025ULL,
		0x018ADEA45A616410ULL,
		0xEBD6D611AA76E83CULL,
		0x6FE38CB3EF106364ULL,
		0x738F2F347122B368ULL,
		0x1D02956BFC40EE69ULL,
		0x37E5DB1A62BA005EULL,
		0x1838D326286073CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F774113A63CB8A7ULL,
		0xE9752E2BCBD3DFA2ULL,
		0xF891AB654D2888FDULL,
		0xBFB97B6A757BD506ULL,
		0x79B9073318761191ULL,
		0xD767C7AFDA14D294ULL,
		0x4F55EFD2FCB90DD3ULL,
		0xBA7C922AE25B45FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50AC93A66B82E77EULL,
		0x1815B0788E8D846EULL,
		0xF3452AAC5D4E5F3EULL,
		0xB02A114979948E5DULL,
		0xF9D6280158ACA1D6ULL,
		0x459ACDBC222C1BD4ULL,
		0xE88FEB476600F28AULL,
		0x5DBC40FB46052DCDULL
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
		0x178D4F76C0ACFB2AULL,
		0xE8A232D661DAE307ULL,
		0xD135EA243B865436ULL,
		0x088BDE4DB60BA4A5ULL,
		0xEAFD70AE3DB05530ULL,
		0x9354BD566A90EAA9ULL,
		0x2030F0548BE7EB3FULL,
		0x07BF4E71DF921C16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9282F17468C5A702ULL,
		0x930A526241C11920ULL,
		0x2D75990D0F3BE9E2ULL,
		0x543A63596ED5EB06ULL,
		0xB17DDFFC210537AFULL,
		0x0350E02297BB4AE9ULL,
		0xBA2BB71353A96E88ULL,
		0xB8D5DC69C30A0CEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x850A5E0257E75428ULL,
		0x5597E0742019C9E6ULL,
		0xA3C051172C4A6A54ULL,
		0xB4517AF44735B99FULL,
		0x397F90B21CAB1D80ULL,
		0x9003DD33D2D59FC0ULL,
		0x66053941383E7CB7ULL,
		0x4EE972081C880F2AULL
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
		0x1BAA48B25388F507ULL,
		0xFDCDF699E79080FDULL,
		0x7A30ACC4863D9682ULL,
		0x8D5A53FD2620CC33ULL,
		0x1312A069A1589505ULL,
		0xD7B78AB2A4EDD8DEULL,
		0xE3C2D8198C53539FULL,
		0x4F8F65A783080B54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9B4719D0218202ULL,
		0xB520D18BBA97E927ULL,
		0x08187ED47B1A31AEULL,
		0x198633AC1D33C96FULL,
		0xC885905348FF66B9ULL,
		0x4457B76D236DFFD4ULL,
		0x9CF2E6D8CC30C5CFULL,
		0x589C20D6FE8FF656ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD0F019883677305ULL,
		0x48AD250E2CF897D5ULL,
		0x72182DF00B2364D4ULL,
		0x73D4205108ED02C4ULL,
		0x4A8D101658592E4CULL,
		0x935FD345817FD909ULL,
		0x46CFF140C0228DD0ULL,
		0xF6F344D0847814FEULL
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
		0x421E128213DA9293ULL,
		0x14D654850DDA5290ULL,
		0x5A950D229DC7F94CULL,
		0xA690F9AFAEDEDE2DULL,
		0xCDF82FDC03B6A4C3ULL,
		0xB0B33310AA4DA98BULL,
		0x652AAA4806A0E243ULL,
		0x7128B8015CA5B323ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x183D7B10CEA6BA0DULL,
		0xFF9D1DF71ADA20D4ULL,
		0xA04A330C3E2E4C4DULL,
		0x4AC9865D412E295CULL,
		0x9BEC055C7212F3F9ULL,
		0xB3B74B571460760BULL,
		0xBCB800C80F114994ULL,
		0x8B324FF6DC4D6B65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29E097714533D886ULL,
		0x1539368DF30031BCULL,
		0xBA4ADA165F99ACFEULL,
		0x5BC773526DB0B4D0ULL,
		0x320C2A7F91A3B0CAULL,
		0xFCFBE7B995ED3380ULL,
		0xA872A97FF78F98AEULL,
		0xE5F6680A805847BDULL
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
		0xB4E2173AD260D0E5ULL,
		0xB5E44C80D2D05326ULL,
		0x0176B45DE8B25D65ULL,
		0xE9B525A9694D5A99ULL,
		0x36D816CBA4C0A150ULL,
		0x6FB8F272ABF65D27ULL,
		0x7ABF751012E1AF1CULL,
		0xC073EBB302B0908EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x319E28C95BCED7B7ULL,
		0xD79970B638BA26E5ULL,
		0x9BCC3AF091299AFBULL,
		0x07889C77CA01E6C0ULL,
		0xFD4235279573B268ULL,
		0xD2F8ACEECA1C4923ULL,
		0x2E5458D6D65A4B34ULL,
		0xA73385BD5C8A03DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8343EE717691F92EULL,
		0xDE4ADBCA9A162C41ULL,
		0x65AA796D5788C269ULL,
		0xE22C89319F4B73D8ULL,
		0x3995E1A40F4CEEE8ULL,
		0x9CC04583E1DA1403ULL,
		0x4C6B1C393C8763E7ULL,
		0x194065F5A6268CB3ULL
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
		0xBD9AABC5BDCAA9A4ULL,
		0x38E4CC6B92ABAEE0ULL,
		0x7E81CC0E11424CF8ULL,
		0x711F7FEC61949DADULL,
		0x0DFB09A35FF0B351ULL,
		0x9F425A0886C8865CULL,
		0x59F44CE485D306D4ULL,
		0xAA3634B633FE15DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B42EC7A6A6F18FULL,
		0x1B11B059078B9031ULL,
		0x11022F464BB1ED8FULL,
		0xB26829B4C13B4A36ULL,
		0x1DCFFA4EABF8543CULL,
		0xB284C3846A8DEC11ULL,
		0x54E96B20F3B095E3ULL,
		0x85D6E12E6CA08A1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BE67CFE1723B815ULL,
		0x1DD31C128B201EAFULL,
		0x6D7F9CC7C5905F69ULL,
		0xBEB75637A0595377ULL,
		0xF02B0F54B3F85F14ULL,
		0xECBD96841C3A9A4AULL,
		0x050AE1C3922270F0ULL,
		0x245F5387C75D8BC1ULL
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
		0xA4D811CB612F4BBEULL,
		0xB888149132172A85ULL,
		0xD3AEEE1336DAEED7ULL,
		0x2DAD0F854BBD0F23ULL,
		0x0A45515B1130CC70ULL,
		0xE142DCCDB08917AFULL,
		0x49B58B513C6AC093ULL,
		0xA24C5B8614678EEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8752EBD460A5F6ULL,
		0xD96C2EF55EF88B32ULL,
		0x344B895BFA6019D8ULL,
		0x5F3C47A00FB2E45CULL,
		0x01584D5B37F62089ULL,
		0x2F1F70E94364CA39ULL,
		0x6E75A346B602EBADULL,
		0xAB2594EBCD3E7C07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE950BEDF8CCEA5C8ULL,
		0xDF1BE59BD31E9F52ULL,
		0x9F6364B73C7AD4FEULL,
		0xCE70C7E53C0A2AC7ULL,
		0x08ED03FFD93AABE6ULL,
		0xB2236BE46D244D76ULL,
		0xDB3FE80A8667D4E6ULL,
		0xF726C69A472912E2ULL
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
		0xC00AA9C290418C51ULL,
		0x35900F324C07387CULL,
		0xEBACEA4B64AE4A06ULL,
		0x090E51B518FE002FULL,
		0x051F53644A41876EULL,
		0x18B10557FDC6ED20ULL,
		0x6418286AB8C1A5D7ULL,
		0x53A74F24607C9A44ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C35CA54E931B165ULL,
		0x426F6169DF11A90CULL,
		0x620FCF03281933BCULL,
		0xCFC96A4EBE7CCEB7ULL,
		0x4A321FD700A6D04BULL,
		0xA1B3D4BFBDF552D5ULL,
		0xE7D0929D28EB594DULL,
		0xAC63DB91F6427666ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3D4DF6DA70FDAECULL,
		0xF320ADC86CF58F70ULL,
		0x899D1B483C951649ULL,
		0x3944E7665A813178ULL,
		0xBAED338D499AB722ULL,
		0x76FD30983FD19A4AULL,
		0x7C4795CD8FD64C89ULL,
		0xA74373926A3A23DDULL
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
		0x8D59E37DECFA3360ULL,
		0xD4BC4B5430DC6C76ULL,
		0x06BCCAD92FDBE5A4ULL,
		0x48ED43ABDF4FF7BBULL,
		0xC1B9E53D73CFE1F0ULL,
		0xE96F3A26AF906B08ULL,
		0x83864D5A5EB11997ULL,
		0x4AB5E937CB23879BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE931C4358E8C87BDULL,
		0x141A90CF73130AFBULL,
		0x6556DBE89B4F2E75ULL,
		0xB02241F021A2F996ULL,
		0xA7A1849EFF597C7DULL,
		0x0BF303A40767CDEEULL,
		0x62DCF79D751E729BULL,
		0xF63988C6855F2383ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4281F485E6DABA3ULL,
		0xC0A1BA84BDC9617AULL,
		0xA165EEF0948CB72FULL,
		0x98CB01BBBDACFE24ULL,
		0x1A18609E74766572ULL,
		0xDD7C3682A8289D1AULL,
		0x20A955BCE992A6FCULL,
		0x547C607145C46418ULL
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
		0xCAEB69A23253367DULL,
		0x2F53AB4E0CB13DDBULL,
		0xB275CC9CAC4D5F0CULL,
		0xE3209CD4CC42AF02ULL,
		0xDE5AEAE79DC57A10ULL,
		0xE0CF968FE62C9C23ULL,
		0x4CF946AFCA3DCCC1ULL,
		0xDD8041C965009E1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x052502FF89D7C9E7ULL,
		0xD61AC4C93A32984AULL,
		0xB22770A2521B977EULL,
		0x2A181717926DF943ULL,
		0xE862561A079A7B21ULL,
		0xD771A3FCD6F9C8D3ULL,
		0xD6F77754DB56E4FAULL,
		0xC777419283A02E49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5C666A2A87B6C96ULL,
		0x5938E684D27EA591ULL,
		0x004E5BFA5A31C78DULL,
		0xB90885BD39D4B5BFULL,
		0xF5F894CD962AFEEFULL,
		0x095DF2930F32D34FULL,
		0x7601CF5AEEE6E7C7ULL,
		0x16090036E1606FD0ULL
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
		0x8E5C3B74940F367EULL,
		0x029E13864893B83CULL,
		0xEB0B3DF6187DD581ULL,
		0x555960B19DC313DEULL,
		0x181EFD0EF5E0829CULL,
		0xF40BB7F6FA793D8CULL,
		0xC69E1B48DE55E8ADULL,
		0x2ED8FADD54655696ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE731A3311726384ULL,
		0xB3633D702561ED1BULL,
		0x49A9835FD0E99E64ULL,
		0x4EA9B7CEB1E60621ULL,
		0x1562814D480BE39CULL,
		0xC0CA7E3499F1C438ULL,
		0x50B87BFE4B4BE852ULL,
		0x0A4CFCBFA36E3BC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE92141829CD2FAULL,
		0x4F3AD6162331CB20ULL,
		0xA161BA964794371CULL,
		0x06AFA8E2EBDD0DBDULL,
		0x02BC7BC1ADD49F00ULL,
		0x334139C260877954ULL,
		0x75E59F4A930A005BULL,
		0x248BFE1DB0F71ACDULL
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
		0xBDABBB041C7EB16CULL,
		0xD0427E611CB07C59ULL,
		0x29059EC8498500B2ULL,
		0x8278E1E85DDD9545ULL,
		0xDAAB6FF0B2735A96ULL,
		0x62495C1150E1B736ULL,
		0x9FF3F999F7D79DA1ULL,
		0xA7A6845A3F4C48E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EBFCA9B733810CULL,
		0x19DA5F593E452FB4ULL,
		0xEC23AC00430B2979ULL,
		0x49457AB796447C4FULL,
		0xDC6C05E17F1DD206ULL,
		0x86FB1A3F9A519019ULL,
		0x77056CACA44C91E8ULL,
		0xC9FE08B3349102DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4BFBE5A654B3060ULL,
		0xB6681F07DE6B4CA4ULL,
		0x3CE1F2C80679D739ULL,
		0x39336730C79918F5ULL,
		0xFE3F6A0F33558890ULL,
		0xDB4E41D1B690271CULL,
		0x28EE8CED538B0BB8ULL,
		0xDDA87BA70ABB460FULL
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
		0x12D4597EB0FE33EEULL,
		0x41471E00D3025F7AULL,
		0xCDE15C25C9503DDBULL,
		0x1FCF9F48ACA48DE8ULL,
		0x1B740B1707047E1DULL,
		0x9C5C3079F6C512A7ULL,
		0xD94D33F6FD45B614ULL,
		0x91A44A7CB8A8338DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE5CFF35D08CB2BULL,
		0xBD68E3AB55089922ULL,
		0x32DB7180D71835BDULL,
		0xEDCF2B830CACCA7EULL,
		0x8D9FF9B5AF482F58ULL,
		0x5C46D6FE15D98D3AULL,
		0x3DB21277FC685B02ULL,
		0xB7F19071DD85ACD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55EE898B53F568C3ULL,
		0x83DE3A557DF9C657ULL,
		0x9B05EAA4F238081DULL,
		0x320073C59FF7C36AULL,
		0x8DD4116157BC4EC4ULL,
		0x4015597BE0EB856CULL,
		0x9B9B217F00DD5B12ULL,
		0xD9B2BA0ADB2286B9ULL
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
		0x67D4C65ABB64C7D5ULL,
		0xB165FBABC931D7C1ULL,
		0xE2D899C1CE3FF8CFULL,
		0x240596072C34D5D7ULL,
		0x48EF1E2D01E311AEULL,
		0x7CB74D8530BF50F0ULL,
		0x628A821C5CA1A092ULL,
		0xB25B81AA63D37160ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BDDBB09C4C6F62FULL,
		0xE07A2DF6DCFE427EULL,
		0x0865185114F9D275ULL,
		0xABA22CD4F94A06CAULL,
		0xA996187BC11AACA7ULL,
		0x62AD9169C144C6C0ULL,
		0x7A4C9BA1184203AFULL,
		0x887ED0D29D41B4B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BF70B50F69DD1A6ULL,
		0xD0EBCDB4EC339543ULL,
		0xDA738170B9462659ULL,
		0x7863693232EACF0DULL,
		0x9F5905B140C86506ULL,
		0x1A09BC1B6F7A8A2FULL,
		0xE83DE67B445F9CE3ULL,
		0x29DCB0D7C691BCA9ULL
	}};
	sign = 0;
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
		0x653A934B7CFEC2AEULL,
		0x899D16A61BA1FFF1ULL,
		0xA6307F2085511057ULL,
		0xCA64676F88D10B2DULL,
		0xE143459273EA78A3ULL,
		0x90D619713A75811AULL,
		0xBAD09FAD56A9429FULL,
		0x8EA9E522E73488A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DBB7CF8F240170CULL,
		0x82C2ACB4DA8C377EULL,
		0xAB8875E7269FDC44ULL,
		0xB20D70F2C0B94D59ULL,
		0x72B945F477EF4D61ULL,
		0x652E810C0D18AD78ULL,
		0xD46E0D45E9D6B1CDULL,
		0x776AF7685AEDD323ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF77F16528ABEABA2ULL,
		0x06DA69F14115C872ULL,
		0xFAA809395EB13413ULL,
		0x1856F67CC817BDD3ULL,
		0x6E89FF9DFBFB2B42ULL,
		0x2BA798652D5CD3A2ULL,
		0xE66292676CD290D2ULL,
		0x173EEDBA8C46B580ULL
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
		0x8D95ABE742E8A656ULL,
		0xE3CAD56361D79A47ULL,
		0xBF95F12C0B1C5E57ULL,
		0xE74C10B96F300877ULL,
		0x663D87138CF8C31CULL,
		0xA08A8FCFD1E59677ULL,
		0xD3FE5EB36C49E9EDULL,
		0xBA798C23656C8BCBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DADB6CF2E011CC3ULL,
		0x1F7DEC3D2FAE2D38ULL,
		0x41460D8F369999D8ULL,
		0xD015AE9B0089882CULL,
		0xE229DE3FA208142CULL,
		0x9563BD116FC0A150ULL,
		0x7BBB6EFB83C25CAFULL,
		0x13AA3CA789FB5444ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FE7F51814E78993ULL,
		0xC44CE92632296D0FULL,
		0x7E4FE39CD482C47FULL,
		0x1736621E6EA6804BULL,
		0x8413A8D3EAF0AEF0ULL,
		0x0B26D2BE6224F526ULL,
		0x5842EFB7E8878D3EULL,
		0xA6CF4F7BDB713787ULL
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
		0x4EA92DD0F1C3D01EULL,
		0x994A07EFA2D955BAULL,
		0x60AE38BA3E16AEEFULL,
		0x892DB5F2BBFF8E52ULL,
		0x3E7D4C8012392F63ULL,
		0xCDB3659AC58563F6ULL,
		0xC86832467FF90035ULL,
		0x4CD5ADDF4BF35D53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47F72FB7A0272A4ULL,
		0x57C9E929C72E1AE7ULL,
		0x5F524F8AC37F319DULL,
		0x6F3A4A0CA33739CBULL,
		0xAC41DB995415C23DULL,
		0x5F8448CA44E7548AULL,
		0x223E820294A8B9C5ULL,
		0x209599C22F691458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A29BAD577C15D7AULL,
		0x41801EC5DBAB3AD2ULL,
		0x015BE92F7A977D52ULL,
		0x19F36BE618C85487ULL,
		0x923B70E6BE236D26ULL,
		0x6E2F1CD0809E0F6BULL,
		0xA629B043EB504670ULL,
		0x2C40141D1C8A48FBULL
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
		0xDDBA26A551969751ULL,
		0xE76B1E70FECBF76FULL,
		0x24CBB0FFA3C5FA0EULL,
		0x7684C7747048584CULL,
		0xE4DCEA3D38287FA6ULL,
		0x8A8645570409323DULL,
		0x23DA41AAC07D9F6BULL,
		0xE3C9A79F18B4B323ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E2F3B01A50D6ACULL,
		0x7DD7AC5AF8312157ULL,
		0x42916751A9F0072FULL,
		0xDB0D216ED4798F3FULL,
		0xF271F015B089C945ULL,
		0x9B5A8AEF1A4BC6C5ULL,
		0x45C4F8FC4EF3452FULL,
		0x0E984D7E51FBC813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AD732F53745C0A5ULL,
		0x69937216069AD618ULL,
		0xE23A49ADF9D5F2DFULL,
		0x9B77A6059BCEC90CULL,
		0xF26AFA27879EB660ULL,
		0xEF2BBA67E9BD6B77ULL,
		0xDE1548AE718A5A3BULL,
		0xD5315A20C6B8EB0FULL
	}};
	sign = 0;
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
		0x22779DF13874815DULL,
		0x08AFF2A0D8879E9CULL,
		0xBB116FAA01613562ULL,
		0x94D7B91AF8F5923AULL,
		0xF72FC48009DF618AULL,
		0x87EF1D46A449782EULL,
		0xE6ECFA3B5DA97CB8ULL,
		0xF8404AA8251A9E77ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52682F4537BF7414ULL,
		0xEC0E57831DBB1A04ULL,
		0x343E5653915AD7A4ULL,
		0x1BA40D45EAEFC819ULL,
		0xA5982A65D6F2FEBBULL,
		0x89C464E271B27B32ULL,
		0xF17F23316BE40C4BULL,
		0xAC95B0B345804ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD00F6EAC00B50D49ULL,
		0x1CA19B1DBACC8497ULL,
		0x86D3195670065DBDULL,
		0x7933ABD50E05CA21ULL,
		0x51979A1A32EC62CFULL,
		0xFE2AB8643296FCFCULL,
		0xF56DD709F1C5706CULL,
		0x4BAA99F4DF9A539BULL
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
		0x59CD5E89F827AF8CULL,
		0x0A0B59C1AC66919FULL,
		0xFEC2B4205B18445EULL,
		0x5CDB3EC6D8C09667ULL,
		0xFFEE846C76040C2CULL,
		0x7A94FFFE1896BA68ULL,
		0x23952DBEA00CD28FULL,
		0xF772763CAB14C09CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB0974F6092D558ULL,
		0xA53C497F18A236DEULL,
		0xE7A2B1D8251A73B7ULL,
		0x3ABCC40D71696BCEULL,
		0x5DA8CAC3B8F19F21ULL,
		0xC3A3041AD8299266ULL,
		0xF0D6DDD375AAE140ULL,
		0x4D5E77DBA362CBA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B1CC73A9794DA34ULL,
		0x64CF104293C45AC1ULL,
		0x1720024835FDD0A6ULL,
		0x221E7AB967572A99ULL,
		0xA245B9A8BD126D0BULL,
		0xB6F1FBE3406D2802ULL,
		0x32BE4FEB2A61F14EULL,
		0xAA13FE6107B1F4F8ULL
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
		0xDB930E7A2AE88546ULL,
		0xD22808D46691E6DBULL,
		0x3F321A6D0B33B2CAULL,
		0x64BDB8A9D407BCF8ULL,
		0xA48574FA7413459DULL,
		0xEA92AF4C72D4B241ULL,
		0x598F59015FB11170ULL,
		0x4ED5A1CFA98E2BD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0FBE26D7ECDA06ULL,
		0xEB6D1027DAFDA27CULL,
		0x2208D090CE655113ULL,
		0x2CA131043ED4CDAAULL,
		0x69BCAEF8438A5EABULL,
		0xC6B5ED6644421B2DULL,
		0xDB73A934132F8BB0ULL,
		0x6CC9799D049D4AAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF83505352FBAB40ULL,
		0xE6BAF8AC8B94445FULL,
		0x1D2949DC3CCE61B6ULL,
		0x381C87A59532EF4EULL,
		0x3AC8C6023088E6F2ULL,
		0x23DCC1E62E929714ULL,
		0x7E1BAFCD4C8185C0ULL,
		0xE20C2832A4F0E126ULL
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
		0x82AF63E5E51F76D6ULL,
		0x5D47E39FF1C408A5ULL,
		0x4D00CB899433A768ULL,
		0xA4A0FE5C8FDACC95ULL,
		0xF8C7C16B3F413D24ULL,
		0x77FB095FDF812FEDULL,
		0xD56A8C8930472C16ULL,
		0x5B74685AF61E39A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38CA8797D50C623FULL,
		0xA3F86CED37928250ULL,
		0xA8C005F0D7831B52ULL,
		0x3FD22537E108519AULL,
		0x9B412F5CB9802A73ULL,
		0x50A1297EBC21D916ULL,
		0x71EBC20FEA57DEB2ULL,
		0x4AAE4296177837BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49E4DC4E10131497ULL,
		0xB94F76B2BA318655ULL,
		0xA440C598BCB08C15ULL,
		0x64CED924AED27AFAULL,
		0x5D86920E85C112B1ULL,
		0x2759DFE1235F56D7ULL,
		0x637ECA7945EF4D64ULL,
		0x10C625C4DEA601E9ULL
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
		0x1CF994AE7ED68274ULL,
		0x2170244D10375557ULL,
		0x38AC43C84EFF91D4ULL,
		0xB68AEAF159A8B05DULL,
		0xD2E7BD459EBB34DEULL,
		0x6CB090AF6B5429CAULL,
		0xBAAAE05752CD93DDULL,
		0x3F1D8F4A1DE0A7ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D60C4BB8BFFBDB8ULL,
		0x5DDA172247B6F788ULL,
		0xC605091FE81B86E8ULL,
		0x79ABD18365CA6F1CULL,
		0x1F14DF0E5A57F8D3ULL,
		0x4600041B905CA95EULL,
		0xC9FA5A5B3854F1A1ULL,
		0x5202450D90180BE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF98CFF2F2D6C4BCULL,
		0xC3960D2AC8805DCEULL,
		0x72A73AA866E40AEBULL,
		0x3CDF196DF3DE4140ULL,
		0xB3D2DE3744633C0BULL,
		0x26B08C93DAF7806CULL,
		0xF0B085FC1A78A23CULL,
		0xED1B4A3C8DC89BC9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEEC9937048E2B962ULL,
		0xBFAA46AEE568941FULL,
		0xAC992F6128437C65ULL,
		0x37B8A67AC9F0153FULL,
		0x9D8BDA86FAAE9360ULL,
		0x70305380C28DAD0EULL,
		0xE7F4D8D1555A383AULL,
		0x97EC754ECA63CB3AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFF1FD94DDB0EABULL,
		0x854CDBDA9C8C203CULL,
		0xA9E891B315F3D5D1ULL,
		0x8E3D7EFD1D280573ULL,
		0x06205FE3C2B6CD44ULL,
		0xC8E18C9B70E95C36ULL,
		0xC1DF3555C47EECC0ULL,
		0xAC69531E0F66F8E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1CA7396FB07AAB7ULL,
		0x3A5D6AD448DC73E3ULL,
		0x02B09DAE124FA694ULL,
		0xA97B277DACC80FCCULL,
		0x976B7AA337F7C61BULL,
		0xA74EC6E551A450D8ULL,
		0x2615A37B90DB4B79ULL,
		0xEB832230BAFCD255ULL
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
		0x1F49C9BC189F6234ULL,
		0x3E938AC1334D6B9CULL,
		0x81FB12833E99E5E5ULL,
		0xA14EA97FA93FD326ULL,
		0x3B6D1E57FD226B37ULL,
		0x3278BFAA84DEA3CAULL,
		0x77E838F918B68C46ULL,
		0x5245CD0E18A98BA4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19C8D8569D719B8ULL,
		0x3ECC06960E503C19ULL,
		0xCE7CCB69127C8E89ULL,
		0xF7969EE9EDA87150ULL,
		0x32449CC708C3E5EBULL,
		0x9CD83981DA95BEADULL,
		0xB13FA98A8BB5C768ULL,
		0x77C4FBB849979D81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DAD3C36AEC8487CULL,
		0xFFC7842B24FD2F82ULL,
		0xB37E471A2C1D575BULL,
		0xA9B80A95BB9761D5ULL,
		0x09288190F45E854BULL,
		0x95A08628AA48E51DULL,
		0xC6A88F6E8D00C4DDULL,
		0xDA80D155CF11EE22ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2CF24B7871F91B6FULL,
		0x6CCE13029E15B753ULL,
		0xD61BE94EB9A23A4EULL,
		0xFF68D0481E456944ULL,
		0x7E68B10DE2C63F48ULL,
		0x587C40A537B68F10ULL,
		0xB47D783A530D5605ULL,
		0x408B8F4A0BE86AAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF191385534A7CF97ULL,
		0x087A721543F5A095ULL,
		0xC55ED3DB7639772DULL,
		0xB76A627F183E0431ULL,
		0xF417C668CB7CB0E6ULL,
		0xFA55D2164E0FBA68ULL,
		0xD747CBB69CFA70EAULL,
		0x888D4566F3EF26A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B6113233D514BD8ULL,
		0x6453A0ED5A2016BDULL,
		0x10BD15734368C321ULL,
		0x47FE6DC906076513ULL,
		0x8A50EAA517498E62ULL,
		0x5E266E8EE9A6D4A7ULL,
		0xDD35AC83B612E51AULL,
		0xB7FE49E317F94407ULL
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
		0x1070E5A8C9F146DEULL,
		0x4F80148CB9C74579ULL,
		0xFDAC4F7C1858BC88ULL,
		0x7064053B814BBFAFULL,
		0x9BE7069766F200A3ULL,
		0xC03BBEBC4E101B2AULL,
		0xBF0431610D92705EULL,
		0x0781CA45DDFBD4FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8883885BA02373BULL,
		0xDAD36E5763F747B6ULL,
		0xFBCEDC4446F90044ULL,
		0xEF6FF65572C9FDB0ULL,
		0xC62E1B77CC7AEFB6ULL,
		0x4BD23FDAA527CBDFULL,
		0xB063FD99CCA5AF36ULL,
		0x6308493CBF5432C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27E8AD230FEF0FA3ULL,
		0x74ACA63555CFFDC2ULL,
		0x01DD7337D15FBC43ULL,
		0x80F40EE60E81C1FFULL,
		0xD5B8EB1F9A7710ECULL,
		0x74697EE1A8E84F4AULL,
		0x0EA033C740ECC128ULL,
		0xA47981091EA7A235ULL
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
		0x92F038A301E27372ULL,
		0x46926E051985A694ULL,
		0x6B000862B5834B77ULL,
		0x9298E4113B742614ULL,
		0x8940A834F0FD5BF3ULL,
		0x0CA38FCA8F25BDAFULL,
		0x4E8D3065DBC89394ULL,
		0x310B1B71DDA48FCCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E03C6A5A439127ULL,
		0x01FF0C2BF1C58DF6ULL,
		0x477DA861CFB163BBULL,
		0xA1FF01FDB837C839ULL,
		0x98AA280A462782BBULL,
		0x6C8CFEB7068386F2ULL,
		0x3BB07FF13F1E1404ULL,
		0x9C04FFF50AA1472EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C0FFC38A79EE24BULL,
		0x449361D927C0189DULL,
		0x23826000E5D1E7BCULL,
		0xF099E213833C5DDBULL,
		0xF096802AAAD5D937ULL,
		0xA016911388A236BCULL,
		0x12DCB0749CAA7F8FULL,
		0x95061B7CD303489EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x805E180C39C552E5ULL,
		0x92DC13BC1F447FDAULL,
		0x3C47EBF31E0EFD9AULL,
		0xA078962625F0B74EULL,
		0x3619FC77452897F1ULL,
		0xE06948002042DE81ULL,
		0xD0939843E0DBF879ULL,
		0x69CCBF402DCF9576ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB644BCD68165FFULL,
		0xC967FAEA47019B8AULL,
		0x0055C528ACD072D1ULL,
		0x8BF40FF61D4D144EULL,
		0x1499836390D4CC44ULL,
		0xF77A02237EBD1A7BULL,
		0x61CDF940B5961F28ULL,
		0xAAE58A9EF7513396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22A7D34F6343ECE6ULL,
		0xC97418D1D842E450ULL,
		0x3BF226CA713E8AC8ULL,
		0x1484863008A3A300ULL,
		0x21807913B453CBADULL,
		0xE8EF45DCA185C406ULL,
		0x6EC59F032B45D950ULL,
		0xBEE734A1367E61E0ULL
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
		0xEA2FA7443C93E843ULL,
		0x96D8D0C26EDD97A4ULL,
		0xD89828D99028314FULL,
		0x325E7716F9CD8DA3ULL,
		0x6E60EF1005477A33ULL,
		0x33F95F59738DCDE9ULL,
		0x8739C8881DB3E2EDULL,
		0x8AC8846BCDC23114ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D90B7F473E6C6B5ULL,
		0x718C0F6BA35D1CC3ULL,
		0x80A6759B0A680FE3ULL,
		0x4D6F5C0EBF9819C8ULL,
		0x522D72A573A039B2ULL,
		0x524B59485C39209DULL,
		0xB0809427132F05FEULL,
		0x0749B98AB20C396DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C9EEF4FC8AD218EULL,
		0x254CC156CB807AE1ULL,
		0x57F1B33E85C0216CULL,
		0xE4EF1B083A3573DBULL,
		0x1C337C6A91A74080ULL,
		0xE1AE06111754AD4CULL,
		0xD6B934610A84DCEEULL,
		0x837ECAE11BB5F7A6ULL
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
		0x42C0FDB423B56E96ULL,
		0xB0F947CB2E03BAD9ULL,
		0x2A1DA6EED4B7ED7CULL,
		0x9D1419365CD7B543ULL,
		0xBBA63CC1749D7E2AULL,
		0x7816BBC7D006B916ULL,
		0x5A61137510F1BA30ULL,
		0x4E995933FA2D0711ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x373CB49732C83E29ULL,
		0x707D9C6BC8D4AEB1ULL,
		0x1F9918299E75F57FULL,
		0x3985B000109A16DDULL,
		0x72A65BDE04F49790ULL,
		0x9467C89353FE3E45ULL,
		0xB78CD7BBFEE562E9ULL,
		0x4A7529229D6356ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B84491CF0ED306DULL,
		0x407BAB5F652F0C28ULL,
		0x0A848EC53641F7FDULL,
		0x638E69364C3D9E66ULL,
		0x48FFE0E36FA8E69AULL,
		0xE3AEF3347C087AD1ULL,
		0xA2D43BB9120C5746ULL,
		0x042430115CC9B065ULL
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
		0x4F5D51B95BE92118ULL,
		0xFB635F9F7CD8F72CULL,
		0xFF9FD48E0EF04656ULL,
		0xD19ABDCC36C5D06EULL,
		0x9189D244ABB13DECULL,
		0xEE422F52CB996E4AULL,
		0xA2E1503ACA7136AFULL,
		0x6A6FCB58A9AB6071ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DC6D3A201F85B58ULL,
		0x6D1C5E8DD6E78A07ULL,
		0xCD024FED5FFCB5BAULL,
		0xF0D1FCCC70E5D581ULL,
		0x688D821254234ED2ULL,
		0x74CD9A433D662B2BULL,
		0x0F35199F8554AFD8ULL,
		0x3F1BBC378E052F7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31967E1759F0C5C0ULL,
		0x8E470111A5F16D25ULL,
		0x329D84A0AEF3909CULL,
		0xE0C8C0FFC5DFFAEDULL,
		0x28FC5032578DEF19ULL,
		0x7974950F8E33431FULL,
		0x93AC369B451C86D7ULL,
		0x2B540F211BA630F5ULL
	}};
	sign = 0;
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
		0x14AE01B6BB0D6BE3ULL,
		0x2BB6E448B26EB0EAULL,
		0x606499255C48A44DULL,
		0xAD761DBED39588ACULL,
		0x8E8A98511E1A02A7ULL,
		0xAF71CF60550516ADULL,
		0x15ECD255046FC5C1ULL,
		0x638C6FA3ED87F25DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0261DB4E72C46F83ULL,
		0x979D87B0A77D21CEULL,
		0xD8A1DDADF68014EAULL,
		0x5A358145C68C1AE2ULL,
		0x7501719835E66C7EULL,
		0xA0EFC816F3062779ULL,
		0x3ED6A2DD558D8ED1ULL,
		0xE2FB9C2C9DD75068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x124C26684848FC60ULL,
		0x94195C980AF18F1CULL,
		0x87C2BB7765C88F62ULL,
		0x53409C790D096DC9ULL,
		0x198926B8E8339629ULL,
		0x0E82074961FEEF34ULL,
		0xD7162F77AEE236F0ULL,
		0x8090D3774FB0A1F4ULL
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
		0xB8107EBD2AFC53A7ULL,
		0x2AEDE57C97003071ULL,
		0xF543BB5D4F406F40ULL,
		0x99C01F971FD40E87ULL,
		0x86621424A1AA44F2ULL,
		0x75A99E23FB60939BULL,
		0xA8E992E76F32E0F2ULL,
		0x057358EE6E02285DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2805714ECA22486AULL,
		0x82F2C146D66F741EULL,
		0xA71E5309C026E5B1ULL,
		0xFE80283640841FB9ULL,
		0x8BB845EF4612E81BULL,
		0xADBCE454158F874FULL,
		0x881A352D227A1EAEULL,
		0x612D21D3F5190665ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x900B0D6E60DA0B3DULL,
		0xA7FB2435C090BC53ULL,
		0x4E2568538F19898EULL,
		0x9B3FF760DF4FEECEULL,
		0xFAA9CE355B975CD6ULL,
		0xC7ECB9CFE5D10C4BULL,
		0x20CF5DBA4CB8C243ULL,
		0xA446371A78E921F8ULL
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
		0xEE3F733CD0C4E6B2ULL,
		0xB975EF6677C20B0CULL,
		0x489E71A936375F50ULL,
		0xD898DCFC479AFC3FULL,
		0x8D00845F169D3A61ULL,
		0xDB1FAD9EE8FC876BULL,
		0x92573C3FB4B0AEE7ULL,
		0x39ADC97B964F25E1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x823480F81C1DC000ULL,
		0x1DEB8A85BD780AE5ULL,
		0x7139E8D418A72D96ULL,
		0x3F2AF245871361A5ULL,
		0xF63BDE74E7746A2DULL,
		0x5FC1B534403B333AULL,
		0x7329F6D072CE36B5ULL,
		0xBCD91ADDC02ADCC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C0AF244B4A726B2ULL,
		0x9B8A64E0BA4A0027ULL,
		0xD76488D51D9031BAULL,
		0x996DEAB6C0879A99ULL,
		0x96C4A5EA2F28D034ULL,
		0x7B5DF86AA8C15430ULL,
		0x1F2D456F41E27832ULL,
		0x7CD4AE9DD6244918ULL
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
		0xCC9A71099AE0393EULL,
		0xABE4A1D2D967B695ULL,
		0x67FC713AF395AAD8ULL,
		0x9171E9926B81C524ULL,
		0x619D064CC34E2A2BULL,
		0xBA9176B98EECB4AEULL,
		0x93FC90BA2FDEB205ULL,
		0x5EC1384829275735ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B055AF0916F8D6ULL,
		0xEB6A62B0F05B11F2ULL,
		0x28E08C2DB44D6ACAULL,
		0x2B784AC47DFD5050ULL,
		0xBEFA90283F2E0EB9ULL,
		0xC3420784D95758ECULL,
		0x29BFE1AC133742EFULL,
		0x699BC270AED526F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBEA1B5A91C94068ULL,
		0xC07A3F21E90CA4A2ULL,
		0x3F1BE50D3F48400DULL,
		0x65F99ECDED8474D4ULL,
		0xA2A2762484201B72ULL,
		0xF74F6F34B5955BC1ULL,
		0x6A3CAF0E1CA76F15ULL,
		0xF52575D77A523041ULL
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
		0xC7DAB66B7FCEFD7BULL,
		0x987BC41197576F5FULL,
		0xDC8772314959B636ULL,
		0x4C16A1DC333A7492ULL,
		0x50DD9CB76B37297FULL,
		0xEFC7C26D28DE36E3ULL,
		0xBBDCC5F51663605FULL,
		0x10DDED2C9AFAE42AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E38E8C4140CB460ULL,
		0x82C6DB0B508D49AFULL,
		0x2CBBDDDC7F7E36E9ULL,
		0x43CA9914F846807AULL,
		0xAA5E3DAF2827A3F7ULL,
		0x25B1A68CD75EE1B0ULL,
		0x3A0A2216EF5F2C57ULL,
		0x23ACB88B230B26A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59A1CDA76BC2491BULL,
		0x15B4E90646CA25B0ULL,
		0xAFCB9454C9DB7F4DULL,
		0x084C08C73AF3F418ULL,
		0xA67F5F08430F8588ULL,
		0xCA161BE0517F5532ULL,
		0x81D2A3DE27043408ULL,
		0xED3134A177EFBD83ULL
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
		0x2642E7130F4B9451ULL,
		0x3E8CDEF8055B0959ULL,
		0xE592A82481BD2BD1ULL,
		0x060D87E82B5EA3B4ULL,
		0x9D1F50DA073F4BA2ULL,
		0x3D8716ACB090BD42ULL,
		0xC8CFBD1B64573EBBULL,
		0xF4E994967374AA73ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x317E3992896C6149ULL,
		0x33A33D2782169295ULL,
		0x564AAB9C55E55516ULL,
		0x16B8EEBB157AB7B4ULL,
		0x1D34256111EC97D1ULL,
		0x0B4E551737DD2088ULL,
		0x9F58FFFDB6D86B01ULL,
		0x3E5367B0776BE60CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4C4AD8085DF3308ULL,
		0x0AE9A1D0834476C3ULL,
		0x8F47FC882BD7D6BBULL,
		0xEF54992D15E3EC00ULL,
		0x7FEB2B78F552B3D0ULL,
		0x3238C19578B39CBAULL,
		0x2976BD1DAD7ED3BAULL,
		0xB6962CE5FC08C467ULL
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
		0x07E37377F8DF8C40ULL,
		0xE7880B7932D0214BULL,
		0x526F2D50944ACA9BULL,
		0x3EF59B5DC58A3CF3ULL,
		0xF9C98582359C5206ULL,
		0xDD3F0796BC93544EULL,
		0x31B8E49656F535ACULL,
		0x85E3ACC9085FBE9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BD4F1642FF63ECBULL,
		0x15CF865012A0080AULL,
		0x2CF2D169FBAE1EB9ULL,
		0x54D7F6E65A586EEDULL,
		0xBB1D8819183A62A8ULL,
		0xC92635D581603184ULL,
		0xBFCA4AECA1848374ULL,
		0xF73D5DB5CA493D5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC0E8213C8E94D75ULL,
		0xD1B8852920301940ULL,
		0x257C5BE6989CABE2ULL,
		0xEA1DA4776B31CE06ULL,
		0x3EABFD691D61EF5DULL,
		0x1418D1C13B3322CAULL,
		0x71EE99A9B570B238ULL,
		0x8EA64F133E168142ULL
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
		0x6A3EE6C0362D4D68ULL,
		0xD6A184F93299834FULL,
		0xB4FF6F849C4EBEDFULL,
		0xF90D30D2B6A28EDCULL,
		0xFAA849D55635676CULL,
		0xC4A297D5E0C47D62ULL,
		0x255007C5852093C8ULL,
		0x05932A09177FF225ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A0516BE4D257D5ULL,
		0xBDB485DC7248B534ULL,
		0x8A67677DA958B310ULL,
		0xF2A868A5E405FF5CULL,
		0x856EB529DD02F3A1ULL,
		0x379C1FE72C7B7B6BULL,
		0xAAAA8802DB837040ULL,
		0xC9648355EB76CA04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x019E9554515AF593ULL,
		0x18ECFF1CC050CE1BULL,
		0x2A980806F2F60BCFULL,
		0x0664C82CD29C8F80ULL,
		0x753994AB793273CBULL,
		0x8D0677EEB44901F7ULL,
		0x7AA57FC2A99D2388ULL,
		0x3C2EA6B32C092820ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x43766828D2622E22ULL,
		0x95A6EDB46AEDC31EULL,
		0x8A0F73FD80FDCD46ULL,
		0xB40746F50A29AC12ULL,
		0xD3FDC09A9ED8FE30ULL,
		0x47CBC6174B5700DEULL,
		0xA48AB5AEBDD67874ULL,
		0x839CED182023E69FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17DD1940136F4C21ULL,
		0x8A928074BD11BD11ULL,
		0xCEF7A800BA00FCA2ULL,
		0xDDB346AEAA9FFDE7ULL,
		0x2D57A98BFA83EF43ULL,
		0x47E859A6F9427E9FULL,
		0x11CF79C742C37F98ULL,
		0x70E17CB61E75F625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B994EE8BEF2E201ULL,
		0x0B146D3FADDC060DULL,
		0xBB17CBFCC6FCD0A4ULL,
		0xD65400465F89AE2AULL,
		0xA6A6170EA4550EECULL,
		0xFFE36C705214823FULL,
		0x92BB3BE77B12F8DBULL,
		0x12BB706201ADF07AULL
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
		0xDB472728B1FC36C6ULL,
		0x22F361E670952374ULL,
		0x67684FCAE1FAC264ULL,
		0x123CA5D2A37EEC45ULL,
		0x00F7136BDB9A65E7ULL,
		0x6C5FFF026F10EF7CULL,
		0xB559B07082CD809FULL,
		0x2551943FD0527F5AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6680E5FFBA379BEFULL,
		0x2792371648943234ULL,
		0x654E977A888F292EULL,
		0x3F76F1DA00DD4FE8ULL,
		0x8EEC1F954B4A8AFFULL,
		0x8CE43FB786A70C6EULL,
		0x3251BFC35F665B54ULL,
		0xB55D6C7B16466653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74C64128F7C49AD7ULL,
		0xFB612AD02800F140ULL,
		0x0219B850596B9935ULL,
		0xD2C5B3F8A2A19C5DULL,
		0x720AF3D6904FDAE7ULL,
		0xDF7BBF4AE869E30DULL,
		0x8307F0AD2367254AULL,
		0x6FF427C4BA0C1907ULL
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
		0x0ACF714BBD5E2935ULL,
		0x3C3EF77E702EE983ULL,
		0xD6C44283B2EFD75BULL,
		0x9E45570F0534E09BULL,
		0x660A25EB19BBC747ULL,
		0x1FFCDA94C71DB204ULL,
		0x49541EBBB67CFBAFULL,
		0xB941968F74292C91ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2379B5A9955A3B8ULL,
		0xDBBA4A0748108D17ULL,
		0x24FB47BB76321AA5ULL,
		0x804FB4A689A94ACAULL,
		0x152F18BBC5A6308EULL,
		0xA5006784774B1B0EULL,
		0x3F3B206F1DAE5422ULL,
		0x9B75BB516316DFC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3897D5F12408857DULL,
		0x6084AD77281E5C6BULL,
		0xB1C8FAC83CBDBCB5ULL,
		0x1DF5A2687B8B95D1ULL,
		0x50DB0D2F541596B9ULL,
		0x7AFC73104FD296F6ULL,
		0x0A18FE4C98CEA78CULL,
		0x1DCBDB3E11124CCFULL
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
		0x3E51B1D393ACAF92ULL,
		0x9A39F0593227A99BULL,
		0x2448BB8DF72CB7F2ULL,
		0x330F5B5E1DA4C216ULL,
		0x72C010A3C7DD6312ULL,
		0xB2DF242AA1244D01ULL,
		0x80D22C7EBF6DB803ULL,
		0xF97F181834E049A6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x611518B6780B0BB7ULL,
		0x9C22538A9BBAA14EULL,
		0xB3B8F596D5FF9742ULL,
		0x20BDE3AF58573170ULL,
		0x4E332490753462F9ULL,
		0xAB8EFEE8984C6E26ULL,
		0xED514874AFFA4E87ULL,
		0x498A000D7DC4199EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD3C991D1BA1A3DBULL,
		0xFE179CCE966D084CULL,
		0x708FC5F7212D20AFULL,
		0x125177AEC54D90A5ULL,
		0x248CEC1352A90019ULL,
		0x0750254208D7DEDBULL,
		0x9380E40A0F73697CULL,
		0xAFF5180AB71C3007ULL
	}};
	sign = 0;
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
		0x8E0853610703DA6CULL,
		0x521AC38EF246346AULL,
		0xDF46C30AEBA440D8ULL,
		0x48976BFFEDEEFAA6ULL,
		0x7DA9A7445B420F72ULL,
		0xAFF4D212090E86B3ULL,
		0x2AC825267A09FABDULL,
		0xA8B7EA4B42454A38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB4A9E16CB8706DULL,
		0x557455DCEA8F6E1EULL,
		0x1F0B17F8D6F9DE17ULL,
		0x76B5D7378BCED53CULL,
		0x9224CA5DA439C58BULL,
		0xC994E465AAEAC672ULL,
		0xF337319A6403F8FEULL,
		0x52D14B95FB3E2BF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE53A97F9A4B69FFULL,
		0xFCA66DB207B6C64BULL,
		0xC03BAB1214AA62C0ULL,
		0xD1E194C86220256AULL,
		0xEB84DCE6B70849E6ULL,
		0xE65FEDAC5E23C040ULL,
		0x3790F38C160601BEULL,
		0x55E69EB547071E41ULL
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
		0x3826E0A2991B857CULL,
		0xB426F7A6B7AE5D0AULL,
		0x780A3F623BCD2C3AULL,
		0x67C09B25898E7E6AULL,
		0x2DD85F9B5DCFAA4EULL,
		0x814421DA5B857480ULL,
		0x246D1E546816B24FULL,
		0xAA6D985B10EF2349ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD266644C58DC441ULL,
		0x131A9C764D22C44FULL,
		0xBA8AB0BE14D02E27ULL,
		0x8697BDF119BFC15DULL,
		0x2B235F640D5785FEULL,
		0xA52738F2671411CFULL,
		0xEBD24F60F0ADBDA5ULL,
		0x74F4237C176A7B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B007A5DD38DC13BULL,
		0xA10C5B306A8B98BAULL,
		0xBD7F8EA426FCFE13ULL,
		0xE128DD346FCEBD0CULL,
		0x02B500375078244FULL,
		0xDC1CE8E7F47162B1ULL,
		0x389ACEF37768F4A9ULL,
		0x357974DEF984A7ABULL
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
		0xAAEF2F5E1BE76B74ULL,
		0xB8259A9783AEF420ULL,
		0x5F12FD6576934839ULL,
		0x166E0F4A2C42E84FULL,
		0x116BA6AC00576AD0ULL,
		0x7110856AE627680FULL,
		0xF0EEC7EFAE9E2111ULL,
		0xD4962BE962DC3E7CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB8086E06E0F1AFULL,
		0xDA491BF131FF85CBULL,
		0xEAD0973637C7B22AULL,
		0xE30F6363F6A5FA83ULL,
		0xD56BF0FD11E41DAFULL,
		0xBE10351FEF239136ULL,
		0x2035F8236FC6BAA9ULL,
		0x6CF006CEF1521C44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE03726F0150679C5ULL,
		0xDDDC7EA651AF6E54ULL,
		0x7442662F3ECB960EULL,
		0x335EABE6359CEDCBULL,
		0x3BFFB5AEEE734D20ULL,
		0xB300504AF703D6D8ULL,
		0xD0B8CFCC3ED76667ULL,
		0x67A6251A718A2238ULL
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
		0x82429C033FA6D928ULL,
		0x536846C2111C2661ULL,
		0xEB4B1D6DF7082121ULL,
		0xC0025860D53CDC9AULL,
		0xA38C11523D4F8474ULL,
		0x0722502615DBAC01ULL,
		0x50F1103D4DB76F8FULL,
		0x0B8C0BE1C7CEB76CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E54308E85E45071ULL,
		0x07C61047F6A28B12ULL,
		0x3087CDED5E36C1CBULL,
		0x0FD09E4B0680F06CULL,
		0x10B5692C35EF327EULL,
		0x810F2047584C0E15ULL,
		0xC5894AA6C2E57D94ULL,
		0x8E51041A8C725519ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23EE6B74B9C288B7ULL,
		0x4BA2367A1A799B4FULL,
		0xBAC34F8098D15F56ULL,
		0xB031BA15CEBBEC2EULL,
		0x92D6A826076051F6ULL,
		0x86132FDEBD8F9DECULL,
		0x8B67C5968AD1F1FAULL,
		0x7D3B07C73B5C6252ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4B00E394D6A035B4ULL,
		0x1AA769A2C48CB934ULL,
		0x8C26F096BF48B1F5ULL,
		0x172162E3E0C4F267ULL,
		0xDF8AD1DB9982575BULL,
		0x7D5FB1790926E1AAULL,
		0x0DFA60671B7589D2ULL,
		0xD0F2CB2A225C1551ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD56FBB071AD68EULL,
		0x64A502E0309F63BFULL,
		0x53669920AC3410A4ULL,
		0x6EF6F581060742F3ULL,
		0xC96BD5804976C630ULL,
		0x290320EDAE6CE0C6ULL,
		0x4458F1AA44945D61ULL,
		0xED260BE23213826FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD2B73D9CF855F26ULL,
		0xB60266C293ED5574ULL,
		0x38C057761314A150ULL,
		0xA82A6D62DABDAF74ULL,
		0x161EFC5B500B912AULL,
		0x545C908B5ABA00E4ULL,
		0xC9A16EBCD6E12C71ULL,
		0xE3CCBF47F04892E1ULL
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
		0x667A301F741A0D50ULL,
		0x78EBB7EDAD9B23CEULL,
		0xE0ABDF35D3EFD413ULL,
		0xE87387D10891FDF6ULL,
		0x954C1B8C638BD547ULL,
		0x092EFBF1B1115BFEULL,
		0x9EFD0242F5317CE6ULL,
		0x09758ED9CE7626DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB80B663C810F1B2FULL,
		0x6FA0466D560245E5ULL,
		0x8909A4A3C2037123ULL,
		0x08E2009E57664AC9ULL,
		0x07554A3E79A051F9ULL,
		0xD7F5EA1C330B6F5FULL,
		0xB123D2D96DA10867ULL,
		0x313197C139E435FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE6EC9E2F30AF221ULL,
		0x094B71805798DDE8ULL,
		0x57A23A9211EC62F0ULL,
		0xDF918732B12BB32DULL,
		0x8DF6D14DE9EB834EULL,
		0x313911D57E05EC9FULL,
		0xEDD92F698790747EULL,
		0xD843F7189491F0DBULL
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
		0xFFF042F0391CFC03ULL,
		0x45DE4BFF82F9B541ULL,
		0xA78E994C7361A9F1ULL,
		0x4BC80F9446C92015ULL,
		0x853208A7DA410F3DULL,
		0xD4B19D61FE612B09ULL,
		0xE3F66CC500A7B05FULL,
		0xB4E15991FC82E7A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F234AF51B275D8ULL,
		0x041B4EC6200FEF27ULL,
		0x3D8733EE2F7886D9ULL,
		0xE62F5036043559DAULL,
		0xFFB09FDFE10D13A8ULL,
		0x0458D07B9D6CF63AULL,
		0x5857DFED7ABE603BULL,
		0x0C5D027D5DF6AE1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCFE0E40E76A862BULL,
		0x41C2FD3962E9C61AULL,
		0x6A07655E43E92318ULL,
		0x6598BF5E4293C63BULL,
		0x858168C7F933FB94ULL,
		0xD058CCE660F434CEULL,
		0x8B9E8CD785E95024ULL,
		0xA88457149E8C3984ULL
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
		0xC3F7510440F9C8FEULL,
		0x7BC4A53F6BF38FBFULL,
		0x45AD44059EADB517ULL,
		0x2D5BA80A737E17ABULL,
		0x5C0E0D2EEF362F4EULL,
		0x58EB499E73422FFBULL,
		0x6DBCD1E848EAE6F4ULL,
		0x16970B0A80FD5C68ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3953F3CCF4321596ULL,
		0xF1E17B544D607865ULL,
		0xC07F8AC6A13C6E94ULL,
		0x87FB75CEFCB8A957ULL,
		0xE5E2E3089317E08FULL,
		0xFECA05DABC003AC4ULL,
		0x570985DD443C0885ULL,
		0x08A243868D429EF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AA35D374CC7B368ULL,
		0x89E329EB1E93175AULL,
		0x852DB93EFD714682ULL,
		0xA560323B76C56E53ULL,
		0x762B2A265C1E4EBEULL,
		0x5A2143C3B741F536ULL,
		0x16B34C0B04AEDE6EULL,
		0x0DF4C783F3BABD78ULL
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
		0x860141B835D74D00ULL,
		0xBC861D77A6F5473EULL,
		0x36F218BD47F29E9CULL,
		0x0CFF70B51DBBB36CULL,
		0x87BB1C3BC4AC9227ULL,
		0x07571DB13B1E5544ULL,
		0xF9EB82D5C5196B1FULL,
		0x9A76E65B7CEDE879ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69437BBA3B593D85ULL,
		0x45942B46494806B1ULL,
		0xFA86B19F123EAFC4ULL,
		0x4CAB2A75FA91E327ULL,
		0xAFEA1FE0D606DC43ULL,
		0x3EAE6C562DECF382ULL,
		0xA1B86CCAF950A2D6ULL,
		0x9056A06AEEEF3F10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CBDC5FDFA7E0F7BULL,
		0x76F1F2315DAD408DULL,
		0x3C6B671E35B3EED8ULL,
		0xC054463F2329D044ULL,
		0xD7D0FC5AEEA5B5E3ULL,
		0xC8A8B15B0D3161C1ULL,
		0x5833160ACBC8C848ULL,
		0x0A2045F08DFEA969ULL
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
		0x757357D04C9BAAD5ULL,
		0xE3E786E14041222CULL,
		0x50DAA3313C830622ULL,
		0x47DAA82D89872DFDULL,
		0x222423C09A594ABEULL,
		0x3F71B748F7D63C79ULL,
		0xF7F99929C82926E0ULL,
		0x6B3BACB03AB86F4CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x128014157B9898E2ULL,
		0x91466868A840B881ULL,
		0x08337C5D3E81B06EULL,
		0xC8FA6386F64B511CULL,
		0xF0F4F0BD7DB251E8ULL,
		0x76F4154EA13ECA03ULL,
		0x0557E25B632DACF0ULL,
		0xAC3EDD5D13F2B9EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62F343BAD10311F3ULL,
		0x52A11E78980069ABULL,
		0x48A726D3FE0155B4ULL,
		0x7EE044A6933BDCE1ULL,
		0x312F33031CA6F8D5ULL,
		0xC87DA1FA56977275ULL,
		0xF2A1B6CE64FB79EFULL,
		0xBEFCCF5326C5B55DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBE1584C19E8D6FBEULL,
		0xB08DF7B48CC2A5FDULL,
		0xB28243BF8F0594D6ULL,
		0x3B9647FE9EB99FF8ULL,
		0x9BAC13A40D057CCAULL,
		0x9AEBB91EAFFBA3FCULL,
		0x8C8B39BDFCF12249ULL,
		0x192BC1A200B146BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7E45E00D9E2EFE7ULL,
		0xC48C733C179BF4F8ULL,
		0x286122403B990CDFULL,
		0x8CB0115F89AA71F2ULL,
		0xF2C3E3B6C31356DDULL,
		0xBC41E525029F1456ULL,
		0x09D73C848C7A257DULL,
		0xB42FCCE634C63380ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x163126C0C4AA7FD7ULL,
		0xEC0184787526B105ULL,
		0x8A21217F536C87F6ULL,
		0xAEE6369F150F2E06ULL,
		0xA8E82FED49F225ECULL,
		0xDEA9D3F9AD5C8FA5ULL,
		0x82B3FD397076FCCBULL,
		0x64FBF4BBCBEB133EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEB7B766085A92AAFULL,
		0x8A250070B13E3F74ULL,
		0x61A68B60094D954DULL,
		0xCB13F0DA74D083FBULL,
		0x95D9543C46132D19ULL,
		0x03C1DA5AB89AD2EEULL,
		0x98C9E678D718A397ULL,
		0x3A12D0CFE4F2ABD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6827CEAB1059C9FULL,
		0x4D01DB71D7261A18ULL,
		0x050A92BD140A9F44ULL,
		0x18C41D88962A736FULL,
		0x2A48B7C3C3858C11ULL,
		0x8C29C10D5A05B43AULL,
		0x779C92F03EFFDD64ULL,
		0xD3758DA1B29C430EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24F8F975D4A38E10ULL,
		0x3D2324FEDA18255CULL,
		0x5C9BF8A2F542F609ULL,
		0xB24FD351DEA6108CULL,
		0x6B909C78828DA108ULL,
		0x7798194D5E951EB4ULL,
		0x212D53889818C632ULL,
		0x669D432E325668C2ULL
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
		0x3F7E4EF2C634F814ULL,
		0xB56A64172914FEFAULL,
		0x3AD5B4A182740BACULL,
		0xF223751F4A4A537FULL,
		0x68D7B614FF974A2FULL,
		0xF5941B0009B91053ULL,
		0xE107E189D5FE38EAULL,
		0xA8CB35D0DFD08E7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x609F7DEE1406577DULL,
		0x72AECF9852C05110ULL,
		0xCDC89A2F60624886ULL,
		0x1817DBD0DE4144A9ULL,
		0xE34F76F029337223ULL,
		0xA5729C9A93152E8CULL,
		0x82E031F25690D1DBULL,
		0xF6D49EFABF0D98BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEDED104B22EA097ULL,
		0x42BB947ED654ADE9ULL,
		0x6D0D1A722211C326ULL,
		0xDA0B994E6C090ED5ULL,
		0x85883F24D663D80CULL,
		0x50217E6576A3E1C6ULL,
		0x5E27AF977F6D670FULL,
		0xB1F696D620C2F5C1ULL
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
		0x71437ADFB7A24D96ULL,
		0xD9A75DDA9F01756AULL,
		0x4F9CE7ED8C3E0084ULL,
		0x5DC7830D33A546ABULL,
		0x14EF0AAA2315A07CULL,
		0xADC7E90E33C64B75ULL,
		0xCC847A92B66395EFULL,
		0x29355EC04403045FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x018593DC856918ACULL,
		0x210D5E735C497E36ULL,
		0xC9F342990E27FBBFULL,
		0xCFBCE9181671B82CULL,
		0x10316CA79AEA6E84ULL,
		0x15639AFB1A1CE316ULL,
		0x94C12A55A162C017ULL,
		0xA817D6C3632F433EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FBDE703323934EAULL,
		0xB899FF6742B7F734ULL,
		0x85A9A5547E1604C5ULL,
		0x8E0A99F51D338E7EULL,
		0x04BD9E02882B31F7ULL,
		0x98644E1319A9685FULL,
		0x37C3503D1500D5D8ULL,
		0x811D87FCE0D3C121ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x43D487477C3E3636ULL,
		0x78EAC253F34A94E9ULL,
		0x780E5EF462BEF475ULL,
		0xA4C6751758ECDD95ULL,
		0x9AFB502472E17A70ULL,
		0x11C3203905EA11A1ULL,
		0x384CEA9C94A19D43ULL,
		0xDE8C7BDCF529CE53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2430630D408630ULL,
		0x2919CA73236C7FD5ULL,
		0xF29C5B204F47969DULL,
		0x4F1EF42CE3D62998ULL,
		0x279EC9F7B2F90551ULL,
		0x71007403742F0705ULL,
		0x437382653064D561ULL,
		0x21EF3EC19E90F13AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28B056E46EFDB006ULL,
		0x4FD0F7E0CFDE1514ULL,
		0x857203D413775DD8ULL,
		0x55A780EA7516B3FCULL,
		0x735C862CBFE8751FULL,
		0xA0C2AC3591BB0A9CULL,
		0xF4D96837643CC7E1ULL,
		0xBC9D3D1B5698DD18ULL
	}};
	sign = 0;
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
		0x27AA5C501A1BC3F8ULL,
		0xD8186B50B4E1E0C7ULL,
		0x304561B5B89B95ECULL,
		0x63EBEDAAEA04D659ULL,
		0x0F0B32BA9736B33CULL,
		0xD552C841D2394E04ULL,
		0xA0AECACD31E19DB0ULL,
		0x5449BBDF275BD97DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B804C300EEF9E2EULL,
		0x229E644165A57DC8ULL,
		0x1442E2BF9091B0F1ULL,
		0x968E56E23F30FD15ULL,
		0x8DEA573C14514958ULL,
		0xAF6589DBEB406474ULL,
		0x4CBDCC1429345111ULL,
		0x1196D5536AA89721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC2A10200B2C25CAULL,
		0xB57A070F4F3C62FEULL,
		0x1C027EF62809E4FBULL,
		0xCD5D96C8AAD3D944ULL,
		0x8120DB7E82E569E3ULL,
		0x25ED3E65E6F8E98FULL,
		0x53F0FEB908AD4C9FULL,
		0x42B2E68BBCB3425CULL
	}};
	sign = 0;
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
		0x86C50C392E31CCB3ULL,
		0x81E3F81A39143A1BULL,
		0xE8B6B3B1B187E673ULL,
		0x691AA375D1419760ULL,
		0x1648EEE044AC42C3ULL,
		0x51AA87D66C3993FBULL,
		0x02E895EA6CF336E6ULL,
		0xD1F921889A600FCBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2ECB2B10E61A6BAULL,
		0xC19BCFEF189C5074ULL,
		0x2D33DF10DDB7DD99ULL,
		0x9953051306F2BD22ULL,
		0x3450E28F8F1A54F5ULL,
		0x9E6A654177789B2CULL,
		0xA1C4BE1AD9337DDFULL,
		0x9FD611FF66B97261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3D859881FD025F9ULL,
		0xC048282B2077E9A6ULL,
		0xBB82D4A0D3D008D9ULL,
		0xCFC79E62CA4EDA3EULL,
		0xE1F80C50B591EDCDULL,
		0xB3402294F4C0F8CEULL,
		0x6123D7CF93BFB906ULL,
		0x32230F8933A69D69ULL
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
		0x863B7D9CE678917FULL,
		0xB959828D2C01DEABULL,
		0xB5DB5994279718BCULL,
		0xC68C36AB1F4257CDULL,
		0x1396AED96EB76325ULL,
		0x370D554EC0008395ULL,
		0xD138FD2DB2F9B59AULL,
		0x0109D3CF9AC385CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB9A2B1F948E131ULL,
		0x0C808A06D39AB376ULL,
		0x48DB330A5D4DC2FAULL,
		0x7C7340B897CBFA22ULL,
		0x156CC7E2DDFE3953ULL,
		0x6786CDA956B3E4E3ULL,
		0x47EFD907278D3C5BULL,
		0x10464C8D24A60AB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD781DAEAED2FB04EULL,
		0xACD8F88658672B34ULL,
		0x6D002689CA4955C2ULL,
		0x4A18F5F287765DABULL,
		0xFE29E6F690B929D2ULL,
		0xCF8687A5694C9EB1ULL,
		0x894924268B6C793EULL,
		0xF0C38742761D7B18ULL
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
		0xF1B82996A89C43B4ULL,
		0xA3BF9DB7A1DF3AE7ULL,
		0xFCC8B0592AB5E011ULL,
		0x147FCB32F5180DECULL,
		0x46C03911138F6512ULL,
		0x0ADBB28694B8F152ULL,
		0x46673A5BCD7148CFULL,
		0x75F0B2D113FFA4DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52051064EA0DC163ULL,
		0x09ADDBE9FD5B1FB6ULL,
		0x1B06E326E574FDD1ULL,
		0xD642CAAD323B2A31ULL,
		0x36A039E995A34117ULL,
		0xB6272E95C00CAAB4ULL,
		0x5718B0B232E3A74CULL,
		0xF25729D427474935ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FB31931BE8E8251ULL,
		0x9A11C1CDA4841B31ULL,
		0xE1C1CD324540E240ULL,
		0x3E3D0085C2DCE3BBULL,
		0x101FFF277DEC23FAULL,
		0x54B483F0D4AC469EULL,
		0xEF4E89A99A8DA182ULL,
		0x839988FCECB85BA4ULL
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
		0xF546AC615E7A0430ULL,
		0xB276195A291B7CB2ULL,
		0xF2A622E46403BDD8ULL,
		0x92C95D59CF3EEF42ULL,
		0x3EFC924130496888ULL,
		0x0FE638CF8D9BF57DULL,
		0xC3A5ED2A88F8AAC6ULL,
		0x36F484FE641FDADCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF1D8AF0207BF167ULL,
		0xBBD26DD03076387BULL,
		0xE63D9CC86177C670ULL,
		0x96A6C42FB70B369CULL,
		0x7FCDC7FBC7E89879ULL,
		0x71C56E883EBEF74DULL,
		0x6705B69CA183C1C0ULL,
		0x578E94FDEED877C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x462921713DFE12C9ULL,
		0xF6A3AB89F8A54437ULL,
		0x0C68861C028BF767ULL,
		0xFC22992A1833B8A6ULL,
		0xBF2ECA456860D00EULL,
		0x9E20CA474EDCFE2FULL,
		0x5CA0368DE774E905ULL,
		0xDF65F00075476319ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCEFF23DF9486AF24ULL,
		0x20C4D5DB37C15BF6ULL,
		0x14A8A8EE7B02FCD2ULL,
		0x2FA60A2965B3B312ULL,
		0x0EC5DADE84819740ULL,
		0xCA4EC21CEE35C4F1ULL,
		0x145AF10707A3FD12ULL,
		0x510A31285B32C62AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C64227665D2FA1BULL,
		0xA03845958C6AC649ULL,
		0x090C6523D908ED4FULL,
		0x67E08759A67FFECCULL,
		0x1624E4003EB99934ULL,
		0xD594ECB755E15AC3ULL,
		0xDB30C92D3A569C59ULL,
		0x3CDC5569814D5690ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x729B01692EB3B509ULL,
		0x808C9045AB5695ADULL,
		0x0B9C43CAA1FA0F82ULL,
		0xC7C582CFBF33B446ULL,
		0xF8A0F6DE45C7FE0BULL,
		0xF4B9D56598546A2DULL,
		0x392A27D9CD4D60B8ULL,
		0x142DDBBED9E56F99ULL
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
		0x09C8868DFFD97555ULL,
		0xB797A0DCB40CB19DULL,
		0x8861253AE6A9315FULL,
		0xDC42C516CD91E16EULL,
		0x10BB1E4CF6A96BC2ULL,
		0x4279025804B99915ULL,
		0xF103F731D3B71DBDULL,
		0xA4E166D5433CCEAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x782697B5BE0DC5F7ULL,
		0x17BC6F0124546FECULL,
		0x56A066C985A0BF9BULL,
		0x1FD7269B6E80CABDULL,
		0x89BB2F09B8FCA543ULL,
		0x33410DE42D623CEDULL,
		0xBDB6E38FD3F1294FULL,
		0x3F718B6F84F07719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91A1EED841CBAF5EULL,
		0x9FDB31DB8FB841B0ULL,
		0x31C0BE71610871C4ULL,
		0xBC6B9E7B5F1116B1ULL,
		0x86FFEF433DACC67FULL,
		0x0F37F473D7575C27ULL,
		0x334D13A1FFC5F46EULL,
		0x656FDB65BE4C5796ULL
	}};
	sign = 0;
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
		0x1E6FAD96B31D931EULL,
		0xE036765E87062C43ULL,
		0xB9C3489AC10786F3ULL,
		0xA2813F48CF3DAB49ULL,
		0x4D42177714BE16D1ULL,
		0x6CEE5C2F12122D10ULL,
		0x8A83996BC368F035ULL,
		0xA1AAC282F6C36795ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA694E19D6C49A37DULL,
		0xD49E6B4A44764795ULL,
		0x15BB952CDF5F6E51ULL,
		0x005AEDD92F9A9E79ULL,
		0xBCB5A1C6033562B3ULL,
		0x3660C725C261C7E7ULL,
		0x76F5D0DF3582DB66ULL,
		0xBB41D841B6761ED7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77DACBF946D3EFA1ULL,
		0x0B980B14428FE4ADULL,
		0xA407B36DE1A818A2ULL,
		0xA226516F9FA30CD0ULL,
		0x908C75B11188B41EULL,
		0x368D95094FB06528ULL,
		0x138DC88C8DE614CFULL,
		0xE668EA41404D48BEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x70B233335DC3BF06ULL,
		0x5ADBAB2AF580890DULL,
		0xA7CAC10348907B03ULL,
		0xA974CBC46444C26CULL,
		0x2D24A5FA58E64965ULL,
		0x3C4A46656A1C22B6ULL,
		0xA481BB9795A702F9ULL,
		0x44A639FDBFFB4E05ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3851468C1755BD2FULL,
		0x3C2919B22168CAE9ULL,
		0xA6810F58C42A970FULL,
		0xD02D5FEB0BD4F360ULL,
		0xA1B1BDC327C557B8ULL,
		0xC94C366E3A17F355ULL,
		0x70B230F49F299D9DULL,
		0x670669F65BE46E29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3860ECA7466E01D7ULL,
		0x1EB29178D417BE24ULL,
		0x0149B1AA8465E3F4ULL,
		0xD9476BD9586FCF0CULL,
		0x8B72E8373120F1ACULL,
		0x72FE0FF730042F60ULL,
		0x33CF8AA2F67D655BULL,
		0xDD9FD0076416DFDCULL
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
		0x5758ADD56AD2D671ULL,
		0x33DF24CB6C3925E9ULL,
		0x56DE3D25020E462DULL,
		0xCF8D71CCC39DE622ULL,
		0x9FC4B24BA0A2DBA7ULL,
		0xEA79A07D323142DBULL,
		0xB95C973EEEB7CCCFULL,
		0xC639B501DD767F45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CB40802CDA7AE8AULL,
		0xC03F271858BB4488ULL,
		0x7294105C9D9EED7EULL,
		0xF78C9291DA32300CULL,
		0x9EB8FA6A41123BD7ULL,
		0x7A990D96D52A7AB3ULL,
		0x0A5988BA42A8C8E4ULL,
		0xFA1E1AC09DB8C12DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AA4A5D29D2B27E7ULL,
		0x739FFDB3137DE161ULL,
		0xE44A2CC8646F58AEULL,
		0xD800DF3AE96BB615ULL,
		0x010BB7E15F909FCFULL,
		0x6FE092E65D06C828ULL,
		0xAF030E84AC0F03EBULL,
		0xCC1B9A413FBDBE18ULL
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
		0x6DB1DCCDF3AA88C0ULL,
		0xEB65BB5B7A32ECDBULL,
		0x2EF272A46D34D585ULL,
		0x0FCC5F8EE13FA5C4ULL,
		0x4520D56C04187358ULL,
		0x389952D9079F787AULL,
		0x622190F7ED503DB4ULL,
		0x44CE02825ADFFF48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4151F207938470A5ULL,
		0xEA8D7397782A69AAULL,
		0x4EC1370ADF0B62B0ULL,
		0xA0773907930AAA73ULL,
		0xF7B0401211E278E3ULL,
		0x921D854338291451ULL,
		0x3987D8173F58C8C2ULL,
		0xCC0810658FF847BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C5FEAC66026181BULL,
		0x00D847C402088331ULL,
		0xE0313B998E2972D5ULL,
		0x6F5526874E34FB50ULL,
		0x4D709559F235FA74ULL,
		0xA67BCD95CF766428ULL,
		0x2899B8E0ADF774F1ULL,
		0x78C5F21CCAE7B789ULL
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
		0x8EF1D9CA8EBDB812ULL,
		0x402AF1AE9FF0E55DULL,
		0x1DE11D6ECEF9E840ULL,
		0xDF788B7A90493D02ULL,
		0xEEA8F7D7BF959838ULL,
		0x47B96F3E3BCC66EEULL,
		0xE90D1D6055CEC538ULL,
		0x4F1192158F17158FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF1E527D2C7DEF29ULL,
		0xC1A7F80796DA55DBULL,
		0xF346500DF7926FE4ULL,
		0x850CF5EF264D1B50ULL,
		0xF37256D78FA9A2FBULL,
		0x7254FEF1F7EFCFE6ULL,
		0xC21896C631DF65B5ULL,
		0x0164D93497F20CDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFD3874D623FC8E9ULL,
		0x7E82F9A709168F81ULL,
		0x2A9ACD60D767785BULL,
		0x5A6B958B69FC21B1ULL,
		0xFB36A1002FEBF53DULL,
		0xD564704C43DC9707ULL,
		0x26F4869A23EF5F82ULL,
		0x4DACB8E0F72508B4ULL
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
		0xDAF0F75EF9BDDEB7ULL,
		0x4C6CAEB3B6F8937FULL,
		0x7A3EEABC6946C31DULL,
		0xAA793A29193AA8F5ULL,
		0xBF152B10A9EFF687ULL,
		0xD3E5EEDC02410464ULL,
		0x7B9902039CABC6C3ULL,
		0x50CD75B353617849ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x143A6269CA467A9CULL,
		0xFD81C3BF0A8C2B62ULL,
		0x8A5F1D45B58D72CCULL,
		0x1177CFD61EAFB375ULL,
		0x2595667EC7E94879ULL,
		0x46331E7A7CC016A3ULL,
		0x30703DCFE0120E1AULL,
		0x95A65ACC45669968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6B694F52F77641BULL,
		0x4EEAEAF4AC6C681DULL,
		0xEFDFCD76B3B95050ULL,
		0x99016A52FA8AF57FULL,
		0x997FC491E206AE0EULL,
		0x8DB2D0618580EDC1ULL,
		0x4B28C433BC99B8A9ULL,
		0xBB271AE70DFADEE1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x951E947C5879218AULL,
		0xD53C5A8956447A1EULL,
		0x1481E2F6EFFB6057ULL,
		0xA96826CEF7155993ULL,
		0x8E7991A8FEC7F357ULL,
		0xF3CCD11325A897D2ULL,
		0x49B9D589FED9FBCFULL,
		0xBAAB528A96A74890ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02869F966186821FULL,
		0xFB11C5F80CBC97CEULL,
		0x9728A1FDECBA88D1ULL,
		0xC49611C2169F6764ULL,
		0xB1D29CAFE2A02E2DULL,
		0xF907D281B3EF2196ULL,
		0x6AC1B03D8C9D3CA2ULL,
		0x2C1C54B64739D645ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9297F4E5F6F29F6BULL,
		0xDA2A94914987E250ULL,
		0x7D5940F90340D785ULL,
		0xE4D2150CE075F22EULL,
		0xDCA6F4F91C27C529ULL,
		0xFAC4FE9171B9763BULL,
		0xDEF8254C723CBF2CULL,
		0x8E8EFDD44F6D724AULL
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
		0x2A4BC4F6E2D3F14CULL,
		0x1E06163FC8CB6994ULL,
		0x5C5758190BF8239BULL,
		0x7E7DAF6F71EF16F4ULL,
		0x8D1BDBE6EB24CF2AULL,
		0x97C3159A51951B34ULL,
		0x188AC0B6DD8F560AULL,
		0xDD2976EB6D0533FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B4FCA74F3DF9EFULL,
		0x7829CD67A52CBEE1ULL,
		0xF2DA76DCC112AA33ULL,
		0xC83841C4BE9B3186ULL,
		0x2F8D5AFD06A32FC4ULL,
		0xFCCD7BFE9023BA5CULL,
		0xBAC28B4F5680C68DULL,
		0x29A4F560A9E2AE78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA296C84F9395F75DULL,
		0xA5DC48D8239EAAB2ULL,
		0x697CE13C4AE57967ULL,
		0xB6456DAAB353E56DULL,
		0x5D8E80E9E4819F65ULL,
		0x9AF5999BC17160D8ULL,
		0x5DC83567870E8F7CULL,
		0xB384818AC3228583ULL
	}};
	sign = 0;
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
		0x024E8ED6A9A455FEULL,
		0x398CDE00F3DD1BE0ULL,
		0xE86E16F3768CB290ULL,
		0x480A3920A448643EULL,
		0xFCA7726CBD5869A4ULL,
		0x4603752D8CE4DFB3ULL,
		0x7ED1349D2B692751ULL,
		0x96CF03C842C4F070ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92FFFA4794CD272ULL,
		0xDB09D57E9190818CULL,
		0x554B894650ADA03EULL,
		0x4513F906CA55C0A2ULL,
		0x531BAB3773A2077CULL,
		0xB8EADA52FF1044B8ULL,
		0x05FF8CD95C3AA74DULL,
		0xA961A8A94EA74871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x491E8F323057838CULL,
		0x5E830882624C9A53ULL,
		0x93228DAD25DF1251ULL,
		0x02F64019D9F2A39CULL,
		0xA98BC73549B66228ULL,
		0x8D189ADA8DD49AFBULL,
		0x78D1A7C3CF2E8003ULL,
		0xED6D5B1EF41DA7FFULL
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
		0x3C4EE12215B68AD9ULL,
		0x93AB61C514A0BD47ULL,
		0x699D16B22C10A738ULL,
		0x35D2A9A21C936E84ULL,
		0x32D307ECCA5BE5A5ULL,
		0x1F96DC8EED677CFCULL,
		0xBCDACBBC447DA6EEULL,
		0x942427AEB4EC3666ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A91F6D4262E027ULL,
		0x8E1412F708980606ULL,
		0x7AB0E0F55DF9C05BULL,
		0xBE2AFABFE44E1A46ULL,
		0xE56C4ECCE6D21E54ULL,
		0xCB4A5ACB34C85D7BULL,
		0xAE0F8D7645B9504EULL,
		0x5236F8FDFF990EEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8A5C1B4D353AAB2ULL,
		0x05974ECE0C08B740ULL,
		0xEEEC35BCCE16E6DDULL,
		0x77A7AEE23845543DULL,
		0x4D66B91FE389C750ULL,
		0x544C81C3B89F1F80ULL,
		0x0ECB3E45FEC4569FULL,
		0x41ED2EB0B5532778ULL
	}};
	sign = 0;
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
		0x82F88C2D1CA66FA1ULL,
		0xD27E8D7A083AF659ULL,
		0xFA1E190C01F5337BULL,
		0x696E5164B16EC33AULL,
		0x65AF318421082BC2ULL,
		0x48AAEAC2BFAC58F5ULL,
		0xBC74D0BF41875929ULL,
		0x2754228A738A607AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA0B7CB79E6F1C8ULL,
		0x6F731E9D7E7C207EULL,
		0x073D16873EE7976FULL,
		0xED186361A0546356ULL,
		0xFF40F3A32018EF34ULL,
		0x23BB40C7FA71F379ULL,
		0x4D6A23270F1BC368ULL,
		0x620CEBA584B62BEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5857D461A2BF7DD9ULL,
		0x630B6EDC89BED5DBULL,
		0xF2E10284C30D9C0CULL,
		0x7C55EE03111A5FE4ULL,
		0x666E3DE100EF3C8DULL,
		0x24EFA9FAC53A657BULL,
		0x6F0AAD98326B95C1ULL,
		0xC54736E4EED4348BULL
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
		0x4CC78AE2CF406138ULL,
		0xE9C6851E0D92871BULL,
		0x4541B46040269E04ULL,
		0x4153E235D13C7019ULL,
		0xF053138CE5144A8FULL,
		0x51583325B00B17B7ULL,
		0x1C734AF2654CFE95ULL,
		0xC0479886D571846FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D38F6AABBB2A94ULL,
		0xDCEC91E0C3513238ULL,
		0xF178952DD8E47238ULL,
		0xDBC2E794531FFB3AULL,
		0x51CBCF5525D7FA64ULL,
		0x858B4486D87D40D7ULL,
		0x0CC8B9AA0F92CF21ULL,
		0x73C0BACBC255C90EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9F3FB78238536A4ULL,
		0x0CD9F33D4A4154E2ULL,
		0x53C91F3267422BCCULL,
		0x6590FAA17E1C74DEULL,
		0x9E874437BF3C502AULL,
		0xCBCCEE9ED78DD6E0ULL,
		0x0FAA914855BA2F73ULL,
		0x4C86DDBB131BBB61ULL
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
		0xD482B349696D5A87ULL,
		0x1C20A13F7D5ADE28ULL,
		0x7F8AD0D54CCFA0D2ULL,
		0x5451016FCB33A451ULL,
		0x9C79D06B3C4D9F28ULL,
		0xDAE3DAF887BB35B8ULL,
		0x76D382C627BF1D6FULL,
		0xEA5B6440CBE65F01ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x314EDBFD7737923CULL,
		0x26D1ECDCFD09F0A0ULL,
		0x3888658F8CA44ED5ULL,
		0x659A11F1905FA329ULL,
		0xBFD906EDEC5EC079ULL,
		0xB409EC6528EE0F33ULL,
		0xC2220CC7CE9CC106ULL,
		0xC5E28CEC6E1CD257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA333D74BF235C84BULL,
		0xF54EB4628050ED88ULL,
		0x47026B45C02B51FCULL,
		0xEEB6EF7E3AD40128ULL,
		0xDCA0C97D4FEEDEAEULL,
		0x26D9EE935ECD2684ULL,
		0xB4B175FE59225C69ULL,
		0x2478D7545DC98CA9ULL
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
		0xB88C1C023F0BF630ULL,
		0x0C3CEBB180025056ULL,
		0x8CC821919E7179F9ULL,
		0xE9C8D6FD156CF634ULL,
		0xA9019D0D6C3A0232ULL,
		0xA9D54B7499252E15ULL,
		0xDC297AFE19493739ULL,
		0xA233B7E3C8FAFAC5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A60400E997EC235ULL,
		0x512CBAF577A8957BULL,
		0xE2AFE49B454AAFABULL,
		0x1A5331D66262D3FDULL,
		0x451B7FF67B72B3D2ULL,
		0x48B0338D2741D8A0ULL,
		0xF71E858A7415663FULL,
		0x0F5A530BF98625DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E2BDBF3A58D33FBULL,
		0xBB1030BC0859BADBULL,
		0xAA183CF65926CA4DULL,
		0xCF75A526B30A2236ULL,
		0x63E61D16F0C74E60ULL,
		0x612517E771E35575ULL,
		0xE50AF573A533D0FAULL,
		0x92D964D7CF74D4EAULL
	}};
	sign = 0;
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
		0x2AAC07808CDDCC3FULL,
		0xCC8F32A1DADC03CBULL,
		0x3DFAFA5EE5670813ULL,
		0x4E2EB0FE6276E940ULL,
		0x000F7575F829420BULL,
		0x9ADCE7149223749CULL,
		0xBE2511B641899B37ULL,
		0x6FB136B5B87FD0B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE55BD3D76D6A4E1ULL,
		0x8AF5E13841CB937EULL,
		0x2F0091248FB97C55ULL,
		0xBDE3294B3D679FB0ULL,
		0x229E0A0D8829E537ULL,
		0x28FCA1C12C1A0083ULL,
		0xE8BE09067E7B52F1ULL,
		0x3FD91EE31D58EB1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C564A431607275EULL,
		0x419951699910704CULL,
		0x0EFA693A55AD8BBEULL,
		0x904B87B3250F4990ULL,
		0xDD716B686FFF5CD3ULL,
		0x71E0455366097418ULL,
		0xD56708AFC30E4846ULL,
		0x2FD817D29B26E59BULL
	}};
	sign = 0;
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
		0x8A2454088DE927CAULL,
		0xCB8D3AA972183BD5ULL,
		0xBD2946FCA331AE5EULL,
		0xC9F8935B4889D1DAULL,
		0x8667309B4E538729ULL,
		0x2C356E6AA571785AULL,
		0xD2D4783BFE407EE2ULL,
		0xEDC6B3BAA310986EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x959768EC41A698F5ULL,
		0x25111D3B21B4A0BAULL,
		0x4AF352C881A61BBAULL,
		0x3ADE561AEA02C223ULL,
		0xDD3CB246BD09AF46ULL,
		0x2C64E984E245D182ULL,
		0x6F5E99F9EA4DB54AULL,
		0xCF36067EA811C0FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF48CEB1C4C428ED5ULL,
		0xA67C1D6E50639B1AULL,
		0x7235F434218B92A4ULL,
		0x8F1A3D405E870FB7ULL,
		0xA92A7E549149D7E3ULL,
		0xFFD084E5C32BA6D7ULL,
		0x6375DE4213F2C997ULL,
		0x1E90AD3BFAFED774ULL
	}};
	sign = 0;
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
		0xB4B2DE84B7D43B61ULL,
		0x3305C033CDF53DCDULL,
		0x165823665614D087ULL,
		0x0993F4EE68B29894ULL,
		0x524DE8E1CA4AC16EULL,
		0x8C2A898A8C444349ULL,
		0x2165D68EBF722B3EULL,
		0x8CB1F48AD92517C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5B7EF88F4A1689ULL,
		0x9960E5C2106198D5ULL,
		0xD0038A6FB1692DBBULL,
		0x98B967C6710AC905ULL,
		0x0FF03A2D760E05ECULL,
		0x16278F5C431E95E9ULL,
		0xAE13CEE0107B18E1ULL,
		0x4FBD077AD2DDBD86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA575F8C288A24D8ULL,
		0x99A4DA71BD93A4F7ULL,
		0x465498F6A4ABA2CBULL,
		0x70DA8D27F7A7CF8EULL,
		0x425DAEB4543CBB81ULL,
		0x7602FA2E4925AD60ULL,
		0x735207AEAEF7125DULL,
		0x3CF4ED1006475A3BULL
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
		0x8CFCC4CD286BC4FDULL,
		0x57296E5D13D1555FULL,
		0x43E7E9C8EC08E1BBULL,
		0xCD4314578A7B5F71ULL,
		0xACF380AC04CACABDULL,
		0x9A4B99C2B9271503ULL,
		0xF9508779B512A745ULL,
		0x0F7F2ED5C780CC07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A4077B3E14B55EULL,
		0x5A938C9C74E3F55BULL,
		0xB6DD0FA053EF8E7AULL,
		0xFC8764C7FB8F9E0BULL,
		0x9EE61B0DD7A3629EULL,
		0xA5070C8EAA79DE77ULL,
		0xE5BE7030BFC1BDCBULL,
		0x1A1BCE5F6AFE18A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C58BD51EA570F9FULL,
		0xFC95E1C09EED6004ULL,
		0x8D0ADA2898195340ULL,
		0xD0BBAF8F8EEBC165ULL,
		0x0E0D659E2D27681EULL,
		0xF5448D340EAD368CULL,
		0x13921748F550E979ULL,
		0xF56360765C82B364ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE6673532530947C8ULL,
		0x17EF5BD520F15C5EULL,
		0xF5492644FD59CD35ULL,
		0xF2B98827DF34CFB2ULL,
		0x0BB2ADA7E64BAC26ULL,
		0x76A6160507D7EBFDULL,
		0xDB4A738F4646CCF0ULL,
		0x8FD269A3C4612EC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC20EDF4E945FD49ULL,
		0x3D57435C3E3A0DC5ULL,
		0xF2E1D7D11E34820BULL,
		0xB8A8D91F06A30AB9ULL,
		0x55351A6D8870CB97ULL,
		0xD41DD3F7F28F5524ULL,
		0x5D4EC3E290E466E6ULL,
		0xB83CDFB9E9C8A120ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A46473D69C34A7FULL,
		0xDA981878E2B74E99ULL,
		0x02674E73DF254B29ULL,
		0x3A10AF08D891C4F9ULL,
		0xB67D933A5DDAE08FULL,
		0xA288420D154896D8ULL,
		0x7DFBAFACB5626609ULL,
		0xD79589E9DA988DA4ULL
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
		0xBEDC2C59054C9215ULL,
		0x4A6CD4B73D75A591ULL,
		0xC5A82893F54D2F83ULL,
		0xEB9E91B85F9DADAEULL,
		0xC9B02722D68405E5ULL,
		0x32D35E96C36B3C72ULL,
		0xC1C22674CC609A9CULL,
		0xB3A8668F3B80F970ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C9F149E5CC8A94FULL,
		0xB6FF80DE80866D1EULL,
		0xCECC11923A4752CAULL,
		0x0499CDECB03EEFDAULL,
		0x66E1EF4CC8F87240ULL,
		0x6E2C4C1B08E7B96DULL,
		0x2C935F3772CD6DC4ULL,
		0xD054F60A645E9504ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x423D17BAA883E8C6ULL,
		0x936D53D8BCEF3873ULL,
		0xF6DC1701BB05DCB8ULL,
		0xE704C3CBAF5EBDD3ULL,
		0x62CE37D60D8B93A5ULL,
		0xC4A7127BBA838305ULL,
		0x952EC73D59932CD7ULL,
		0xE3537084D722646CULL
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
		0x1A8FC437BEC1AEAAULL,
		0x1AD8E74E702EB7E9ULL,
		0xE40A465B3AB1E42CULL,
		0xCBB6C037FAC2F129ULL,
		0x973950DEB74F258CULL,
		0xE40A4ABDE6EFBD2AULL,
		0x0E4197A0F801377CULL,
		0x6247E04156F65EFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x49946CA14AA72D12ULL,
		0x427DA9A65B56E73DULL,
		0x5032592ACE1B3928ULL,
		0xC4A6F57E811D6F3CULL,
		0xDB72CDE1D2EC665BULL,
		0xF082B3AFD5268E39ULL,
		0xB1D7C471C5169B6EULL,
		0x46765F13785C1EDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0FB5796741A8198ULL,
		0xD85B3DA814D7D0ABULL,
		0x93D7ED306C96AB03ULL,
		0x070FCAB979A581EDULL,
		0xBBC682FCE462BF31ULL,
		0xF387970E11C92EF0ULL,
		0x5C69D32F32EA9C0DULL,
		0x1BD1812DDE9A4020ULL
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
		0x45F9B215438FFDABULL,
		0xDAE67EBA3AED2C73ULL,
		0x5CB4CA92964F528DULL,
		0x03107BA384BBED5CULL,
		0x9FF35CC91C6B712DULL,
		0xF4C2A9DA7895920EULL,
		0x9168A96F6AE84DA0ULL,
		0x297BF62988052330ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x679FB4BBF66CAA2CULL,
		0x89AF44A1EDD98F31ULL,
		0xE914436B43537FFCULL,
		0xF0395BB247E58FE2ULL,
		0xFB303CCE06B6BD14ULL,
		0x0E8267AC079DD265ULL,
		0x853F0AC6F79DCEF0ULL,
		0x9EF529AA98A14E51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE59FD594D23537FULL,
		0x51373A184D139D41ULL,
		0x73A0872752FBD291ULL,
		0x12D71FF13CD65D79ULL,
		0xA4C31FFB15B4B418ULL,
		0xE640422E70F7BFA8ULL,
		0x0C299EA8734A7EB0ULL,
		0x8A86CC7EEF63D4DFULL
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
		0x89739B8DC1B76D13ULL,
		0x5688505E068C2BB4ULL,
		0x352EDC1150DFADC3ULL,
		0x86C1236268B2CC16ULL,
		0xB23D41825F7E618BULL,
		0x8DEB1F2910B06091ULL,
		0x8752E67A9768F8CEULL,
		0x087D11F8AC74B8D0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0730514421CF799ULL,
		0xBA36F175792436C3ULL,
		0xDA76C506AE781E9BULL,
		0x10F713415167C611ULL,
		0xFCE5EB5D7E5234F2ULL,
		0x0199BB1294721B47ULL,
		0x3CFD4F13E45345E2ULL,
		0x7C96ABDE11387602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD90096797F9A757AULL,
		0x9C515EE88D67F4F0ULL,
		0x5AB8170AA2678F27ULL,
		0x75CA1021174B0604ULL,
		0xB5575624E12C2C99ULL,
		0x8C5164167C3E4549ULL,
		0x4A559766B315B2ECULL,
		0x8BE6661A9B3C42CEULL
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
		0x00336C6B4D9A54A1ULL,
		0x208DE88E76F814DEULL,
		0xE969AABBDAA67BDCULL,
		0x0213FF0B2965DFEFULL,
		0x7AF825EB8FE74676ULL,
		0xCB4432EE891BA067ULL,
		0xCDB85156D17B3E97ULL,
		0x77B44CD8F4E82A80ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA52B34661622634ULL,
		0x2AE67AD43AB21591ULL,
		0x6B434E9505ECC19EULL,
		0x1EAE88E4C3585157ULL,
		0x9B74379D3D78EA4FULL,
		0x9001648AFC43F590ULL,
		0x82552E1E28B91DE7ULL,
		0xB7AF1BC68FA33D95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45E0B924EC382E6DULL,
		0xF5A76DBA3C45FF4CULL,
		0x7E265C26D4B9BA3DULL,
		0xE3657626660D8E98ULL,
		0xDF83EE4E526E5C26ULL,
		0x3B42CE638CD7AAD6ULL,
		0x4B632338A8C220B0ULL,
		0xC00531126544ECEBULL
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
		0x1E398FC9907A9127ULL,
		0x453AF6A98E0A1FE9ULL,
		0x37001083586727CCULL,
		0xB57F8667A931C7C4ULL,
		0x7B21BF69C80B0BBFULL,
		0x1450DFB30DC7990DULL,
		0xF392AFB4CBDFDA47ULL,
		0x335F97F3C94D4DBCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x99FE94B82A68ABC6ULL,
		0x250C8E3E78C4D0A6ULL,
		0xD82750BE0EC08372ULL,
		0x240895B4B55DE7BDULL,
		0x369A1234367AB8A3ULL,
		0x7C6EE0D96BC9500FULL,
		0x9CFF61DEC29E4E68ULL,
		0xA5F66B49F241C99FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x843AFB116611E561ULL,
		0x202E686B15454F42ULL,
		0x5ED8BFC549A6A45AULL,
		0x9176F0B2F3D3E006ULL,
		0x4487AD359190531CULL,
		0x97E1FED9A1FE48FEULL,
		0x56934DD609418BDEULL,
		0x8D692CA9D70B841DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x670D8A36E5FDEF1AULL,
		0xD423555C9A13D0BBULL,
		0x87E44F3DBB291C41ULL,
		0x23DF0695AA8ED188ULL,
		0x863A99F85CCDDF68ULL,
		0x5F8F9CD8AC5765E7ULL,
		0x4F4544C8CD710577ULL,
		0x404733BA2A51A2E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12306D57C3AE94A2ULL,
		0xAC02098C87272DFDULL,
		0x92E581590ABA8B70ULL,
		0xC50BBE7ED24B8E98ULL,
		0x806148555727FF72ULL,
		0xF83809F94BD33E78ULL,
		0x005AB34D1DB8B27DULL,
		0x155FC27EA845AFB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54DD1CDF224F5A78ULL,
		0x28214BD012ECA2BEULL,
		0xF4FECDE4B06E90D1ULL,
		0x5ED34816D84342EFULL,
		0x05D951A305A5DFF5ULL,
		0x675792DF6084276FULL,
		0x4EEA917BAFB852F9ULL,
		0x2AE7713B820BF32BULL
	}};
	sign = 0;
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
		0x349EC4457EF2E956ULL,
		0x42D487CC01149424ULL,
		0x35C2061DC9A28B14ULL,
		0x163C1D5D3FCEC06CULL,
		0x856EB1ADE21AB89BULL,
		0x5E7E3C10D39F59D8ULL,
		0xC3A79F44B0D3ED7CULL,
		0x3F18EBF73E7CEB6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9299C22CDD5CDF61ULL,
		0x6D2DCCC4B0C1D643ULL,
		0xFF9AF65EB327C1F6ULL,
		0x6E8565CB0CDD4A2EULL,
		0x76EA2D8707CBF783ULL,
		0xEC2066CBE02FA13DULL,
		0x5DDDE07410BE61D8ULL,
		0x37FE54D16488A622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2050218A19609F5ULL,
		0xD5A6BB075052BDE0ULL,
		0x36270FBF167AC91DULL,
		0xA7B6B79232F1763DULL,
		0x0E848426DA4EC117ULL,
		0x725DD544F36FB89BULL,
		0x65C9BED0A0158BA3ULL,
		0x071A9725D9F4454AULL
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
		0x3A07748EAEA494D6ULL,
		0xD1BFC58EADF6ACDDULL,
		0x127EFD246F30E4EDULL,
		0x81FC9180E13B459AULL,
		0x85E3E1828591B332ULL,
		0x13B1D92C117690E8ULL,
		0x5C2904D2550ABA24ULL,
		0x3A3BA8B00FFA6F85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD645889AEF4A0CC9ULL,
		0x1F9F0305DF764AB5ULL,
		0x6D618526C286B558ULL,
		0x4ADB07E135253C28ULL,
		0xE6BAFD59D2EAAE7EULL,
		0xE93ABEABE81E4546ULL,
		0x9BCB28EBE497EA85ULL,
		0x870D10F12D392B3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63C1EBF3BF5A880DULL,
		0xB220C288CE806227ULL,
		0xA51D77FDACAA2F95ULL,
		0x3721899FAC160971ULL,
		0x9F28E428B2A704B4ULL,
		0x2A771A8029584BA1ULL,
		0xC05DDBE67072CF9EULL,
		0xB32E97BEE2C14448ULL
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
		0x7D13E032839179D7ULL,
		0x9A7BE1D5FE603881ULL,
		0x50AAE239BCFB475FULL,
		0x5A21095CD30A4D29ULL,
		0x73BB656B7E2094C6ULL,
		0x4811D99BE64AF588ULL,
		0x3268595DC34031FFULL,
		0xD4A448E916E99921ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0226644F7F761CF9ULL,
		0x52DC0D57EBF8D897ULL,
		0x48327A9BB5E1C647ULL,
		0xC692D9D515930445ULL,
		0x3C78AEDE8EF38B3EULL,
		0x7B1BF08EC618434FULL,
		0x5C63693DFE956F62ULL,
		0xF3EE6F3AD3F15863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AED7BE3041B5CDEULL,
		0x479FD47E12675FEAULL,
		0x0878679E07198118ULL,
		0x938E2F87BD7748E4ULL,
		0x3742B68CEF2D0987ULL,
		0xCCF5E90D2032B239ULL,
		0xD604F01FC4AAC29CULL,
		0xE0B5D9AE42F840BDULL
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
		0x5CE57550871F0104ULL,
		0xCD62ECF43ABB4480ULL,
		0x413E5EB2A00DDABEULL,
		0x850EF34787A7B686ULL,
		0x7BD6D0AB867A5B86ULL,
		0x4DBA8DAA5175D38AULL,
		0x86749DA4F6BF9E98ULL,
		0x5091DD748ED9A094ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x801B2969CF60A6FFULL,
		0x0330EA9883C136A5ULL,
		0xFFA6CDDA339C76EAULL,
		0x7A538F1857D1571AULL,
		0xF4EC917C43DDBB92ULL,
		0x19940CEEB6207E80ULL,
		0x27192DD1E40A2F7EULL,
		0xA43E6E61DBF338AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCCA4BE6B7BE5A05ULL,
		0xCA32025BB6FA0DDAULL,
		0x419790D86C7163D4ULL,
		0x0ABB642F2FD65F6BULL,
		0x86EA3F2F429C9FF4ULL,
		0x342680BB9B555509ULL,
		0x5F5B6FD312B56F1AULL,
		0xAC536F12B2E667E6ULL
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
		0x0C2436F548DF746AULL,
		0x24A9624FF3BF7AF4ULL,
		0xF40FB44B2BADBD28ULL,
		0x34D67F59854AC42CULL,
		0xEF4651D56130071DULL,
		0xF73444DC074C7208ULL,
		0x53B2A32C4DD80D5DULL,
		0x6FF3004181331060ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x854B9C5E4715EBD4ULL,
		0x80C2781A483BB005ULL,
		0x0F712F4ADE41E193ULL,
		0xEF91672D8AEF93A6ULL,
		0x5C6D7349834B5212ULL,
		0x389FE955C456D123ULL,
		0xE88744F8D5392E30ULL,
		0x72A097DCBEE5BEB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86D89A9701C98896ULL,
		0xA3E6EA35AB83CAEEULL,
		0xE49E85004D6BDB94ULL,
		0x4545182BFA5B3086ULL,
		0x92D8DE8BDDE4B50AULL,
		0xBE945B8642F5A0E5ULL,
		0x6B2B5E33789EDF2DULL,
		0xFD526864C24D51A7ULL
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
		0xE5329F47BD7C4CF2ULL,
		0x3900B939A30A8C0BULL,
		0x3A854D3DAB645FAEULL,
		0xA32084D57EF51CA1ULL,
		0x152763A582996CFFULL,
		0x78C685E7ED848EE2ULL,
		0x91BB061FC9CC3FD7ULL,
		0x2344750F30CCA949ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66828E3968F42750ULL,
		0x1118F1E38BAD125DULL,
		0x0CD803AFD5D48DE9ULL,
		0x0492653BD478049EULL,
		0xF84D6B52F63EDDC2ULL,
		0x4A82D89488C358A6ULL,
		0x4503C408B215A02EULL,
		0xBF1C1FF9AC339B6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EB0110E548825A2ULL,
		0x27E7C756175D79AEULL,
		0x2DAD498DD58FD1C5ULL,
		0x9E8E1F99AA7D1803ULL,
		0x1CD9F8528C5A8F3DULL,
		0x2E43AD5364C1363BULL,
		0x4CB7421717B69FA9ULL,
		0x6428551584990DDDULL
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
		0x2187621F32994810ULL,
		0x8288BD392B393707ULL,
		0x9E468AF829E53053ULL,
		0xEEF52D01499EA6F1ULL,
		0x32EE605D9AC96D72ULL,
		0xB093956F7B2D5C93ULL,
		0x775743CFA1F8BFEFULL,
		0xB3329A9E2A766F25ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E858A7DE6848AA1ULL,
		0xBB0AC9B089165831ULL,
		0x2FF007BFEEA38EABULL,
		0xA2BF35A6C2BD65A4ULL,
		0xAF41D5BD1FC3DDBFULL,
		0x68D310FABCE170C4ULL,
		0xB570796DC55A82E1ULL,
		0xAB68203581DAA1F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE301D7A14C14BD6FULL,
		0xC77DF388A222DED5ULL,
		0x6E5683383B41A1A7ULL,
		0x4C35F75A86E1414DULL,
		0x83AC8AA07B058FB3ULL,
		0x47C08474BE4BEBCEULL,
		0xC1E6CA61DC9E3D0EULL,
		0x07CA7A68A89BCD2EULL
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
		0xBC003FE85F07B051ULL,
		0x18D9B3E06296A553ULL,
		0x2111559E6FE8E5C9ULL,
		0x8CF08D4703A289F9ULL,
		0x3CCDA15D1CE9970FULL,
		0x59D9B23F0C4C4351ULL,
		0xA62DD0E03F5AF246ULL,
		0x1D8771AD38F9CDD6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x59886066B7ABEC12ULL,
		0xA7B8DCB41030D535ULL,
		0xCFF031685C4B1641ULL,
		0x123177F317182BFAULL,
		0x9151C0470E482D11ULL,
		0x8A3064172C24883BULL,
		0xD844ACBDA6A7AB4BULL,
		0x9B7A4A83FDEE8054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6277DF81A75BC43FULL,
		0x7120D72C5265D01EULL,
		0x51212436139DCF87ULL,
		0x7ABF1553EC8A5DFEULL,
		0xAB7BE1160EA169FEULL,
		0xCFA94E27E027BB15ULL,
		0xCDE9242298B346FAULL,
		0x820D27293B0B4D81ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x895BC8994F7ADCC0ULL,
		0x339985CDF90A12A7ULL,
		0xC152B289349C035AULL,
		0xA69E8D11DB9A68DEULL,
		0x3E0AE39DE9563F72ULL,
		0x2CF0935488426ED9ULL,
		0x23270FD0A1B34C0BULL,
		0xD5CA344C3E483F98ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC35E556160B2D5AULL,
		0x1619001D6A28FD58ULL,
		0x6AA12F7527BE6DBFULL,
		0x1CBD908183521DE4ULL,
		0x7F5312FFA305ABF7ULL,
		0xBB011D74D51F3E2AULL,
		0x9A59FC4BE42C2F72ULL,
		0x97D3971A5213C4C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D25E343396FAF66ULL,
		0x1D8085B08EE1154EULL,
		0x56B183140CDD959BULL,
		0x89E0FC9058484AFAULL,
		0xBEB7D09E4650937BULL,
		0x71EF75DFB32330AEULL,
		0x88CD1384BD871C98ULL,
		0x3DF69D31EC347AD3ULL
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
		0x513BA0DE4A2D2F5FULL,
		0x8933E71F204F5B97ULL,
		0x7C24B9C86E608C9DULL,
		0x605EB17410A7E674ULL,
		0xF6D1015F2293093AULL,
		0x260811602899B4B5ULL,
		0x360D09666A6AFEC1ULL,
		0x1D972800D46EA89DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EBAF1247F268E93ULL,
		0x650C386681608761ULL,
		0xF0AA66560B3E4971ULL,
		0x2549E693E34A2FBEULL,
		0xAF3ADB8A21628276ULL,
		0x5FBA859D1B1D9BF6ULL,
		0x96EA87763095574EULL,
		0x4EE42D13A39D91B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0280AFB9CB06A0CCULL,
		0x2427AEB89EEED436ULL,
		0x8B7A53726322432CULL,
		0x3B14CAE02D5DB6B5ULL,
		0x479625D5013086C4ULL,
		0xC64D8BC30D7C18BFULL,
		0x9F2281F039D5A772ULL,
		0xCEB2FAED30D116E7ULL
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
		0x91C297C9F995FDF7ULL,
		0x4D1C3E7DC8126488ULL,
		0x04488516F01FB899ULL,
		0x14D9C27C1681D7B1ULL,
		0xC2C9ACCAE3E03EADULL,
		0x46A8F80DEE05ECE6ULL,
		0x70BAA6685E6E7277ULL,
		0x7B514350BD493E9CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CD6954B3746BE91ULL,
		0x03E5218BEEEDDFA9ULL,
		0xB40FDC6135D94188ULL,
		0x07225FC2DD482F45ULL,
		0x52174E07B8DEB885ULL,
		0xD8E6F81CC0D02A10ULL,
		0x8E2C82F98EE06F60ULL,
		0xD4D9BFAEA5E1F5F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04EC027EC24F3F66ULL,
		0x49371CF1D92484DFULL,
		0x5038A8B5BA467711ULL,
		0x0DB762B93939A86BULL,
		0x70B25EC32B018628ULL,
		0x6DC1FFF12D35C2D6ULL,
		0xE28E236ECF8E0316ULL,
		0xA67783A2176748A5ULL
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
		0x9CF730D7440F603DULL,
		0x65A2B235354E5E68ULL,
		0x6477623B4E1792B2ULL,
		0x3AA14F507201A396ULL,
		0x7DF1CD7F0F5C6C8CULL,
		0xEDACC1E7D2B485E6ULL,
		0x5829B496E45E027CULL,
		0x9104D36F08305E78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE38C6F37E763008DULL,
		0x7BD9251663D7A5DFULL,
		0x30CEEFC748A0672FULL,
		0x89F153A5A49EAB09ULL,
		0x84B66534AE5A2065ULL,
		0xB25D9DEE677929C1ULL,
		0x70C6D3A01C4534ADULL,
		0xB93047F74E2E315BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96AC19F5CAC5FB0ULL,
		0xE9C98D1ED176B888ULL,
		0x33A8727405772B82ULL,
		0xB0AFFBAACD62F88DULL,
		0xF93B684A61024C26ULL,
		0x3B4F23F96B3B5C24ULL,
		0xE762E0F6C818CDCFULL,
		0xD7D48B77BA022D1CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x10B771804C983D81ULL,
		0xBDA0BACFD716EDBCULL,
		0x83CD65F284FFDF89ULL,
		0xD70674B3A7EE5D11ULL,
		0x17D626A3488A4B67ULL,
		0xAE09863DB4BD9B03ULL,
		0xE60E9529948BF09FULL,
		0x8894E2EB730A4706ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F28129E2A462AFULL,
		0x1966865C7CD4DDB4ULL,
		0x6151C58686E733D5ULL,
		0xB9979FDBC528E480ULL,
		0x8BE0686507495A6CULL,
		0xC38A3024A3B4382AULL,
		0x0790B1F3B0B2A626ULL,
		0x76D9262A4E55C5D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAC4F05669F3DAD2ULL,
		0xA43A34735A421007ULL,
		0x227BA06BFE18ABB4ULL,
		0x1D6ED4D7E2C57891ULL,
		0x8BF5BE3E4140F0FBULL,
		0xEA7F5619110962D8ULL,
		0xDE7DE335E3D94A78ULL,
		0x11BBBCC124B48133ULL
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
		0x59B7ED527675D400ULL,
		0x5CE31C2AEE4E7014ULL,
		0x1AB30FCF9BF975D0ULL,
		0x3853DCC84E8E58DDULL,
		0x794A226E7F3374DFULL,
		0x82EAAE0100588C2BULL,
		0xA36BDD028AF415DBULL,
		0xF763FB0D5ADCEB33ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BB616745025E59ULL,
		0x32D66AF50952B8FAULL,
		0x46E148403A06C0B1ULL,
		0xD64CE436248276F6ULL,
		0x8ED965FC1E70F557ULL,
		0x355BDBEEF94F5745ULL,
		0xFB00149C40D2FD08ULL,
		0xE5788CBDF7E92A15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2FC8BEB317375A7ULL,
		0x2A0CB135E4FBB719ULL,
		0xD3D1C78F61F2B51FULL,
		0x6206F8922A0BE1E6ULL,
		0xEA70BC7260C27F87ULL,
		0x4D8ED212070934E5ULL,
		0xA86BC8664A2118D3ULL,
		0x11EB6E4F62F3C11DULL
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
		0xDCF1B648D3916EB7ULL,
		0xECF930798DF74C07ULL,
		0x9D5E41DC99558CE7ULL,
		0x9DB6C82E5BF02188ULL,
		0x350050A058988E6BULL,
		0xB198C186FAE5438CULL,
		0x809DA58968954149ULL,
		0x53B09A91919E53A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BF4A63B1A97C74ULL,
		0x2CCEE18DCEA194ECULL,
		0xF30CC20AEE12BBD6ULL,
		0xDABBA126D37B85F7ULL,
		0xE828FAE3D1113343ULL,
		0xE2F7AC7A618819E8ULL,
		0xF7AD874810451E91ULL,
		0xC24B6122A5F57954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39326BE521E7F243ULL,
		0xC02A4EEBBF55B71BULL,
		0xAA517FD1AB42D111ULL,
		0xC2FB270788749B90ULL,
		0x4CD755BC87875B27ULL,
		0xCEA1150C995D29A3ULL,
		0x88F01E41585022B7ULL,
		0x9165396EEBA8DA4BULL
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
		0x9B7B721230BBC065ULL,
		0xC441019A27DA3307ULL,
		0x35191F27FA157414ULL,
		0x52D69D9DDE37B531ULL,
		0x878323D03C8A8C7EULL,
		0x536A58FFFC4EA8A3ULL,
		0x9414E1B079A8F2B8ULL,
		0x842063190F4AEC38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35510D958218AF37ULL,
		0xE46C6570AB34A144ULL,
		0x4985922E085EE061ULL,
		0xB103B373DB0586B3ULL,
		0xC63733A38CBCC134ULL,
		0x0F8EAB5FF309D4CCULL,
		0xD7B3F36E0B3B05B2ULL,
		0x39572E23EEC90D7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x662A647CAEA3112EULL,
		0xDFD49C297CA591C3ULL,
		0xEB938CF9F1B693B2ULL,
		0xA1D2EA2A03322E7DULL,
		0xC14BF02CAFCDCB49ULL,
		0x43DBADA00944D3D6ULL,
		0xBC60EE426E6DED06ULL,
		0x4AC934F52081DEBBULL
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
		0x37FBE97B7EE211E1ULL,
		0xA1006E56654EB841ULL,
		0x78D361DDBE437344ULL,
		0xE28AE394815AE6F2ULL,
		0xB4D731CCB1F0ACC6ULL,
		0x39C2595C3F22F358ULL,
		0xB514BBF0D229743EULL,
		0xA25EBEEF4E8F4DFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1618C4B0E5D7B263ULL,
		0x6AFAD01EC1C8E601ULL,
		0xA29708C78A99C555ULL,
		0x8EAB4E5AB441677BULL,
		0xD9E81D0F4456F6CAULL,
		0x837D3FD554BED731ULL,
		0xC015CA69D6FAF8E6ULL,
		0x94AF7876ADF2299CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21E324CA990A5F7EULL,
		0x36059E37A385D240ULL,
		0xD63C591633A9ADEFULL,
		0x53DF9539CD197F76ULL,
		0xDAEF14BD6D99B5FCULL,
		0xB6451986EA641C26ULL,
		0xF4FEF186FB2E7B57ULL,
		0x0DAF4678A09D245FULL
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
		0x1C5BDE9ADC827ACCULL,
		0x98E549D09B161919ULL,
		0xAD11D801EEE21363ULL,
		0x068F93F56DB00031ULL,
		0x07B5C3F5086D0BF6ULL,
		0x0E9CDE56A32EBA0DULL,
		0xE34B5DCB86893A5FULL,
		0x6BEF49CBED71B5E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C96381E34D54290ULL,
		0x80478BB2FD1548F2ULL,
		0x527F6649FC04F71EULL,
		0xD7EC7DD2A6F49153ULL,
		0x8004E82877977417ULL,
		0x3D2894E9DC510D8DULL,
		0x9705D9D2437A57F4ULL,
		0x146E992477EA574DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFC5A67CA7AD383CULL,
		0x189DBE1D9E00D026ULL,
		0x5A9271B7F2DD1C45ULL,
		0x2EA31622C6BB6EDEULL,
		0x87B0DBCC90D597DEULL,
		0xD174496CC6DDAC7FULL,
		0x4C4583F9430EE26AULL,
		0x5780B0A775875E97ULL
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
		0xCFDC8DF23D8D33FBULL,
		0x8F37221212F56592ULL,
		0xC83D69887911B735ULL,
		0x2C9FBDCE66F9D138ULL,
		0x19D2015CCCCC235CULL,
		0xD17FA0EACACBA962ULL,
		0x04F52B31D0A98850ULL,
		0xD981DF79445512CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA04B77F052A2228EULL,
		0x239FA837AD807964ULL,
		0x4D72BB238EC2A74FULL,
		0xD53F45ECF2FC98EEULL,
		0x54CCD9AD08AB752CULL,
		0x55BAAD48C1C0E8F4ULL,
		0x9DB12BC1C718BA13ULL,
		0x01BD84FE86099CA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F911601EAEB116DULL,
		0x6B9779DA6574EC2EULL,
		0x7ACAAE64EA4F0FE6ULL,
		0x576077E173FD384AULL,
		0xC50527AFC420AE2FULL,
		0x7BC4F3A2090AC06DULL,
		0x6743FF700990CE3DULL,
		0xD7C45A7ABE4B7622ULL
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
		0xF3A5406A613F62BAULL,
		0xF112238C0C178FB1ULL,
		0xA6D92C4A7EDDC0EAULL,
		0x1C25D56B8715EBB5ULL,
		0x70230AEDB9693B74ULL,
		0x52BDA6EADB7F3196ULL,
		0xB808C7F3E00F3638ULL,
		0x3E3A99C6C006166AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4027ECF4BA2C6B59ULL,
		0x5A459860D7CAC2C0ULL,
		0x52E4F4378F171E2FULL,
		0xCCC0915B880E9AEFULL,
		0x97202B5D2A3BA2A7ULL,
		0x48072C527D43FAE9ULL,
		0x5541BE676F271A8BULL,
		0x5063E78938B585FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB37D5375A712F761ULL,
		0x96CC8B2B344CCCF1ULL,
		0x53F43812EFC6A2BBULL,
		0x4F65440FFF0750C6ULL,
		0xD902DF908F2D98CCULL,
		0x0AB67A985E3B36ACULL,
		0x62C7098C70E81BADULL,
		0xEDD6B23D87509070ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAFCCE905FB03885BULL,
		0x160157426416889EULL,
		0x37B153EE00FCF3DCULL,
		0x5CB0837A846458F7ULL,
		0xE4E92616BC5B132BULL,
		0x9499210E5FAE6E5FULL,
		0x25A14F9CBAC489CCULL,
		0x7AD90BAF7EC6F41DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB7CCB921AB6175ULL,
		0x4FB04B253824686CULL,
		0x9A6057DC96525D40ULL,
		0xB0AB3EB128F2BC0AULL,
		0x5123F9CDDDDCB272ULL,
		0x6F893253F09E7362ULL,
		0x86EB9718256E67B4ULL,
		0xCCABA15B67AB11CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44151C4CD95826E6ULL,
		0xC6510C1D2BF22032ULL,
		0x9D50FC116AAA969BULL,
		0xAC0544C95B719CECULL,
		0x93C52C48DE7E60B8ULL,
		0x250FEEBA6F0FFAFDULL,
		0x9EB5B88495562218ULL,
		0xAE2D6A54171BE24FULL
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
		0x79C06F2B55CF5423ULL,
		0x0A5E467889D0F82FULL,
		0x0CEA59F9B4267EC2ULL,
		0x832C2352B749D9FEULL,
		0x1F757F49A4DE3007ULL,
		0x71C4D0A571A2A819ULL,
		0xEE3DCA0312EC2F5EULL,
		0xDE1BACB35B5A2F2FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9B22667F77CCF03ULL,
		0x90C12D17B56D3043ULL,
		0x3B4118E82B99E2EAULL,
		0x43FE51C3B8E93E6EULL,
		0x60A8CB8EDDFDE17DULL,
		0x87E04FA8E67BDB50ULL,
		0x68BAD129F7FA537DULL,
		0x22E08FE32A8FD084ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA00E48C35E528520ULL,
		0x799D1960D463C7EBULL,
		0xD1A94111888C9BD7ULL,
		0x3F2DD18EFE609B8FULL,
		0xBECCB3BAC6E04E8AULL,
		0xE9E480FC8B26CCC8ULL,
		0x8582F8D91AF1DBE0ULL,
		0xBB3B1CD030CA5EABULL
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
		0x11291D1709C06E79ULL,
		0x3CBB8E73FF88CFEBULL,
		0x311C0B2F0E02B38EULL,
		0x4E297893B6AE5559ULL,
		0x7C03B4984D3521CCULL,
		0x4CB929D14376AB98ULL,
		0x0FC927CDDEA67682ULL,
		0x29CF6600ADBACBA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38539820FC6E72DAULL,
		0x1A0B7D2DEC8DAAADULL,
		0x3A81E21764EEF68DULL,
		0x41FDCB05F35208BDULL,
		0x767DCE8F3B91FC04ULL,
		0xA281A3A90E4DE2C2ULL,
		0xBE929BF264A4BC12ULL,
		0xD8FA1211E267F5C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8D584F60D51FB9FULL,
		0x22B0114612FB253DULL,
		0xF69A2917A913BD01ULL,
		0x0C2BAD8DC35C4C9BULL,
		0x0585E60911A325C8ULL,
		0xAA3786283528C8D6ULL,
		0x51368BDB7A01BA6FULL,
		0x50D553EECB52D5DDULL
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
		0x33348469FF65042CULL,
		0x3E271D969567B04CULL,
		0x11C73D94AD5B4F43ULL,
		0x5109312D7BB0F13CULL,
		0x295AA576AE49E6D1ULL,
		0x0E70951801B50B97ULL,
		0x891D4D7E95995B1DULL,
		0x36CBCB68D30419DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19030A9B7FA43BEBULL,
		0xC149306505015BCAULL,
		0xDE0F1B86792A9E91ULL,
		0x571F89DC8E971C7AULL,
		0xBF04DDCE19A71209ULL,
		0x0A7F17DC0D3F3677ULL,
		0x59AE4563B836FBD1ULL,
		0x6D5E0F471223DB1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A3179CE7FC0C841ULL,
		0x7CDDED3190665482ULL,
		0x33B8220E3430B0B1ULL,
		0xF9E9A750ED19D4C1ULL,
		0x6A55C7A894A2D4C7ULL,
		0x03F17D3BF475D51FULL,
		0x2F6F081ADD625F4CULL,
		0xC96DBC21C0E03EBEULL
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
		0xFC80194C7A1B7B6CULL,
		0xB5CAAB5F54146CCDULL,
		0x20D48A276E0BA48CULL,
		0xFFEF9E401F800364ULL,
		0xFCF18CB3FCECBF9EULL,
		0x702110932D3C3620ULL,
		0x4F6C29DDC8D78E48ULL,
		0xDA998084E47C291DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B74D64126BDCA3AULL,
		0x822228566ACCBB36ULL,
		0x0EFD65CFFD6619E5ULL,
		0xE14662225BE8CE17ULL,
		0x6F76B93264DA34DFULL,
		0xC9D5E11C39C7AB7AULL,
		0xC8C4D3DCF0D28C2CULL,
		0xB884DBB463721D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x910B430B535DB132ULL,
		0x33A88308E947B197ULL,
		0x11D7245770A58AA7ULL,
		0x1EA93C1DC397354DULL,
		0x8D7AD38198128ABFULL,
		0xA64B2F76F3748AA6ULL,
		0x86A75600D805021BULL,
		0x2214A4D0810A0BC3ULL
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
		0xD1D61E5051C8E7EDULL,
		0x64E789A632FBA313ULL,
		0x14F91CD1720B73C2ULL,
		0x2A3837D0AC2CE852ULL,
		0xC1E8B57E59139723ULL,
		0x381B05B522FE0305ULL,
		0x587A4DFE44EBACB6ULL,
		0xB51FCBAF82BCA185ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7C3EEDBB767927ULL,
		0x5B1AB575101C325AULL,
		0xE80DC285A24D8CCCULL,
		0x821BA4D096D82338ULL,
		0x137615A0FA714C59ULL,
		0x04C4ACF66F8CC725ULL,
		0x6C5F9D4FEAB95DBDULL,
		0x5F72858988C7D5BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3659DF6296526EC6ULL,
		0x09CCD43122DF70B9ULL,
		0x2CEB5A4BCFBDE6F6ULL,
		0xA81C93001554C519ULL,
		0xAE729FDD5EA24AC9ULL,
		0x335658BEB3713BE0ULL,
		0xEC1AB0AE5A324EF9ULL,
		0x55AD4625F9F4CBC6ULL
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
		0x6E8253F686714F96ULL,
		0x4609047FEECC901BULL,
		0xE796AA5D43988FCDULL,
		0x0548D7A105D7F079ULL,
		0x5DDDDAB0CBC52432ULL,
		0x4D96C7199E289446ULL,
		0x7D0A38CBA8973A98ULL,
		0xCA875E1B0F62AD2AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x839A25F641A71CA5ULL,
		0x7E21DCCA500B2D21ULL,
		0xF5ADEA91B8C908A2ULL,
		0x5556CDE536D43DF0ULL,
		0x3FE752FD1DE12941ULL,
		0x708F7B8B33144CCAULL,
		0x1C3F7B42735C9637ULL,
		0xA1E9608D7EF27EC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAE82E0044CA32F1ULL,
		0xC7E727B59EC162F9ULL,
		0xF1E8BFCB8ACF872AULL,
		0xAFF209BBCF03B288ULL,
		0x1DF687B3ADE3FAF0ULL,
		0xDD074B8E6B14477CULL,
		0x60CABD89353AA460ULL,
		0x289DFD8D90702E6AULL
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
		0xBD16750765948850ULL,
		0x2DF2498E70C3C18CULL,
		0x1B0A580E8A01C43CULL,
		0x4CB2F74ED6C37644ULL,
		0xF7124933B575A596ULL,
		0x0E4F13161ED4B46EULL,
		0x603582A7B74783E2ULL,
		0xBD8EAA112334DAC2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x297F3B8873D7BEA6ULL,
		0x34F25E5D87679895ULL,
		0x3BE09EC8BA0479B2ULL,
		0x512007CFB9BDDC34ULL,
		0x34618D0A9D8A05E9ULL,
		0xE153E3EBBAF16813ULL,
		0x8865A09018BBD92EULL,
		0x7ED5D1368C3E92E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9397397EF1BCC9AAULL,
		0xF8FFEB30E95C28F7ULL,
		0xDF29B945CFFD4A89ULL,
		0xFB92EF7F1D059A0FULL,
		0xC2B0BC2917EB9FACULL,
		0x2CFB2F2A63E34C5BULL,
		0xD7CFE2179E8BAAB3ULL,
		0x3EB8D8DA96F647D9ULL
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
		0xCC64E91E6D9F7628ULL,
		0x93844399F6C369CCULL,
		0x33FF843CBDBD919AULL,
		0x80C1FFE0CCC600C0ULL,
		0xB45D25CD7B067F1EULL,
		0xA043D3151A0E2489ULL,
		0x021B4CD7484E92A9ULL,
		0xC5C5F17EBFF403DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ED4EE8E66A3C325ULL,
		0x727DC4815EF1CFA9ULL,
		0x550C197C72A04F83ULL,
		0x77B2C5E6EE8BCBBDULL,
		0x897C3CCB004B909FULL,
		0x6D2C8BA4CF88462FULL,
		0x96003D44E2877037ULL,
		0xA4855B8F2FB08B4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D8FFA9006FBB303ULL,
		0x21067F1897D19A23ULL,
		0xDEF36AC04B1D4217ULL,
		0x090F39F9DE3A3502ULL,
		0x2AE0E9027ABAEE7FULL,
		0x331747704A85DE5AULL,
		0x6C1B0F9265C72272ULL,
		0x214095EF9043788FULL
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
		0x930BC139BAB86125ULL,
		0xABB80EB807E02A38ULL,
		0x0B33753ACB7CCEF5ULL,
		0x4C58EF8F9D0501BCULL,
		0xDF16EDEFB63843C4ULL,
		0x6C35FCF9979FEE4EULL,
		0x4A49F4B7F4EFF6C5ULL,
		0x3BB71FC6D826EE6AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF48502E25633F166ULL,
		0xAE2B54CD5A90F583ULL,
		0x8D76AAD2D2C934CDULL,
		0xCF0BEA1E05801CA3ULL,
		0xC7A642BA47C32F7BULL,
		0x6407A017B56D1E7BULL,
		0xBD903752B55467AFULL,
		0xF238455C9695B427ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E86BE5764846FBFULL,
		0xFD8CB9EAAD4F34B4ULL,
		0x7DBCCA67F8B39A27ULL,
		0x7D4D05719784E518ULL,
		0x1770AB356E751448ULL,
		0x082E5CE1E232CFD3ULL,
		0x8CB9BD653F9B8F16ULL,
		0x497EDA6A41913A42ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x62FAF623948B0282ULL,
		0x4171651FD2D309EBULL,
		0x96034C179ECB0F27ULL,
		0xF4E03EF411F3ECAFULL,
		0x8EDBC8743A2EBAAFULL,
		0x498018064146AE25ULL,
		0xFB992F92C9209151ULL,
		0x8B43A9B49E958524ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x696F721DAF9EB7ABULL,
		0x47C54DE162ADFE9FULL,
		0x2FF11E3403EBF832ULL,
		0xE5552FAA8FAA2A68ULL,
		0xBB22EC3BA69FCC63ULL,
		0x66CDBDEFACCAEB6FULL,
		0xA8A7F962F49AEE2EULL,
		0x8087C95E7A8C39F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF98B8405E4EC4AD7ULL,
		0xF9AC173E70250B4BULL,
		0x66122DE39ADF16F4ULL,
		0x0F8B0F498249C247ULL,
		0xD3B8DC38938EEE4CULL,
		0xE2B25A16947BC2B5ULL,
		0x52F1362FD485A322ULL,
		0x0ABBE05624094B2DULL
	}};
	sign = 0;
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
		0xDA2A7F0B79D2C6DFULL,
		0xDA95DD45091F26EEULL,
		0x06B230F3936A0E4CULL,
		0x16C0E3873A91B16CULL,
		0x7369A5918A9473B2ULL,
		0x18FB724556F510FAULL,
		0xE500F40EB20CBC84ULL,
		0x0D6774FEBE508E5BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9051646AAF86E271ULL,
		0x469AD5A1B0089933ULL,
		0xAFD3888449921C38ULL,
		0xA4A85274D47541FAULL,
		0x0F9F091C484CE501ULL,
		0xCF02B9B7F2922881ULL,
		0xA9E1D391C1ABEC50ULL,
		0x294C4381BB497915ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D91AA0CA4BE46EULL,
		0x93FB07A359168DBBULL,
		0x56DEA86F49D7F214ULL,
		0x72189112661C6F71ULL,
		0x63CA9C7542478EB0ULL,
		0x49F8B88D6462E879ULL,
		0x3B1F207CF060D033ULL,
		0xE41B317D03071546ULL
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
		0xF29F8D6B3A889025ULL,
		0x30ADBACBE586ADB6ULL,
		0x47B8716FA2A74DACULL,
		0xBF575583FC6ECF92ULL,
		0xA29FF25D033E392EULL,
		0x3B371F662B93D310ULL,
		0x343A295E70C231B6ULL,
		0x48CE0E31D7DF13C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4360F5F10F46C86EULL,
		0x6F4C79776CA03CC9ULL,
		0x721387AFBDFFCB3CULL,
		0xE61A4C905ABE6972ULL,
		0x3E54B70C4C2FF893ULL,
		0xF4D5D88A45A8DEA1ULL,
		0x00761650B547B2C0ULL,
		0xFEB61B72DF7FB97BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF3E977A2B41C7B7ULL,
		0xC161415478E670EDULL,
		0xD5A4E9BFE4A7826FULL,
		0xD93D08F3A1B0661FULL,
		0x644B3B50B70E409AULL,
		0x466146DBE5EAF46FULL,
		0x33C4130DBB7A7EF5ULL,
		0x4A17F2BEF85F5A48ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3A2A589B8B27C5FCULL,
		0xF153EC0F39166A79ULL,
		0x1D62E69B494B5FB1ULL,
		0x25672A9EE0A1D90EULL,
		0x11AF046C153DF01BULL,
		0x47133C990E691235ULL,
		0xB02298BA9CC53F91ULL,
		0x58199F5263FD1BFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C474EDE55C87A08ULL,
		0xFFC41FADBD3762DDULL,
		0x3161A688695AF98AULL,
		0x18BE5DD90418C525ULL,
		0x5B3E2019020F8189ULL,
		0x2E27044FAC98FD66ULL,
		0xDA221CA4F56F1E41ULL,
		0xFCD5185A9560388EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DE309BD355F4BF4ULL,
		0xF18FCC617BDF079CULL,
		0xEC014012DFF06626ULL,
		0x0CA8CCC5DC8913E8ULL,
		0xB670E453132E6E92ULL,
		0x18EC384961D014CEULL,
		0xD6007C15A7562150ULL,
		0x5B4486F7CE9CE36CULL
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
		0xB98BCDBC39DE3735ULL,
		0x1C71C28052DED1D6ULL,
		0x62CE75DB7F15FFEAULL,
		0x3847DFA70FA83F95ULL,
		0x6BE0EC00620E3E7BULL,
		0x01F2F0BE8C97C9ADULL,
		0x4C262086EC194F29ULL,
		0xB1F054AA1BCED2AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7577CE6A30210DC4ULL,
		0x7674CB8F90DE1980ULL,
		0xC27EB0C4C3746533ULL,
		0xCDE470E46A3B457BULL,
		0xE20EED003CA51201ULL,
		0x60107866C381F97CULL,
		0xF301A0537F76F0D5ULL,
		0xD02635D84BD81948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4413FF5209BD2971ULL,
		0xA5FCF6F0C200B856ULL,
		0xA04FC516BBA19AB6ULL,
		0x6A636EC2A56CFA19ULL,
		0x89D1FF0025692C79ULL,
		0xA1E27857C915D030ULL,
		0x592480336CA25E53ULL,
		0xE1CA1ED1CFF6B965ULL
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
		0xD23955A4247ACEFEULL,
		0xD0DAE08B7D361272ULL,
		0x5C2D87CE9E40D939ULL,
		0x19103835ACF3EF1DULL,
		0x15A61656D22D34DFULL,
		0x511EAB261C91A1AAULL,
		0xA81BA2EBE1D32626ULL,
		0x133E625017B2A61BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA28DFE9BDE84560ULL,
		0xDEB2A302C710D740ULL,
		0x8ADDB0F0320F1A0CULL,
		0x6F0C24354C503E58ULL,
		0x3C9CA57004C99F31ULL,
		0x95E5EDE7305563C0ULL,
		0xB308C3E0C0FB68B0ULL,
		0xE683F13D1A381414ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081075BA6692899EULL,
		0xF2283D88B6253B32ULL,
		0xD14FD6DE6C31BF2CULL,
		0xAA04140060A3B0C4ULL,
		0xD90970E6CD6395ADULL,
		0xBB38BD3EEC3C3DE9ULL,
		0xF512DF0B20D7BD75ULL,
		0x2CBA7112FD7A9206ULL
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
		0xC330E797AF711E03ULL,
		0xDDA0D7DA3EE5E50EULL,
		0xED15583985884C28ULL,
		0xE51D360B0B43EC7EULL,
		0xA3A76A9B2A47C0D4ULL,
		0x35F3519A78AC2DB7ULL,
		0x0FD6F12CD4B0DE79ULL,
		0x700588099DE51B63ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4129B898A709C36ULL,
		0x27A4EDAE80FFDEA0ULL,
		0x845FBADEEABB58C6ULL,
		0x3BDCD33E2281AB4CULL,
		0x3351BCBD58907AA7ULL,
		0xC6370AF15ECC299EULL,
		0xB95423601F8FA27CULL,
		0xDD059329CAF3BB7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F1E4C0E250081CDULL,
		0xB5FBEA2BBDE6066EULL,
		0x68B59D5A9ACCF362ULL,
		0xA94062CCE8C24132ULL,
		0x7055ADDDD1B7462DULL,
		0x6FBC46A919E00419ULL,
		0x5682CDCCB5213BFCULL,
		0x92FFF4DFD2F15FE7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC36A57433798B7C4ULL,
		0x39EE681458D9F2F5ULL,
		0x3A6583789828447CULL,
		0xC5E6D1951112A81AULL,
		0x37F57C22C123158BULL,
		0x44DC1B4F67A9CA7EULL,
		0xA94CBCBC9D371646ULL,
		0x0CD81A6328D7B6C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A645BFBADB94C9ULL,
		0xB220183C723542C6ULL,
		0xFC05C9BF539545E9ULL,
		0xFFD4F6CA030A9FE6ULL,
		0x7BC67BD2EE07B094ULL,
		0xF03ACE3EF2F03810ULL,
		0xDA12F7BF645B4FE3ULL,
		0x9102E5DB70232898ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9C411837CBD22FBULL,
		0x87CE4FD7E6A4B02EULL,
		0x3E5FB9B94492FE92ULL,
		0xC611DACB0E080833ULL,
		0xBC2F004FD31B64F6ULL,
		0x54A14D1074B9926DULL,
		0xCF39C4FD38DBC662ULL,
		0x7BD53487B8B48E2CULL
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
		0xFE5D30C17DFFCE0CULL,
		0xCDE161253A4BD6CCULL,
		0x615D5A9656FBE089ULL,
		0x6FE6CB6C7BFA458FULL,
		0x37E52A3AC70C961AULL,
		0x2A809E548D6145B5ULL,
		0xBEC29D25D505D655ULL,
		0x3CB3EA588D299139ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CCC41A6283FAC89ULL,
		0x8150A6634B541A96ULL,
		0xD52BAC0A2C08B482ULL,
		0xDCF02F3E15F830C8ULL,
		0x075286D74B63239AULL,
		0x7B95422A72585AE3ULL,
		0x6ADEF02ECE1AC48CULL,
		0x0F465CCB1DB7D63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD190EF1B55C02183ULL,
		0x4C90BAC1EEF7BC36ULL,
		0x8C31AE8C2AF32C07ULL,
		0x92F69C2E660214C6ULL,
		0x3092A3637BA9727FULL,
		0xAEEB5C2A1B08EAD2ULL,
		0x53E3ACF706EB11C8ULL,
		0x2D6D8D8D6F71BAFBULL
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
		0x86CF9424F0FAF3A0ULL,
		0xC8F94ACC486880F0ULL,
		0xB61ADC27C7ACD1E0ULL,
		0xFB00A79145BDCE7AULL,
		0x45CC8A2F2198BFA4ULL,
		0x1D6DEE9B9B8AF75DULL,
		0x37119152CFDF841FULL,
		0xD48FC728550D6C29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x51183E7F7891668FULL,
		0xC2FF0F7833315C66ULL,
		0x6166AF86B57DB2BEULL,
		0xC5D2B3204D792E51ULL,
		0xDDCE197436645024ULL,
		0xE178FD386D5EE455ULL,
		0x3FDF09A3DA3EC525ULL,
		0x9955688BFAAD35D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35B755A578698D11ULL,
		0x05FA3B541537248AULL,
		0x54B42CA1122F1F22ULL,
		0x352DF470F844A029ULL,
		0x67FE70BAEB346F80ULL,
		0x3BF4F1632E2C1307ULL,
		0xF73287AEF5A0BEF9ULL,
		0x3B3A5E9C5A603650ULL
	}};
	sign = 0;
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
		0x6EFB4A216810F263ULL,
		0xAF3610DBA9C3E7C2ULL,
		0x491DF5A9AF9CC11DULL,
		0x509C7A067EEA426CULL,
		0x626DAF5F66F79AB5ULL,
		0x9271FF7F131A2AD0ULL,
		0xF86F8267DC02C4D6ULL,
		0xA529100B536519B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E4BBD9ED8EC3BCULL,
		0xE1232E17FB58597CULL,
		0x973D4E00F7C8459CULL,
		0x8BBB81AA4A7E774FULL,
		0x80EA57289C6BC1C9ULL,
		0x2F52C66CC4CCECE6ULL,
		0xE193AE98FEB645F4ULL,
		0x98D44941E0959739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D168E477A822EA7ULL,
		0xCE12E2C3AE6B8E45ULL,
		0xB1E0A7A8B7D47B80ULL,
		0xC4E0F85C346BCB1CULL,
		0xE1835836CA8BD8EBULL,
		0x631F39124E4D3DE9ULL,
		0x16DBD3CEDD4C7EE2ULL,
		0x0C54C6C972CF827CULL
	}};
	sign = 0;
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
		0x3CD0D86E8FB4F44DULL,
		0xC8BE2B22BD713029ULL,
		0x2A38878C4DB8A2E5ULL,
		0x2A04D466258C7428ULL,
		0xEB54C64D0A0CBA70ULL,
		0x860130F978A9ECB4ULL,
		0x0B3B2C956856E8AEULL,
		0xDE6480BB2FFECC50ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BD58BFEEA5F1C8ULL,
		0xF8C1667B3C871750ULL,
		0x8F671E97C1F9B8FDULL,
		0xBACEE25DA96E2D85ULL,
		0x43A4B6B746E1202FULL,
		0x9FA9A7DEC5482739ULL,
		0x6C4A46A13EBF65F3ULL,
		0x3FFB9656C8A60DFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35137FAEA10F0285ULL,
		0xCFFCC4A780EA18D9ULL,
		0x9AD168F48BBEE9E7ULL,
		0x6F35F2087C1E46A2ULL,
		0xA7B00F95C32B9A40ULL,
		0xE657891AB361C57BULL,
		0x9EF0E5F4299782BAULL,
		0x9E68EA646758BE54ULL
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
		0x77506A64C71ABE06ULL,
		0x525D1C65894702DEULL,
		0xD50F1A08B8B961D6ULL,
		0xF917D4D5DD5252D4ULL,
		0x4EF153753EB8E7AAULL,
		0xF69CD6E7A862B1ADULL,
		0xFC9ADF0F0E0A5F16ULL,
		0xF84EE0FBE4B2BD9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BC3612E39ADD59ULL,
		0x67C0E4A076670280ULL,
		0xD9C6D31DE268104BULL,
		0xF4D6689269F0B0ECULL,
		0x71FCC84EA7D2A423ULL,
		0xDA4B2B6CAE2D7E3FULL,
		0x3289113AC71C404CULL,
		0xB6616797534C0BA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E943451E37FE0ADULL,
		0xEA9C37C512E0005DULL,
		0xFB4846EAD651518AULL,
		0x04416C437361A1E7ULL,
		0xDCF48B2696E64387ULL,
		0x1C51AB7AFA35336DULL,
		0xCA11CDD446EE1ECAULL,
		0x41ED79649166B1FAULL
	}};
	sign = 0;
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
		0x1ADA99E95BF8BE38ULL,
		0x0A2063FA547A7058ULL,
		0xB2DED966A6AC49B2ULL,
		0x84DBDE4C75D91709ULL,
		0x655821645261FA6AULL,
		0x644619F35DFAE253ULL,
		0x5432AC5A7FE0340EULL,
		0xF2C2C8D9EE4FBC34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0CD44CD3297F44AULL,
		0x6F01EE24FB59C088ULL,
		0xA59121F05D83352DULL,
		0xAF5BD5E588088F11ULL,
		0x1344C04AAFF9FD79ULL,
		0x11DB5EC22B3580C0ULL,
		0xC325D32C08A4AEC3ULL,
		0x2DC40A64E513D1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A0D551C2960C9EEULL,
		0x9B1E75D55920AFCFULL,
		0x0D4DB77649291484ULL,
		0xD5800866EDD087F8ULL,
		0x52136119A267FCF0ULL,
		0x526ABB3132C56193ULL,
		0x910CD92E773B854BULL,
		0xC4FEBE75093BEA8AULL
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
		0x2E03468CA576B26FULL,
		0xC596B51906E3943FULL,
		0x6B3E8B3A3997138DULL,
		0x8AE70E7B791CBC98ULL,
		0x7101025B31881C7DULL,
		0x9E718B1AC9244351ULL,
		0x8C2E66545B199BE6ULL,
		0xF411E549358B3890ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1929242C21AB779EULL,
		0xCED3BB2284F120AFULL,
		0xA290B64A59B1B88DULL,
		0xAB7217EAFFEC9529ULL,
		0x8F1C00F7144F2566ULL,
		0x9A7EC705EEA0EEC7ULL,
		0x53C6184852C6F12BULL,
		0x830C214B10AAE827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14DA226083CB3AD1ULL,
		0xF6C2F9F681F27390ULL,
		0xC8ADD4EFDFE55AFFULL,
		0xDF74F6907930276EULL,
		0xE1E501641D38F716ULL,
		0x03F2C414DA835489ULL,
		0x38684E0C0852AABBULL,
		0x7105C3FE24E05069ULL
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
		0x84A7EE9E43EAD158ULL,
		0xFCA409B5864BFD10ULL,
		0xF256C60C4210C211ULL,
		0xC76DB987C001B5F6ULL,
		0x8077248FD27B03A1ULL,
		0x348BA8FB49C7C5C7ULL,
		0xCD4C3AF0E7F91C58ULL,
		0x9A6F720AD984DEFFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C2609EA8CB7C45ULL,
		0x2F818A33E2920A6EULL,
		0xDD9153E8D7048FC1ULL,
		0xBC1DDE6FE1371C8AULL,
		0x9562ED41859E0F04ULL,
		0x4D85A73D248E661FULL,
		0x4EA0EB6D0677D51AULL,
		0x73725CB0D338F2DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE58DFF9B1F5513ULL,
		0xCD227F81A3B9F2A1ULL,
		0x14C572236B0C3250ULL,
		0x0B4FDB17DECA996CULL,
		0xEB14374E4CDCF49DULL,
		0xE70601BE25395FA7ULL,
		0x7EAB4F83E181473DULL,
		0x26FD155A064BEC23ULL
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
		0x9E60029ACF9F9FF6ULL,
		0x20AA70FCC826DC32ULL,
		0x4413AA8CEAC2CD13ULL,
		0xEFDDB5E9CE4BDE71ULL,
		0xB2E127238F723DFFULL,
		0x2EBB145555708290ULL,
		0xBBF147B49E5033AEULL,
		0xA4B76E56D2EE64C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x617437A04DDF6709ULL,
		0x0A03713C1E92E856ULL,
		0xE0FDB46F543E2150ULL,
		0xA68562E5B25E79E1ULL,
		0x18C0E35B181A9662ULL,
		0x4FAE60C6BDC3F16FULL,
		0x943A4782FC8EF4F1ULL,
		0xF4212B4B905BFF49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CEBCAFA81C038EDULL,
		0x16A6FFC0A993F3DCULL,
		0x6315F61D9684ABC3ULL,
		0x495853041BED648FULL,
		0x9A2043C87757A79DULL,
		0xDF0CB38E97AC9121ULL,
		0x27B70031A1C13EBCULL,
		0xB096430B42926577ULL
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
		0x0EBD857AB61A33B0ULL,
		0xBCC155476BA405C7ULL,
		0x5DEEC26D1FB0C722ULL,
		0x7EB9E4D131CF7F66ULL,
		0x0E7C2197FBD6C8DBULL,
		0xE187C1A016E2CB86ULL,
		0x62CC379698C885BBULL,
		0x190632F0B9411232ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D0E4858A6A10C5EULL,
		0x19C8E9DE9CFF71C2ULL,
		0xC400C65BC2D96BB7ULL,
		0x28B6176CA6D2714AULL,
		0x4DB167397EFA11D5ULL,
		0x7E9895A80AAEE864ULL,
		0x3BFB38B31C69E260ULL,
		0xF1E37F6ECDD13F0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71AF3D220F792752ULL,
		0xA2F86B68CEA49404ULL,
		0x99EDFC115CD75B6BULL,
		0x5603CD648AFD0E1BULL,
		0xC0CABA5E7CDCB706ULL,
		0x62EF2BF80C33E321ULL,
		0x26D0FEE37C5EA35BULL,
		0x2722B381EB6FD327ULL
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
		0x705DAF0870959E84ULL,
		0xF93B7DF2E29DBE5CULL,
		0xAF4E3C205509E9C7ULL,
		0xF68390641F02A701ULL,
		0xA7793F33962E578AULL,
		0xF9A80752C6DBBEE6ULL,
		0x03BE4FE9FB67FF23ULL,
		0xA9EF6A8CE2B56C4AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A36BEEE562B93EULL,
		0x80699CEE4FFDA376ULL,
		0x26289FC59E566DF7ULL,
		0x362877E500FB2279ULL,
		0x3DAC70684B899F70ULL,
		0xBDC653D0574E828EULL,
		0x31B14EF6EAA946A6ULL,
		0x68F16FDC1C3DB227ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCBA43198B32E546ULL,
		0x78D1E10492A01AE5ULL,
		0x89259C5AB6B37BD0ULL,
		0xC05B187F1E078488ULL,
		0x69CCCECB4AA4B81AULL,
		0x3BE1B3826F8D3C58ULL,
		0xD20D00F310BEB87DULL,
		0x40FDFAB0C677BA22ULL
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
		0x6118EA8E5EFD5064ULL,
		0xF12B0E755D2D4080ULL,
		0xCA7A9979142077BFULL,
		0x15BAD513DF5FA6CBULL,
		0x467B70C73987B90AULL,
		0x87E305485964B08BULL,
		0xEAE7DC0469E98E61ULL,
		0xC268429768E6B910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x079BBB76D170A67BULL,
		0x25507DE13ABE1A26ULL,
		0xA948D5E2F6D515CAULL,
		0xB4DE56F4B481A096ULL,
		0xDFFCDF5553F6A1B9ULL,
		0x16E968E8A5CAB52FULL,
		0x7C679BAD643D1884ULL,
		0x27E7F21D6441985CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x597D2F178D8CA9E9ULL,
		0xCBDA9094226F265AULL,
		0x2131C3961D4B61F5ULL,
		0x60DC7E1F2ADE0635ULL,
		0x667E9171E5911750ULL,
		0x70F99C5FB399FB5BULL,
		0x6E80405705AC75DDULL,
		0x9A80507A04A520B4ULL
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
		0xB92FCF2244E5A902ULL,
		0xF0188DED919DC460ULL,
		0x64551812221A6D3DULL,
		0x6CF52D8FC878109AULL,
		0x6E114495A39BA08EULL,
		0xDD94F013DD0FDA5EULL,
		0xC1B183EB31747843ULL,
		0xD7DB7A9511EA8DE7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB260312BA402219FULL,
		0x0C4A1E7F798267F9ULL,
		0x940B74B8C8D6FAEDULL,
		0x971B9F89E80C913CULL,
		0x5A2348F892C8550AULL,
		0x4919784BE6EA4174ULL,
		0xAFCB7591E3281E3FULL,
		0x7DE1B35A100E79EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06CF9DF6A0E38763ULL,
		0xE3CE6F6E181B5C67ULL,
		0xD049A35959437250ULL,
		0xD5D98E05E06B7F5DULL,
		0x13EDFB9D10D34B83ULL,
		0x947B77C7F62598EAULL,
		0x11E60E594E4C5A04ULL,
		0x59F9C73B01DC13FAULL
	}};
	sign = 0;
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
		0xEFBC3093B8CFA520ULL,
		0xF5AF613EA6F7BE22ULL,
		0xC737D2B0B7D9380BULL,
		0x085AF5BEDB0A0FD8ULL,
		0xBE5B7B528988FF63ULL,
		0xFF34180660914C1DULL,
		0x92667AEB15E3BFD7ULL,
		0x6D810D8A0C262AAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E8D4DFABB6F172BULL,
		0xB7E65486C5C8DF06ULL,
		0x98C18AEEB4C53F57ULL,
		0x90131B1C11A72454ULL,
		0x05A23A40FE197095ULL,
		0x3F4A8DADC601CCA3ULL,
		0x205D962B91850179ULL,
		0xA4BAE4ABAAD3C5AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x512EE298FD608DF5ULL,
		0x3DC90CB7E12EDF1CULL,
		0x2E7647C20313F8B4ULL,
		0x7847DAA2C962EB84ULL,
		0xB8B941118B6F8ECDULL,
		0xBFE98A589A8F7F7AULL,
		0x7208E4BF845EBE5EULL,
		0xC8C628DE61526500ULL
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
		0xD0D2938959560038ULL,
		0x5AF515FEE98323BAULL,
		0x363C6EEADD545DB7ULL,
		0xCD89703BB57464CAULL,
		0xB6104A1E207AAA8BULL,
		0xE85E86A07BC5FCFBULL,
		0x9874CAB05ADD2843ULL,
		0x255867631D35A53BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D9AC0E6BC4AFCB0ULL,
		0xF59495232F2A83B6ULL,
		0x28B381F5ED3494CBULL,
		0xEEA72E03E24CAC2AULL,
		0x7FF52F642C081B04ULL,
		0x3159532CFD0B2DC4ULL,
		0x98E65CCE6D3870C7ULL,
		0x8ACD9D097639ED31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7337D2A29D0B0388ULL,
		0x656080DBBA58A004ULL,
		0x0D88ECF4F01FC8EBULL,
		0xDEE24237D327B8A0ULL,
		0x361B1AB9F4728F86ULL,
		0xB70533737EBACF37ULL,
		0xFF8E6DE1EDA4B77CULL,
		0x9A8ACA59A6FBB809ULL
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
		0xEB0D3E195AEDC810ULL,
		0x8EB78B52A402B90BULL,
		0xE4D548963F511EF7ULL,
		0xCD2D44ED041A29ABULL,
		0x403786CE84E66113ULL,
		0xB7963382803D5872ULL,
		0x8C281AE4ABE4E83DULL,
		0x327554862280FD2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52295E01386E3675ULL,
		0xD6A34D489D82E7D5ULL,
		0xD911FA49B5896C2BULL,
		0x491ADC2C65EDEF9CULL,
		0x7D9F9F55C201FBACULL,
		0x8BC0F40A34B40E88ULL,
		0xFA81BFD1443AAC62ULL,
		0xA730C6B178AEB1A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98E3E018227F919BULL,
		0xB8143E0A067FD136ULL,
		0x0BC34E4C89C7B2CBULL,
		0x841268C09E2C3A0FULL,
		0xC297E778C2E46567ULL,
		0x2BD53F784B8949E9ULL,
		0x91A65B1367AA3BDBULL,
		0x8B448DD4A9D24B87ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x74DB9572CD6CD58CULL,
		0x6BC157B170F8B0BDULL,
		0xCD990BBB737EEEE7ULL,
		0x1E7FD48CD691FE14ULL,
		0x7208EE598931DD5BULL,
		0x69DFDBDD58E9C5F4ULL,
		0xABEE59D3D82D0BC3ULL,
		0xB67595E43638A0E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26055EBCB688FA92ULL,
		0xF1936E861A69807CULL,
		0xC82EAEA66A19ACBFULL,
		0xA6C2E79BD656F941ULL,
		0x0B5C7DA7529952EBULL,
		0x57D5803766832311ULL,
		0xB5BACB9ABFA053C2ULL,
		0x0ECBD7457FFAA37FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ED636B616E3DAFAULL,
		0x7A2DE92B568F3041ULL,
		0x056A5D1509654227ULL,
		0x77BCECF1003B04D3ULL,
		0x66AC70B236988A6FULL,
		0x120A5BA5F266A2E3ULL,
		0xF6338E39188CB801ULL,
		0xA7A9BE9EB63DFD67ULL
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
		0xDCCFBC476B8522DDULL,
		0x7D7B177831F4F9F5ULL,
		0xF0B6FD702C4240ECULL,
		0x3C80C92D3AC22F77ULL,
		0x711F5E2C317F7B47ULL,
		0x18272C8695A99C28ULL,
		0xE6244E5D7918E2F3ULL,
		0xF325E755B2E121C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE198941AE1DDBD55ULL,
		0xAB6B19D031ECC51CULL,
		0xAA009197B53CB6F7ULL,
		0xF949751B6773A6C7ULL,
		0x3C0F84C36E27307FULL,
		0xD6F6B8C50FA53B3CULL,
		0xC0F23DEC944CE275ULL,
		0x5954C8C507E4B75CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB37282C89A76588ULL,
		0xD20FFDA8000834D8ULL,
		0x46B66BD8770589F4ULL,
		0x43375411D34E88B0ULL,
		0x350FD968C3584AC7ULL,
		0x413073C1860460ECULL,
		0x25321070E4CC007DULL,
		0x99D11E90AAFC6A6BULL
	}};
	sign = 0;
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
		0xC3957F4238311490ULL,
		0x3E38E16150D5F77FULL,
		0xC1EB1A0E8AB54DC1ULL,
		0x0B8D939C95D729EEULL,
		0x91B5566E06EA4A29ULL,
		0x0A8522C52BB1CF66ULL,
		0xD1D607849459FADCULL,
		0x47D005376B41F454ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C4D8FD28C796766ULL,
		0x4F31AD501E5E7F6DULL,
		0x0E4F81FC34AB290AULL,
		0xA6ACC3F55522288BULL,
		0x5FCFC3C63850C9C2ULL,
		0x0D2A9B028DBE4190ULL,
		0x09A8A9063B8C61B7ULL,
		0x133830F3510DD5B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5747EF6FABB7AD2AULL,
		0xEF07341132777812ULL,
		0xB39B9812560A24B6ULL,
		0x64E0CFA740B50163ULL,
		0x31E592A7CE998066ULL,
		0xFD5A87C29DF38DD6ULL,
		0xC82D5E7E58CD9924ULL,
		0x3497D4441A341EA2ULL
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
		0x42110E2D205BC4C9ULL,
		0x1B3657705E5D0E60ULL,
		0x492C219773FFFE00ULL,
		0xB7AEE89A100A69FFULL,
		0x7631145EB27677CBULL,
		0xF79CD6FCCC5C70BDULL,
		0x433596D1886BA41FULL,
		0xA26FC8FC72C9FFC9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC23040BE42D07118ULL,
		0xA392B720782ECD06ULL,
		0xD76EC8F367696000ULL,
		0x9B5CE9A314BBA000ULL,
		0x0712D584500653D3ULL,
		0x0377C5EFA2D930CAULL,
		0x5A955EDB7750CAE7ULL,
		0x967124E3A7F5EC4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FE0CD6EDD8B53B1ULL,
		0x77A3A04FE62E4159ULL,
		0x71BD58A40C969DFFULL,
		0x1C51FEF6FB4EC9FEULL,
		0x6F1E3EDA627023F8ULL,
		0xF425110D29833FF3ULL,
		0xE8A037F6111AD938ULL,
		0x0BFEA418CAD4137EULL
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
		0x5769899C299A740FULL,
		0x13D9B0252D34C9B4ULL,
		0x8076C0D996146710ULL,
		0x5E371F18CC9D63F3ULL,
		0x282B2D6A346ECD27ULL,
		0x577DF3DB047C9C59ULL,
		0x6D310655D6A21060ULL,
		0x27C6645819414A96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x234A5081045B1526ULL,
		0xFC46836DA60C6AD9ULL,
		0x953141F2AB18700FULL,
		0xEAC6D6FF23504943ULL,
		0xFDBF3A4D0508B532ULL,
		0x3B66E23E12386A3FULL,
		0x2142C40F8F7DF33CULL,
		0x1B28420E3372822FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x341F391B253F5EE9ULL,
		0x17932CB787285EDBULL,
		0xEB457EE6EAFBF700ULL,
		0x73704819A94D1AAFULL,
		0x2A6BF31D2F6617F4ULL,
		0x1C17119CF2443219ULL,
		0x4BEE424647241D24ULL,
		0x0C9E2249E5CEC867ULL
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
		0x88BC98A842C7B7D1ULL,
		0xE9E2BBA5E1263BEFULL,
		0x4DFB20AABE3B5355ULL,
		0x31510528DC2EB52BULL,
		0xEB214C5E3C978FCAULL,
		0x9D3A41C76FD3B6D7ULL,
		0xE8C521424EED3742ULL,
		0xB9BE5D680104FB50ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68DCCC5E26BEC71ULL,
		0x6CCA816D6093FB53ULL,
		0xD52F3315A7C2A14EULL,
		0x1078FF5545D8A660ULL,
		0x5891455FB89C0F1CULL,
		0x985BEF321EC5A72AULL,
		0x2FB2C6DC966DD63CULL,
		0xE2BFEFC002D7B32FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC22ECBE2605BCB60ULL,
		0x7D183A388092409BULL,
		0x78CBED951678B207ULL,
		0x20D805D396560ECAULL,
		0x929006FE83FB80AEULL,
		0x04DE5295510E0FADULL,
		0xB9125A65B87F6106ULL,
		0xD6FE6DA7FE2D4821ULL
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
		0x36FDA655EC99BB48ULL,
		0x635AE3CAC916E659ULL,
		0x7091CAC73D7F3AEBULL,
		0x9F2F04082DCB232FULL,
		0x5863051F34E3D6DBULL,
		0xAE3B62C890958C16ULL,
		0x25CF36C915F4B089ULL,
		0x37A919B79BEB5227ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB8ED5185A3F2E2ULL,
		0x67FA399577B92833ULL,
		0x3A068051DEC8AE71ULL,
		0xDA56E22CF56DE641ULL,
		0x686BE57B0B2241C0ULL,
		0x96614E601F91E83BULL,
		0xE90DC6B8B8DC0DE8ULL,
		0xA9424A4C670D0961ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3944B90466F5C866ULL,
		0xFB60AA35515DBE25ULL,
		0x368B4A755EB68C79ULL,
		0xC4D821DB385D3CEEULL,
		0xEFF71FA429C1951AULL,
		0x17DA14687103A3DAULL,
		0x3CC170105D18A2A1ULL,
		0x8E66CF6B34DE48C5ULL
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
		0xA87B35E9B9D682E5ULL,
		0xAADA08E02F85AD30ULL,
		0x8CBAF9C240A3574BULL,
		0x82FCDAC5D5F2F283ULL,
		0x2B65F29C6A2E64F9ULL,
		0xB966A42913861AE8ULL,
		0x0C44BBB675D38DB6ULL,
		0x043A0B26AE279BBEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80EDC99CAE6A0F6AULL,
		0x04F20DF0EFBAEE27ULL,
		0x4C68C73C2F58BB8EULL,
		0xD0E922484796924FULL,
		0xA1E8E43488F1DBFCULL,
		0x563B5889D1210A8AULL,
		0x3A908E87562EE7E6ULL,
		0xE5B87A5BCAE72546ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x278D6C4D0B6C737BULL,
		0xA5E7FAEF3FCABF09ULL,
		0x40523286114A9BBDULL,
		0xB213B87D8E5C6034ULL,
		0x897D0E67E13C88FCULL,
		0x632B4B9F4265105DULL,
		0xD1B42D2F1FA4A5D0ULL,
		0x1E8190CAE3407677ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4FC091F486F3EC16ULL,
		0x9B9F1EF35C15E95AULL,
		0xF0856DA8EC0A4E89ULL,
		0x50644CCE087EBC63ULL,
		0x76662ECD4964955CULL,
		0xBA8921BFC7CDD1C8ULL,
		0x3AC611C31E65AF3EULL,
		0xA9286655BDC35471ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x809A9B332B21923AULL,
		0x901860214269A73FULL,
		0x2BC0AE21F1F46BE0ULL,
		0x37D588FDCDF8A349ULL,
		0xA627854481EA8BF4ULL,
		0xCA3FA44B049A729EULL,
		0xA7DC4E788D6674FBULL,
		0xB243DB082E37C481ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF25F6C15BD259DCULL,
		0x0B86BED219AC421AULL,
		0xC4C4BF86FA15E2A9ULL,
		0x188EC3D03A86191AULL,
		0xD03EA988C77A0968ULL,
		0xF0497D74C3335F29ULL,
		0x92E9C34A90FF3A42ULL,
		0xF6E48B4D8F8B8FEFULL
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
		0xB83772077CF99711ULL,
		0xE9FE55CC344A8539ULL,
		0xF9A7EF6A4662FF75ULL,
		0xF38F6C455AECFEC4ULL,
		0x8576C980648A8092ULL,
		0xD1EA111CAC58EF7AULL,
		0xE134C5B8D336EE7CULL,
		0x3004D2D2EB7A7F70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4669DD74CDB1208ULL,
		0xE90888CEADB66090ULL,
		0xF29D00F2A457A86EULL,
		0x15A5D9CF342FC03FULL,
		0x0DA44226F2911506ULL,
		0xCA61AE979A50EE40ULL,
		0x5D10468B1B8250F3ULL,
		0x8EF68E13AD016E6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03D0D430301E8509ULL,
		0x00F5CCFD869424A9ULL,
		0x070AEE77A20B5707ULL,
		0xDDE9927626BD3E85ULL,
		0x77D2875971F96B8CULL,
		0x078862851208013AULL,
		0x84247F2DB7B49D89ULL,
		0xA10E44BF3E791102ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCF86E350857D0280ULL,
		0x2116DEE3091102FBULL,
		0x5F62BA8F8F0A4B9CULL,
		0x2A4D451675481FF4ULL,
		0x20A4A3EAA1AE462FULL,
		0x25D1446F825DF1ABULL,
		0x5EA203449E7C2451ULL,
		0x9D5EA903BABD7039ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EB9FF5D5F2EEE85ULL,
		0x27C504573A9705C5ULL,
		0x9AEC9F84E68D309DULL,
		0x378182659D0B69A8ULL,
		0x879D0292D4A16EC9ULL,
		0x8F839F61B49D64FFULL,
		0x015C49E405D69924ULL,
		0xEFF07A346363A6ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0CCE3F3264E13FBULL,
		0xF951DA8BCE79FD36ULL,
		0xC4761B0AA87D1AFEULL,
		0xF2CBC2B0D83CB64BULL,
		0x9907A157CD0CD765ULL,
		0x964DA50DCDC08CABULL,
		0x5D45B96098A58B2CULL,
		0xAD6E2ECF5759C98EULL
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
		0x3BD337EFCC00BAC0ULL,
		0x72ADEA8B3FFD9AA9ULL,
		0xC84E73498A17F8CCULL,
		0x900149643FE71B9EULL,
		0xDFD2C8F7F2FE497EULL,
		0xDA13C87278D8D98DULL,
		0x7D94E5AAB2F7B3B6ULL,
		0x7DDBC8F65FC21D8BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60BC0F34A0D6B264ULL,
		0x777DEFB77074785FULL,
		0x34F3E057BBD9CB61ULL,
		0x83EC88AA5ACF6840ULL,
		0x62F963CF6A2FBF38ULL,
		0xA3F34F58BFEAC5C0ULL,
		0x738366AC405DF191ULL,
		0x93D886E3AB6ECC08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB1728BB2B2A085CULL,
		0xFB2FFAD3CF892249ULL,
		0x935A92F1CE3E2D6AULL,
		0x0C14C0B9E517B35EULL,
		0x7CD9652888CE8A46ULL,
		0x36207919B8EE13CDULL,
		0x0A117EFE7299C225ULL,
		0xEA034212B4535183ULL
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
		0xDDFDB2F530DF8AD6ULL,
		0x149258E20F134697ULL,
		0x2F43AA0460E47096ULL,
		0xBC9702CC382CAE3DULL,
		0xFCBFA289E6F3001DULL,
		0xAE1EBA0156989945ULL,
		0xF786DDE4500AA79BULL,
		0xEAB8C985D3ED3CDAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F02638F3296C1FCULL,
		0x1A6556DCDA0E1036ULL,
		0x53F92B43B1102B60ULL,
		0x2847257167F903DEULL,
		0x0A5EDF1EF68EFFB0ULL,
		0x6167FDAF78BE9C8DULL,
		0xD32712E32B7BF23EULL,
		0x8BDFEB62CF7CECE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEFB4F65FE48C8DAULL,
		0xFA2D020535053661ULL,
		0xDB4A7EC0AFD44535ULL,
		0x944FDD5AD033AA5EULL,
		0xF260C36AF064006DULL,
		0x4CB6BC51DDD9FCB8ULL,
		0x245FCB01248EB55DULL,
		0x5ED8DE2304704FF7ULL
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
		0x2A82DA4D5CF38941ULL,
		0x9260BC7F6CC707C1ULL,
		0xBE073F2B1F0E760DULL,
		0x244FD61B1D938298ULL,
		0x15D09CC7FCDBB3F6ULL,
		0x2734A95A189FB42AULL,
		0x50B5D2A85407AC60ULL,
		0x7ABE624B0A887AA6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4E18658E394BB10ULL,
		0x1CA3FEE9D60E3849ULL,
		0x68B06FD1FD646F16ULL,
		0x36C858782D208CC1ULL,
		0x6BAE5259580CDFACULL,
		0x4A55CDE0341B5C6AULL,
		0xE7B26580A5F06557ULL,
		0x2E13A4A163F41BF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75A153F4795ECE31ULL,
		0x75BCBD9596B8CF77ULL,
		0x5556CF5921AA06F7ULL,
		0xED877DA2F072F5D7ULL,
		0xAA224A6EA4CED449ULL,
		0xDCDEDB79E48457BFULL,
		0x69036D27AE174708ULL,
		0x4CAABDA9A6945EAEULL
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
		0x32641176AE0D2D7BULL,
		0xF82FAF2A16F65392ULL,
		0x7D21197A88819279ULL,
		0x1431E026A7850F40ULL,
		0xC4E0C8292A268F24ULL,
		0x39F61A4084ADED41ULL,
		0xB3B0A071CE4E9B52ULL,
		0x984694B7393646CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC95020C357145FULL,
		0x2A071AEACBED5945ULL,
		0xC82FBF05001BE592ULL,
		0xEDFCFD1BAD1DA7BCULL,
		0xE878DE5D0ED9137CULL,
		0x6F710CD11FA4AFC3ULL,
		0x1FE200EE3299EBBFULL,
		0xAEEFB9057A0E4BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC59AC155EAB6191CULL,
		0xCE28943F4B08FA4CULL,
		0xB4F15A758865ACE7ULL,
		0x2634E30AFA676783ULL,
		0xDC67E9CC1B4D7BA7ULL,
		0xCA850D6F65093D7DULL,
		0x93CE9F839BB4AF92ULL,
		0xE956DBB1BF27FB0BULL
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
		0x43100D3F62C361DBULL,
		0x1259B58A53B2B58AULL,
		0x730249C458FD52AAULL,
		0x48CFB953710A4977ULL,
		0x7EBB0FF5F8AEE63EULL,
		0x491A55463E46B56FULL,
		0xB6538940CDC0EF7EULL,
		0xDDFEBA4CA76E777DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x90F35BB7686658D6ULL,
		0xD5D0D39BA26464B3ULL,
		0xE864BDFE07E95BACULL,
		0x520C4A632D16F8BBULL,
		0x1ED8044F6DCE746AULL,
		0x6F9A5AAE6062A32BULL,
		0x6CE8690C78BE2AE1ULL,
		0x33178FA1B287B05DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB21CB187FA5D0905ULL,
		0x3C88E1EEB14E50D6ULL,
		0x8A9D8BC65113F6FDULL,
		0xF6C36EF043F350BBULL,
		0x5FE30BA68AE071D3ULL,
		0xD97FFA97DDE41244ULL,
		0x496B20345502C49CULL,
		0xAAE72AAAF4E6C720ULL
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
		0x00D762FCD98A13F4ULL,
		0x3D83026AF462683FULL,
		0xEF338BB8AD49664CULL,
		0xF62287B966809AF4ULL,
		0x47E52128B5B79A1FULL,
		0xC333A7464900D6A0ULL,
		0x47BC92F4A7CE8396ULL,
		0xC1309EFD3070F7EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x625B067E077A71DCULL,
		0x008D03EA905461ACULL,
		0x5062D2A19DC7CE08ULL,
		0x11B18BD796A584F1ULL,
		0x29FC945EB5118A73ULL,
		0xF4ABC01F5A578916ULL,
		0xE6B08C2BCA414066ULL,
		0xD81455A7DB4ECC60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E7C5C7ED20FA218ULL,
		0x3CF5FE80640E0692ULL,
		0x9ED0B9170F819844ULL,
		0xE470FBE1CFDB1603ULL,
		0x1DE88CCA00A60FACULL,
		0xCE87E726EEA94D8AULL,
		0x610C06C8DD8D432FULL,
		0xE91C495555222B8AULL
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
		0xCCD21C208750F177ULL,
		0xBCC94917CC5D0A8FULL,
		0xF7C055587B26F8DEULL,
		0xC5489A45BF06F7A2ULL,
		0x6F2A8F3D4FAE3E61ULL,
		0x4768A912AA1D19FDULL,
		0xC745A6E925AD60B6ULL,
		0x6A4E2B2B6E80A470ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x768ABB5925D1D64FULL,
		0x9D7106AA49746D68ULL,
		0x96524FFF8A3147C4ULL,
		0x04A28955C29A3DA5ULL,
		0x920E4EA510173F3EULL,
		0x83670C0BCF61EFC6ULL,
		0x7F6A9AB9D0B4684EULL,
		0xED33A24C68BF69BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x564760C7617F1B28ULL,
		0x1F58426D82E89D27ULL,
		0x616E0558F0F5B11AULL,
		0xC0A610EFFC6CB9FDULL,
		0xDD1C40983F96FF23ULL,
		0xC4019D06DABB2A36ULL,
		0x47DB0C2F54F8F867ULL,
		0x7D1A88DF05C13AB3ULL
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
		0x44C62335B186BB5BULL,
		0x86C99E31EBC6EBD3ULL,
		0xB4482B112F93761AULL,
		0x5C52C4DE0F99C2DAULL,
		0xAF04422C8507295EULL,
		0x54C7C03D60F38665ULL,
		0x0E993182C55EEEEFULL,
		0x8CDB5BA848B48ACFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74ACAADCEAF9A3D5ULL,
		0x4B2E68CB51D8DF00ULL,
		0x9045880CD139060DULL,
		0x85E53932C41DC475ULL,
		0xCFDECC7A4B202402ULL,
		0x22D4FD64D4F4AB9FULL,
		0xFF3C1B7AD2962AA3ULL,
		0x0FA9E7DBC5180B66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0197858C68D1786ULL,
		0x3B9B356699EE0CD2ULL,
		0x2402A3045E5A700DULL,
		0xD66D8BAB4B7BFE65ULL,
		0xDF2575B239E7055BULL,
		0x31F2C2D88BFEDAC5ULL,
		0x0F5D1607F2C8C44CULL,
		0x7D3173CC839C7F68ULL
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
		0xA13AA3876672131CULL,
		0xEF8CB8AFF92B182FULL,
		0x942B57A3E55E7B9BULL,
		0x8D483222D672C2A6ULL,
		0xD15FDCF3D26059D5ULL,
		0xD8DADD68A23B529AULL,
		0x2B9B454BD35CC0C0ULL,
		0x997626264DA18810ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24D35794924011B7ULL,
		0xFD0A524E48CDE2B1ULL,
		0x1048AB7F617E2C77ULL,
		0x8CE7BE5636BED0A3ULL,
		0xF2CCBEF4A9A17878ULL,
		0x6FAA371DA8688D2FULL,
		0x4798BDB0CFA64ABDULL,
		0x040BDE7A53F4C43EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C674BF2D4320165ULL,
		0xF2826661B05D357EULL,
		0x83E2AC2483E04F23ULL,
		0x006073CC9FB3F203ULL,
		0xDE931DFF28BEE15DULL,
		0x6930A64AF9D2C56AULL,
		0xE402879B03B67603ULL,
		0x956A47ABF9ACC3D1ULL
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
		0x4E193649CCBF0692ULL,
		0x9E5C9BFFC161BD75ULL,
		0xE3FCA22C63895A50ULL,
		0x53D42214B9742C26ULL,
		0x8BE3E355DBBF45FDULL,
		0x01C66F6D20FD6D56ULL,
		0xEAE0D6B5731F1E47ULL,
		0x905DD921861BA3E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87A58DE40754E22ULL,
		0x338D02A155C8E405ULL,
		0xD119ADE6088869E5ULL,
		0x71D066FEED55559BULL,
		0xBC01F1E1726825DBULL,
		0x97084A3ED9AF226FULL,
		0x6FAB64B0030ED3D2ULL,
		0xDEE924C952C0430BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x659EDD6B8C49B870ULL,
		0x6ACF995E6B98D96FULL,
		0x12E2F4465B00F06BULL,
		0xE203BB15CC1ED68BULL,
		0xCFE1F17469572021ULL,
		0x6ABE252E474E4AE6ULL,
		0x7B35720570104A74ULL,
		0xB174B458335B60D8ULL
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
		0x6DFED04F6FC6D9EAULL,
		0xC1851745B8F18D55ULL,
		0x672E21E04E1B3622ULL,
		0x4B6D4AF9501E858BULL,
		0x4EEF69799DBC94BDULL,
		0xF7EE572CC6E4CE2FULL,
		0xF0C9770375B043DCULL,
		0x066901153FC585CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBB0E02CA9E8560ULL,
		0xCF812C95FD96363DULL,
		0x82E0C98B1BB3C5C4ULL,
		0x76909939B92B5E17ULL,
		0x2712D233652AD8CCULL,
		0x06285B6CAFB764BBULL,
		0x0D98A847DDA043DAULL,
		0x412E9C27BC66F7FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA243C24CA528548AULL,
		0xF203EAAFBB5B5717ULL,
		0xE44D58553267705DULL,
		0xD4DCB1BF96F32773ULL,
		0x27DC97463891BBF0ULL,
		0xF1C5FBC0172D6974ULL,
		0xE330CEBB98100002ULL,
		0xC53A64ED835E8DD1ULL
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
		0xDE58B7631A5B0EE9ULL,
		0x341EEE7C15606DA8ULL,
		0xB45E171998C6C33DULL,
		0x3A985C58EAEF3E41ULL,
		0x752064C21940940EULL,
		0xAFE8440C7C673D14ULL,
		0x3DDC093160D3D190ULL,
		0x01322FED330CA9D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE427B69479E6E8F0ULL,
		0x39D3754D72D8F41BULL,
		0xB641DF4DB8CFE81FULL,
		0xF20D1EFE8B3C0F91ULL,
		0x7B50A47F2C027C8EULL,
		0xFB4AB389D4A47A84ULL,
		0xBE6A19D4B96FEBACULL,
		0x62F775A5BB44A66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA3100CEA07425F9ULL,
		0xFA4B792EA287798CULL,
		0xFE1C37CBDFF6DB1DULL,
		0x488B3D5A5FB32EAFULL,
		0xF9CFC042ED3E177FULL,
		0xB49D9082A7C2C28FULL,
		0x7F71EF5CA763E5E3ULL,
		0x9E3ABA4777C80369ULL
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
		0x00A6415A93AC6244ULL,
		0xA2CF1001594DABD5ULL,
		0x53D6DAC580D27469ULL,
		0x5039DB30DA120134ULL,
		0x2FE31992760AD7D6ULL,
		0xEC738B37ACFAEA5FULL,
		0x5138AAFCC96F6E7CULL,
		0xE5899473B15646A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF69D76F56B61E2ULL,
		0x0B4D56DB7407A850ULL,
		0xC3A83D7033E95370ULL,
		0x3BDA5FD843A64763ULL,
		0xECF8854524F70434ULL,
		0xD16F24C14BA9BA1AULL,
		0xF50BE06BFF724B31ULL,
		0x627F39381CFA849FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91AFA3E39E410062ULL,
		0x9781B925E5460384ULL,
		0x902E9D554CE920F9ULL,
		0x145F7B58966BB9D0ULL,
		0x42EA944D5113D3A2ULL,
		0x1B04667661513044ULL,
		0x5C2CCA90C9FD234BULL,
		0x830A5B3B945BC200ULL
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
		0x701C9399024478B6ULL,
		0xA47911D075903DF8ULL,
		0x11178D9F31B869ECULL,
		0xBD8E8F4C8C592294ULL,
		0x43BB26DCE8D7988CULL,
		0x29D702078E20E72CULL,
		0x7E62775B4BFB00AFULL,
		0x09F9355A7A426073ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7753717E5C72783ULL,
		0x02ADA074CFA5C2B6ULL,
		0xA2C31E9572CA56A3ULL,
		0x8ABB9E5139DEF63FULL,
		0xB41E4B1CD53814A7ULL,
		0x8BD242BA458FAA1AULL,
		0xB3C5E92766AD57BDULL,
		0x80C65BAE5CEEB6E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98A75C811C7D5133ULL,
		0xA1CB715BA5EA7B41ULL,
		0x6E546F09BEEE1349ULL,
		0x32D2F0FB527A2C54ULL,
		0x8F9CDBC0139F83E5ULL,
		0x9E04BF4D48913D11ULL,
		0xCA9C8E33E54DA8F1ULL,
		0x8932D9AC1D53A98FULL
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
		0x96840F0114C0F229ULL,
		0x9C2F0CA73B3E3A69ULL,
		0x09D81816A6948D0EULL,
		0xA316FC2F100863ADULL,
		0x3028CCF25DDB1141ULL,
		0x0FFF6EBA71C46229ULL,
		0x0D4C2047F3FCAAC3ULL,
		0x7E731993A5EEBB49ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC8AC8CE4A225890ULL,
		0x19FB68CF17C945E2ULL,
		0xE935851C80B4646BULL,
		0x769A9AD43359B7F7ULL,
		0x80292DA18AAD66F5ULL,
		0x66C7088197BC1DCEULL,
		0x7023F8CD4E50CA0DULL,
		0x8D10614E4C828CD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99F94632CA9E9999ULL,
		0x8233A3D82374F486ULL,
		0x20A292FA25E028A3ULL,
		0x2C7C615ADCAEABB5ULL,
		0xAFFF9F50D32DAA4CULL,
		0xA9386638DA08445AULL,
		0x9D28277AA5ABE0B5ULL,
		0xF162B845596C2E72ULL
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
		0x09E1F7F6EE1A8EA5ULL,
		0xE45C2FB66D84D7A5ULL,
		0xA0EBA75262A7E008ULL,
		0xD557161DAAA41AB0ULL,
		0x817AA00279233E58ULL,
		0xD0F4C81688C92FF7ULL,
		0xFC5230989E10F8D4ULL,
		0x3FB65CFB39710545ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x496F4E0B9241B906ULL,
		0x364E368CA649F80BULL,
		0x257E12AB680510D7ULL,
		0x3E20CD503D0203F1ULL,
		0xFCEFCD73BD4E9815ULL,
		0x5D90BD9548FAD669ULL,
		0xCA19B52138A5D9FDULL,
		0x5E2F40A717A2F142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC072A9EB5BD8D59FULL,
		0xAE0DF929C73ADF99ULL,
		0x7B6D94A6FAA2CF31ULL,
		0x973648CD6DA216BFULL,
		0x848AD28EBBD4A643ULL,
		0x73640A813FCE598DULL,
		0x32387B77656B1ED7ULL,
		0xE1871C5421CE1403ULL
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
		0x8DB9C909BFBD3EAAULL,
		0xB2A08070345E3040ULL,
		0x6AED6B8AD0CBA727ULL,
		0xAE643082D4FBCBA6ULL,
		0x0696AC3FFD73D228ULL,
		0xD896D0080F02F262ULL,
		0x91F44262AA4456A4ULL,
		0x7C3B46923F80F96FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97E66D563B661ABULL,
		0x1B8022DAE98A8B17ULL,
		0xC050835DB208A6C6ULL,
		0x5D0B5E47C3C8071BULL,
		0x40DFA224E530390FULL,
		0x3311E816C88BAA66ULL,
		0xD65B291B1FA48A31ULL,
		0x8DC00098D3DB58C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD43B62345C06DCFFULL,
		0x97205D954AD3A528ULL,
		0xAA9CE82D1EC30061ULL,
		0x5158D23B1133C48AULL,
		0xC5B70A1B18439919ULL,
		0xA584E7F1467747FBULL,
		0xBB9919478A9FCC73ULL,
		0xEE7B45F96BA5A0A9ULL
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
		0x676209B844595686ULL,
		0x999E5FBB783BD3E7ULL,
		0x4A78D42C808D7872ULL,
		0x9EAAE30010D074DDULL,
		0x016811439F290D8EULL,
		0xEAE7CA3ACD7C4456ULL,
		0x5EDB9BEF19EFDBF7ULL,
		0x61287E641743F0CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F853041459F219AULL,
		0xFB3CE73E4860698EULL,
		0x2D109EAABE174E61ULL,
		0xDC60D4E88F306823ULL,
		0x5CA1C90AD7CCBDEEULL,
		0xB4B058FB143B1FE9ULL,
		0xEBE33EF9CB081FC6ULL,
		0x329F60436CE3EF3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57DCD976FEBA34ECULL,
		0x9E61787D2FDB6A59ULL,
		0x1D683581C2762A10ULL,
		0xC24A0E1781A00CBAULL,
		0xA4C64838C75C4F9FULL,
		0x3637713FB941246CULL,
		0x72F85CF54EE7BC31ULL,
		0x2E891E20AA60018CULL
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
		0x399D7B755572D79AULL,
		0xF08C8821562C34E8ULL,
		0x475707F6650932DDULL,
		0x1AFC1FE23A8F2A0BULL,
		0x0257804CF45A8336ULL,
		0x3AD2466A374465A1ULL,
		0x1DB6CE77B4D12D99ULL,
		0x3C97D7E77DD79A9DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E100305D8B753CULL,
		0x102B06652EE7B382ULL,
		0x8C0DE37D02F67902ULL,
		0x841414429EC6BA0AULL,
		0x50B049A528CE2886ULL,
		0x0D4504B8B83C1B76ULL,
		0x0B9DC781F32F605FULL,
		0x99941BFC694AC523ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96BC7B44F7E7625EULL,
		0xE06181BC27448165ULL,
		0xBB4924796212B9DBULL,
		0x96E80B9F9BC87000ULL,
		0xB1A736A7CB8C5AAFULL,
		0x2D8D41B17F084A2AULL,
		0x121906F5C1A1CD3AULL,
		0xA303BBEB148CD57AULL
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
		0x761A9DC4CAFF3101ULL,
		0x793A44B729F15D7EULL,
		0x1F2225BB8A3087E9ULL,
		0x3D2F7BEFF29357DDULL,
		0xED72DC008992D5E7ULL,
		0x12C063C572E5D8CEULL,
		0xF02ACBDB1D337D3FULL,
		0xD2755C5A62ABF865ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB5A1A418A98B110ULL,
		0xABC2AB2CC7EF6FFAULL,
		0x36250B2B1C92208BULL,
		0x01B1E00F8EC94D41ULL,
		0x3201A15EB93CE9DDULL,
		0x74E16A3D111C9792ULL,
		0xC60975C6ABF62D68ULL,
		0x8D30FB80DB0AAD98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AC0838340667FF1ULL,
		0xCD77998A6201ED83ULL,
		0xE8FD1A906D9E675DULL,
		0x3B7D9BE063CA0A9BULL,
		0xBB713AA1D055EC0AULL,
		0x9DDEF98861C9413CULL,
		0x2A215614713D4FD6ULL,
		0x454460D987A14ACDULL
	}};
	sign = 0;
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
		0x1F077388D9965148ULL,
		0x5D6A0D3F65660C83ULL,
		0x8801A125F218E824ULL,
		0xFB63C5438F2EAE24ULL,
		0x9D525F4B3BF29397ULL,
		0x33B03F16D2DE4E4AULL,
		0xB0D45A71527E5BC2ULL,
		0xE48B250A38067239ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x399873A5F2CCF635ULL,
		0x4EC630D4EC5B5351ULL,
		0x58D6BAF16641BEB0ULL,
		0x6C198587D5DB8E54ULL,
		0xF1474FE12E479AE7ULL,
		0x02B93CCBD6FA754BULL,
		0x42F4D2DDE8E3D828ULL,
		0xC0486CE8BB798A8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE56EFFE2E6C95B13ULL,
		0x0EA3DC6A790AB931ULL,
		0x2F2AE6348BD72974ULL,
		0x8F4A3FBBB9531FD0ULL,
		0xAC0B0F6A0DAAF8B0ULL,
		0x30F7024AFBE3D8FEULL,
		0x6DDF8793699A839AULL,
		0x2442B8217C8CE7ADULL
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
		0x2A4CB551748FDD12ULL,
		0x2A49B719C6F5D340ULL,
		0xDBC887445357ECEBULL,
		0x32A03883BE86CBBDULL,
		0x0318DBF1FD650BBDULL,
		0xE5732E526668420BULL,
		0xB745711797737EB1ULL,
		0xB9AD9F60FE8FF36CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x23ACFDE8959C7745ULL,
		0x1FD3D1C27A004D3CULL,
		0x5E0A3D2509EE800BULL,
		0x4BDC75986E66DAACULL,
		0xCD30A562849B9E6EULL,
		0x4414F1AB7E4DCD6AULL,
		0x3574DD37ED6AD4F3ULL,
		0x429FD584193B100CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x069FB768DEF365CDULL,
		0x0A75E5574CF58604ULL,
		0x7DBE4A1F49696CE0ULL,
		0xE6C3C2EB501FF111ULL,
		0x35E8368F78C96D4EULL,
		0xA15E3CA6E81A74A0ULL,
		0x81D093DFAA08A9BEULL,
		0x770DC9DCE554E360ULL
	}};
	sign = 0;
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
		0x987FCF8C19716F29ULL,
		0x5EE1BB7C9E4C1C70ULL,
		0x8E1CECC75A848491ULL,
		0x116D04A4C6587D52ULL,
		0xCB30F363D7D2B245ULL,
		0x5706EE4DA0CD4CC8ULL,
		0xF7E4A47050A7760AULL,
		0x2DBDBE0AA84668E8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76CB147C08035ABBULL,
		0x6DA2BFDB5A86302EULL,
		0xAEAB6123B7B3FE25ULL,
		0x0F9F02A7C726B0C3ULL,
		0x58B93163D4BFE35AULL,
		0xDCEBC45CB046C997ULL,
		0x90CBE4258DAF4764ULL,
		0xD1F6516C5C6ACD38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21B4BB10116E146EULL,
		0xF13EFBA143C5EC42ULL,
		0xDF718BA3A2D0866BULL,
		0x01CE01FCFF31CC8EULL,
		0x7277C2000312CEEBULL,
		0x7A1B29F0F0868331ULL,
		0x6718C04AC2F82EA5ULL,
		0x5BC76C9E4BDB9BB0ULL
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
		0xB7A4D4559D2B41E4ULL,
		0xADA278AEBD631DC8ULL,
		0x07093361F0D2841DULL,
		0x1ADF2D4733F00F5FULL,
		0xEAD44DF19CB914FEULL,
		0x6384B7102EC5FA6CULL,
		0x711A624DC5350F95ULL,
		0x45707C554B34103FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B0C3907485FC4AULL,
		0xE06A331FB4A53C72ULL,
		0xDB1D1521B6660E91ULL,
		0xDCF8F4308B4D8B59ULL,
		0xA1ABAA350E46D97CULL,
		0x81A34FAC0B162840ULL,
		0x3740460E5D634221ULL,
		0x8DF14B4A958F3EA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6F410C528A5459AULL,
		0xCD38458F08BDE155ULL,
		0x2BEC1E403A6C758BULL,
		0x3DE63916A8A28405ULL,
		0x4928A3BC8E723B81ULL,
		0xE1E1676423AFD22CULL,
		0x39DA1C3F67D1CD73ULL,
		0xB77F310AB5A4D19EULL
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
		0xC1B372CAE0D0DBBCULL,
		0x0CFAFC050AEE9EADULL,
		0xF2E22067868EFEB9ULL,
		0x2173D688BAB24000ULL,
		0x25809D9954A75B6EULL,
		0xCD18E7AC92F790B3ULL,
		0x8BA8A69D45D6E1BEULL,
		0x3748725C18C56E00ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9B384247497E511ULL,
		0x7764CE2BA1BC5D0DULL,
		0x150D6A7FFAB9C834ULL,
		0x8320C615CB9B9A4FULL,
		0xDF2FF31D7551D1DBULL,
		0xEE070AA7B0BEB1D3ULL,
		0xBB5C140B65943743ULL,
		0x7AF2DE70F3B9C768ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7FFEEA66C38F6ABULL,
		0x95962DD96932419FULL,
		0xDDD4B5E78BD53684ULL,
		0x9E531072EF16A5B1ULL,
		0x4650AA7BDF558992ULL,
		0xDF11DD04E238DEDFULL,
		0xD04C9291E042AA7AULL,
		0xBC5593EB250BA697ULL
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
		0x6E6A5449EEE35D84ULL,
		0x40A88F590CF1BE7CULL,
		0xBF528A1BFAAFF1ECULL,
		0xAD6B6BD7F68DD7F5ULL,
		0xF16E97F27F04BBFBULL,
		0x87171B1E990EACC4ULL,
		0x063D18668B46B90BULL,
		0xDDBE821AC727F50FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE509BF98050BB84ULL,
		0x8562C0846EFA592EULL,
		0x298EE6A9F9BCDFFAULL,
		0x9EDB284C316FEB36ULL,
		0x2F845367A355BF10ULL,
		0x65B00F3E992DAA21ULL,
		0xBA6A300BBFA920B6ULL,
		0xB93624CD54DE6602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA019B8506E92A200ULL,
		0xBB45CED49DF7654DULL,
		0x95C3A37200F311F1ULL,
		0x0E90438BC51DECBFULL,
		0xC1EA448ADBAEFCEBULL,
		0x21670BDFFFE102A3ULL,
		0x4BD2E85ACB9D9855ULL,
		0x24885D4D72498F0CULL
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
		0x99607EBAE31CB21CULL,
		0xBEFFCEA53759DD34ULL,
		0xEF660A9A816678A7ULL,
		0x69ED4E4377DC3E70ULL,
		0x155485A33061C7B1ULL,
		0x3982EF1200F50339ULL,
		0x57C9D9852A3FD7A2ULL,
		0x231475AB7D6421E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC2F269C335F364DULL,
		0xBFB67F24F85BC9D0ULL,
		0xB31EDF58632E1B9DULL,
		0x59CE90137A238631ULL,
		0x589156F2B80B905FULL,
		0x148A142577F48351ULL,
		0x6D1CFC637F4C221FULL,
		0x9E6F4132D6F40E3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD31581EAFBD7BCFULL,
		0xFF494F803EFE1363ULL,
		0x3C472B421E385D09ULL,
		0x101EBE2FFDB8B83FULL,
		0xBCC32EB078563752ULL,
		0x24F8DAEC89007FE7ULL,
		0xEAACDD21AAF3B583ULL,
		0x84A53478A67013A6ULL
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
		0x5899B547C912703BULL,
		0x0BCD19760EAA332FULL,
		0xF61C8E64B6857FEFULL,
		0x7E6F3595FE554C5CULL,
		0x9B991991927D993CULL,
		0xEEED7D1A2582091AULL,
		0x41CFAAD739E9697FULL,
		0x9E6298CCD0D70CDEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9D0CA4E45C8FBEULL,
		0xDECAED52F96C32D5ULL,
		0x9201AE93B83DE2D8ULL,
		0x11ED31F4CEF9912AULL,
		0xA1CEFE12D66D9144ULL,
		0x888CEC9E2483B78EULL,
		0x209B0C263EAE47C4ULL,
		0x19929727D2D6342DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19FCA8A2E4B5E07DULL,
		0x2D022C23153E005AULL,
		0x641ADFD0FE479D16ULL,
		0x6C8203A12F5BBB32ULL,
		0xF9CA1B7EBC1007F8ULL,
		0x6660907C00FE518BULL,
		0x21349EB0FB3B21BBULL,
		0x84D001A4FE00D8B1ULL
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
		0x86575D06FFA0AF91ULL,
		0xA42F2E67FEC9C187ULL,
		0x128E1C91E8C47E4CULL,
		0x179350D22F5ED462ULL,
		0xD48FEFE5FDD7FE20ULL,
		0xD0B6BC2AAC0DC1DAULL,
		0x2E5DFDEE5F2C5A1EULL,
		0x09898E91255778AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x569BA3F663208729ULL,
		0xDCAB3D98A5A1DE57ULL,
		0x3AEE60FAD8149AAFULL,
		0x5BE56980898E222CULL,
		0xDA103D4512FD52C7ULL,
		0x1033CF4DA4A83CCBULL,
		0x4B6EED198EFC379EULL,
		0x3480B51F60454BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FBBB9109C802868ULL,
		0xC783F0CF5927E330ULL,
		0xD79FBB9710AFE39CULL,
		0xBBADE751A5D0B235ULL,
		0xFA7FB2A0EADAAB58ULL,
		0xC082ECDD0765850EULL,
		0xE2EF10D4D0302280ULL,
		0xD508D971C5122D09ULL
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
		0xD3BA27D7D3E1E5F2ULL,
		0x04D1D92BEB84BD2AULL,
		0x471A798BC3E97DB9ULL,
		0x2C3D2096C6FC55F7ULL,
		0x6B0EDD05A791C4DDULL,
		0x1F6E58EBF8CE7432ULL,
		0x4446C7BEB4A4D2E2ULL,
		0x25A02E86C4263FFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8306CBCC27ADB9FAULL,
		0xED204D682276676AULL,
		0xBC8FF5230E8E3EB8ULL,
		0x70AE37C28E4623B3ULL,
		0xE28C76AB67A10BC9ULL,
		0x2D49DE7FE49718CEULL,
		0xBE8B023AFD44048DULL,
		0x992948666229BF22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50B35C0BAC342BF8ULL,
		0x17B18BC3C90E55C0ULL,
		0x8A8A8468B55B3F00ULL,
		0xBB8EE8D438B63243ULL,
		0x8882665A3FF0B913ULL,
		0xF2247A6C14375B63ULL,
		0x85BBC583B760CE54ULL,
		0x8C76E62061FC80D9ULL
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
		0x77B0422BE7A55E88ULL,
		0xA34AE7E8592181A3ULL,
		0x4CEC798CE1250CE5ULL,
		0x5E117BA745EF05B3ULL,
		0xA06B0CDB01C8D7A3ULL,
		0xC292C0E416A83AA9ULL,
		0x286D8EF4C1227ADCULL,
		0xA858787870273987ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE35F44EEAACCCD3ULL,
		0x2AC00D14530CA1FEULL,
		0x4B2EBD6DB75CCEECULL,
		0xD93C9CA14ADCD804ULL,
		0xA9EF33B78BE75D5AULL,
		0xB333AEBA82F47C81ULL,
		0x0172C8DB1A934311ULL,
		0xC59FCA53440FF41EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC97A4DDCFCF891B5ULL,
		0x788ADAD40614DFA4ULL,
		0x01BDBC1F29C83DF9ULL,
		0x84D4DF05FB122DAFULL,
		0xF67BD92375E17A48ULL,
		0x0F5F122993B3BE27ULL,
		0x26FAC619A68F37CBULL,
		0xE2B8AE252C174569ULL
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
		0xF0F85AEA48430E09ULL,
		0xC299EC71C5095DE1ULL,
		0x54A01F5831117785ULL,
		0xC1F9606AC97EB453ULL,
		0x4D4CC62007084888ULL,
		0x095226611AB73F5DULL,
		0x0A13FE1791E36F6FULL,
		0xC871E84017FD2399ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AF3A90CCA03E6FULL,
		0xBD7BC804D4462F0FULL,
		0x8C9EF4D424EED46BULL,
		0xE69C6A5E97988942ULL,
		0x7146AC08E5A312A8ULL,
		0x29B294796CE90D32ULL,
		0xB8A29BEE2EE5BCB6ULL,
		0xB118557575FD9E91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E4920597BA2CF9AULL,
		0x051E246CF0C32ED2ULL,
		0xC8012A840C22A31AULL,
		0xDB5CF60C31E62B10ULL,
		0xDC061A17216535DFULL,
		0xDF9F91E7ADCE322AULL,
		0x5171622962FDB2B8ULL,
		0x175992CAA1FF8507ULL
	}};
	sign = 0;
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
		0x56919583FA7082ACULL,
		0x7DEA634AC1D38FF5ULL,
		0x755D3E1B3BC0236EULL,
		0x23D9F43C44033A2DULL,
		0x0447033FE3C72B8AULL,
		0xAB9378A14728FD8AULL,
		0xCD646507BD49022FULL,
		0x38B8556EA15E1ED6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x984502D04B6C297DULL,
		0x8C733F84F566F082ULL,
		0x4EAEB17A7D0D0743ULL,
		0xFFCCD63369CB5730ULL,
		0x4EE96ACCC49F4A74ULL,
		0x98340CA052FE83FCULL,
		0x75FEB6A405477D76ULL,
		0x392367A4E1D229FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE4C92B3AF04592FULL,
		0xF17723C5CC6C9F72ULL,
		0x26AE8CA0BEB31C2AULL,
		0x240D1E08DA37E2FDULL,
		0xB55D98731F27E115ULL,
		0x135F6C00F42A798DULL,
		0x5765AE63B80184B9ULL,
		0xFF94EDC9BF8BF4D9ULL
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
		0xFDF6146E1DA8A81EULL,
		0x25685780E82DF524ULL,
		0xEE048747D090DE94ULL,
		0x9ED237FE11FAF392ULL,
		0xF4ADBF50173AF609ULL,
		0x29FFB614134AA404ULL,
		0x8A16056DB3FB3B63ULL,
		0x8D7BE1BF44168878ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x859DF94186B9D089ULL,
		0x7E5D7F9810B88596ULL,
		0xDD26BA9893C92455ULL,
		0xDB169B48D862E16DULL,
		0xC3DF83621E917D0EULL,
		0xEB4717DBC22DA440ULL,
		0x4A781CE21DA5C67CULL,
		0xB65CE41E7A62AD58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78581B2C96EED795ULL,
		0xA70AD7E8D7756F8EULL,
		0x10DDCCAF3CC7BA3EULL,
		0xC3BB9CB539981225ULL,
		0x30CE3BEDF8A978FAULL,
		0x3EB89E38511CFFC4ULL,
		0x3F9DE88B965574E6ULL,
		0xD71EFDA0C9B3DB20ULL
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
		0xE39372260A47320AULL,
		0xD01945DACD2CEEFAULL,
		0x12A354B48C3D2B86ULL,
		0x6F8EFE02DA6C3227ULL,
		0x7B91597DB8F58682ULL,
		0x0543947FC41F0AD8ULL,
		0xFC140D046719C593ULL,
		0x1A8386BDB9354969ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA1E450E3A7E2F7CULL,
		0x67028E30D5FB5C73ULL,
		0x9EBDC224524A8825ULL,
		0x0E205B57BA7EE092ULL,
		0xA5B65C5B31860615ULL,
		0x5ACC5C8D0A6AB489ULL,
		0xB0B2A607C1C3559EULL,
		0x2C463D7C628ABA14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39752D17CFC9028EULL,
		0x6916B7A9F7319287ULL,
		0x73E5929039F2A361ULL,
		0x616EA2AB1FED5194ULL,
		0xD5DAFD22876F806DULL,
		0xAA7737F2B9B4564EULL,
		0x4B6166FCA5566FF4ULL,
		0xEE3D494156AA8F55ULL
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
		0x88795B430EBABD86ULL,
		0x51D534E743F52CB8ULL,
		0x0B7923BA02C0D990ULL,
		0xF91DA550CAA4B5E0ULL,
		0x83C6A8AF56DE31E8ULL,
		0x721F9671D2C2FDF7ULL,
		0xD483586541CA40A7ULL,
		0xD77454A3893048DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3738C217F9E204F2ULL,
		0x79F02D5706CFEF2CULL,
		0x6FCDE2C9CEE15130ULL,
		0x071A06D6845897A0ULL,
		0x1858C341C27B6C92ULL,
		0x77478DBA1790F582ULL,
		0x34396268D8A72B27ULL,
		0xB36B80910C8901ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5140992B14D8B894ULL,
		0xD7E507903D253D8CULL,
		0x9BAB40F033DF885FULL,
		0xF2039E7A464C1E3FULL,
		0x6B6DE56D9462C556ULL,
		0xFAD808B7BB320875ULL,
		0xA049F5FC6923157FULL,
		0x2408D4127CA74730ULL
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
		0xCAA291AE7AA430E7ULL,
		0x7F514FB53004AAA3ULL,
		0x17D714C384A21BF5ULL,
		0x07B6A9061DDF1AAAULL,
		0x11856842B881BBA4ULL,
		0x975DFA02896E1A62ULL,
		0xE07A3D8F448859E2ULL,
		0x22A430AA3ABE386BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3E7F8795E036AEULL,
		0x7DED37020AC06CB0ULL,
		0x85B9BBE4B47689C9ULL,
		0xB88E42539922CFF4ULL,
		0x40F04BDACF2F8507ULL,
		0x204A40BCA0922E05ULL,
		0x02D2BF12EBC053DDULL,
		0xCF2E8D294084FF9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60641226E4C3FA39ULL,
		0x016418B325443DF3ULL,
		0x921D58DED02B922CULL,
		0x4F2866B284BC4AB5ULL,
		0xD0951C67E952369CULL,
		0x7713B945E8DBEC5CULL,
		0xDDA77E7C58C80605ULL,
		0x5375A380FA3938D0ULL
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
		0x45E93BD0BEEE26BAULL,
		0xE19043BEF636B650ULL,
		0x8E5D1D02A2FE9146ULL,
		0x216B88F1B976EC9FULL,
		0xEE866E930D515B3BULL,
		0x75D8486C64341A05ULL,
		0x10BF15E6010286C1ULL,
		0xB75237A3DF7648EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00FE9889CFFF4919ULL,
		0x9AD8D5881D7E0FB0ULL,
		0x6C64C139584E6A01ULL,
		0xD2DB809DE636928EULL,
		0xD168D6D1BA1E8044ULL,
		0xAC3108F0E42D5743ULL,
		0xD687D369AE5DC71FULL,
		0x6183F97A23B2567BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44EAA346EEEEDDA1ULL,
		0x46B76E36D8B8A6A0ULL,
		0x21F85BC94AB02745ULL,
		0x4E900853D3405A11ULL,
		0x1D1D97C15332DAF6ULL,
		0xC9A73F7B8006C2C2ULL,
		0x3A37427C52A4BFA1ULL,
		0x55CE3E29BBC3F273ULL
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
		0xF215FC0C62A7B123ULL,
		0xF6C750B77ECC8939ULL,
		0x29A464D72C83904BULL,
		0xD04486831D5D65AAULL,
		0x8BE317416455A8A8ULL,
		0x3C38CD0E97EC7B12ULL,
		0xBD23D009F5F3533CULL,
		0x5661B2D00629AA7AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC20FDE7BFEB2CDULL,
		0xD51EC6BBC6CD0F9AULL,
		0xDD89E480137DFE54ULL,
		0x0AFFE4EE92D285F5ULL,
		0x27877ABEE3051CD5ULL,
		0x3CF4A5044BF10FFFULL,
		0xDE65C0366FC78400ULL,
		0xA16B6E4710F33F8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9253EC2DE6A8FE56ULL,
		0x21A889FBB7FF799FULL,
		0x4C1A8057190591F7ULL,
		0xC544A1948A8ADFB4ULL,
		0x645B9C8281508BD3ULL,
		0xFF44280A4BFB6B13ULL,
		0xDEBE0FD3862BCF3BULL,
		0xB4F64488F5366AEFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6C17C2E2BF7D5ADBULL,
		0x4FD8F5D14B645E04ULL,
		0x95C13148A06CD6A4ULL,
		0x7C85E0BF91C545F9ULL,
		0xF3800B67DA0AB6A1ULL,
		0x6B0E9A7B33A02AE0ULL,
		0xFAD41E91BD529E58ULL,
		0x919C8685230007E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF117728AEF822CDULL,
		0x8EBF8F91F70987B9ULL,
		0x31A50BCCC0EB6960ULL,
		0x6699E29ACD1496D0ULL,
		0xD51B583AB65F43C0ULL,
		0x3EB8F35AAFFF720BULL,
		0xEFF44BEBEB0DBCDEULL,
		0x90F5C99052646D69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D064BBA1085380EULL,
		0xC119663F545AD64AULL,
		0x641C257BDF816D43ULL,
		0x15EBFE24C4B0AF29ULL,
		0x1E64B32D23AB72E1ULL,
		0x2C55A72083A0B8D5ULL,
		0x0ADFD2A5D244E17AULL,
		0x00A6BCF4D09B9A7AULL
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
		0x2EAB4A8976DF0D04ULL,
		0xEA3FDB22ADD12A6AULL,
		0x39225476AF91B2DCULL,
		0xC2C99A7078F95AADULL,
		0x1AA51936690B735CULL,
		0x1760D65E1C9DB01FULL,
		0xE00D8B35A078061CULL,
		0xE48737AD2B2A7115ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EE827145F5CCBDULL,
		0x24E50981F41D61E3ULL,
		0x5546E3E7802CCD76ULL,
		0xE84299C5D0CAB3A1ULL,
		0x1860B8E5EDC5B6FBULL,
		0x073C7ADAA0F19AFFULL,
		0x482EA42EFC89C61DULL,
		0x403BF08A6576595BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4BCC81830E94047ULL,
		0xC55AD1A0B9B3C886ULL,
		0xE3DB708F2F64E566ULL,
		0xDA8700AAA82EA70BULL,
		0x024460507B45BC60ULL,
		0x10245B837BAC1520ULL,
		0x97DEE706A3EE3FFFULL,
		0xA44B4722C5B417BAULL
	}};
	sign = 0;
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
		0xDAD814E1DC51F660ULL,
		0x2F83B30A05DFFB2CULL,
		0x1BB2D687EFEAB8E2ULL,
		0x5445477555B62EC6ULL,
		0xC7C9153B315A1EDDULL,
		0xF6D2AA9F3952672BULL,
		0xC44A916C97C4C794ULL,
		0x7431DDEA2F7BC1E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5471370948F59035ULL,
		0x941041FF0A7FB0A9ULL,
		0x93638FFE2DBD860FULL,
		0x67B85F885B4EC9D5ULL,
		0xC6FB8447987CEA83ULL,
		0x3C8249CC8E286793ULL,
		0x7862407E794E67E1ULL,
		0xB9AB3E5095BC19EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8666DDD8935C662BULL,
		0x9B73710AFB604A83ULL,
		0x884F4689C22D32D2ULL,
		0xEC8CE7ECFA6764F0ULL,
		0x00CD90F398DD3459ULL,
		0xBA5060D2AB29FF98ULL,
		0x4BE850EE1E765FB3ULL,
		0xBA869F9999BFA7FFULL
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
		0x1720B5F99BBB8CEBULL,
		0x7AFB193242537860ULL,
		0x448E2D63670110D0ULL,
		0x4BADC8F87D9AEF54ULL,
		0x2B4E9ED9FAAB2861ULL,
		0x34576FC40F06EDACULL,
		0x7B05B2178F4E6E46ULL,
		0x382911417560C166ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F3DD016E456458EULL,
		0xE7AEA27C55D3F920ULL,
		0x03C87235EEDC65FFULL,
		0x0C16592CE8BE35B5ULL,
		0x59B8D83F4729571BULL,
		0x31DFFB17FC41E6F1ULL,
		0x15E11DAE3C17D597ULL,
		0x2A1A4AB4076A123CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7E2E5E2B765475DULL,
		0x934C76B5EC7F7F3FULL,
		0x40C5BB2D7824AAD0ULL,
		0x3F976FCB94DCB99FULL,
		0xD195C69AB381D146ULL,
		0x027774AC12C506BAULL,
		0x65249469533698AFULL,
		0x0E0EC68D6DF6AF2AULL
	}};
	sign = 0;
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
		0xC4101AAF626E6523ULL,
		0xA38082634E5A0E56ULL,
		0x606FDFB52CC2950CULL,
		0x5E12596F4CCBB61DULL,
		0x7E68C30CF4680D8AULL,
		0xFDBC7C17E6CC57BAULL,
		0x3B5BCB8E8ED5CAB0ULL,
		0x4DE84A7E18F26072ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2E760478D5463EULL,
		0xDFCEDA61F6A0C3BFULL,
		0x5D3A67181BA8784DULL,
		0x02EE328C4E4C34C9ULL,
		0x702FFB790C75CFABULL,
		0x818B2B42EFD5D039ULL,
		0x5E695CAA31CEFD27ULL,
		0x31A341163D12CCE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96E1A4AAE9991EE5ULL,
		0xC3B1A80157B94A97ULL,
		0x0335789D111A1CBEULL,
		0x5B2426E2FE7F8154ULL,
		0x0E38C793E7F23DDFULL,
		0x7C3150D4F6F68781ULL,
		0xDCF26EE45D06CD89ULL,
		0x1C450967DBDF938DULL
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
		0xA30AA54925A37DEAULL,
		0x32610F1D4BD8B96DULL,
		0x71E69EF98AEF27C6ULL,
		0xCC0D6D7D631D0533ULL,
		0x5CBEE61356982991ULL,
		0xCB4FA166BFA97E52ULL,
		0x30AB93614A88BAB7ULL,
		0x8171CD8A95282136ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E2CFA19DA74547DULL,
		0xC84BDE977A703792ULL,
		0x88D01F3984016FD8ULL,
		0x2BA0286725438E21ULL,
		0x02ED3A72BD51E8E0ULL,
		0x2CF449DA3E29E745ULL,
		0x30E864D8D7CBD684ULL,
		0x71F40C749DCCF63CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74DDAB2F4B2F296DULL,
		0x6A153085D16881DBULL,
		0xE9167FC006EDB7EDULL,
		0xA06D45163DD97711ULL,
		0x59D1ABA0994640B1ULL,
		0x9E5B578C817F970DULL,
		0xFFC32E8872BCE433ULL,
		0x0F7DC115F75B2AF9ULL
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
		0x046B5AC5190358B7ULL,
		0xF36CA0DB50BFF0DBULL,
		0x86DA3DCAA110AE28ULL,
		0x2CB7DFADADC36842ULL,
		0x2636608C780D7D7EULL,
		0x6919AC1C2ED0A68FULL,
		0xD00E3E3055702BEDULL,
		0xA7A4C34DF419DA46ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C54BF0166E3B62ULL,
		0xDE355F09DB7DF0D3ULL,
		0x68DDA1545FA167A7ULL,
		0x7D5F48489F63A771ULL,
		0x993692C75A76B884ULL,
		0x85B182AEE6CAF3DAULL,
		0xC4EBCB2E7D936289ULL,
		0xC301C3B522BA10E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A60ED502951D55ULL,
		0x153741D175420007ULL,
		0x1DFC9C76416F4681ULL,
		0xAF5897650E5FC0D1ULL,
		0x8CFFCDC51D96C4F9ULL,
		0xE368296D4805B2B4ULL,
		0x0B227301D7DCC963ULL,
		0xE4A2FF98D15FC95DULL
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
		0xD81F87D20B973A41ULL,
		0x632739E6F4004339ULL,
		0x9A6C7F13DB4DD33BULL,
		0x3ED61B648400495EULL,
		0xD5B3E7FBC97366C6ULL,
		0xBA00140CEC8E78B7ULL,
		0xF6B846A7FC3F321AULL,
		0x7E81671A4616FF60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCFC391E083F5E92ULL,
		0xEFEB8A2EF4595376ULL,
		0xC084B6B773575508ULL,
		0xA79FE6AC2E4B332BULL,
		0x1619BCAEDD3ED291ULL,
		0x84AA9DBFFE40BAF5ULL,
		0x027EDDDE41F85C19ULL,
		0xA9BC2A2F442EE755ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B234EB40357DBAFULL,
		0x733BAFB7FFA6EFC3ULL,
		0xD9E7C85C67F67E32ULL,
		0x973634B855B51632ULL,
		0xBF9A2B4CEC349434ULL,
		0x3555764CEE4DBDC2ULL,
		0xF43968C9BA46D601ULL,
		0xD4C53CEB01E8180BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x973EAEB1ED7D7F41ULL,
		0x9C0111511E856A35ULL,
		0x86B8D4FAA4DD89DDULL,
		0xFA7DB541703FF3ECULL,
		0xB6639FDC626D11D5ULL,
		0xAF975F0C3B071B54ULL,
		0x37429EA448688F85ULL,
		0xEE0BB4B54FCE2D5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63FE64333FD0064BULL,
		0x399ACCD81E19D3BCULL,
		0x932D5AB57EF06A66ULL,
		0xD16A4CCD59F9F1DDULL,
		0x3945BDA777C237A5ULL,
		0xD0FB1F5780EAE62CULL,
		0xBE39AC394B626B59ULL,
		0x0E8C386566216D6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33404A7EADAD78F6ULL,
		0x62664479006B9679ULL,
		0xF38B7A4525ED1F77ULL,
		0x291368741646020EULL,
		0x7D1DE234EAAADA30ULL,
		0xDE9C3FB4BA1C3528ULL,
		0x7908F26AFD06242BULL,
		0xDF7F7C4FE9ACBFEFULL
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
		0xB65C2E87A5C7507CULL,
		0x6B09A563FD907639ULL,
		0xF55E23A2FFBACF90ULL,
		0x101FE56A9FE089A7ULL,
		0xFDCA5669710F4CC1ULL,
		0x61342896E5FEFEFBULL,
		0x40D24898EC23C5E9ULL,
		0xE3D3A7DD22EDEE4FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26F1D0AE729C0C4CULL,
		0xF8DCBF170CA1DF48ULL,
		0x958E6038A5770E2EULL,
		0x4653062841BF7051ULL,
		0x1F3408C237BA61E2ULL,
		0x9BEB100A8C9906D8ULL,
		0x8A03A9EA8A962082ULL,
		0x1B3B567DE3B4C13FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F6A5DD9332B4430ULL,
		0x722CE64CF0EE96F1ULL,
		0x5FCFC36A5A43C161ULL,
		0xC9CCDF425E211956ULL,
		0xDE964DA73954EADEULL,
		0xC549188C5965F823ULL,
		0xB6CE9EAE618DA566ULL,
		0xC898515F3F392D0FULL
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
		0xF0786AA0C4427BB0ULL,
		0x7722CD80532337E2ULL,
		0xAC279E25634A90AAULL,
		0x6A5E679E09919D15ULL,
		0xBD31174BDC45F91CULL,
		0xDFA99C867A28474FULL,
		0xF995BE95C8BD54E9ULL,
		0x710B4F6E9E472E1FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B07627113103F0ULL,
		0x766A071ECB72068AULL,
		0x3B9C58D7A734C68FULL,
		0xEEB38F05D7EC30BDULL,
		0x8AB05277ABCA0F5CULL,
		0x60175E9E7BEF2CF2ULL,
		0xC634CE62BB50EE7BULL,
		0x5975ABF314351793ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BC7F479B31177C0ULL,
		0x00B8C66187B13158ULL,
		0x708B454DBC15CA1BULL,
		0x7BAAD89831A56C58ULL,
		0x3280C4D4307BE9BFULL,
		0x7F923DE7FE391A5DULL,
		0x3360F0330D6C666EULL,
		0x1795A37B8A12168CULL
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
		0x384EFF6292365633ULL,
		0xD3A4540C994B0CB2ULL,
		0xF96A4A03995433ADULL,
		0xD1C35D5D5E4DD1E7ULL,
		0x8EAEA59AA3BCC7EEULL,
		0x999CF96D8B6EB08BULL,
		0x82F10C322F02B2D5ULL,
		0x04F5973D195320FFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x499B1FF01702C6F2ULL,
		0xBDF04F9E196471BFULL,
		0xFE2956D2B4EF9C05ULL,
		0x58E1C9F387B8B43FULL,
		0x71A1DBCA96F84391ULL,
		0xDDDCEEC39ED22AD9ULL,
		0xCFF587CB426FD829ULL,
		0x3ECD89846D84E86FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEB3DF727B338F41ULL,
		0x15B4046E7FE69AF2ULL,
		0xFB40F330E46497A8ULL,
		0x78E19369D6951DA7ULL,
		0x1D0CC9D00CC4845DULL,
		0xBBC00AA9EC9C85B2ULL,
		0xB2FB8466EC92DAABULL,
		0xC6280DB8ABCE388FULL
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
		0x06F6CA92D77D067BULL,
		0x5D625972B47D1205ULL,
		0x9D0FF38AC8918896ULL,
		0x4D8CF3FEE9134C7DULL,
		0x7AFE5D069DF1C990ULL,
		0xBF9BA9965963226CULL,
		0x2D0EE28C4CA11C3EULL,
		0x6C96E128EE8DF84FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA43AD6CE70D9A12ULL,
		0x937CE039F612E24AULL,
		0x36EAD862181CE27AULL,
		0xCF3E886A777AEAF7ULL,
		0xEF720FC466AD7978ULL,
		0x2B7DF3DC5E777839ULL,
		0xD9B910E8D29DE588ULL,
		0x62915AC8F325D6C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CB31D25F06F6C69ULL,
		0xC9E57938BE6A2FBAULL,
		0x66251B28B074A61BULL,
		0x7E4E6B9471986186ULL,
		0x8B8C4D4237445017ULL,
		0x941DB5B9FAEBAA32ULL,
		0x5355D1A37A0336B6ULL,
		0x0A05865FFB682187ULL
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
		0x98A1C54A477D2E54ULL,
		0xDD1830F889EC4D77ULL,
		0x0B80103532B0125BULL,
		0x71915361C41F7CAEULL,
		0x3D4C7700C4F1CC7BULL,
		0x0CFA22D945190C99ULL,
		0x030E3035B90F466FULL,
		0x8614C0C7572B6E66ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB56C444CEEB4959EULL,
		0x33286B6BD1E11078ULL,
		0x6409DDF8669C0D45ULL,
		0xF4E56555340BA86AULL,
		0x561BF0C4E660AA4FULL,
		0x9AB1937280CD4490ULL,
		0xAF7ED049D01A3E31ULL,
		0xBE31167BA503A6FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE33580FD58C898B6ULL,
		0xA9EFC58CB80B3CFEULL,
		0xA776323CCC140516ULL,
		0x7CABEE0C9013D443ULL,
		0xE730863BDE91222BULL,
		0x72488F66C44BC808ULL,
		0x538F5FEBE8F5083DULL,
		0xC7E3AA4BB227C76AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE365D90BAAC9E07CULL,
		0xB8854A5FB6664F2BULL,
		0x329C646436957B91ULL,
		0x186F762689B0C18CULL,
		0xFD568DAEAE993BEDULL,
		0xCE1B379FF2BFFE7BULL,
		0xF32756BD2A80C209ULL,
		0x0B6F460A16341B85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0906B68A9BCC4EULL,
		0xE79C34374F3F73D2ULL,
		0x1B5247EA6030A323ULL,
		0xA66AB9D87DB48409ULL,
		0xC13C1590DE785684ULL,
		0x319D32D314C7692DULL,
		0x99CB598599947344ULL,
		0xC7B8E0F1F4C9B1A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x655CD255202E142EULL,
		0xD0E916286726DB59ULL,
		0x174A1C79D664D86DULL,
		0x7204BC4E0BFC3D83ULL,
		0x3C1A781DD020E568ULL,
		0x9C7E04CCDDF8954EULL,
		0x595BFD3790EC4EC5ULL,
		0x43B66518216A69E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBACFD862025C7F1BULL,
		0x859726E09A3EC47EULL,
		0xFE8EC138F23805F5ULL,
		0x0A066F1869F9C0C9ULL,
		0xEFF6ABD72BBE88A0ULL,
		0xB16DEE62D04C9752ULL,
		0x2A08B68568C8C5A3ULL,
		0x7B0001026D2D4DD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B8442B2BEE8528ULL,
		0x9B820BCFC995099BULL,
		0xA9E418EEE8D45A02ULL,
		0x014A5267E36B522FULL,
		0x23E42F7009292D9BULL,
		0xB70DEFF572BA9CC2ULL,
		0x75D33F23A6875DB5ULL,
		0x47F680F0618B8B7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8179436D66DF9F3ULL,
		0xEA151B10D0A9BAE3ULL,
		0x54AAA84A0963ABF2ULL,
		0x08BC1CB0868E6E9AULL,
		0xCC127C6722955B05ULL,
		0xFA5FFE6D5D91FA90ULL,
		0xB4357761C24167EDULL,
		0x330980120BA1C256ULL
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
		0x3C99894C7324799BULL,
		0x5F97FFAC0F2C4958ULL,
		0xF7E9027C28CCB93EULL,
		0xDA1C69FF8800DA29ULL,
		0xC459FEFAD51F3CD9ULL,
		0x04004BCC73440D49ULL,
		0x70DB5B3568124865ULL,
		0xAEAD06A410E4074EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F285FA6CD6A7BF5ULL,
		0x9EF5EA3154731A45ULL,
		0xE9E93DB42448C052ULL,
		0x31B95596125A1C4AULL,
		0x22098DA9070EDA49ULL,
		0x5AD46ED9F7EA90ECULL,
		0x7AE0C46DF13AA080ULL,
		0x2813744844EB1B0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD7129A5A5B9FDA6ULL,
		0xC0A2157ABAB92F12ULL,
		0x0DFFC4C80483F8EBULL,
		0xA863146975A6BDDFULL,
		0xA2507151CE106290ULL,
		0xA92BDCF27B597C5DULL,
		0xF5FA96C776D7A7E4ULL,
		0x8699925BCBF8EC42ULL
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
		0xAFCEE521018CF98DULL,
		0x59EC3BB1C84C1F95ULL,
		0x733D263BE6FE82C4ULL,
		0xEAD38DE3836C0FE2ULL,
		0xE5D7581DCFAB07FCULL,
		0x3D3149DED4079096ULL,
		0xB7246F512F14D0D8ULL,
		0x1BCFD1BC2AECC626ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA444E5786D84F30DULL,
		0x61C81F7265A50328ULL,
		0x4E09763529B1DF6DULL,
		0xD3489B2E59801138ULL,
		0xC1FE74BDFF030FE9ULL,
		0xFBCB585CC99C3D8AULL,
		0xFA8A7FB23E47A7EEULL,
		0xF0DBAD231EF6A494ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B89FFA894080680ULL,
		0xF8241C3F62A71C6DULL,
		0x2533B006BD4CA356ULL,
		0x178AF2B529EBFEAAULL,
		0x23D8E35FD0A7F813ULL,
		0x4165F1820A6B530CULL,
		0xBC99EF9EF0CD28E9ULL,
		0x2AF424990BF62191ULL
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
		0x13610BF13C0B447FULL,
		0xF4CF7504C7F36D04ULL,
		0xC2AA2F0B4A4E86F2ULL,
		0xA806AD1165318B7CULL,
		0x01D6B46C7411CD91ULL,
		0x110FE84F88797284ULL,
		0x65D774E79BF2B6E0ULL,
		0x238305B056A97EADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x226D45F57BEBD270ULL,
		0xE9B94C29134565D2ULL,
		0x7B68104B10261340ULL,
		0x965FD47E9C8E3A08ULL,
		0x97748738EAE35035ULL,
		0xAD9BEA6914CDBBF8ULL,
		0x2ED0AF215C9A5F64ULL,
		0xE17EAA747953910DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0F3C5FBC01F720FULL,
		0x0B1628DBB4AE0731ULL,
		0x47421EC03A2873B2ULL,
		0x11A6D892C8A35174ULL,
		0x6A622D33892E7D5CULL,
		0x6373FDE673ABB68BULL,
		0x3706C5C63F58577BULL,
		0x42045B3BDD55EDA0ULL
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
		0xAF6FBAC870DFAD96ULL,
		0x4799DFC78E587416ULL,
		0x8DAC3C91FCEDB02CULL,
		0x7616303D9DB9AE2CULL,
		0x05264C78849EECC8ULL,
		0x009C7D73B457619DULL,
		0xC072213A57023127ULL,
		0x449130F96EAB1B94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1400F5C28D49AAE7ULL,
		0xAA64FBD7C31B9018ULL,
		0xC6D83EBCB930E6E5ULL,
		0x8B767B3884717FB5ULL,
		0x67A2FDC5B543A28BULL,
		0xBD3A835212BA061EULL,
		0x68A51ADC3386F4A2ULL,
		0xC4204D17CC7476A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B6EC505E39602AFULL,
		0x9D34E3EFCB3CE3FEULL,
		0xC6D3FDD543BCC946ULL,
		0xEA9FB50519482E76ULL,
		0x9D834EB2CF5B4A3CULL,
		0x4361FA21A19D5B7EULL,
		0x57CD065E237B3C84ULL,
		0x8070E3E1A236A4EEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0CDF08C4EC1A80F6ULL,
		0x89D6E5D3D4B67997ULL,
		0x90635C9EB35A0526ULL,
		0xD7C77CA42CFC6956ULL,
		0x91D06D6E69053663ULL,
		0x8FD5EDB5ABC2268FULL,
		0x609A9048BD7CBFCEULL,
		0x7D1B26BA7F938195ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C1178EE9E0C0A6DULL,
		0xE5C5C2975F924F30ULL,
		0xC776661D05B59DACULL,
		0x905914B26F814CE9ULL,
		0x9261166C62A3C314ULL,
		0x291E8E11C91C6268ULL,
		0xC930EB898B705385ULL,
		0xB27D6D017D490CCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0CD8FD64E0E7689ULL,
		0xA411233C75242A66ULL,
		0xC8ECF681ADA46779ULL,
		0x476E67F1BD7B1C6CULL,
		0xFF6F57020661734FULL,
		0x66B75FA3E2A5C426ULL,
		0x9769A4BF320C6C49ULL,
		0xCA9DB9B9024A74CAULL
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
		0x912E3C82CBFE4CA5ULL,
		0xD9F8F74EA877BFB6ULL,
		0x4458A1E4560BA28BULL,
		0x1BBA03D614B6B0B0ULL,
		0x211FF74F7CAB35D7ULL,
		0x2CB28A3861FE3088ULL,
		0x7F4229CEE86F2FFBULL,
		0x560AB5D81A180694ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DAA19C68E166D1AULL,
		0x365533B84C7CB33BULL,
		0x2291E8E590A7B8A1ULL,
		0x47EA7619BE384725ULL,
		0xFB453983C5092711ULL,
		0x96BB0CC668F3A92BULL,
		0x7A0A6F0C0E6BBEB3ULL,
		0x135945BA7F5B2DD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x238422BC3DE7DF8BULL,
		0xA3A3C3965BFB0C7BULL,
		0x21C6B8FEC563E9EAULL,
		0xD3CF8DBC567E698BULL,
		0x25DABDCBB7A20EC5ULL,
		0x95F77D71F90A875CULL,
		0x0537BAC2DA037147ULL,
		0x42B1701D9ABCD8BCULL
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
		0x9684A8E16DE6D0C4ULL,
		0x423F24FA4CC4EC93ULL,
		0x976AE9284C9579E7ULL,
		0x559EBA1B2E1236B2ULL,
		0xC17E39EDC2E09DD6ULL,
		0x116803052571ABFAULL,
		0x7C2E76015A1CB01EULL,
		0xAEAE00782C744DB9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x273C0363553B0858ULL,
		0x05FF9B6D61C4E575ULL,
		0x2FAC448CDAEAA956ULL,
		0x4869E988683AFEE8ULL,
		0xF3431853D23499D6ULL,
		0x7A3152D732422EC4ULL,
		0x0A75E16EC831F66EULL,
		0x8D526DCD434B2D81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F48A57E18ABC86CULL,
		0x3C3F898CEB00071EULL,
		0x67BEA49B71AAD091ULL,
		0x0D34D092C5D737CAULL,
		0xCE3B2199F0AC0400ULL,
		0x9736B02DF32F7D35ULL,
		0x71B8949291EAB9AFULL,
		0x215B92AAE9292038ULL
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
		0xCCD54300145198EFULL,
		0x095058223C794351ULL,
		0x4A853B7FD79B4E66ULL,
		0x476415FC8816CF18ULL,
		0xCB327E55061B6D68ULL,
		0x0FDAC3A15BDC3F76ULL,
		0x9A084769B9498D1CULL,
		0x5A1CC37303D166A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64E4B1E7D626FAD6ULL,
		0x0DAC09DA98B08BEBULL,
		0x8BE796F7DFD6F5CEULL,
		0x1048F11A85910614ULL,
		0x90A9FEFBFB0DA78FULL,
		0xD6D8AEB7357B291AULL,
		0xC4DD6BCF6887FCEFULL,
		0x748DD861993B33A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67F091183E2A9E19ULL,
		0xFBA44E47A3C8B766ULL,
		0xBE9DA487F7C45897ULL,
		0x371B24E20285C903ULL,
		0x3A887F590B0DC5D9ULL,
		0x390214EA2661165CULL,
		0xD52ADB9A50C1902CULL,
		0xE58EEB116A963300ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA6D4794F9DBCB2DDULL,
		0x3DB4155901ADB927ULL,
		0x61B1A78ED38ED79AULL,
		0x0E1CA66E85463840ULL,
		0x7B1A605038DE9BFAULL,
		0x4A66DE6CB10383CEULL,
		0x96915CAA69FD928FULL,
		0x8DB2B7F963A8700EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE346E541AAF4BB69ULL,
		0x526E03099841E494ULL,
		0xE81CD3BC192FAB62ULL,
		0x8BAAC430A00648F7ULL,
		0x59EF00B618E35611ULL,
		0xD77074BFA9F5D452ULL,
		0x8C0D33D0F159C7F1ULL,
		0x8455801A32A33C24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC38D940DF2C7F774ULL,
		0xEB46124F696BD492ULL,
		0x7994D3D2BA5F2C37ULL,
		0x8271E23DE53FEF48ULL,
		0x212B5F9A1FFB45E8ULL,
		0x72F669AD070DAF7CULL,
		0x0A8428D978A3CA9DULL,
		0x095D37DF310533EAULL
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
		0x1F8DF1CDB847A601ULL,
		0xF025E4184B6D74CCULL,
		0xA9E6C979978D8045ULL,
		0x60E30283FC7E67AFULL,
		0xC6E9936446FE833AULL,
		0x479EB800DF9A5D0CULL,
		0x2AF64340F25F5136ULL,
		0xE613CE6A7BE5DAB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E461CD591D83FAULL,
		0x64428FAC4E1F50D7ULL,
		0x5FE74EAA398F5033ULL,
		0x20B206D206FD68F1ULL,
		0x0D07F17E10F95E6FULL,
		0x0B7D7B4A65B72729ULL,
		0x9CF93A553DAD8457ULL,
		0xD2037FFEF44AA04FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBA990005F2A2207ULL,
		0x8BE3546BFD4E23F4ULL,
		0x49FF7ACF5DFE3012ULL,
		0x4030FBB1F580FEBEULL,
		0xB9E1A1E6360524CBULL,
		0x3C213CB679E335E3ULL,
		0x8DFD08EBB4B1CCDFULL,
		0x14104E6B879B3A61ULL
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
		0x6C43A3061BAFAAF7ULL,
		0xB2D1C1BBC64F36FAULL,
		0x38FE44E257E4F4D2ULL,
		0xF0F7152F9FFB2790ULL,
		0xE26ECCED6170A82AULL,
		0xA07BD70EBE097612ULL,
		0x68D16B5F68E4AF02ULL,
		0xCA7AA32BADAE078CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA521CB9FF0BB70ULL,
		0xD0EF377A654C1490ULL,
		0xE9DB6E4E16836CEFULL,
		0x8865647DC6342BA2ULL,
		0x6D04D46BACD4C8B4ULL,
		0x2FC367E1884547B2ULL,
		0xCDB58AA6E4F480D4ULL,
		0x4AB994AA0C143FC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA19E813A7BBEEF87ULL,
		0xE1E28A4161032269ULL,
		0x4F22D694416187E2ULL,
		0x6891B0B1D9C6FBEDULL,
		0x7569F881B49BDF76ULL,
		0x70B86F2D35C42E60ULL,
		0x9B1BE0B883F02E2EULL,
		0x7FC10E81A199C7C7ULL
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
		0x374AE759A5C30AD5ULL,
		0x6A0E50DD5148C5A7ULL,
		0xCB35EE6BC5578924ULL,
		0x8797DA3365F349BFULL,
		0xE9E563E28FDA1AADULL,
		0xFE25D911B482EA36ULL,
		0x5B28741AC2D2B207ULL,
		0x3500EF17D403EB60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF67A063E7D4A87ULL,
		0x8C32E617499851BBULL,
		0xF9C81CDEFD707B1CULL,
		0x4FC05A160B339C0CULL,
		0x47AF8968F47177B7ULL,
		0x60D8C885432A825AULL,
		0x1F97B4548DFAD079ULL,
		0xF4F7057B7DE43174ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58546D536745C04EULL,
		0xDDDB6AC607B073EBULL,
		0xD16DD18CC7E70E07ULL,
		0x37D7801D5ABFADB2ULL,
		0xA235DA799B68A2F6ULL,
		0x9D4D108C715867DCULL,
		0x3B90BFC634D7E18EULL,
		0x4009E99C561FB9ECULL
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
		0x6731ECC913FB0714ULL,
		0xC5EA014D13EADCF2ULL,
		0xC644CA62B77842E1ULL,
		0x00E24212AEBAD315ULL,
		0x6AA11CF7BFA73B60ULL,
		0x62A04ED539CA33F7ULL,
		0x96D7AE7048466102ULL,
		0x6B9807891B8FEB94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ADF774B6FF7BD22ULL,
		0x603E332FA213CA07ULL,
		0x6B6C0D59DFAA277CULL,
		0xD757F4D5B06C4E89ULL,
		0x7F4675B80A2D67CEULL,
		0x0C1D272D271C6289ULL,
		0xAA8057CD3118DB0BULL,
		0xED4D96CFED7760A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC52757DA40349F2ULL,
		0x65ABCE1D71D712EAULL,
		0x5AD8BD08D7CE1B65ULL,
		0x298A4D3CFE4E848CULL,
		0xEB5AA73FB579D391ULL,
		0x568327A812ADD16DULL,
		0xEC5756A3172D85F7ULL,
		0x7E4A70B92E188AEBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1AAE17DC8C0CFA84ULL,
		0x4A813664A480B595ULL,
		0x76CE5F8E1A1008E0ULL,
		0xB74CA55E06A3D303ULL,
		0xE1B43F6D79A3B4DDULL,
		0xFAE56E4DDCD73F31ULL,
		0xB4E587F6540A54CCULL,
		0x51086AC25C09B4C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E25943811776B88ULL,
		0x7A385BA48E8F7054ULL,
		0x8E326D70DD86AE5BULL,
		0x0F748F3E27CD186CULL,
		0x86826DADFA6FCC3FULL,
		0x0F9CF916BD018D2DULL,
		0x660D0BD9680217B2ULL,
		0x0F03FC35312DA086ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC8883A47A958EFCULL,
		0xD048DAC015F14540ULL,
		0xE89BF21D3C895A84ULL,
		0xA7D8161FDED6BA96ULL,
		0x5B31D1BF7F33E89EULL,
		0xEB4875371FD5B204ULL,
		0x4ED87C1CEC083D1AULL,
		0x42046E8D2ADC143EULL
	}};
	sign = 0;
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
		0x88A8C59B886F86ADULL,
		0x89264DDACD4B84C0ULL,
		0x5651DFB18007772CULL,
		0xAB8F2A34A381A082ULL,
		0xA9717E05CAA937D9ULL,
		0xB275FCAD3193AFCCULL,
		0x3F245FCEF3E4831EULL,
		0x842043D0F0AC9E62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7459037A278B6CF1ULL,
		0x30B0B58F34F7F1FBULL,
		0xC634B7395FD5B147ULL,
		0xB422F8F3F5513F7AULL,
		0x211DA756B593237BULL,
		0x0533A1CA576B1A9EULL,
		0xCCA559B1E73D8190ULL,
		0x53FADF29F915BB0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x144FC22160E419BCULL,
		0x5875984B985392C5ULL,
		0x901D28782031C5E5ULL,
		0xF76C3140AE306107ULL,
		0x8853D6AF1516145DULL,
		0xAD425AE2DA28952EULL,
		0x727F061D0CA7018EULL,
		0x302564A6F796E354ULL
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
		0xA4E87EA755EFACC8ULL,
		0x05B1D4883815C3B6ULL,
		0x3875A9F9974940CDULL,
		0x51B3EDC2EB969FF4ULL,
		0x0A2BB12401B6E197ULL,
		0xF5B0B5312A627BE2ULL,
		0x39B099E57D1A6302ULL,
		0x6D7A637CC27512B3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D8835F8C9E8337ULL,
		0x91E24475E5D18274ULL,
		0x09DB82E7E1591FE2ULL,
		0xBB4398C6B8BD4CB3ULL,
		0xACAD098E5948473CULL,
		0xE3637FB35ECB2E50ULL,
		0x482DA19BD224D22AULL,
		0x77DB63F9FE982283ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE20FFB47C9512991ULL,
		0x73CF901252444141ULL,
		0x2E9A2711B5F020EAULL,
		0x967054FC32D95341ULL,
		0x5D7EA795A86E9A5AULL,
		0x124D357DCB974D91ULL,
		0xF182F849AAF590D8ULL,
		0xF59EFF82C3DCF02FULL
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
		0x67613733B524582DULL,
		0x1CF3151B14A2FFD4ULL,
		0x9F78521DFF7CD71DULL,
		0x25A70866D7A62C23ULL,
		0x177156F7B9440614ULL,
		0xE34EFE4863A04B5BULL,
		0x01E44B5D0EDBC6E2ULL,
		0xF88B8C8669C70BA0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000B6CE10DEE4FBULL,
		0x21B55A22017D4CA7ULL,
		0xB73555405A097B9CULL,
		0x820324FA69814A1EULL,
		0xE0815F08FD98BB95ULL,
		0xAB7A18D0B8B9BCAAULL,
		0xE089D2B027EA0B77ULL,
		0x4281E045F90F67F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57608065A4457332ULL,
		0xFB3DBAF91325B32DULL,
		0xE842FCDDA5735B80ULL,
		0xA3A3E36C6E24E204ULL,
		0x36EFF7EEBBAB4A7EULL,
		0x37D4E577AAE68EB0ULL,
		0x215A78ACE6F1BB6BULL,
		0xB609AC4070B7A3A8ULL
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
		0xBA25F49DD49FAC4EULL,
		0xC90679E5A3A71807ULL,
		0xFDEAB2A76B9CA945ULL,
		0xF20614C841B84857ULL,
		0xBC7240AAA503C1BCULL,
		0x0AA29A05F66D6EAFULL,
		0x66D91E72B5811414ULL,
		0x9D5C93C2769BF6C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB710BE2AE27DE8BULL,
		0x1BA72C7FC2650E93ULL,
		0xBD03FE3AEB0ED849ULL,
		0x72001863D055A20AULL,
		0xCC712810AF2BEF06ULL,
		0x85197B9AD06B017BULL,
		0x7AC2A15E7E9FADFEULL,
		0x613B6ED34D571C25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEB4E8BB2677CDC3ULL,
		0xAD5F4D65E1420973ULL,
		0x40E6B46C808DD0FCULL,
		0x8005FC647162A64DULL,
		0xF0011899F5D7D2B6ULL,
		0x85891E6B26026D33ULL,
		0xEC167D1436E16615ULL,
		0x3C2124EF2944DA9EULL
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
		0x0D917FA26921B750ULL,
		0x39A0199A4141E4BCULL,
		0x7D260F4765A94BB7ULL,
		0xB9A8375FDB44F167ULL,
		0xE40FDACE9BC6BD78ULL,
		0xC8879CE3876E6857ULL,
		0xB127DCDF10FFBF9FULL,
		0xC048392E14033B9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA8885FA6B444260ULL,
		0xA7370CA88262004DULL,
		0xEC3B9848D4F8D641ULL,
		0xD8C1D7DED81054DAULL,
		0x5425AA29204CBF63ULL,
		0x770B7CE1115280EEULL,
		0x73C120EF9BD0C1B4ULL,
		0x34C3ED1E662AB658ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3308F9A7FDDD74F0ULL,
		0x92690CF1BEDFE46EULL,
		0x90EA76FE90B07575ULL,
		0xE0E65F8103349C8CULL,
		0x8FEA30A57B79FE14ULL,
		0x517C2002761BE769ULL,
		0x3D66BBEF752EFDEBULL,
		0x8B844C0FADD88546ULL
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
		0xEE51F5E6DCFAA78DULL,
		0xAADC348693E563E8ULL,
		0xF5E04D4A04393DC9ULL,
		0xB85D57C9C1CA041FULL,
		0x1A46A71C45016C7EULL,
		0xB17187DF4819BCB7ULL,
		0xD46D7198069DA313ULL,
		0x02881598B3EA5341ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F8010901F3500CULL,
		0x87A0BFF111F1DD77ULL,
		0xFA398859B2CF5645ULL,
		0x80DAD1EFCAB9BF7BULL,
		0x2DF205228FDC7FCAULL,
		0x5C33B670197CD339ULL,
		0xD63322B921E3A150ULL,
		0x4756EB0FF418EE6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B59F4DDDB075781ULL,
		0x233B749581F38671ULL,
		0xFBA6C4F05169E784ULL,
		0x378285D9F71044A3ULL,
		0xEC54A1F9B524ECB4ULL,
		0x553DD16F2E9CE97DULL,
		0xFE3A4EDEE4BA01C3ULL,
		0xBB312A88BFD164D5ULL
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
		0x47476C8167908CF6ULL,
		0xF112D163ADA3D47BULL,
		0x9D8557F34123F358ULL,
		0x3C5D0C363E7BFBA6ULL,
		0x40B1D18CBC2D122AULL,
		0x9DE5F22B9B358B76ULL,
		0xD3AB40FFC5D34E5EULL,
		0xF387785886E80A21ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC32AFCC5531D3BULL,
		0xA961B1B9241BC4AAULL,
		0x4AB8EFCC078C3E28ULL,
		0xF09E3A967FACF4AAULL,
		0xF603BB14E0DE4B36ULL,
		0x9CC2DD5A2917D426ULL,
		0x7960DF3BA1A3B460ULL,
		0x7364A9142A9A6A30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A844184A23D6FBBULL,
		0x47B11FAA89880FD0ULL,
		0x52CC68273997B530ULL,
		0x4BBED19FBECF06FCULL,
		0x4AAE1677DB4EC6F3ULL,
		0x012314D1721DB74FULL,
		0x5A4A61C4242F99FEULL,
		0x8022CF445C4D9FF1ULL
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
		0x09ED13D601929903ULL,
		0x9000DF3F377864E2ULL,
		0x4A8FF29D41D108DEULL,
		0x0C893112F80AAE26ULL,
		0x00F303A16946C295ULL,
		0xFAEA077FCB83A8E0ULL,
		0x00509A68E0A808FBULL,
		0x936643C0F8AD43D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76CC8A7BA19441CULL,
		0x9914312606173FCFULL,
		0x004B39CC5C399BBBULL,
		0xE1C073C84717AFEEULL,
		0xA209A661DE63CF60ULL,
		0xD758A38E9989D1D6ULL,
		0x4774CADA93878CF0ULL,
		0xB69D867441E3B71FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52804B2E477954E7ULL,
		0xF6ECAE1931612512ULL,
		0x4A44B8D0E5976D22ULL,
		0x2AC8BD4AB0F2FE38ULL,
		0x5EE95D3F8AE2F334ULL,
		0x239163F131F9D709ULL,
		0xB8DBCF8E4D207C0BULL,
		0xDCC8BD4CB6C98CB1ULL
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
		0x19FF537674C8889DULL,
		0xCDF32462CDF0A701ULL,
		0x1180AF86987A728BULL,
		0x3A83DFB9829980BFULL,
		0x20BA629A8E591909ULL,
		0x0ABE02BDCE009E20ULL,
		0xD6E2226729D93B9BULL,
		0x546A2C8753FFFD77ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57954B05DF32CBCULL,
		0x7800C9121F9CB095ULL,
		0x3EF8F5D67D70DFC8ULL,
		0xF052F1DE57570F04ULL,
		0x09AB33FB7BC6D4B8ULL,
		0x242053D537850514ULL,
		0xEE5B8FEB06C2B74FULL,
		0x338763D8760E9F46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2485FEC616D55BE1ULL,
		0x55F25B50AE53F66BULL,
		0xD287B9B01B0992C3ULL,
		0x4A30EDDB2B4271BAULL,
		0x170F2E9F12924450ULL,
		0xE69DAEE8967B990CULL,
		0xE886927C2316844BULL,
		0x20E2C8AEDDF15E30ULL
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
		0xF4571096BEF20184ULL,
		0x5139D877F207AEE0ULL,
		0xC6A06C40764F747DULL,
		0x8B13592BE1F35FE9ULL,
		0x72D0FD6F0D97F8B9ULL,
		0xB26D483F4D029408ULL,
		0x0B71EA3BFE06F190ULL,
		0x8940C6FC9D19FA12ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02721B90A96DB846ULL,
		0x905A796B4FA9AB1DULL,
		0x1703404CF945C415ULL,
		0x1A5E20515E46417DULL,
		0x9E2099409D8B3FE2ULL,
		0x1EB51A1FCDDBC02CULL,
		0x48C673CD22B8E778ULL,
		0x9D974A9FE148EBA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1E4F5061584493EULL,
		0xC0DF5F0CA25E03C3ULL,
		0xAF9D2BF37D09B067ULL,
		0x70B538DA83AD1E6CULL,
		0xD4B0642E700CB8D7ULL,
		0x93B82E1F7F26D3DBULL,
		0xC2AB766EDB4E0A18ULL,
		0xEBA97C5CBBD10E6FULL
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
		0x5B695604A0EB0FDDULL,
		0xB6D8BFB63ABFAF70ULL,
		0x1DF8291D223E897BULL,
		0xF8420D6C4F13E932ULL,
		0x09E88EDDB2E7051EULL,
		0x45BFB57F2F6C7439ULL,
		0xEBFD8407C966B504ULL,
		0x57A8073323F9551CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8F792030D73CDF5ULL,
		0x9605BE0E2D0B4606ULL,
		0x70B33DA889097785ULL,
		0x7D63A0A5B1FE4875ULL,
		0xE24DA7372AA1B11FULL,
		0xF0A40A1502F401D4ULL,
		0x5D2326A05082C4EAULL,
		0xC0FC75A0ABF8348FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA271C401937741E8ULL,
		0x20D301A80DB46969ULL,
		0xAD44EB74993511F6ULL,
		0x7ADE6CC69D15A0BCULL,
		0x279AE7A6884553FFULL,
		0x551BAB6A2C787264ULL,
		0x8EDA5D6778E3F019ULL,
		0x96AB91927801208DULL
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
		0x0CDF801CA7316B3DULL,
		0x72E05FE4199D13E5ULL,
		0x6CB0061C72667576ULL,
		0x37E63584103AAD84ULL,
		0x97C05E0DC557233BULL,
		0xD8D6CE212CE00BF0ULL,
		0x9B9522A78E744C5EULL,
		0x579386DA12AD8696ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30BCF0A968D82949ULL,
		0x496CCF0B1A5D7D98ULL,
		0x003BA689B46411F1ULL,
		0x43E3FCB0D4C0CFA2ULL,
		0x40F98A3390ED3A6DULL,
		0x554EF52FED28ACCBULL,
		0x54419BF86F7F05B3ULL,
		0xE815C307AA2DDFC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC228F733E5941F4ULL,
		0x297390D8FF3F964CULL,
		0x6C745F92BE026385ULL,
		0xF40238D33B79DDE2ULL,
		0x56C6D3DA3469E8CDULL,
		0x8387D8F13FB75F25ULL,
		0x475386AF1EF546ABULL,
		0x6F7DC3D2687FA6CEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x38FB9E6E71640C10ULL,
		0x218B7B6EE4DA1091ULL,
		0x99AEFFC041CC8072ULL,
		0x0A551C3F0B3150FDULL,
		0xB0F9C930BE361877ULL,
		0xFB61B9579F03CCF3ULL,
		0x60FD89AE14B7DCD0ULL,
		0xE6FB0937E166B0D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0A2A577D0ACE9BULL,
		0x03948D558D7F06DEULL,
		0xAA5DE05270CDE4EBULL,
		0xF121C949770BA889ULL,
		0x0D7DDA0AE3817972ULL,
		0xDE863EF24FD2B7C6ULL,
		0x9E9174A8C58E5708ULL,
		0x751FA60026A76A66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBF17416F4593D75ULL,
		0x1DF6EE19575B09B2ULL,
		0xEF511F6DD0FE9B87ULL,
		0x193352F59425A873ULL,
		0xA37BEF25DAB49F04ULL,
		0x1CDB7A654F31152DULL,
		0xC26C15054F2985C8ULL,
		0x71DB6337BABF466FULL
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
		0x73941DE29D8184F3ULL,
		0x4C9FCBE8A9310CC7ULL,
		0x0F6F3370E2C24B2EULL,
		0xEB11913BAE99294CULL,
		0x4CD0B167245855E5ULL,
		0xB63007035894ED8DULL,
		0xD6CEBE36C566B4CCULL,
		0xC4C6BD0B1CD36047ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD98245145AAD7643ULL,
		0x60A7ECF3D5CDA499ULL,
		0x28B97A036D49BDEFULL,
		0x4DF5E259DE6FA6CEULL,
		0x9FF67AFB7CDAF89FULL,
		0x64A14718C93A4FC5ULL,
		0x59E0C5697D8FB1B9ULL,
		0x9DCC86910A9EB7C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A11D8CE42D40EB0ULL,
		0xEBF7DEF4D363682DULL,
		0xE6B5B96D75788D3EULL,
		0x9D1BAEE1D029827DULL,
		0xACDA366BA77D5D46ULL,
		0x518EBFEA8F5A9DC7ULL,
		0x7CEDF8CD47D70313ULL,
		0x26FA367A1234A880ULL
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
		0xB2B38C7802DA1E54ULL,
		0x64B73E9EF9A7E4EDULL,
		0x9C01968EAC2AD7F3ULL,
		0x8820BAF6AE86423AULL,
		0x1F0C94795446BA40ULL,
		0xAAB94679CD79591FULL,
		0xF3F4CAF219999952ULL,
		0x6E2DEB5240B998ACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1456EE2495E74D92ULL,
		0xB2112804FB529185ULL,
		0x5219FFDDF4B03C99ULL,
		0x405001EA6B8B8C1CULL,
		0x6C30A8D2266AD4ABULL,
		0x5BF610958C5BB0D4ULL,
		0x12DCD46E4ECDE4EEULL,
		0x8B0C0D4C7B07DFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E5C9E536CF2D0C2ULL,
		0xB2A61699FE555368ULL,
		0x49E796B0B77A9B59ULL,
		0x47D0B90C42FAB61EULL,
		0xB2DBEBA72DDBE595ULL,
		0x4EC335E4411DA84AULL,
		0xE117F683CACBB464ULL,
		0xE321DE05C5B1B905ULL
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
		0x1B705413F3044715ULL,
		0x8806D9CF4329DD47ULL,
		0xE9DD4B2DA455713CULL,
		0x619F00D345553CB4ULL,
		0xCC5EC865B37186ACULL,
		0xCD375405050229D3ULL,
		0xB40D6E042E034208ULL,
		0xD73E026561FF351BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC840206CBD24E11DULL,
		0x9869058F5FF66C6EULL,
		0x7337E741B0B175ECULL,
		0x613A4828FAB539B6ULL,
		0xEF7DE9C6F0AD74B1ULL,
		0xF1C8C0668BD154B6ULL,
		0x0F26D1C65C83E6C4ULL,
		0x35BE019F5F079DCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x533033A735DF65F8ULL,
		0xEF9DD43FE33370D8ULL,
		0x76A563EBF3A3FB4FULL,
		0x0064B8AA4AA002FEULL,
		0xDCE0DE9EC2C411FBULL,
		0xDB6E939E7930D51CULL,
		0xA4E69C3DD17F5B43ULL,
		0xA18000C602F7974CULL
	}};
	sign = 0;
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
		0xAECAFF5666497CDEULL,
		0x4170FB03A468B7C3ULL,
		0xD04682A73FB1513AULL,
		0xA7AAA4CDA0858B63ULL,
		0xE43E71C2B9C789C5ULL,
		0x5AE7E9D1ADE31796ULL,
		0x63BD44CE99D79EC2ULL,
		0x38D1CDFE5118B2E0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB337116A0E069EE3ULL,
		0xE7E79ED5DF0F3689ULL,
		0x5D3FC250E3ABE435ULL,
		0x36E94ADA3756D8C3ULL,
		0xB2FA5C591287A920ULL,
		0x06B181FC95DF01B4ULL,
		0x44FFC01C89074CA8ULL,
		0xE305E4D26CC79721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB93EDEC5842DDFBULL,
		0x59895C2DC5598139ULL,
		0x7306C0565C056D04ULL,
		0x70C159F3692EB2A0ULL,
		0x31441569A73FE0A5ULL,
		0x543667D5180415E2ULL,
		0x1EBD84B210D0521AULL,
		0x55CBE92BE4511BBFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x68B9BD7096432E71ULL,
		0xE8D4FABB12F5BA43ULL,
		0xE4B46792EAB44225ULL,
		0x4A7C3EFE50CC0E09ULL,
		0xC2857256D07A03B5ULL,
		0x98FB17DA66E59B15ULL,
		0xF21AA06B3DA71656ULL,
		0xAD6B5572690733F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB62A4BD8D3C647ULL,
		0x4617503A69803D62ULL,
		0xC81FDA972D8B9665ULL,
		0x447ACEDDEF335C9FULL,
		0x44B02AA474295F28ULL,
		0xA74ECF2D69A966A0ULL,
		0x3DD4856705AD0A6DULL,
		0xDF2BF4E66B3B5B85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA039324BD6F682AULL,
		0xA2BDAA80A9757CE0ULL,
		0x1C948CFBBD28ABC0ULL,
		0x060170206198B16AULL,
		0x7DD547B25C50A48DULL,
		0xF1AC48ACFD3C3475ULL,
		0xB4461B0437FA0BE8ULL,
		0xCE3F608BFDCBD86DULL
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
		0xF229D37AE8E1DE2EULL,
		0xE4868352A2FEE5F9ULL,
		0x18C7067A1819EE6CULL,
		0x7AEE61FFC66C070EULL,
		0x8E783B7AAE06EE8CULL,
		0x5A6DCB5ABDA08D80ULL,
		0x64ECE949728320ABULL,
		0xD6B6A22479F880EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97D2E31C5809510ULL,
		0x1444FD155C7DF20AULL,
		0x1CDC9DAD8956D28DULL,
		0x6BAD2B5011C99C24ULL,
		0xEE204418D1E1D17FULL,
		0x2B96909D25BC705DULL,
		0xCBEAD0519BC0785AULL,
		0x9173D89AB0E8D306ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08ACA5492361491EULL,
		0xD041863D4680F3EFULL,
		0xFBEA68CC8EC31BDFULL,
		0x0F4136AFB4A26AE9ULL,
		0xA057F761DC251D0DULL,
		0x2ED73ABD97E41D22ULL,
		0x990218F7D6C2A851ULL,
		0x4542C989C90FADE6ULL
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
		0x4497105D8FCAFBCBULL,
		0x02DEC5AAA451BA03ULL,
		0x6FC62A10774D97FDULL,
		0xE372788F687337A1ULL,
		0x6C1F7409CA6CEC76ULL,
		0xBBC97351331AA61DULL,
		0x2E01F2DC0DB37BCFULL,
		0x9B5500F325E8F906ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9171D83CAB59CA4ULL,
		0x7317DA8372098A4BULL,
		0xED4A172B8F9607EBULL,
		0x8152F3BC8FB63BF6ULL,
		0x2AC5D36773E94853ULL,
		0x7E38582FD1B8F03EULL,
		0x8B2B32D5FF393A11ULL,
		0xD418506D212DD13DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B7FF2D9C5155F27ULL,
		0x8FC6EB2732482FB7ULL,
		0x827C12E4E7B79011ULL,
		0x621F84D2D8BCFBAAULL,
		0x4159A0A25683A423ULL,
		0x3D911B216161B5DFULL,
		0xA2D6C0060E7A41BEULL,
		0xC73CB08604BB27C8ULL
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
		0x50806D45BABEEB95ULL,
		0xFB3F6285EA9240BBULL,
		0xFA4F45C67B0CA4D7ULL,
		0x3ADCDFE63D52E1A6ULL,
		0xBEAFFBE3F3D7BF96ULL,
		0x54B9A0320BCE8D86ULL,
		0xCC3E5A0325A43A76ULL,
		0x0757145962120220ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A180EA549182204ULL,
		0xFC4C88B41488CFA3ULL,
		0xF52D4F20A6A9F02CULL,
		0x37C9727B60BD79A2ULL,
		0x161D25A62CE21E0BULL,
		0x6D5B0694BD1AAF0CULL,
		0x48DE226274264B8BULL,
		0xF26CC649DDC65DD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6685EA071A6C991ULL,
		0xFEF2D9D1D6097117ULL,
		0x0521F6A5D462B4AAULL,
		0x03136D6ADC956804ULL,
		0xA892D63DC6F5A18BULL,
		0xE75E999D4EB3DE7AULL,
		0x836037A0B17DEEEAULL,
		0x14EA4E0F844BA450ULL
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
		0x435C383721130FA8ULL,
		0x5843F6289CB49789ULL,
		0x974BBE51C84D8386ULL,
		0xD1486CD5DF6C1BAAULL,
		0x188E5E80577E3C43ULL,
		0x3604D9415259571DULL,
		0x552618DABE91D49FULL,
		0x7612E10223002F99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C67CBE5C62E4831ULL,
		0xC684C8E2708D4C29ULL,
		0xEF7BE8EAD5056118ULL,
		0x8296D13B7A8C2E2DULL,
		0xB827DDEEFCE11536ULL,
		0xB32D93191FB4A4D7ULL,
		0xEF8BA1C18AD1FDF8ULL,
		0x1023B23387BD029CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36F46C515AE4C777ULL,
		0x91BF2D462C274B60ULL,
		0xA7CFD566F348226DULL,
		0x4EB19B9A64DFED7CULL,
		0x606680915A9D270DULL,
		0x82D7462832A4B245ULL,
		0x659A771933BFD6A6ULL,
		0x65EF2ECE9B432CFCULL
	}};
	sign = 0;
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
		0x5A0898D1771270B3ULL,
		0xD8C86BA0BF004DE1ULL,
		0xACB4531FB54617D1ULL,
		0x40D516A504C36443ULL,
		0x33871C0B228D826DULL,
		0x99BA59511774D0A7ULL,
		0x1D22EE01B15C06ECULL,
		0xEFF6C681EC66BD63ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E4A4E4843B76EA9ULL,
		0x8D2D0907951E5E3FULL,
		0x6F2460065E32165EULL,
		0xE2B7A813E4F83ECFULL,
		0x5A0120486A7E6E01ULL,
		0xF3F560940E7FC3A6ULL,
		0x7BF110C632282C71ULL,
		0xF06877FF4AFC64E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBBE4A89335B020AULL,
		0x4B9B629929E1EFA1ULL,
		0x3D8FF31957140173ULL,
		0x5E1D6E911FCB2574ULL,
		0xD985FBC2B80F146BULL,
		0xA5C4F8BD08F50D00ULL,
		0xA131DD3B7F33DA7AULL,
		0xFF8E4E82A16A587AULL
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
		0x21771DD6FF4CED8AULL,
		0xE399D926A292949FULL,
		0xDC37471B4FBF7336ULL,
		0x993A7EB76610E86AULL,
		0xFA207F3A40756A2DULL,
		0x7AA381392F011E89ULL,
		0xB3C6CBA74313AB37ULL,
		0xFDF6C00FA5CF6815ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B17CFC2216DB47ULL,
		0xF7E71CB520EA69C0ULL,
		0x03E00FE98B6D16FBULL,
		0x89C2F32B5A2CD07DULL,
		0x3DDD4AEE09A977D3ULL,
		0x0EFDCEA74270B01DULL,
		0x03299EC65D336F29ULL,
		0x2E9B45579092EDEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCC5A0DADD361243ULL,
		0xEBB2BC7181A82ADEULL,
		0xD8573731C4525C3AULL,
		0x0F778B8C0BE417EDULL,
		0xBC43344C36CBF25AULL,
		0x6BA5B291EC906E6CULL,
		0xB09D2CE0E5E03C0EULL,
		0xCF5B7AB8153C7A2BULL
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
		0x15C459028E9FFF28ULL,
		0x5B52114A2990E8CCULL,
		0x03076F997C4D386EULL,
		0xF129963373FD5506ULL,
		0x5DB1638B98133A62ULL,
		0x433DD18DF7AE1C92ULL,
		0xA02689CC9DAD0B1AULL,
		0x2D81838F37FC10C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47F9FF858C4C4447ULL,
		0x7533B7D552849C98ULL,
		0xDEFC33CBA48DF915ULL,
		0xCFC388A153C9496BULL,
		0xEAA653ABD72A1995ULL,
		0xD2E55F88358847A0ULL,
		0xCCA23CFF07694D9AULL,
		0x315F6620834E8030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDCA597D0253BAE1ULL,
		0xE61E5974D70C4C33ULL,
		0x240B3BCDD7BF3F58ULL,
		0x21660D9220340B9AULL,
		0x730B0FDFC0E920CDULL,
		0x70587205C225D4F1ULL,
		0xD3844CCD9643BD7FULL,
		0xFC221D6EB4AD9094ULL
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
		0xBB3E368869CFD17AULL,
		0x9BFE975BD8C59E51ULL,
		0x843AAAAB59703707ULL,
		0x606F2666EDE878ECULL,
		0x1B34D622D0F126D8ULL,
		0x005D598E3552FFAEULL,
		0x861A46D17D63342FULL,
		0x212F3A49D69F74C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C7106BE7D1232EULL,
		0x1FAD161315DC8DADULL,
		0x3463CB58544C48FDULL,
		0x795A185E7F7A0E0AULL,
		0xDF8AE0E0A01BEF05ULL,
		0xDFD225E632BC5674ULL,
		0xCAAE1A9423EF3D68ULL,
		0x952D015FD6E101DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6477261C81FEAE4CULL,
		0x7C518148C2E910A4ULL,
		0x4FD6DF530523EE0AULL,
		0xE7150E086E6E6AE2ULL,
		0x3BA9F54230D537D2ULL,
		0x208B33A80296A939ULL,
		0xBB6C2C3D5973F6C6ULL,
		0x8C0238E9FFBE72E5ULL
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
		0x426E6071F0322F41ULL,
		0x43F152A9ACC94244ULL,
		0x29AD9C9CA826D809ULL,
		0xAEAAF844293DC04AULL,
		0x6412E348B8C52CD3ULL,
		0x2280CD006DE13E9EULL,
		0x14256F507AC769CEULL,
		0x248144F0DEE5B4F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54439CF27241F113ULL,
		0x14B0DAB929323C35ULL,
		0x08ADD5F056A5DFF0ULL,
		0x5B29BAEF7D574C0BULL,
		0x134A0480340930BCULL,
		0x11915CE55D8C8929ULL,
		0x0880040DF0C2B5D8ULL,
		0x2E539F86DD07272CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE2AC37F7DF03E2EULL,
		0x2F4077F08397060EULL,
		0x20FFC6AC5180F819ULL,
		0x53813D54ABE6743FULL,
		0x50C8DEC884BBFC17ULL,
		0x10EF701B1054B575ULL,
		0x0BA56B428A04B3F6ULL,
		0xF62DA56A01DE8DC9ULL
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
		0x5F7B94448837C8E5ULL,
		0x793AC527CB55F186ULL,
		0x40EB9DF0C8C57772ULL,
		0xBC2480280566C186ULL,
		0xE30C95A2089E738AULL,
		0xF4A24E03B4C37604ULL,
		0x9DC6027745E91C38ULL,
		0x8616C4C4012EE137ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDF6B2DE0419BD8ULL,
		0x2D0FC1426AF41477ULL,
		0x6667F21DA5831D30ULL,
		0xEBEA7BF36E3EF5ADULL,
		0x38A75174EED75184ULL,
		0x61B019A0735267D4ULL,
		0x15F0C4BBAE1680C2ULL,
		0x47F27FD729C94E3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x439C2916A7F62D0DULL,
		0x4C2B03E56061DD0FULL,
		0xDA83ABD323425A42ULL,
		0xD03A04349727CBD8ULL,
		0xAA65442D19C72205ULL,
		0x92F2346341710E30ULL,
		0x87D53DBB97D29B76ULL,
		0x3E2444ECD76592F9ULL
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
		0xF7645041789E364CULL,
		0xC9A670CF7A10CB5FULL,
		0xBBB10760DE127A50ULL,
		0x0693301CA63F0A9BULL,
		0x261E698529324D47ULL,
		0xA94D9039F1F0899CULL,
		0xF6D72E1C3E16B058ULL,
		0x396EEE7C96412A8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2C382B47E7CA6BULL,
		0xF27D5D1B88A814F0ULL,
		0x005673DC43158ECDULL,
		0xB649F125D961FE65ULL,
		0x71A53F43DFD015A4ULL,
		0x11446D1706896B6EULL,
		0xD090F9FDAAC434E5ULL,
		0x0C523016AC8CCFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A38181630B66BE1ULL,
		0xD72913B3F168B66FULL,
		0xBB5A93849AFCEB82ULL,
		0x50493EF6CCDD0C36ULL,
		0xB4792A41496237A2ULL,
		0x98092322EB671E2DULL,
		0x2646341E93527B73ULL,
		0x2D1CBE65E9B45AE5ULL
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
		0x4BB1256D1C31D1A9ULL,
		0xC98BB3370A1E320BULL,
		0x888A52758AB7BA71ULL,
		0x2E399D4E961E5AF6ULL,
		0x3B4D13C4B1BE3B39ULL,
		0xD696BD0079F9FAB7ULL,
		0x1FDCC775234955C6ULL,
		0xBF5F1A16B69798E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F4132829F376DAULL,
		0x13AA921DDE2556BCULL,
		0x7150A7D73B7BADBCULL,
		0xA9AAF6AB3C1EB4BCULL,
		0x3BB39B256E932FF8ULL,
		0xB4786F6E8DCC65C5ULL,
		0x9E76E49C907E24E2ULL,
		0x6203D76F43055184ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09BD1244F23E5ACFULL,
		0xB5E121192BF8DB4FULL,
		0x1739AA9E4F3C0CB5ULL,
		0x848EA6A359FFA63AULL,
		0xFF99789F432B0B40ULL,
		0x221E4D91EC2D94F1ULL,
		0x8165E2D892CB30E4ULL,
		0x5D5B42A773924762ULL
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
		0x597D42E3B865F3BCULL,
		0x93B90D9476BE0F04ULL,
		0x0E22587F9B0817C2ULL,
		0x9B3703467BA77D97ULL,
		0xD97ABF44B19D2FEAULL,
		0x5D63E0C4AB6D643CULL,
		0x997CD5279F9E53E8ULL,
		0x9CBF21E4D03719DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2EE46D545515F57ULL,
		0xACDE95C211045AD4ULL,
		0x962570360B78F0DFULL,
		0x4F986238C51CE43CULL,
		0x456CE7C93E3F6020ULL,
		0x7AE10C20A91E8216ULL,
		0xB384B5777D5FC86FULL,
		0x980A3A1882D169B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x768EFC0E73149465ULL,
		0xE6DA77D265B9B42FULL,
		0x77FCE8498F8F26E2ULL,
		0x4B9EA10DB68A995AULL,
		0x940DD77B735DCFCAULL,
		0xE282D4A4024EE226ULL,
		0xE5F81FB0223E8B78ULL,
		0x04B4E7CC4D65B026ULL
	}};
	sign = 0;
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
		0x4A60D2581734C402ULL,
		0xAF000472E01B4C5FULL,
		0xE42957228B18AC36ULL,
		0x6A74A74BBE11CE3EULL,
		0xB5696F2309D75422ULL,
		0xB02FA65B63A40AE7ULL,
		0x6D476500031C5E1DULL,
		0xBB073AD4F3DA94FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C724B35DC609FBCULL,
		0xFD9A307204DD715EULL,
		0x3F8FD7CB526B0BBDULL,
		0xF7F55FFF8FF4FBF8ULL,
		0x61A6DCA9136E66E1ULL,
		0x0C714BB4ADA5C776ULL,
		0x40F01F79074B3111ULL,
		0xD670457052AF32D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DEE87223AD42446ULL,
		0xB165D400DB3DDB01ULL,
		0xA4997F5738ADA078ULL,
		0x727F474C2E1CD246ULL,
		0x53C29279F668ED40ULL,
		0xA3BE5AA6B5FE4371ULL,
		0x2C574586FBD12D0CULL,
		0xE496F564A12B6225ULL
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
		0x54C6B21B4DB06771ULL,
		0xBC30F920008B408DULL,
		0xF827E945B00BC067ULL,
		0x34433D4BE7D1C7D9ULL,
		0xEC72F35AD634F28BULL,
		0x1869CA4265FA576AULL,
		0xC6F82363676D21B2ULL,
		0x4DE7AD075E21E272ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6FD43B6016CB58ULL,
		0x2B554C40B42C37E7ULL,
		0x6177FC3BE5077947ULL,
		0x9F1E4890E0FD74B1ULL,
		0x3E3A0B8E047FA2B6ULL,
		0x9BB2332CC4BEF6E9ULL,
		0x5C1182A6566EC61BULL,
		0x300E64ADAC5F7398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3956DDDFED999C19ULL,
		0x90DBACDF4C5F08A6ULL,
		0x96AFED09CB044720ULL,
		0x9524F4BB06D45328ULL,
		0xAE38E7CCD1B54FD4ULL,
		0x7CB79715A13B6081ULL,
		0x6AE6A0BD10FE5B96ULL,
		0x1DD94859B1C26EDAULL
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
		0xD257B08490F268B9ULL,
		0x770C05D95F2D287BULL,
		0x784BCA8E77AC291EULL,
		0x114C188E72AD3A25ULL,
		0xDFC556B80485F8D5ULL,
		0xD7DCD4F8F17399E3ULL,
		0xCB0E159568C6EDB5ULL,
		0x0ACF97744D36FE9CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B5672321765227ULL,
		0xDA556C636F3E8906ULL,
		0xAF10B8F95B85F30DULL,
		0xB0AF10D38EF78DD7ULL,
		0xE6763AEA4DE834B5ULL,
		0xE77D53B27595C7A2ULL,
		0x2A8A7029A0D972A3ULL,
		0x69C33F2DA49B9D8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31A249616F7C1692ULL,
		0x9CB69975EFEE9F75ULL,
		0xC93B11951C263610ULL,
		0x609D07BAE3B5AC4DULL,
		0xF94F1BCDB69DC41FULL,
		0xF05F81467BDDD240ULL,
		0xA083A56BC7ED7B11ULL,
		0xA10C5846A89B6111ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAD87CDAD5092DE98ULL,
		0x064AA6E099FCC564ULL,
		0x59DAF69386192371ULL,
		0xC0C1A2E2B667838FULL,
		0xEB9B43587D316BA0ULL,
		0x8DD5DC36F5C05C2CULL,
		0x76B1FFABCAE936BEULL,
		0x5C4452B9B4D8DD53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3E8CBC7190D48CULL,
		0x49FEE0AAE5D6D053ULL,
		0xEA7CFAE5B7F27942ULL,
		0x6915E72D49777906ULL,
		0x4DCE3891E0BEF292ULL,
		0xDD7C99AAB9E18CD5ULL,
		0xB726997B2F77418AULL,
		0x5424192D0A40A540ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x314940F0DF020A0CULL,
		0xBC4BC635B425F511ULL,
		0x6F5DFBADCE26AA2EULL,
		0x57ABBBB56CF00A88ULL,
		0x9DCD0AC69C72790EULL,
		0xB059428C3BDECF57ULL,
		0xBF8B66309B71F533ULL,
		0x0820398CAA983812ULL
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
		0x7ECC22F6544A15A2ULL,
		0x0BE4F672197469B5ULL,
		0x9B89C13D217CF901ULL,
		0xE32AF5D3A7EA5AEFULL,
		0x1F185A3A4E2BF74AULL,
		0xDD6D24EB314046E2ULL,
		0xE50F9D6D09F3FFF0ULL,
		0x10BC8D1DE92CBA59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A7B46AEFB3B7E15ULL,
		0xD550742D41262548ULL,
		0xFD8A88994AD2670FULL,
		0xB26B0C4880536EC3ULL,
		0xB5FC97FCC365A37FULL,
		0xDDF4C4B63E8074A3ULL,
		0xC8C3F7665271B1E6ULL,
		0xFBBAE3C23064F43AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3450DC47590E978DULL,
		0x36948244D84E446DULL,
		0x9DFF38A3D6AA91F1ULL,
		0x30BFE98B2796EC2BULL,
		0x691BC23D8AC653CBULL,
		0xFF786034F2BFD23EULL,
		0x1C4BA606B7824E09ULL,
		0x1501A95BB8C7C61FULL
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
		0xADC31FD10B77CD5EULL,
		0x9DACDF28BF9F533AULL,
		0xCADFF8792D5466D2ULL,
		0x85E9FA6F0470AEB0ULL,
		0x658631F8FD91BBC9ULL,
		0x4C107E2FE34D7A3BULL,
		0x1D3C218EBADAB3F0ULL,
		0x03C28054B37A6EB2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC625B37D4EE55514ULL,
		0x938B44005F7C63D9ULL,
		0xA3054869CA4EC610ULL,
		0xC63114B298114BCAULL,
		0x4D7540B0596F1163ULL,
		0x1797D0E687661CEAULL,
		0xFB36752BE6A22E1EULL,
		0x3AFBCABAAC57DE71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE79D6C53BC92784AULL,
		0x0A219B286022EF60ULL,
		0x27DAB00F6305A0C2ULL,
		0xBFB8E5BC6C5F62E6ULL,
		0x1810F148A422AA65ULL,
		0x3478AD495BE75D51ULL,
		0x2205AC62D43885D2ULL,
		0xC8C6B59A07229040ULL
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
		0xDF8D25A7A64B5EA9ULL,
		0x0B5B7030A1F50A8DULL,
		0x0D7C03D4B1F4A889ULL,
		0xF54CA5C2CC5E254CULL,
		0xCB11DF5F124822A1ULL,
		0xEB9728229A554DE1ULL,
		0x1FAF4C20D5F6FDEEULL,
		0x1B0C500EC34F6FD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABBB301A87665959ULL,
		0xA3B05F1368027D32ULL,
		0x438085367255D21EULL,
		0x924D001DF132EC1BULL,
		0x364B64D424B5BCA9ULL,
		0x89ACF3015ABCD9D1ULL,
		0x16A4E6718CF1645EULL,
		0x9FBBBEEEE73220D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33D1F58D1EE50550ULL,
		0x67AB111D39F28D5BULL,
		0xC9FB7E9E3F9ED66AULL,
		0x62FFA5A4DB2B3930ULL,
		0x94C67A8AED9265F8ULL,
		0x61EA35213F987410ULL,
		0x090A65AF49059990ULL,
		0x7B50911FDC1D4F09ULL
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
		0xC5C2EFBD27ECD693ULL,
		0xC313BD671C1B661EULL,
		0x7398B114F9CF4237ULL,
		0xCB812F5322B2F303ULL,
		0x6A0E5E69FA170B65ULL,
		0xAEC2AF7BCE8E0A00ULL,
		0x53E7346937DBE353ULL,
		0xBEC8E47DD5CAA588ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11870020E7809B0DULL,
		0xB2A5489A9ACD3568ULL,
		0xD8439DE7C0AEE5FBULL,
		0xA84E430286E73A44ULL,
		0x7C2853EB48C4E957ULL,
		0x66DA1A54DD63B34BULL,
		0xC4FB6D56BC069726ULL,
		0x2B2BCD4D240D0E71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB43BEF9C406C3B86ULL,
		0x106E74CC814E30B6ULL,
		0x9B55132D39205C3CULL,
		0x2332EC509BCBB8BEULL,
		0xEDE60A7EB152220EULL,
		0x47E89526F12A56B4ULL,
		0x8EEBC7127BD54C2DULL,
		0x939D1730B1BD9716ULL
	}};
	sign = 0;
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
		0x32ABF1F21D1D3728ULL,
		0x06BA6634B202AECFULL,
		0x468679C38E627B87ULL,
		0x2058932E4511D69CULL,
		0x57399DCB6B95818BULL,
		0x54C505182B675112ULL,
		0x378C2785D0AD84EBULL,
		0x88CE344739BA5D0AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7AFC0DE5FBB40C1ULL,
		0xAD207556573DC05DULL,
		0x01DC842B7A50D1D7ULL,
		0xA714D0B2D9176C38ULL,
		0x6132BB71E69027E6ULL,
		0x446F1BB4DE6FC742ULL,
		0x2004EB959D298385ULL,
		0x76A2C689BEA0D1AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AFC3113BD61F667ULL,
		0x5999F0DE5AC4EE71ULL,
		0x44A9F5981411A9AFULL,
		0x7943C27B6BFA6A64ULL,
		0xF606E259850559A4ULL,
		0x1055E9634CF789CFULL,
		0x17873BF033840166ULL,
		0x122B6DBD7B198B5CULL
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
		0x5F96FF23B2479DE2ULL,
		0xA2E5E97F9FF68809ULL,
		0x854AEF640416D1A8ULL,
		0x1709576E10DAE3A8ULL,
		0xA7C05FDB00CAB9B7ULL,
		0x87E90686F0840BD4ULL,
		0x412A88E5E837762EULL,
		0x7D61C76382335D23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64EA50F0D00DEA6CULL,
		0x14C2178915C5B9E3ULL,
		0xEC0956FA8AD2E0BBULL,
		0x671258AF678A6E97ULL,
		0xEE34A1AB9B324429ULL,
		0xA8C69CA35E3AA45FULL,
		0xB99E4605449C8510ULL,
		0xAE202140D7BF0041ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAACAE32E239B376ULL,
		0x8E23D1F68A30CE25ULL,
		0x994198697943F0EDULL,
		0xAFF6FEBEA9507510ULL,
		0xB98BBE2F6598758DULL,
		0xDF2269E392496774ULL,
		0x878C42E0A39AF11DULL,
		0xCF41A622AA745CE1ULL
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
		0x8C8D3F0B8BA15454ULL,
		0x1C8386B9B8EB0706ULL,
		0x465C1E02C410A61BULL,
		0x242A9F7A115B6B22ULL,
		0x51D9A77D241849D0ULL,
		0x926AEED0AB091379ULL,
		0xABDD739B9FA4BB86ULL,
		0x84AF6E5430A7D1FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BC71E8D12C3955EULL,
		0x5B1636247DD1C5DCULL,
		0xC77316838EA555CAULL,
		0xF9EF9E22AAA07F35ULL,
		0xD22EBCA411D8A1B0ULL,
		0xB77EFEFF99078976ULL,
		0x69A93233B7FD02F9ULL,
		0xA6A818968930AF07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C6207E78DDBEF6ULL,
		0xC16D50953B19412AULL,
		0x7EE9077F356B5050ULL,
		0x2A3B015766BAEBECULL,
		0x7FAAEAD9123FA81FULL,
		0xDAEBEFD112018A02ULL,
		0x42344167E7A7B88CULL,
		0xDE0755BDA77722F7ULL
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
		0x0FCE10D61C723E8AULL,
		0xFF309E5C6B264782ULL,
		0x3FB3EAF5D4B2B107ULL,
		0x0EAEED3A12FDC0A2ULL,
		0xE67186D51B269F3BULL,
		0x845BC96B6D4D9577ULL,
		0xD37B708772AECACAULL,
		0xFC719FFC5C62781AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3293FE6B29C3B112ULL,
		0xDC58D3E139E7D2E2ULL,
		0xADF8CA4179B5F7D6ULL,
		0x60FEDC9CEBEC9EF7ULL,
		0x465C70ED9E610973ULL,
		0x2FBDCC3984235F1BULL,
		0xFF2168B1757D54BEULL,
		0x962D4CD981F9F08CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD3A126AF2AE8D78ULL,
		0x22D7CA7B313E749FULL,
		0x91BB20B45AFCB931ULL,
		0xADB0109D271121AAULL,
		0xA01515E77CC595C7ULL,
		0x549DFD31E92A365CULL,
		0xD45A07D5FD31760CULL,
		0x66445322DA68878DULL
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
		0xD7FD81A1E228EE7DULL,
		0xEF5EB30D8E57EA56ULL,
		0xE35BCFB925BA8B4EULL,
		0x80B4BB3634A1E906ULL,
		0x53D73E10DA92CFAFULL,
		0xC28B317DE7A94073ULL,
		0xC7CF667C5AA6257FULL,
		0x46D9B63E2A7C09C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1225CAF86307F9B0ULL,
		0x02D6A8E60D9EE58CULL,
		0x99B4AAD78EA797B8ULL,
		0xF5138B3DED21B2D6ULL,
		0x3BCDDA88CDACF070ULL,
		0x95AF882B58D7832AULL,
		0xE9DE45592CEF5974ULL,
		0x7F0EBB966183C59DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D7B6A97F20F4CDULL,
		0xEC880A2780B904CAULL,
		0x49A724E19712F396ULL,
		0x8BA12FF847803630ULL,
		0x180963880CE5DF3EULL,
		0x2CDBA9528ED1BD49ULL,
		0xDDF121232DB6CC0BULL,
		0xC7CAFAA7C8F84427ULL
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
		0x442B8C3220335D5EULL,
		0x65708BFC247BC95FULL,
		0xFA27F6F5D569ED6DULL,
		0xDEB690B6A79B27A1ULL,
		0xDDF834C4FE629E5BULL,
		0x1EE697AACAAFA6ABULL,
		0x64A5EFA5A83040F5ULL,
		0xB82CB6150B604DADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB907BD7B8AE35490ULL,
		0x9C8A3BCFB96A4945ULL,
		0xEE9318DD26BACA81ULL,
		0x961C5B7EB88F2EEBULL,
		0x785F8BBD424BF4F3ULL,
		0xD14CBCE5A155E457ULL,
		0x72E5DF7CBF14D5A1ULL,
		0x89F809B850F35CD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B23CEB6955008CEULL,
		0xC8E6502C6B118019ULL,
		0x0B94DE18AEAF22EBULL,
		0x489A3537EF0BF8B6ULL,
		0x6598A907BC16A968ULL,
		0x4D99DAC52959C254ULL,
		0xF1C01028E91B6B53ULL,
		0x2E34AC5CBA6CF0D5ULL
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
		0x1E15BB3DD7332079ULL,
		0xC8366F5BD6C68D04ULL,
		0xC9132EB629D4F2D1ULL,
		0x21BD222352A94F44ULL,
		0x4A0505CAECADBDD8ULL,
		0xFA9300044E33D6FFULL,
		0x8F604C0080865D14ULL,
		0xDAC475BBA9513995ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F160FD60303869ULL,
		0x6C23C0E5913D7BEAULL,
		0x5C70C0851C1CD5FDULL,
		0x97B449CCF4A69C24ULL,
		0x966ED51546660301ULL,
		0x136A39C32591BFECULL,
		0x74A7DCD52534C4C0ULL,
		0xBC7C21399BB4F7E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9245A407702E810ULL,
		0x5C12AE7645891119ULL,
		0x6CA26E310DB81CD4ULL,
		0x8A08D8565E02B320ULL,
		0xB39630B5A647BAD6ULL,
		0xE728C64128A21712ULL,
		0x1AB86F2B5B519854ULL,
		0x1E4854820D9C41AEULL
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
		0xCD97C622BB971BB5ULL,
		0xED69DA59BAFB16FAULL,
		0x1EE3AC91DCA9755FULL,
		0xAC118044A615B14DULL,
		0x1C224A3CA97083DEULL,
		0x03F1722F9535C73CULL,
		0xB3EA130EAAFF5DA5ULL,
		0x133C797B2997018CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF774FBD079E59152ULL,
		0xD691B0EA0EF9003EULL,
		0xB5C45805039F8EFEULL,
		0x50A6AAFC5900778EULL,
		0xA0E992DD1460AFB4ULL,
		0x7B2ED6A89E1A5AEDULL,
		0xEC4DE674288F2F54ULL,
		0xC819372D4C53CE12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD622CA5241B18A63ULL,
		0x16D8296FAC0216BBULL,
		0x691F548CD909E661ULL,
		0x5B6AD5484D1539BEULL,
		0x7B38B75F950FD42AULL,
		0x88C29B86F71B6C4EULL,
		0xC79C2C9A82702E50ULL,
		0x4B23424DDD433379ULL
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
		0x3C3F13A56292EC14ULL,
		0xE00A0759F68F23C2ULL,
		0xCA84378D6AB9B3E3ULL,
		0xC56CADE7B098AD24ULL,
		0x06E19BA6609E0CFFULL,
		0xB73AB028247FFF1CULL,
		0x55EE44E1EBFEA8BEULL,
		0x11A264BE944DC8F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x966F6619FB2921E0ULL,
		0x94A3A8ADA4CC2C92ULL,
		0xEB5F52CF4501AD4CULL,
		0x55144146D2A80786ULL,
		0xBF627A5DA4DE744EULL,
		0x4F29AEC824DE8DE9ULL,
		0xA71D58980B608C23ULL,
		0xAD36E37ABD90C025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5CFAD8B6769CA34ULL,
		0x4B665EAC51C2F72FULL,
		0xDF24E4BE25B80697ULL,
		0x70586CA0DDF0A59DULL,
		0x477F2148BBBF98B1ULL,
		0x6811015FFFA17132ULL,
		0xAED0EC49E09E1C9BULL,
		0x646B8143D6BD08CDULL
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
		0xFA08F188A6001852ULL,
		0x579E7916E83FE105ULL,
		0xAEEB1E91848181E5ULL,
		0xC76376A6D6F857BCULL,
		0x1034EF1F50C6C2B1ULL,
		0xAD7571A1C8DBC165ULL,
		0x0CD9BC866D104FAAULL,
		0xD1A54A14D01C7205ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x178E343BB42DAFE7ULL,
		0x8A074A013240234CULL,
		0x8250B9C467D0FD2AULL,
		0x39B72625AE852569ULL,
		0xFFDB5D0696153CD8ULL,
		0xA36B6696BEB817ACULL,
		0x21A42D7F0E80CB4EULL,
		0x80784D82F3E6F030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE27ABD4CF1D2686BULL,
		0xCD972F15B5FFBDB9ULL,
		0x2C9A64CD1CB084BAULL,
		0x8DAC508128733253ULL,
		0x10599218BAB185D9ULL,
		0x0A0A0B0B0A23A9B8ULL,
		0xEB358F075E8F845CULL,
		0x512CFC91DC3581D4ULL
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
		0x65B89CB6F64E6120ULL,
		0x8BB04702F7B05A6BULL,
		0x367094831C2C092FULL,
		0xE276339818E80CC3ULL,
		0x4776DB1B99EA59C7ULL,
		0xE723684DE4113FE4ULL,
		0x8B59A85988EA9CB3ULL,
		0x1E87765261169B46ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D563E2EBE0F9FFULL,
		0xC847D1F3E97C87CBULL,
		0xB0E91C9E60EA4F87ULL,
		0x97520CE96D232DBAULL,
		0x6229023571A3FD5AULL,
		0x33F8EC9BF7C2679DULL,
		0xE44851639441B49FULL,
		0x6C08006B7B024AB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FE338D40A6D6721ULL,
		0xC368750F0E33D2A0ULL,
		0x858777E4BB41B9A7ULL,
		0x4B2426AEABC4DF08ULL,
		0xE54DD8E628465C6DULL,
		0xB32A7BB1EC4ED846ULL,
		0xA71156F5F4A8E814ULL,
		0xB27F75E6E6145092ULL
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
		0x73D333458D8552AFULL,
		0x6FBC945840C53B59ULL,
		0xAA22207F3E925CE5ULL,
		0xA9C9830C156815A6ULL,
		0xA498AD605AA1BE0EULL,
		0x7E1E945938F83869ULL,
		0x391567D67E4A1C3CULL,
		0x796D1CAA76D7C3AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36274A77AFF1950ULL,
		0x399D946E2C27D7D8ULL,
		0x4545BEAE42BCB483ULL,
		0x03892A186D2C4D3AULL,
		0xDABAB7B7880C33C5ULL,
		0xC744E9279F3D95D7ULL,
		0x7FD8DE6CB377A687ULL,
		0x375BF782772ECA88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC070BE9E1286395FULL,
		0x361EFFEA149D6380ULL,
		0x64DC61D0FBD5A862ULL,
		0xA64058F3A83BC86CULL,
		0xC9DDF5A8D2958A49ULL,
		0xB6D9AB3199BAA291ULL,
		0xB93C8969CAD275B4ULL,
		0x42112527FFA8F925ULL
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
		0x65E544F07C6F6861ULL,
		0xC44A575A5ED32422ULL,
		0x9F357F87F6C191D5ULL,
		0x289D3AC42D4DFD3BULL,
		0xEA26E70179EB512FULL,
		0x03B8FCC57433E30AULL,
		0xA57533637E0CBF92ULL,
		0x6972BAA220F79958ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ADCF4558EB91B7EULL,
		0x0345B98BF305C6C9ULL,
		0xF83E5A0F7BAD3777ULL,
		0xB8D9CF1A137FB4DFULL,
		0x4FED31399159728CULL,
		0x1C78924256169950ULL,
		0x579E8AD1AA99766BULL,
		0x092D31886050521DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B08509AEDB64CE3ULL,
		0xC1049DCE6BCD5D59ULL,
		0xA6F725787B145A5EULL,
		0x6FC36BAA19CE485BULL,
		0x9A39B5C7E891DEA2ULL,
		0xE7406A831E1D49BAULL,
		0x4DD6A891D3734926ULL,
		0x60458919C0A7473BULL
	}};
	sign = 0;
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
		0xD1DE48EA64DA0B83ULL,
		0xB069982CF5F865FBULL,
		0x4F44F9EA53C896B0ULL,
		0x79F4AA04B77632E0ULL,
		0x61A884AE148E1BD1ULL,
		0xB212A3B76C4B9EF7ULL,
		0x4DE77B8D6AC27AE3ULL,
		0x1D445D66EF7F18A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF9CEA735FF84EFULL,
		0x8AC305EFDC93A9EAULL,
		0xCC850B0A8F599559ULL,
		0xF8516D142BAACA29ULL,
		0x9F45CC8A97923299ULL,
		0x898C2A39D63348EAULL,
		0x9B0B67ABD224822CULL,
		0xFA59C2A685535227ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16E47A432EDA8694ULL,
		0x25A6923D1964BC11ULL,
		0x82BFEEDFC46F0157ULL,
		0x81A33CF08BCB68B6ULL,
		0xC262B8237CFBE937ULL,
		0x2886797D9618560CULL,
		0xB2DC13E1989DF8B7ULL,
		0x22EA9AC06A2BC680ULL
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
		0xB0A3A406AF31D97EULL,
		0x8AC3495F75AE56FFULL,
		0x6A6AED6B47B5153DULL,
		0x67A3CCF3A4886A5DULL,
		0xA81B9B24D405E253ULL,
		0x2E230A00203BFA71ULL,
		0x58F1275BFF0A9A3AULL,
		0x82391FCAC48DA41EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x090D1CE7DF3F1F14ULL,
		0x248C1AB31C6AA0DEULL,
		0x0F25D2C2359F7711ULL,
		0xC6B9E988FEA5470EULL,
		0x7E6ACEB32CE6AF12ULL,
		0x198AFA850EB9E753ULL,
		0x46572D8C7D4FA03EULL,
		0x1A4D7F90E32CBA7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA796871ECFF2BA6AULL,
		0x66372EAC5943B621ULL,
		0x5B451AA912159E2CULL,
		0xA0E9E36AA5E3234FULL,
		0x29B0CC71A71F3340ULL,
		0x14980F7B1182131EULL,
		0x1299F9CF81BAF9FCULL,
		0x67EBA039E160E9A2ULL
	}};
	sign = 0;
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
		0x5043F405239ED099ULL,
		0x6E8EE8CC01ECBC33ULL,
		0x8B65289C7DEAAA24ULL,
		0xA3E63CE3DF2D7B6DULL,
		0xDDF6BB20B2069195ULL,
		0x477D40A5A9D5FCF3ULL,
		0x4343C13B3C393680ULL,
		0x076FBFC225BC4ED2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9542520D6404F230ULL,
		0xF375DB91F497F23FULL,
		0x5DB44E067EFEFA12ULL,
		0x1A03ADA555909A2DULL,
		0x21F9E7C248F429DBULL,
		0xA43B3EF81E96B67EULL,
		0x5524D51E45049F53ULL,
		0x7F0925949F8647B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB01A1F7BF99DE69ULL,
		0x7B190D3A0D54C9F3ULL,
		0x2DB0DA95FEEBB011ULL,
		0x89E28F3E899CE140ULL,
		0xBBFCD35E691267BAULL,
		0xA34201AD8B3F4675ULL,
		0xEE1EEC1CF734972CULL,
		0x88669A2D8636071EULL
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
		0x480C52CBB8232C06ULL,
		0xC60AA304AA9ABE6DULL,
		0x37E9645BB509E575ULL,
		0x8062208E4E57DB8DULL,
		0x32F233FFFC5F57BDULL,
		0xB205A1756556A247ULL,
		0x22147A4E643F907FULL,
		0x9879D5F1588CBE00ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F325D9A807D2E8ULL,
		0x9AFCD3508B111058ULL,
		0xA4FCED7C13BD3499ULL,
		0x4A113D4C914B1151ULL,
		0x4303877CD5AA697FULL,
		0xB6932BDAA1F55E60ULL,
		0xD00BE17F26656849ULL,
		0x4154A7E4641B3E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1192CF2101B591EULL,
		0x2B0DCFB41F89AE14ULL,
		0x92EC76DFA14CB0DCULL,
		0x3650E341BD0CCA3BULL,
		0xEFEEAC8326B4EE3EULL,
		0xFB72759AC36143E6ULL,
		0x520898CF3DDA2835ULL,
		0x57252E0CF4717FE7ULL
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
		0xAB9608E6E53C356AULL,
		0xB426DE7233C23CD4ULL,
		0xDBD39614408DD8E6ULL,
		0xFC802BD105E5BB88ULL,
		0x5F1ABA2F126CB87BULL,
		0x26D1C51BA4CA7D3FULL,
		0xAD1C5B5CD006A2B4ULL,
		0x320B655642707752ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D8324DE99628C8ULL,
		0xBE0F93FEC9CBC372ULL,
		0x9587A7188F9C98BCULL,
		0x739A7482B4EF86D1ULL,
		0x401ECE4F41A8478AULL,
		0xCD86B2DA7978AFC0ULL,
		0x33BFB987BC9315F7ULL,
		0x33CF5475F64FE7D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ABDD698FBA60CA2ULL,
		0xF6174A7369F67962ULL,
		0x464BEEFBB0F14029ULL,
		0x88E5B74E50F634B7ULL,
		0x1EFBEBDFD0C470F1ULL,
		0x594B12412B51CD7FULL,
		0x795CA1D513738CBCULL,
		0xFE3C10E04C208F82ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x73DF379D682AC201ULL,
		0xE5FDAF34DAAD4BFDULL,
		0x9E2E844114D1C0A7ULL,
		0xED4E0699A8EB164AULL,
		0x3DDEF0FD56D4FA61ULL,
		0x481694DB936FBD90ULL,
		0x1179AECEB3517837ULL,
		0x428E24B9EEF6E9AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC54E1BC4856F36EEULL,
		0x828B886F51B14DC5ULL,
		0x2F323643FDF04D7AULL,
		0x34989EB3D5ACB832ULL,
		0xCE1EE4AE423570CEULL,
		0xCA72DD4863BFB5F9ULL,
		0x780CD8E6F8F50B6CULL,
		0xD3B6F681A273C44DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE911BD8E2BB8B13ULL,
		0x637226C588FBFE37ULL,
		0x6EFC4DFD16E1732DULL,
		0xB8B567E5D33E5E18ULL,
		0x6FC00C4F149F8993ULL,
		0x7DA3B7932FB00796ULL,
		0x996CD5E7BA5C6CCAULL,
		0x6ED72E384C83255CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2EBBD489C41497B6ULL,
		0x892B9E91C9DA83B2ULL,
		0xF207DFA92803DFB2ULL,
		0x76D895E0C27CD356ULL,
		0x510804E3D2848792ULL,
		0x6F1B214037004452ULL,
		0xCD791261C6C95A0EULL,
		0x084CD6BC70F44215ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E90276FF40158DBULL,
		0xF3D0D8A23D542DAFULL,
		0x841E99AAC1D22F6EULL,
		0x999B4E84674FA115ULL,
		0x393643689499A464ULL,
		0x52887F51C2A371D0ULL,
		0x3052F073AAFFD187ULL,
		0x081A49D57B0D48ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE02BAD19D0133EDBULL,
		0x955AC5EF8C865602ULL,
		0x6DE945FE6631B043ULL,
		0xDD3D475C5B2D3241ULL,
		0x17D1C17B3DEAE32DULL,
		0x1C92A1EE745CD282ULL,
		0x9D2621EE1BC98887ULL,
		0x00328CE6F5E6F929ULL
	}};
	sign = 0;
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
		0x9215358C72E61855ULL,
		0x8A0FF21EF17DF05AULL,
		0x86F4E946738AE218ULL,
		0xD15D7CFD9184912CULL,
		0x30422A48ACF72891ULL,
		0x4953CF015A282E64ULL,
		0x12FF2A902430544BULL,
		0x0015C42FF8E9B4D9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A8CC267A2E705AEULL,
		0x776DF55D3577C609ULL,
		0x2D3383CD3BA3846AULL,
		0xA6B782A07CF96D7EULL,
		0x64C59F48D6251E77ULL,
		0xB54BB4FEB23F6478ULL,
		0x014E5F6B17847E64ULL,
		0xA54149020FCD1E3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17887324CFFF12A7ULL,
		0x12A1FCC1BC062A51ULL,
		0x59C1657937E75DAEULL,
		0x2AA5FA5D148B23AEULL,
		0xCB7C8AFFD6D20A1AULL,
		0x94081A02A7E8C9EBULL,
		0x11B0CB250CABD5E6ULL,
		0x5AD47B2DE91C969CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFD7063AFE903FA05ULL,
		0x2BB9B89B890B0E27ULL,
		0x8C71FB3B60895AF0ULL,
		0xC89D1EC5781DF8D4ULL,
		0xFD117193E7845FCAULL,
		0x4DA976AA7E14B557ULL,
		0xCB8AE6839E996F7CULL,
		0xCF68D535E5090DAEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA677653E232A6AF0ULL,
		0x26DDDA6A7FFCA437ULL,
		0xF75070AACE0C6FADULL,
		0x5569AF8E7E355B25ULL,
		0xA9D857851EB16FE2ULL,
		0xEE47E84D857E8CDCULL,
		0x04A28BB7409F34B8ULL,
		0xD9FF3865A41A0F9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56F8FE71C5D98F15ULL,
		0x04DBDE31090E69F0ULL,
		0x95218A90927CEB43ULL,
		0x73336F36F9E89DAEULL,
		0x53391A0EC8D2EFE8ULL,
		0x5F618E5CF896287BULL,
		0xC6E85ACC5DFA3AC3ULL,
		0xF5699CD040EEFE10ULL
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
		0x37519F7E543BAA29ULL,
		0x8B1BAC006466682AULL,
		0xB589FEA4442F1771ULL,
		0x575F83EA82C537B2ULL,
		0x7B59E82B23896F70ULL,
		0x57BB7EF9617EF89CULL,
		0x053FE1ACED34177CULL,
		0xE568ACD679241AADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABED3323F3358DF4ULL,
		0xB73A79637C7C4087ULL,
		0x79C416258BA81632ULL,
		0x4DBBC6BA822B6187ULL,
		0x731D5D9CE6291A4CULL,
		0x1094B9FAA0169F17ULL,
		0x197DC085C1C049A0ULL,
		0xA40F2220DC1BC880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B646C5A61061C35ULL,
		0xD3E1329CE7EA27A2ULL,
		0x3BC5E87EB887013EULL,
		0x09A3BD300099D62BULL,
		0x083C8A8E3D605524ULL,
		0x4726C4FEC1685985ULL,
		0xEBC221272B73CDDCULL,
		0x41598AB59D08522CULL
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
		0xD6ABBF758FB40B1DULL,
		0x17306A96FDE7BFDDULL,
		0xBBD23C70F59560F2ULL,
		0xBC5368965D323A12ULL,
		0x158856B30804D2D4ULL,
		0xBAD3BAAE806E63AFULL,
		0x3DE660928CF11ECAULL,
		0xDD76C896F3D28460ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x237D14DD6118706BULL,
		0x7E7AAE671897506EULL,
		0xCE38FA8564BFA33DULL,
		0x041E2D34BBD0F256ULL,
		0xF636254B4FB45B9CULL,
		0xB39BC9D1D6B9CF49ULL,
		0xF610CBFDAA8A8250ULL,
		0x98D51E54BAEF9B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB32EAA982E9B9AB2ULL,
		0x98B5BC2FE5506F6FULL,
		0xED9941EB90D5BDB4ULL,
		0xB8353B61A16147BBULL,
		0x1F523167B8507738ULL,
		0x0737F0DCA9B49465ULL,
		0x47D59494E2669C7AULL,
		0x44A1AA4238E2E95EULL
	}};
	sign = 0;
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
		0x6204542AC1373E48ULL,
		0x95440275EC563904ULL,
		0xF705ACAA7612555AULL,
		0xE8A822EB338CCDADULL,
		0xDD7322E2CE59458BULL,
		0x4CDA37312E624C80ULL,
		0xC00302FAC026EBF7ULL,
		0xFCC357ACE2744611ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AED911515382280ULL,
		0xF8D2380B04A309ACULL,
		0x91D563966EEB19B6ULL,
		0x2AFA648DC1376E34ULL,
		0x101865EC9807C925ULL,
		0xEB1191512D1D0FEAULL,
		0x6F5825FBC2DAE1F1ULL,
		0x8AED7E35E8682767ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC716C315ABFF1BC8ULL,
		0x9C71CA6AE7B32F57ULL,
		0x6530491407273BA3ULL,
		0xBDADBE5D72555F79ULL,
		0xCD5ABCF636517C66ULL,
		0x61C8A5E001453C96ULL,
		0x50AADCFEFD4C0A05ULL,
		0x71D5D976FA0C1EAAULL
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
		0x03378CC1CDD00301ULL,
		0x700119151DBE9D96ULL,
		0xE6C521CA9B95353AULL,
		0xF15C33B45152746AULL,
		0x7C3BC5FFC4D130ABULL,
		0xE7FA6751FD28BE12ULL,
		0x21EC2D858722BBA9ULL,
		0xEA65A9E0110633B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B1A81CB016D5897ULL,
		0xB711BA6A60D5824DULL,
		0x128E897DBE31B7E2ULL,
		0x10EAA985EBC1C352ULL,
		0xF0C6FA58DAFF251CULL,
		0xF8F10DA5D46B11DFULL,
		0xA7A88815451750C9ULL,
		0xB46BE470B9D775EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF81D0AF6CC62AA6AULL,
		0xB8EF5EAABCE91B48ULL,
		0xD436984CDD637D57ULL,
		0xE0718A2E6590B118ULL,
		0x8B74CBA6E9D20B8FULL,
		0xEF0959AC28BDAC32ULL,
		0x7A43A570420B6ADFULL,
		0x35F9C56F572EBDC7ULL
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
		0x7249C398794E3416ULL,
		0x3CC1293733ABAF79ULL,
		0x65A74C220F002622ULL,
		0x0B84FA1FD8F394B7ULL,
		0xB53BE08A65F1A393ULL,
		0x1F9A461A7F6C3808ULL,
		0xCCA252BFFD416746ULL,
		0x7E86BAB5616E2C4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80AED08E2C447A4ULL,
		0xBECF035B509850C8ULL,
		0xB144F2CFC5C46D27ULL,
		0x46AFEFB97E6DAB24ULL,
		0xC66E916CC10F363DULL,
		0xD1A59F6FB2803CA2ULL,
		0x93556D50FFE3C56EULL,
		0x9BE0A7DCF73905E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A3ED68F9689EC72ULL,
		0x7DF225DBE3135EB0ULL,
		0xB4625952493BB8FAULL,
		0xC4D50A665A85E992ULL,
		0xEECD4F1DA4E26D55ULL,
		0x4DF4A6AACCEBFB65ULL,
		0x394CE56EFD5DA1D7ULL,
		0xE2A612D86A352667ULL
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
		0x9E41907FCFC18DD1ULL,
		0xF697DA05CE3BEB7AULL,
		0xC60B69A95575B6A7ULL,
		0x4D3E44AAC84C7DEDULL,
		0x2843F92851CB183AULL,
		0xA5F210E2F0282851ULL,
		0xDFF2A011D69051C6ULL,
		0x616AC60C3290EEEDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3C3EDC1F1A8F3CULL,
		0xB188A49316C6AAF6ULL,
		0x0B53C981F9CFA921ULL,
		0xAFCF4A54EE5B6507ULL,
		0x672EB04A3E244F87ULL,
		0xFA6A6C04C6F1ADC2ULL,
		0xB2843FEFFCD6F501ULL,
		0xF6CD546A45E85874ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x910551A3B0A6FE95ULL,
		0x450F3572B7754084ULL,
		0xBAB7A0275BA60D86ULL,
		0x9D6EFA55D9F118E6ULL,
		0xC11548DE13A6C8B2ULL,
		0xAB87A4DE29367A8EULL,
		0x2D6E6021D9B95CC4ULL,
		0x6A9D71A1ECA89679ULL
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
		0x421492927999801FULL,
		0x7B37D4C7E40C0B9AULL,
		0x8B5E5E24C549DDADULL,
		0xE5FFFC182CE466C4ULL,
		0xE2A7A9955FE67115ULL,
		0xEE72060A78F47997ULL,
		0xD5FE984D62454E60ULL,
		0xC77AC0240BDD2EECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE737B3C7E6339B5ULL,
		0xF56B9E429C8E3EBDULL,
		0x644746110EDABD40ULL,
		0xF5EF2A15962EDD20ULL,
		0xFCBCF6EE3FABA6D4ULL,
		0x9FC78901666BE679ULL,
		0x3E20818ABC3D346DULL,
		0x3C0706A1959274C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63A11755FB36466AULL,
		0x85CC3685477DCCDCULL,
		0x27171813B66F206CULL,
		0xF010D20296B589A4ULL,
		0xE5EAB2A7203ACA40ULL,
		0x4EAA7D091288931DULL,
		0x97DE16C2A60819F3ULL,
		0x8B73B982764ABA26ULL
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
		0xE192A95BC34E03E9ULL,
		0xB096D4ED905EBE4DULL,
		0x6A16DCD28B57A8D7ULL,
		0x6632E618E8DDE59CULL,
		0xAA44F45A9CC8798CULL,
		0x2E8231C548713207ULL,
		0xC517A7A204CEA0C5ULL,
		0x42E51E11D537D8DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8D5D4474681E5CULL,
		0x43BF7A8DBD4624E3ULL,
		0x3E2E492F7A3DFB51ULL,
		0x3FEA49BC8C0DC625ULL,
		0x948C0A17782397F6ULL,
		0xAAD65677DC9B0B70ULL,
		0x8FFA60E474F298E0ULL,
		0xD4514C873C2356EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33054C174EE5E58DULL,
		0x6CD75A5FD318996AULL,
		0x2BE893A31119AD86ULL,
		0x26489C5C5CD01F77ULL,
		0x15B8EA4324A4E196ULL,
		0x83ABDB4D6BD62697ULL,
		0x351D46BD8FDC07E4ULL,
		0x6E93D18A991481EFULL
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
		0x38251F0C59E8622BULL,
		0xF0EBA71D33EC8EA9ULL,
		0x2715FBD140E62BB4ULL,
		0x35B0ECE25E91D469ULL,
		0x54C7F95060365F5FULL,
		0x1BFA8A65E58E3793ULL,
		0x99B4A6699E35A96DULL,
		0xD2C51569A6CDC85DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4BA5C0EE9A18E1BULL,
		0xFE4EDB17A6700905ULL,
		0x9F1644F0551CC4B7ULL,
		0x16B4426C9CF11FFAULL,
		0xB5F1DF35D615AF2DULL,
		0x9560057E86CE3DEFULL,
		0xD6ABD1C93A5D3311ULL,
		0x418BB7EE7E9EB2E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x936AC2FD7046D410ULL,
		0xF29CCC058D7C85A3ULL,
		0x87FFB6E0EBC966FCULL,
		0x1EFCAA75C1A0B46EULL,
		0x9ED61A1A8A20B032ULL,
		0x869A84E75EBFF9A3ULL,
		0xC308D4A063D8765BULL,
		0x91395D7B282F157BULL
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
		0x1AFD9C649FF11533ULL,
		0x2C405E03C121E56DULL,
		0xB953EE7461E1DEECULL,
		0x71FAF88A46F69F64ULL,
		0xF63E21CD057B61B0ULL,
		0xCC0494B12FD29787ULL,
		0x12828D9013DB1505ULL,
		0x245AE09CD4C8F91FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x25E08BBF45CBCD0CULL,
		0x47F40C0827E19709ULL,
		0x6AAA2453F0B2E26EULL,
		0x050E04ECFBF4B873ULL,
		0xDE424223434C59F4ULL,
		0x94A26B0D314434B7ULL,
		0x00D7B56AD1EDD50EULL,
		0x52B06D839A75E0F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF51D10A55A254827ULL,
		0xE44C51FB99404E63ULL,
		0x4EA9CA20712EFC7DULL,
		0x6CECF39D4B01E6F1ULL,
		0x17FBDFA9C22F07BCULL,
		0x376229A3FE8E62D0ULL,
		0x11AAD82541ED3FF7ULL,
		0xD1AA73193A531828ULL
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
		0xB04F19235B766301ULL,
		0x8D31E2F77A21CA2BULL,
		0xB736BA7D60B8A622ULL,
		0x0C558F273FC3663AULL,
		0xDA41D0CD0643B80AULL,
		0xA739423E3EDACAB2ULL,
		0x379D5CB2C98C3FC0ULL,
		0x0F7D48EDD204A30FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC13546D6B42B5DULL,
		0x0876DE3910AB9581ULL,
		0xB66600765F411849ULL,
		0xEC8890B55DD7E6A7ULL,
		0xCBFA85A73B49FC6EULL,
		0xAD523C1EEC15BDE3ULL,
		0x1409CDBC3805945BULL,
		0x01E934778A8BC4A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF18DE3DC84C237A4ULL,
		0x84BB04BE697634A9ULL,
		0x00D0BA0701778DD9ULL,
		0x1FCCFE71E1EB7F93ULL,
		0x0E474B25CAF9BB9BULL,
		0xF9E7061F52C50CCFULL,
		0x23938EF69186AB64ULL,
		0x0D9414764778DE66ULL
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
		0x4945B72E37F0784FULL,
		0x093C27C482D70FB0ULL,
		0x2CAED8195D597C89ULL,
		0x95CBA32798663CD7ULL,
		0x78A68ED833F40D92ULL,
		0xD5E2DD85F893033EULL,
		0x9F01C56A7FA1DF91ULL,
		0xDA026E062B80B904ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B1E6A186C876268ULL,
		0x20B5141989146B66ULL,
		0x0706CC1987340036ULL,
		0x56B2F6D3C26D4777ULL,
		0x810285490BA14C67ULL,
		0xB389D129DE99FC39ULL,
		0x0E6C610E5A475715ULL,
		0x7F05B0B38B2D9226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE274D15CB6915E7ULL,
		0xE88713AAF9C2A449ULL,
		0x25A80BFFD6257C52ULL,
		0x3F18AC53D5F8F560ULL,
		0xF7A4098F2852C12BULL,
		0x22590C5C19F90704ULL,
		0x9095645C255A887CULL,
		0x5AFCBD52A05326DEULL
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
		0x5F9D0D2CC1E0DFAFULL,
		0x3F46C402040538A4ULL,
		0x478DA9CDD12CDEA8ULL,
		0x1DFEDE503C2FD871ULL,
		0x4C05B3C19E9E7F58ULL,
		0x264076673CBFEA30ULL,
		0xD6FB6D7E68698627ULL,
		0xE43FF99BBA011E16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34C94BEFD7E7DF8ULL,
		0x2C9559B95E531CFCULL,
		0xB93B0EDAEE0A673AULL,
		0x76F4442CCA2061BDULL,
		0xADF8BF2C04806C52ULL,
		0xD8438B59DABA767DULL,
		0xB21ADE66C1C0FC8DULL,
		0xF6F2EE5098FC5AA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C50786DC46261B7ULL,
		0x12B16A48A5B21BA7ULL,
		0x8E529AF2E322776EULL,
		0xA70A9A23720F76B3ULL,
		0x9E0CF4959A1E1305ULL,
		0x4DFCEB0D620573B2ULL,
		0x24E08F17A6A88999ULL,
		0xED4D0B4B2104C372ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB6CA12F859A84BCAULL,
		0xC0E0409ED5D12B42ULL,
		0x22FE0DC25584C303ULL,
		0xBBDF7332998D50BBULL,
		0x176B640A1B3A35AAULL,
		0x459DE14BB580CB35ULL,
		0x60E35B3BADC73AEFULL,
		0x3B9DD89128266A7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8750576A4147784EULL,
		0xB380C3168A396EFEULL,
		0xF813C79638BDBE1FULL,
		0x5388E388F3A7BA3AULL,
		0x1863E7BA747BF836ULL,
		0x598DF2AC50FAB8AAULL,
		0x025F83A56BC6FA95ULL,
		0x973B0FD19A35FD03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F79BB8E1860D37CULL,
		0x0D5F7D884B97BC44ULL,
		0x2AEA462C1CC704E4ULL,
		0x68568FA9A5E59680ULL,
		0xFF077C4FA6BE3D74ULL,
		0xEC0FEE9F6486128AULL,
		0x5E83D79642004059ULL,
		0xA462C8BF8DF06D7AULL
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
		0x77B025496E55E5ACULL,
		0x8BD594743DBFF0B1ULL,
		0xA42B4911388CCDFDULL,
		0x32058DC9E5A42645ULL,
		0xF02A7DEFC69D8467ULL,
		0x3CD6956370BE7D04ULL,
		0x93B1D2F8C57BAD22ULL,
		0x364B83365FB3EF58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC0037B639B6A89ULL,
		0x24A22A05508DCABFULL,
		0xFDB2F5E6C5FCAFE8ULL,
		0xCF8E6504A3DB54ACULL,
		0x1BE1E8985BBE8BB6ULL,
		0xC7A5FE0DBED98667ULL,
		0x4CCA6D0366D9FF06ULL,
		0x149880EC5674A8B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCF021CE0ABA7B23ULL,
		0x67336A6EED3225F1ULL,
		0xA678532A72901E15ULL,
		0x627728C541C8D198ULL,
		0xD44895576ADEF8B0ULL,
		0x75309755B1E4F69DULL,
		0x46E765F55EA1AE1BULL,
		0x21B3024A093F46A3ULL
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
		0x4AE126979F5F9A79ULL,
		0xF95063688EE9B957ULL,
		0x76DEE7D940C52901ULL,
		0x748DA017A6224AD4ULL,
		0xC970CCDEE03F6076ULL,
		0x150E1EF1A3BFC57CULL,
		0x2CD40D6DAFB8453BULL,
		0x3ECACD972C69DF0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x835BFF5A91996957ULL,
		0xEB02FDF37C43C52DULL,
		0xA78B8B4327E288F4ULL,
		0x76E61BEA57844A49ULL,
		0x562B446042ACB992ULL,
		0x2D5AF60652F5F0DAULL,
		0x74584D814AC4C4F9ULL,
		0x67D037A13AE33013ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC785273D0DC63122ULL,
		0x0E4D657512A5F429ULL,
		0xCF535C9618E2A00DULL,
		0xFDA7842D4E9E008AULL,
		0x7345887E9D92A6E3ULL,
		0xE7B328EB50C9D4A2ULL,
		0xB87BBFEC64F38041ULL,
		0xD6FA95F5F186AEF7ULL
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
		0x88EBBEA1F8EBCAD2ULL,
		0xD5C7EA746CD2ACD7ULL,
		0x06C9E67BCD1023D1ULL,
		0x6B2C89F78409789BULL,
		0xA559E1CD966B3327ULL,
		0xC81DBC0199DB1521ULL,
		0xE97D4404C72957BAULL,
		0xE895744F3B6ED15DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0BCD1E0723C13ECULL,
		0xC999BD088C96D54BULL,
		0x4A507888625B23C5ULL,
		0xCC130D5661F75423ULL,
		0x0312C60350062AE8ULL,
		0xA4986D96AB7893B2ULL,
		0x88243DFB07A38904ULL,
		0x4C99147E3842F6EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB82EECC186AFB6E6ULL,
		0x0C2E2D6BE03BD78BULL,
		0xBC796DF36AB5000CULL,
		0x9F197CA122122477ULL,
		0xA2471BCA4665083EULL,
		0x23854E6AEE62816FULL,
		0x61590609BF85CEB6ULL,
		0x9BFC5FD1032BDA72ULL
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
		0x80A3CBBF34F7B2C7ULL,
		0x0F513D0513BACF23ULL,
		0x33C2E0F95754A0BAULL,
		0x00942E0844165C4FULL,
		0x23069DB71926DE2BULL,
		0x3A8A06A43CF83F7CULL,
		0x2B8A9878B9145AA2ULL,
		0xFE4E0946F455F285ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x560E90062210645CULL,
		0x6FB746E0C8EF9407ULL,
		0x84C74E3560ED7A70ULL,
		0x6F8BFCADCB2DB773ULL,
		0x62B0CC890754FE5FULL,
		0x161AA8599B19C3F2ULL,
		0x992B7D1D25C1D5B7ULL,
		0xE93686153B28F315ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A953BB912E74E6BULL,
		0x9F99F6244ACB3B1CULL,
		0xAEFB92C3F6672649ULL,
		0x9108315A78E8A4DBULL,
		0xC055D12E11D1DFCBULL,
		0x246F5E4AA1DE7B89ULL,
		0x925F1B5B935284EBULL,
		0x15178331B92CFF6FULL
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
		0xBA877800A544BE8DULL,
		0x3FFB9F8CDE830327ULL,
		0x462C42E774C1A906ULL,
		0x473C926FF7D4ACB8ULL,
		0xB1195A7AC2F81CF0ULL,
		0xAC9A83821362F212ULL,
		0xA8913D101D97F408ULL,
		0xAD16EF173B8997FFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9627337AC7CEA2ULL,
		0xEA300365317C65EAULL,
		0x304EA29942DA74F3ULL,
		0x5021FB6FD08186E5ULL,
		0x2F391DCBCC6E9921ULL,
		0xCC8BED4028D1FEE2ULL,
		0x01BBBDCEC0F8120EULL,
		0x50066818FFF37DC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF150CD2A7CEFEBULL,
		0x55CB9C27AD069D3CULL,
		0x15DDA04E31E73412ULL,
		0xF71A9700275325D3ULL,
		0x81E03CAEF68983CEULL,
		0xE00E9641EA90F330ULL,
		0xA6D57F415C9FE1F9ULL,
		0x5D1086FE3B961A36ULL
	}};
	sign = 0;
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
		0xAF5663958BA5EEEDULL,
		0xCB2A2FC3ECE1FDADULL,
		0xC3A85652CC6A52EEULL,
		0x70B886236C72EDECULL,
		0x1052C56FE61FE390ULL,
		0x263CC6FF92586157ULL,
		0x8999257CE2040D87ULL,
		0xE987100F1B79FAA4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x67FE7D300C0BBA17ULL,
		0x95A5F873FE6909EDULL,
		0x6C61FB31AF5ECA90ULL,
		0x293554F5138FB021ULL,
		0x97D0C329EB152926ULL,
		0xFA0C69A9A0EEA1E1ULL,
		0x4386BE096EB7674EULL,
		0xA8F18754CFEEA574ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4757E6657F9A34D6ULL,
		0x3584374FEE78F3C0ULL,
		0x57465B211D0B885EULL,
		0x4783312E58E33DCBULL,
		0x78820245FB0ABA6AULL,
		0x2C305D55F169BF75ULL,
		0x46126773734CA638ULL,
		0x409588BA4B8B5530ULL
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
		0xAB73C8C2F24DE3D6ULL,
		0xB1D78AF0AED6DB4FULL,
		0xD9D23CCD102F2A6BULL,
		0xEA7ED9D7F22F068EULL,
		0xA46240C91DA30331ULL,
		0xB06B82DF3C4D8CB0ULL,
		0x32467487C79987DBULL,
		0x3E23366EF74020ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11448D7769EE5C9EULL,
		0xE56D6F06B8C44E23ULL,
		0xB8F8F4281C0059FCULL,
		0xB1A2E17299410AE7ULL,
		0xC435FB049CEBA300ULL,
		0xABEBF9E0659AF5C8ULL,
		0x5A131613716A92CDULL,
		0xC741CCE244ECDAD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A2F3B4B885F8738ULL,
		0xCC6A1BE9F6128D2CULL,
		0x20D948A4F42ED06EULL,
		0x38DBF86558EDFBA7ULL,
		0xE02C45C480B76031ULL,
		0x047F88FED6B296E7ULL,
		0xD8335E74562EF50EULL,
		0x76E1698CB25345DBULL
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
		0x362198AA43A31D5BULL,
		0x2873F8E5331DF72DULL,
		0x8F8A4FA4A2CE1453ULL,
		0xC350EB72830CAC9BULL,
		0x333C221945C34C88ULL,
		0x800EFD3AAFBAE0B4ULL,
		0x851DF6312299DB76ULL,
		0x25733362DE39DCE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE04E27D5B561B1DULL,
		0xD275571DB97F2F20ULL,
		0x3732E27787AD6D1CULL,
		0x6DD51BACF34BD696ULL,
		0xADE1E5E730F621E8ULL,
		0x546A983C733A79EAULL,
		0xEE57594B128B9A76ULL,
		0xA5A378F619F48D9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x381CB62CE84D023EULL,
		0x55FEA1C7799EC80CULL,
		0x58576D2D1B20A736ULL,
		0x557BCFC58FC0D605ULL,
		0x855A3C3214CD2AA0ULL,
		0x2BA464FE3C8066C9ULL,
		0x96C69CE6100E4100ULL,
		0x7FCFBA6CC4454F42ULL
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
		0x019E180DEBEDF69DULL,
		0x853CC9AEF92C955EULL,
		0xF5FC34EE43EC0AACULL,
		0x48E240D3D97CA5F3ULL,
		0xE085D06BE1255F1BULL,
		0x29B34B76849DD9D0ULL,
		0x11034F64DE502A09ULL,
		0x5F4D5C7C3B844FDDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x45AF410FD673218BULL,
		0xE03EA911DE40C736ULL,
		0xA3A81A01D5F08F44ULL,
		0x587887543FCE97F1ULL,
		0x043C4A0BEA97BC75ULL,
		0x0887DE6857E0353CULL,
		0x135C530360A026BDULL,
		0x2DC69516E2547039ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBEED6FE157AD512ULL,
		0xA4FE209D1AEBCE27ULL,
		0x52541AEC6DFB7B67ULL,
		0xF069B97F99AE0E02ULL,
		0xDC49865FF68DA2A5ULL,
		0x212B6D0E2CBDA494ULL,
		0xFDA6FC617DB0034CULL,
		0x3186C765592FDFA3ULL
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
		0x55AFFAFC68FBBF26ULL,
		0x1507F157739645AEULL,
		0x5EE7E142FC7390E8ULL,
		0x79181A8B3775C9C7ULL,
		0xD60A3A703402B1BDULL,
		0x6EDE1985C4E7AAC0ULL,
		0xCA011D5285C8E4D6ULL,
		0x538A83B97EDA2D85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A775C12B02BFD54ULL,
		0xFD538F0FAAA4D600ULL,
		0xD3B8C64C2638E36DULL,
		0x94E8DADECB14FC54ULL,
		0xC5B2EF52BF46D22FULL,
		0xEBF9AD9C96E4935CULL,
		0x405296320BB6B121ULL,
		0x64511E7BF47E6E25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB389EE9B8CFC1D2ULL,
		0x17B46247C8F16FADULL,
		0x8B2F1AF6D63AAD7AULL,
		0xE42F3FAC6C60CD72ULL,
		0x10574B1D74BBDF8DULL,
		0x82E46BE92E031764ULL,
		0x89AE87207A1233B4ULL,
		0xEF39653D8A5BBF60ULL
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
		0xA3F81EBB45D12783ULL,
		0x5E4293C128D37651ULL,
		0x1E56CE8E33D978E7ULL,
		0xFD1E14970C671308ULL,
		0x9F16620E6DA76F92ULL,
		0x4587C4817EBA70C9ULL,
		0xCD76B74B5A9F6653ULL,
		0x795148AABFCCFB2EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECF19593F74CA39ULL,
		0x68FEDB9AD41A4D4AULL,
		0x6D39324463C919A2ULL,
		0x1682F1CFA291071BULL,
		0xC6FA5FA2C1CD3FA2ULL,
		0x3E4CDAA8EF12708DULL,
		0xADEE5A62DE5F244DULL,
		0x349AA91CE950ED20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85290562065C5D4AULL,
		0xF543B82654B92907ULL,
		0xB11D9C49D0105F44ULL,
		0xE69B22C769D60BECULL,
		0xD81C026BABDA2FF0ULL,
		0x073AE9D88FA8003BULL,
		0x1F885CE87C404206ULL,
		0x44B69F8DD67C0E0EULL
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
		0xBE27217CDF44E3C6ULL,
		0x18D8DB8A546B2433ULL,
		0x7E10800BEA1E2985ULL,
		0x3B829B512F7AB7F6ULL,
		0x0EC34142F5AEAFCEULL,
		0xF8247A5DADE4A416ULL,
		0xD7CDA63E86120F9FULL,
		0xE9653A4866C251B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A380F93071AAAAULL,
		0x0E3C38233FE8FB64ULL,
		0x523116877BCF20DCULL,
		0x3F8861D1752EBFD1ULL,
		0x569BFC36E7B812FAULL,
		0x18E7CE72F0707D79ULL,
		0xCEFEA0ED3F2003D4ULL,
		0xE458A170DEF2EDA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA83A083AED3391CULL,
		0x0A9CA367148228CFULL,
		0x2BDF69846E4F08A9ULL,
		0xFBFA397FBA4BF825ULL,
		0xB827450C0DF69CD3ULL,
		0xDF3CABEABD74269CULL,
		0x08CF055146F20BCBULL,
		0x050C98D787CF6415ULL
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
		0x82430BEA03BFE656ULL,
		0x378076562D8837BEULL,
		0x52B373E5BFE78839ULL,
		0xC3C71D53F18B2615ULL,
		0xE89D6BE62D7B8C0FULL,
		0x28D4D05A0552A568ULL,
		0x82E6F060B0B77F9EULL,
		0x01F8B52C8A850101ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB886F96032EF00ULL,
		0x5D4A6BC6364E6B99ULL,
		0x7D558E37F787DA8CULL,
		0x0BCA3423CF33F41CULL,
		0x68E31A372619960AULL,
		0x8AA71C31FBEF4431ULL,
		0xE0FB232C689A2E48ULL,
		0x1055FD9C62DB3581ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58A84F0A38CF756ULL,
		0xDA360A8FF739CC24ULL,
		0xD55DE5ADC85FADACULL,
		0xB7FCE930225731F8ULL,
		0x7FBA51AF0761F605ULL,
		0x9E2DB42809636137ULL,
		0xA1EBCD34481D5155ULL,
		0xF1A2B79027A9CB7FULL
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
		0x8B2C085493B928B5ULL,
		0xD189B9012363DD48ULL,
		0x95A96E834B5A2FD3ULL,
		0x54E182271E6C46F4ULL,
		0xA5324DAB430C95A9ULL,
		0x8C4F10A493681C3AULL,
		0x4BB7443D7CDCC6A2ULL,
		0x6D69A30FA7357F01ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8945BFCC77DA596BULL,
		0x223612EE8B3A6A32ULL,
		0xFA95EE111FFB72D2ULL,
		0x17CF2C26EC63A94BULL,
		0xB5303A832AA6CB86ULL,
		0xC9EB49303C9980B1ULL,
		0x42B5757409CE8978ULL,
		0x7959A37124BD3ED9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E648881BDECF4AULL,
		0xAF53A61298297316ULL,
		0x9B1380722B5EBD01ULL,
		0x3D12560032089DA8ULL,
		0xF00213281865CA23ULL,
		0xC263C77456CE9B88ULL,
		0x0901CEC9730E3D29ULL,
		0xF40FFF9E82784028ULL
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
		0x2667033632DE7EB0ULL,
		0xFABEF2ADA3EF868BULL,
		0x408993623AB0121DULL,
		0x1CD6DE814A1993DFULL,
		0x9FE4B08F925281B6ULL,
		0x0A097570E93E2D33ULL,
		0x08811B10361E3CE9ULL,
		0xD09FBA19A1CD92C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x741FA0F3072D0F10ULL,
		0x39A3C5EA931750B2ULL,
		0x11825633DA8AD607ULL,
		0x94F1E03C780D32F9ULL,
		0x85C36C847A783ACDULL,
		0xAF60077D085CE85FULL,
		0xE7E2C6C33F911CAAULL,
		0xB891434F06124DAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB24762432BB16FA0ULL,
		0xC11B2CC310D835D8ULL,
		0x2F073D2E60253C16ULL,
		0x87E4FE44D20C60E6ULL,
		0x1A21440B17DA46E8ULL,
		0x5AA96DF3E0E144D4ULL,
		0x209E544CF68D203EULL,
		0x180E76CA9BBB4516ULL
	}};
	sign = 0;
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
		0x0502599B8E79C4AAULL,
		0x32D96A386C761939ULL,
		0x4487D8F31AFAC8A1ULL,
		0xFC96BD683752AE22ULL,
		0xBB324DDA9AB68C6CULL,
		0x2EFEE117D53069F5ULL,
		0x7940C85B141B4223ULL,
		0x834672A27CA00B65ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C4A31CCA3F7A7AULL,
		0x549B8A7E7C81F892ULL,
		0x4BD4F37F1737A738ULL,
		0x0490D6187272471BULL,
		0xFC8551E84DA5E7ECULL,
		0x84A43CA1ACCA7380ULL,
		0x7224C3439E68643DULL,
		0x11C4099CA96F1F0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023DB67EC43A4A30ULL,
		0xDE3DDFB9EFF420A7ULL,
		0xF8B2E57403C32168ULL,
		0xF805E74FC4E06706ULL,
		0xBEACFBF24D10A480ULL,
		0xAA5AA4762865F674ULL,
		0x071C051775B2DDE5ULL,
		0x71826905D330EC5AULL
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
		0x1DC1CFC9BDDC1D11ULL,
		0x21756EC9AD4ED226ULL,
		0xECB1EE0E2977AAFDULL,
		0xF8D2459E249B3872ULL,
		0xA0B9C38EC8A6EB3EULL,
		0x9FF197A5AAE6A018ULL,
		0xE4DDA4421A49C0BFULL,
		0x1EDB6142333BB5BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9BD3FD7DADEB61AULL,
		0x2AF03BCDAD7CEE01ULL,
		0x53F301FBF9D451E3ULL,
		0x019393F02F034DF1ULL,
		0x2104C9947467BB83ULL,
		0xA325DC02EE8EAD79ULL,
		0x4DA25036FBEDEC59ULL,
		0x8A775DB5051B9BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64048FF1E2FD66F7ULL,
		0xF68532FBFFD1E424ULL,
		0x98BEEC122FA35919ULL,
		0xF73EB1ADF597EA81ULL,
		0x7FB4F9FA543F2FBBULL,
		0xFCCBBBA2BC57F29FULL,
		0x973B540B1E5BD465ULL,
		0x9464038D2E2019D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x82BE3FC47B28B743ULL,
		0xF2274643CC9B621AULL,
		0xFFCC81600BFD2656ULL,
		0x4CE514E63A6953FDULL,
		0xF9E35B2FCDF01DEAULL,
		0xF12589707E1F4F3BULL,
		0x2D25A5183B82AA68ULL,
		0x0D385191E4F4B2ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB7AEAD8C145FCABULL,
		0xAD2F5657582C71DCULL,
		0xF6F9F2CFCCF52D09ULL,
		0x5FE6F25FFF752E66ULL,
		0xFAB45314A4B4350EULL,
		0x5F592E10F6D5ABE1ULL,
		0x14F826F54EBA349BULL,
		0x0F8EEDE3F749F8EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x874354EBB9E2BA98ULL,
		0x44F7EFEC746EF03DULL,
		0x08D28E903F07F94DULL,
		0xECFE22863AF42597ULL,
		0xFF2F081B293BE8DBULL,
		0x91CC5B5F8749A359ULL,
		0x182D7E22ECC875CDULL,
		0xFDA963ADEDAAB9C3ULL
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
		0xF8FB34FEB7E4E6DFULL,
		0x28EFDC705C62EA25ULL,
		0xF9E99EC000986ED0ULL,
		0xA3978497D79C80D3ULL,
		0x0AD38A350C1F1768ULL,
		0x8959CBCD9F86C9FDULL,
		0x7AE4AB5BAFD1FD3FULL,
		0x09EC6AB03AD45A17ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B6DDC483C62D3F0ULL,
		0x87C3F4F71174159FULL,
		0x0F95AD5E3C49F4FDULL,
		0x94D35BA96F68DFD4ULL,
		0xC75C006E2D20CDABULL,
		0xD1AEF230C777AEF8ULL,
		0xB5F64122C62A195BULL,
		0xAADB622CD85C08E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D8D58B67B8212EFULL,
		0xA12BE7794AEED486ULL,
		0xEA53F161C44E79D2ULL,
		0x0EC428EE6833A0FFULL,
		0x437789C6DEFE49BDULL,
		0xB7AAD99CD80F1B04ULL,
		0xC4EE6A38E9A7E3E3ULL,
		0x5F1108836278512FULL
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
		0x7A6FABF5523B9103ULL,
		0x56C5271058D78428ULL,
		0x8F9FC8921784B6D2ULL,
		0x16F5CDA06D3443CEULL,
		0xAEFE97CBA04AD70AULL,
		0x21B63347A950E451ULL,
		0x2F0323BB20C101A1ULL,
		0x3624582FEB965045ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x739DB5285A820622ULL,
		0x2AA63C83F585867AULL,
		0x9B00D315BDFECB2CULL,
		0x1F4E9F17A860C628ULL,
		0xF53377806DF9F3AEULL,
		0x98036AB24D467D2BULL,
		0x5FB1BC7CF906C044ULL,
		0x74017CD02A860F22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06D1F6CCF7B98AE1ULL,
		0x2C1EEA8C6351FDAEULL,
		0xF49EF57C5985EBA6ULL,
		0xF7A72E88C4D37DA5ULL,
		0xB9CB204B3250E35BULL,
		0x89B2C8955C0A6725ULL,
		0xCF51673E27BA415CULL,
		0xC222DB5FC1104122ULL
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
		0x499AF51F15F15A4BULL,
		0xF7087B12930A70D4ULL,
		0xF050432935376217ULL,
		0x893B25A7FDB780BDULL,
		0xA406E8C6DB6B9203ULL,
		0x6A6440AB9D382EA3ULL,
		0x85780F2A704EBEE5ULL,
		0xE6378206C3C4E46AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE42B96AF796D8E2ULL,
		0x69B68E6873DEC73CULL,
		0x6FBE37BD75D1E45EULL,
		0xF66AD8CA8AC87E02ULL,
		0xAFFDDEECFBF064C0ULL,
		0x06DA37FAADB663E1ULL,
		0xA8896BFDC3C1E55AULL,
		0xB6046C52122F3793ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B583BB41E5A8169ULL,
		0x8D51ECAA1F2BA997ULL,
		0x80920B6BBF657DB9ULL,
		0x92D04CDD72EF02BBULL,
		0xF40909D9DF7B2D42ULL,
		0x638A08B0EF81CAC1ULL,
		0xDCEEA32CAC8CD98BULL,
		0x303315B4B195ACD6ULL
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
		0xA2AC0A4A89041C17ULL,
		0x6A11BC4C06AB669DULL,
		0xE907D3E5292AD9F5ULL,
		0xB4D8095B5A19ED6DULL,
		0xA40A63A8FAEBB8C6ULL,
		0x479F1AA829C5F96DULL,
		0x78A59EC0892A4DFEULL,
		0x1DE3F462146985CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F36EB20E32D031ULL,
		0xB5882EB3E648EC27ULL,
		0x0DB24ADEBEFCE4A6ULL,
		0x2A8DB9512C18C41AULL,
		0x4235D01C1378B600ULL,
		0x0FF088970C0BD5C8ULL,
		0xDBBF07AD8CA43079ULL,
		0x6ADD7688BEE769E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98B89B987AD14BE6ULL,
		0xB4898D9820627A76ULL,
		0xDB5589066A2DF54EULL,
		0x8A4A500A2E012953ULL,
		0x61D4938CE77302C6ULL,
		0x37AE92111DBA23A5ULL,
		0x9CE69712FC861D85ULL,
		0xB3067DD955821BEAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x94A00BB5A9EDF667ULL,
		0x721DC7930AA124BDULL,
		0x975A945D6E3D735AULL,
		0xD9C42A13AB89128CULL,
		0x10CDA2734DDFA806ULL,
		0x03FC5748D6696CC6ULL,
		0x5BC72AF50156103AULL,
		0x932115D9A5BE146BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6571ECFEAC59985FULL,
		0x11E46FFBC1C8E929ULL,
		0x9DC763AF6D183BE6ULL,
		0x79C11D7D1FC2A6FEULL,
		0xC6D9B7D971BAEADFULL,
		0x505EC32164811ED6ULL,
		0xDA7138AF4403C74DULL,
		0x8D4E629802B1C647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F2E1EB6FD945E08ULL,
		0x6039579748D83B94ULL,
		0xF99330AE01253774ULL,
		0x60030C968BC66B8DULL,
		0x49F3EA99DC24BD27ULL,
		0xB39D942771E84DEFULL,
		0x8155F245BD5248ECULL,
		0x05D2B341A30C4E23ULL
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
		0xA92A144D6AA2C6E0ULL,
		0xCFE2807B1194C64EULL,
		0x405B92F6F33102F7ULL,
		0xAB08406EDBCE0749ULL,
		0x9322AA06B3576FECULL,
		0x851D07F33D87A2ADULL,
		0xEBBA4E2993E31733ULL,
		0x64F6E1FE505B3B2AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x469333533C2E316EULL,
		0x044C836CA75D4ED3ULL,
		0xA8AFD693A4BA4820ULL,
		0x4AE37A8906E1CC50ULL,
		0xF57A308A126AA783ULL,
		0xB092DF014A45FC57ULL,
		0x95751A491741029FULL,
		0xC3622EB3EE5AB9F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6296E0FA2E749572ULL,
		0xCB95FD0E6A37777BULL,
		0x97ABBC634E76BAD7ULL,
		0x6024C5E5D4EC3AF8ULL,
		0x9DA8797CA0ECC869ULL,
		0xD48A28F1F341A655ULL,
		0x564533E07CA21493ULL,
		0xA194B34A62008136ULL
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
		0xE792DADF6E167310ULL,
		0x1CC4ADDAF1DAD2A3ULL,
		0x36D294AA6FD4A612ULL,
		0xF22441BDA954DEECULL,
		0x7E4C8D1F92DEE52FULL,
		0x0D17E582CBC517D6ULL,
		0xC16BECBC82ACF32CULL,
		0x54FC83FCC4A09E5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A0EB650361497F4ULL,
		0x91DDA5778C371F16ULL,
		0x3C912F8B6B1504D6ULL,
		0x2915DCBA1540140AULL,
		0x72FEAAED1334D7C1ULL,
		0x7AF7599DCC593841ULL,
		0xBF175B2C1F3CAD7BULL,
		0x2708973DD2C65489ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD84248F3801DB1CULL,
		0x8AE7086365A3B38DULL,
		0xFA41651F04BFA13BULL,
		0xC90E65039414CAE1ULL,
		0x0B4DE2327FAA0D6EULL,
		0x92208BE4FF6BDF95ULL,
		0x02549190637045B0ULL,
		0x2DF3ECBEF1DA49D4ULL
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
		0x582875C98B69F7FFULL,
		0x47AADBAF0EB592E9ULL,
		0x3AEACC2F85EBF3EEULL,
		0x8C7A9CD9BB537BC3ULL,
		0x90AA743A9F8B343FULL,
		0x012967DDA8C1E557ULL,
		0x0627705BB882C9D5ULL,
		0x8043BD702F036CEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B731E835A3782A9ULL,
		0x8A60A40926196606ULL,
		0xE4F094BCB72AEE45ULL,
		0xC79BA92C2ED32A5EULL,
		0xEA99A2F0EA12F497ULL,
		0x7D46FAA54B65AA66ULL,
		0xB85F178512A80C98ULL,
		0xD5F3F2D67B443DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CB5574631327556ULL,
		0xBD4A37A5E89C2CE3ULL,
		0x55FA3772CEC105A8ULL,
		0xC4DEF3AD8C805164ULL,
		0xA610D149B5783FA7ULL,
		0x83E26D385D5C3AF0ULL,
		0x4DC858D6A5DABD3CULL,
		0xAA4FCA99B3BF2EF5ULL
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
		0x35FDD24F0B376381ULL,
		0x161492769268F26EULL,
		0x5D101EC2E16CE5BEULL,
		0xF08294C7867DE47AULL,
		0x93322398BCA70118ULL,
		0x5D30AADFDE6387C1ULL,
		0x08F30405551A2CB9ULL,
		0x4A6104592D688269ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5552FA811073AE76ULL,
		0x77C0FE4B4B167716ULL,
		0x03B23C9299147D60ULL,
		0x1B26E52FC0DAD706ULL,
		0x3DD4072152E1C386ULL,
		0x6826BA782AEF90A3ULL,
		0x5239F6838EC0DF47ULL,
		0xC7806C48D07DE832ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0AAD7CDFAC3B50BULL,
		0x9E53942B47527B57ULL,
		0x595DE2304858685DULL,
		0xD55BAF97C5A30D74ULL,
		0x555E1C7769C53D92ULL,
		0xF509F067B373F71EULL,
		0xB6B90D81C6594D71ULL,
		0x82E098105CEA9A36ULL
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
		0x4CE4EBC5CFB48B83ULL,
		0x62CF2976E4138914ULL,
		0x2D1CBB730442083DULL,
		0x8FE30F0875511AE1ULL,
		0xB8B3EA6EB0FFB18DULL,
		0x89B97CDD52E51C43ULL,
		0xFB882A3E45C8545AULL,
		0xCDC36E35E3CF7AC7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x576DF18AF4E2D2B0ULL,
		0x36A8050F1E24057BULL,
		0xF971C541B092EE56ULL,
		0xB61F33842EA07B51ULL,
		0xB64645D3F01121BAULL,
		0x30F71D8F51671504ULL,
		0xC06915082A70C654ULL,
		0xB82D546A5C0FCD58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF576FA3ADAD1B8D3ULL,
		0x2C272467C5EF8398ULL,
		0x33AAF63153AF19E7ULL,
		0xD9C3DB8446B09F8FULL,
		0x026DA49AC0EE8FD2ULL,
		0x58C25F4E017E073FULL,
		0x3B1F15361B578E06ULL,
		0x159619CB87BFAD6FULL
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
		0x21466A9AD5CFC59EULL,
		0xFDD2503EA0F664E1ULL,
		0x4DA638DF64103A50ULL,
		0x3962FFC681DA4BD2ULL,
		0x71D0C6FDA79D7188ULL,
		0x2D03427FEB39C0C7ULL,
		0xB5530657128910E2ULL,
		0x3A6C22EA3318A433ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5268C82E4032F7A7ULL,
		0x2F0BA7CCCE9D3F36ULL,
		0x0519E7374ECB4D88ULL,
		0xC4E57C779225347EULL,
		0xA5E577D99D491599ULL,
		0x2195B169F4B1560EULL,
		0x6BB2F9FF544B36EAULL,
		0xAB4C84AC775E7C98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEDDA26C959CCDF7ULL,
		0xCEC6A871D25925AAULL,
		0x488C51A81544ECC8ULL,
		0x747D834EEFB51754ULL,
		0xCBEB4F240A545BEEULL,
		0x0B6D9115F6886AB8ULL,
		0x49A00C57BE3DD9F8ULL,
		0x8F1F9E3DBBBA279BULL
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
		0x5C30F20827779C18ULL,
		0xC53455A9C180B0B2ULL,
		0x93AAB4BE8DA3896DULL,
		0xFCCE81D0F1F534D2ULL,
		0x9B6589CCD9EB3027ULL,
		0x040A47DC28C7502BULL,
		0xF615D48D5C9A2EBCULL,
		0xDF4C744E0E85AE61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC34C8FDA2220EEULL,
		0xBBB103ED66B45ED4ULL,
		0x5267618AB3230C6EULL,
		0x193F80529FD52D9FULL,
		0x5554FA287ABC2854ULL,
		0x27CFAF71881566B1ULL,
		0x1BEDAB6AC91826EBULL,
		0xE4B8F491779B5C2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD6DA5784D557B2AULL,
		0x098351BC5ACC51DDULL,
		0x41435333DA807CFFULL,
		0xE38F017E52200733ULL,
		0x46108FA45F2F07D3ULL,
		0xDC3A986AA0B1E97AULL,
		0xDA282922938207D0ULL,
		0xFA937FBC96EA5232ULL
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
		0x86B01F28E07B5491ULL,
		0x5DD5CADC363FB09FULL,
		0x0224CDF40B6B3D91ULL,
		0x3BF1E36F2FDD2ECAULL,
		0xD4C5516F6BB9AA00ULL,
		0xF68C83F7904A48E3ULL,
		0x9D85695E2B51D8D6ULL,
		0x7D24634994B45D04ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FEEF9716993E12ULL,
		0x68E16D5CA60207D4ULL,
		0x2E4A3A827147E5E8ULL,
		0x8DE40265AF09AF25ULL,
		0x95FF03A9B32A4D8BULL,
		0x9FB5B7396DE44462ULL,
		0x39B6C4AF080A4239ULL,
		0x0324F95D973472A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4B12F91C9E2167FULL,
		0xF4F45D7F903DA8CAULL,
		0xD3DA93719A2357A8ULL,
		0xAE0DE10980D37FA4ULL,
		0x3EC64DC5B88F5C74ULL,
		0x56D6CCBE22660481ULL,
		0x63CEA4AF2347969DULL,
		0x79FF69EBFD7FEA64ULL
	}};
	sign = 0;
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
		0x2EEBD617E0873434ULL,
		0xF6B536A6FB47546CULL,
		0xA90E6412B545BAE6ULL,
		0x8B901AC05846A723ULL,
		0x3F6DA290741114D2ULL,
		0xF1DE2BA8C9224ED0ULL,
		0xDEC48F1098487CFEULL,
		0x4DEF3FE0A0589B62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC05BB40DB48438FAULL,
		0x887F1B8E645BDF8EULL,
		0xBD2DA3AB5C48B96CULL,
		0x051CA8BCA053820CULL,
		0x70DB873B61EFC074ULL,
		0xEC9B0D330A8355E1ULL,
		0xCCBC14E1958E3A54ULL,
		0xD49CA51576F081FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E90220A2C02FB3AULL,
		0x6E361B1896EB74DDULL,
		0xEBE0C06758FD017AULL,
		0x86737203B7F32516ULL,
		0xCE921B551221545EULL,
		0x05431E75BE9EF8EEULL,
		0x12087A2F02BA42AAULL,
		0x79529ACB29681966ULL
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
		0xBDAEA99FCD0E4081ULL,
		0x7C9C95BD689D4ADBULL,
		0x3937DDA8E5751FE6ULL,
		0x26F475EF7E740FB9ULL,
		0x69D917CD1F4A6480ULL,
		0x2C0F1B69149F01ACULL,
		0x1CECE64E53118DDDULL,
		0xB9087B5A3219D795ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA3EDB68A0419C04ULL,
		0xF896008A05F5226CULL,
		0x016636AEE70A0160ULL,
		0xFACCE70991650C87ULL,
		0x5ECAC76134988B15ULL,
		0x266BEE0356CE8C2BULL,
		0x6841ED80BC79FD69ULL,
		0x8667DBEC265AD041ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF36FCE372CCCA47DULL,
		0x8406953362A8286EULL,
		0x37D1A6F9FE6B1E85ULL,
		0x2C278EE5ED0F0332ULL,
		0x0B0E506BEAB1D96AULL,
		0x05A32D65BDD07581ULL,
		0xB4AAF8CD96979074ULL,
		0x32A09F6E0BBF0753ULL
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
		0xF07E064999F29460ULL,
		0x95C462E2C83AC055ULL,
		0x38A52534B52DE268ULL,
		0xBC492EE9FD5C690EULL,
		0x13E9965D7CE94C9BULL,
		0xB525F37474AD58E9ULL,
		0x07D7829E9054C5EDULL,
		0x85BC0053A070F795ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE397985982BACA4ULL,
		0xE49A441D5F53B2DDULL,
		0x7DB11B1A1F3679B8ULL,
		0xD042A06DF5B30A44ULL,
		0x5CC8A6BC4DB2EC60ULL,
		0xEF27ADC0C0D1C1E2ULL,
		0x48C1ADBAA40D3486ULL,
		0x6AA7A0BA3919B1E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02448CC401C6E7BCULL,
		0xB12A1EC568E70D78ULL,
		0xBAF40A1A95F768AFULL,
		0xEC068E7C07A95EC9ULL,
		0xB720EFA12F36603AULL,
		0xC5FE45B3B3DB9706ULL,
		0xBF15D4E3EC479166ULL,
		0x1B145F99675745B3ULL
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
		0x30AC82B4DCA976DDULL,
		0x6A60DBE47E9BC74FULL,
		0x4F6B0937627628C1ULL,
		0x2922258C32184A8AULL,
		0x32456E0028C5B4B6ULL,
		0x807E658A5778263CULL,
		0x3DA1FC4EDB3B3498ULL,
		0x525E3A6C27B3992AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38EA91558F68DAE2ULL,
		0x47EF69F54FC6DC73ULL,
		0xA15006DDDBE042C0ULL,
		0x57DC47ECFEC5923BULL,
		0x389189881E35889BULL,
		0xF00A3E27427D8681ULL,
		0x9EB9C8DC098621E6ULL,
		0x3F4FAF687A981AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7C1F15F4D409BFBULL,
		0x227171EF2ED4EADBULL,
		0xAE1B02598695E601ULL,
		0xD145DD9F3352B84EULL,
		0xF9B3E4780A902C1AULL,
		0x9074276314FA9FBAULL,
		0x9EE83372D1B512B1ULL,
		0x130E8B03AD1B7E3CULL
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
		0x70948C6E1195ECA8ULL,
		0x4BD92E2102593412ULL,
		0x6A3C3A50FCE44DB7ULL,
		0x0DD3DB228CA76AFDULL,
		0xB8C690050C495AC9ULL,
		0x224FEDA68C0ABC58ULL,
		0x369DEC4F2380CD0CULL,
		0x65B9D8D40AC21439ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8743A7EFA5F8F6ULL,
		0x9F19383D71FBA645ULL,
		0xBA55EFAED4484BB7ULL,
		0x1A7F51EE111F2855ULL,
		0xC1D46D92384F75B2ULL,
		0x154CFDCE5A21B7AAULL,
		0xB21C1356552B2D59ULL,
		0x073ABE6978552963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x710D48C621EFF3B2ULL,
		0xACBFF5E3905D8DCCULL,
		0xAFE64AA2289C01FFULL,
		0xF35489347B8842A7ULL,
		0xF6F22272D3F9E516ULL,
		0x0D02EFD831E904ADULL,
		0x8481D8F8CE559FB3ULL,
		0x5E7F1A6A926CEAD5ULL
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
		0xF702BEE9BDCFFDF5ULL,
		0xDF65251E4C20D98FULL,
		0xFC12E5C707180F81ULL,
		0xBD4C729B4FF70E9AULL,
		0xA6F98BB56C35BEF3ULL,
		0x7755DA59EF046F87ULL,
		0x035F4A948661FAA2ULL,
		0x219BF031ECAB8A60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19554E0B1898985BULL,
		0x6D634263A5B5E715ULL,
		0x2E5C4ED4BF631B6EULL,
		0x243BCE2A0D392D29ULL,
		0xDAE86CC78853906CULL,
		0x447A80E87106F9C9ULL,
		0x22E6B88C85F02D69ULL,
		0x8A6B3983AE2EB1A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDAD70DEA537659AULL,
		0x7201E2BAA66AF27AULL,
		0xCDB696F247B4F413ULL,
		0x9910A47142BDE171ULL,
		0xCC111EEDE3E22E87ULL,
		0x32DB59717DFD75BDULL,
		0xE07892080071CD39ULL,
		0x9730B6AE3E7CD8B9ULL
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
		0x7AF0395E9C3E3454ULL,
		0xD40EDB96F32FDFB3ULL,
		0x5176B81928757A28ULL,
		0xDD632EC20DEFC581ULL,
		0x770D339DACD7499DULL,
		0xDCEE2C468FB9F657ULL,
		0x724D0BB74346E0E3ULL,
		0x52D8EAA7D5662944ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEABD841194DD0B21ULL,
		0x55B2242325BBAE8BULL,
		0x60E121F6B65E0EA2ULL,
		0x43068FC6075B6942ULL,
		0x41EA33DA2EA9FEBAULL,
		0x450D5EEEB116BD54ULL,
		0x65EE44B18DD527D2ULL,
		0xB42EEE0D8C31977DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9032B54D07612933ULL,
		0x7E5CB773CD743127ULL,
		0xF095962272176B86ULL,
		0x9A5C9EFC06945C3EULL,
		0x3522FFC37E2D4AE3ULL,
		0x97E0CD57DEA33903ULL,
		0x0C5EC705B571B911ULL,
		0x9EA9FC9A493491C7ULL
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
		0xF4FE123384560A5EULL,
		0x48F8BA1C22247A5EULL,
		0xF51DE134CAF8E1C7ULL,
		0x698DF665206BB91FULL,
		0xF1D9FEDFD81BF982ULL,
		0xB83DF2B84534ABCDULL,
		0x9FA5AD4058CE6DDEULL,
		0x82D4F9DF4ECA51E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x988E79192B8DE43CULL,
		0xEEADCE6055327D8EULL,
		0xAA2C15DB313B00AFULL,
		0x62DB8D447ABD3339ULL,
		0x0F473AC2FEFDF065ULL,
		0x52A90C2D42923903ULL,
		0x75EA576B63842B11ULL,
		0x14A8E795A8778A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C6F991A58C82622ULL,
		0x5A4AEBBBCCF1FCD0ULL,
		0x4AF1CB5999BDE117ULL,
		0x06B26920A5AE85E6ULL,
		0xE292C41CD91E091DULL,
		0x6594E68B02A272CAULL,
		0x29BB55D4F54A42CDULL,
		0x6E2C1249A652C7D7ULL
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
		0x61443D5C38AE798BULL,
		0xD61500AE4D0790E6ULL,
		0xB19306805033BD52ULL,
		0x38183D9C453F33FEULL,
		0x59012DD94B0D5540ULL,
		0xF96203482F13FD4FULL,
		0xF03C7A85FD1F8334ULL,
		0x8431AF07CAB43366ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D41EFC8F5120684ULL,
		0x739B9E9670378B34ULL,
		0x0BB08A15268667D1ULL,
		0xB1AC07ACC1ABD571ULL,
		0x9D4D87723EBC087BULL,
		0x4B62F81009A8FA49ULL,
		0x99EF04270F71D935ULL,
		0x40CC044E902D8BDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4024D93439C7307ULL,
		0x62796217DCD005B1ULL,
		0xA5E27C6B29AD5581ULL,
		0x866C35EF83935E8DULL,
		0xBBB3A6670C514CC4ULL,
		0xADFF0B38256B0305ULL,
		0x564D765EEDADA9FFULL,
		0x4365AAB93A86A788ULL
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
		0x6667FD6B56BC9FC2ULL,
		0x8B6824D38F9A6798ULL,
		0x22E72DF3B9F8C3C8ULL,
		0x8EC2CC8DB4D29946ULL,
		0xAE2C7894403FA55BULL,
		0x6849CBE65432CB98ULL,
		0x57368D83AED84C3EULL,
		0x2E06359B4553BB40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x237FDC4483A9AAB1ULL,
		0xA96B84EB1F3B10DFULL,
		0x2E9ADED3B039F3D7ULL,
		0x877954DCEBEF6CB6ULL,
		0xB3F37213AB562376ULL,
		0xA6888C741C56670FULL,
		0x3C76FFAA7E9A761CULL,
		0x00893939B2B5D2E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42E82126D312F511ULL,
		0xE1FC9FE8705F56B9ULL,
		0xF44C4F2009BECFF0ULL,
		0x074977B0C8E32C8FULL,
		0xFA39068094E981E5ULL,
		0xC1C13F7237DC6488ULL,
		0x1ABF8DD9303DD621ULL,
		0x2D7CFC61929DE860ULL
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
		0x40BF5D5B264CE4B7ULL,
		0xD86EA3694C4FFCA8ULL,
		0xA63706A39393E222ULL,
		0x6C9F479474EDAC77ULL,
		0xC34A7872ED65C5BCULL,
		0x0793E2CB2A37CD75ULL,
		0x828F842D7E52B524ULL,
		0x8CFACA6684C82A31ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5669E65FD74101B1ULL,
		0x42D69DEEA7F07AC4ULL,
		0xA6D6B6C9E0106A27ULL,
		0xF7263D40F74F536CULL,
		0xBBEE7ADF848919C2ULL,
		0x424FAE725DC0F639ULL,
		0x06BE1D7A0BF11A52ULL,
		0x2E9281C7EB191162ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA5576FB4F0BE306ULL,
		0x9598057AA45F81E3ULL,
		0xFF604FD9B38377FBULL,
		0x75790A537D9E590AULL,
		0x075BFD9368DCABF9ULL,
		0xC5443458CC76D73CULL,
		0x7BD166B372619AD1ULL,
		0x5E68489E99AF18CFULL
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
		0x8E8DEACC14417833ULL,
		0xC1BE35BBF1401CE3ULL,
		0x0AC6F27BE4923E80ULL,
		0xCCAD36BDC220EC99ULL,
		0x380D6CE5D029EE22ULL,
		0x4F7645293E9E24A3ULL,
		0x860A456D3A37CE29ULL,
		0x32F4623C64875978ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEF7A1A8EBD3E5DFULL,
		0x986356DA96172877ULL,
		0x30E0C25E173280FAULL,
		0xAD6F9822C2BE3302ULL,
		0xBA4FA567EB178D19ULL,
		0xECC15CFDBD531336ULL,
		0x8C83589CB0F85A7AULL,
		0x8DA73D08B1E5B845ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF964923286D9254ULL,
		0x295ADEE15B28F46BULL,
		0xD9E6301DCD5FBD86ULL,
		0x1F3D9E9AFF62B996ULL,
		0x7DBDC77DE5126109ULL,
		0x62B4E82B814B116CULL,
		0xF986ECD0893F73AEULL,
		0xA54D2533B2A1A132ULL
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
		0x7A7D0E2201B0B306ULL,
		0x90438791DF61F480ULL,
		0x8FC5A2CBEEDB6AC3ULL,
		0x3791366F0D055C97ULL,
		0x40011ECD918F5803ULL,
		0x9EC470282333909FULL,
		0x7A5EC629D0444C90ULL,
		0xC5420E2970A9391AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x41D1C314F3EDBEACULL,
		0xCF31AA8268B3AFCEULL,
		0xD1945948B2DB6DE7ULL,
		0x868811D814F9FAD6ULL,
		0xD782E0D4116B295FULL,
		0xE854A06EE7611C5FULL,
		0x3669C2E89B097E05ULL,
		0x50CC695E59D3096AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38AB4B0D0DC2F45AULL,
		0xC111DD0F76AE44B2ULL,
		0xBE3149833BFFFCDBULL,
		0xB1092496F80B61C0ULL,
		0x687E3DF980242EA3ULL,
		0xB66FCFB93BD2743FULL,
		0x43F50341353ACE8AULL,
		0x7475A4CB16D62FB0ULL
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
		0xA1EB089A93B8093BULL,
		0xA9E292EA4F325D1CULL,
		0x3A546489FFD98183ULL,
		0x17D65D46CAD92A9CULL,
		0x2C03E8D8417A26FAULL,
		0xFD5625A7FD171806ULL,
		0x54D129D8E836B667ULL,
		0xE4DB4AD6A9B2B6E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD15BAFA7829680FULL,
		0xC4ADD377EAAE90D8ULL,
		0x18D76E9B9DC2288DULL,
		0x423EEF14B64C12FFULL,
		0x82CF031DFA202B4EULL,
		0x9675FE372BEF63F7ULL,
		0x23C196FFDD820DE0ULL,
		0xA56FEEEE788EC73EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4D54DA01B8EA12CULL,
		0xE534BF726483CC43ULL,
		0x217CF5EE621758F5ULL,
		0xD5976E32148D179DULL,
		0xA934E5BA4759FBABULL,
		0x66E02770D127B40EULL,
		0x310F92D90AB4A887ULL,
		0x3F6B5BE83123EFA9ULL
	}};
	sign = 0;
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
		0xF4175EB4E58AD947ULL,
		0x381A054A4D8D4224ULL,
		0x16BD9F0DD10BF8C7ULL,
		0x681F8AB733E7583EULL,
		0x0A96623F35A1DDF9ULL,
		0xEC962971A2A3CB54ULL,
		0x7C01295DFD97D0CCULL,
		0xE9C4A03AE10C6FA1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFB32DF65653068ULL,
		0x6528C027F69AF3F5ULL,
		0x51821259437D2AA6ULL,
		0x27FEBE467FB072DDULL,
		0x4430D0F68D384AB4ULL,
		0x5E084C2E4B9A4854ULL,
		0xDDC7E3C61EAA91E5ULL,
		0xB95FD01287267727ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x581C2BD58025A8DFULL,
		0xD2F1452256F24E2FULL,
		0xC53B8CB48D8ECE20ULL,
		0x4020CC70B436E560ULL,
		0xC6659148A8699345ULL,
		0x8E8DDD43570982FFULL,
		0x9E394597DEED3EE7ULL,
		0x3064D02859E5F879ULL
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
		0x2E00CDA6A8D4428EULL,
		0x8027137B6C8311CBULL,
		0xFD4156269CCDD4C8ULL,
		0x64A9C322C6D0D9A5ULL,
		0x07E6EA4471762793ULL,
		0x9F3A03F637208763ULL,
		0xFE99DB32D1AB0AFCULL,
		0x253125C1BA885566ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7011C1C7FFD6ED48ULL,
		0x7B3F9D90EA68A87AULL,
		0xD02DB8E1F6E29C3AULL,
		0xA0B0314C4F43EE91ULL,
		0x9B38AE610F19799EULL,
		0x43D7A8FCCA996FB1ULL,
		0x45459021852B6B4CULL,
		0xB31D34A37C9FFF44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDEF0BDEA8FD5546ULL,
		0x04E775EA821A6950ULL,
		0x2D139D44A5EB388EULL,
		0xC3F991D6778CEB14ULL,
		0x6CAE3BE3625CADF4ULL,
		0x5B625AF96C8717B1ULL,
		0xB9544B114C7F9FB0ULL,
		0x7213F11E3DE85622ULL
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
		0xF8D47950B77DC9EBULL,
		0x9201D354F02CF02DULL,
		0x5BFE76BD0C67AA6CULL,
		0xF38F320A50B5BDE5ULL,
		0xE6F478217D161EAEULL,
		0xB3921A9D714D1737ULL,
		0xA5DB2E0F88C3726FULL,
		0x6C3148FB62554C11ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7018703569FA76DCULL,
		0x13ACCA1A743D4430ULL,
		0xD8E2A8B23953A294ULL,
		0xB8BC6401CC1780FBULL,
		0x06598A9F0460B969ULL,
		0xEE1AA805E53F8512ULL,
		0xA84AD67BEE174562ULL,
		0x715B4EF953374E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88BC091B4D83530FULL,
		0x7E55093A7BEFABFDULL,
		0x831BCE0AD31407D8ULL,
		0x3AD2CE08849E3CE9ULL,
		0xE09AED8278B56545ULL,
		0xC57772978C0D9225ULL,
		0xFD9057939AAC2D0CULL,
		0xFAD5FA020F1DFDE6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7F42B6DC7ADA7812ULL,
		0xC1F77EC4A3701309ULL,
		0x5A386C8E2A885DE7ULL,
		0x66C0839AD34F5686ULL,
		0xCB70ABC89E705AABULL,
		0x60FC0B2629E91E06ULL,
		0xF351BA4B72E8941AULL,
		0xF8FFDA643FD5536CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x04C3AB9390A6B325ULL,
		0xDC23F72B53D62396ULL,
		0x5869C8B5D5199BA9ULL,
		0x5178F0137E73D576ULL,
		0x62FADF8CABC4D20EULL,
		0x503A54A3C251F3BBULL,
		0x2E904C0DC3410539ULL,
		0x2A210095E74336F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A7F0B48EA33C4EDULL,
		0xE5D387994F99EF73ULL,
		0x01CEA3D8556EC23DULL,
		0x1547938754DB8110ULL,
		0x6875CC3BF2AB889DULL,
		0x10C1B68267972A4BULL,
		0xC4C16E3DAFA78EE1ULL,
		0xCEDED9CE58921C76ULL
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
		0x5AD0B7A5978F3620ULL,
		0x6DBE0AD61A507A37ULL,
		0x21E8B57C0A7A15B8ULL,
		0x8DA02371F70B0B11ULL,
		0x3D988964BBD40188ULL,
		0xE78CE0DD509AE271ULL,
		0x6AEBC11A19FDF611ULL,
		0xD0F1431FE1E290DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA904721A615C35ULL,
		0xE02BDD0DE90CF256ULL,
		0x3FE4FDD516CA9459ULL,
		0x8F289242BACDEC78ULL,
		0x992D0FDEE6488512ULL,
		0x8258AB82EE9917BCULL,
		0xEA0312B6A1CA2959ULL,
		0x868BA73CF6DEB133ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B27B3337D2DD9EBULL,
		0x8D922DC8314387E1ULL,
		0xE203B7A6F3AF815EULL,
		0xFE77912F3C3D1E98ULL,
		0xA46B7985D58B7C75ULL,
		0x6534355A6201CAB4ULL,
		0x80E8AE637833CCB8ULL,
		0x4A659BE2EB03DFA6ULL
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
		0x5FFC54A02961B359ULL,
		0x868D22552751204EULL,
		0x50AC0CC0E943A32CULL,
		0x7B51DA08D62316CEULL,
		0x6426D8DB00CF27E2ULL,
		0xF8D19BC09FC9345AULL,
		0x2E37146194187E2AULL,
		0x2290D36FB7596385ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BDA8011FB078C4ULL,
		0x309DDD221B42DCECULL,
		0x01E374CA09D8C27EULL,
		0x37ACBDD17965474CULL,
		0x3CCEEA9743CF0EF2ULL,
		0x3DFBE344AA159199ULL,
		0xFDF7CB0934EA8C1EULL,
		0x792F18A1C74D3925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B3EAC9F09B13A95ULL,
		0x55EF45330C0E4361ULL,
		0x4EC897F6DF6AE0AEULL,
		0x43A51C375CBDCF82ULL,
		0x2757EE43BD0018F0ULL,
		0xBAD5B87BF5B3A2C1ULL,
		0x303F49585F2DF20CULL,
		0xA961BACDF00C2A5FULL
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
		0x7A7AC6CC07B02853ULL,
		0xEFFB5C94FE5D9A72ULL,
		0xC1BDAFB36767C749ULL,
		0x3452ABEF66BD7C49ULL,
		0xCF8725628C1D3094ULL,
		0xAF6A7F25559126D4ULL,
		0x99455F3286B3755AULL,
		0xD5C62533D6746BF6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB46E66D2F0C9C1CULL,
		0x3C6033C9CFCB21DFULL,
		0x7E0261A888171708ULL,
		0x4824AD949381EC15ULL,
		0xEEE386518E558126ULL,
		0x339EB1ED9AF94990ULL,
		0x858DC1262F9C25B3ULL,
		0x6F102B0739E5BB5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F33E05ED8A38C37ULL,
		0xB39B28CB2E927892ULL,
		0x43BB4E0ADF50B041ULL,
		0xEC2DFE5AD33B9034ULL,
		0xE0A39F10FDC7AF6DULL,
		0x7BCBCD37BA97DD43ULL,
		0x13B79E0C57174FA7ULL,
		0x66B5FA2C9C8EB097ULL
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
		0x41683C8F1C926151ULL,
		0xCDFDE78BBE502BFFULL,
		0x78D73BD4C9D68236ULL,
		0xF3A44AFC4AA5CCF1ULL,
		0x858188229D9B1424ULL,
		0xA3F02C963C21FD7DULL,
		0x0A59D841C6BACEFCULL,
		0x5654737BD3953382ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC62E45E12F93A48ULL,
		0xCF999586EEC513BAULL,
		0x0230D1B368BEFEC0ULL,
		0xF5AE33CBAEF7FBA4ULL,
		0x54197F1FE0A02BCBULL,
		0xF11E59412A4B7F75ULL,
		0xE9B04F5A7D2367C7ULL,
		0x066C7B03F6D33B86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9505583109992709ULL,
		0xFE645204CF8B1844ULL,
		0x76A66A2161178375ULL,
		0xFDF617309BADD14DULL,
		0x31680902BCFAE858ULL,
		0xB2D1D35511D67E08ULL,
		0x20A988E749976734ULL,
		0x4FE7F877DCC1F7FBULL
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
		0x1137E067870CA1F8ULL,
		0xB1C046B1F3D490EDULL,
		0x7BD2C78B58954FB8ULL,
		0xBA3036B877B359E0ULL,
		0x56F570C77E744FACULL,
		0xADC40A742F1DEFC2ULL,
		0xAA70E36D73439D61ULL,
		0x518AD7CFE69FE456ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35C057C94D176017ULL,
		0xE4FF33E5C7ABF590ULL,
		0x247DB9F99D0F6EB6ULL,
		0xACC35431DE15D238ULL,
		0xC287AC91A8ACC680ULL,
		0xAE49C561EBA5914AULL,
		0xFD064EFC799126D8ULL,
		0x2EA17132ED1688F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB77889E39F541E1ULL,
		0xCCC112CC2C289B5CULL,
		0x57550D91BB85E101ULL,
		0x0D6CE286999D87A8ULL,
		0x946DC435D5C7892CULL,
		0xFF7A451243785E77ULL,
		0xAD6A9470F9B27688ULL,
		0x22E9669CF9895B64ULL
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
		0x552927211D5C6519ULL,
		0x6B061DA01D39A2ADULL,
		0x1C8BA808645E4976ULL,
		0x1B85F8D63BABF4F3ULL,
		0x1D79B5508E303C51ULL,
		0x403C41E77584EE93ULL,
		0xFDCED3BB644926FEULL,
		0xFF855FD1186639B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB40C5162D7EA18AULL,
		0x8DE1571D8EBAFBF2ULL,
		0x5CC19FE5156B6CC6ULL,
		0x410944AF5CB22076ULL,
		0x1A6B7B001E26CB19ULL,
		0x003E76C18636F479ULL,
		0xD96154480380D654ULL,
		0x513F3BAE4515DBD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E8620AEFDDC38FULL,
		0xDD24C6828E7EA6BAULL,
		0xBFCA08234EF2DCAFULL,
		0xDA7CB426DEF9D47CULL,
		0x030E3A5070097137ULL,
		0x3FFDCB25EF4DFA1AULL,
		0x246D7F7360C850AAULL,
		0xAE462422D3505DE2ULL
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
		0x0DAB7D197BC59872ULL,
		0x4BCD4245FC266BD2ULL,
		0x19AE7A7EC20415D0ULL,
		0x881580D0614C8112ULL,
		0x5037EE4906A10C9BULL,
		0x7B33DB32B371CFF8ULL,
		0x9811210A5ACF1146ULL,
		0x3DCE4F10E635E9CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6601F4D311F77E7FULL,
		0x5879B7F166B3B01DULL,
		0xB26139C10F8F01A8ULL,
		0x69C9CEAB85306AC2ULL,
		0x92A0D5E194650A73ULL,
		0x4A8A4B40DEDB513DULL,
		0x11E44F739308A358ULL,
		0xC33A775957109C82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7A9884669CE19F3ULL,
		0xF3538A549572BBB4ULL,
		0x674D40BDB2751427ULL,
		0x1E4BB224DC1C164FULL,
		0xBD971867723C0228ULL,
		0x30A98FF1D4967EBAULL,
		0x862CD196C7C66DEEULL,
		0x7A93D7B78F254D4CULL
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
		0x923005DFED65CD5FULL,
		0x86C385A800C91F3BULL,
		0x5997C43522B6FBDDULL,
		0x27680E898B1299EFULL,
		0x5D9FE639FA0446B0ULL,
		0x50A4CD57834815B0ULL,
		0xC03EA20EF75ECE8FULL,
		0x47A949A06EB8FE15ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC93EAC31EBBCABULL,
		0xC156FFA2C8F6E25DULL,
		0xF5372AA593B16C56ULL,
		0xDE093F3DD0FBEC3DULL,
		0xDC0D53543BBAAB24ULL,
		0x368010F026571DAAULL,
		0xEF22E9D5AD95152BULL,
		0xB7E3BE585A8513B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA366C733BB7A10B4ULL,
		0xC56C860537D23CDDULL,
		0x6460998F8F058F86ULL,
		0x495ECF4BBA16ADB1ULL,
		0x819292E5BE499B8BULL,
		0x1A24BC675CF0F805ULL,
		0xD11BB83949C9B964ULL,
		0x8FC58B481433EA60ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x148203160202DA69ULL,
		0xC9DBF7AD311C36F7ULL,
		0x03C46D68736067A9ULL,
		0x802307FC85FD0CCAULL,
		0xD18BEEA59CE14603ULL,
		0xBFD356FF867BDE9DULL,
		0xA17A08C791A46E97ULL,
		0xDD76DC5DD137B1BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7364B35EBCB7398ULL,
		0x97E84F2E1B8681BBULL,
		0x33CE6F0D365D4240ULL,
		0x8656675FE0B7CBE2ULL,
		0x41E5342CD6807D4FULL,
		0x18137CB3957AA3B6ULL,
		0x84B48FDC5E81EA59ULL,
		0x5AECA07995EBFD75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4BB7E0163766D1ULL,
		0x31F3A87F1595B53BULL,
		0xCFF5FE5B3D032569ULL,
		0xF9CCA09CA54540E7ULL,
		0x8FA6BA78C660C8B3ULL,
		0xA7BFDA4BF1013AE7ULL,
		0x1CC578EB3322843EULL,
		0x828A3BE43B4BB445ULL
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
		0x2836061A3EF94D9EULL,
		0xB8104CC22E21A747ULL,
		0x3B7C5871F7FD7B4CULL,
		0xDBC0AE443242DD83ULL,
		0x4280FD1C0057B2C9ULL,
		0xF4749E3FB2F2D28DULL,
		0x5D5BD5218E6BE118ULL,
		0x4BDBC0992A6322F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x833EF6B791FE2EDAULL,
		0x9F65E460280B3D5CULL,
		0x32F8838BE03C48C1ULL,
		0x8EE1F5B4E18FACB6ULL,
		0x0BD83186943B57E3ULL,
		0xB02C6C414913F751ULL,
		0x03CB3FF9AA0A41E7ULL,
		0xE2A77B1DB1F476B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4F70F62ACFB1EC4ULL,
		0x18AA6862061669EAULL,
		0x0883D4E617C1328BULL,
		0x4CDEB88F50B330CDULL,
		0x36A8CB956C1C5AE6ULL,
		0x444831FE69DEDB3CULL,
		0x59909527E4619F31ULL,
		0x6934457B786EAC46ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9DD5E0C66A212481ULL,
		0x65D881725C71FAE7ULL,
		0x5DF650122229A92AULL,
		0x912A37AA99D763EBULL,
		0x111B8ECF2F41D661ULL,
		0x0631C7FA7808F83AULL,
		0xBAAF8B3D6364E0FCULL,
		0xA4DFAA139B8B15F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8D0A3BECA62F07ULL,
		0x8FDDD31344F85494ULL,
		0x1CD7BCCEF746E5FBULL,
		0xAF0440841AC06F47ULL,
		0x45698B0999F46E44ULL,
		0xCCE4731E7987853BULL,
		0x134DA13E0EFEE148ULL,
		0xB481A442D54C9E91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD248D68A7D7AF57AULL,
		0xD5FAAE5F1779A652ULL,
		0x411E93432AE2C32EULL,
		0xE225F7267F16F4A4ULL,
		0xCBB203C5954D681CULL,
		0x394D54DBFE8172FEULL,
		0xA761E9FF5465FFB3ULL,
		0xF05E05D0C63E7765ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA14514E2D0447AE3ULL,
		0xCB91DC3A595FB7D7ULL,
		0x8EA215D680400689ULL,
		0x2BDC1F7B20BB4DA7ULL,
		0x09DBA7BE7AD0717CULL,
		0x6BDF129BA3B6C2FBULL,
		0xE56C1338ED8CFECBULL,
		0x8C5E9D34C3D6E9BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF665935CA2FD589ULL,
		0xF288485AFAC63E6CULL,
		0xB76BB54FB38F7D04ULL,
		0xFBAE912C68D1673EULL,
		0x991D894FAEED4244ULL,
		0x2084489BEE740982ULL,
		0x240412AA678EA35DULL,
		0x02219A44088ACC7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1DEBBAD0614A55AULL,
		0xD90993DF5E99796AULL,
		0xD7366086CCB08984ULL,
		0x302D8E4EB7E9E668ULL,
		0x70BE1E6ECBE32F37ULL,
		0x4B5AC9FFB542B978ULL,
		0xC168008E85FE5B6EULL,
		0x8A3D02F0BB4C1D40ULL
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
		0xE76D3ABA18BC0A79ULL,
		0x838B96340AAB9F14ULL,
		0x7961012479E53EACULL,
		0x7528E95B443D166AULL,
		0x306BF6E7F87A676FULL,
		0x712C7308BC28160DULL,
		0x393B016EBE1E53EAULL,
		0x79BC229B1C8F2B3AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9635D3F0C7EB4045ULL,
		0x5711008A9878E48DULL,
		0xFE8CADB7B8E3891BULL,
		0xD5DA6CB764555F72ULL,
		0x57E1A3693B39DBA1ULL,
		0x3E23DF033D1F4DD0ULL,
		0xD46EA1CA5C974108ULL,
		0x6C1C9FAF05764093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x513766C950D0CA34ULL,
		0x2C7A95A97232BA87ULL,
		0x7AD4536CC101B591ULL,
		0x9F4E7CA3DFE7B6F7ULL,
		0xD88A537EBD408BCDULL,
		0x330894057F08C83CULL,
		0x64CC5FA4618712E2ULL,
		0x0D9F82EC1718EAA6ULL
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
		0xF2E80C54A23A7F9DULL,
		0x14B98CB6CFE694F9ULL,
		0x69D8063B5EA01768ULL,
		0x3D8D5195ADCEDE39ULL,
		0x6E27047910811586ULL,
		0xE45BCB4E31DB994CULL,
		0x4739E0BD78D934ACULL,
		0x3B77081D357A7FD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2687AF1F9D50BEULL,
		0xCA1F9D7F23F00C56ULL,
		0x4C5E60CD6F18AFC1ULL,
		0xEB4D4BE14344B972ULL,
		0x9D5F943030DD5A01ULL,
		0xA2753BF7EC00551CULL,
		0x0C8BBB3180D745EAULL,
		0xF7834E91E42AD65DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16C184A5829D2EDFULL,
		0x4A99EF37ABF688A3ULL,
		0x1D79A56DEF8767A6ULL,
		0x524005B46A8A24C7ULL,
		0xD0C77048DFA3BB84ULL,
		0x41E68F5645DB442FULL,
		0x3AAE258BF801EEC2ULL,
		0x43F3B98B514FA973ULL
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
		0xAD0ED53DE3AB1719ULL,
		0x988404CF705613ECULL,
		0x46205C3CC5F14FF9ULL,
		0x6B07CB3A04C3A195ULL,
		0xAE5C96F644E3E4F2ULL,
		0x406400C2F2A39F4FULL,
		0x5B6EE9B629DD4010ULL,
		0xF13A59F5E15E7396ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68FC770507B2E6FULL,
		0x65AF9E896411ECCEULL,
		0x3BD85A03BCF41A2DULL,
		0x3DB57585DC4BD87CULL,
		0x313FE264FA2579C4ULL,
		0xFED41183D4CBD93DULL,
		0xDAD3B9474CC9055AULL,
		0x33177D80B64DF133ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE67F0DCD932FE8AAULL,
		0x32D466460C44271DULL,
		0x0A48023908FD35CCULL,
		0x2D5255B42877C919ULL,
		0x7D1CB4914ABE6B2EULL,
		0x418FEF3F1DD7C612ULL,
		0x809B306EDD143AB5ULL,
		0xBE22DC752B108262ULL
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
		0x6D2477A5E1E5657BULL,
		0xA44CA944018077EEULL,
		0xDD314B4AF99570CDULL,
		0x0A96D7FEF98515FEULL,
		0x3F99D7D5EA52AF5AULL,
		0x6D92471F84C456D9ULL,
		0x899BD4ABEC8FDA6AULL,
		0x415FD6B2A4662BC1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42FB4D676CDC0B2ULL,
		0xBE4A54B3556F7FB4ULL,
		0xA713C0743E3288A5ULL,
		0x6C99B8F988E479FCULL,
		0xAAFC80C7C6F693C7ULL,
		0x7D4E3D61FD906584ULL,
		0xB40B2DD2806F7F69ULL,
		0xAAB2FAC48914F05EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78F4C2CF6B17A4C9ULL,
		0xE6025490AC10F839ULL,
		0x361D8AD6BB62E827ULL,
		0x9DFD1F0570A09C02ULL,
		0x949D570E235C1B92ULL,
		0xF04409BD8733F154ULL,
		0xD590A6D96C205B00ULL,
		0x96ACDBEE1B513B62ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x334887345FD91B57ULL,
		0x30C63A24925387A0ULL,
		0x6CF7ED2ABBF4D8FFULL,
		0x93072A0FB9F48E6EULL,
		0x1661D552CAB7AD37ULL,
		0xFC6C226996EFF9D9ULL,
		0x0317394A0521DE26ULL,
		0x8377DAC292EF9CB2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x385F6E8B98228EECULL,
		0x115B7E87E80C2D55ULL,
		0x7AD2ACEB1CC93871ULL,
		0x05EBC89A479CEA13ULL,
		0x92CA28BB8C94948EULL,
		0x2319C0E00AF8CAAEULL,
		0x357CA4A8060630F2ULL,
		0xBDE3F54A44081307ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAE918A8C7B68C6BULL,
		0x1F6ABB9CAA475A4AULL,
		0xF225403F9F2BA08EULL,
		0x8D1B61757257A45AULL,
		0x8397AC973E2318A9ULL,
		0xD95261898BF72F2AULL,
		0xCD9A94A1FF1BAD34ULL,
		0xC593E5784EE789AAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4ED838096E064FE2ULL,
		0x3D800128CD5211C6ULL,
		0x62E5AEEB68912362ULL,
		0x492CCF8EE6152078ULL,
		0x0FDC8D22FABEE11EULL,
		0xC4989D5D55EC2F96ULL,
		0x6D38E0CEB00AEF7AULL,
		0x4970C02AAF2BADC7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D718A92ADCCD417ULL,
		0x64B571B0B345F456ULL,
		0x19B0E7225F35DAFDULL,
		0x33258CD6D52F8FD2ULL,
		0xDE6582DC1D88F957ULL,
		0xD450E0C2CFC6AA81ULL,
		0xDF8427F92C186EA9ULL,
		0x9D760E321081B03CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4166AD76C0397BCBULL,
		0xD8CA8F781A0C1D70ULL,
		0x4934C7C9095B4864ULL,
		0x160742B810E590A6ULL,
		0x31770A46DD35E7C7ULL,
		0xF047BC9A86258514ULL,
		0x8DB4B8D583F280D0ULL,
		0xABFAB1F89EA9FD8AULL
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
		0x1A156C18B40F9237ULL,
		0x77E860214DD63466ULL,
		0xB71EFD7131718A63ULL,
		0x2FD1985CFC0B2802ULL,
		0xD5939B83812B66B9ULL,
		0xB7B731DF6C110789ULL,
		0xBC41A4FCA1CB1E87ULL,
		0x8C48FCE8BA145337ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB749BC302266377CULL,
		0xDDF55FD4FD1B2A79ULL,
		0x56E4910EB1FFA2DAULL,
		0xA967FDAC5182250DULL,
		0x9FB71890A7FCB8E0ULL,
		0xA814FAE3B9C4EC7AULL,
		0xE4A0A13B996F9A95ULL,
		0x89749265581F9050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62CBAFE891A95ABBULL,
		0x99F3004C50BB09ECULL,
		0x603A6C627F71E788ULL,
		0x86699AB0AA8902F5ULL,
		0x35DC82F2D92EADD8ULL,
		0x0FA236FBB24C1B0FULL,
		0xD7A103C1085B83F2ULL,
		0x02D46A8361F4C2E6ULL
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
		0xD4B99800EDA7FD53ULL,
		0xD8EC219344479645ULL,
		0xD5C7A073DD0AD2B4ULL,
		0x7F505EBEEC16CEB5ULL,
		0x02748FAF5477F031ULL,
		0x466D5F175884CB26ULL,
		0xBC42D8044013816DULL,
		0x8C3986422223C785ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDD19BFEA670171ULL,
		0x0E88E547FBC74699ULL,
		0x7519507CFBA2D796ULL,
		0xEE812334E84ADE59ULL,
		0x246AD4DF6220C91DULL,
		0x4F29F25B6DFCB6E8ULL,
		0x3CA3E427AB81CCE8ULL,
		0x4594E35EBA132D5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7DC7E410340FBE2ULL,
		0xCA633C4B48804FACULL,
		0x60AE4FF6E167FB1EULL,
		0x90CF3B8A03CBF05CULL,
		0xDE09BACFF2572713ULL,
		0xF7436CBBEA88143DULL,
		0x7F9EF3DC9491B484ULL,
		0x46A4A2E368109A27ULL
	}};
	sign = 0;
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
		0xE1D738F1F38C4BFEULL,
		0x7C008D6F1C7FC5BDULL,
		0xB647AE7D5FB4825CULL,
		0x9E018C4910AA603FULL,
		0x2C5BB99827FE1171ULL,
		0xF5B4449E098E5C1FULL,
		0xF2B81B9F2C76583FULL,
		0xADCC6860085CC3C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76334A06448AB43EULL,
		0x5193D283B9D30186ULL,
		0xEC20FF81518D6539ULL,
		0xB0448AF76CB263BAULL,
		0xEF9873916B1EA83DULL,
		0x3255EB7CB730F304ULL,
		0x407D38A3B3FF696EULL,
		0x098AC560E3F0C3FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA3EEEBAF0197C0ULL,
		0x2A6CBAEB62ACC437ULL,
		0xCA26AEFC0E271D23ULL,
		0xEDBD0151A3F7FC84ULL,
		0x3CC34606BCDF6933ULL,
		0xC35E5921525D691AULL,
		0xB23AE2FB7876EED1ULL,
		0xA441A2FF246BFFCFULL
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
		0x2B348584BB29C487ULL,
		0x1EE89D04E07B17E4ULL,
		0x127417E7B3134463ULL,
		0x8E1B270A4F3E65BCULL,
		0x8671CCFEE5CE6F15ULL,
		0xD0A81D3B3F0C24A5ULL,
		0x25EDC62EAD85A473ULL,
		0xE8FDFC0EDE9449C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85EE344169AD9DAFULL,
		0x09D126049D887CA5ULL,
		0x08B9E9DE994E6A6EULL,
		0xCD96CB7C84DD3C21ULL,
		0x3628C2758FFBFC8AULL,
		0x490E17BC8D6ABB44ULL,
		0x482C3CB8A348D7C1ULL,
		0xA10A2005B568CE84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5465143517C26D8ULL,
		0x1517770042F29B3EULL,
		0x09BA2E0919C4D9F5ULL,
		0xC0845B8DCA61299BULL,
		0x50490A8955D2728AULL,
		0x879A057EB1A16961ULL,
		0xDDC189760A3CCCB2ULL,
		0x47F3DC09292B7B3DULL
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
		0x46396D784268097EULL,
		0xF1E04FF5AC09506FULL,
		0xBBC0750D302882BBULL,
		0xC96C742347C65E61ULL,
		0x5CAAC2A24ECAE900ULL,
		0x870C636E44240F1EULL,
		0x1FC0364254E9D922ULL,
		0xC8DC084D887276C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0161028EC08CEE5ULL,
		0xC5D684957EAC0E34ULL,
		0xD79C716D15739378ULL,
		0xD43F7B07E0028822ULL,
		0xFE4E75657A2EA653ULL,
		0xACCA7728D8BE5A0CULL,
		0x859C54BDB4877FF2ULL,
		0xB6F3057C840509C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6235D4F565F3A99ULL,
		0x2C09CB602D5D423AULL,
		0xE42403A01AB4EF43ULL,
		0xF52CF91B67C3D63EULL,
		0x5E5C4D3CD49C42ACULL,
		0xDA41EC456B65B511ULL,
		0x9A23E184A062592FULL,
		0x11E902D1046D6D01ULL
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
		0x99BB95F94FC12503ULL,
		0xEF5F5CC1C956290DULL,
		0x858C4E1BFFAA641AULL,
		0xB7C48AC25AAB0FEFULL,
		0x20B79E441EF560E6ULL,
		0x404AE746545968DBULL,
		0xC3DDB64518ECA1EAULL,
		0x3A4C68699EEBF6CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF423D70D517CD745ULL,
		0xEFC0AFD38EA5FC96ULL,
		0xC64C85C351CEB0D9ULL,
		0xA4F71226F5D393F6ULL,
		0x35ACF094CF6BBAF1ULL,
		0x6F26F5B3EA1082A6ULL,
		0x6BB6B50C7AE42A08ULL,
		0xD151E80E6A45FA21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA597BEEBFE444DBEULL,
		0xFF9EACEE3AB02C76ULL,
		0xBF3FC858ADDBB340ULL,
		0x12CD789B64D77BF8ULL,
		0xEB0AADAF4F89A5F5ULL,
		0xD123F1926A48E634ULL,
		0x582701389E0877E1ULL,
		0x68FA805B34A5FCACULL
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
		0xB829D2B239AA8681ULL,
		0xF4A945BAB8FD90A9ULL,
		0x0A4D9F9FDFB7FDA1ULL,
		0x0B02905AFAF43A7CULL,
		0x971274613B97AFE6ULL,
		0x584978FD0D5E352BULL,
		0xA665F2E75BEAEDB1ULL,
		0xC662070E5FAE225DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F70841BE63A0A4ULL,
		0x5063FB0C29FC76B0ULL,
		0xB0362DC6D149F7C0ULL,
		0x1A954472B7189780ULL,
		0x3636672474FAF1BEULL,
		0xB308E148C38C3541ULL,
		0x2E5EC4714D9F350FULL,
		0x7E203A0D768E746DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA632CA707B46E5DDULL,
		0xA4454AAE8F0119F9ULL,
		0x5A1771D90E6E05E1ULL,
		0xF06D4BE843DBA2FBULL,
		0x60DC0D3CC69CBE27ULL,
		0xA54097B449D1FFEAULL,
		0x78072E760E4BB8A1ULL,
		0x4841CD00E91FADF0ULL
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
		0x77F4058685F8E24CULL,
		0x3882B5939B878CFCULL,
		0x424378AEFF72846BULL,
		0xFCE4FB4E1C55C9F8ULL,
		0x2A0ADF31FA5AE124ULL,
		0xB879FBFE11B0486AULL,
		0x725B35D909A0CCCEULL,
		0x27F629C01515038EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF36023AB5222C1ULL,
		0x9EEFABFFF8C36411ULL,
		0x4B18EE50611192ECULL,
		0xD3F150004EFABF3DULL,
		0xDC9C6B9196DB986AULL,
		0x1BA99C0643A48D2AULL,
		0xAF29E469F2FEC1C5ULL,
		0x5B4E179C3B33C6DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB00A562DAA6BF8BULL,
		0x99930993A2C428EAULL,
		0xF72A8A5E9E60F17EULL,
		0x28F3AB4DCD5B0ABAULL,
		0x4D6E73A0637F48BAULL,
		0x9CD05FF7CE0BBB3FULL,
		0xC331516F16A20B09ULL,
		0xCCA81223D9E13CB2ULL
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
		0xAC57E093A0C6324BULL,
		0x5E27B51FBE96C3E3ULL,
		0xE6BCFABCB49D7EE5ULL,
		0x247A23DDC98B0EAFULL,
		0xA21CBBFBD1287CE5ULL,
		0xD23023A471FF0964ULL,
		0xA4F834536FDCF1C0ULL,
		0x834F9E70430D3844ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CAEFB2A9916C50ULL,
		0x88883C72AE6B8D93ULL,
		0xD2B47990F9A2D9C8ULL,
		0x5CA6EE0F256898D6ULL,
		0x21317B7F6D23FB5DULL,
		0xC1AC191B833BDC2CULL,
		0x31F49FF77F5A7E1AULL,
		0x8B67DDB04A389AF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x438CF0E0F734C5FBULL,
		0xD59F78AD102B3650ULL,
		0x1408812BBAFAA51CULL,
		0xC7D335CEA42275D9ULL,
		0x80EB407C64048187ULL,
		0x10840A88EEC32D38ULL,
		0x7303945BF08273A6ULL,
		0xF7E7C0BFF8D49D51ULL
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
		0xA9478CF24415E84CULL,
		0x7E32E04CDDE0FF78ULL,
		0x4B77C9F7196B2063ULL,
		0x4B2E7056BBF4E044ULL,
		0x1554C69F3393DDAAULL,
		0x88E0615816D8219EULL,
		0x7D4673AE34F826B7ULL,
		0x9B7AD5818EDDFB94ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E4E2BF783437A7ULL,
		0x24A338850E6223EFULL,
		0x910AD02A48E7373FULL,
		0x76B9B0A95FA0EABCULL,
		0x78F22CA273A1F18BULL,
		0xEEAB91AF3BF0A116ULL,
		0x226E49688C16AA37ULL,
		0xEAC88316F05CEE7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6062AA32CBE1B0A5ULL,
		0x598FA7C7CF7EDB89ULL,
		0xBA6CF9CCD083E924ULL,
		0xD474BFAD5C53F587ULL,
		0x9C6299FCBFF1EC1EULL,
		0x9A34CFA8DAE78087ULL,
		0x5AD82A45A8E17C7FULL,
		0xB0B2526A9E810D16ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x40DFFC1CA9DDDAFEULL,
		0x5C780F78A9CE3852ULL,
		0xB6F1AA61C036F33BULL,
		0x2CBF8B76C523B813ULL,
		0x0C1B0E016593AD74ULL,
		0x560F3410337A6D80ULL,
		0x8F851009AABA59BDULL,
		0xCC76C056BC866DD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE758555FB321C056ULL,
		0xBFB8D2FA8E03301BULL,
		0xE44D6E9D0A391563ULL,
		0x9DF0872F9DB1B70FULL,
		0xAC9DB02081FED051ULL,
		0xDA0E2836725B28D7ULL,
		0x8BD936D85268079EULL,
		0xEF14C8C4A70AFCCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5987A6BCF6BC1AA8ULL,
		0x9CBF3C7E1BCB0836ULL,
		0xD2A43BC4B5FDDDD7ULL,
		0x8ECF044727720103ULL,
		0x5F7D5DE0E394DD22ULL,
		0x7C010BD9C11F44A8ULL,
		0x03ABD9315852521EULL,
		0xDD61F792157B7107ULL
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
		0x42A03D59910F7DCCULL,
		0x0C88C668A43B599CULL,
		0x4343B49716E586DCULL,
		0x798430E68F3E6F0DULL,
		0x677514CEB0BFE723ULL,
		0xAA4C9CD3CF224515ULL,
		0xC7AD135B5B02E944ULL,
		0x6FEB68A6A9657167ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x561CEB601AE94D58ULL,
		0xFB9BA6982F1B7CBEULL,
		0x84AAF7FA64247B53ULL,
		0x75C529CDC96C2302ULL,
		0x4732DEF2F3046806ULL,
		0xFD2807894B52A267ULL,
		0x3FF6BF54645331E0ULL,
		0x461540C1319B0DA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC8351F976263074ULL,
		0x10ED1FD0751FDCDDULL,
		0xBE98BC9CB2C10B88ULL,
		0x03BF0718C5D24C0AULL,
		0x204235DBBDBB7F1DULL,
		0xAD24954A83CFA2AEULL,
		0x87B65406F6AFB763ULL,
		0x29D627E577CA63C0ULL
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
		0x571177543364D16FULL,
		0x75984F00E614D037ULL,
		0xB1495E31301E3EADULL,
		0x08C184D58CDE00C3ULL,
		0x3511586506D1426CULL,
		0x74C8C39B16F7AB5DULL,
		0xE232B569738FD475ULL,
		0x523F7DEE8FF79DD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DC67C01919126DULL,
		0x60EF19649DCB8367ULL,
		0xFD4802E9F4BFD195ULL,
		0xA6131F835A1FE962ULL,
		0xC0603B58E1392EFAULL,
		0xA33A7E780893A409ULL,
		0xA049AC94E9DF3F30ULL,
		0xE003BFB0C9647EBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D350F941A4BBF02ULL,
		0x14A9359C48494CD0ULL,
		0xB4015B473B5E6D18ULL,
		0x62AE655232BE1760ULL,
		0x74B11D0C25981371ULL,
		0xD18E45230E640753ULL,
		0x41E908D489B09544ULL,
		0x723BBE3DC6931F16ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6314381246A4B43EULL,
		0x8F9C5A3F53AE1B84ULL,
		0x26CF4920201B3DB4ULL,
		0xFFBE1C9C4522BAB2ULL,
		0xD19B0C685776CA1CULL,
		0x958FF4BFA5BB6260ULL,
		0xD1FC50EC4AEDD342ULL,
		0xE16405F0434A825BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A249C602CCB29BCULL,
		0xBB23F1972FE506CDULL,
		0x9C6C746F1748DB50ULL,
		0xFA6D78B84E4C7786ULL,
		0x0057C710FC9CDED2ULL,
		0x7876F5EB904921A4ULL,
		0x845596FBF5B64D1DULL,
		0x69081C7C9BE9C80AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38EF9BB219D98A82ULL,
		0xD47868A823C914B7ULL,
		0x8A62D4B108D26263ULL,
		0x0550A3E3F6D6432BULL,
		0xD14345575AD9EB4AULL,
		0x1D18FED4157240BCULL,
		0x4DA6B9F055378625ULL,
		0x785BE973A760BA51ULL
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
		0x9471FC1249F6CEACULL,
		0xA37950BDBAE1D01AULL,
		0xA6EC19554F9F4796ULL,
		0xA318D54FEBDDFDE4ULL,
		0x032F6AAD9F2845B5ULL,
		0xFE07B72CE42D15F9ULL,
		0x2FE21699F52E6399ULL,
		0x50E6409FA0F842C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D9DD74085E0AAFULL,
		0xA6ADC49759B4969CULL,
		0x3443A85D5E9BBE96ULL,
		0x63B7A65F88463CAEULL,
		0x9D64D88E86B52EC3ULL,
		0x1C5EDE4F98FF7AA6ULL,
		0x40F09538F5FB30F8ULL,
		0x7DABE8B5CFA21A64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E981E9E4198C3FDULL,
		0xFCCB8C26612D397EULL,
		0x72A870F7F10388FFULL,
		0x3F612EF06397C136ULL,
		0x65CA921F187316F2ULL,
		0xE1A8D8DD4B2D9B52ULL,
		0xEEF18160FF3332A1ULL,
		0xD33A57E9D156285EULL
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
		0x6DBBF9AC227463A4ULL,
		0xE1A48C99CDD799C6ULL,
		0x3576FD0A389488CEULL,
		0x573135DC384A8DD4ULL,
		0x1F0BDC48DBE25598ULL,
		0x99215C817797335AULL,
		0xF2052BF16FA7705CULL,
		0x1770F19B65E21EE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1288779999178CDEULL,
		0x9052DC22E3EB7BE7ULL,
		0x5C14BD57AEFD95E5ULL,
		0xEC1356C193DF8E9AULL,
		0xAAF03303093FBCCBULL,
		0x4B19BB69CE6F0359ULL,
		0x09268B0BD5BA95E2ULL,
		0x3C6E1AE6D2C563DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B338212895CD6C6ULL,
		0x5151B076E9EC1DDFULL,
		0xD9623FB28996F2E9ULL,
		0x6B1DDF1AA46AFF39ULL,
		0x741BA945D2A298CCULL,
		0x4E07A117A9283000ULL,
		0xE8DEA0E599ECDA7AULL,
		0xDB02D6B4931CBB05ULL
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
		0x61E7CF289567597AULL,
		0x19FC74F77EFF8EEEULL,
		0x133662FA92016050ULL,
		0x66E7382F65C263C4ULL,
		0xA5EDE54C0E02077FULL,
		0x70688B29EC034306ULL,
		0xA56B1E6BD5FB6D8DULL,
		0xE250FD1C9C7578D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FEB40D708F761B4ULL,
		0x83DC8609542193BCULL,
		0x335029E5C3B0AAA0ULL,
		0x161F1BE6279BF36FULL,
		0xE9EA84DA1FA8335BULL,
		0x4DD1ABBA5EB6A857ULL,
		0xA77FB359F9AEE6D3ULL,
		0x69C5C8CAAD02AE3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01FC8E518C6FF7C6ULL,
		0x961FEEEE2ADDFB32ULL,
		0xDFE63914CE50B5AFULL,
		0x50C81C493E267054ULL,
		0xBC036071EE59D424ULL,
		0x2296DF6F8D4C9AAEULL,
		0xFDEB6B11DC4C86BAULL,
		0x788B3451EF72CA97ULL
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
		0x8B185C18DB6133CCULL,
		0xABEB24EE64F02001ULL,
		0x13876A623ED87B45ULL,
		0x4936498FDB79AA97ULL,
		0xF2C1A09B70A9D2CBULL,
		0x4D7A547733434459ULL,
		0x9903DF9A3435612BULL,
		0xC074CD1E1AEE571CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79536C641EDCAA9ULL,
		0x1B34449B0D88CE63ULL,
		0x898545335CC6A573ULL,
		0xDEB48B0DEFC87001ULL,
		0x183460DF30358366ULL,
		0x458282305F80E58AULL,
		0xD8092B4EA86AB953ULL,
		0x4DEA6D0CA8C53902ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9383255299736923ULL,
		0x90B6E0535767519DULL,
		0x8A02252EE211D5D2ULL,
		0x6A81BE81EBB13A95ULL,
		0xDA8D3FBC40744F64ULL,
		0x07F7D246D3C25ECFULL,
		0xC0FAB44B8BCAA7D8ULL,
		0x728A601172291E19ULL
	}};
	sign = 0;
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
		0xF849B5318F5BA2B6ULL,
		0x90A6478E700F462AULL,
		0xE3FA4896EA3C7B91ULL,
		0xE8EFAA4B4D689FA9ULL,
		0x0B742E1726235EC2ULL,
		0x2AF77081C7E427A4ULL,
		0x91A0A7BE9F8C23CBULL,
		0x4F562BE977434A09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x05306FBB8AA65806ULL,
		0x337D5F5707BEB0DEULL,
		0x99A955E5C895D622ULL,
		0x077295574D8161F5ULL,
		0x24B11C434B43962AULL,
		0x14B56C5691F77A3CULL,
		0xE1E1BFC41CACD5D5ULL,
		0x10860A67AD7AB26FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF319457604B54AB0ULL,
		0x5D28E8376850954CULL,
		0x4A50F2B121A6A56FULL,
		0xE17D14F3FFE73DB4ULL,
		0xE6C311D3DADFC898ULL,
		0x1642042B35ECAD67ULL,
		0xAFBEE7FA82DF4DF6ULL,
		0x3ED02181C9C89799ULL
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
		0x3E62E3DA2B82DA67ULL,
		0x965F87F041E7257AULL,
		0xED92DE93EAB0791BULL,
		0x63F5780D90E846DAULL,
		0xD59B062A2D42D2D1ULL,
		0x39AC36A45EA48E27ULL,
		0x579A6408DEDF6E9AULL,
		0x7FB890ABB33F4A58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2C0FDD51A90EE06ULL,
		0x10DCFEC31BB505A1ULL,
		0xC34E5F467901EF65ULL,
		0xFADE6DB4961F850CULL,
		0xC0A39582BAD508F4ULL,
		0xCBE6773E859940B1ULL,
		0x3FFFFB8BCEC4514EULL,
		0xD84F75E6A3C7B873ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA1E60510F1EC61ULL,
		0x8582892D26321FD8ULL,
		0x2A447F4D71AE89B6ULL,
		0x69170A58FAC8C1CEULL,
		0x14F770A7726DC9DCULL,
		0x6DC5BF65D90B4D76ULL,
		0x179A687D101B1D4BULL,
		0xA7691AC50F7791E5ULL
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
		0xACAB55DE15BD3198ULL,
		0xDED05C31D1C30FD4ULL,
		0xE06183C837BCB7EAULL,
		0x0598199BDE252DA2ULL,
		0x5DA8FD550A83A0CDULL,
		0x6085FD4EDC6A90D3ULL,
		0xFADE561BA2BD7868ULL,
		0x2CC22554718E4CEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2053D97E295C249AULL,
		0x5A14EE396B2244B5ULL,
		0xC8F5FC988DB0EACDULL,
		0x6D5DAB0AD1444672ULL,
		0x106D6F4DE9306221ULL,
		0x8BBAA6A6B4EF3817ULL,
		0xF1FBBF0E485C3ED1ULL,
		0x1FA04725194B6E02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C577C5FEC610CFEULL,
		0x84BB6DF866A0CB1FULL,
		0x176B872FAA0BCD1DULL,
		0x983A6E910CE0E730ULL,
		0x4D3B8E0721533EABULL,
		0xD4CB56A8277B58BCULL,
		0x08E2970D5A613996ULL,
		0x0D21DE2F5842DEE8ULL
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
		0xE39072203D9EC084ULL,
		0x3E4F2F34EA555699ULL,
		0x8D2C9F0CA63CCFD5ULL,
		0x1E9A7E5DC106E168ULL,
		0xF56CE94349421D1CULL,
		0xD3D0A58F6C905225ULL,
		0x7C4713C76595E744ULL,
		0x8872F7493C360734ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B07ADED5AB0AA8FULL,
		0x14880B025908E75AULL,
		0x73F35E0EC06B48EEULL,
		0x72004D3EA338951FULL,
		0xEF81C2282FBF5665ULL,
		0xCBC989C481842BA3ULL,
		0x209C41D174B3486AULL,
		0x3A1B148E6BFC86EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA888C432E2EE15F5ULL,
		0x29C72432914C6F3FULL,
		0x193940FDE5D186E7ULL,
		0xAC9A311F1DCE4C49ULL,
		0x05EB271B1982C6B6ULL,
		0x08071BCAEB0C2682ULL,
		0x5BAAD1F5F0E29EDAULL,
		0x4E57E2BAD0398046ULL
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
		0x082215B4629683ADULL,
		0x3CE6882DDBB33B80ULL,
		0xB6699EE2DEB3B76AULL,
		0xA7501F8BFAD7E0B6ULL,
		0x69D0C6D65DFDFED3ULL,
		0xCD3E63EE829C7E4AULL,
		0x6D1409F90E9DB43AULL,
		0x6018B7D5AB1C730FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB60AC08AA5023DULL,
		0xB5FAEF3FE2C47960ULL,
		0xEF2FAA661B61F597ULL,
		0xE95463F57E7191A5ULL,
		0x528D27B47C5E1B74ULL,
		0x4704F905AD59365BULL,
		0x71662A682EB655B1ULL,
		0x20E2CF1FF84358E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A6C0AF3D7F18170ULL,
		0x86EB98EDF8EEC21FULL,
		0xC739F47CC351C1D2ULL,
		0xBDFBBB967C664F10ULL,
		0x17439F21E19FE35EULL,
		0x86396AE8D54347EFULL,
		0xFBADDF90DFE75E89ULL,
		0x3F35E8B5B2D91A27ULL
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
		0xCFEDCDFCC58A2B74ULL,
		0xE0D09A00121D4A0BULL,
		0x0ADE58ED02B55E04ULL,
		0xBC43D97AE6991362ULL,
		0x71902F5F58E29F79ULL,
		0x8A5FE868F88D408AULL,
		0x03F27C95A1022AA7ULL,
		0x2163F0106B3EB81FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C7A84230710B50EULL,
		0x7D7AE2869F0E4F84ULL,
		0x3FFB1FCB3834299EULL,
		0x43840E3D97E96971ULL,
		0x41D6C037C61ACB3AULL,
		0xF1E2EAC511A8321DULL,
		0x0763A0CF0876C8E4ULL,
		0xE9F3C1F77CF1A64FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x537349D9BE797666ULL,
		0x6355B779730EFA87ULL,
		0xCAE33921CA813466ULL,
		0x78BFCB3D4EAFA9F0ULL,
		0x2FB96F2792C7D43FULL,
		0x987CFDA3E6E50E6DULL,
		0xFC8EDBC6988B61C2ULL,
		0x37702E18EE4D11CFULL
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
		0xE031F07DBEE78069ULL,
		0xBBEE3CB42EB6FBE6ULL,
		0xD8195FAA1829AF58ULL,
		0x145919892CF17765ULL,
		0xEBECB86308D8A107ULL,
		0xA31E5B8F5D85662EULL,
		0x1BF51E1FACF42C32ULL,
		0xEB2E041DA92E1C4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C329FBAB1B4F17ULL,
		0x539E9FCD6091C665ULL,
		0x894E12B0B8D29BE2ULL,
		0x75F868517DAA6265ULL,
		0xF1D798202FF14A93ULL,
		0x23D8557CA6B36EEFULL,
		0xBC1048153A8687AAULL,
		0x1A3F65824AC08E1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x586EC68213CC3152ULL,
		0x684F9CE6CE253581ULL,
		0x4ECB4CF95F571376ULL,
		0x9E60B137AF471500ULL,
		0xFA152042D8E75673ULL,
		0x7F460612B6D1F73EULL,
		0x5FE4D60A726DA488ULL,
		0xD0EE9E9B5E6D8E2DULL
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
		0x1CF89652BFBBE6E0ULL,
		0xAB64D16C6E7A0739ULL,
		0xBDAB57CB32DC1CF5ULL,
		0x47EC29F9C19C7FC4ULL,
		0x0F950ECE22E48EA7ULL,
		0xAEE2BFA3F4151381ULL,
		0x6FCAD1F772BAEA9DULL,
		0xA504A4958A29A21BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF54FA641BA41E4ULL,
		0x82597B563E2CAFFFULL,
		0xC97B4406F135DD3CULL,
		0x0231818399BFCD63ULL,
		0x2134A9AF72990EBBULL,
		0xF8CB62E47B2524F5ULL,
		0x7942E2031CFCA26FULL,
		0x733244AC7B71496CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D0346AC7E01A4FCULL,
		0x290B5616304D5739ULL,
		0xF43013C441A63FB9ULL,
		0x45BAA87627DCB260ULL,
		0xEE60651EB04B7FECULL,
		0xB6175CBF78EFEE8BULL,
		0xF687EFF455BE482DULL,
		0x31D25FE90EB858AEULL
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
		0xA8FF9CA978951287ULL,
		0x73624916D308880EULL,
		0xA597858C9E999BC1ULL,
		0x75D0DDCAD46823D6ULL,
		0x7AC9C34A43AC1D41ULL,
		0x4F054174583370B9ULL,
		0x8200FC6904E8F94CULL,
		0x44C0B04DBA9D45EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x314B9A8B4DA18732ULL,
		0x8EEEDB0222A043BDULL,
		0x0A8CFFD97F3E6F35ULL,
		0x0B7525E867C3BCFFULL,
		0x350B5F03329F452BULL,
		0xBD4E47C118E2C7CBULL,
		0x1773F7AEB5C2B8F4ULL,
		0xF265AA65048079B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77B4021E2AF38B55ULL,
		0xE4736E14B0684451ULL,
		0x9B0A85B31F5B2C8BULL,
		0x6A5BB7E26CA466D7ULL,
		0x45BE6447110CD816ULL,
		0x91B6F9B33F50A8EEULL,
		0x6A8D04BA4F264057ULL,
		0x525B05E8B61CCC31ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE0BBF8B55E4B27A9ULL,
		0x772FC4688D9BB7B1ULL,
		0x797C737A466034A7ULL,
		0xA0D9EC94660DFD78ULL,
		0x3F2ADE89CA488A99ULL,
		0x9602A5D01257E81EULL,
		0x12146287D1F9A419ULL,
		0x6D185A3CF3FBA8F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0A9D24922A1310EULL,
		0xA0ED0ADE62931742ULL,
		0x65D31D6618F60757ULL,
		0xDBC8078D8FCBDEEFULL,
		0xDB6FAAB5B5DEF76CULL,
		0x2A2EDF74254DFA9AULL,
		0x359D5881869DE84EULL,
		0x488190FC04D752ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2012266C3BA9F69BULL,
		0xD642B98A2B08A06FULL,
		0x13A956142D6A2D4FULL,
		0xC511E506D6421E89ULL,
		0x63BB33D41469932CULL,
		0x6BD3C65BED09ED83ULL,
		0xDC770A064B5BBBCBULL,
		0x2496C940EF245609ULL
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
		0x91CEBF67BD16B6F5ULL,
		0xD150352E6E759531ULL,
		0x59F053B67FCD1EE9ULL,
		0x3497EB7CD270F461ULL,
		0x4359070E1967BA0EULL,
		0xC14E7EF9E6D5DDBFULL,
		0x43B320938BCEDFAEULL,
		0x74B56FE88D5EE091ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FC79C699BB2460ULL,
		0x0999011914E1DF8DULL,
		0x55EC8F7F7B4E18EAULL,
		0x2253C947FDAA0544ULL,
		0x4BCB607E411943D1ULL,
		0x1BE10EF6A6F7D4FAULL,
		0xFA1724DF04DDD340ULL,
		0x33DB25E56191AF3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39D245A1235B9295ULL,
		0xC7B734155993B5A4ULL,
		0x0403C437047F05FFULL,
		0x12442234D4C6EF1DULL,
		0xF78DA68FD84E763DULL,
		0xA56D70033FDE08C4ULL,
		0x499BFBB486F10C6EULL,
		0x40DA4A032BCD3153ULL
	}};
	sign = 0;
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
		0xBC189EEC9BAF36DEULL,
		0x01BB9D2C51EBDFE4ULL,
		0xFFC3CC7F571F604FULL,
		0x90092AB5ECC10B67ULL,
		0x7BEA3AC587E5AE4EULL,
		0x458F259F5FB6D5F0ULL,
		0xF09A33BFBD8C5AB1ULL,
		0xB8F4B4ED29D6BA4FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x286B7282BA0E37A3ULL,
		0xDB433A5FD56F8F3BULL,
		0x2AA3FB14C35C4A9DULL,
		0x650C34049586C605ULL,
		0x7886207E4AF16452ULL,
		0xA950A637FFB7B244ULL,
		0xC421E4341BE80150ULL,
		0xB961A38B83D7C154ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93AD2C69E1A0FF3BULL,
		0x267862CC7C7C50A9ULL,
		0xD51FD16A93C315B1ULL,
		0x2AFCF6B1573A4562ULL,
		0x03641A473CF449FCULL,
		0x9C3E7F675FFF23ACULL,
		0x2C784F8BA1A45960ULL,
		0xFF931161A5FEF8FBULL
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
		0x8EA6885358F01609ULL,
		0x7FB7D74D7E9E3643ULL,
		0xAA2A41BEC9A20628ULL,
		0xF224C6FEB85CE8CAULL,
		0x0F2C836FFCE3C921ULL,
		0xBF403B5A7B743FE4ULL,
		0x5EB043815DAA728FULL,
		0x76E12711B86A286CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4950F904AD13C8DCULL,
		0x775B11EED85FFC7AULL,
		0x167B7B38492A6A94ULL,
		0xED4F6D0FE74407C3ULL,
		0xB5CD4FD6C4881617ULL,
		0xC010D47AFD15BFF0ULL,
		0xE645EFF943ABA8B9ULL,
		0x42FFD27E9B1DC99DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45558F4EABDC4D2DULL,
		0x085CC55EA63E39C9ULL,
		0x93AEC68680779B94ULL,
		0x04D559EED118E107ULL,
		0x595F3399385BB30AULL,
		0xFF2F66DF7E5E7FF3ULL,
		0x786A538819FEC9D5ULL,
		0x33E154931D4C5ECEULL
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
		0x9EE0797754A107C5ULL,
		0xDEA9BDD7E246C7ECULL,
		0x741C91A0567757CDULL,
		0xEADAA847CB3997DFULL,
		0xF903C3C975E88B80ULL,
		0x85D1FE76C530F43BULL,
		0xBBE08F1742001745ULL,
		0xFD96EE78BF0DA529ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x766A33C300CE58D0ULL,
		0x9773A4910FB30D89ULL,
		0x4143A2EBD92FBFB1ULL,
		0x0496611FE360BC89ULL,
		0x4AD455839951012EULL,
		0x92F9A41A998E3458ULL,
		0xB8EBBF6F05D26FDAULL,
		0x0FCDFD647E4D8EE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287645B453D2AEF5ULL,
		0x47361946D293BA63ULL,
		0x32D8EEB47D47981CULL,
		0xE6444727E7D8DB56ULL,
		0xAE2F6E45DC978A52ULL,
		0xF2D85A5C2BA2BFE3ULL,
		0x02F4CFA83C2DA76AULL,
		0xEDC8F11440C01640ULL
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
		0x98904DC3F114F306ULL,
		0x8A2A3159129D92C5ULL,
		0xDB795982CA3AF1FFULL,
		0xE8E25969082B9635ULL,
		0xF4FB5D82E0911525ULL,
		0xADDA5E0BA80BC192ULL,
		0xF45AD82A1DE0E990ULL,
		0xEEADDA9314E0EBB2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2DDD6D0925CDE7ULL,
		0xD3DC466D01E4C541ULL,
		0xAC6BA21363F11167ULL,
		0x6414C7D420C5EBC1ULL,
		0x432ECA8917EA3B6CULL,
		0x176C7E3398ECEF93ULL,
		0xA19F8E162A2948A8ULL,
		0x416005CF215B0214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A627056E7EF251FULL,
		0xB64DEAEC10B8CD84ULL,
		0x2F0DB76F6649E097ULL,
		0x84CD9194E765AA74ULL,
		0xB1CC92F9C8A6D9B9ULL,
		0x966DDFD80F1ED1FFULL,
		0x52BB4A13F3B7A0E8ULL,
		0xAD4DD4C3F385E99EULL
	}};
	sign = 0;
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
		0xD884AA0B7458B271ULL,
		0x9CE4B113524CD69CULL,
		0x3D23A4CEF1432B35ULL,
		0x43C2812D4B14CCDAULL,
		0xBE31D61B441D3F2CULL,
		0xAEEB0228C3B32D60ULL,
		0xFC5E479358B269A3ULL,
		0x7C8D9D7D78CC4219ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x443078D96E436A7EULL,
		0x097DD5342CA1FBEDULL,
		0x762AD1D6604CAF3DULL,
		0x99708F1049EF010FULL,
		0xC7A33E1E255F8DD7ULL,
		0x02EE52DE1D623832ULL,
		0x9AA9CF6761FFE987ULL,
		0xCCC45BA044D47A74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94543132061547F3ULL,
		0x9366DBDF25AADAAFULL,
		0xC6F8D2F890F67BF8ULL,
		0xAA51F21D0125CBCAULL,
		0xF68E97FD1EBDB154ULL,
		0xABFCAF4AA650F52DULL,
		0x61B4782BF6B2801CULL,
		0xAFC941DD33F7C7A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x315628F4D570F2E6ULL,
		0xA43754E7A09BD00DULL,
		0x4A5784DD0F2B60B7ULL,
		0x54EE3B7A982A0C70ULL,
		0x3DCC4184479156EAULL,
		0xADD1A1754540ED5EULL,
		0xC935AB0091E423F1ULL,
		0xD35A28244F023DBFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD64AE45C9E658DULL,
		0xA4A34B3B7049EE59ULL,
		0x14673A9C9BFF8977ULL,
		0xED0886D10571B7B1ULL,
		0x1370B6170A948BF2ULL,
		0x942DD2C32FFD42EDULL,
		0x8A8F43AFCD69788CULL,
		0xAB47E7FCE7F7A7E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x137FDE1078D28D59ULL,
		0xFF9409AC3051E1B4ULL,
		0x35F04A40732BD73FULL,
		0x67E5B4A992B854BFULL,
		0x2A5B8B6D3CFCCAF7ULL,
		0x19A3CEB21543AA71ULL,
		0x3EA66750C47AAB65ULL,
		0x28124027670A95DEULL
	}};
	sign = 0;
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
		0x90AFB33C3F02DA32ULL,
		0xB9067C5C4B5FE190ULL,
		0x08BEB5BC033D0F3BULL,
		0xA7C1D6A8F8750D8CULL,
		0xB0B744312EE70F6CULL,
		0x92BC3CF7D3C79AF6ULL,
		0x23B63E1111BFD2DFULL,
		0x3320B20D8D4BEF0FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9954D4B1AE4A92EULL,
		0x2408482D60637399ULL,
		0xC7382E68BD3D88E4ULL,
		0x25A210EED51FC373ULL,
		0x6EE7495DFFEABB6CULL,
		0xF21ADFA8AA1BCC0CULL,
		0x13BF068D21EA8D2EULL,
		0x4689E7185BC91C38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC71A65F1241E3104ULL,
		0x94FE342EEAFC6DF6ULL,
		0x4186875345FF8657ULL,
		0x821FC5BA23554A18ULL,
		0x41CFFAD32EFC5400ULL,
		0xA0A15D4F29ABCEEAULL,
		0x0FF73783EFD545B0ULL,
		0xEC96CAF53182D2D7ULL
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
		0xA103A40AF263E414ULL,
		0x4EC38AEAF0607BF4ULL,
		0xB023CFDB9DA4E85BULL,
		0x04E762A9C02E1A39ULL,
		0x74440E3B7E334E1AULL,
		0x7EB4D0468E251590ULL,
		0xE4D2E41612191933ULL,
		0xD8A65138DDA63341ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2E0366777918A8ULL,
		0x4F89F932B88E36F9ULL,
		0x5A7E87D217C51FA1ULL,
		0x8C857312153A54A0ULL,
		0xD89D7147B926EC69ULL,
		0xB42F313F26316F1FULL,
		0xBBA6171A94C99300ULL,
		0xDFCF3CF9D99F710CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41D5A0A47AEACB6CULL,
		0xFF3991B837D244FBULL,
		0x55A5480985DFC8B9ULL,
		0x7861EF97AAF3C599ULL,
		0x9BA69CF3C50C61B0ULL,
		0xCA859F0767F3A670ULL,
		0x292CCCFB7D4F8632ULL,
		0xF8D7143F0406C235ULL
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
		0x3239EBEF5DB12F01ULL,
		0x5FE48B24EFAE8293ULL,
		0xF2046C5C7938529DULL,
		0x7AC295850CF7BDCDULL,
		0x46ECB6D3DFC38E64ULL,
		0x1166CBA47C49F8CDULL,
		0x5842D270F5BCB724ULL,
		0xD8301E1058622029ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17EF86D9ED79176BULL,
		0xA858AC81154347EAULL,
		0x31AD9CBF85AA3F47ULL,
		0xE1EBBB81201F054EULL,
		0x18AB0656AC2CA601ULL,
		0xCF4E1EF237ABEBA8ULL,
		0xC1979A35F9DFBDF0ULL,
		0x719C45EA7C3CEA6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A4A651570381796ULL,
		0xB78BDEA3DA6B3AA9ULL,
		0xC056CF9CF38E1355ULL,
		0x98D6DA03ECD8B87FULL,
		0x2E41B07D3396E862ULL,
		0x4218ACB2449E0D25ULL,
		0x96AB383AFBDCF933ULL,
		0x6693D825DC2535B9ULL
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
		0x0FE10D331B3D2F55ULL,
		0x971531A2AF6920DFULL,
		0x48B3515B3B4DA81BULL,
		0xBA0A922FA0473DA0ULL,
		0x73DFF3CFB18A86FBULL,
		0x4D640415D5CE6FFFULL,
		0xD8AC06CDA8EE796CULL,
		0x95104B02BBC63219ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA42659A2652BDE04ULL,
		0x51E320806340213EULL,
		0x13EF03EEA076297FULL,
		0x7C1CBA7D73A511DCULL,
		0xFB6997CC0A07789CULL,
		0xAF2A1C2F33B4B439ULL,
		0x8DE487C93C6FDC13ULL,
		0xC3D80289021EB6C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BBAB390B6115151ULL,
		0x453211224C28FFA0ULL,
		0x34C44D6C9AD77E9CULL,
		0x3DEDD7B22CA22BC4ULL,
		0x78765C03A7830E5FULL,
		0x9E39E7E6A219BBC5ULL,
		0x4AC77F046C7E9D58ULL,
		0xD1384879B9A77B58ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1B964739403F49E1ULL,
		0xCB22B9106D3B70EAULL,
		0x035A4631C188290FULL,
		0xC6485183D6856F33ULL,
		0xAE925AB03A670ED9ULL,
		0x2911DEB30A77C7A6ULL,
		0xFA383DDF142657C6ULL,
		0x025369C704D75DBBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB25F5D867A07EAEULL,
		0x5AC0A55CFCF6AA87ULL,
		0xABA44A0461949A22ULL,
		0x5F9E2343F7A88B07ULL,
		0x93EF11E618D8D7E0ULL,
		0x4BCD95C698A0A6C7ULL,
		0x6493F8885D7D0502ULL,
		0x7DAC5B6F928E5179ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30705160D89ECB33ULL,
		0x706213B37044C662ULL,
		0x57B5FC2D5FF38EEDULL,
		0x66AA2E3FDEDCE42BULL,
		0x1AA348CA218E36F9ULL,
		0xDD4448EC71D720DFULL,
		0x95A44556B6A952C3ULL,
		0x84A70E5772490C42ULL
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
		0x0A4D1AAFE6D9FABBULL,
		0xEF0D6D7D676D5D12ULL,
		0x73AECF35AAED5883ULL,
		0x19D8046538777559ULL,
		0x1D7DCF9F954A6EFFULL,
		0xDCDFEBB6C9B7F194ULL,
		0x4E88AE06C6FF80D9ULL,
		0x9030B1FBEC0223B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F5CB1180BD4CC9ULL,
		0x29291C0910D4CAB1ULL,
		0x061524DD46D51783ULL,
		0xB866CF919C594509ULL,
		0x4EA5441D303F7B16ULL,
		0xCFB7603D0FEC9ECAULL,
		0xC6EF268D8DE04A2CULL,
		0x05D5865CEE727613ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89574F9E661CADF2ULL,
		0xC5E4517456989260ULL,
		0x6D99AA5864184100ULL,
		0x617134D39C1E3050ULL,
		0xCED88B82650AF3E8ULL,
		0x0D288B79B9CB52C9ULL,
		0x87998779391F36ADULL,
		0x8A5B2B9EFD8FADA0ULL
	}};
	sign = 0;
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
		0x136C53166D8B6A39ULL,
		0x1A759514FD158D8DULL,
		0x7C9E38ED544BAC4AULL,
		0xB916837D40CDFDCFULL,
		0xE09A673DDF9D2D4BULL,
		0xC7198DEB4C65AD43ULL,
		0xDC1F7408C3E52775ULL,
		0x3992D1214EC9C1FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CF0833800E0AD9ULL,
		0x11895262C01BFF37ULL,
		0x355FE59409511F30ULL,
		0xB295CBB226564569ULL,
		0x359B58F40B5AAECBULL,
		0xB7D73A2C0C279E8AULL,
		0xD75920200D58408AULL,
		0x2D9120B1EFF01A54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x609D4AE2ED7D5F60ULL,
		0x08EC42B23CF98E55ULL,
		0x473E53594AFA8D1AULL,
		0x0680B7CB1A77B866ULL,
		0xAAFF0E49D4427E80ULL,
		0x0F4253BF403E0EB9ULL,
		0x04C653E8B68CE6EBULL,
		0x0C01B06F5ED9A7AAULL
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
		0x973E1A322B60EB0BULL,
		0x51DB49E37F128389ULL,
		0x9ACEEBE155B103EDULL,
		0x24CA3C374719D242ULL,
		0x2455000BF432A39DULL,
		0xD2B4CF3F84489B28ULL,
		0x858CF496D7986AA2ULL,
		0x8E2A28F8642C0B00ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07664BC272BC21D9ULL,
		0xE413E4CE21F23FEAULL,
		0x0014CFE6C72C7748ULL,
		0xD261729A81465782ULL,
		0xDCFCA3566A33A53EULL,
		0xB18AB047BF5ACEEFULL,
		0x74874B8A510B959BULL,
		0x8FAD19136011170EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FD7CE6FB8A4C932ULL,
		0x6DC765155D20439FULL,
		0x9ABA1BFA8E848CA4ULL,
		0x5268C99CC5D37AC0ULL,
		0x47585CB589FEFE5EULL,
		0x212A1EF7C4EDCC38ULL,
		0x1105A90C868CD507ULL,
		0xFE7D0FE5041AF3F2ULL
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
		0x828D2F8AA7A2DE1DULL,
		0x511D9BC2B42D0414ULL,
		0xADEECA122E632288ULL,
		0x762E82E7B6368EB9ULL,
		0x3638D40EE5AF7750ULL,
		0xA396004F1514D582ULL,
		0x3DBC4C468D088523ULL,
		0x556B7E4EF0974ECBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x228A912689EC2721ULL,
		0xA49479331D805896ULL,
		0xD06F73E4DF09FEB9ULL,
		0x299D2DEF43CA71ADULL,
		0x77265009AF9CDFE6ULL,
		0x9B0586A6E99A03F1ULL,
		0x3B2E7358A38A0E3AULL,
		0x25F059E6974F130CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60029E641DB6B6FCULL,
		0xAC89228F96ACAB7EULL,
		0xDD7F562D4F5923CEULL,
		0x4C9154F8726C1D0BULL,
		0xBF1284053612976AULL,
		0x089079A82B7AD190ULL,
		0x028DD8EDE97E76E9ULL,
		0x2F7B246859483BBFULL
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
		0x32F594B616024DFFULL,
		0xA1053F47297DD909ULL,
		0x29B0EC530FE13161ULL,
		0x058994C60E59CC1CULL,
		0x5DF1AFA45952A1E3ULL,
		0xA372B50DA1D3384DULL,
		0xD9229681587733F4ULL,
		0xE20DC2865C6FDD69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB43A8F5788157DULL,
		0x93C0C52DF39D2461ULL,
		0x6B60E23A3817EC7EULL,
		0xBC22A2E353E48EEFULL,
		0x422EAB8051356ACCULL,
		0xF70A3258676EF4EDULL,
		0xE2BB1AE4527A85E9ULL,
		0xC27D2E14E3D3263FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06415A26BE7A3882ULL,
		0x0D447A1935E0B4A8ULL,
		0xBE500A18D7C944E3ULL,
		0x4966F1E2BA753D2CULL,
		0x1BC30424081D3716ULL,
		0xAC6882B53A644360ULL,
		0xF6677B9D05FCAE0AULL,
		0x1F909471789CB729ULL
	}};
	sign = 0;
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
		0x2407B15BD5BCC29BULL,
		0xE81C4A2C37055CE5ULL,
		0x6292726ED657413BULL,
		0xBB8BF12D09EB6213ULL,
		0x68454AF7D1E68A36ULL,
		0xF04F456BA31FDAC8ULL,
		0x9A5ABBC2B0075C99ULL,
		0x46DEEC31D3F0C2C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42596318470EDFEEULL,
		0xED1C1BFAD74000F1ULL,
		0x444D129B5BF87D28ULL,
		0xB0DA4301BA4657B6ULL,
		0xD70986EDEC1A7BA6ULL,
		0x890439E71CAB064AULL,
		0x19F97A4C48EC1850ULL,
		0x97D328513C7F1504ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1AE4E438EADE2ADULL,
		0xFB002E315FC55BF3ULL,
		0x1E455FD37A5EC412ULL,
		0x0AB1AE2B4FA50A5DULL,
		0x913BC409E5CC0E90ULL,
		0x674B0B848674D47DULL,
		0x80614176671B4449ULL,
		0xAF0BC3E09771ADC5ULL
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
		0x2049FE9E2052A6C1ULL,
		0x85DBA92CD931742FULL,
		0x2723D12BD53983E6ULL,
		0x3F6CD370338579E3ULL,
		0x9CBF94CD7BC0143EULL,
		0xC61F1A05FE969A34ULL,
		0xFE9E17D91D4046B4ULL,
		0x66DFFFA5DE361504ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98DFA5120FB9E432ULL,
		0xB9CD366AE181206BULL,
		0x8DA4586E410F55C9ULL,
		0x2655225EDAE44F84ULL,
		0x275949BE364EA056ULL,
		0xEE551BB05E3B7702ULL,
		0xCA62AD3A87B52771ULL,
		0x755EFA59461DEA8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x876A598C1098C28FULL,
		0xCC0E72C1F7B053C3ULL,
		0x997F78BD942A2E1CULL,
		0x1917B11158A12A5EULL,
		0x75664B0F457173E8ULL,
		0xD7C9FE55A05B2332ULL,
		0x343B6A9E958B1F42ULL,
		0xF181054C98182A75ULL
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
		0x983CADA6EA30C798ULL,
		0xAEFD65CE56640CE6ULL,
		0xB4B02762D4F77EC1ULL,
		0x897BCCE2B7B41E2CULL,
		0xE45E3EBE05F20515ULL,
		0x8581033064122C28ULL,
		0x8DFFC863924DEA69ULL,
		0x2EE29A069D1DDAE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2BC0B0434C8B81CULL,
		0xB18851C03F431353ULL,
		0x9E66416A1165BD10ULL,
		0x200630959B5122B2ULL,
		0x5DD452A64885C895ULL,
		0xE8E0938673B427F9ULL,
		0x368A80F05636328FULL,
		0x86F4C86E76D4E647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF580A2A2B5680F7CULL,
		0xFD75140E1720F992ULL,
		0x1649E5F8C391C1B0ULL,
		0x69759C4D1C62FB7AULL,
		0x8689EC17BD6C3C80ULL,
		0x9CA06FA9F05E042FULL,
		0x577547733C17B7D9ULL,
		0xA7EDD1982648F49AULL
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
		0x7315B1501880DE03ULL,
		0xC2B06EAB54D3BB2BULL,
		0x739C6FF1E9B921A1ULL,
		0x96B270FFCB17C02CULL,
		0x8BC2952684DA9EBAULL,
		0x5096DA72E0AD1094ULL,
		0x670EDD3C2EC8184DULL,
		0xB5304AD319BD9F42ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86CAD514BDCA4C4ULL,
		0xFDBE1A38EE3AAFA3ULL,
		0x222E6A51CC687AD4ULL,
		0xEAECADC4F47534CFULL,
		0x21B7D5965777C2C1ULL,
		0x48672524BA78BBBEULL,
		0x3CBF1378C7EFF2ACULL,
		0xC84AE0175D2CACB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAA903FECCA4393FULL,
		0xC4F2547266990B87ULL,
		0x516E05A01D50A6CCULL,
		0xABC5C33AD6A28B5DULL,
		0x6A0ABF902D62DBF8ULL,
		0x082FB54E263454D6ULL,
		0x2A4FC9C366D825A1ULL,
		0xECE56ABBBC90F28FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x17E5E161E7556126ULL,
		0xCB94FE9300D3AC66ULL,
		0x0268B465D3754BB7ULL,
		0xA1A8BC1C050E3BB5ULL,
		0x35DF952E6752FE69ULL,
		0xDCB6C2E951878ADCULL,
		0x40A4C7CA7578B3DEULL,
		0x2FF579E3214A61E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD0550DF701C148ULL,
		0x14E5326FF37BFBFCULL,
		0xDF56A3241773E214ULL,
		0xF4F9A4F18B6EBFEAULL,
		0x04E80A35EC0448F9ULL,
		0xE457ED158AB94E69ULL,
		0x87350B06D832747AULL,
		0x5691D4F846D01885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C158C53F0539FDEULL,
		0xB6AFCC230D57B069ULL,
		0x23121141BC0169A3ULL,
		0xACAF172A799F7BCAULL,
		0x30F78AF87B4EB56FULL,
		0xF85ED5D3C6CE3C73ULL,
		0xB96FBCC39D463F63ULL,
		0xD963A4EADA7A4963ULL
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
		0xFB0238F537197AC5ULL,
		0xC1D8CE6C2286B845ULL,
		0x9BC914646CC45782ULL,
		0xD8A5B4AA17B0E10EULL,
		0x19B16842D4A6B91BULL,
		0x838C8631435BE005ULL,
		0xD37B927DF7BDC212ULL,
		0x3A7938C923E6043AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C84B278E8BF47A1ULL,
		0x13DC61CC34089E68ULL,
		0xEEB707DAB2502FCAULL,
		0x2CA1B5AE23EAD89DULL,
		0xA7A8828778E3320AULL,
		0x36BDAB0C8C0FAB8AULL,
		0x6F46DFB3B700BC7EULL,
		0x39171C2C6BFC621FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E7D867C4E5A3324ULL,
		0xADFC6C9FEE7E19DDULL,
		0xAD120C89BA7427B8ULL,
		0xAC03FEFBF3C60870ULL,
		0x7208E5BB5BC38711ULL,
		0x4CCEDB24B74C347AULL,
		0x6434B2CA40BD0594ULL,
		0x01621C9CB7E9A21BULL
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
		0xDB0DBE6E2A1A8130ULL,
		0x814BD05097F8C482ULL,
		0x02F9A580230F901CULL,
		0x4C9A3BCB3B9A257DULL,
		0x78DD2129571848ABULL,
		0x7FCF63DA4CEC6FCDULL,
		0x980E774E3B310BFEULL,
		0xDC9705AD3AC369EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E490E51CC862A92ULL,
		0xF2A6F487D9F49151ULL,
		0x8CEA092AA117FB49ULL,
		0xA54D3DE8453DB57AULL,
		0xAE6F20450EB06610ULL,
		0x3758E96A0F42C9C5ULL,
		0x4BC37D4A2D215A94ULL,
		0x31AB134A7A68AD9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CC4B01C5D94569EULL,
		0x8EA4DBC8BE043331ULL,
		0x760F9C5581F794D2ULL,
		0xA74CFDE2F65C7002ULL,
		0xCA6E00E44867E29AULL,
		0x48767A703DA9A607ULL,
		0x4C4AFA040E0FB16AULL,
		0xAAEBF262C05ABC4EULL
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
		0xBD8ACA7C23E6EC40ULL,
		0x422A277331FF0F39ULL,
		0x1663D9443A1FC750ULL,
		0x6CC2801CA89FF46DULL,
		0x8E089A76A168EA78ULL,
		0x10A213F6BD886010ULL,
		0x2C786CB0C5A95BBDULL,
		0x41C79BD30E0DE0B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCBF99DDC9E53CF1ULL,
		0x833E1C10225B63CCULL,
		0x23AD7705211BCF8BULL,
		0xF0A4E82ADBEFDEA1ULL,
		0xA92CBCAAC8955DEFULL,
		0xD42FDEE570C65606ULL,
		0xE3971F104F1A68E2ULL,
		0xCA24F9957B2FD1C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00CB309E5A01AF4FULL,
		0xBEEC0B630FA3AB6DULL,
		0xF2B6623F1903F7C4ULL,
		0x7C1D97F1CCB015CBULL,
		0xE4DBDDCBD8D38C88ULL,
		0x3C7235114CC20A09ULL,
		0x48E14DA0768EF2DAULL,
		0x77A2A23D92DE0EF6ULL
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
		0xAC3ED8362649C143ULL,
		0x94824CAB79058091ULL,
		0x7ADC5D27FD7C6FB4ULL,
		0xC40665E9794893AEULL,
		0x0DF6314A3D0D2DDBULL,
		0xFFB3B1DEF19AF0BFULL,
		0x426125A04D67D054ULL,
		0xC2BC7E16BA43351AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1499F37A5302F3E7ULL,
		0x4136EE26512E342CULL,
		0xD5CDF18CD9C3BB38ULL,
		0x939683683BBFE4DFULL,
		0xB6372B37893D63F3ULL,
		0x9A84E8A09F183C04ULL,
		0x7D65552AACF8D6B0ULL,
		0x9D8DE563B091EBB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97A4E4BBD346CD5CULL,
		0x534B5E8527D74C65ULL,
		0xA50E6B9B23B8B47CULL,
		0x306FE2813D88AECEULL,
		0x57BF0612B3CFC9E8ULL,
		0x652EC93E5282B4BAULL,
		0xC4FBD075A06EF9A4ULL,
		0x252E98B309B14968ULL
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
		0x3F513D39F63FC0A5ULL,
		0xF6CAA22B4354B75BULL,
		0xEF4235D03CAC5A00ULL,
		0xFFC24567DDA0B659ULL,
		0x401CC3CF84DFB795ULL,
		0x64B6186699FA966FULL,
		0x064EFEB15F88E1CDULL,
		0x99972BAF0D1E7B88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x195B73939CC2B72EULL,
		0x8F696C0E9C736FA5ULL,
		0x90CA30709D2F1BE9ULL,
		0xB72CD6E1865EF799ULL,
		0x14DE22DB673D1B7BULL,
		0xBF41E77558C1E3C1ULL,
		0x47292CF9A4259FEDULL,
		0xB5031849DCEC05EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25F5C9A6597D0977ULL,
		0x6761361CA6E147B6ULL,
		0x5E78055F9F7D3E17ULL,
		0x48956E865741BEC0ULL,
		0x2B3EA0F41DA29C1AULL,
		0xA57430F14138B2AEULL,
		0xBF25D1B7BB6341DFULL,
		0xE494136530327599ULL
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
		0xFF5F31A595848B6DULL,
		0xBE5E6CA19F265204ULL,
		0xA3E170FDE7FAF238ULL,
		0x929158A0E79A0AA2ULL,
		0xEB45CEB4994EC537ULL,
		0xD61548EA124669D5ULL,
		0xFDA4777A8BD50C92ULL,
		0x3BED050B8401EDC3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA4C572C1FAF76DULL,
		0x0BE74A9AAEBFD41DULL,
		0xBA7C766216A927C9ULL,
		0xAD037A8C4461E187ULL,
		0x05EC62AC92DBD230ULL,
		0x11C3C5BF44736C1FULL,
		0x9623BABC362CF661ULL,
		0xBC81E605E12F8DF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4BA6C32D3899400ULL,
		0xB2772206F0667DE7ULL,
		0xE964FA9BD151CA6FULL,
		0xE58DDE14A338291AULL,
		0xE5596C080672F306ULL,
		0xC451832ACDD2FDB6ULL,
		0x6780BCBE55A81631ULL,
		0x7F6B1F05A2D25FCCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9E95A4B045890E23ULL,
		0x74B1DCF72A8819CFULL,
		0xDF301FA0C663ECE6ULL,
		0x5856006F200D95E5ULL,
		0x18628B67D73E7A80ULL,
		0x4BC5F79C81AFE24EULL,
		0xBF1FBF46A0752534ULL,
		0xDFBB3C18C09300E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AC8E25970FAC99ULL,
		0xB8743575CD081A72ULL,
		0x4901E353DEEF756CULL,
		0x6F9A90AD22A4C26CULL,
		0x7A80F0F7769F57ABULL,
		0xD9A0307505D5A204ULL,
		0xFC1C649898EE824DULL,
		0x4F063FA4BCD73F72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4E9168AAE79618AULL,
		0xBC3DA7815D7FFF5CULL,
		0x962E3C4CE7747779ULL,
		0xE8BB6FC1FD68D379ULL,
		0x9DE19A70609F22D4ULL,
		0x7225C7277BDA4049ULL,
		0xC3035AAE0786A2E6ULL,
		0x90B4FC7403BBC172ULL
	}};
	sign = 0;
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
		0x9995A28907B5777EULL,
		0xF35F6D82B8677C87ULL,
		0x1D13414486560F83ULL,
		0x67278636E4768F73ULL,
		0x9A9521E6981989AEULL,
		0x3117D53DB907075BULL,
		0x8E75F1FE014B7A1DULL,
		0x035D0F67E4E62724ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D6033D98E1173EULL,
		0xB309B228463D4162ULL,
		0xB910AEFFBE8783CAULL,
		0x8884A53AAEC5CCD5ULL,
		0xE23131E438E689D2ULL,
		0x0359708F8E8512C8ULL,
		0xE6C15204E2106753ULL,
		0x7A6C3D0297F170B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FBF9F4B6ED46040ULL,
		0x4055BB5A722A3B24ULL,
		0x64029244C7CE8BB9ULL,
		0xDEA2E0FC35B0C29DULL,
		0xB863F0025F32FFDBULL,
		0x2DBE64AE2A81F492ULL,
		0xA7B49FF91F3B12CAULL,
		0x88F0D2654CF4B66EULL
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
		0x80B0E8F2B5A5D99EULL,
		0x3F7E09115252A081ULL,
		0x0A3D0829A76747BEULL,
		0xFF833F715D21E977ULL,
		0x325F4E66462225BDULL,
		0x1708246269AE7034ULL,
		0x48022455B73B6C88ULL,
		0x70C5CC740F765B0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F5B3F581F7F197ULL,
		0x46597DD387982282ULL,
		0x36D82353F98AC85BULL,
		0x5F3B81AB198EDA05ULL,
		0xE0EA125227365E57ULL,
		0x4E524E8FFB98DDE6ULL,
		0x2455998E81F88B01ULL,
		0xAAA01957EF20CA54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EBB34FD33ADE807ULL,
		0xF9248B3DCABA7DFFULL,
		0xD364E4D5ADDC7F62ULL,
		0xA047BDC643930F71ULL,
		0x51753C141EEBC766ULL,
		0xC8B5D5D26E15924DULL,
		0x23AC8AC73542E186ULL,
		0xC625B31C205590B7ULL
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
		0x62C78DEA487FFE6DULL,
		0x60C2592339D231A2ULL,
		0xD92A773AEE61F7B0ULL,
		0xCC36E7B188C3F3D2ULL,
		0x7F86981C25092A50ULL,
		0x55C36B3CBE111A72ULL,
		0xACBCFF792957FF3EULL,
		0x95E4CF683D653B85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x991CA2107C59F9A6ULL,
		0xAE18455B48BBCA1AULL,
		0x5CFB90C695325A98ULL,
		0x1B05AD9A9F863EF7ULL,
		0x17A8500CCD8E4DA4ULL,
		0xA69C1217CE590995ULL,
		0x11706F31357BAC6DULL,
		0x0F27F71EA67AD54BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9AAEBD9CC2604C7ULL,
		0xB2AA13C7F1166787ULL,
		0x7C2EE674592F9D17ULL,
		0xB1313A16E93DB4DBULL,
		0x67DE480F577ADCACULL,
		0xAF275924EFB810DDULL,
		0x9B4C9047F3DC52D0ULL,
		0x86BCD84996EA663AULL
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
		0x9DD17B7648DE8954ULL,
		0x6EF188BFEC7F9EABULL,
		0xFA6C34848D3816DBULL,
		0x6570433230397541ULL,
		0xF41F476A043C510CULL,
		0xD8E2750A34EE5172ULL,
		0xB650864AE5D31811ULL,
		0x36F9D7974B69373CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C4E3CB44D71898BULL,
		0x8B894D69D31126B0ULL,
		0xF8D040E4E6B979DEULL,
		0xE13E11518A8C131DULL,
		0x88EB03A79746AA63ULL,
		0x4EF6B8C77E214F53ULL,
		0x4FDA255B546E06AFULL,
		0x3909D22179E6CE9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31833EC1FB6CFFC9ULL,
		0xE3683B56196E77FBULL,
		0x019BF39FA67E9CFCULL,
		0x843231E0A5AD6224ULL,
		0x6B3443C26CF5A6A8ULL,
		0x89EBBC42B6CD021FULL,
		0x667660EF91651162ULL,
		0xFDF00575D18268A2ULL
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
		0xA3326481EFBAC3DDULL,
		0xCF94197D41517954ULL,
		0xF7475468B724FB85ULL,
		0xDB21C5E4EA7AE605ULL,
		0x13EEDE8229FC1F7FULL,
		0x7B56DC99F6124DF6ULL,
		0x013AC88BC3CD1440ULL,
		0x02FB07F17FC60B59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x782419A086E9496FULL,
		0x6032031206C5E7F1ULL,
		0x236915E8F8C279DCULL,
		0x4C2FB1E825953D73ULL,
		0x9814A19635AFD826ULL,
		0x0B75AB823638EFEDULL,
		0xD4103C793F051F97ULL,
		0x87A3017E29054E94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B0E4AE168D17A6EULL,
		0x6F62166B3A8B9163ULL,
		0xD3DE3E7FBE6281A9ULL,
		0x8EF213FCC4E5A892ULL,
		0x7BDA3CEBF44C4759ULL,
		0x6FE13117BFD95E08ULL,
		0x2D2A8C1284C7F4A9ULL,
		0x7B58067356C0BCC4ULL
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
		0x20E044A6F9CBD7C5ULL,
		0xF562B0D5E9C0911CULL,
		0x14E6CA94EF90DFEEULL,
		0x6D3D63D02DA13E96ULL,
		0x979B0A7E53AF3E9AULL,
		0x4C4764D949EF092DULL,
		0x7893612CD5F6628DULL,
		0xBA91267904FDDD2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3748305ED9F091BBULL,
		0xAD453CCADBFF6EC4ULL,
		0x5C01F428ACF3E013ULL,
		0x33B8A550E5CCB2EFULL,
		0xC5BAB852446A4527ULL,
		0xAEF06303A73A44D7ULL,
		0xC24E182E95ADDA21ULL,
		0x3001748E12E935FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE99814481FDB460AULL,
		0x481D740B0DC12257ULL,
		0xB8E4D66C429CFFDBULL,
		0x3984BE7F47D48BA6ULL,
		0xD1E0522C0F44F973ULL,
		0x9D5701D5A2B4C455ULL,
		0xB64548FE4048886BULL,
		0x8A8FB1EAF214A72CULL
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
		0xC480D6E736F5BF4BULL,
		0x9063A3247B96FA4BULL,
		0xEAA06CAAF6C095D3ULL,
		0x721A4EF124D0EE62ULL,
		0xD1B825CA4C016D8CULL,
		0xA9D0971EEC3A11CEULL,
		0x3672945F519C3658ULL,
		0x73BB08384C51FAB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C778D28F888AEFULL,
		0xE744F8CEA870EBE9ULL,
		0x02F97B827E8E287BULL,
		0xE614B800363E607CULL,
		0xE5D957EFD970FA6AULL,
		0x86937455D3ADA508ULL,
		0xA514738DC3919E97ULL,
		0xA24F896AF485E77EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB95E14A76D345CULL,
		0xA91EAA55D3260E62ULL,
		0xE7A6F12878326D57ULL,
		0x8C0596F0EE928DE6ULL,
		0xEBDECDDA72907321ULL,
		0x233D22C9188C6CC5ULL,
		0x915E20D18E0A97C1ULL,
		0xD16B7ECD57CC1335ULL
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
		0xD56A88DE29A9F4EDULL,
		0x71C572568F64FF5BULL,
		0xC1F22A6987F834AAULL,
		0x9E6963C56913806DULL,
		0xFD36B23851F66F38ULL,
		0x0DD199A7A85CD6A5ULL,
		0x4604A73EE800BCE6ULL,
		0xB40784FD114B52AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E7DDC10A30FE744ULL,
		0xAB2B881B978CEFCFULL,
		0x8348F84BC8750AB0ULL,
		0xFF1028017C80EAA4ULL,
		0x9934CCA7145B145EULL,
		0x56DEDB59513573EAULL,
		0x6D587C6594BB37ECULL,
		0xD434248CE66A83C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46ECACCD869A0DA9ULL,
		0xC699EA3AF7D80F8CULL,
		0x3EA9321DBF8329F9ULL,
		0x9F593BC3EC9295C9ULL,
		0x6401E5913D9B5AD9ULL,
		0xB6F2BE4E572762BBULL,
		0xD8AC2AD9534584F9ULL,
		0xDFD360702AE0CEE5ULL
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
		0xC4411689BA8C9D50ULL,
		0x17A1643DD6C70B36ULL,
		0x1925324684AE0831ULL,
		0xEB5D89A93243854CULL,
		0xFBFC1870B45F42AFULL,
		0x8599FDEF4F72771EULL,
		0x5ED8016DB7F5DD95ULL,
		0x649D1A4B3B42E0E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73125A2412FFC58ULL,
		0x8AE4D54EAACE2A5BULL,
		0xA10AD1278529BB3AULL,
		0x728E0B344AB5187DULL,
		0x9D49EDBC75C047ADULL,
		0x97B72B8506CE6297ULL,
		0x8C2BD10EA2F5DE23ULL,
		0xDDB6CFB50A567D4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD0FF0E7795CA0F8ULL,
		0x8CBC8EEF2BF8E0DAULL,
		0x781A611EFF844CF6ULL,
		0x78CF7E74E78E6CCEULL,
		0x5EB22AB43E9EFB02ULL,
		0xEDE2D26A48A41487ULL,
		0xD2AC305F14FFFF71ULL,
		0x86E64A9630EC6393ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDDB26A3559832E29ULL,
		0xB48FD65D5BC7580BULL,
		0xC5388A0F9A56EF8DULL,
		0xD7CDFE799282A096ULL,
		0x96E8B057F901124DULL,
		0x4A714289E40554EFULL,
		0xDEBA6A9541F26599ULL,
		0x5BE70D513B0297C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39FA40D6B371646ULL,
		0x9512CE43720BB8A2ULL,
		0xA049B986B59068DDULL,
		0x885B67B6CEB55267ULL,
		0x440E5B83B0EB351FULL,
		0x6171682F5BC93881ULL,
		0xAE9C86F73CE0EA50ULL,
		0xEAE95DD716381B61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A12C627EE4C17E3ULL,
		0x1F7D0819E9BB9F69ULL,
		0x24EED088E4C686B0ULL,
		0x4F7296C2C3CD4E2FULL,
		0x52DA54D44815DD2EULL,
		0xE8FFDA5A883C1C6EULL,
		0x301DE39E05117B48ULL,
		0x70FDAF7A24CA7C61ULL
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
		0x7E316DD8F84E0C6BULL,
		0xCDC1D1BEFC819DA6ULL,
		0x8509CA0CFD819992ULL,
		0x6B75EF12664DB3DAULL,
		0x9F7BD352D1659D26ULL,
		0x86EF22B947C0A788ULL,
		0x075D89AEBC239205ULL,
		0xB8F94B8A29C6696AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x016002388F4ACECFULL,
		0x3F599C6F80EAF4D0ULL,
		0xF202CFC02EDD501BULL,
		0xB2D88749828BC409ULL,
		0xDB224BA0D9E466C2ULL,
		0x17D80B3213927F11ULL,
		0xD5CCC07EB1B1724EULL,
		0x6CFC7F523B1BD3B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD16BA069033D9CULL,
		0x8E68354F7B96A8D6ULL,
		0x9306FA4CCEA44977ULL,
		0xB89D67C8E3C1EFD0ULL,
		0xC45987B1F7813663ULL,
		0x6F171787342E2876ULL,
		0x3190C9300A721FB7ULL,
		0x4BFCCC37EEAA95B6ULL
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
		0xB3D54A091F1BF707ULL,
		0x8D7A5B431C946964ULL,
		0xEF8A77C24C5E8FFEULL,
		0x42BDBD24429F0C40ULL,
		0x7FF114BE36DD037AULL,
		0xE3EEB99045871493ULL,
		0xA9927BEAC36E5149ULL,
		0x2A199E8C5FD29DFAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C41DD1114CC1BBAULL,
		0x8E01AC6041D9B9CBULL,
		0x54B5D39606C294EFULL,
		0x4C69BF21788B5287ULL,
		0x64463A5018AF363CULL,
		0x3E9678E17F6A6392ULL,
		0xDC6BAD64111EB0E5ULL,
		0x4A87DCB3AA45EA08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87936CF80A4FDB4DULL,
		0xFF78AEE2DABAAF99ULL,
		0x9AD4A42C459BFB0EULL,
		0xF653FE02CA13B9B9ULL,
		0x1BAADA6E1E2DCD3DULL,
		0xA55840AEC61CB101ULL,
		0xCD26CE86B24FA064ULL,
		0xDF91C1D8B58CB3F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4ADF283AB7C64730ULL,
		0x47F27BAF420B2B76ULL,
		0xE65665687A50D17BULL,
		0x452165F7675D097DULL,
		0x111943525A566836ULL,
		0x276B1F10A2316F5AULL,
		0x2106AE86BBFC518BULL,
		0x4CAD4AD31C3AC568ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AB86686FF10BBDFULL,
		0x3FEC82A5140B7652ULL,
		0x68F8DDBD74D99C71ULL,
		0x38D95AC99057F20FULL,
		0x6C22A974F015B4F3ULL,
		0x243C2AC59DB53C73ULL,
		0x7A2365309E58A072ULL,
		0x0C1123096599FF32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1026C1B3B8B58B51ULL,
		0x0805F90A2DFFB524ULL,
		0x7D5D87AB0577350AULL,
		0x0C480B2DD705176EULL,
		0xA4F699DD6A40B343ULL,
		0x032EF44B047C32E6ULL,
		0xA6E349561DA3B119ULL,
		0x409C27C9B6A0C635ULL
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
		0x23852891B0A7F731ULL,
		0xAA0F191357A3333BULL,
		0xE08A8D7FF10C787FULL,
		0xD37706279D685EA5ULL,
		0x0BCAF4E9DD4F4DA7ULL,
		0x9A4BA808700495E7ULL,
		0xB571D6A5D3748A81ULL,
		0xF74E37B7C354E982ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0F37D4F468BC86ULL,
		0xBB5F8B3C01793940ULL,
		0x77CC5842854132A5ULL,
		0xEB015AEE6F3D02AFULL,
		0xBAB095ED41D0B147ULL,
		0xE4A43B06A8EEE8A3ULL,
		0x938787662BC0E8C6ULL,
		0xADA3104BC8FF0BC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8975F0BCBC3F3AABULL,
		0xEEAF8DD75629F9FAULL,
		0x68BE353D6BCB45D9ULL,
		0xE875AB392E2B5BF6ULL,
		0x511A5EFC9B7E9C5FULL,
		0xB5A76D01C715AD43ULL,
		0x21EA4F3FA7B3A1BAULL,
		0x49AB276BFA55DDBFULL
	}};
	sign = 0;
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
		0x5CC902B2675A9F3FULL,
		0x0F9B55E7F67024BBULL,
		0x5C50E1854E99BF2AULL,
		0x931ABB0519903B97ULL,
		0x578A1AC881A51F5AULL,
		0x54DC66D51AC81DB3ULL,
		0x5396251D9EA6A4C8ULL,
		0x9BF80B4D8C11AB0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EA71ADE13CB9FFULL,
		0xAC4880F764B6F76DULL,
		0x60AEF8EB635CE97FULL,
		0x62269CFCADE18D3FULL,
		0x278D5217F55BC435ULL,
		0x496776F3F02380EBULL,
		0xA84FF0A9F6698D27ULL,
		0x8FEC43346E78AD68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3DE9104861DE540ULL,
		0x6352D4F091B92D4DULL,
		0xFBA1E899EB3CD5AAULL,
		0x30F41E086BAEAE57ULL,
		0x2FFCC8B08C495B25ULL,
		0x0B74EFE12AA49CC8ULL,
		0xAB463473A83D17A1ULL,
		0x0C0BC8191D98FDA5ULL
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
		0x93917F9AD84C6390ULL,
		0x459810337CDBD051ULL,
		0xBACEF09976F4FC53ULL,
		0x018EEE1C460CEFDEULL,
		0xB0707852D2B35393ULL,
		0x96D6EBD6E4810629ULL,
		0x8147C357BF9AC7D3ULL,
		0x3DC70F3169233306ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD632AF4AFCC4F1ULL,
		0x9F762E327CB9BD0EULL,
		0x02E2EEE74F73427AULL,
		0x390CF4365AD0267EULL,
		0x80718DA9FC24F2B7ULL,
		0x73D2C6EF362604CEULL,
		0xC3826BC87DE2D643ULL,
		0x4B0A2B464F48E3EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3BB4CEB8D4F9E9FULL,
		0xA621E20100221342ULL,
		0xB7EC01B22781B9D8ULL,
		0xC881F9E5EB3CC960ULL,
		0x2FFEEAA8D68E60DBULL,
		0x230424E7AE5B015BULL,
		0xBDC5578F41B7F190ULL,
		0xF2BCE3EB19DA4F16ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x998FA502D152287EULL,
		0x49C8BC9FA8C7951CULL,
		0xE6315B275796624AULL,
		0xC272E11381C5C989ULL,
		0x2074F14AF440FCC5ULL,
		0x29A1EC6B8EA5AF63ULL,
		0xDA50FDF01E83DEFDULL,
		0x7F88095B1787B4F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F986FB3EA407EDULL,
		0x79BE85F8820430A5ULL,
		0x86787C2F75BC8A85ULL,
		0xB4278B613704DE4DULL,
		0x18F41BBF52D8498FULL,
		0xBED1B10FAC47CB9DULL,
		0xA622FF15ADDB56E7ULL,
		0xD9FB4BD050409206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2961E0792AE2091ULL,
		0xD00A36A726C36476ULL,
		0x5FB8DEF7E1D9D7C4ULL,
		0x0E4B55B24AC0EB3CULL,
		0x0780D58BA168B336ULL,
		0x6AD03B5BE25DE3C6ULL,
		0x342DFEDA70A88815ULL,
		0xA58CBD8AC74722EEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC8BF84DCE817A9BEULL,
		0xEC2BBFA3AAED4A75ULL,
		0x01C81D3A900399BCULL,
		0x23B5D70C93B2267EULL,
		0x02A6D9112FD78A4DULL,
		0x68F9847A67CE012EULL,
		0x10046B1AD1B132B9ULL,
		0x415D2E154D693FD5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E41884E23C2B4FULL,
		0xFDEB134DFE94E343ULL,
		0x17A699A1E90C6028ULL,
		0xB9548802539DED15ULL,
		0xAB33A9C546812192ULL,
		0xB4C20631689176ACULL,
		0x26575188B3BE514EULL,
		0xF5A064031E8725D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87DB6C5805DB7E6FULL,
		0xEE40AC55AC586732ULL,
		0xEA218398A6F73993ULL,
		0x6A614F0A40143968ULL,
		0x57732F4BE95668BAULL,
		0xB4377E48FF3C8A81ULL,
		0xE9AD19921DF2E16AULL,
		0x4BBCCA122EE21A00ULL
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
		0x84826F0C76C2DD90ULL,
		0x6A8896DBDD521A81ULL,
		0x196E40DCB3DC7B35ULL,
		0x5DFA51540AC57603ULL,
		0xB1F33B93E296C5E7ULL,
		0x8E89281ACD1AFAA3ULL,
		0x371A6AA3ADD077E5ULL,
		0x48B88C5C4A8D1E1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1009757F723FD1ULL,
		0x1D02AAF67F1D3FE0ULL,
		0x6B84042FFF4D31ADULL,
		0x1296C79D42795D8AULL,
		0xD36A65645EEC3F36ULL,
		0x45181ACC8BAA0527ULL,
		0x8983D6082A49E1D3ULL,
		0x8DE8D2BCAAB4A592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9726596F7509DBFULL,
		0x4D85EBE55E34DAA0ULL,
		0xADEA3CACB48F4988ULL,
		0x4B6389B6C84C1878ULL,
		0xDE88D62F83AA86B1ULL,
		0x49710D4E4170F57BULL,
		0xAD96949B83869612ULL,
		0xBACFB99F9FD87887ULL
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
		0x19504B1C03490042ULL,
		0xBBDB25D56BBF8149ULL,
		0xA5DDB3E8ACAC58A6ULL,
		0x2813B4A45EC54887ULL,
		0x1483B87248790C08ULL,
		0x3B53EA85D07BB3A6ULL,
		0xA383D6D532F7F6EFULL,
		0xB15AECAB027B3926ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E45B90C942BAA8ULL,
		0xA2FCBE2FDE87B3B3ULL,
		0x4C4EF7BD64A1D200ULL,
		0xC4CF0FA08927E861ULL,
		0xDD85E43FB275CD36ULL,
		0x0EECD2E3257B3854ULL,
		0x84CEC52AE6785A13ULL,
		0xD6F6BE13B93B3315ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC46BEF8B3A06459AULL,
		0x18DE67A58D37CD95ULL,
		0x598EBC2B480A86A6ULL,
		0x6344A503D59D6026ULL,
		0x36FDD43296033ED1ULL,
		0x2C6717A2AB007B51ULL,
		0x1EB511AA4C7F9CDCULL,
		0xDA642E9749400611ULL
	}};
	printf("Underflow\n");
	sign = 1;
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