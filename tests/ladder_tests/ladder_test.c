#include "../tests.h"

int32_t curve25519_ladder_test(void) {
	printf("Montgomery Ladder Test\n");
	curve25519_key_t n = {
		.key64 = {
				0xD21CA17052708C80ULL,
				0x545C2090CF9A9B6BULL,
				0xAFAA358DB5924492ULL,
				0x66D313E00EF6010CULL
		}
	};
	curve25519_key_t nBASE = {
		.key64 = {
			0x7574CD67F57087DBULL,
			0x2A3A14C85154ECECULL,
			0xA053129914200C23ULL,
			0x329592DB6CB4C357ULL
		}
	};
	curve25519_key_t r = { .key64 = { } };
	printf("Test Case 1\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	int res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x41FE858C33EFEA70ULL,
			0xBE9B37F775259C35ULL,
			0xB639B10CC2139B72ULL,
			0x4783A900E6065A84ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCEA40A1CF8F4FBFBULL,
			0xB168FDED49B37BA1ULL,
			0xF8B848AD53AD6199ULL,
			0x02EBED7997F843F8ULL
		}
	};
	printf("Test Case 2\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5E1FBCA01E263CC8ULL,
			0x15D030842214869CULL,
			0xD7E9BC8542BCB664ULL,
			0x4A9112D225C53BF7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2E883DA92D879EFBULL,
			0xAF862221E6738A53ULL,
			0xE0ECBFE897C81E6EULL,
			0x0D8CADE3530A46A9ULL
		}
	};
	printf("Test Case 3\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFC9D2F5500728240ULL,
			0x1A854684D027600AULL,
			0x266CB02F510C20EFULL,
			0x69472A33E4D87D2EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3F4A4903D217A139ULL,
			0x6CFBCE8527A1067CULL,
			0xE21AD147DA1222FBULL,
			0x64C2E04451BDA324ULL
		}
	};
	printf("Test Case 4\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1D75294C30F83DD8ULL,
			0x416159AE7714ACF7ULL,
			0x8A9300CD0D22BB63ULL,
			0x6A14CFD56DD01F9FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE93E6CD1904D219BULL,
			0xE97DBC932932E7C8ULL,
			0x4E79DCD0959A5389ULL,
			0x4B7FE33B41EC8727ULL
		}
	};
	printf("Test Case 5\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2B998DA4203B8D20ULL,
			0x403E881666E55C62ULL,
			0xE7E395E06E75B80DULL,
			0x45CCAEE99B4CF42CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3A8DF26A18C492E4ULL,
			0x5A81669CE258A11CULL,
			0xBB44A122686A1246ULL,
			0x575D409A620A6D3EULL
		}
	};
	printf("Test Case 6\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x66B7FA794B8E3590ULL,
			0x37EE08182EA791E1ULL,
			0x958F9FA2D9A96910ULL,
			0x612E515BEF4385B2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x954F6555A432ED8FULL,
			0x8070E8FFDA6B627BULL,
			0xEFC64CB869AB38B0ULL,
			0x11F635E02D9FB66AULL
		}
	};
	printf("Test Case 7\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDC76A5C368A21D00ULL,
			0x7F5115A1DB00F2F3ULL,
			0x4288B7C6DD4AD8FCULL,
			0x796C91593CCEAB13ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2EF3ACB4D5A857D0ULL,
			0x5BADBFCB9123FA2CULL,
			0x140373B5A82B63EEULL,
			0x4269B2911D9E43A5ULL
		}
	};
	printf("Test Case 8\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1F7C930CA0148508ULL,
			0xC3C368789DE4FFEBULL,
			0x52FFB5E1945620A5ULL,
			0x64D51D468DC44C3FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD5BB1E588804DA37ULL,
			0x7C6343480D45405FULL,
			0xE901B1428F048D45ULL,
			0x610A2E8D91D760DBULL
		}
	};
	printf("Test Case 9\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD4621F6EBAE21300ULL,
			0x9CAD4EF54C3DECE1ULL,
			0x5523AC8212227E1CULL,
			0x5085547D92DE1B38ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8903AB5208B82C33ULL,
			0x3AD04883A2EB71D8ULL,
			0x69D8169718E4EBD9ULL,
			0x3171ADE2E7CBE3B3ULL
		}
	};
	printf("Test Case 10\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9DC644AFD3F56950ULL,
			0xE9137A59E9190A3DULL,
			0xE6C34D8660DA03B4ULL,
			0x65D6E46D75547513ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCF966E81577A6C9AULL,
			0xF8B345A77236475FULL,
			0x321D1E8D3024B007ULL,
			0x0FA2D612775F6B33ULL
		}
	};
	printf("Test Case 11\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1C90F0712E7E1FE8ULL,
			0xD4673EFF4991DA29ULL,
			0x93DDC83CDB954451ULL,
			0x411A61EA0137A36BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x29CD133AB20AE370ULL,
			0xBBAB33C138622C27ULL,
			0x93D0AC15C28964C2ULL,
			0x3239799CF628DF82ULL
		}
	};
	printf("Test Case 12\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD47FB56B7E828938ULL,
			0xE328F2B2802E83B9ULL,
			0x0FD6E38815FC3B75ULL,
			0x65041D40BD9E399CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF5D356696DF03EF4ULL,
			0xD173D40AF69CE932ULL,
			0xFA913156CD982688ULL,
			0x0E399EAF0865DD88ULL
		}
	};
	printf("Test Case 13\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCD412681DA776798ULL,
			0xEF99B59E28178AB0ULL,
			0xF04C520BBC725B3AULL,
			0x56510CAB1AF0C46CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6116249F4AD65BA6ULL,
			0xF6AE6FA2CEF11844ULL,
			0xBE0FE3A1EBA38B81ULL,
			0x1D981FA131783264ULL
		}
	};
	printf("Test Case 14\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5652F2C7D588A8D8ULL,
			0x70796C1E694652D8ULL,
			0x0DC55854FFF718B8ULL,
			0x60C3968618217806ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x81A233648AFC7DD2ULL,
			0x0E7BE32710E3D91FULL,
			0xA8437D389ECF2B16ULL,
			0x66D78173544AAF75ULL
		}
	};
	printf("Test Case 15\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEBB8BBF4E6E54670ULL,
			0xA25C6BF13FACC836ULL,
			0x59496A554066839BULL,
			0x7C57422F32BCA94FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x99E637B98674A794ULL,
			0x51004B32C8A9CE94ULL,
			0x56E9C70B5A6F2CA2ULL,
			0x53BBC9E5601BB9D6ULL
		}
	};
	printf("Test Case 16\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x118EC8AFE0142290ULL,
			0x7CFD4E3BBAED8D0DULL,
			0x56E949D981082582ULL,
			0x5697A7D785B00DEFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8AC9675CAA48B3BDULL,
			0x5D8462CF1D9BD778ULL,
			0xCED6AFA3D88A3488ULL,
			0x74AB0B2C3346E3E1ULL
		}
	};
	printf("Test Case 17\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x60D06C7DCFAC8EB0ULL,
			0x8D90E1BA3E78B155ULL,
			0xE4E33C5A39D7C916ULL,
			0x7D06EFA844B8B741ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x36CF7D783F6F7F77ULL,
			0x4D1A5268EFB6034FULL,
			0x3E1562D7BDCAE88FULL,
			0x0D44AB488ED798E5ULL
		}
	};
	printf("Test Case 18\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x617EAD3CE6F81AF8ULL,
			0xADEB80DE98A260CAULL,
			0x3A28A181424BFB2DULL,
			0x6E58607B3DFC4B95ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF02133868E92B84ULL,
			0x60FA98AAF08B0C1CULL,
			0x3C447330877551F4ULL,
			0x4E260C4617ADF3CBULL
		}
	};
	printf("Test Case 19\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD580D7D89E9A6028ULL,
			0x552538DEEA248AB9ULL,
			0xBED1F11CE2910269ULL,
			0x5B6A9EF44BF0EFD1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x43142ED2351E5FBDULL,
			0x68A66CBB98D9B4A3ULL,
			0xC922C1FCA7DDEDB5ULL,
			0x6EE1B165BDD6EBDAULL
		}
	};
	printf("Test Case 20\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7F82C2F45FEDC808ULL,
			0x9B0A7B8B405218C1ULL,
			0x219695C0AF88D18CULL,
			0x689DC1194460ADF1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDC93B52AD64861F1ULL,
			0x3ADDF34C1CD5DA92ULL,
			0x629CE9B3E7E8E3CCULL,
			0x7A29BD2ABE3AD55EULL
		}
	};
	printf("Test Case 21\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x387384BE5125D568ULL,
			0x46E449EDCB755AD8ULL,
			0x9105BD1C745AE905ULL,
			0x6714867EDB5BDBFBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3565508E2F64E817ULL,
			0xE0A72C53E62B329AULL,
			0x6E2E6B935976EF96ULL,
			0x5A3A39C618B9AFDCULL
		}
	};
	printf("Test Case 22\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7D01245884C4E948ULL,
			0x45A5D56999C0B277ULL,
			0x606931EDAB6EFE94ULL,
			0x6721D85198BCD973ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7DE139771AD3DCFAULL,
			0x2C56D5307E286370ULL,
			0xF72B2CA04CE23026ULL,
			0x1CBC2B293389A244ULL
		}
	};
	printf("Test Case 23\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBD94C513F1EA95F0ULL,
			0x45DC30AEDF57DC18ULL,
			0xC88A9B483ED6447CULL,
			0x5A7B644AD76BEA17ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8D56C8BDA6845D32ULL,
			0xA77661A6E376AA0CULL,
			0x8908942007042645ULL,
			0x153F0B2BC4A27697ULL
		}
	};
	printf("Test Case 24\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8871F204B9330CD0ULL,
			0x6BF91CF50B9EAF28ULL,
			0xC1107F9B583C6E42ULL,
			0x789EB5B5A241C33BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x46FF830FD0A745F7ULL,
			0x37BF5EA8CFDD0E07ULL,
			0x722FB6F8E5874FC3ULL,
			0x4068CDCD0E35780FULL
		}
	};
	printf("Test Case 25\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC6E2B0F9C59E0168ULL,
			0xE3B676BFBB9CCA45ULL,
			0x4223F59AB8648106ULL,
			0x74FC1975452E91F5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC84CC69B09938AF4ULL,
			0xBD2BF156472C9045ULL,
			0x4FB81400C5BD643AULL,
			0x35B489F7F96C40C7ULL
		}
	};
	printf("Test Case 26\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFCD864D3735EB318ULL,
			0xF84BC75D48B397A6ULL,
			0xCECC61F211A74005ULL,
			0x7C45E9BE5ED1E841ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x36EF19700D767850ULL,
			0x09E1E955154C57EDULL,
			0x655D1E09FE906CDFULL,
			0x6668D63B39753E2AULL
		}
	};
	printf("Test Case 27\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD2B9A4F92C97CA58ULL,
			0xE384874DE62A492AULL,
			0x298DD7E0F50A2C97ULL,
			0x57BAD844D754532AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF11B040D5340DBE8ULL,
			0xEF2E1694CB8A170EULL,
			0xD82F7EB4D42C8B79ULL,
			0x41BB46BA032FE9CDULL
		}
	};
	printf("Test Case 28\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x89939164CE083FE8ULL,
			0xAD0860F1A61DBBD9ULL,
			0x81C210D0AE8E0C56ULL,
			0x7DF1C74287A62BBAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x351B34FFC6B7B01CULL,
			0x98C299B12350EC78ULL,
			0x915BD25A7ECD4EAEULL,
			0x60615149C3382D98ULL
		}
	};
	printf("Test Case 29\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xED8A8E3C41F72F28ULL,
			0x0252B334C1EA9A31ULL,
			0xD2E2BF7A3DC7C702ULL,
			0x76505D577D52705EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFC467EAD1888D8E5ULL,
			0x9108DFEA353F6E67ULL,
			0x1C1F1FF1B4F85BC3ULL,
			0x1C068BDCB9C46334ULL
		}
	};
	printf("Test Case 30\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDD4646C0666023A0ULL,
			0x0CA4755DFD19B9F6ULL,
			0x38B911036FA3964EULL,
			0x7F1BD7E2BE7DEC4BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x90ED9E22E707DD9CULL,
			0x706B13C529726B19ULL,
			0xE7DF8182E4FC3C09ULL,
			0x4E915E55C438B34FULL
		}
	};
	printf("Test Case 31\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD0D9C2A979029400ULL,
			0x04E164D660A73B14ULL,
			0x0FEC8C72B8FC5C5CULL,
			0x4B253D72566A3381ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0A5A58DBCB862992ULL,
			0xA9E96DA40A3D454AULL,
			0xC591DD18F25CFEADULL,
			0x590911A3730860CDULL
		}
	};
	printf("Test Case 32\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2BAFB5A77367B970ULL,
			0xF1A7CE6B8A25108AULL,
			0x04F5EC1B4C16210FULL,
			0x4488ED942BD712EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4DF86ED0A9A1AFD7ULL,
			0x95B4CE3AE1CEE993ULL,
			0x95A1B70E49C17FDEULL,
			0x1623498E6E65BEE4ULL
		}
	};
	printf("Test Case 33\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x86EA237275225768ULL,
			0xE84538FA7DF880B7ULL,
			0xE215B1E76BA434C1ULL,
			0x5813A9DEB6680D00ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x51A7958181FB671BULL,
			0xBEF2C1F669C2ACC3ULL,
			0x9931C9C143A38A79ULL,
			0x0FEFE70D022C7694ULL
		}
	};
	printf("Test Case 34\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1B4B640428593BF0ULL,
			0x9F9366C59878BF5AULL,
			0x3BF1F095636893F1ULL,
			0x4A85E96632C39E7DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9AAD1024099CC34AULL,
			0x91C5479C9ED0C0C8ULL,
			0x781A724A163FBC25ULL,
			0x10217A8C55E482B9ULL
		}
	};
	printf("Test Case 35\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x228D0185E0C33BA0ULL,
			0x2C2AE1E9FA2D69DAULL,
			0x6D0E3EF219A04801ULL,
			0x67B6E8BD14D603E2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFAE6D377592DD549ULL,
			0xE8E0B8B70F8E6F7AULL,
			0x3200E4FB61816F5CULL,
			0x0D0F52F31B867EA8ULL
		}
	};
	printf("Test Case 36\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7587B3D13380F2A0ULL,
			0x901FF9948C6AF7C4ULL,
			0xC61B4E602AF638D7ULL,
			0x4770175973D0CB4EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x05333096BCC1E8F0ULL,
			0x4BCE2490E1279938ULL,
			0xD6F6A46423DF9949ULL,
			0x72F3B549FC0CA6A2ULL
		}
	};
	printf("Test Case 37\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA22F246843133958ULL,
			0x5EBE45C8F32D6EACULL,
			0x698AB8BB4A2600DAULL,
			0x6CB68A811F74C535ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDF242D391D2FAEA2ULL,
			0xE6ACDCA220B0D79FULL,
			0xCBC5B1775C8D42D1ULL,
			0x343273A2A9635842ULL
		}
	};
	printf("Test Case 38\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x425C84EBA16FAF18ULL,
			0x78BAE4799987ABB2ULL,
			0x9189032A48C462C8ULL,
			0x6C46AF24F5415741ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA91031440C1B1F41ULL,
			0x935CFDED287D8A9AULL,
			0x3D9F327AFD06FE23ULL,
			0x32C6001F4B2D8A89ULL
		}
	};
	printf("Test Case 39\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5BCC1A48730EA890ULL,
			0x006F4AD69F6F3D28ULL,
			0x32F823EEE4AEA27CULL,
			0x6F1ECDF5C0F1FEC4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAFFF90AA3463A56DULL,
			0x4AEF68C91A42EF8DULL,
			0xA49C924E3868BEA8ULL,
			0x581188EF3CE6454BULL
		}
	};
	printf("Test Case 40\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0ABF6B153A07C6E0ULL,
			0x2CD2F43B08C18418ULL,
			0x722DA9BDFA99293BULL,
			0x67DF454C1B57BD0EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5EBC05805AED22D3ULL,
			0x46DC102A5A51DC12ULL,
			0xB9FD0FD0A6E01581ULL,
			0x2A580781FA84261AULL
		}
	};
	printf("Test Case 41\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1FE8BF2DC23A8C20ULL,
			0x1466751263315AAFULL,
			0x6B837B4E3294ED44ULL,
			0x646CBCB5D8386CE2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1D6699251C7398E0ULL,
			0x92CD7A5E00C52680ULL,
			0xADFEC8D3CB1507E2ULL,
			0x6980EF2A892C8D38ULL
		}
	};
	printf("Test Case 42\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x81455C8CD8637B60ULL,
			0xBA3134E196F03267ULL,
			0xEB5AD35D18ACC43AULL,
			0x5B2D20E8CE399339ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB720200730A0260DULL,
			0xF1C12A0137619D89ULL,
			0x24F462461F80BF9AULL,
			0x3FB5AE1EA92995A7ULL
		}
	};
	printf("Test Case 43\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7FCE2159136EBEC8ULL,
			0xA32D75177376AF38ULL,
			0x04B5CFC285E08014ULL,
			0x7088982EEB17E668ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9EF8922C9C469943ULL,
			0x6FEA0B045F73CC7BULL,
			0x6ADA503CF24CC2DBULL,
			0x48110DEE72C9E5EDULL
		}
	};
	printf("Test Case 44\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFC4155693E5BC928ULL,
			0xC6ED9E54120780F0ULL,
			0x1414066E4E28D715ULL,
			0x77FEE256C3748C1DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5345CE86F7A88850ULL,
			0xEFCAFBFF25CAA1EBULL,
			0xCF85FEABDF3335B7ULL,
			0x2FE3D602A9A62A33ULL
		}
	};
	printf("Test Case 45\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD730D575A6554968ULL,
			0x1071A63A6C1CDD4DULL,
			0x77C1F2690CBAEA62ULL,
			0x5C93D525BF369E4CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDFBC8E13B4105564ULL,
			0xDDCA885C588DD155ULL,
			0x70EA82F1026B3EFBULL,
			0x70D8D6696914DEA2ULL
		}
	};
	printf("Test Case 46\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xADB23F7A209016C8ULL,
			0x0C3747D2C1E60952ULL,
			0xA62CC9183121B05AULL,
			0x7D12AF0247E97B5EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5CC502E6D7E7955DULL,
			0x11166F82166C94FBULL,
			0x4D5E0982ACAFD81EULL,
			0x29E0DB1F580E81DAULL
		}
	};
	printf("Test Case 47\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x343A7EC47B830F60ULL,
			0x49448786D2D2BBF8ULL,
			0xC65D2608D7C82C6DULL,
			0x5E6F5F3BD0B46DF0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD406395A81502F88ULL,
			0x879C84D77F618635ULL,
			0xB29A314B84044C76ULL,
			0x339CCA9DF6005037ULL
		}
	};
	printf("Test Case 48\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x86993E4D12E55E28ULL,
			0x6314B044803E0D09ULL,
			0x5623D2B79902E03FULL,
			0x579D9ED6AD64A226ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC6B1AC505392799FULL,
			0x8DFDD77E2144429AULL,
			0x7262BC9A8210C3D1ULL,
			0x04E646603E6FF87AULL
		}
	};
	printf("Test Case 49\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5848AC3150A8CD60ULL,
			0x3A8EBD5809867B5EULL,
			0xB3AD660005EBE533ULL,
			0x4A92066A3C9DD8DAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0C909E1709F76CABULL,
			0x57CCEB4EF9C04171ULL,
			0x089921D1CFB60447ULL,
			0x660618D6ECAFEC1CULL
		}
	};
	printf("Test Case 50\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC181FFBBA0765B38ULL,
			0xF9C567B93459139BULL,
			0x6BD50A47A447FBD6ULL,
			0x4CBAA2897719DE39ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC78707642943EBBEULL,
			0x3779FF49E152B250ULL,
			0xB1B740B1584CCC5DULL,
			0x513272C4BD7899A9ULL
		}
	};
	printf("Test Case 51\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x60FF9F5FBD4C52C8ULL,
			0x31327AA08B654901ULL,
			0xB4D592FA8CE22E00ULL,
			0x71DD3821A7E8BB2EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB671892AC76A8BA4ULL,
			0x729B5E705F1E7747ULL,
			0xBE9634F3D2DEC284ULL,
			0x1FF7AFB899B812F8ULL
		}
	};
	printf("Test Case 52\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x06B8BF481F4C00E0ULL,
			0x59493FA4770C1140ULL,
			0xBC2E502697FFC92FULL,
			0x5C74A18EE07778F9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1C2698AA22BF770EULL,
			0x6A0910C06DF702E7ULL,
			0x62951FDACD8866E1ULL,
			0x408CA7C4DA9EB0C8ULL
		}
	};
	printf("Test Case 53\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4B19805E2E62F900ULL,
			0x8E58E69CDF23DC14ULL,
			0xFA3863CEA46B68FBULL,
			0x6AA98BB4BEB86A56ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x83D1EAECAA9BAC08ULL,
			0xED62986B058D2A4BULL,
			0x1C22174CAB546CD9ULL,
			0x4476949ACE638555ULL
		}
	};
	printf("Test Case 54\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6F93285DA0320110ULL,
			0x06CA343ACBF9D3C4ULL,
			0xF44C4ED2F82F13E5ULL,
			0x7E6CAD9BC77D1899ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC41A46AAC3EC63A2ULL,
			0x713987AD1988A092ULL,
			0x300EA53252A1179EULL,
			0x0428829DCBEB9A2AULL
		}
	};
	printf("Test Case 55\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF1D4977C769DF8C0ULL,
			0xC80A7F91B38DED96ULL,
			0x9A54941A23A836DBULL,
			0x498B9CF657831767ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2807F7306EBC8F6AULL,
			0xCDC12F4335002B65ULL,
			0x68A330D0FF040AAAULL,
			0x7DC35E1C68585A3CULL
		}
	};
	printf("Test Case 56\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8227B2597DFBE8C0ULL,
			0x5A14807D9D162D6BULL,
			0x0B5B76852B27D333ULL,
			0x4EBEAD7F81B56CEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7AE5BE7F0EF44D75ULL,
			0xCD96AF3D1E5F89ABULL,
			0xD350070CD3FAAFBDULL,
			0x25C1C6A640CEA388ULL
		}
	};
	printf("Test Case 57\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAAA6D50BCA4C99B8ULL,
			0xAAE74217EB168D38ULL,
			0x440E9B05062E6D4BULL,
			0x552B28DADB344FE6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x89F88E0321FCFEA9ULL,
			0x9914937FBDE7C711ULL,
			0x75A2B7EA5A5E5F12ULL,
			0x77280713BEB9FA89ULL
		}
	};
	printf("Test Case 58\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE5ABC76BE5FE9768ULL,
			0xD1CE5B2E64713491ULL,
			0xFF042F0E15D67C71ULL,
			0x6D194EDCAA26935CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x547BA0BF06773896ULL,
			0xA9B14842D30DA032ULL,
			0x162E6889FA53CD2DULL,
			0x4DAAB1144CED62B2ULL
		}
	};
	printf("Test Case 59\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB14551403CE6BD70ULL,
			0x40F5D941A90A3FAFULL,
			0xDE6DDCBC3EEFD7A8ULL,
			0x73E605259CA2D4F8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDC4BC09A44A939E8ULL,
			0xD62D7B16789835D5ULL,
			0x4CE7E513C0EA0C67ULL,
			0x6041BFB0F1189D25ULL
		}
	};
	printf("Test Case 60\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC05DF5157DFE1650ULL,
			0xA3602623359621A7ULL,
			0x335735E4C25CDBFFULL,
			0x6D2DCDA3BC99457CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x081572AA6A500EA6ULL,
			0x77A59CE9A48D3A8CULL,
			0x722D3DBFE301FFDFULL,
			0x11B620446ED0523AULL
		}
	};
	printf("Test Case 61\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD368ED2E97D0BF80ULL,
			0x775C41BFC7D079A1ULL,
			0x9354358F3622FA76ULL,
			0x73BBC6A490984AEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2792B5765941649CULL,
			0x95BFD0A9069E7B0FULL,
			0x4F0C7CBA05D8702CULL,
			0x416F0443DDA25723ULL
		}
	};
	printf("Test Case 62\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9292CBB08C3ECBB8ULL,
			0x56DA527AE031A77EULL,
			0xF100B4D9DAEC512CULL,
			0x7C9417A6384EB17DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x94EC65AB7B3D5514ULL,
			0x87621E770AE9D9A7ULL,
			0x51DAC7F8B0E7319EULL,
			0x76EE775D197AA772ULL
		}
	};
	printf("Test Case 63\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8381CAAA4F6DFEC0ULL,
			0x53E511D435E21446ULL,
			0xE43C8B69A82ABD6AULL,
			0x6A222EDA5A71F798ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7E2D7922AFDC4780ULL,
			0x6A9ED7BE8E611CF7ULL,
			0x0E5AC4DA918DE486ULL,
			0x550595658FAA35A7ULL
		}
	};
	printf("Test Case 64\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7C5F105358BDA110ULL,
			0x72C84AECB4119223ULL,
			0xB8A7CA24E1E10B4AULL,
			0x6106741091BA2A4BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x28078AD68B51D1ECULL,
			0x69D75C1DE42B7DFFULL,
			0xD4E7E58479BC883EULL,
			0x0E1A3B08B4810DB0ULL
		}
	};
	printf("Test Case 65\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB849EE5FBA55DE10ULL,
			0xAE99946257009490ULL,
			0xC4A01051797CD67CULL,
			0x5366710BAE8B9943ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x082CA2867D883A68ULL,
			0xF10869005C72CA79ULL,
			0x56B736EFC09BFD9BULL,
			0x792470CBC0BAB2A7ULL
		}
	};
	printf("Test Case 66\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3EA27513A88242B0ULL,
			0x8257D93CD0635443ULL,
			0x1B787E435C49083FULL,
			0x628799EE7FAAF895ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB2162D81AD593C1FULL,
			0x91164FF6452C90CBULL,
			0xD7DAE8D227D2813CULL,
			0x4537C61D4EC879F6ULL
		}
	};
	printf("Test Case 67\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0040611C3D52FB10ULL,
			0xC936EB4B84F0FB95ULL,
			0x4BC58205675DF907ULL,
			0x4E7B862AA6ECB077ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6F707C7C2B63FAA0ULL,
			0x69AEDFFC5B46908FULL,
			0x0E306DE358DD039AULL,
			0x1D1ECB4CF21543B1ULL
		}
	};
	printf("Test Case 68\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x75AAFCEAFC654948ULL,
			0x8DC5A2E338F521CCULL,
			0xD193D48AF97591C6ULL,
			0x42DB240E1B5BE273ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x17D5C5B271536043ULL,
			0x772162C96D1E167EULL,
			0xB3E097AB118F8CF5ULL,
			0x2DD70DD4C86C9F6FULL
		}
	};
	printf("Test Case 69\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAD3706FFBA876610ULL,
			0x49D5A9E431EBE367ULL,
			0x65FFE71876ED77D0ULL,
			0x528A896792A9F9F5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC872ABA1343B4100ULL,
			0x6F54B14238258DE0ULL,
			0x21C794966BA1FBD0ULL,
			0x2B2C9634B15DB74AULL
		}
	};
	printf("Test Case 70\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4DA68F42A3798858ULL,
			0x5A716F2D218C1FAAULL,
			0x2C053C85FDA7148EULL,
			0x4CF96A90167899FAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x677D162B87B2AC64ULL,
			0x9FD3DAC5E60D7402ULL,
			0xAF02D2C22D9C5B61ULL,
			0x0F4CC60ADE229B5AULL
		}
	};
	printf("Test Case 71\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x42E3FC0A76B163B0ULL,
			0xB0CC3E12CABE8526ULL,
			0x8CCBE9A1D5C1FEBFULL,
			0x52F6FF6F1332A036ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA8C94A2B4897D860ULL,
			0x57B813562A24B021ULL,
			0x27C827BB04A4FAC8ULL,
			0x50A8430CA936E58BULL
		}
	};
	printf("Test Case 72\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA376D484E3CF7868ULL,
			0x8F25948884002112ULL,
			0x03E59068ACD44181ULL,
			0x5272B6FF623DCF0FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x48F18F5810B5FF2DULL,
			0x34A303EEB7BDA36EULL,
			0xC83D0836813F8DCEULL,
			0x75E5D6AE7E8A74A3ULL
		}
	};
	printf("Test Case 73\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8711C4E3648E45F0ULL,
			0x9BAC7A30781B6CC8ULL,
			0xB40CDE7ADCE78122ULL,
			0x7893193E0C7B52D2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1F21770AC4A84B40ULL,
			0x37857F97784DDA1FULL,
			0x03BFA00965EA3EE2ULL,
			0x17928BE1C770D1C0ULL
		}
	};
	printf("Test Case 74\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9E8C12D20419B270ULL,
			0xD90767DCC9FE54FCULL,
			0x422D2E65E92AF378ULL,
			0x75A09C21E65973D7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5F3249DF42D47B78ULL,
			0x421B3C2F286EABD0ULL,
			0x84FA65E3D95484BDULL,
			0x41DC60547B9E553EULL
		}
	};
	printf("Test Case 75\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEE3EB29C97F9D428ULL,
			0x7B14338F19715149ULL,
			0x5109CCD46D3BC1D6ULL,
			0x4C5E22F6F70C3327ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x99A150999DB26574ULL,
			0x900A0A21C289B984ULL,
			0x81787F5CAD49B638ULL,
			0x733F15A7CC32ACB3ULL
		}
	};
	printf("Test Case 76\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x470E660829ED6390ULL,
			0x10AFD87F02516F7FULL,
			0xB6C7DA709FE36C23ULL,
			0x57E855FB262F9B4FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBA8A024CABA18C3BULL,
			0x2FFA5E4778FF736DULL,
			0x0C9767A55289F627ULL,
			0x2CBFA7B10E7CFD70ULL
		}
	};
	printf("Test Case 77\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x84F951AD0DE0DA40ULL,
			0xBF48883885DA8EFEULL,
			0x3E4C6B6BFFEA7425ULL,
			0x7CF58378BCEE20DAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x58F0C024DBA16A58ULL,
			0x979F0F2EA70458C6ULL,
			0xF6948C7CB388BEAEULL,
			0x151A3F39F00330C9ULL
		}
	};
	printf("Test Case 78\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7F4C486127E65428ULL,
			0xDB580C89F34AB656ULL,
			0x8C19E5DADD8FCE4BULL,
			0x6739294F3F2BDE28ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0C158B6A000D34C7ULL,
			0xC68F78FF0293CB3EULL,
			0xE9E801A2923E9EB2ULL,
			0x4862E97D94B8A84BULL
		}
	};
	printf("Test Case 79\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA5A67728DC71E4D8ULL,
			0x299ADF82D8611FD7ULL,
			0xFF78D18D6EB9720FULL,
			0x6523591143618244ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7602D58727A67343ULL,
			0x4B8B8E2019B4A6B9ULL,
			0x30DD55550A6A5D77ULL,
			0x234FF568AA9BD67AULL
		}
	};
	printf("Test Case 80\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB1DCDDEF77211E50ULL,
			0x6C5A5F851D0965ECULL,
			0xAE979FE5E9A4E8B9ULL,
			0x72B550993044B85CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC853E171B088979AULL,
			0x814019B84E3B6DCEULL,
			0x15B150E0C9DFB50BULL,
			0x33968DAF968F64DDULL
		}
	};
	printf("Test Case 81\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x613B0722CF24D858ULL,
			0xE64A2D107CA8C5A2ULL,
			0xD2CC2C2A8EAF55A0ULL,
			0x5E671609D1A4A49BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7A48FB21C679032CULL,
			0x294230C923DC8097ULL,
			0x0C5ECA501F65FADAULL,
			0x5916E899B5A797BDULL
		}
	};
	printf("Test Case 82\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6A5E4B76D4030E40ULL,
			0x6E51465E09E99F56ULL,
			0x88EE0CFDD3D57B71ULL,
			0x4D92841E4EFC189FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x28FBF60752A5B249ULL,
			0xDA5D77A796474830ULL,
			0xD67A41F6ECC31E22ULL,
			0x4216D561970B9C5FULL
		}
	};
	printf("Test Case 83\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x30EC06198FE8C318ULL,
			0xEEB36B031DC5FD3DULL,
			0x5CE977B9188B7F27ULL,
			0x65AB5862BF258C5EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDED289DDEB54911BULL,
			0x774C0C59901E9A0FULL,
			0x2A3BC3B42CD171F7ULL,
			0x539DC89070365076ULL
		}
	};
	printf("Test Case 84\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF1ED3691F01DDF28ULL,
			0x53EEC536C50310ACULL,
			0x3F5DC248A2F5A204ULL,
			0x78F7AD514E8A289BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF13E5B727DD8B36ULL,
			0xB1210D6CC8317064ULL,
			0x6CAF7376E657BCF0ULL,
			0x177908D22B90BA33ULL
		}
	};
	printf("Test Case 85\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x46C6C6A169BD12D0ULL,
			0xA2BD4898D296E746ULL,
			0x12463C356BC3EFE0ULL,
			0x7B5745526C3B64A1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x65E0B5668CED20E7ULL,
			0x4047455A81015BB4ULL,
			0xA5EB64A4FE074E2AULL,
			0x1438CE4C3F0D25EAULL
		}
	};
	printf("Test Case 86\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7F1FFB6CBA6B2F78ULL,
			0xCA61F25018FF52A2ULL,
			0x07C04A5AC6A69FCEULL,
			0x624113893AF8DF1AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE99A6E84C15B0F02ULL,
			0xB5F49514B25CE900ULL,
			0xC3E62D4D2F5027AFULL,
			0x36A097F64D0545B8ULL
		}
	};
	printf("Test Case 87\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEF7B047CC0FA2848ULL,
			0xFC5895100220A47DULL,
			0xCD86788B290EDB37ULL,
			0x6226070C90A2507AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFCCA17CD1D144FA0ULL,
			0x1F4FDEE16148C20DULL,
			0xDE554EC15CA9774AULL,
			0x33B3E7FF4B23EDDBULL
		}
	};
	printf("Test Case 88\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x53E5969DE66B96D0ULL,
			0x56FEA49CEA7D6344ULL,
			0x8F672AB84376B70DULL,
			0x76712487B8351A7AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD8F2E1F01DC3EDB9ULL,
			0xD8EF828F81D0CECCULL,
			0xD3673F92A687110DULL,
			0x0C3E98CF1C7EE84DULL
		}
	};
	printf("Test Case 89\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x447AAE22F3A5DE78ULL,
			0x4BA0C988177ADA0CULL,
			0xE8A2EA6EC9DC0D26ULL,
			0x58E79ECBCAEFFA4CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC74C9A2C3393EF29ULL,
			0xF2BBA661BE0E51BBULL,
			0xEEF6B90A8526049EULL,
			0x39ADB6054F56FB8BULL
		}
	};
	printf("Test Case 90\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD5CCB3A818591F38ULL,
			0x5B82E1D2E28E6E9CULL,
			0xA612A14B15DCA71DULL,
			0x501EBAD33DD7B7B0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5680201D9A52CA01ULL,
			0x1AD79C531D1F1458ULL,
			0xB633067D8DEE38D6ULL,
			0x778EB51A54C30093ULL
		}
	};
	printf("Test Case 91\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x39C07C04C51BB238ULL,
			0x27120201BFE1290EULL,
			0xA69665F376B1C4EAULL,
			0x72F0A9009A050FBAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC4D49070A6B74D45ULL,
			0x7FE0977C5AF7F53EULL,
			0x3A5D5B82F36763A3ULL,
			0x329A5B063A18945AULL
		}
	};
	printf("Test Case 92\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFF60FAD86DF9AE70ULL,
			0x52D7416CE099613DULL,
			0x18C5D2D8602906D5ULL,
			0x65E1F56F1FE16634ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFE5DCE032B6EA937ULL,
			0x075E0B929364EDE1ULL,
			0xFB8B3CCFBD5AD270ULL,
			0x6C268EB21CDFF8BEULL
		}
	};
	printf("Test Case 93\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x227130176817FA00ULL,
			0x7DBEC6AAE3EEF9D0ULL,
			0xC1D94E9F27398309ULL,
			0x5901C6A8D9647380ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEBA1D2E921EBB155ULL,
			0x9B0AC7B608D1448BULL,
			0x9D956E82D8751277ULL,
			0x59FD4748DD3ECF8EULL
		}
	};
	printf("Test Case 94\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x98A8289007E477E0ULL,
			0xECA1F411729E45BEULL,
			0xF14E9FC0A00B1101ULL,
			0x626EF8D2EAF806AEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x192770E53B9FE712ULL,
			0x204213EBE79F223BULL,
			0x101708A5D82075BCULL,
			0x6A8D370762E7933DULL
		}
	};
	printf("Test Case 95\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x64D4B1EFA81858F8ULL,
			0x4E597CA6D595158CULL,
			0x194A6345B66E43EFULL,
			0x5CF75287512DA579ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1026A67E3E92D36CULL,
			0x8B7BBB53835FFFF9ULL,
			0x5AC2657BE0A1BDF1ULL,
			0x3F88B50DFEF8015BULL
		}
	};
	printf("Test Case 96\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5EC240C4088AB0A0ULL,
			0x239FC6AD0F8ADFCDULL,
			0xFA6B0B9E46CCC776ULL,
			0x51C1E9ECE6DAC492ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x92E0E09657D6EB54ULL,
			0x50B176EA126BFC73ULL,
			0xDB880D5FC20EF089ULL,
			0x654CD1F48359CE06ULL
		}
	};
	printf("Test Case 97\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE16588E40CC06BC8ULL,
			0x637B0901ACB119D6ULL,
			0x02A72D2B1CC2389FULL,
			0x5B8A0A38F48BCB24ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x267B1B067959244EULL,
			0x87243D06214977ABULL,
			0x04A17F9CC3EC89C2ULL,
			0x0284024AB6E221CBULL
		}
	};
	printf("Test Case 98\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFD2FF33ED51E35E0ULL,
			0x1859176E6385FBC0ULL,
			0xC3BE611213714A2CULL,
			0x664DBA6543D71412ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x462ABCDB59613C1CULL,
			0xC0C38F12E4F66A03ULL,
			0xFF5A00457FB92AC6ULL,
			0x5C5F4B7FE53E35A7ULL
		}
	};
	printf("Test Case 99\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC156EC3A0D710C40ULL,
			0x0670214F63945861ULL,
			0x7127E15FE75E6C8BULL,
			0x5A94A4542C9FC752ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4FD8B52D2A183E74ULL,
			0x0BB68C6A1EF201BBULL,
			0x6E3C0E58424B43DCULL,
			0x5E58D51BBE1AFFC6ULL
		}
	};
	printf("Test Case 100\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4DA3DC5120DACE60ULL,
			0xFE9924DC651C3095ULL,
			0x41FEEF8A742D2869ULL,
			0x44658BA317A90627ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x242608AA115C1691ULL,
			0x6A92E945FE95C7C5ULL,
			0x8AA684EB5C35641FULL,
			0x1F7858D3E2A8DFC1ULL
		}
	};
	printf("Test Case 101\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBC0D5C2577C73090ULL,
			0x065F28E36A2F190DULL,
			0x2B3DC6A7F9290211ULL,
			0x5F9A2470643CC9BEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCAB8AF3B4F789CD1ULL,
			0x9DBB0012281211E4ULL,
			0x9768347BC822D8CAULL,
			0x656910C030DCC4A7ULL
		}
	};
	printf("Test Case 102\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC0E0B39A4B9FD8D8ULL,
			0xF90C80515E3FB350ULL,
			0x228CD3352EEC99ACULL,
			0x4725C07E3B9E6633ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDAB70FA6813DDF9DULL,
			0xC47083B821A71FCFULL,
			0x4A22D16AEB747C98ULL,
			0x3B0F037EE31D80FDULL
		}
	};
	printf("Test Case 103\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0848C7CB1DE40970ULL,
			0x4A2B0459A03A6FA7ULL,
			0xD7ACDA6871DB236CULL,
			0x49993A536DB5E1CBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBBEEEF8901077590ULL,
			0x87386165547918A0ULL,
			0x9B552CC2AC12334BULL,
			0x1951641F082EF58FULL
		}
	};
	printf("Test Case 104\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x181A7FEE90568830ULL,
			0xFFAFED35EE07524EULL,
			0xDE2EFADAE96854F1ULL,
			0x4B9A118AEE43C81AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC0E4B0E13242B3B0ULL,
			0xB6875873A145373EULL,
			0xB00D5592C4FDFB20ULL,
			0x69A3BE794557F8C6ULL
		}
	};
	printf("Test Case 105\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA10D7F9E6B79C5B8ULL,
			0x0DC087E6DB31401BULL,
			0xC49A65588EFA2865ULL,
			0x6E32BAAD1E57B62AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE16ADEB93CC7EF73ULL,
			0xB5D3711FA22FF43EULL,
			0x58B025F37019B20FULL,
			0x06D013385A156193ULL
		}
	};
	printf("Test Case 106\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA18DFB2DD425C870ULL,
			0x430403AB77980DF3ULL,
			0xBE4794FCF71D5A25ULL,
			0x4DFB20FC27DFD237ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDD227E1696011171ULL,
			0x57428C28830921B6ULL,
			0xD0EA55DD9DCF766CULL,
			0x4D7903322ED34FADULL
		}
	};
	printf("Test Case 107\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x73B37DA25D39DEB8ULL,
			0xF4EBE3488A8813F3ULL,
			0x8E127D4E1B92B88DULL,
			0x47CE78CD1E5D2F9BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4C8F34F7244262CFULL,
			0x32763309206C62E7ULL,
			0xD47A0FC188FE3BE5ULL,
			0x14380B1FE63833E2ULL
		}
	};
	printf("Test Case 108\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1166ACD492F86328ULL,
			0x3723A107F46C7B78ULL,
			0x3F3AF98ACF9B24A8ULL,
			0x66594AAC74F371F4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC06C192919CE21E1ULL,
			0x8F70A5B2C921A480ULL,
			0x3DA6D2F72BD0CA15ULL,
			0x3531DB514D16399FULL
		}
	};
	printf("Test Case 109\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x921DB95D23319748ULL,
			0xD412DF6187AC86A8ULL,
			0xCE41DED545CF099BULL,
			0x5DCDEA2F44290BDCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x65CB00E3C41093A1ULL,
			0x83E696A0B02FFFB4ULL,
			0x4ACCC4820EC21E56ULL,
			0x396608B2C1DF2EE5ULL
		}
	};
	printf("Test Case 110\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA179D4245C2F5478ULL,
			0x3CC82DF67D4CC742ULL,
			0x3342ED7A065FEF65ULL,
			0x7E877CF66B520CC5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x828676E1706555EEULL,
			0x74DD0816DBB245ECULL,
			0xCE4EE6BCD1B97406ULL,
			0x0F770280C258DA10ULL
		}
	};
	printf("Test Case 111\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9C0A338684233EA8ULL,
			0x0FAF29560D4FE8D5ULL,
			0x8B85EC601113471EULL,
			0x501048F8FE64D45BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA57195A999F8B282ULL,
			0x370613532A76F147ULL,
			0x773D07224B2BA3BEULL,
			0x6781ACEDE3480E53ULL
		}
	};
	printf("Test Case 112\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4E32ADB9C1A1D400ULL,
			0x8B4C39E32275640CULL,
			0xAD7C07DC52A00C7FULL,
			0x4AAE99D1C06880BDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA6CF1E73A5A556DAULL,
			0x854429B420EB82AFULL,
			0xBDD18A61935AE959ULL,
			0x29157A6B02CAABB8ULL
		}
	};
	printf("Test Case 113\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF2070D19F0C7E9F0ULL,
			0xFB6F2913D1A71FFDULL,
			0xA9873A604FED9A73ULL,
			0x5BA67990E8D266ABULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEBD601D2A221B3E9ULL,
			0xDFEE7A94754DF665ULL,
			0xDF68A0FECD6DCAA4ULL,
			0x3860FC08BBDB0B8DULL
		}
	};
	printf("Test Case 114\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF5C31D30741BDEF8ULL,
			0x0147D54BAF190F01ULL,
			0x525B47563FF12D24ULL,
			0x59D8495E9367335AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD60C1694A6A0B287ULL,
			0x758C5BE885BD1ECBULL,
			0x4D408F62812411F6ULL,
			0x5FAD2741E5BCA962ULL
		}
	};
	printf("Test Case 115\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE2B8ACB030AA0C78ULL,
			0x56A2E57CEC48D5B1ULL,
			0xD792C8654E3A6900ULL,
			0x4248538522055E18ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x357FF98EFB49DB1DULL,
			0xBD4233E20A15F595ULL,
			0x27B0DFD9906AE6EFULL,
			0x19A4C038D7596C0EULL
		}
	};
	printf("Test Case 116\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5C38243C8A12EB18ULL,
			0x6EAA4597C99C4509ULL,
			0x6544048BB8296FCAULL,
			0x43D20C05F360EAA1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC93AE8683194F026ULL,
			0xFEDF2AF8981CCC60ULL,
			0x92C41CCF39391A4DULL,
			0x1A9072B5C917109AULL
		}
	};
	printf("Test Case 117\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBB648B17A1EF2B80ULL,
			0xEB05E03829FD9742ULL,
			0x5593C4836800E694ULL,
			0x4A3DC12F87DB850FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2D694C5875A066E8ULL,
			0xCE6E26658A83FD66ULL,
			0xFDE3DDC9BEC9210DULL,
			0x019E7FA6658405D7ULL
		}
	};
	printf("Test Case 118\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE738EF6482132898ULL,
			0x9238F329DEFA4442ULL,
			0x8EEBFCA801B711ADULL,
			0x6E52DEA89793684BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8FAC88FBF90DBFBFULL,
			0x8B6FE8072A8C8DBEULL,
			0x0D2FBE9E6DE55397ULL,
			0x037ED7B1EE7FDEFFULL
		}
	};
	printf("Test Case 119\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2890FE59EEA1FAC8ULL,
			0x3F41A41890E59228ULL,
			0x19D614F51D7F7935ULL,
			0x721F1E7F797D2ECDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B23AD27EC108299ULL,
			0x6FD6DA3447BFA180ULL,
			0x1BFABAEBF80DFBABULL,
			0x1B756F1233F0CF1BULL
		}
	};
	printf("Test Case 120\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x468EB2FCF70BDAB8ULL,
			0x8A14078B23FB0934ULL,
			0xD9C8B2F2B017DD00ULL,
			0x49BEA1B38E8E10E2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x47A9E86871E47566ULL,
			0x7BA90BCE01E88C80ULL,
			0x36BB7EE1D99CE91BULL,
			0x590A377200E567C6ULL
		}
	};
	printf("Test Case 121\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x394CBA64524722E0ULL,
			0x2751352B5F50102DULL,
			0x2D61F82CD1EF270EULL,
			0x6FD06EEE06DB9B75ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3922CF9FA14FB9D6ULL,
			0x21FD339C9700C2A2ULL,
			0xB1540CB7C20C621EULL,
			0x455812A458B78C69ULL
		}
	};
	printf("Test Case 122\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA74C473B05602380ULL,
			0xA5AD38FB5F3C7910ULL,
			0xEBA1D8D80265A21FULL,
			0x6305BDBE6CCCE39EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA6D8B945CB10AC0FULL,
			0x0CB01122BFACCB2FULL,
			0x71FD8E5D7548D3F2ULL,
			0x17706CC1369202BFULL
		}
	};
	printf("Test Case 123\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x428E5F1657CACA78ULL,
			0x26618B8E8AA8EF39ULL,
			0xB18614082122131EULL,
			0x7E5C561620276B30ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x91E92A2722D49228ULL,
			0xD42F8762BDAC1AD5ULL,
			0x7CC43C41BC61D93BULL,
			0x7550C2B717D471C0ULL
		}
	};
	printf("Test Case 124\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x369B1D88CB5E5848ULL,
			0x63EBA5BF1019C613ULL,
			0xCBCAA7C6C08013DDULL,
			0x4DE51DBD35F79294ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD819F5DD44F564DULL,
			0xE20BAF7EBA90A2C1ULL,
			0xBE66E63F10E14A8CULL,
			0x6675C09FA4B5860BULL
		}
	};
	printf("Test Case 125\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF710D646FB0197E8ULL,
			0x014B21A662B11F52ULL,
			0xD34BAACF9AB18D57ULL,
			0x7B405CFDEA796258ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDE3DFE0ADE8B0643ULL,
			0x061E6B927B99EE53ULL,
			0x2B93B26C6ECFD2A9ULL,
			0x6FF460C40472644AULL
		}
	};
	printf("Test Case 126\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE0C84C7EC11E1FB8ULL,
			0xFAEDB5A98C9D8EB4ULL,
			0x32DF03A019449132ULL,
			0x79C889EEB7A19D48ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4165DC56364EF052ULL,
			0xB57381ABF01AC70BULL,
			0xF4987025591996FAULL,
			0x31395729905FC6F6ULL
		}
	};
	printf("Test Case 127\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x38DB5B8E0A7FF3F8ULL,
			0x4824DF718BCEA438ULL,
			0x15C7F34BAF6D9F48ULL,
			0x646BF99DA057EE68ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x87F058FA179D745DULL,
			0xA2F251FD290F5C1BULL,
			0xE16738C47F24D938ULL,
			0x32E45FFDF55ECB69ULL
		}
	};
	printf("Test Case 128\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x72985ED545268A38ULL,
			0xD7BFDE53A3C393ACULL,
			0x31C5999CFB35552DULL,
			0x51F44A10EA0D20EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC71B4D2E5C6844BCULL,
			0x12DD122A55B05D75ULL,
			0x013F8B05B8B3D5C5ULL,
			0x6A45DAA48CE288E9ULL
		}
	};
	printf("Test Case 129\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5BAA0182B2B69DA0ULL,
			0x453076B367C24475ULL,
			0x73CE631FC52CCC4AULL,
			0x7B5589DC99634DCEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x032311E6F60C49E8ULL,
			0x6DA13DFD61EF9E81ULL,
			0xE146531E3077ACB5ULL,
			0x2A95632DA0E9F94AULL
		}
	};
	printf("Test Case 130\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB7472EA8FB329450ULL,
			0x2A71D7816AD60511ULL,
			0x31A531C4617CCD2BULL,
			0x5ADF2DE78AE50E6BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB94EEB17C92A9D7FULL,
			0xD9F4F93BF7F752DCULL,
			0xD189658AAD336ADCULL,
			0x0AC010D10DFD7325ULL
		}
	};
	printf("Test Case 131\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB288C4986A83F930ULL,
			0x4DF6308A99E60082ULL,
			0x2ED5C7A9B2D14284ULL,
			0x4F155D9058128DD8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFF24D23B099A690CULL,
			0xCE5BCBD0F4C5A0B9ULL,
			0x619396C577465526ULL,
			0x45819B7649B6FE98ULL
		}
	};
	printf("Test Case 132\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5DAA8498DBC10CE8ULL,
			0x1DB2443FA3447A20ULL,
			0xBFF28310ED93FE65ULL,
			0x59D806E7AF2E655CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8AA7ED363196F620ULL,
			0x29ADA6D2BEB9B0DCULL,
			0x71B4A1AAE139F347ULL,
			0x6199F9F3D6D05D63ULL
		}
	};
	printf("Test Case 133\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x323FB7B625612480ULL,
			0x77B3F1D7B0FE9813ULL,
			0x6011EE505CF1CD2FULL,
			0x730C65CDB4925BF8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1014241086EED728ULL,
			0xFECAE8C8733D3258ULL,
			0x07AFBEB133D876BBULL,
			0x094845BE3DBD66A6ULL
		}
	};
	printf("Test Case 134\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xED805301628A64F8ULL,
			0xEE70569963BB3BFAULL,
			0xF760AB8D26EC541CULL,
			0x5196AB1AB2CD54B1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0905F8B765FB49D9ULL,
			0x2992BA311D22ABD0ULL,
			0xDB9A5827D4E934BAULL,
			0x7F0993A9A1C01029ULL
		}
	};
	printf("Test Case 135\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x64D9C44803D6ACC8ULL,
			0xD88CF9B03DFC7463ULL,
			0x5E507290EDC0CBF4ULL,
			0x71C3E1118FC81F48ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7141F3AC55376CDCULL,
			0x5D6F2C15745A84F8ULL,
			0x9AECA8D8A842EC70ULL,
			0x7567BBD93245E3FFULL
		}
	};
	printf("Test Case 136\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0046FF9BE165B9D0ULL,
			0xF28806B27439F397ULL,
			0xEF67A1597485AC0BULL,
			0x7DD695547654B25EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF9FF1C1FF5C32EFULL,
			0xD351AACA95697525ULL,
			0x714BC64285CC6FA3ULL,
			0x4E34062110CB937BULL
		}
	};
	printf("Test Case 137\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9BDF19897101E580ULL,
			0x8037A20BAB14C041ULL,
			0xD3EE4B192FD7DF35ULL,
			0x747DBCEBD8C178F2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x75288387FC07DB39ULL,
			0xCCA53BF2356A904CULL,
			0x73AE0DD3739F3688ULL,
			0x578C011F195F5F31ULL
		}
	};
	printf("Test Case 138\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4E182FB1F388A6E8ULL,
			0x9C3349CE8413F7E5ULL,
			0x8DC98F873CD3D6DFULL,
			0x685E505576C9294BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCBBA29F139B53756ULL,
			0x632C24C1450E273CULL,
			0xA45A6D37495F3878ULL,
			0x17942965A39DB0B6ULL
		}
	};
	printf("Test Case 139\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFD2AED7899660340ULL,
			0x0668CD0E8A3B57EDULL,
			0x79EE0711977BB83EULL,
			0x6744C6599C173554ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF9AAF550E7605B5DULL,
			0xC416E54E3C1740D4ULL,
			0x55A16596888347A0ULL,
			0x5790719C37605F30ULL
		}
	};
	printf("Test Case 140\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDB859B5303EC29B8ULL,
			0xEB3D7DE5C0DC0E2DULL,
			0x8DB149CADE2B1CFAULL,
			0x66E647681FFBCD06ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB6D699703C126D11ULL,
			0xCF36E180DF98EC32ULL,
			0xC38840E91FB3B361ULL,
			0x1B5E833C8FB924FBULL
		}
	};
	printf("Test Case 141\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE856CBADC6592DF8ULL,
			0x8A72E4E9954D55FFULL,
			0x2E3944D1077070F7ULL,
			0x7550E6C84ABA0BCFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x161EFB13C80609F1ULL,
			0x063026267426F71EULL,
			0x020F47831BF173A1ULL,
			0x41E4E76D03987AE8ULL
		}
	};
	printf("Test Case 142\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9FA1CD246D2BDDE8ULL,
			0xC430F2A09700815FULL,
			0x265F0302CFAE15A4ULL,
			0x7DDAE4EC6742CEA2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x181F8EF42CE83230ULL,
			0x6CBA65B2F87F8E71ULL,
			0x361EB38AEA263369ULL,
			0x4923904F6AAAB47BULL
		}
	};
	printf("Test Case 143\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x52C3179BC55EB3F0ULL,
			0xF2E9A570FB87CF2BULL,
			0xE98D15F05B633B73ULL,
			0x51D55EB3CCFD8582ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x47EA9D245191DC80ULL,
			0x53691A4D76ECCF44ULL,
			0xDD1306098B48E9D9ULL,
			0x06A87A8EF5E65E0CULL
		}
	};
	printf("Test Case 144\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCDF0E10838AA1778ULL,
			0x6CB2E12EFEF9E83DULL,
			0x3F33A3940FB309D0ULL,
			0x642822AA41873A72ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFCB578BB6F024137ULL,
			0x728217B0424F7350ULL,
			0x29CF519C44026FA4ULL,
			0x3DDE39CD68DE9078ULL
		}
	};
	printf("Test Case 145\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA1029B2D36E2B4A8ULL,
			0x434DD747AB2DCE70ULL,
			0xA9075FD3D59B65D2ULL,
			0x573F7731A0A5450AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9C4EC09AC0E941FDULL,
			0x849EE5A26076E2BFULL,
			0x0E5976EA883E351DULL,
			0x12B4E37961CE7AD8ULL
		}
	};
	printf("Test Case 146\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7F8F70A23B591AB8ULL,
			0x11EF9F6DEB837D09ULL,
			0x355150F372A7D6BDULL,
			0x5C5A8E8E7EE97E41ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEE40629CBC296F8EULL,
			0xE08F3C91DD074FDEULL,
			0xABABC60A7FBC9500ULL,
			0x1E70A5A62D58036AULL
		}
	};
	printf("Test Case 147\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9D562D7DA0860D68ULL,
			0xAA02B35822B64419ULL,
			0x23D6258B261BEE41ULL,
			0x42928F0D99185765ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8EBBC3D01E27B80EULL,
			0x5255A2ED09EDF2DAULL,
			0x94ED0D21B323DAE3ULL,
			0x58A2F9EF7EAE06CDULL
		}
	};
	printf("Test Case 148\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD19B5F503AF77AE8ULL,
			0x05ACFF692411DB64ULL,
			0xF7E46B01D12AB89EULL,
			0x6D8694A0E89C1F37ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC31B5DCA67B910E0ULL,
			0x3BF1936FECFB118FULL,
			0xF6F659467C17E4E0ULL,
			0x24A5689A52AF5FA5ULL
		}
	};
	printf("Test Case 149\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x17512D11DBE0BDE8ULL,
			0x84FCA36D02C0923CULL,
			0x3D82B32DAAF77F03ULL,
			0x4E2A40B8CE73CB43ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9BF75DEE4623F283ULL,
			0x4E85C467F9F6B841ULL,
			0x82B2971088D03CFAULL,
			0x08E95EC62A1AB6AAULL
		}
	};
	printf("Test Case 150\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x469F8FED03E36CA8ULL,
			0x75BAF2A171E527CAULL,
			0xF1B50C3BDD2540E0ULL,
			0x7A84A64FB46C4D7AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEF2BA4167A62C263ULL,
			0xC85AC71B80DB2E8FULL,
			0x87DB7F7BFBB0C6E8ULL,
			0x057E2F8D60136B05ULL
		}
	};
	printf("Test Case 151\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEFBF9EECACDF8718ULL,
			0x21452813DB326C57ULL,
			0xF13C283A9233BB8CULL,
			0x4703BE2C39EC4B60ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6EF69447816E395FULL,
			0x50C7BC11B1D976A3ULL,
			0x715F1EE7F8DEDD93ULL,
			0x2360D635E6586C6FULL
		}
	};
	printf("Test Case 152\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA5BFAC9E254B8288ULL,
			0xF6AAAA667662A997ULL,
			0x56A0979480F696E4ULL,
			0x47F64AE3C29C784FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3FA82A95BF806A98ULL,
			0x209DACC4A38BF7A5ULL,
			0x34E59E8880D9B499ULL,
			0x22A807A730CE9608ULL
		}
	};
	printf("Test Case 153\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x594A4771DC238270ULL,
			0x4B1272A0EBBAB746ULL,
			0x810C19CF18DB247FULL,
			0x41F2A23A7A53AA99ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x107A57FB0C7CC440ULL,
			0xB1A6077E8EC6633DULL,
			0xD4D6667BD5A903C7ULL,
			0x7ADCF8BE713B2BD1ULL
		}
	};
	printf("Test Case 154\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD92381BB543CE030ULL,
			0xF419E3D5D33F7881ULL,
			0xB88CAE9BB2AC260EULL,
			0x7D8B899F57119E96ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3B007774EBFE1387ULL,
			0x1E8ED738DD6B0920ULL,
			0x272B2049C327588DULL,
			0x7E5D4DEFA6E1A12EULL
		}
	};
	printf("Test Case 155\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x61414A7D944843C0ULL,
			0xCD7DB215873CAD26ULL,
			0xBD13F63F75D946B2ULL,
			0x7EA7149BB8F2D16FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA1EC0C5E99D7D36BULL,
			0x1C60AD798104E454ULL,
			0xB983F37D47E182E7ULL,
			0x5B438255699DAA1CULL
		}
	};
	printf("Test Case 156\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE0FE4F491F05B6A0ULL,
			0x6ACCE01CA1072560ULL,
			0x2809F466C3067195ULL,
			0x6F4DC95256037E3CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAA9B45ED0C8636C0ULL,
			0x3198672BB875D553ULL,
			0x2188289538D0AA27ULL,
			0x1D9BB9B81120521BULL
		}
	};
	printf("Test Case 157\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x225ED7D97D9C95E8ULL,
			0xD647AD44152F8D9DULL,
			0x436FA110DBEFB733ULL,
			0x731ED0415ABA2074ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x35E881F5A7393F9BULL,
			0xDEDA7D5CCBA09409ULL,
			0xC6A79940CFF78B34ULL,
			0x006A5E30EFB8B2EBULL
		}
	};
	printf("Test Case 158\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA4190F0E512C7768ULL,
			0x78733CA667134D0DULL,
			0x20CD7CF123A4C1B0ULL,
			0x68E9CF8471A3AF26ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x27AF0001709EB5EFULL,
			0x05D4CACB7DACA6F7ULL,
			0x3CD87D54EAD39DAEULL,
			0x36748F441F5E94BDULL
		}
	};
	printf("Test Case 159\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF4B35CBA15243B18ULL,
			0x4B8BBFFDAD023AD1ULL,
			0x14FF82741CC0E706ULL,
			0x7F428C000D71D463ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x16205D4EEC99CE1AULL,
			0xD54281DE31325711ULL,
			0x1C9D6D73F17EB515ULL,
			0x306A3AFB7719BF46ULL
		}
	};
	printf("Test Case 160\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6AC506FBDED55E50ULL,
			0xBC9F06B3BCC86A4BULL,
			0x3430126D61B97836ULL,
			0x7E6F92EA7A9F52C9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD9D66CB7DD9E5744ULL,
			0xF2611AD3B5B2CBCBULL,
			0x5891F81F620C4E48ULL,
			0x05E3185EBCD997CCULL
		}
	};
	printf("Test Case 161\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x26FFAB0EB7CE8C88ULL,
			0x54A7E5372B709BDAULL,
			0x9421052FF8A4E0D8ULL,
			0x58C644B4D8F62282ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF87D9D6F1D2A9B69ULL,
			0x835321B880EA2BD7ULL,
			0x79D370F9262343EEULL,
			0x5825A9AF7195713AULL
		}
	};
	printf("Test Case 162\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1B354CAEEB02A428ULL,
			0xF6F688FE1CFD82DEULL,
			0x2C6859D24379DBB0ULL,
			0x4505D5B854353DF7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF07B016C5D2C2A1ULL,
			0x1928AE0BE5ABA40AULL,
			0xC8C4A6C88A9F091BULL,
			0x34DA09F3ACF661D3ULL
		}
	};
	printf("Test Case 163\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB25E65A4CF285F58ULL,
			0x601CDFFA6112DFA9ULL,
			0x1B8D5EA15BDE2B92ULL,
			0x580C1FF413DC2767ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8E37354F3317EF2BULL,
			0x16FFDA9300A7CFB9ULL,
			0x0CFD2B71C1A86E67ULL,
			0x3C202A87CDE8AE20ULL
		}
	};
	printf("Test Case 164\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEF957D18A90FB5D0ULL,
			0xC4CDDE4A89FB1F7BULL,
			0x5B4CF9984B537542ULL,
			0x497FA24F87213F5DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE1196981099D7206ULL,
			0x4EE9A2F5F81DE277ULL,
			0x1040A8610D77FD88ULL,
			0x7CE9FEDBED1D08E5ULL
		}
	};
	printf("Test Case 165\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA349C82389B79AF0ULL,
			0x1833CA739891F886ULL,
			0xB399E8CB56F677B6ULL,
			0x6E4868F67518148BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5DDEBDC34F703C64ULL,
			0x0876D88B475162BCULL,
			0xE681A8F7F5980277ULL,
			0x64C56C84019387A0ULL
		}
	};
	printf("Test Case 166\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1689B34D5BAA6470ULL,
			0x31AFB18E64F28899ULL,
			0x25CBAD218DA636E7ULL,
			0x74D2C45FC3C27B36ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB4849100A68D46C2ULL,
			0x8CAFB5B48907668FULL,
			0x3134DF790FF84160ULL,
			0x5AA963C038042AB7ULL
		}
	};
	printf("Test Case 167\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7825E4D01753BBB8ULL,
			0xF509A6FA4A23B833ULL,
			0x359381BC938A8F73ULL,
			0x53D2B889365AF4B2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x425B217D0A9B3E4EULL,
			0xAA8779A5B922524FULL,
			0x287527C8504D48B8ULL,
			0x5CE7E03085933A50ULL
		}
	};
	printf("Test Case 168\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x030AC10565DB82F8ULL,
			0xA7F59C433071D48DULL,
			0xD8B4C515AAD007E8ULL,
			0x5302A20C57A530A9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC99B27BF6428AB6AULL,
			0x0BDB5F47781B0EB9ULL,
			0x7FF29BF12852DC17ULL,
			0x4869B3A012B933EBULL
		}
	};
	printf("Test Case 169\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8C7E571CA9DBB1A0ULL,
			0x78E56A3C7653C2AEULL,
			0x311984B71B55118FULL,
			0x48F5C851181FF7ACULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE5F7AA5DC57EAAD1ULL,
			0xCCD54C38844489C2ULL,
			0xA4A968A2C8C285CCULL,
			0x6B2B759BEBBF09FDULL
		}
	};
	printf("Test Case 170\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x08B0D3008B269A58ULL,
			0xFDC7B6341A18C6FFULL,
			0xA9D94F0FF144F1E0ULL,
			0x621DDEC82D38D660ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCD0E6D5ACD178187ULL,
			0xAA132D48F1F30683ULL,
			0x9C573E8BCD232586ULL,
			0x6E0CE9CB89D99A38ULL
		}
	};
	printf("Test Case 171\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3255D3B2F905A850ULL,
			0x371E8E8BD5012631ULL,
			0x939676CAA4158D1AULL,
			0x50DC175343FE9408ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC1BFD6B1B3984988ULL,
			0x22E83C4792943B10ULL,
			0x451614F009794B02ULL,
			0x5C409489CC0912A9ULL
		}
	};
	printf("Test Case 172\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC23CCEFE37A709A0ULL,
			0x8175C54953A3F5F2ULL,
			0xD483F8ABE6042BB5ULL,
			0x5E8328A0132DAEADULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA357CC88F36FB084ULL,
			0x646379680DBBCD17ULL,
			0x8E1CA8A13CB3895BULL,
			0x4C2357C4A10BF540ULL
		}
	};
	printf("Test Case 173\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x396DAC7CF09025D8ULL,
			0x2B4A99FDA812DA3CULL,
			0xAADF5A150162E47EULL,
			0x49572AE337D21C3DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x023B9B6EE9CC2357ULL,
			0x21A5C82E27BEA22AULL,
			0x0299F9671B1CA3CCULL,
			0x11E69C136A035800ULL
		}
	};
	printf("Test Case 174\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF18316941664D3F8ULL,
			0x7FB9A4EB679D49F5ULL,
			0xF35D4CACC4A450A3ULL,
			0x60B9FA87D197F9F4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x19394011E3AE7B92ULL,
			0x236D7A2D182DD1DEULL,
			0x437AEB4537864763ULL,
			0x7E4CF0898C90D9C6ULL
		}
	};
	printf("Test Case 175\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC552201B357950A8ULL,
			0x060472DD3C9D9ED9ULL,
			0xC402873720F7F454ULL,
			0x63BA33327739A6FBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFAB2E6A2CA592750ULL,
			0x2C06C08A24CD93E2ULL,
			0x9DE7DF7C5C4CAEC3ULL,
			0x59D66162F927EBB4ULL
		}
	};
	printf("Test Case 176\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE96507E3C7EEC7F8ULL,
			0xD0FE0E5BCD2DBD17ULL,
			0xB48CB1B918F918B6ULL,
			0x6595673F59DF540EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC35D3FB880310EE9ULL,
			0x03228A448C31D82EULL,
			0xDAC44182615AA619ULL,
			0x2D9E0C4369B38EA2ULL
		}
	};
	printf("Test Case 177\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x26E0F8A3A43BFD48ULL,
			0x3C4D2EE452455AB0ULL,
			0xCE207A7E29AA4CEDULL,
			0x4CF8D5627EBAD8C4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x20E8466991BDDF89ULL,
			0xCDA98AAC9D14B429ULL,
			0x2D62B65D441896BEULL,
			0x61C696F4EF8BD574ULL
		}
	};
	printf("Test Case 178\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC88BAA942BFD3D68ULL,
			0x9EBD89CFE3B75FABULL,
			0x0110EB5196F7994DULL,
			0x6A837631CC49E049ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1B63164081E851E1ULL,
			0xF860C05093A8A519ULL,
			0xF49966775E94A08AULL,
			0x1C29FB171E1AF79AULL
		}
	};
	printf("Test Case 179\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8C1D766C54E2D578ULL,
			0x121502428B2C539FULL,
			0xEC38058D1D8C891DULL,
			0x5AD484E268E29B78ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0A6205FCA017F91AULL,
			0x5DE3B1A62328218AULL,
			0xA7E5E05367FF0CA8ULL,
			0x6459DB32FF9A5E64ULL
		}
	};
	printf("Test Case 180\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x42369239B31411E0ULL,
			0x6540FE438F7C32F3ULL,
			0xEF0A8EA796BEA815ULL,
			0x5F47878FF26D0E4CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE061FEB355BA9D6CULL,
			0x0776D747F77554E9ULL,
			0x6CBA3BB3F9BD4E9BULL,
			0x5983AAE9252612EFULL
		}
	};
	printf("Test Case 181\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF3391FB2510F7598ULL,
			0xDA0858F2F807FAB6ULL,
			0x55234C33A2599BFDULL,
			0x4E5B4ECDA4C9F00CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3AA9062A2928FC9FULL,
			0x894CFD426155985DULL,
			0x79B2C299829939ADULL,
			0x4D46A3C799AA6D39ULL
		}
	};
	printf("Test Case 182\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x163481EE6BAB6790ULL,
			0xF8FAF4934A77A97DULL,
			0x9FD6F2FE0A9AA7BDULL,
			0x52ED4C267C559970ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x03EDF4BE18C80B64ULL,
			0x89844DA6C84EE198ULL,
			0x817F6E8C81DCE7DDULL,
			0x19FC2ECAF793198CULL
		}
	};
	printf("Test Case 183\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFAF41B44823F5E98ULL,
			0xBFDB180CBD36FE7BULL,
			0xD84DFAAC9ED94224ULL,
			0x566239A9664B6541ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1AEADFA5411715C3ULL,
			0x1E98586CDE349D6EULL,
			0x692E8AFE1399930AULL,
			0x7874C6577707E228ULL
		}
	};
	printf("Test Case 184\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3BB409BD51AC7530ULL,
			0xBF748086336566DEULL,
			0x70F559B5F0F93AF7ULL,
			0x7C5B3332A4C92ADCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8441E29479E4D1C3ULL,
			0x2D9C688A5CBCF364ULL,
			0xA725A2632438CE42ULL,
			0x254A0DCB59BFEE48ULL
		}
	};
	printf("Test Case 185\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0BC4D0ECE0092740ULL,
			0xF0E7D1C0DCC63609ULL,
			0x05021C90EFB5FB46ULL,
			0x66FFEF3E7C77F6D7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEAB1FF6B7613ECB3ULL,
			0x9F1F500038717B80ULL,
			0xEEE027D8D37DEF83ULL,
			0x61DF46A4C8C23ADBULL
		}
	};
	printf("Test Case 186\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA9C4075A465FF558ULL,
			0x1F20BECFC6D3EFDCULL,
			0xF3573B31AB3D66E5ULL,
			0x416F5741509C06C9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3209F291E5D61FA5ULL,
			0x6796C92268CC14A1ULL,
			0x8B88ECD1C5C59FD1ULL,
			0x67E3F217AC6213C4ULL
		}
	};
	printf("Test Case 187\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAB926F825295DA08ULL,
			0x02EE5FD451439D9CULL,
			0x1461AC628C2F1036ULL,
			0x4D020F4D685204A5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x505E62874062696AULL,
			0xCDCEE28BFC90FE30ULL,
			0x1F0940F2F012254FULL,
			0x2A7A9D543CAB9B41ULL
		}
	};
	printf("Test Case 188\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8F6669E7C43554F8ULL,
			0xF1AB4B3FE7179A77ULL,
			0x1DFD6D4E08A40636ULL,
			0x5252939DC68E1915ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2E557E1474CB3016ULL,
			0xFFB191173F2E7BB9ULL,
			0x923F6BA52FC52A7AULL,
			0x4C383EC9B5909622ULL
		}
	};
	printf("Test Case 189\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB864237D501BF568ULL,
			0x009B54761880C606ULL,
			0x5A9F57899DB8B796ULL,
			0x4B4436145880ED40ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC8D7C94C1E0806EEULL,
			0xCCA2B90F35572036ULL,
			0x711581E7A66F8C7AULL,
			0x130FF62507C32DC1ULL
		}
	};
	printf("Test Case 190\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD3F2924BFC876D58ULL,
			0x65A24B6269663944ULL,
			0x4C17123EC3E96C18ULL,
			0x7E1CBA0220D07903ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9E7F69559B257501ULL,
			0xA2BC81E04731C417ULL,
			0x93B4E606735B1ECEULL,
			0x1A1D8E186C6C1A82ULL
		}
	};
	printf("Test Case 191\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4251C8A497485E98ULL,
			0xB153314D540A1A1FULL,
			0xC184DC039B9A12DCULL,
			0x70C148E2B441B111ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0EB967DF468A1294ULL,
			0xDFF7B043BA3509F8ULL,
			0xA14312734E782380ULL,
			0x55C05AA6D0C8ADA3ULL
		}
	};
	printf("Test Case 192\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD63995BD0F730EF0ULL,
			0x35CB378FC2C44202ULL,
			0xDD3F1402FE18A09BULL,
			0x5FCA44CD0A3B8A63ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3A4ECD321169D431ULL,
			0x8894691DA0C17B91ULL,
			0xE0079F0BAD0722F8ULL,
			0x763B810BB5AB040CULL
		}
	};
	printf("Test Case 193\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2C5F6A13AD7D8B98ULL,
			0x2249ACCD5C342F3EULL,
			0x8DAF52C59D8D2C5BULL,
			0x4FFF853315529D60ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6318D5DA869A1AF2ULL,
			0x8AC094DAC841BB97ULL,
			0x898206AA444416B2ULL,
			0x456DA2BA34793D2CULL
		}
	};
	printf("Test Case 194\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2387631BF1C9AD40ULL,
			0x970152F0C992635EULL,
			0x1266C24077C2043BULL,
			0x73E4D589DBE89927ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3BCD26318CCD894AULL,
			0xF1EA171D46C8B7DFULL,
			0x0FB63E210416FB7EULL,
			0x743046E560A0D3CDULL
		}
	};
	printf("Test Case 195\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1C9C3A769C28A038ULL,
			0x2E54EEB434D9F028ULL,
			0x70D5ADFB7A355567ULL,
			0x50552F49E780EEC1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBC4EC5182339774BULL,
			0xB3A612B189315A97ULL,
			0x5AEB15993FB95C32ULL,
			0x3770B365A44B147DULL
		}
	};
	printf("Test Case 196\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE88287FABFD835B0ULL,
			0x2027BE2EF897B04BULL,
			0xA7D4CB3AA381422EULL,
			0x67B9AD002DF64C14ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB1A73319C31DB755ULL,
			0x0EF0A6848B997646ULL,
			0xDB201223947DB666ULL,
			0x4607E52DE6B3D58BULL
		}
	};
	printf("Test Case 197\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC6EBEBB265467858ULL,
			0xA4B6154D122FC2EAULL,
			0x45997295072D5C88ULL,
			0x53648C3FE9C13640ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF197DEFD1BB360FULL,
			0x35A1D3FDCCE2FFF5ULL,
			0x6B8313EB15617598ULL,
			0x2E44957C9AF765CEULL
		}
	};
	printf("Test Case 198\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2212094A0C347AD8ULL,
			0x1613F199E1BEA104ULL,
			0xC6584D46A6449AFDULL,
			0x4FFA4835511A64A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6C3B8DB238C72E0EULL,
			0xE764AA689ED67505ULL,
			0x24B40BB6D25F6D5AULL,
			0x4DC2009B8971F5C1ULL
		}
	};
	printf("Test Case 199\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD1236393A80238A0ULL,
			0xE86F58F1F3D26904ULL,
			0x9BA6E8393C4FA1C7ULL,
			0x61908815B93D1E47ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0DAF38BF5428690CULL,
			0x823ECCE839C1CD7CULL,
			0xE13FF590A3EDD808ULL,
			0x1BB595F2018F4E02ULL
		}
	};
	printf("Test Case 200\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x538867F32B8D82F0ULL,
			0x3FCCFB7E4FA9190FULL,
			0xFED6ABB96FD8189FULL,
			0x793A127DC81DA525ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1836CEDB6FCB77B5ULL,
			0x375A7FA0FE07A68EULL,
			0x6E69F57636ACC47EULL,
			0x769AA0345F3068C0ULL
		}
	};
	printf("Test Case 201\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x89B87F4829EC7820ULL,
			0x73598848E1410692ULL,
			0xFA1AC62BA03CAE5CULL,
			0x47FD30DEC05ECFB8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9870C37B9EBD3ABFULL,
			0x626A7550D3FBAE47ULL,
			0xEB6FBD7921190CEFULL,
			0x35FB32F7B942F5DEULL
		}
	};
	printf("Test Case 202\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x516C14913653FCA0ULL,
			0x8701BB1F73866EFCULL,
			0x10E4C39F5A5CEEB0ULL,
			0x6D911333CDEFE355ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8FBACC98FBC15C5AULL,
			0x29D334BF433F463CULL,
			0x32D1A1C77B3B405EULL,
			0x105DDFBF5F27EA0AULL
		}
	};
	printf("Test Case 203\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA32DCE6C219F6D58ULL,
			0x36F00C3842A91FF9ULL,
			0xAA5DF3C304DF2F7FULL,
			0x738FBAF570A57723ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6E2EBBFCEE247087ULL,
			0x0756B2348F02C5B6ULL,
			0x3942AF2EFC0786EDULL,
			0x038C87FF34C657AAULL
		}
	};
	printf("Test Case 204\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x77AEE19E4FE05BA0ULL,
			0x3234C9F86AA2807DULL,
			0xF07A975B7E4A152AULL,
			0x7E67A0E3A10F24E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x74ABD234E5BAEB7CULL,
			0x4E10188C8D0C688AULL,
			0x1276E176916375D9ULL,
			0x5E66116D7EB569C9ULL
		}
	};
	printf("Test Case 205\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x286FCE8E994D7C10ULL,
			0x025EDF11C2269126ULL,
			0x8AC3B2EFD860E5D7ULL,
			0x5B488425C8363F30ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB0911BDF153885E9ULL,
			0xF063EB346F644325ULL,
			0x60D223311FE34CEAULL,
			0x201DE22F19111BEBULL
		}
	};
	printf("Test Case 206\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDBFC793BD7BFB4A8ULL,
			0xF04DC67248A87CA8ULL,
			0x59A3C45A46F7CFF4ULL,
			0x6505BC3727D36CABULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1B17876265493E5FULL,
			0xFB6A8C9D8A09BBE1ULL,
			0x410C6A9BA4EE109DULL,
			0x06BD851B11613002ULL
		}
	};
	printf("Test Case 207\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8C1B9FDFC3458870ULL,
			0x8A56FC10AD6609F7ULL,
			0x02E574EF7CC6D9E5ULL,
			0x444C3BA97787A8E2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA7D226818583A85CULL,
			0xC434FB3EA7770DA0ULL,
			0x12470DDCD08118BAULL,
			0x7D8C96543BCB5EA5ULL
		}
	};
	printf("Test Case 208\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC7AD03308F07E0B8ULL,
			0x5008CBD5D554C985ULL,
			0x72EF7A37DD50B73FULL,
			0x49231AFB3EA92111ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x14623A5A785EF988ULL,
			0x6E6647AE741AF85EULL,
			0xE31F8FFA8C197DBDULL,
			0x5ABDAFC27BF157D9ULL
		}
	};
	printf("Test Case 209\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x40EDF818D6A72D18ULL,
			0x0171DA9D22C6219DULL,
			0xE891C67D636CD8A9ULL,
			0x6D79D5B3638DE4F9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x73BE2801EEAFCD22ULL,
			0x6E47EC2DCF933A90ULL,
			0x604159CFB5E37BCEULL,
			0x350DE39010AFAEE6ULL
		}
	};
	printf("Test Case 210\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x94C81C7D79B5A720ULL,
			0x975D0F26C4D1CC4FULL,
			0xA78865C0F1C1022CULL,
			0x408AB39E64A51AC5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2A188FF5DBA484DULL,
			0x338C3CB61EDE6462ULL,
			0xF17F33830BACABF6ULL,
			0x1096EDC648618561ULL
		}
	};
	printf("Test Case 211\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4414113FAB774E08ULL,
			0x57BE7779B5DABF36ULL,
			0x9C4D2D029EC9EC61ULL,
			0x7D53412963918F50ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x15FF24D51C7A0461ULL,
			0x9DB18E1EEE4C4A76ULL,
			0x0D190DE36D96FB69ULL,
			0x32B6A27729413329ULL
		}
	};
	printf("Test Case 212\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBB13869DF987FEA8ULL,
			0xF0A13A6772CEB209ULL,
			0xE259EE10DC394E34ULL,
			0x6CBD76F81E4092B4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x610CCE09014E21CCULL,
			0x6922E82F6943FF6BULL,
			0x1486BE1C01D4610CULL,
			0x020C1DB54B33C1F6ULL
		}
	};
	printf("Test Case 213\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x15207E286AE6EC08ULL,
			0x48E8543B4AD4C8D1ULL,
			0x6DC3FDDC3262784EULL,
			0x7F575F3B7533AB0CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB2529BAAD6595468ULL,
			0x2475D4F21A207F7FULL,
			0x492A2B034367BAAEULL,
			0x06B0B6566DAE14EFULL
		}
	};
	printf("Test Case 214\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x70E2D3B78474F6C0ULL,
			0x147D71C7EA223048ULL,
			0x9CB3FE6162720DBEULL,
			0x4E31074D09EE0365ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2B4012F28CD060EULL,
			0x64B606E859FB35E6ULL,
			0x9A1878DED7ADF2B6ULL,
			0x6C32138CAFAF322AULL
		}
	};
	printf("Test Case 215\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4D1D55EBCF7FF600ULL,
			0xDEFE2370849D86BEULL,
			0x5EDEDCD38E10F4DAULL,
			0x75D8720D9BC5D464ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x301DCC1396167673ULL,
			0xF4BE3A8D963B4740ULL,
			0x7378BE728C0D264EULL,
			0x25839E9F1DFD52B2ULL
		}
	};
	printf("Test Case 216\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x62C3F531BA3AB428ULL,
			0x268ED86002F19B50ULL,
			0x63C0E837CE8DB2A7ULL,
			0x7A837C730B5E4023ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7C6E149ECDF8899DULL,
			0xFE23A1A5B5135704ULL,
			0x7F7FFB83E5A8CBC9ULL,
			0x387D998BC72ED843ULL
		}
	};
	printf("Test Case 217\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCFC40C7FF3943348ULL,
			0x0EAB81797EF60EB7ULL,
			0x2188A0653B515785ULL,
			0x6E04CF58D0ACA2F6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x40129954A2970BEEULL,
			0xFAA217D39B9E26C7ULL,
			0xE8DF49F5F2FD0F1BULL,
			0x0506F3D00F010304ULL
		}
	};
	printf("Test Case 218\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA7A8C9074B03E9B0ULL,
			0x4A8B5C2E4A8ACD72ULL,
			0x82820F881E493DF6ULL,
			0x44090F5ECE675ABBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC66DDBE64BE3B710ULL,
			0x1F747DFF2F6261B2ULL,
			0x969E6C8ABB6F0825ULL,
			0x419F127E16C7CAC0ULL
		}
	};
	printf("Test Case 219\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF45FDD7682B83548ULL,
			0x3DB024747780E61FULL,
			0x1EC57C5CED0A311DULL,
			0x6DD7F4DEAF63F346ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6A23AD9770F21DBDULL,
			0xAA966CBCABFCB3CCULL,
			0x3093BA4A166CB0A1ULL,
			0x7CC64CF4DE005886ULL
		}
	};
	printf("Test Case 220\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x648CD2AD8A570A90ULL,
			0x94EADFBFCB4F9B9EULL,
			0xA50EB98041B93057ULL,
			0x5966D1970F7FF526ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE021F0E47676A40EULL,
			0x9F9626A10C597966ULL,
			0x9F67E94F1FCC53DCULL,
			0x3D2D32A02CE64BB7ULL
		}
	};
	printf("Test Case 221\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEFAFEE2AC38EFAF8ULL,
			0x6A2E645AF07B260DULL,
			0xC8D009505A6871DEULL,
			0x6E4749432057FDE0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x753BCECA13EBC242ULL,
			0xF2442119991CFCB9ULL,
			0x223B55275B29C5CDULL,
			0x21F6766520B31DB2ULL
		}
	};
	printf("Test Case 222\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA0E1CE44DBF5E620ULL,
			0xC808FE6158C32834ULL,
			0x6787F91240276C96ULL,
			0x6B9BFFAEB02736E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD5A41E46A373C01DULL,
			0xA3018972B0D14355ULL,
			0x0720E977427C1090ULL,
			0x171BF8680616FE6EULL
		}
	};
	printf("Test Case 223\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC0226148DDC10410ULL,
			0x08DFD510674F7669ULL,
			0xDAC115FFDB6C008AULL,
			0x464F0C871BB9B279ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC1BE2E462D430A3AULL,
			0xC4C992918C52C9E7ULL,
			0xADB78E69A9547A2CULL,
			0x26E0A582051A0576ULL
		}
	};
	printf("Test Case 224\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x39F922EBF9904848ULL,
			0xEEA314AFAA45A9C6ULL,
			0x8E08949883517A1DULL,
			0x6985D783120B4F20ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAB9A4E4B3EBBAD29ULL,
			0x47EFBB1A6985D5B7ULL,
			0x1039594165624838ULL,
			0x74FAA718DB93361CULL
		}
	};
	printf("Test Case 225\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x380A42313EFDE060ULL,
			0x1492C608CA2E9E89ULL,
			0x9A7465E4E6C7A886ULL,
			0x5FD3C5DDEDEADDC7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2EDC41D9ECF9B24DULL,
			0x9CC2EE26405EBA72ULL,
			0x75F3E1D5871C3DA1ULL,
			0x747AA296C5B02F38ULL
		}
	};
	printf("Test Case 226\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA7F9D4FEA81464A0ULL,
			0xBD3625F0B75F3FF9ULL,
			0x3CFCC0DC03CC1641ULL,
			0x7892ACC084C51FC5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE4CBAFFA660EF7B4ULL,
			0x3218C81E89FC1ACCULL,
			0x3B5E072027E7072BULL,
			0x0E834A31152C475DULL
		}
	};
	printf("Test Case 227\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x17631D7CCCDBCAC0ULL,
			0xCB9CE71A6A77F1B6ULL,
			0x403CAC5049512AE9ULL,
			0x40A7E9DCD5AE2A98ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8CA7029E2D29DA4FULL,
			0xEFCDCBC25D730302ULL,
			0x05B4BFC385545BF7ULL,
			0x5D45D43BB846E784ULL
		}
	};
	printf("Test Case 228\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAFA1CAF9CF9CF7D8ULL,
			0xE92741CF030973DDULL,
			0x549F17B2AA1FD43DULL,
			0x645DC4EB57D5848FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x19A8DEC463D45D7DULL,
			0x199E70D0166EBE4DULL,
			0x6B3F5E30B736C7E6ULL,
			0x100EB931E742CC2EULL
		}
	};
	printf("Test Case 229\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1BE56D1F986ED518ULL,
			0x3DC027E10647684AULL,
			0x1DF37FF346ACAEBEULL,
			0x6498CBD048433078ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3D1E4C3E7A8B4D6AULL,
			0x7182930FC8B63802ULL,
			0x2742BE7B3921684CULL,
			0x28E7D86F17760648ULL
		}
	};
	printf("Test Case 230\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE096BC4D974143C0ULL,
			0xCC3B585EBBAEE065ULL,
			0xDBE258913B114210ULL,
			0x6D6791C94125E299ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDB91421B482F5551ULL,
			0x3CEE1B22B7C63D22ULL,
			0x4597A7E6A21599F1ULL,
			0x7F54AC97089403B3ULL
		}
	};
	printf("Test Case 231\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x48A8ECD09A81A150ULL,
			0xBE6AEBC41E8106C5ULL,
			0x6439ED1B5A908DC5ULL,
			0x52FD3C6BBE7FB3F1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x37F025EDADE2521CULL,
			0x9FFB55BD0A83B7F1ULL,
			0x1CE4EDFF65D4F9F6ULL,
			0x47E575644AB9929FULL
		}
	};
	printf("Test Case 232\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBC7E26FBF4086368ULL,
			0xFC02AE03FC4287E6ULL,
			0x14DBDB83C36B75BAULL,
			0x5E8CDEF99D742416ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFC225F69DE23C338ULL,
			0x95A33B2A3EBA5052ULL,
			0xAF54DDF8BC357398ULL,
			0x6EE31575397A29ACULL
		}
	};
	printf("Test Case 233\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4104979641D33B60ULL,
			0xE01D6BEA5826CC1FULL,
			0x052E7EC4C80066E8ULL,
			0x4C0D95F4C95CE981ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x65528374793EB2A1ULL,
			0x60BA00059D849C23ULL,
			0x032A301F6E5C5D45ULL,
			0x7C7CC39002837C86ULL
		}
	};
	printf("Test Case 234\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBE27CC64E1F61B50ULL,
			0x4DA9E7863175FA3DULL,
			0xCB0E849F625C6428ULL,
			0x51A54B6FE064EE31ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x855F56E7F390ABF8ULL,
			0x4E59F75F617445F5ULL,
			0xAE7E91BDAB8E80E3ULL,
			0x6A7D0F03DE7B3EA1ULL
		}
	};
	printf("Test Case 235\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x319B98D2217FE448ULL,
			0x8422294D86A15DF4ULL,
			0xA958F25C37FBEC4BULL,
			0x6D40B414B512B402ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B8AF9268932C42BULL,
			0x6A579B7CC43A52FDULL,
			0x93D55D0232DDD1D6ULL,
			0x2856154B232DE51EULL
		}
	};
	printf("Test Case 236\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCFBE3CC8DFE9D0A8ULL,
			0x65F3CAEF7589AA05ULL,
			0xCE6C476C46A3A992ULL,
			0x691B74CD77314D44ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x831C6EE8BF1427F8ULL,
			0x3D229D43D22B2492ULL,
			0xA624D0044B382FC4ULL,
			0x20FC9AAA6A4C18C8ULL
		}
	};
	printf("Test Case 237\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9C844512DCCC51B8ULL,
			0xAE259BEA8011ABF8ULL,
			0x0713AEB77062475EULL,
			0x7A3D334F304CE33AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4B34DCE7FF3AB993ULL,
			0x02CEB6DF74A1C627ULL,
			0x56C6DC57F436F1B0ULL,
			0x0E11EEDBA4A22DD6ULL
		}
	};
	printf("Test Case 238\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x92ED865DC6B15350ULL,
			0x18751B7A0F812CC7ULL,
			0x1ADA913327CA474DULL,
			0x5C9B0484EC437E50ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x949585C3475C80ABULL,
			0x5C6F2C99A90A5EEBULL,
			0x1718B6B905858AB3ULL,
			0x0E2C31704A73ED85ULL
		}
	};
	printf("Test Case 239\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF9E3E1DE01E44408ULL,
			0xA3ACEA4DF62C53B8ULL,
			0xA1D368E27AC27210ULL,
			0x77DAB151F8FBB9E3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x57842F00307B5173ULL,
			0x2AF9605604C5A3CEULL,
			0x2BFA1D0002F688ABULL,
			0x4E9DB3982056EC24ULL
		}
	};
	printf("Test Case 240\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3E78D7D34B9D8500ULL,
			0xB44851EA71D8586AULL,
			0x4DAA152DB00F9D3EULL,
			0x728266D0743FFD7CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x64D70125AA3F9A7BULL,
			0xB3E1364F09828279ULL,
			0x6D7D6BCA2663FA63ULL,
			0x7E37EEF83537E180ULL
		}
	};
	printf("Test Case 241\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x81588FC4672F5258ULL,
			0x8B0D66CFB2A64FC0ULL,
			0xEA06952D7A2B0C02ULL,
			0x6AF410AA2016C276ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x60988E0F6D760392ULL,
			0x6C29ACA90CD3EEE4ULL,
			0x164CBFEAAFE386D8ULL,
			0x09BDE03E83B16F4EULL
		}
	};
	printf("Test Case 242\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x36C2917BD63C6D18ULL,
			0x9B30275B84881F79ULL,
			0xC20A6501C4B12C8FULL,
			0x7B3FD3A177F96867ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB2ED36B49FAD0819ULL,
			0xFD99008835453D85ULL,
			0x3D7B29D9479720DDULL,
			0x3A21BD331B6446F9ULL
		}
	};
	printf("Test Case 243\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x80E4E6F6A194C858ULL,
			0xA8C4FE2F5ECFF88DULL,
			0xFAA519DF7F67476AULL,
			0x6879D04C3D54BE61ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9FAE919EDF62C089ULL,
			0xF74CDAFF5DC69AC0ULL,
			0xFA13863DD3CF6ADCULL,
			0x761A673CFD47539DULL
		}
	};
	printf("Test Case 244\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x37A22BA6C2D33960ULL,
			0xF08F188CA51324C4ULL,
			0x246413DF24D2025CULL,
			0x6B4199680E92135BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEEA8502902C98EB8ULL,
			0x6B33637D8E035896ULL,
			0x2ABEFC4D424C7E76ULL,
			0x52BFA6881782E16EULL
		}
	};
	printf("Test Case 245\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x881E6C27E05BF4B0ULL,
			0x3D48C43B3019DF09ULL,
			0x8E6807028B93EF06ULL,
			0x57F815A1C9620EBCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEEC8FCB31B9760EAULL,
			0xA9592F4C08338135ULL,
			0x03D394B3F186893FULL,
			0x143332A6C588F37AULL
		}
	};
	printf("Test Case 246\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD98248B5CADCAB90ULL,
			0xEC6483C0D7AB566CULL,
			0x00501D64B5CEF802ULL,
			0x6123BA868E04D222ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x401AEEAE47709466ULL,
			0xF68EC34111983C9EULL,
			0xC0137B204EF40D96ULL,
			0x29BDD94F8A69F0C9ULL
		}
	};
	printf("Test Case 247\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x17B0CFD38D7516B0ULL,
			0x0DC91CF1F77A98C0ULL,
			0x95576EBF094AEF42ULL,
			0x744E7E87F2F1EB92ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x228819039C3F7A13ULL,
			0x79C424500B88B67AULL,
			0x240207819F004071ULL,
			0x6281A41155AC62AFULL
		}
	};
	printf("Test Case 248\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x87D4705EABA47090ULL,
			0x42EB12261118BB46ULL,
			0x513F4F5C936421ABULL,
			0x7817D134A71ADCEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x421C3C531D71EA15ULL,
			0xB29DEE9923218DEDULL,
			0x228DEC9F04BB214BULL,
			0x266C349F74702F39ULL
		}
	};
	printf("Test Case 249\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF174EA15A2D8EB68ULL,
			0x6166F0C72848ED7AULL,
			0x60D688D4CC323353ULL,
			0x4D72E7BF6BDEF1DDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3CCF635996828E4BULL,
			0x4A13A52A1697953AULL,
			0xA76EF09DDDC20556ULL,
			0x088818CE192F0D88ULL
		}
	};
	printf("Test Case 250\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x76725C64FDE04760ULL,
			0xEBFAEE393F5F1FC6ULL,
			0xAFA10C1654E58009ULL,
			0x42502DF5D45CFBBDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC596506E8D23825BULL,
			0x4D299CDA84BF4B3DULL,
			0xB35C38721D8A406DULL,
			0x3BC7472C5645A49EULL
		}
	};
	printf("Test Case 251\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3B926018A64831B0ULL,
			0xA916B7F989CFF76CULL,
			0xED99D931CAA5F338ULL,
			0x5D7E427EB21C8732ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDD4508F8160A9E91ULL,
			0x552005A426604CE7ULL,
			0x5E42972DB113412BULL,
			0x5DD4BDCCFB01AB10ULL
		}
	};
	printf("Test Case 252\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFB2326D6F3B7B7D8ULL,
			0x0935F16F50A8A5FCULL,
			0x5A87E237841B896EULL,
			0x5A5C7BEF93E7F2EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8F9FEAA0AD10CEBEULL,
			0x0D9BE36CEA4F1501ULL,
			0x83599D9347B1B71EULL,
			0x167D8CF1A6E63075ULL
		}
	};
	printf("Test Case 253\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0E8728359770EBA0ULL,
			0x95BBD9881A9AB7EAULL,
			0x9C8D3BFB6A61F539ULL,
			0x721E22FBBBF0953EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x71D072DCD57C3D9DULL,
			0x52475C07D1FE76CFULL,
			0x16078B320C4148BFULL,
			0x54AD2AA7DF2B7D84ULL
		}
	};
	printf("Test Case 254\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3CCCEEE9FF2F5BA0ULL,
			0x9ACD121F252FDF50ULL,
			0x113C8B1D2AE19D75ULL,
			0x4920DF598A3D4ED6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8ABE043899910419ULL,
			0x34F1124089C24A30ULL,
			0x736D49C5F87E05D9ULL,
			0x53ECA81570D00912ULL
		}
	};
	printf("Test Case 255\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x157261B186E0F210ULL,
			0x5AFFCDCE7F4EB545ULL,
			0xE8DAEA281D14469AULL,
			0x491410393442638AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8D539EE19CAAC4B7ULL,
			0x894F95DECD158999ULL,
			0x100B3BA4021E605FULL,
			0x2724B686F053A4E3ULL
		}
	};
	printf("Test Case 256\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x95ACD8BB75A640E8ULL,
			0xBCEEDC36F14CDFDFULL,
			0x0E49EDE05406E4DAULL,
			0x4CC79CE9A1472496ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAF34BF88099C6132ULL,
			0xF3816D2F23C934F4ULL,
			0xCFF6DD2D29E52D52ULL,
			0x39D720BDD59F3B94ULL
		}
	};
	printf("Test Case 257\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6556E58552461138ULL,
			0x27587524F4367252ULL,
			0x7009B0300E0CA2ADULL,
			0x4DBA2EA063D7548FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x95742EE7699DA342ULL,
			0xAFA8AC6DF185AE6DULL,
			0x3B6F57A56179124EULL,
			0x3F81B488237185A7ULL
		}
	};
	printf("Test Case 258\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC76B876D17EAC460ULL,
			0x2BC846BA785CEBA8ULL,
			0x3F6298B40F3D711CULL,
			0x732A84B2C9EA41CCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC285B06458641E55ULL,
			0x2733F4DC47B1C610ULL,
			0xC7728B96139BB27AULL,
			0x6A595A0C880B4461ULL
		}
	};
	printf("Test Case 259\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFCFB2275C5739388ULL,
			0x78DD38B5A9EA5E9BULL,
			0xA8928A5EDCFF19B8ULL,
			0x654CA5C7C51EEA3DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC895426F5772B961ULL,
			0x4D291467B021ECAAULL,
			0xBE4F3C6D853E0DDDULL,
			0x7E773DE5610D7ADBULL
		}
	};
	printf("Test Case 260\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0541ED87DACC6D18ULL,
			0xA22695E0FE1B4B44ULL,
			0xDD5975D2517517FCULL,
			0x6234322FE04B081FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4B38E633F48DEEB3ULL,
			0x78C743B44ED4CA98ULL,
			0xAA79E33DACE2EB4BULL,
			0x0DE3486DE4FE6F9EULL
		}
	};
	printf("Test Case 261\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF0121A54B31A6980ULL,
			0x72DBE1EC60950602ULL,
			0xFCF54F823E7D63D7ULL,
			0x54C33476AC2D97F7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5C3BA71493EE4400ULL,
			0x6F240982EE65476EULL,
			0xE139433E7B67F6D1ULL,
			0x52A91491F852EABBULL
		}
	};
	printf("Test Case 262\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x663283D033F024D8ULL,
			0xAC3D4E4F1A565646ULL,
			0x8A682C8D367D2CB6ULL,
			0x7B0ABD1CAA07417FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBA1CD8833F8AAC1EULL,
			0x91D9AA4FCB80EB37ULL,
			0xDB4097911B7B2123ULL,
			0x77FF97F735A9F93BULL
		}
	};
	printf("Test Case 263\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC01C7FFA8EC9D9A0ULL,
			0x90F520BD5840F3AAULL,
			0xB7C700814EA4FDF5ULL,
			0x7CD2F8EEBA5A109AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEEC85DA08263DFEDULL,
			0xDDBC7300FD17807AULL,
			0x2416D319E129B208ULL,
			0x28B9088BF733DFD7ULL
		}
	};
	printf("Test Case 264\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5AC978C0B87F5D08ULL,
			0x65BA85E009AB806DULL,
			0x3D215D91DDACC2BEULL,
			0x562D866FD707C416ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x11CF1E32CC678D90ULL,
			0x532247E59E51FE2BULL,
			0x9A6E2246714DF8CDULL,
			0x5E14E44CB2796E81ULL
		}
	};
	printf("Test Case 265\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC9940242A17C2798ULL,
			0x08D1452D7D30C2F9ULL,
			0xF796B501A2DAC2B8ULL,
			0x498263140E3F9CAAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B1887F4DCA37F0EULL,
			0xFFC34F0F0A684C71ULL,
			0x1EC1290BDF3D5CFFULL,
			0x45A40E5ABEBC4641ULL
		}
	};
	printf("Test Case 266\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC08CB71AC577B6B0ULL,
			0x3A299EF00AFA34DDULL,
			0xF2392A726C8AF5D5ULL,
			0x7A3FD805C4E40F9AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA7FB8650A3D1614AULL,
			0x596F558F7FA175B1ULL,
			0x16C42F8A30013325ULL,
			0x24B148AADD062D0DULL
		}
	};
	printf("Test Case 267\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x727A304D38EBC608ULL,
			0xECBBDE68424ABD18ULL,
			0x51C18ABA24753FACULL,
			0x609B15B19FB83B23ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0E2EEAC9B45F95BDULL,
			0xCC1E999AEE8CDD39ULL,
			0xE1A6BBB470747064ULL,
			0x4971B21C6390380FULL
		}
	};
	printf("Test Case 268\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB2DDDFA43A70C5D8ULL,
			0x8B9CF6BF92D3B196ULL,
			0xCBF523BA4638F0D7ULL,
			0x613F20DD704F7369ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCEBCAA95102943C7ULL,
			0x7CC65B91CA9719FBULL,
			0x61D0C12D32FC638DULL,
			0x6EE7E07A0462BB10ULL
		}
	};
	printf("Test Case 269\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBEADAD16AFBCCDB0ULL,
			0xE32665C2E0226DFDULL,
			0x852379288D7F3735ULL,
			0x71DF35E36301D225ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4807C21366D91918ULL,
			0x9199776FC1FDD994ULL,
			0x91E05D12091BC779ULL,
			0x6467939B8E7889A4ULL
		}
	};
	printf("Test Case 270\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x609F3284B5F9AB40ULL,
			0x0B07709DB0B68604ULL,
			0xA7891FC6C05B9972ULL,
			0x551EE9865918438EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1B2EA72911D0FBC4ULL,
			0xEF9E4DE8C03BE3CAULL,
			0x8F1CAF86349EA821ULL,
			0x7080E80713C28237ULL
		}
	};
	printf("Test Case 271\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x13B541AD45236000ULL,
			0x36C3F1593B660458ULL,
			0x03C1AED41245C640ULL,
			0x49390A2E87AA0F92ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x53E62E9C70448FCAULL,
			0xA045A5A181DEB096ULL,
			0xE5F9DB47C57D3746ULL,
			0x1C944B1A8AD4CD61ULL
		}
	};
	printf("Test Case 272\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAA41FFB98E88CDA8ULL,
			0xD3D06102D9ED2BB1ULL,
			0x28E805145A92928FULL,
			0x48EB07C86D431747ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x531D68396225C3ABULL,
			0xB3EEE987B4D61007ULL,
			0x707E2EB4FC360C63ULL,
			0x2058F4FE92FDE840ULL
		}
	};
	printf("Test Case 273\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7E81B450CC3C4320ULL,
			0x32231D5F93438DB8ULL,
			0xCD6636CF522DF3CCULL,
			0x4D7CF29F8A6D395CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5DBB535DF8C44DCAULL,
			0xF68E42262A6C5BF6ULL,
			0x88520240C2CC5E16ULL,
			0x75FBDD29687F406FULL
		}
	};
	printf("Test Case 274\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC055070F8AF72C48ULL,
			0x9F7F3A1CB08D2BE6ULL,
			0xEBD8028460AED310ULL,
			0x6BACAEDDBA76B0FAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9EAF735BEB6D7D01ULL,
			0xB4BBB369F933A919ULL,
			0xD9B65A9A4A9D0718ULL,
			0x1972B68AD388DAB9ULL
		}
	};
	printf("Test Case 275\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA02CD791279FF990ULL,
			0xF6A1D620CD6D42ECULL,
			0x569C3AA1570832C4ULL,
			0x51B8551C9EB78894ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x939F234E9606E386ULL,
			0x7204D584955A5108ULL,
			0x53F137EF1345E465ULL,
			0x38EECF8E5DC0FF9BULL
		}
	};
	printf("Test Case 276\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x69D4F92E8730CE08ULL,
			0x3238830AD87D4F8CULL,
			0x05E26BC009418CDAULL,
			0x690ACBA877EC7A42ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2ED765522DA842D5ULL,
			0x1BEA3C5DCCFFED0BULL,
			0xD337D5AC1656601FULL,
			0x2F0A153C681C53A0ULL
		}
	};
	printf("Test Case 277\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6057BBC6505AB028ULL,
			0x82F7D4475CC071F4ULL,
			0x78D66159762198A8ULL,
			0x630D3D5CC30D716CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0920ACEE5D2671EDULL,
			0x5F8302027885FEABULL,
			0xDA3379194B3C05D3ULL,
			0x3580CBA703606AB3ULL
		}
	};
	printf("Test Case 278\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEFBE99BE0D891B00ULL,
			0x771C1C2F341A57AAULL,
			0xBC31BC0CA127F7FEULL,
			0x78905371BAB9C8B0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA0329B913B946BD3ULL,
			0x73B70AB74603D8E7ULL,
			0x37B4C8334E9B4B1FULL,
			0x4A6A6941D76C462DULL
		}
	};
	printf("Test Case 279\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9D19934466B18C08ULL,
			0x85BD9BEF7CA1FD86ULL,
			0x5233F784729BD205ULL,
			0x7B295A8177F07890ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1A8C90F88C7729BBULL,
			0xE428D6A508916C81ULL,
			0x20FE22541EEA9DC4ULL,
			0x6C03199DD5EE1A50ULL
		}
	};
	printf("Test Case 280\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA9CD48C18F5FF160ULL,
			0x6E6510363C2667CEULL,
			0xCA31B7848018324BULL,
			0x6E006DF5B8AA7CE3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x08AC28D81994AA59ULL,
			0xF67D6D871E5891C6ULL,
			0x0458FCF146BF3A6FULL,
			0x0DA19CF7C1EEBBADULL
		}
	};
	printf("Test Case 281\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9FED0281C6483F90ULL,
			0x869568FCA51D15FDULL,
			0xE10DA943319E9E59ULL,
			0x438FEF6ECF99018BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x71D00E1F6D8502D3ULL,
			0x4101875998146E5CULL,
			0x76556DF5928CE113ULL,
			0x39C96A5E97119483ULL
		}
	};
	printf("Test Case 282\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA9B11CCDF3F56358ULL,
			0x7C23877068B6EEE2ULL,
			0x605A60D8C9DD2206ULL,
			0x6A1C11E95A18B117ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9F1F5A763F525934ULL,
			0xA17AC09BA4EAC140ULL,
			0xA1CC70DE15D3B6E1ULL,
			0x5EA788CA69288F26ULL
		}
	};
	printf("Test Case 283\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x55E760376A09A790ULL,
			0xAF161505465B278DULL,
			0xFACAFFFA8DEEBA79ULL,
			0x5D2AF7B6E7896B61ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4ADB1D255BAB6597ULL,
			0x6D9A8B4CD63BBCB2ULL,
			0xDFC27FF1A29E3585ULL,
			0x623E968A3BB66C51ULL
		}
	};
	printf("Test Case 284\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9F745E86C59862D0ULL,
			0x23E85F53498F3026ULL,
			0x816804B92B8112A9ULL,
			0x79AE1BA0EF0947F4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x37EC45F7E845C8DCULL,
			0xCB89770FFA653BF2ULL,
			0x09B67CB1BAC3D460ULL,
			0x534C19324AC43AECULL
		}
	};
	printf("Test Case 285\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF90D0A53E45DC800ULL,
			0xF3A86F299F77E607ULL,
			0xDE9217F31FE681CBULL,
			0x4BFDEAE7B897AE43ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8C893E68AA45B55BULL,
			0xD67A4C7C39072DC0ULL,
			0x405A1EC84772503FULL,
			0x18EBA7A6B24243ACULL
		}
	};
	printf("Test Case 286\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x27E4DAA281B301F0ULL,
			0x2632B0E5B07EFEB3ULL,
			0xC7F18A97A4B50DDCULL,
			0x485705970E200A10ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8840F1C568717CE5ULL,
			0x851A9A6CAA5576E9ULL,
			0xBAE6E667085131C0ULL,
			0x5399C6350A087C0FULL
		}
	};
	printf("Test Case 287\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x230A26E2EDE9A588ULL,
			0xC5263A6EEC886E7AULL,
			0x3DC554545C95C002ULL,
			0x435FA2353072DCA8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD5A5A5A04BCB0D7FULL,
			0x0E83E9F4A86B986EULL,
			0x491834E99D66571FULL,
			0x78DA290497210C1AULL
		}
	};
	printf("Test Case 288\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFF8FB3ADEC3A2358ULL,
			0xB62BFC09E8CC1F9FULL,
			0xC8E76B44B948395DULL,
			0x6DAC4A282D6947A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8BFA2B205EC226C5ULL,
			0x721516E4B9640160ULL,
			0x3C2F609ECAEA07B3ULL,
			0x38AEC788D2B3407DULL
		}
	};
	printf("Test Case 289\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9C919B40BF1F61D8ULL,
			0x4120E4213E91E484ULL,
			0x1DD76AC110B5567CULL,
			0x4E678E76566AB7F7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD301209BC27F2D32ULL,
			0x32865F02000B3272ULL,
			0x8BD8DF442C9DE8C7ULL,
			0x178BB4092411FDB0ULL
		}
	};
	printf("Test Case 290\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE4032B68E7CAA920ULL,
			0x9F252ABA9B55703DULL,
			0x5BC890FA875F7148ULL,
			0x6244AA6A6E835082ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCE643BC0C609EE5CULL,
			0x86B393A528E7C71CULL,
			0x4676D0CE3D10CEE6ULL,
			0x1B1553134A6C0058ULL
		}
	};
	printf("Test Case 291\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x835E3F1B0F7DBD30ULL,
			0xC31DC53E597696C3ULL,
			0x647937842D7C9EF4ULL,
			0x749BFD947DBF9218ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFFD91E30E169957EULL,
			0xBEF0ED49342B5DCDULL,
			0x85814282E23DC705ULL,
			0x5D612F7AC8B6B47DULL
		}
	};
	printf("Test Case 292\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD6F93ED27F6514A8ULL,
			0x8311C48A24C05086ULL,
			0xC70623806A3BE91AULL,
			0x7C50A9A55482038EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x701CC3210443A7D6ULL,
			0x2292EC9DA0E55686ULL,
			0x55FACB37883B194FULL,
			0x685B13A85C2D1C99ULL
		}
	};
	printf("Test Case 293\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x294D6C08A1192580ULL,
			0x5F01262B8F246EC3ULL,
			0x9758D1200A480E07ULL,
			0x56D27FE300ECC116ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBB398A0727FEF7D7ULL,
			0xDAB03FF2E76A14D8ULL,
			0xD14E8D1013B6A6E3ULL,
			0x45398963AA4ED41CULL
		}
	};
	printf("Test Case 294\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x99CBD8E87B6520B8ULL,
			0xC110362AF3154590ULL,
			0x90F00E2559AA2DB9ULL,
			0x627289BF639C2534ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD653FEE667254445ULL,
			0xA3F36F3EB232C051ULL,
			0x4BFD9FD7E6F6E089ULL,
			0x0E65C9E9A359756EULL
		}
	};
	printf("Test Case 295\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x33C0AF1FC43F8CF8ULL,
			0x76DAD820E5AE0A48ULL,
			0x7411EEA0E9C56361ULL,
			0x72138A4E97A5BE83ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x15D87A7CD14A0300ULL,
			0xE9A491CC8217C8B6ULL,
			0x74D633BCF9112FD1ULL,
			0x193DD40B68AE8827ULL
		}
	};
	printf("Test Case 296\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x55731279070CF638ULL,
			0x665756E3877D8A0EULL,
			0x9B3A4FFDA381512EULL,
			0x79058C2B51089F7DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3CE8FAD4846B8A3FULL,
			0xEC56C09A53AD5A85ULL,
			0xC3A03B20F3B53F92ULL,
			0x53D4F9827DD7D943ULL
		}
	};
	printf("Test Case 297\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD347AEDD307AD528ULL,
			0x95E6F3C9AF76878AULL,
			0x99C36F0384F44736ULL,
			0x54D7845DC01FCA19ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD5B052BF2EA70F1BULL,
			0xE1D4144DE8B4A00FULL,
			0xB5DF0366E7D9E23FULL,
			0x6C69552D7E05EF6AULL
		}
	};
	printf("Test Case 298\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4F82A9AA14265928ULL,
			0x24AEE60226395C18ULL,
			0xD90AAE1EEFD049F6ULL,
			0x4AB50F8CB1755466ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2B436AB572FFA80AULL,
			0xFE4EAB5A7CE1D17CULL,
			0xB23BAC1FB9065A06ULL,
			0x1C119768C1676DCDULL
		}
	};
	printf("Test Case 299\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4C643A5179CE92F0ULL,
			0x3499CB851C2005A8ULL,
			0x624760E386DE2045ULL,
			0x593DCCF914047401ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA69E39B2BC71CF62ULL,
			0xFF476E418D4B67DFULL,
			0x1152F342143C3AE0ULL,
			0x2A18A502DD8877A0ULL
		}
	};
	printf("Test Case 300\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7040AC6AA81BBF50ULL,
			0xD9F3B6B1B4577B84ULL,
			0x5944BEEB9C5E1E87ULL,
			0x7EAC9EFA33ADF3B9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9C1216C616693E45ULL,
			0x724ECC5754127995ULL,
			0x50F2995E2E929A25ULL,
			0x6E580E76CA1610CAULL
		}
	};
	printf("Test Case 301\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5F9D15E4F6614A10ULL,
			0xF69E62E1EB65BD78ULL,
			0x40DA66D566B0523BULL,
			0x77B4D83D0183D23DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB5EF6F2D7ABA625CULL,
			0x7A2E66DE3347327BULL,
			0xF1AC861F21E19FAAULL,
			0x3D63A84983B8C841ULL
		}
	};
	printf("Test Case 302\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA03287A09CBDB1B0ULL,
			0x1565B688D7FE127CULL,
			0xD862FC8CEC3D1318ULL,
			0x4E8E6BB523F7834FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4A49A47EE4AAC0B8ULL,
			0x9EF104B1D373ADBBULL,
			0x6D5F22815B668183ULL,
			0x1B7DEB8FB09FA735ULL
		}
	};
	printf("Test Case 303\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAF14366AE4130BA8ULL,
			0xA7017CEF925C8837ULL,
			0x9E9AFD460112A222ULL,
			0x7BA7D3B6D8E01CE4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5A04CB6CD8D53843ULL,
			0xB3855D600A7C73E3ULL,
			0xF117461C6CDA68BFULL,
			0x579D582DA29A15D7ULL
		}
	};
	printf("Test Case 304\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE946C0B628529B90ULL,
			0xC7AAF9F7E01BB423ULL,
			0x26BF070FCFF0EF96ULL,
			0x6475C2A7E07702A2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x64C215AE9126F6C8ULL,
			0x5B9049D6F9BCC5A1ULL,
			0x0A03C03F72891B27ULL,
			0x3BAA06EEF7633507ULL
		}
	};
	printf("Test Case 305\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD7A21A4D717F06F8ULL,
			0xFADD0B9720D1CE60ULL,
			0xF06EDCAF0336C8F1ULL,
			0x47DACBC83EA48FA0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE8919C04CBB07266ULL,
			0x9E8A087DEAEE2B4FULL,
			0x9AF3FA619CC1A919ULL,
			0x14A775A1CA91789AULL
		}
	};
	printf("Test Case 306\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x035B487F2BBD3400ULL,
			0xD548FEEFFD75F681ULL,
			0x1F031C189454034EULL,
			0x7A3E2CF3C6A276F7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x711B8E21A73E56F6ULL,
			0x9B1755B136916B7CULL,
			0x4CB9D4D1ADC75073ULL,
			0x756D77BB7437B7ADULL
		}
	};
	printf("Test Case 307\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCA6434AA393F8470ULL,
			0xABD0859AE9564708ULL,
			0x7597A3B6C91B3BC3ULL,
			0x73366424AF2B08F8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB1582FED9DBEC572ULL,
			0xE0902859400A039FULL,
			0x15592EC612AACA08ULL,
			0x7E24A5B377414B97ULL
		}
	};
	printf("Test Case 308\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6DEC38D028D0B308ULL,
			0x5DF856A656357527ULL,
			0xA727592FB8299685ULL,
			0x711D903120DF3799ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7A5A3A3899A3C989ULL,
			0xA5810711F3770477ULL,
			0x1C8465B3D0D2C8B3ULL,
			0x5EC197AA492969FFULL
		}
	};
	printf("Test Case 309\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x636466AB6E23DD78ULL,
			0x06323A79025FF404ULL,
			0xE5C1D27D4D433C29ULL,
			0x5599912E3F432AAAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x08AD63B107A522F4ULL,
			0x5592724C876DDCA5ULL,
			0x24335563178328F8ULL,
			0x46D3B5FAD1CAFA90ULL
		}
	};
	printf("Test Case 310\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x48F094E36D1622F8ULL,
			0xC047404AE5E11BFDULL,
			0x5A54933F764BC929ULL,
			0x68751E6C7E8C7ABFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x13F2C54209F1AAC3ULL,
			0xEDA97A9FD432A40CULL,
			0xED12092D67D5451AULL,
			0x3E5A0DE2A34C55B3ULL
		}
	};
	printf("Test Case 311\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD86B2C497F957100ULL,
			0x39B67441702BC7D2ULL,
			0x2625F2B04414CF05ULL,
			0x4784C035DE5DC7ECULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3219F0BB2E1A2440ULL,
			0x5458901FEC201686ULL,
			0x75840E4ED251FD49ULL,
			0x720F49E49301409EULL
		}
	};
	printf("Test Case 312\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x849C45DD43407928ULL,
			0x29C96A584260D65BULL,
			0x471285DCF85E0962ULL,
			0x4D061D0BA5FE4D9CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBC1706771BB98A35ULL,
			0x0F40C858B3642F56ULL,
			0x166035027942B660ULL,
			0x64E3A6270FCF5533ULL
		}
	};
	printf("Test Case 313\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC6D933E7B3A73A18ULL,
			0xBBA2B72CB22C3C22ULL,
			0x508A1D92EDD363E1ULL,
			0x6AF1CEEED22B69EBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3AE653C2504FFC2BULL,
			0xCE8F1E175E7AE650ULL,
			0x5ED50EBAE93C0171ULL,
			0x491E69F7AE4AA90DULL
		}
	};
	printf("Test Case 314\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5EB5E0F1D9967860ULL,
			0x129B20ED37479D89ULL,
			0xB651A2356B383B67ULL,
			0x50BA021888D2E191ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x697606D56472EA15ULL,
			0x68322B611C06FC5DULL,
			0x8F8B0CD8FDCDA85AULL,
			0x2279B97E05FE13A9ULL
		}
	};
	printf("Test Case 315\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF23F8DE96E606860ULL,
			0xFA03DC57A4AA3B10ULL,
			0xA31BB7038175A504ULL,
			0x407FAE0FCA02DF47ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD033D7B1E990C95ULL,
			0x12B83D98EB4AAE3BULL,
			0x409F1066C13E0E7BULL,
			0x44080D7121DBF450ULL
		}
	};
	printf("Test Case 316\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD8E918DD71EAAFA8ULL,
			0xE92808810DA1A3B0ULL,
			0x08EA007F28FC59BAULL,
			0x74FE14C9D001D19BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9253C7113B11CFE8ULL,
			0x570E18CFCEB8C870ULL,
			0x28D61B3C6A8A7C13ULL,
			0x5D2FC26650443DFFULL
		}
	};
	printf("Test Case 317\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0831552BBB4A24B0ULL,
			0xE74BBCD207ACED32ULL,
			0x55FEBDB89E9D1E08ULL,
			0x74FC09D71506A6BBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6ADC55C9FC696DE2ULL,
			0x73D8D8F80E97F1DFULL,
			0x2B00F509B3C1EDEEULL,
			0x56B6FE2CF02853AEULL
		}
	};
	printf("Test Case 318\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD50C6569B45FC888ULL,
			0x29EFFA3F3AF24466ULL,
			0x88316D54B690D866ULL,
			0x502784DD6D6DEA59ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC464841C4AC06E1BULL,
			0x1DEFC55D7D5F0F2EULL,
			0x49321C2AE2052CD7ULL,
			0x77A91C4EBC3427D2ULL
		}
	};
	printf("Test Case 319\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFFCFE86C4CAD7320ULL,
			0x9947E4B231DB2D8BULL,
			0xD59BEC01CDCE1269ULL,
			0x4404AC6316A715D2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC0D8EF090A22FEF0ULL,
			0xA8596CFA68930DE2ULL,
			0xFE955F99F5AE87A5ULL,
			0x0FF53C05E6F95D81ULL
		}
	};
	printf("Test Case 320\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB9AD88F1B5DA5D48ULL,
			0x12C01C9F0F6EB662ULL,
			0x9A9754D6570C74AEULL,
			0x66CCA73931EA924AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDBABD13784CEA862ULL,
			0x5F7E97B1D0CEFD73ULL,
			0xF9047206684A7A08ULL,
			0x0C8B6F3BA5F5D7C9ULL
		}
	};
	printf("Test Case 321\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5012B8B561B2ADC0ULL,
			0xCC549E4A16D029C3ULL,
			0xD034B9D4B55A8536ULL,
			0x40C7DC8D2E4BDBD0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x92B00AEDD2CA4AA8ULL,
			0xD09C529D8A6A628DULL,
			0x8D91B9E3E7C5C76FULL,
			0x1FAA777C9DF64997ULL
		}
	};
	printf("Test Case 322\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x63D73F18C948C400ULL,
			0xD78E5633F27CDD5FULL,
			0x6BB97604FF1D28F7ULL,
			0x46DA11FD3BACBD59ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0668FD8CB00E4D16ULL,
			0xAFE1C1CCED864927ULL,
			0x189967F57B9582A3ULL,
			0x0FFFBC54FA3182CDULL
		}
	};
	printf("Test Case 323\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x34666DC43EFADFF8ULL,
			0x2E34280EAA6B6304ULL,
			0xFE3BFE9639C09BD3ULL,
			0x7E8073224873F265ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x31732EEC2FA65932ULL,
			0xA8DFA44A4A775D48ULL,
			0x1110A606101E2960ULL,
			0x0CA1CDC718AA9441ULL
		}
	};
	printf("Test Case 324\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEC06A56123F00438ULL,
			0x704FFD17C127CEAFULL,
			0x292F918BAE557E08ULL,
			0x7F8451D2B98854BAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEBA64A6DF858C055ULL,
			0xD33F3C7700B5375EULL,
			0xB669ADF5D0D20681ULL,
			0x5F12532AB7E83C82ULL
		}
	};
	printf("Test Case 325\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE9C77308C48510C8ULL,
			0x5969FDE51A8B7BC9ULL,
			0xC9E0E971DC91A514ULL,
			0x4E60646EB064A663ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD969F64B051885C7ULL,
			0xF5F55EED8A7416E0ULL,
			0x6B2CF037F6D39380ULL,
			0x378105646E525B25ULL
		}
	};
	printf("Test Case 326\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9F2E171C94C6D918ULL,
			0xDE47E0C6F4171823ULL,
			0x70C38EBA95DB5675ULL,
			0x793FBCA820037CF1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x744AFC9F6D3924CCULL,
			0x716010B3FD8956C7ULL,
			0x173756F832725ECBULL,
			0x27D0D0C6BF7B43BEULL
		}
	};
	printf("Test Case 327\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBEFEA979911F1270ULL,
			0xEA955687DF5EAE70ULL,
			0x44352EB84F18BFF7ULL,
			0x743935F2BC675E42ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD3F073E807102943ULL,
			0x7F211836B4D041EAULL,
			0xF0CEF4B9A71B121FULL,
			0x6C9F5E3569634FC5ULL
		}
	};
	printf("Test Case 328\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x183FDB4724DA2DB8ULL,
			0x8FD2E5760E8E47FFULL,
			0xB1A4E0642C7A8052ULL,
			0x58782B9E1D562C21ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB9B9EAE5594640CDULL,
			0x1D14157D8ECFDA0CULL,
			0x1F17B7A7D7B17727ULL,
			0x245876CD87830398ULL
		}
	};
	printf("Test Case 329\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD1A74474042AA3C8ULL,
			0x3027DF0FD9B884E1ULL,
			0x72F356CE43A30349ULL,
			0x7FD4DCB895A920FCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC3DD193826F9B5F9ULL,
			0x14DFFB672F7060F4ULL,
			0x2008B357DD9D8688ULL,
			0x5C20263FC501F1E2ULL
		}
	};
	printf("Test Case 330\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x251D233847133BE0ULL,
			0xE48DB6C20E566754ULL,
			0x5FE9FFB07A2BBBA4ULL,
			0x513D936F755DDC3AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF4E6254702578404ULL,
			0x27C7AB404830FADFULL,
			0xADCAA88F8B8FF7ABULL,
			0x67346FEDC97C2CF2ULL
		}
	};
	printf("Test Case 331\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8F13A1D0259E3338ULL,
			0xEA31B7B7C7909E01ULL,
			0xD66161107A64B95AULL,
			0x549BC97F25168B1DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2BF490896F4A5EAULL,
			0xA7F6B054A7B10B10ULL,
			0xFCE14D39E3FB2587ULL,
			0x1FA2822712560DAAULL
		}
	};
	printf("Test Case 332\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x660429D9F4B8E3A0ULL,
			0x68B4C444FCF05135ULL,
			0xB40B234BF321004FULL,
			0x7DC9E34F5814CCD0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x61A31164EA545A54ULL,
			0x00C555F509BC2D0BULL,
			0x538AAABDD50FF76AULL,
			0x6476EBCB681E9255ULL
		}
	};
	printf("Test Case 333\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xED90A4590528F190ULL,
			0x91884BEEDF33A8C7ULL,
			0x9A8126701AA591CAULL,
			0x5F4EA02D785A2F08ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1F42C7303D05B79FULL,
			0x1E3A5F55560683D3ULL,
			0xA27205D236E78D96ULL,
			0x11E85C576C43C188ULL
		}
	};
	printf("Test Case 334\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBC0BBFCD1CBEED70ULL,
			0xA56A3B9AB104DEB9ULL,
			0x213D56300709A2D2ULL,
			0x614881D42A2AB792ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD2EC10BC9C706F9ULL,
			0x6BD8B36066C8A450ULL,
			0x258B652219F6FDB2ULL,
			0x071B98B8C609991DULL
		}
	};
	printf("Test Case 335\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x477E04EF87B9A510ULL,
			0x525087B98663C454ULL,
			0x556BD2BA83992905ULL,
			0x736B00917DF6DF74ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9011AB30EB986753ULL,
			0x97DC7A97ACC0E9A8ULL,
			0xBB1F6CDE26F82A15ULL,
			0x69036F3AC33B8B62ULL
		}
	};
	printf("Test Case 336\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x55C7D415A0709518ULL,
			0xAC323F99ACC045FDULL,
			0x4A252678F563D90CULL,
			0x62C2B1DDFC54E3B8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x30DACA8FF1CC090AULL,
			0xEAC80E826923FC50ULL,
			0xA9BF129DA5972C27ULL,
			0x12C4767332AFB785ULL
		}
	};
	printf("Test Case 337\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9C05EFD61B175D08ULL,
			0x8EBF73D9C2030F37ULL,
			0x63B1080BB6C91F7DULL,
			0x531E5F28E21CA571ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9225F62C4F91B2A0ULL,
			0x1DFD7BDBDCEF141AULL,
			0x421C3162E27D6D2AULL,
			0x68FD81A2D69880D5ULL
		}
	};
	printf("Test Case 338\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7E31655EF43E35A8ULL,
			0xD8131366A5388BF2ULL,
			0xC855A9D6F47D3B82ULL,
			0x5556834E6B2F5741ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEC14ADDA219F4458ULL,
			0x46836719E4A5E7D8ULL,
			0x751B88DD9991321BULL,
			0x2F9C1AABDF15C7BFULL
		}
	};
	printf("Test Case 339\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4A95D16A20D18AB0ULL,
			0x27B9C12F37EE93A7ULL,
			0x7322246E86FB5B3BULL,
			0x78280890FF8959A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x665967957FA7BAADULL,
			0x764ED5291B4AA821ULL,
			0xA921C443563EC478ULL,
			0x164CC310B06EF41BULL
		}
	};
	printf("Test Case 340\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7415049E67046F98ULL,
			0xA06EB931268A0AD6ULL,
			0xF28C321FAE68B8E2ULL,
			0x7444D3ED130E85CFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1CAFEA5983A6EF3FULL,
			0x069FB585AE00A525ULL,
			0x38EED2180F75AD63ULL,
			0x09A9A26E12A66A66ULL
		}
	};
	printf("Test Case 341\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x709A6698F6BC0640ULL,
			0xF95D9FC0C44C8D19ULL,
			0xB78A234D29B4C284ULL,
			0x64A678FE9807A0A8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x077A245CBC6E1CC1ULL,
			0x5F0B6A22025E4782ULL,
			0x57C0D0452B00B844ULL,
			0x39C3A6018E807237ULL
		}
	};
	printf("Test Case 342\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6E90734F7EB8BDA0ULL,
			0x945D44B908FF99AAULL,
			0xBD19123549115834ULL,
			0x6B2AB8C8DA0B7F72ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2FF185A1C0AF5AFBULL,
			0x4D66E1697A6E82CDULL,
			0x821A9EC6B901B10AULL,
			0x7BF39A075A37D857ULL
		}
	};
	printf("Test Case 343\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2BC23F86E55D5268ULL,
			0xF5F63A0137D6FC0FULL,
			0xC50685A95767D9CDULL,
			0x4D5F2CF8C257AFF8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD88479F8D4CA7AC9ULL,
			0x41FADB280ABB8A1BULL,
			0x030FE6800EBD7C54ULL,
			0x28655FC51A76F423ULL
		}
	};
	printf("Test Case 344\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x59A7D85FDBFE53A8ULL,
			0x7EE7139D54074FACULL,
			0xA3B99FA7865F6C47ULL,
			0x49F16D6BE0680C5DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x92EBDEE3AD3B6265ULL,
			0x5D2EC4D486EF6785ULL,
			0x40FE99A5372D5F8AULL,
			0x14EEB63C9F84C137ULL
		}
	};
	printf("Test Case 345\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE5693FCDF0393CE0ULL,
			0x98CB6E04F45297C1ULL,
			0x2EC42D07101C798CULL,
			0x6A9627A89476A65FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x11C88046C801E56DULL,
			0x96E5FCB267E09A97ULL,
			0x8853594BCA394747ULL,
			0x6B72A76A570E9E35ULL
		}
	};
	printf("Test Case 346\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5618E124A3F41D70ULL,
			0xD8F80200AF0E6107ULL,
			0x6103B9A78BA78BA0ULL,
			0x4BBC448BA18E68EEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x870A512E124057E9ULL,
			0x5A74E9A2F09C844EULL,
			0xEC63160D860C2849ULL,
			0x062B9CD8EDE7665AULL
		}
	};
	printf("Test Case 347\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF7C1BB48C162B318ULL,
			0xAE4D0C679276FA0CULL,
			0xB1DF24F1DE5B8170ULL,
			0x7A8824EF3780EB80ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA858814386AB4DD0ULL,
			0xEBEDECECE2B6F458ULL,
			0x23C7D3361BE04774ULL,
			0x220209019D4BA990ULL
		}
	};
	printf("Test Case 348\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC1465D7E87A9B050ULL,
			0xA454D498511A250AULL,
			0x3455370160682C92ULL,
			0x420DA94A824A83D4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B01401BF6BC783AULL,
			0x741B337BC01A3C7AULL,
			0x4E2CE7119FE171F2ULL,
			0x771A1E689F81CC66ULL
		}
	};
	printf("Test Case 349\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x28F3910CAE55AB40ULL,
			0x4D13868A2D3F63F1ULL,
			0x6D1CE9458ED95115ULL,
			0x6874D5B87B5DFAF1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2BCE1DB64CE50FD2ULL,
			0x50E693270E44B3B2ULL,
			0x39E43A86B5194979ULL,
			0x48E117C075D39DD7ULL
		}
	};
	printf("Test Case 350\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1150FF3AA0342700ULL,
			0xDD667E94D74ABE15ULL,
			0xE99DAD2507E86800ULL,
			0x475A3771BD0FB2EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA1F8398C0F2D0A7DULL,
			0x1BC0FC45A7C5C82EULL,
			0x70DFB3C191993215ULL,
			0x36F768D3D827405FULL
		}
	};
	printf("Test Case 351\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x44A72E2FA1E7ED68ULL,
			0x5A1291EE2326F5A9ULL,
			0xC73EA472F5283ADCULL,
			0x7414129C118A3F01ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDEB4A2A9167F1217ULL,
			0xDD5FEFC2F50FC955ULL,
			0x3CEB20F9CC94220EULL,
			0x257F985F49A42607ULL
		}
	};
	printf("Test Case 352\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6F1C291C98CAED68ULL,
			0xA4412C8A59DD94D4ULL,
			0x3E7852C24CA48DF0ULL,
			0x6C2FBBACE6F49722ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF494F72172281322ULL,
			0xBFE2C9319C594D44ULL,
			0x41C5BAE239C86B43ULL,
			0x091E2D3206D4AD39ULL
		}
	};
	printf("Test Case 353\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9CD47DBF9277A410ULL,
			0x054872BD28D6F1C2ULL,
			0xF86EF8ACD25DFEA4ULL,
			0x7A0A9A5069E985FCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD78AC32D77738D8ULL,
			0x36A7DAB92B56B553ULL,
			0x26EA69E7231B3E4EULL,
			0x31E53138581EDDB7ULL
		}
	};
	printf("Test Case 354\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE6244BFADF66E9B8ULL,
			0xAAABE409E46F682FULL,
			0x4B429D23BFE6D33BULL,
			0x5884DFF4B7952F8EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5E99A95E251D9A3CULL,
			0x2B6ED6A2EF494ACDULL,
			0xB30037EEE436A6B6ULL,
			0x66079D7271615C29ULL
		}
	};
	printf("Test Case 355\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5A42600359BBD480ULL,
			0x8C2F9FAA6A804EBAULL,
			0xDEA14718670EF9B3ULL,
			0x7849D35A0976A170ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x40FD083782BDC22FULL,
			0x4C7C1370A8797B16ULL,
			0x5CDDEDD1B067F5B0ULL,
			0x6A71897C27394956ULL
		}
	};
	printf("Test Case 356\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA4C15C3D8CC1ACA0ULL,
			0x680149DC0D109605ULL,
			0x8EA7917A600F4CCBULL,
			0x55A4F8BE8095A54DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDD139F420210E653ULL,
			0x0C3911C8073501F9ULL,
			0x0A92D6115EA7B6B7ULL,
			0x61ED48E606314D53ULL
		}
	};
	printf("Test Case 357\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x52D8325C73480A58ULL,
			0x022A989646B4D16DULL,
			0xFFC63381C106F1D8ULL,
			0x55C0D3088A64BE33ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3ABEBB792709E6F1ULL,
			0xC114151655C3453EULL,
			0x6350BDDC56BD9431ULL,
			0x51FE61E07A7A8A69ULL
		}
	};
	printf("Test Case 358\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x75D6E8097D71C8F0ULL,
			0x7099DB2CAB8D05B9ULL,
			0x9FBB7A0B252DA1B0ULL,
			0x748B4B07F31F7015ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFB52564EA27C7726ULL,
			0x7D5EB9E82E55FB26ULL,
			0x563AF1682D6F4EFBULL,
			0x7C5AB048FC516A2BULL
		}
	};
	printf("Test Case 359\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFAAD4D1B98C4D508ULL,
			0x39B470AC6D796C92ULL,
			0x19D2DCAEDABD3C3BULL,
			0x496B878110FAF2CAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBC50DF0811CBFBF0ULL,
			0x2646202F82544C53ULL,
			0xD245E8AA2C7C8CD8ULL,
			0x63F94D0713D1D9E6ULL
		}
	};
	printf("Test Case 360\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9394CD1A1E91C038ULL,
			0x894A48A7DABBCF82ULL,
			0xEDF842FFFC5DD7E1ULL,
			0x6D1BBD09C666768EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5705805A62A001ABULL,
			0x5AF95A3AF0B07F6FULL,
			0xC5540D53CB7BF526ULL,
			0x0EDF8105E3D7DC9BULL
		}
	};
	printf("Test Case 361\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA4ED4C23C6BE0188ULL,
			0xB735D1133CF0FC61ULL,
			0x2C873DAB41DA6AA6ULL,
			0x5C5CD4EE6C0FF4B8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6B4A12EE1412980EULL,
			0xD95F99F3ABE12B9FULL,
			0x9BA328651E03B8BEULL,
			0x57AB20C03D1EC6F7ULL
		}
	};
	printf("Test Case 362\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE59B7D53CAE2AF48ULL,
			0xC36C66E3031531E6ULL,
			0xA548BD78C6407EA7ULL,
			0x5E4A19C9AF5D7B32ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x87884FA7DB3BA075ULL,
			0xAF59927656DC33BBULL,
			0x10ACDFA574BF391AULL,
			0x25E139CB0509D371ULL
		}
	};
	printf("Test Case 363\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1B5D2FA296B7E5D8ULL,
			0xA33936E774E4DD9EULL,
			0x91C1180F547DF08DULL,
			0x7CA5E3C59E904485ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3D8F5EC367115186ULL,
			0xFD75002EFCFA90AAULL,
			0xD6B93DFC63032EACULL,
			0x35A30E0CED1C07EFULL
		}
	};
	printf("Test Case 364\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x73489C8DAAF5F030ULL,
			0x230E3BFA00C0288FULL,
			0x19E608787CD2AE6CULL,
			0x741FDE60C1E1D7ACULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA99E56B54F816C2CULL,
			0x1DF590F3378A6A6CULL,
			0x745845886AD374A2ULL,
			0x6A17179F002C9CCBULL
		}
	};
	printf("Test Case 365\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3104AE4068BDE480ULL,
			0xFEAB337A2682CC9EULL,
			0xCCBF49C2DC7BEE52ULL,
			0x75C4F3DDC6C89835ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x958C8DBAA3DD5BB4ULL,
			0x270331AED2DFBDE6ULL,
			0x2EE414809DC75C56ULL,
			0x0F81C45E46E92E29ULL
		}
	};
	printf("Test Case 366\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBE4BC9B2A9023848ULL,
			0x9DC345912CD3E8DAULL,
			0x1774E9D7CB524CB1ULL,
			0x7E7C8A4E6512A10EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8560082000DECC44ULL,
			0x122D2DA1FCEEDA9CULL,
			0xF0EC8C648029F46BULL,
			0x1AA006A4B5846C5DULL
		}
	};
	printf("Test Case 367\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x31C229233DA186D0ULL,
			0xCB10F867DA7107BAULL,
			0x8D6AD5704646DCCDULL,
			0x414DF3362D4954A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE7581577E61965DAULL,
			0x221790ADBCB57FABULL,
			0x7703AD19441FB853ULL,
			0x02E478E31C39D5A8ULL
		}
	};
	printf("Test Case 368\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAE03DEB2C8AB9BB8ULL,
			0x08C90CAA9FE4EB1AULL,
			0x9C861C0DF04EB3C5ULL,
			0x501A84C08797383BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CB21D685C93D0A4ULL,
			0x6AFD9B10345F3E8DULL,
			0x2F9D0EF6642BCEC3ULL,
			0x553CDD8C9658655CULL
		}
	};
	printf("Test Case 369\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7D60FB9B200FAD10ULL,
			0xF8D5D28671D67435ULL,
			0x146402683047102BULL,
			0x54C6C0EAD14B9455ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4D0B47DF6A94D343ULL,
			0x7E3D2605D71CFC74ULL,
			0xBD62CA821643D00FULL,
			0x10EF383475C821BAULL
		}
	};
	printf("Test Case 370\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC79F235CE0F5EA20ULL,
			0x5FBFFC65B05FBE67ULL,
			0x4DD07F7FB814AAC7ULL,
			0x62EEB5A896EED644ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCB812A820583A577ULL,
			0x307902A0C0028DB9ULL,
			0x4ACD7B8C20D9CC98ULL,
			0x30842962D2493DEFULL
		}
	};
	printf("Test Case 371\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5654EF296DFBA1E0ULL,
			0x6556716431C24E47ULL,
			0xD381CCCCF4234F85ULL,
			0x7AD67493C1C7EAAFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1B30C1EB1546793BULL,
			0x35DB1E3CB9212C3DULL,
			0x72E51E1D10C18D26ULL,
			0x44A2594270310FD1ULL
		}
	};
	printf("Test Case 372\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCFDA657169B2A000ULL,
			0xBE5AD6A662963DBDULL,
			0xAD38EE83F15E1664ULL,
			0x509ECB8E192E223EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xABDD8D6E5EA6D4D8ULL,
			0xD13BAEEB40A377D5ULL,
			0xFA060857917B9F5DULL,
			0x70D91227EBD6172DULL
		}
	};
	printf("Test Case 373\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC7F8A1A1238762D0ULL,
			0xA0C5C055825968CAULL,
			0xA87DC0B68DFF6073ULL,
			0x4D08BD7E8C8D55B9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5D19A1A5FF45294DULL,
			0xC165CFDED86F4D52ULL,
			0x030F2EC049400F96ULL,
			0x1F1D4A809295733DULL
		}
	};
	printf("Test Case 374\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x33CE0E19B2ECE0D8ULL,
			0xD05FCCFEF56ACA6CULL,
			0x61FD7AE46043B4EBULL,
			0x48EA6F61E41ACC8DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x62B8F0C04ADD03DFULL,
			0xA770C8D09BB83458ULL,
			0x7296330032B99D36ULL,
			0x03B34B5C304FD0CEULL
		}
	};
	printf("Test Case 375\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5A5DE0B89B034B20ULL,
			0x4B50825796CB048EULL,
			0x1319F791E871B194ULL,
			0x408BA117E019520FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8E18459C91990CB4ULL,
			0xCE2DB7E17356DA6DULL,
			0x4D40B1DB7ECA982BULL,
			0x7CAEFC63D3707DF4ULL
		}
	};
	printf("Test Case 376\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7C66E37B6E6B8BF0ULL,
			0xC0864D56557530C4ULL,
			0xFC714BC45DFBF636ULL,
			0x608B9EA1A51C321AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE9D2B685244E3DDCULL,
			0x9B5C98D308C7291CULL,
			0x968FC4BCB1DBD3A4ULL,
			0x303FDEFED35391C7ULL
		}
	};
	printf("Test Case 377\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x60F5476267656768ULL,
			0x82CEDC191819645EULL,
			0x1C2517375F0E2C4AULL,
			0x4EB70A2E8BCA6FE7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x35A2A19D56362D37ULL,
			0x01DC0594037DD4DDULL,
			0xDD2A0F91FC62C507ULL,
			0x246BCA1268FF5A04ULL
		}
	};
	printf("Test Case 378\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCE55ADF2F8CF5DC0ULL,
			0xBE3A8D023793F62EULL,
			0x0275F53ACA336476ULL,
			0x47B18251D39B948AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8C6DFE7F14EE4F42ULL,
			0x346426996661A00DULL,
			0x65C5127D074A9A04ULL,
			0x16D19B3FFA717D7EULL
		}
	};
	printf("Test Case 379\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5522D638FF9CDC28ULL,
			0x4F5F6387BA51A359ULL,
			0x80DDD4708CA5EAD7ULL,
			0x53FC386ED65B795DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF6711DA936C88B27ULL,
			0xD6497297FA593D99ULL,
			0x80DB7AE3955BB2DFULL,
			0x3CA5596A16AF81BBULL
		}
	};
	printf("Test Case 380\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6F0AA6E969BCB100ULL,
			0x268B7335E5356E35ULL,
			0xD267CA2AEA359D55ULL,
			0x6345279DC54ED00BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6B1FC059C0BBF928ULL,
			0xB959D31B1B9619BBULL,
			0xFF058D88A6ECA5CEULL,
			0x7242FA22FB679F96ULL
		}
	};
	printf("Test Case 381\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5D5712D3660ED680ULL,
			0x9417ED3B7071BAA5ULL,
			0x380E00D3981329FEULL,
			0x64A5DA592574E1DDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4FECAA1AE8AB27D1ULL,
			0x212F8CBB399240F5ULL,
			0x6CBAA7613DDE31C5ULL,
			0x102AC62BE96EDD9DULL
		}
	};
	printf("Test Case 382\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD85F46C3DC1E9500ULL,
			0xF4EC95EA8978F7C2ULL,
			0xDBBBF74525C1D453ULL,
			0x41BB693D55488FE5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC7AD5868677E761CULL,
			0xC6A9ABB6EC58F6E0ULL,
			0x4B9F11D4EE1FA845ULL,
			0x5D9C87CA12C98F57ULL
		}
	};
	printf("Test Case 383\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x535F35DFA5A72D40ULL,
			0x3708737F607DE613ULL,
			0x4F7DF2C83DF824B7ULL,
			0x5F64B4D60535C573ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x75F566AD30ACE6FDULL,
			0x172DAEE7304AF667ULL,
			0xBE7650ABEDF5E26BULL,
			0x45B0BC8657C5C51FULL
		}
	};
	printf("Test Case 384\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7654FA1F8FB6FF48ULL,
			0x14B7AD5464FADCE8ULL,
			0xEB132CA3D3F6B81CULL,
			0x41E94866D59B6284ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1C5A94298CDAC0EAULL,
			0xA7765920923982A1ULL,
			0xED67A799D8D26851ULL,
			0x534A5AB4B53E2467ULL
		}
	};
	printf("Test Case 385\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEB262106BEC1B2B8ULL,
			0xDEF931F9B627DE69ULL,
			0x3BE513208242189AULL,
			0x6B41DAD788945B44ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x39DFC364C4DBA888ULL,
			0xE36F4FD503CCDDCAULL,
			0x810888D90097B6D5ULL,
			0x12D13893A547A934ULL
		}
	};
	printf("Test Case 386\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9589F4545FC797D8ULL,
			0x07B9DE8B42189212ULL,
			0xEE8637E51D3BA688ULL,
			0x5AA15069FCEFF6C3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2F0F0985729534BEULL,
			0xE6CA5A45860DC82DULL,
			0x567ECF843BAD1B00ULL,
			0x751090D6FCC9C740ULL
		}
	};
	printf("Test Case 387\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD77B52CCA8575448ULL,
			0x7064D1923AA2CD7EULL,
			0x398362D8DAF90481ULL,
			0x6D4FA4939C508BF1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x68F12A525AF60E23ULL,
			0x5BE8881D571A3B07ULL,
			0x6F57D615D706F62EULL,
			0x3BD49035B7EDE3D4ULL
		}
	};
	printf("Test Case 388\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x10BCB790C8786B20ULL,
			0x4AFFE6F369842357ULL,
			0x59E898D898EEE591ULL,
			0x7B3BAD430E64CF14ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8C5DA2AC724AE500ULL,
			0x082B33ABE489245DULL,
			0x395B9EF62CB295DEULL,
			0x19CEDC5FA50F977AULL
		}
	};
	printf("Test Case 389\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x10FDDAC4E48C2C00ULL,
			0x8C19A96856C472A1ULL,
			0xD7B2024C0CD9F7F2ULL,
			0x6E8ADD446D653724ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD9C7BF6DCB79E02ULL,
			0x072EAA5A3975BCE1ULL,
			0xAF1945DC8DF9866FULL,
			0x4A2869D36654BC88ULL
		}
	};
	printf("Test Case 390\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEBF873AD523AF9B0ULL,
			0x4350EBDA7F7F81FAULL,
			0xFE8DF17847B61BD4ULL,
			0x7EB002AA70BA80FAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x865ED04E708ECFD7ULL,
			0xE37CC514BC63DC1EULL,
			0x19AB98C89754B17CULL,
			0x7480D338DA4BA5D9ULL
		}
	};
	printf("Test Case 391\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x606B48EB1E3026C8ULL,
			0xF5E154057C001CB9ULL,
			0xE2732ECBC4AE7086ULL,
			0x52BA12776CA23EE1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8C7F3F7FC79DC5E4ULL,
			0xF5921BDEA10AE76DULL,
			0xED7972758273DCBCULL,
			0x615B4DA20B2E25D5ULL
		}
	};
	printf("Test Case 392\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x630072840EA69178ULL,
			0x26498B8B8CAF886BULL,
			0x88A7F74D4F621C17ULL,
			0x460100AC879E0445ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x740DC14C5190367BULL,
			0x0E31FEA3BF4A006BULL,
			0xA927161023869C09ULL,
			0x43C5A5AAFBAD5132ULL
		}
	};
	printf("Test Case 393\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5278F6D78318AFF0ULL,
			0xD2337CC8CBC3153CULL,
			0xD8C70165E395D10FULL,
			0x4653C4B3EA3AF556ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5579E90C6B15A3F3ULL,
			0x479CD90E3A9ECE09ULL,
			0x7AC4B6268A537E2EULL,
			0x76CD107DEFFBDBDBULL
		}
	};
	printf("Test Case 394\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6D9383C6A5A0DD30ULL,
			0xB6D282761430F205ULL,
			0xAB877F02A4A7FF6BULL,
			0x71BBBBB177DCD324ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0E1ABF9D07676766ULL,
			0x4AC7CC720CEC997CULL,
			0xDC68F53E7D1E8DB5ULL,
			0x75986DF308511B1DULL
		}
	};
	printf("Test Case 395\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD94D397CD9BACD78ULL,
			0xB71BA42045E6C361ULL,
			0xDAB9FFBC59F6768DULL,
			0x5A2288903756E502ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDE9D52D45C0595ECULL,
			0x43DD7DE2EF10C0E6ULL,
			0x433A558C3E56D8E5ULL,
			0x3392AE4794A3D44FULL
		}
	};
	printf("Test Case 396\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD441AE42F5B4EBD0ULL,
			0x0B347477AA94E5ABULL,
			0x7AB5BF06EE9AE871ULL,
			0x4C000CD283D0064FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1020132C55180F89ULL,
			0xAF8E239B0B8C6770ULL,
			0x095BF9C8699432BFULL,
			0x3F20294581ADA0BAULL
		}
	};
	printf("Test Case 397\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x064000B96B2B5AA0ULL,
			0x00B3247BB9F6A243ULL,
			0x8ECE2A47684E6BA3ULL,
			0x636F113E8C2A0CC1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8B5F67562E3B5A8DULL,
			0x13B1956C7C535049ULL,
			0x61537F8188753733ULL,
			0x26684EAB616B87CBULL
		}
	};
	printf("Test Case 398\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x84E742EB2E792E68ULL,
			0x45E55FDF736A099FULL,
			0xB904FF29638F5AE8ULL,
			0x710C9B96F5146443ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9DE477B47F4A2031ULL,
			0x02197E85F1A5E10FULL,
			0x64D95240FE15C625ULL,
			0x50F4CBBEFA88DE02ULL
		}
	};
	printf("Test Case 399\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB64E20DEC6C0D2E8ULL,
			0xE6F4CF138D24687CULL,
			0xD4885AFD7BDF23AEULL,
			0x52AB394F482D6C2DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x64B0467145CA485EULL,
			0xC03088FC5A9E71DBULL,
			0xD622C61C73FC440CULL,
			0x01A5311AACFD6C3FULL
		}
	};
	printf("Test Case 400\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0BF1D8C23A54E940ULL,
			0x3338713A4A22C80FULL,
			0x3C8BCA2ABE6CF7E9ULL,
			0x5C0C80598EEFFA6EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBB01607798EC9140ULL,
			0x33D9E01BA994C78DULL,
			0x0F1D2D3B868DB1F0ULL,
			0x6E31F3B59E3B3E1BULL
		}
	};
	printf("Test Case 401\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x026B30E91F293260ULL,
			0x25B0B4033AE4B011ULL,
			0x27C48DD1C9510687ULL,
			0x516C40F4B8EFC89EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6440DBF57F9E0F9AULL,
			0x9900FD507138E41BULL,
			0x6023D66A90028D3CULL,
			0x706E7F4BA897B81AULL
		}
	};
	printf("Test Case 402\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2CDDBB5E684372C0ULL,
			0xEB64CC7AE409F3F5ULL,
			0xEF88C5B89BC399FAULL,
			0x4AAF92EFB3D3CFC4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x21EFF6562CE97672ULL,
			0x9814741A80F38DE6ULL,
			0x9A61B7CA2F166223ULL,
			0x62C4FF48C751BE2BULL
		}
	};
	printf("Test Case 403\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1F95341B02076FA8ULL,
			0xF76795209A01E3C4ULL,
			0xD7974D64E2181624ULL,
			0x55662C4FDA0DE07BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE7D4582EDD9A02A6ULL,
			0xFAF524E62F7CA7E3ULL,
			0x58C57B6C1DEA25FDULL,
			0x28FD17F7F19FFD1EULL
		}
	};
	printf("Test Case 404\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x35DBBC6CCB6BCC20ULL,
			0xCC4E7A3802452FCFULL,
			0x47C09251C7D72452ULL,
			0x6277BBC483D88D32ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6429884E91E5D0C5ULL,
			0x88FA6F8E72CCD1D4ULL,
			0xDD8526525F9D848BULL,
			0x3F515EA4F81A49FDULL
		}
	};
	printf("Test Case 405\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2C701552ACD72D08ULL,
			0x4BDF161FF50CD018ULL,
			0xA6E6878C82577819ULL,
			0x469A39E808E55FEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3F9D9988AECD833CULL,
			0x34C9D5088F539E6FULL,
			0x0E795965301DFBC4ULL,
			0x1C21FA24378DAD90ULL
		}
	};
	printf("Test Case 406\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x94185F3D971F5E10ULL,
			0xD0594346D99E6C25ULL,
			0x49BFA11F87A4F8C8ULL,
			0x6020EBD9C5AB386FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x26F78C0CC112398FULL,
			0x960EBE264549BD09ULL,
			0x9FB5F455BE9E8E3CULL,
			0x2558D252B5F71E5DULL
		}
	};
	printf("Test Case 407\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2206F06ACCBC8E88ULL,
			0xAAED08E1AC5330AAULL,
			0x7A6FA154258573A8ULL,
			0x64BF6C83509C6491ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD6CAD9216D76DB8FULL,
			0x289D8EF4A6BE642BULL,
			0x9914702ED9DDB6C1ULL,
			0x2074A915A07F3F36ULL
		}
	};
	printf("Test Case 408\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBA579537110458F8ULL,
			0x79402E2C632F6EA3ULL,
			0x37B2C362C68C682DULL,
			0x45A27B56A735C8CAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2705FA41460EC78EULL,
			0x400A349B12F8BC5EULL,
			0x21818BC432E3E615ULL,
			0x009B708FA89FDF66ULL
		}
	};
	printf("Test Case 409\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAF1A1165174B3F68ULL,
			0x80EB3950F22B999BULL,
			0xEC56C880614F9791ULL,
			0x5CCBB387ACF4296FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE6CC91E1539F853EULL,
			0xEC791D2103024861ULL,
			0xC38C0F4AB701F9BDULL,
			0x6BDDFE9293FA70AEULL
		}
	};
	printf("Test Case 410\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6D9131E9CF083138ULL,
			0x847AC9D049D5A671ULL,
			0xD3F24C0388C8E582ULL,
			0x6408998E70B8A2E8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x03D5B9B9262476CEULL,
			0x5B4B247706B0D4B2ULL,
			0x1EDE512A4654CC1AULL,
			0x47DF15ECFB70B672ULL
		}
	};
	printf("Test Case 411\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9C2B12F8CB44D1A0ULL,
			0x3B126CD4275C2642ULL,
			0x990A50087ABC5E86ULL,
			0x5C8FB98D1272445EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9C3EA9B27FA86E4EULL,
			0x840F93217D9D80B6ULL,
			0x19DC6A5FB259545CULL,
			0x18BD6F8FE6C067FCULL
		}
	};
	printf("Test Case 412\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE1246C424CB12B98ULL,
			0x60165129C169BA35ULL,
			0x21DE02647F856A94ULL,
			0x4F2E611633DF4C84ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x63D635496410C3F6ULL,
			0xEAC0490F1B46ED77ULL,
			0x3256B5AF3CAE224CULL,
			0x1E44D3658A61DEE1ULL
		}
	};
	printf("Test Case 413\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA723FDCCC7B7B458ULL,
			0xB8F0BA4E1DF06FB6ULL,
			0x087CB1BBF91BBE79ULL,
			0x57D7F676E7015C2BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x459E8A3F8A253BD5ULL,
			0x54DA53E29323A112ULL,
			0xCA02850B1B71F2B4ULL,
			0x4BADAEF8941AF528ULL
		}
	};
	printf("Test Case 414\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8AC77DF6C4284028ULL,
			0x195CB418EDFDE472ULL,
			0x2D29EEC8A7B77EE3ULL,
			0x7B5262777EF43867ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC09412908F5E0CDDULL,
			0x590748CE157DD74CULL,
			0x0C655E9CB6B2D2C9ULL,
			0x24B9A74F93DA75C3ULL
		}
	};
	printf("Test Case 415\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1C96C98FD04C1CB0ULL,
			0x0CCD20818423C272ULL,
			0xF3F3CC51BECAD913ULL,
			0x701D23EB0A8F6656ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CBD8F26F1990355ULL,
			0x9EEA1E74ECB2DEBEULL,
			0x664EF6289638AA3CULL,
			0x533DC767E75D8F02ULL
		}
	};
	printf("Test Case 416\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEF463E2383FDC5A8ULL,
			0x08FC0844E3867D10ULL,
			0xFFF1C08F5ADC3829ULL,
			0x48D6105E1EA08429ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5835548B48B48541ULL,
			0x22714BB16723E333ULL,
			0x33220BB0710F8347ULL,
			0x1098085C92680059ULL
		}
	};
	printf("Test Case 417\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4A3C842C10FB3AB8ULL,
			0x3A42A7B3DD6285BCULL,
			0xFB59FB65F497D60DULL,
			0x6B0EF0A891EE4491ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD43A7A88CA267CB6ULL,
			0x047523AEFCF4D742ULL,
			0xFA35AFCD450303D2ULL,
			0x16626A5590058AADULL
		}
	};
	printf("Test Case 418\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x90A554EE22492270ULL,
			0x06BD2C64F2C20F0AULL,
			0x9459BAB54181736DULL,
			0x711CB700DEEA4383ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0E246D7342761BD6ULL,
			0x4B2A96D8C842D815ULL,
			0x25373DBCAB6D0DDEULL,
			0x5C8426931DB678BCULL
		}
	};
	printf("Test Case 419\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x8BF6E0AC8A2FFC88ULL,
			0xFF67B7E6D1CC5937ULL,
			0x628BD00FD1DABF59ULL,
			0x4A55C735C64F35C5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD3525E244893557CULL,
			0x7891C9B8C1B74617ULL,
			0x16D3311307C264C2ULL,
			0x53C6403805578802ULL
		}
	};
	printf("Test Case 420\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0A5AAFD5E9DED5D8ULL,
			0xC9AFCCCBE0F5F7B3ULL,
			0x8E0C503BD8D2BE09ULL,
			0x6C1538DE5534D6D5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC3310984601FBDF7ULL,
			0x24B0AE1FEC864F58ULL,
			0x602ED0EB7B388020ULL,
			0x4FA74C61BDCFCD61ULL
		}
	};
	printf("Test Case 421\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEEB11A7351145350ULL,
			0xAE1447BD7AE09463ULL,
			0x29CC4E009EFC72CBULL,
			0x51616E535B77888EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDE410E605782A8CAULL,
			0xFC5856B12CD2E576ULL,
			0xA146DAACF7645076ULL,
			0x58AFA6C0837F3DBAULL
		}
	};
	printf("Test Case 422\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3F15B1429E742F18ULL,
			0xE0BECBD0ABAB50DFULL,
			0x345DD1FDA7E8CFF5ULL,
			0x7F1D85BA2BF2B23CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFE79281F25A4E107ULL,
			0x3FE8B9CA99EF9AE2ULL,
			0x3E2EE806F38A81C3ULL,
			0x51FB099C6AA25BC6ULL
		}
	};
	printf("Test Case 423\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x0A728C6567C11FD0ULL,
			0x865971CAFA0900C6ULL,
			0x0CA2155843522120ULL,
			0x6275332AC3C3DED0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x44E70B6BE4304370ULL,
			0xDDCE6CFA36EE4B15ULL,
			0xD79065E2ED7FB0E4ULL,
			0x6B99B8F3C2E8917AULL
		}
	};
	printf("Test Case 424\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAE7AD72B45625FD0ULL,
			0x91DD562C118C68ADULL,
			0xB8E2C030920936E3ULL,
			0x4C5515A89BF37A74ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x246B9ADE1EE44B2EULL,
			0xF6582729C58BD9E9ULL,
			0x9880F9F86AEB78E6ULL,
			0x6B03C48462436954ULL
		}
	};
	printf("Test Case 425\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1E754A2E40495EE0ULL,
			0x06D7A32C7813CF2CULL,
			0xF006DB0FE2CB4911ULL,
			0x5EDFF3183DEC074AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA046451917FBE9A4ULL,
			0xD75A258A607E63CDULL,
			0xCFE45DDA68D5E49AULL,
			0x19BD7B6700B650ADULL
		}
	};
	printf("Test Case 426\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x81264624FF31BC20ULL,
			0x97753A6C0E5635F6ULL,
			0x7A39DEA142CAEB6AULL,
			0x417653B641761F16ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x23E7F68F47DE0288ULL,
			0x1A4470B8989E3880ULL,
			0xBA87E8289D996D09ULL,
			0x4F26275B49168A0FULL
		}
	};
	printf("Test Case 427\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE86CFAC25ED34740ULL,
			0xE54BBED012C3FD4BULL,
			0x876C4434DDB043A0ULL,
			0x4AD6592A8ED5E389ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFC38218FEB3DC27BULL,
			0x213C0C8E44393103ULL,
			0xCE785ACA453C6C2EULL,
			0x64CAA34E55599566ULL
		}
	};
	printf("Test Case 428\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x884B4817385B45F8ULL,
			0x755167B341A3582BULL,
			0xDDB0BE369257658AULL,
			0x73FCA7CDE2EB8A94ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEE87A99CD72B6590ULL,
			0x80589F7EE3A5703CULL,
			0x1E7B8E6982512AA7ULL,
			0x64048C7307B0B5D4ULL
		}
	};
	printf("Test Case 429\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD5511F780A84CCE0ULL,
			0xEB5FBC7F9EE5BBD6ULL,
			0x91F3FFA5157132B1ULL,
			0x698B2E1F120B2F28ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x62A56ECABF0B4E98ULL,
			0x2B03B5537A5EBA9CULL,
			0x6335B0EFBD24306AULL,
			0x1238B5F09EB5871BULL
		}
	};
	printf("Test Case 430\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2BDEF08A8226A900ULL,
			0x2D88EDD7E4308BEEULL,
			0x1C3C9F77D9F6FDBAULL,
			0x68E6917CE2BA1F9EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA86249B7F6D44984ULL,
			0x2362AE4B2427582DULL,
			0xDB4E7223DFA4DD2BULL,
			0x6E21F30D8EDF92B5ULL
		}
	};
	printf("Test Case 431\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x956FE6500C1725D0ULL,
			0x53D8674801E52543ULL,
			0x3131B2020EE88B96ULL,
			0x411878D68A2921D3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x45C1AEFF0828BD72ULL,
			0x8798B462E39FCAB9ULL,
			0x4E2E860CCA731094ULL,
			0x6016F82BA5DAAEC3ULL
		}
	};
	printf("Test Case 432\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7338FAE5C9569A60ULL,
			0xBCCD4A67BB761D13ULL,
			0x6D4058B2FDBC954CULL,
			0x585D2F0C9E849269ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEE892CE2ED8A5D4EULL,
			0xDE462EA08E8EF4D9ULL,
			0x9AF41CB979A686D4ULL,
			0x2817E9601F85B54BULL
		}
	};
	printf("Test Case 433\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA7CCAABA0C8A6A40ULL,
			0xCCE4593A4075901DULL,
			0xCF0EE64E339B53B9ULL,
			0x59B7296295C1873CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB01C831CE6DEDE04ULL,
			0xC4AFEDAE94298E67ULL,
			0x8553EACC4848B7DCULL,
			0x15B99FBE5BF98264ULL
		}
	};
	printf("Test Case 434\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1ACAB4CFDB874310ULL,
			0x552721B7A52828A3ULL,
			0x37F4CD0BC2878733ULL,
			0x7B39FDA904438822ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8D6509D5018A93A7ULL,
			0xFE37B5C4FB6E7D5AULL,
			0x113D73E2E83F8D70ULL,
			0x528FDF4D78C0D7D6ULL
		}
	};
	printf("Test Case 435\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD56EB97725AB91E8ULL,
			0x4AA38B845D0568D7ULL,
			0x12A4AC8BC163D28BULL,
			0x54F209A995A6A546ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x58BCB4F572F4503FULL,
			0xFC34F372B031578EULL,
			0xBC094BBCE239DBBDULL,
			0x0C716BDB53012CC5ULL
		}
	};
	printf("Test Case 436\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9E8B417058AE5B10ULL,
			0xAA4B6BDEAF83FD49ULL,
			0xD64ED11220A69170ULL,
			0x5E0C9F5B6B137DA3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x297B9ADC93516195ULL,
			0x46A601DDEBD91B12ULL,
			0xB60EAFEA93C5BABCULL,
			0x1C43807194DC2336ULL
		}
	};
	printf("Test Case 437\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA4A802CB595FD848ULL,
			0x6A22807B65D59922ULL,
			0x2EDBE8DDC1AA866DULL,
			0x7394E1A27D0D5D4DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x882AEB87F78EEE50ULL,
			0xF3E0CDE5FB653A52ULL,
			0x02B40557847C8B33ULL,
			0x57BF285F7F0E12CFULL
		}
	};
	printf("Test Case 438\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC58D53EE3A5C0170ULL,
			0x99FE38310BD99E79ULL,
			0x4923E007265F5F9AULL,
			0x5ED1149E8791EE84ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x716F82CEF662DD0EULL,
			0xDB81669E689D8C73ULL,
			0x07F8471F31257CD4ULL,
			0x07A6972708EF719CULL
		}
	};
	printf("Test Case 439\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xCFED81D393077FF8ULL,
			0x82981FF27EDD64D4ULL,
			0xC01271C56E0740FFULL,
			0x4AC5842BBBBFBC0AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x887FFD86C1391E9FULL,
			0xD7C5C39ADCEEE66BULL,
			0x2EB74E628F7EB114ULL,
			0x189472B5953EE4A1ULL
		}
	};
	printf("Test Case 440\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x443F74D5C3D51CA8ULL,
			0x7441BAB243B27C17ULL,
			0x7761F3CCDE7FF448ULL,
			0x53A4792E0772B654ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x563C004314E60913ULL,
			0x96C789DDD99B7D90ULL,
			0xA5432335B92B843EULL,
			0x7E52C75491833E5EULL
		}
	};
	printf("Test Case 441\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x206BF4B3A0F01E98ULL,
			0x10CD17CCDCA8C2A3ULL,
			0x5227F0DA4303B272ULL,
			0x7B7A52E7CFA970EEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6A40D0DED1B9AFB4ULL,
			0xDD45433EEAE8BAA9ULL,
			0x4BABD4C81BE1B24FULL,
			0x5EFCBB610BE09290ULL
		}
	};
	printf("Test Case 442\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6F0667B528ADCC60ULL,
			0xF57A9599145B7600ULL,
			0xFF0066272831A742ULL,
			0x5CE39762E42DC67EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB7ED586675E3A440ULL,
			0xA93CFFB0501C3FAAULL,
			0xFD1783F227F38FC5ULL,
			0x7ED9C975FF3259BEULL
		}
	};
	printf("Test Case 443\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x58401ED5C2047108ULL,
			0xD2CAA1B299B9E8A5ULL,
			0xC804C47887ED9E2EULL,
			0x53442E7DF1BB9CC3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x374FC0E01DA7E3EEULL,
			0xE702A008C818C426ULL,
			0x3B5C80C9ABC1C9B6ULL,
			0x77FBA3D5CC8F7A3FULL
		}
	};
	printf("Test Case 444\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6B2FF649DEF9E948ULL,
			0x1D483138D2DB5723ULL,
			0xE97AE643AD865816ULL,
			0x701A8A44C051F98EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9BEA220CC7D4531EULL,
			0x888D8F8B234825A0ULL,
			0x81685F8A94B03B28ULL,
			0x0F07311F7AA57242ULL
		}
	};
	printf("Test Case 445\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB54EAA88D5CCAC68ULL,
			0x5C671A32D49BAF95ULL,
			0x4836A7DBBDE61F06ULL,
			0x6D145024DDCD1EA2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBAE6458FE0F31193ULL,
			0x2272DDE7D367B187ULL,
			0x29784C59A10BDC51ULL,
			0x3E6DC0DEDDC73FA3ULL
		}
	};
	printf("Test Case 446\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC4462F4A52A46700ULL,
			0x4C2EDECD91CB881CULL,
			0x0CF6C9E84DFAE266ULL,
			0x42E520B4A2FEB1DEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDB34167B6C7AEFD2ULL,
			0xFC8FE18C0A4F27D9ULL,
			0x112BFEC829FE25D3ULL,
			0x71780D3130753B6FULL
		}
	};
	printf("Test Case 447\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x229358BDC02E1840ULL,
			0xC5CA6DEB51287594ULL,
			0xE390A46338D8B39FULL,
			0x658C6F007D47640AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x29D1DFD0C10198D0ULL,
			0x0E91B677ECD7CA16ULL,
			0x778D40C3882BD577ULL,
			0x36C1171D1C40B467ULL
		}
	};
	printf("Test Case 448\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB95B2A7155A05858ULL,
			0x961B6D85CE404375ULL,
			0xE5C007881A6F6854ULL,
			0x5A67A32298B9378EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1E05EC37200F1EC6ULL,
			0xFCE333C4F824C9BCULL,
			0xBF5725C04B859A09ULL,
			0x2D9FB62D178EECC4ULL
		}
	};
	printf("Test Case 449\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4910DD0700B6F680ULL,
			0x24B4F63DACA7E5E3ULL,
			0xFD53B82921D509F5ULL,
			0x5019D00D15AC45C0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x220DDF171C38E425ULL,
			0xA79A2D963C8D5AA2ULL,
			0xEF8A0042E3B792E7ULL,
			0x0E3AEA74D5E7F42DULL
		}
	};
	printf("Test Case 450\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x80B0E8F3E44F82A8ULL,
			0xC692D5B2A7FA436DULL,
			0x9E36A78B06908C85ULL,
			0x6AE4746D7BFC07DDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x930D522F8B33FE7AULL,
			0xA0CAD75E257D5553ULL,
			0xC27783E7353A63E0ULL,
			0x1FC18A5A7C0899FDULL
		}
	};
	printf("Test Case 451\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x22C9015C4CD4B230ULL,
			0xB9301DA269444D1EULL,
			0x88B456ED475E623AULL,
			0x521F6A411065DB12ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5839763040156B81ULL,
			0xF46151F287B6CE78ULL,
			0x2FB5F7E35D32052AULL,
			0x149A4175BD5CAD74ULL
		}
	};
	printf("Test Case 452\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xEB1C37B51DBD28E8ULL,
			0x758599561DC0F8F3ULL,
			0x4E51455F3C679368ULL,
			0x42AD19336DF9F601ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3FC3FF578FD6716EULL,
			0x6193E8C498ECF096ULL,
			0xD995D3C6B8AB400DULL,
			0x0D50B735584F87FCULL
		}
	};
	printf("Test Case 453\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD584613E5FAD2B30ULL,
			0xAAF414C751229F3DULL,
			0x161D41EBDF0B2353ULL,
			0x7081787FF4B8FF24ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3FF5876CF790BF48ULL,
			0xFC735C3FBA4C37E4ULL,
			0x14B6E023766137B7ULL,
			0x49B6F7833F1CC397ULL
		}
	};
	printf("Test Case 454\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x47E51A0DCEC7B208ULL,
			0x8CE3D53F8C5B94C2ULL,
			0xB7CF637E2A3AE28FULL,
			0x51C199B9F1F8E04EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9C89102D4ADA6A7AULL,
			0x0894C5C97EB135C2ULL,
			0x865FEEE95D240F63ULL,
			0x6FE9F4075E0D881AULL
		}
	};
	printf("Test Case 455\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x586EBC7C9D93E868ULL,
			0xB261F4A5214CC824ULL,
			0xC8365D7564335C4AULL,
			0x52329C3B4E658D53ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x099315F23CC2FC0EULL,
			0xF911DF56F82F0EF2ULL,
			0xA9A3FD9D044F6A71ULL,
			0x77B466F65907A2E2ULL
		}
	};
	printf("Test Case 456\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xF7D670ACC6AA77F8ULL,
			0x2C31025070C5E2A1ULL,
			0xA9CFAB068ABF2EF0ULL,
			0x7146B9626984F418ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9ADB694E17B2AFDDULL,
			0x08C075F52ECE0067ULL,
			0x71475D24616DC525ULL,
			0x0C7EB1BC26370CEAULL
		}
	};
	printf("Test Case 457\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x57C030780B95B600ULL,
			0xA1917F59E958E805ULL,
			0x2F3A2104D456D4DAULL,
			0x40DD0AAFA88FB683ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8BEC9C0DA8248D9EULL,
			0xC4FB6EB62D9FACBCULL,
			0xF9075DEC87A305F7ULL,
			0x4A22B1DBF3440EE8ULL
		}
	};
	printf("Test Case 458\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDE85EBB7088CEFA8ULL,
			0x3FBFF4C78FA64A56ULL,
			0x9CB4642A983B2FEAULL,
			0x629C012885291159ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4DCC7F9B1939656FULL,
			0xD66E72D334886634ULL,
			0x68DCA7980CA20952ULL,
			0x674A285E9726B293ULL
		}
	};
	printf("Test Case 459\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE9191723D3664FE0ULL,
			0x7CE8C291498D85F0ULL,
			0xF1CA984191DED414ULL,
			0x6F46C3FF54B6CB2BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8A1E0FDA1066FE6AULL,
			0x0048DF64713C9746ULL,
			0xF533BEA25DB24120ULL,
			0x4330ACDDE68F4AA5ULL
		}
	};
	printf("Test Case 460\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB99822F14EB32088ULL,
			0x844BDA3BFB602660ULL,
			0x109D77723B3540F3ULL,
			0x6DE71B4E2FDEA6CAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE1A2E16D533284A4ULL,
			0x008C4AFDF4C40029ULL,
			0x8042A67F8314EFA4ULL,
			0x5ED73FAAC51A51E0ULL
		}
	};
	printf("Test Case 461\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA781622EC4F87710ULL,
			0x745431D0F171C210ULL,
			0x569A7A39ED172D47ULL,
			0x74CB053FB92F7C0FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE587FA44FB2ED879ULL,
			0x7AD29E8916866305ULL,
			0xC51A75CBFBC4B373ULL,
			0x71B0EBBCA3EF6531ULL
		}
	};
	printf("Test Case 462\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5B71A3FBC864F4D0ULL,
			0x78F635FED652F2E7ULL,
			0x1B9A0137D90DE384ULL,
			0x6B8D0374D5C4A081ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE3B39F8EEDB6601EULL,
			0x00F6B4977C989D43ULL,
			0x78C5F168B4C0AD9EULL,
			0x5FB83EEB883EE19EULL
		}
	};
	printf("Test Case 463\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC047ED9A431B5958ULL,
			0x3E408B90CE147201ULL,
			0x694D2135A1BA7EEEULL,
			0x42BEDE235D6247B7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x458C9DBEFA21152CULL,
			0x092BD3CA4A23904CULL,
			0x6DBDA43D551E88C3ULL,
			0x768F9D129051536DULL
		}
	};
	printf("Test Case 464\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5A2827A6EC153638ULL,
			0xDA7D0F8DE80DA064ULL,
			0xD0E5AF255BD4B24CULL,
			0x711A0F31A923D024ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x723CA610CA933CCAULL,
			0x0BAD057337FDE59FULL,
			0x09FE610A775E2331ULL,
			0x1FBECCEDFBF1FCC5ULL
		}
	};
	printf("Test Case 465\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6210BEC1ABB8EC28ULL,
			0x297E709F53648A04ULL,
			0x28FEC55AF0CF8D8EULL,
			0x4589D6FBEC88C378ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x74473648F978E1F5ULL,
			0xD245BAC0357D3181ULL,
			0xF1AFFF9122741D1AULL,
			0x20C35AF767208F8FULL
		}
	};
	printf("Test Case 466\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x1917C0199AC8D1C0ULL,
			0xC2EB360C6CCDF81BULL,
			0x99F0DDF5D6B4EDB8ULL,
			0x4996F3F111EA92B2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x23F710D4BE5DC567ULL,
			0x171CD78044569550ULL,
			0x6F4E3F647125B948ULL,
			0x241DECCA72D76520ULL
		}
	};
	printf("Test Case 467\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7D7072FDD80337F0ULL,
			0xC562A100AE21015CULL,
			0xE7EF3CAFA61B3D37ULL,
			0x477294F40B8BA20CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x67D80244E35BA297ULL,
			0x68F2E5124CD7CCAEULL,
			0xD46E103C457C15C2ULL,
			0x6D5C66EA298B0E9DULL
		}
	};
	printf("Test Case 468\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x282CABF5A23FEC68ULL,
			0xA5982C63C116AAD8ULL,
			0xA4703E8D8CB86010ULL,
			0x712F9FBD3CC52AD9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4A96B3A1ACFCBDBBULL,
			0x6E541EE238E6F75DULL,
			0xBDA232B3C9AB66EFULL,
			0x61948694CD1163D6ULL
		}
	};
	printf("Test Case 469\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x085EF80365779638ULL,
			0xA21E77B177C47C81ULL,
			0x9B5191F909874023ULL,
			0x5DD4E8EFC63C3D5CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x933EC1DD84F20E57ULL,
			0xB6520B05881CFCE9ULL,
			0x6A19E3B4B42E3B9DULL,
			0x7AC22EEFE41F8E60ULL
		}
	};
	printf("Test Case 470\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x91CB379F88233730ULL,
			0x27FF9993396A872FULL,
			0x50F3C83296E4EA7FULL,
			0x74444E0FD573540DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x132954E1EA1DDC17ULL,
			0x2B4BA1D3BFBB28ADULL,
			0xDCBF80DBD361628FULL,
			0x5A2CA324C2C21DB9ULL
		}
	};
	printf("Test Case 471\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xE47D248C15141DC0ULL,
			0x108CC9DD52FEF48EULL,
			0x4422CC2F3B391DE8ULL,
			0x4048F068D9023013ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x39234B9877B34C9EULL,
			0xB4C4834D359ACB83ULL,
			0x5F0601BDCAB9ABCFULL,
			0x742F4B1996BE773CULL
		}
	};
	printf("Test Case 472\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xFE1C51A76B1F0868ULL,
			0xD35211819760DD5CULL,
			0xF1632C64931C3A74ULL,
			0x4472AEAAFE5097D1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD5F0E58A73977EB0ULL,
			0xE64ADA02939A5D50ULL,
			0xFFF09DCDBC1C9364ULL,
			0x641213913665181BULL
		}
	};
	printf("Test Case 473\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xDC8146FF4A10F580ULL,
			0x28939F4696441EA0ULL,
			0x59E7ED6197F3D767ULL,
			0x456167B8654F923DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCAA7ACC7BE90E5A4ULL,
			0x1758E5B1E794BF36ULL,
			0xB84BB928D00EA917ULL,
			0x11707A4844F0629BULL
		}
	};
	printf("Test Case 474\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xC763EB471F782B20ULL,
			0xCF3C7C4E9C7DBEEAULL,
			0x23D86E4C035C8699ULL,
			0x61B741C09F588179ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x725BB7BC2810D0FDULL,
			0xFEDB2BF1337A5C6DULL,
			0x342BEFE1AA7D8F4DULL,
			0x1C99450472F8EE4EULL
		}
	};
	printf("Test Case 475\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2BE2D806FCCE9D30ULL,
			0x09A57EFABAFE5C10ULL,
			0xDB40C56235D4F1DFULL,
			0x775EAA8D5CD6961EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFBD2A05A87FDA17EULL,
			0x74BC997A22A7CC70ULL,
			0x6F26DFE69C30137AULL,
			0x363822C48E2B3886ULL
		}
	};
	printf("Test Case 476\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x786B1EA3120F5D68ULL,
			0xC8302BB06B820719ULL,
			0xBC06E7AE99E912E9ULL,
			0x60EC9690F5986BCFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0C419D533F6FD1E1ULL,
			0xE30D4E9B02949CD3ULL,
			0xBBEF5BD2339679EFULL,
			0x7DD88C3593996A00ULL
		}
	};
	printf("Test Case 477\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x6E2442F33FEB93A8ULL,
			0x7050D51EB15CDB3BULL,
			0x687DB70FFDBC474AULL,
			0x7134DFADE4DDD4DCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5925954DA2DF8D12ULL,
			0xF7446CD9D8603CCEULL,
			0x3C4A3799C307C456ULL,
			0x732E528E91C49512ULL
		}
	};
	printf("Test Case 478\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x49F1EB1DFAD45950ULL,
			0x7307D7C1A8A2ADD9ULL,
			0x5A1AC5BFA94D4008ULL,
			0x4CE3990564F8EA05ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2E95C8D0BB17667BULL,
			0xB8E695F38BE2FED3ULL,
			0xF46285F146873E66ULL,
			0x0147770BF86736E9ULL
		}
	};
	printf("Test Case 479\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x910B9F7DCBDF1608ULL,
			0x528FEE46584F4FB0ULL,
			0x163D7D9B989CB090ULL,
			0x5E46315D3D68CA6AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x847928EFC6A38CF1ULL,
			0x2FB2EF11D75DE017ULL,
			0x36344987D01386C0ULL,
			0x7DDB611AE72569EFULL
		}
	};
	printf("Test Case 480\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x57A9E713CCEAA788ULL,
			0xAAB69A2D406AF804ULL,
			0xD602A2D27031AF9AULL,
			0x78208927F9736349ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x22D86246E5CABDDAULL,
			0x8755BC45E8AD1336ULL,
			0x51BE75FC1BB6CAD8ULL,
			0x673546E5AC3519F7ULL
		}
	};
	printf("Test Case 481\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x9CC079EDC97155A0ULL,
			0x73DB1FF8F898DF82ULL,
			0xCABFBBEF4A622F8EULL,
			0x50A6178FD6884AD3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x62BA97058B3F7292ULL,
			0xD7244AC28F8A27D6ULL,
			0x96EF6AE321F3B1D5ULL,
			0x16757F3B83CFCA37ULL
		}
	};
	printf("Test Case 482\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x46D511900D830E48ULL,
			0x72528B7109FBEF3DULL,
			0xD4337073789AC90BULL,
			0x68855DFD83646332ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7074DAC81C3DE680ULL,
			0xFC100D9E7BC328F2ULL,
			0x6A77EFC81E647C65ULL,
			0x784A41A0E47B3B94ULL
		}
	};
	printf("Test Case 483\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7A10C0D9BBB47EC0ULL,
			0xF584AA677C961898ULL,
			0xA38EE637A9352F39ULL,
			0x73D555D3E170208FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE8A63F0B23231BC6ULL,
			0x96F70537E142E688ULL,
			0x9362488A9A7B4D59ULL,
			0x509C9E3F2633EA9DULL
		}
	};
	printf("Test Case 484\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x04EF77199A7C5838ULL,
			0x35524FD1A29DAAF1ULL,
			0x358B163036A5C548ULL,
			0x52FB2E315E3D3B7BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5E1495163C216A23ULL,
			0x7973504A99CDDEB7ULL,
			0x278143F5BEB87F9BULL,
			0x701A974BC952FD93ULL
		}
	};
	printf("Test Case 485\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xA7CDF29C03813068ULL,
			0xE4FAF5B1CAEBF76DULL,
			0xB6E43F784F34B862ULL,
			0x5BF2E56FC3F0615EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDFCC8A8150828C24ULL,
			0xD7037E9D7C249A59ULL,
			0x2B59B64A1C584DFAULL,
			0x1E1890F49F0BC5F3ULL
		}
	};
	printf("Test Case 486\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x4F802C74E45473C0ULL,
			0x0AA9A26115E7CF96ULL,
			0x1BC22B45C59FABB6ULL,
			0x5F30AF34DD2629B7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD14A15DC948AC5A0ULL,
			0xD6BBB1BF14DD156BULL,
			0xDAEE6AEF64C98659ULL,
			0x4CCEAD9DF92E709AULL
		}
	};
	printf("Test Case 487\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xAE1F78156A449948ULL,
			0x338C15F05C2BFAB0ULL,
			0xBA2479FA1838C2A8ULL,
			0x53F01DA8449FCEDFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD31E4CAF4F8F8193ULL,
			0xAAABC030992C9948ULL,
			0xD4A690D90DF9E74FULL,
			0x7BECA215FB09ECFDULL
		}
	};
	printf("Test Case 488\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD1EAE437E1BEDD10ULL,
			0xB8DB12CAC12778C9ULL,
			0xD26742C2069E2C8FULL,
			0x7BBA4C2AF1C16B56ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x33C0D950AB3E7D4DULL,
			0x41F7E122880624D2ULL,
			0xEFC886B5D9A3E3E3ULL,
			0x1346018FAB1E9576ULL
		}
	};
	printf("Test Case 489\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xD45FCAA090EB6458ULL,
			0xD739AEFCAAF23F83ULL,
			0xE4A0D785BADC4EDCULL,
			0x54719346EDC0F162ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x536433DB53BDAF22ULL,
			0x7BFF962AF09BEC31ULL,
			0x5651C634A8AA411BULL,
			0x3DC456EBA7B19F32ULL
		}
	};
	printf("Test Case 490\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xBF7754274ED7A3A0ULL,
			0xFA34EAF6C9CC92A1ULL,
			0xC0796B9465DF58D0ULL,
			0x7194A3B095D43298ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x66A1C1B72927D553ULL,
			0xCF12EF3E2202A56DULL,
			0x44BA91A75BE9E7F7ULL,
			0x23693A9F7446BA2DULL
		}
	};
	printf("Test Case 491\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x75C1592C1ABAEA78ULL,
			0x86F450B3D7068FA6ULL,
			0x9EE48C082F68E683ULL,
			0x7DF619ECF8ECC673ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3AFCED3D6F8ACD3BULL,
			0x2FBE2673DE0A91A4ULL,
			0xCBB367CF1B85ED2BULL,
			0x390E86A8F118EB1DULL
		}
	};
	printf("Test Case 492\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0xB428266AB87A1E50ULL,
			0xC917D57B5E6981F1ULL,
			0xF103C14A5863603CULL,
			0x411E4C643E26000AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8233A8E4C73B8EF0ULL,
			0x757688C16C3B5D59ULL,
			0xFBA46191BC2A9F27ULL,
			0x0A321CA2CABF2761ULL
		}
	};
	printf("Test Case 493\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5ECE40E2D96CE290ULL,
			0xD0DA54AE9800E82EULL,
			0x519E258038E78C23ULL,
			0x541512502A4B86A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0DB658785B6708CDULL,
			0xBCE1CC63C9A9B440ULL,
			0x49E456832130FD37ULL,
			0x3593876B9D57159DULL
		}
	};
	printf("Test Case 494\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x30FF8ADDF2A98DB0ULL,
			0x844631E3A0361320ULL,
			0xD795D74DBF16BFA9ULL,
			0x536A52CD30582355ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE88E82A224C46452ULL,
			0x9A5EEE92C70F10A9ULL,
			0x7C62BCE980F08E93ULL,
			0x4DF43929123DBB12ULL
		}
	};
	printf("Test Case 495\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x7BC2E84AAFA693F0ULL,
			0xA76D40F4D5DA3DFAULL,
			0x723E3EAECC1725F4ULL,
			0x489B6FAC8B0FE76EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE138B7F7B0B38144ULL,
			0x8852FA597DC39A8AULL,
			0xE5C6FE3C08634E0DULL,
			0x11A8BA88F0B94D5BULL
		}
	};
	printf("Test Case 496\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x5D16C2F66CC4B7C0ULL,
			0xC169F13449D1B430ULL,
			0x27E78538C14A16BDULL,
			0x6383709515653C3FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x56D5F423E12A1C57ULL,
			0xA35273911E7100F6ULL,
			0xEAC5336FD1104AD0ULL,
			0x615FF191EC4A12F5ULL
		}
	};
	printf("Test Case 497\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x32304EC6EE277970ULL,
			0xC7FE478425FCB61FULL,
			0xB7B90E7C431FD28CULL,
			0x40B27D7BD83CF3E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9806398197B318E8ULL,
			0x628ACD40B9283394ULL,
			0x021E908FE24F6C57ULL,
			0x1C04C1AD38D1DFFCULL
		}
	};
	printf("Test Case 498\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x3D9A50BBD71971C0ULL,
			0x0E6AAAB53381242AULL,
			0xCF636A28807EB367ULL,
			0x4D3B9A836F995EA7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB2E472DEBBB1728DULL,
			0x7D1C300BF8925254ULL,
			0x2D287E429F08781CULL,
			0x22DAEB77007457ABULL
		}
	};
	printf("Test Case 499\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}

	n = (curve25519_key_t){
		.key64 = {
			0x2245386D54C60C10ULL,
			0x0DE0B90840C78C7AULL,
			0x1D2CC9DA7BD71D9FULL,
			0x4AE7D11584E9B448ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB50C62056DE97875ULL,
			0x7AA970746ECAA8B9ULL,
			0xC158A22DC0D5F7EAULL,
			0x670D7C46CE81FD82ULL
		}
	};
	printf("Test Case 500\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nBASE, COMPLETE);
	curve25519_ladder(&n, BASE, &r);
	res = curve25519_key_cmp(&nBASE, &r);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("r:\n");
		curve25519_key_printf(&r, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}

	return 0;
}