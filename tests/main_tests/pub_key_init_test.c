#include "../tests.h"

int32_t curve25519_pub_key_init_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t n = {
		.key64 = {
			0x092ECB72D2D4A9D8ULL,
			0xEBAF40CB02470848ULL,
			0x8892335AB7A5CFFDULL,
			0x4E9746FA66891DCFULL
		}
	};
	curve25519_key_t base = {
		.key64 = {
			0xE38165004F6C0A38ULL,
			0x3652E9A26A00EEFDULL,
			0x02FAE4254F78BC13ULL,
			0x455CB7357BD342E0ULL
		}
	};
	curve25519_key_t nbase = {
		.key64 = {
			0x1AEB6B0101C7AA32ULL,
			0xFF24E9C985A21B77ULL,
			0x37A66679CD5CCF68ULL,
			0x70841F5C5B8E89AAULL
		}
	};
	curve25519_key_t r = { .key64 = { } };
	printf("Test Case 1\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	int res = curve25519_key_cmp(&nbase, &r);
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
			0x3C493139F8E16700ULL,
			0x9D7AA3AED14AB6B2ULL,
			0x0B375C8DE8B435F3ULL,
			0x5B246D89AD727EAFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFEB3B9930FC0C030ULL,
			0x280772C1B5CC244CULL,
			0x16A4425767C71AF2ULL,
			0x65FF94AF4464A6E6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x18B4A8730A0891EEULL,
			0x593014CBA59C33D1ULL,
			0xDBAB36CB59D60C04ULL,
			0x483882B0CEF81C01ULL
		}
	};
	printf("Test Case 2\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFE49B4B65EE9F2A0ULL,
			0x8F18BBB7A5445CABULL,
			0x1350FCA854E9F9B2ULL,
			0x7BEB77E6CADD4FCBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x438EB97DA458A0F8ULL,
			0xE9EA8210141F56D6ULL,
			0xCAF091A22DAD5187ULL,
			0x58CC806952A614ACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9650C1AC8EFF2855ULL,
			0x96ADE22B901DC9B0ULL,
			0xF96B74402E5BB986ULL,
			0x658CAEB0241F3B19ULL
		}
	};
	printf("Test Case 3\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBEDEC12C9C5D9EF0ULL,
			0xE441CE006B2B6CF7ULL,
			0x63E610DE7B1CD1B6ULL,
			0x4F238A89C82F0781ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E83A00E0B4F0D10ULL,
			0xE870FAE2651E8B80ULL,
			0xA08A0D33BABF7E6BULL,
			0x78A26457D478D1A9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x74E1CACB357A6BA2ULL,
			0x4280BB02EC951DB4ULL,
			0x0A70D4C52C2510F8ULL,
			0x251118DF041E7FE2ULL
		}
	};
	printf("Test Case 4\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x86DCCC5E3BA84000ULL,
			0xBFC7F78F0EEE3A1EULL,
			0xC2D1A56FDFA99E8CULL,
			0x46E8EC3D6377CAFBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF3F68152CD663818ULL,
			0xE334DC372CB9CBD2ULL,
			0x97927755C2056EA4ULL,
			0x606A0A94D0DD6F2DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x00C907492AF61AB4ULL,
			0xBD3A5139E4744C53ULL,
			0xD1D187D5D7751B63ULL,
			0x454733A859203740ULL
		}
	};
	printf("Test Case 5\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2DE89F24803EB768ULL,
			0xD31959752AD372DEULL,
			0x83F6487A0608DEF0ULL,
			0x47CBAC546E024490ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB6CD61D3ACA54EA8ULL,
			0xA967798D524284BDULL,
			0x4943FF59327DD3CCULL,
			0x49FBE37F8E3D4615ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7883E9918F9A2B79ULL,
			0xCC07CE10E27BD1C8ULL,
			0xB5190A7138E46A56ULL,
			0x42A9A087DFBFD863ULL
		}
	};
	printf("Test Case 6\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4F25D216F492DA90ULL,
			0x3278A8D9E0B12B4EULL,
			0xF3EAD6F9DFE38EF5ULL,
			0x7DBCDCAEA89E94D3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0FC30B8F69DC2D88ULL,
			0x983F4B9EC027F23BULL,
			0x8C7276AD2739E3C3ULL,
			0x67FADD30CD3EA927ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC42DED6BB5B9C00BULL,
			0x0753C58CA87EF482ULL,
			0x3BD2786496FAF331ULL,
			0x7B2D15BD19537A71ULL
		}
	};
	printf("Test Case 7\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x505DAC69B68B5D10ULL,
			0xA98188EF1B66CAA2ULL,
			0x95BCC76ED69759C6ULL,
			0x46810C831A8193F8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC4EC050D84F6E6B8ULL,
			0x90AD04DCD6A8F0BBULL,
			0x4C3A2ED18F729F64ULL,
			0x53F94E818B8C0014ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x444765AA370E0200ULL,
			0xEDAD463A8808BA93ULL,
			0xA01630184EDB29A2ULL,
			0x16C59A7F1FD54D52ULL
		}
	};
	printf("Test Case 8\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC8611017A65274A8ULL,
			0x7175AB4C15D15882ULL,
			0x49669F92924CCFABULL,
			0x608B5F58FBB732BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7B4A30A2045B5028ULL,
			0xF9B4BA8EBB6472EFULL,
			0xB2ED0169A5C0787AULL,
			0x5C97AA017E24652CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5349955FC24B887DULL,
			0x4474E87A7E499C61ULL,
			0xF786A30DF9E18573ULL,
			0x73C661F7E275E323ULL
		}
	};
	printf("Test Case 9\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA013EBA3903B1280ULL,
			0xF392F59A7A1E71DAULL,
			0xB22FC5C4B31E821CULL,
			0x624E7CCC74F2F05BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x969BE904047A7278ULL,
			0x59E4B67A57B924B3ULL,
			0x7801C48D78FD08E6ULL,
			0x4EFBB665ECEA6B60ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA8B86C3CE1CD1560ULL,
			0x49DC6C4965B467E8ULL,
			0xFA6192B99F712B01ULL,
			0x4B01DAC2400CF9A8ULL
		}
	};
	printf("Test Case 10\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x271D03B999E83110ULL,
			0xE7A8471BC7245B11ULL,
			0xE64984D27F5E1576ULL,
			0x6279F93AE2E5D007ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFABF8E23088A15D0ULL,
			0x8EF1F773825E1ABFULL,
			0xFD082DDB4871BE82ULL,
			0x6985AF09258FE708ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47C795CF6665ED3EULL,
			0x6AF3E670BDC96236ULL,
			0x6885DD7F73FE0DB6ULL,
			0x2A4FC9D78A76043BULL
		}
	};
	printf("Test Case 11\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF7777BCBF5E6D5B0ULL,
			0x3ADD99F41E54E353ULL,
			0xC70D6C334A1BD83FULL,
			0x44469DC10B91CD90ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x638E131E23F40788ULL,
			0x689132AD62F29B37ULL,
			0xEB1ED7B134C1EFB4ULL,
			0x7E35AFD943E693D6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3BCB9704DBDE775FULL,
			0xF38BA83780A0A59EULL,
			0x2F1B171FE41217D3ULL,
			0x034B9EF1F2831053ULL
		}
	};
	printf("Test Case 12\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x685BC79112311730ULL,
			0xB5073CD55B2DD16CULL,
			0x938BE283A35594C0ULL,
			0x5FA858B3B2429B4BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1907887625FA42D8ULL,
			0x79738CCBE657EBDAULL,
			0x473EBA1CDFDA0D32ULL,
			0x5E38D8B9ACC72A9BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E9488B6D24A095EULL,
			0x5207BCFA14C0D265ULL,
			0xA2D60B814F03F2BCULL,
			0x47F515E8B40D98CDULL
		}
	};
	printf("Test Case 13\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1990B59D06695610ULL,
			0xBD632AB5F314CE32ULL,
			0x5E9691DA41D01843ULL,
			0x7AE93CF95C501D33ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x338C9AD15BFBC6D8ULL,
			0x62AD2B4B43543CA7ULL,
			0x77F9EB757D842E57ULL,
			0x4003857E8A487DF3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9EAAEAEFD79A702FULL,
			0x2855576105C719F4ULL,
			0xA835C9A7506866FBULL,
			0x526F9CD6AC004078ULL
		}
	};
	printf("Test Case 14\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD87C0BE3F1705DB8ULL,
			0x791F14EE4338304FULL,
			0x9FB096F388A72DE5ULL,
			0x53D7A83324362103ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6CDC786A33CE7898ULL,
			0x78A2A0865C6E5410ULL,
			0x424F9E801CA1BCEFULL,
			0x4AEEC146A87996B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEDC034C60136F91BULL,
			0xABDA211E46E661FAULL,
			0x7FE8FA07809D833EULL,
			0x250FC5C50461E209ULL
		}
	};
	printf("Test Case 15\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCE793224643150C8ULL,
			0x38436E8AB1F1DE93ULL,
			0xEE1A6197CA6B36EEULL,
			0x75F8F642686FB682ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA78075E24561AA58ULL,
			0xEED5FEB44EC4EDEBULL,
			0x9D74D5218EEE2596ULL,
			0x503CFED1F8A324DCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x088C6C2C132F60E9ULL,
			0x9A86BE1EF153DC7EULL,
			0x67BB5099D0B6E636ULL,
			0x0B9708057F7BF521ULL
		}
	};
	printf("Test Case 16\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5D7FE16396D1D9B8ULL,
			0xA0CC7B1173511F2FULL,
			0xF2BE67E493033AADULL,
			0x7A2B1F1EF0EE4D1FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3E99133A04F5F7E8ULL,
			0xFC1DEBF0CCB021AEULL,
			0xC2A868349AD4D2B6ULL,
			0x5E29A213C6E9DDCFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E22BA14174A9DBDULL,
			0x8288C6003E016376ULL,
			0x19CA057D5D034231ULL,
			0x2BD1967E504353A6ULL
		}
	};
	printf("Test Case 17\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x13F07A283D9ACBE8ULL,
			0xC105C49E667B99BDULL,
			0xB5472F5719F554A0ULL,
			0x4BC0A463C6AAA7EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x12471E231713E3B0ULL,
			0x4C6051AB5CF312B6ULL,
			0x46A9CF94C9BC056EULL,
			0x64D3C807CFEB3566ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x71DFD51E18E1308DULL,
			0xF3E998CC82547BD1ULL,
			0x1E9C2D64D1A5FEBFULL,
			0x332F579F69C2EFEFULL
		}
	};
	printf("Test Case 18\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCF09F2AA1AC235F0ULL,
			0x74B0D89971A6CD05ULL,
			0xDFFB147982A53661ULL,
			0x7D77C83972AF8F9FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC26FCAD5DFD9A8B8ULL,
			0xE4C831FBE0122FB2ULL,
			0x20E1B5FA31AFE248ULL,
			0x7EE9CBD6D890273CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDA019E4531CF2AC4ULL,
			0x27EBE747ED976E93ULL,
			0xD20EA7B1461B20CEULL,
			0x2B290E2DFFC8E44FULL
		}
	};
	printf("Test Case 19\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4D7A53B19B45C170ULL,
			0xEE68903CDEFDBF1DULL,
			0x15E398584BFA71E3ULL,
			0x7957C6807BFB8CF4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x99A0D63C1D6AD320ULL,
			0x8788BE237FA9737AULL,
			0xAC89487DE971A44BULL,
			0x597072D9D4CD97BBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE230C87C25B3381ULL,
			0x8859119AFDCE86F5ULL,
			0x2F054CC9607E74ABULL,
			0x54259717AE921AE3ULL
		}
	};
	printf("Test Case 20\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB07DBF825BDC6BD0ULL,
			0x938E31F8B3735939ULL,
			0x635B747B4E6D6DD8ULL,
			0x771D9766D256A3F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF9DEA8B38EC61DA0ULL,
			0x219C8957BF797932ULL,
			0xA11701918214CBF1ULL,
			0x564E6BE77EBA0C82ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB6B34143CCD1C031ULL,
			0xF7E01FEFAB456477ULL,
			0x7564953B01124BA6ULL,
			0x09E7D2C13401ADCCULL
		}
	};
	printf("Test Case 21\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2FCA6EB7A5EABC90ULL,
			0x77CC80C7FC31610AULL,
			0x9FB3E1AE5D9E38CCULL,
			0x462C01DCFA858EBBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2570BAD86DB44368ULL,
			0xA714853E3E5068C6ULL,
			0x9A2679CAC2FB6596ULL,
			0x61921BEE332373A4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAF5725C58A4F50EDULL,
			0xDC72193882BC48BBULL,
			0xA0BED0DF70F7C56EULL,
			0x4BDE1C9566D59867ULL
		}
	};
	printf("Test Case 22\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4321E4F26188F620ULL,
			0xC3F86178DC8581E2ULL,
			0xAF7FA7B13AF3934BULL,
			0x70A6B4838B261CF7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD96B0FE514361468ULL,
			0xF7620984B8D1F8CBULL,
			0x9A77154BE085708DULL,
			0x6167FA8FCB792000ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7088ECA55D0DA878ULL,
			0x2F8172BB72AD7F74ULL,
			0x0687485F1F19DDCAULL,
			0x453DA0D17EA9B58BULL
		}
	};
	printf("Test Case 23\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1D3A23F8C0C245C8ULL,
			0xE60711686E37DBA6ULL,
			0x2332A28C4C4F9C32ULL,
			0x529050095827CE24ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE127DC0BD6987A28ULL,
			0x63D062AD95680B77ULL,
			0x3C61E5EE5002C724ULL,
			0x7C72EB0CDD085CA7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x87300D0EA0A9FABDULL,
			0xCA1AB1B00AFB7EF4ULL,
			0x96C80C0683AB63ADULL,
			0x01CC5C6BA84CBD8DULL
		}
	};
	printf("Test Case 24\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3B84D9AE68DCCEB8ULL,
			0x0E1165E065C57A25ULL,
			0xCFF375DE690C0AC3ULL,
			0x6A8E8FC0AEEB5ED9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEDF405489B800210ULL,
			0x8AB775BB81426972ULL,
			0x0A53C1BF3A83AB36ULL,
			0x68E3E549219B2272ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9267BE1DA028DF4EULL,
			0x4AA9266E34FD33D8ULL,
			0x26ABF14151FF5341ULL,
			0x1BB0A399D2B959E4ULL
		}
	};
	printf("Test Case 25\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE6A19F68656B9920ULL,
			0x2F41790D027F584BULL,
			0x6617BA6872CE2A62ULL,
			0x73D7A6E62A294B37ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x857E27625F8FFE58ULL,
			0x1BA0073BA51D7292ULL,
			0xA6FD1FDC90725170ULL,
			0x722F19055CC1DE8CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x99E2EC427FDBEB90ULL,
			0xB278CC0B8247DE30ULL,
			0xA28CE3B9060AAEC0ULL,
			0x69E0D002D59BAC14ULL
		}
	};
	printf("Test Case 26\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x62A2DAB5E8D8A6C8ULL,
			0x300119ACDD0B3AD5ULL,
			0x33A31B7738FD1D2AULL,
			0x6A9208CDA84016ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC0D9C5408887F490ULL,
			0x8379CA88620384F5ULL,
			0xE8D3ECA537C428E4ULL,
			0x6E0F0BE52FA8D13DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD23E7072FFBEB9AULL,
			0x3318ACFEB1C97CF4ULL,
			0x62656DF93EA29B57ULL,
			0x18EC0F13642A706CULL
		}
	};
	printf("Test Case 27\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD2CC985E5B8A8B70ULL,
			0x925A166F3EA9B19BULL,
			0xEE9A691B01A7FB4AULL,
			0x4E6F9828CEE0E33AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0699003DBB1A0170ULL,
			0x928E005069CF10FEULL,
			0xC5DE2727F0805A7CULL,
			0x4BCE90919FBCCE50ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF1EB47AF5CBE161BULL,
			0x60D4D2880F9C7830ULL,
			0xA710E36AB30F0980ULL,
			0x46CBF48E6CEA6642ULL
		}
	};
	printf("Test Case 28\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x06A31DB3ECD81470ULL,
			0xF0B1B13834645F31ULL,
			0x3FA5B54CFBFF04A2ULL,
			0x53859CED4810BA55ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0555074B9AFD40B0ULL,
			0xD81B369E2403C726ULL,
			0xEA2417942162BF0EULL,
			0x77BC1A8A3F4C591EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F3DB4FE5F75C186ULL,
			0x69CAC4427D1D1E27ULL,
			0x523831E8E0F0BCB6ULL,
			0x2A134FA103D69B2EULL
		}
	};
	printf("Test Case 29\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1A5A2FCDAE247EB8ULL,
			0x01F87656CD81B381ULL,
			0x9A3F7C4F60C3DF16ULL,
			0x55E2F99DBE340719ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x33377AACF86D8BE8ULL,
			0x62E09F3B42A005AFULL,
			0xDBD43A303397B03DULL,
			0x411F20C1E4880291ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD7BA2787B61B1EDFULL,
			0x8027BDB66B4813CFULL,
			0x1B1ACFB3EAF3BE01ULL,
			0x0783B0AD1F26FF9BULL
		}
	};
	printf("Test Case 30\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7F3A77379CAB6710ULL,
			0x034C92880FDC9DA8ULL,
			0x0587111E0CD3D8C4ULL,
			0x43A681F626C46FC0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFC93E665816CC7E8ULL,
			0x63B524371AED8467ULL,
			0xA3324B1B4E5D21E5ULL,
			0x623E434F3CA7B3DBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x42C0255573697EA0ULL,
			0x18641610EDCDE6EDULL,
			0x2C72056A81DDB50AULL,
			0x32D7A8F1465513DAULL
		}
	};
	printf("Test Case 31\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAD585CC79D856890ULL,
			0x36909B5ADE7F21DBULL,
			0xD3C51FF520A58AB4ULL,
			0x5DCDCE77E0FDAC57ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x848486479F643720ULL,
			0x421F383CC5806FEEULL,
			0xBF0CE0BA32DA0AB7ULL,
			0x5214AB0114376138ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD3947525922A6C60ULL,
			0xDCD6006AAE510201ULL,
			0xA54D11169EADFE06ULL,
			0x14FA58889CA0A29AULL
		}
	};
	printf("Test Case 32\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x710E564D099F0BF0ULL,
			0xF867D1902F9A79EEULL,
			0x3535708DA9E0A04FULL,
			0x4A9CE12850A7DF9BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2224D7F94A0DFBA0ULL,
			0x911E2C967B279329ULL,
			0x080F7163D82BC105ULL,
			0x58EE3195BEE43A6AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAC1FA24E76042D72ULL,
			0x69BB65DD5E5333E2ULL,
			0x88C9C1BC9ACF6FA1ULL,
			0x5C4C31C6DB31D903ULL
		}
	};
	printf("Test Case 33\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x14FE20395DD3B120ULL,
			0xAD8A7055F858AAFAULL,
			0xF78AD3D1CCFDBC65ULL,
			0x5657061FE49FD4C5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6D2DD84EBA5F5F68ULL,
			0xF4E4E8588EDE3280ULL,
			0x92C6FEDC7E9A97AAULL,
			0x7E1D371AE8ADCFC9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1CCBC2A7B3323C4EULL,
			0x252EA6F927CDFA67ULL,
			0x7BEA3685B8103D25ULL,
			0x798D9DEFC6079F22ULL
		}
	};
	printf("Test Case 34\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x17FC2944C4359020ULL,
			0xDD784EEBF920447CULL,
			0x0CFA85F779631203ULL,
			0x6B2898487E38856FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA35FB3453AB89CD0ULL,
			0xAB54EF440A8D5412ULL,
			0xC67CEB9B2DE4FFE4ULL,
			0x762D56EF3974E206ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0FAA237BD913001FULL,
			0xC630DE47010FDF13ULL,
			0xFCFF0C022B629BA5ULL,
			0x43A664D38FFB06ABULL
		}
	};
	printf("Test Case 35\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF9DEDB0B2ED2B550ULL,
			0xA3DD65798DAA2C14ULL,
			0x761C3F5BA4C41FD7ULL,
			0x4C7B46BFDA804DD2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBDA8AD787FD3F268ULL,
			0x486CA5DCD98C16C1ULL,
			0x5947181AA4DC34ADULL,
			0x5A9C18665D036D56ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF42DD0FE3CAA0E83ULL,
			0xCB705888A84ECE23ULL,
			0xEFFDE1A1F082243FULL,
			0x10E323BAF4A95C35ULL
		}
	};
	printf("Test Case 36\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB437E2F4DB3F1010ULL,
			0xDCFF0BF48BA336EEULL,
			0x3AC7DEA4626E174AULL,
			0x5AFF8A65CC03AD14ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA96C70F41A747560ULL,
			0x05EE6B0ACD5C5252ULL,
			0x12401C701C94224CULL,
			0x6B8729AF47AE4CCBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0B3954C8F2273466ULL,
			0x3A4B3A91B1F4F93CULL,
			0x66B7A13D99CB59EFULL,
			0x7214DFF3DCD7607EULL
		}
	};
	printf("Test Case 37\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x70270525EC42C0D8ULL,
			0xCB3C29B1CFBE988FULL,
			0x60E8AB737A835F17ULL,
			0x504C2EC4BA6D3D41ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC1A2E63D8BFECB38ULL,
			0x2C436A7C2BF088E7ULL,
			0xE19C789E5E4A9A55ULL,
			0x7D5E3070FA6964C6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x35273EA7241ED821ULL,
			0x9947117F21785072ULL,
			0xC90EAF2D26F13B97ULL,
			0x6651FA042994FA98ULL
		}
	};
	printf("Test Case 38\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF1855007CBF2B610ULL,
			0x6AB51A6E758F39E8ULL,
			0x4A4D7BA4BD307374ULL,
			0x77280EA4F056C577ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x05CC9506928D5210ULL,
			0x722A3E4601677F20ULL,
			0x29D77FFC7C116A89ULL,
			0x74B55A8C71AD22C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE61CA26B4E036115ULL,
			0xCACA2CE85CBA8C14ULL,
			0xD6FE3EFED338059DULL,
			0x2A57B5703B1F1ECAULL
		}
	};
	printf("Test Case 39\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0E552D2F7FDF1108ULL,
			0x47F36E436267B9B0ULL,
			0x6BAA75F122AC7174ULL,
			0x40BE9587AF5257C4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2B93885BAD69C808ULL,
			0x2FA702F66231DF1BULL,
			0xBC5A074C91371783ULL,
			0x490557CCF1C8B24BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAF42FD34424738FEULL,
			0xAF4BAF86657E1968ULL,
			0xEAC9EC4ACE5D4ED4ULL,
			0x7FE3F3B31628BDF0ULL
		}
	};
	printf("Test Case 40\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x60601E0626BB58C8ULL,
			0x4D8DC7606A27DF15ULL,
			0xF2D4BA90BA653D80ULL,
			0x6B718AEB35A50AF1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B9DEC02E4B69DC8ULL,
			0x2F87AD2E5ED0CC6DULL,
			0x6594CFDF2FB3F5B7ULL,
			0x7B40B745B0990A02ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD5E5699A93EE734ULL,
			0xAF469A89D34D4756ULL,
			0x694303018B5B7B55ULL,
			0x1FC897A7C331856BULL
		}
	};
	printf("Test Case 41\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAA89888FC51B31A8ULL,
			0x53E5EF5F0A2840A6ULL,
			0x3FF8C244FA040E25ULL,
			0x5B4F7858083827CDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3444D03899C6760ULL,
			0x2A77A455F6C751CAULL,
			0xF74D143B2B31DC87ULL,
			0x7B621E0E83C12C6CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x661824CB01977C5BULL,
			0x5857F83847720442ULL,
			0x180F2101854BB4DAULL,
			0x635504C5A6184719ULL
		}
	};
	printf("Test Case 42\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x86BEB6B0DA0399F0ULL,
			0x90939107E323EABEULL,
			0xE73933203E88EE16ULL,
			0x63F5F4ABE760E877ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x212A323C2AF528E0ULL,
			0xFF0867FC086AD692ULL,
			0x77A625D9ED180495ULL,
			0x4F7370E3D6A2E5FBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCDD5AC8A8EDDA7A7ULL,
			0x4005966CDCC9F989ULL,
			0xDA2CB5B3A53BA749ULL,
			0x46DD820D8306459CULL
		}
	};
	printf("Test Case 43\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2382B8334CF8C778ULL,
			0xC0FE53449DE61B9BULL,
			0xCCC2A501F57AC165ULL,
			0x48A44B1EA4AFF199ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA4A170C81D15D810ULL,
			0xDDBB04D80E37F72BULL,
			0xA3639B4955181C51ULL,
			0x7DE49A75AEA3BACDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD649B0AB2ABA4A33ULL,
			0x0E7EBC9608B77715ULL,
			0x21D3A954B520B793ULL,
			0x2BB87D22B9FC9DFAULL
		}
	};
	printf("Test Case 44\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x76E2A5B3B3EA3098ULL,
			0x67FC8AA12726D660ULL,
			0x124043DD6F065DFDULL,
			0x5DF91795EC3A6974ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x243B7C055BAC2458ULL,
			0xEA011458958E459CULL,
			0x4B35380B20FF4B34ULL,
			0x6B3DF9C765D02B04ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFB73C3458A931C7AULL,
			0x1C3BDBC567C628C1ULL,
			0x2FA3345F955C7AB8ULL,
			0x1243858697351C1AULL
		}
	};
	printf("Test Case 45\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xED8E6742A1CD92A0ULL,
			0x57B13C0139C50608ULL,
			0x98C8FA07DA8E2BE3ULL,
			0x7ABB4D4660F3467EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x50292082C2450BF8ULL,
			0x6E5A336F8797A146ULL,
			0xE7469FC422AAFE23ULL,
			0x4F8CCBD0AD5954E2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFAD4E2EA9F6D88EDULL,
			0xA1783C32768000CFULL,
			0x84580AB9DB5448B0ULL,
			0x25AACB6EDD0A8BE8ULL
		}
	};
	printf("Test Case 46\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x42BEB1AF96A9CAD0ULL,
			0x67E4BC52B644A2AEULL,
			0x306AA86432940F7FULL,
			0x6D0BA11B07F6E5CEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9B36EE4C1771A3C0ULL,
			0x0310482B223191D0ULL,
			0xC31B59B19C5D6BB7ULL,
			0x64CF9028EAE56555ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE6F943B33A415E55ULL,
			0xD1B64EFF9D596B61ULL,
			0xDE6D1BD76423CC82ULL,
			0x2E99F42D13E43FF8ULL
		}
	};
	printf("Test Case 47\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x378CD07E69DFF608ULL,
			0x47438B7295401E93ULL,
			0x59163CDC35815638ULL,
			0x607C3C79CFF852E8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE97C6BACBF806EA0ULL,
			0xD7637FA6770AFC43ULL,
			0x03AE14797351E0CCULL,
			0x7FEBFEAAAC8AF442ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAB84BDF20428623AULL,
			0x46F6ECB14F57BC97ULL,
			0x56383B5334C72991ULL,
			0x2502ADEBC1D45BCEULL
		}
	};
	printf("Test Case 48\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x545004CEEEB72C88ULL,
			0x7E9121A8FCDF899FULL,
			0xDCF34ABB4FC98F39ULL,
			0x760C7E8C3BA8415EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8E2FF6D5DB1A9208ULL,
			0xC24C163FBB8357DEULL,
			0x8C3B4B70FA0A02DDULL,
			0x46474035DB4B6B62ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37C521C6ABD2CEF4ULL,
			0x35CA71B8EC5373B4ULL,
			0xE8DD91B24A1837E6ULL,
			0x3351E128F875BC12ULL
		}
	};
	printf("Test Case 49\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD1ABCBAE5B207010ULL,
			0x7D2A8AF54D7CF3FCULL,
			0xBB1024291871802FULL,
			0x784BA541701466BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6B333AAF607AA658ULL,
			0xA6C94A9ED79ABC2AULL,
			0x2CD98B1B50B0A79FULL,
			0x4BE51B73A0E71A09ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x17E9458D03224BCBULL,
			0x7DC576A1AAF0B374ULL,
			0xC7A6C44752F59F84ULL,
			0x0A99599D7A349F9EULL
		}
	};
	printf("Test Case 50\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDC05DD740D495A78ULL,
			0x94D55D6324D38467ULL,
			0xABC6E34BEB8E5801ULL,
			0x72C33669FAD9B5DBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7904BCD5F6455848ULL,
			0x00AF1A0CD617C5DFULL,
			0xC6EC537C4F9F8772ULL,
			0x4739B6B6AD6177ACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEBA62037EA086B5EULL,
			0xC69DBF12508B7A5CULL,
			0xC256DAB37839280EULL,
			0x43663DD07EAD5562ULL
		}
	};
	printf("Test Case 51\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x93118BDE567337B0ULL,
			0xC1354F9225C225F8ULL,
			0x95F1AAA7A6A07D96ULL,
			0x73F554A47FEBD705ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE9599C42D3A3EF40ULL,
			0x740D32AAB955B453ULL,
			0xC39E8FA9E6C74026ULL,
			0x690EDFD9B16720FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x99AEDE9FB547683CULL,
			0xB7CC4617771E8A2BULL,
			0xDA532671C4AC92EAULL,
			0x43A6F5081015C3D7ULL
		}
	};
	printf("Test Case 52\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD8AD1FC076B94C90ULL,
			0xEF89F5AC67AD04CFULL,
			0x93C5A272FFB807E6ULL,
			0x4571D12C99F9811EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBC059B128607DB20ULL,
			0x7DF249E89B3EFF4FULL,
			0xD4FAABE9C33FB6F0ULL,
			0x46E53C72FA247DE3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA826E8F8BBBF879CULL,
			0xA93E4C6347E65F29ULL,
			0xE0254C7D286B6F75ULL,
			0x1F9EF3BA2CFBE3BFULL
		}
	};
	printf("Test Case 53\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x59B75B426C875DD8ULL,
			0xDF0B3F1798C1C672ULL,
			0xF7F7694F4B4D76EFULL,
			0x5E9A3FC367FA9EDBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0DABDE5DA1A17DD8ULL,
			0xC9E8681FACAA16F7ULL,
			0xC0BD2414A04C8CDCULL,
			0x70F20CCF91561F03ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x46AB2C59C7940D40ULL,
			0x06069A2E3C7B0110ULL,
			0x6264A32F1713C48FULL,
			0x77EC6303ACEEE3B0ULL
		}
	};
	printf("Test Case 54\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA0BAF1E5BDBDEE80ULL,
			0x8CDA0AADA8BB290FULL,
			0x6AA28D0E2F0CF786ULL,
			0x50BC89C6572E8252ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFCC52D511637A958ULL,
			0xC7F56D9B477675E0ULL,
			0x2CEE12F125F1C5D1ULL,
			0x74905E980E11433FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x68CE1386EB293BC2ULL,
			0xB232158CF41D7259ULL,
			0xC26746C4843CB501ULL,
			0x4C1CB9F48415198DULL
		}
	};
	printf("Test Case 55\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2BC6D5597269D938ULL,
			0x10A7DDF3B00DFAE3ULL,
			0xC0BDBD4E1E459AF9ULL,
			0x7415290FF8D179E2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC8CCA0DCA68EF690ULL,
			0x94D05CFD16FB7AE6ULL,
			0x5F3C5AA63357B239ULL,
			0x6B40FEE6F0CB57F0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E50071A2ED2F0C4ULL,
			0x383EA99A71D3F9CAULL,
			0x1FD66ED48CA273C4ULL,
			0x3D1F5F1C3FDA9C3DULL
		}
	};
	printf("Test Case 56\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEE79ECE90BFE0EC8ULL,
			0xD0D03EB4E8AC33F6ULL,
			0x7DE28D6804CB260DULL,
			0x6607298FC4E376CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x444342D69A23D430ULL,
			0xE488E345EEAE990FULL,
			0xBDC56CF20381434DULL,
			0x76E43E81FDADF56BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x695251A5AF856629ULL,
			0xFF55611083E5AB43ULL,
			0x8E82F7813D00400AULL,
			0x76170365A7BABA91ULL
		}
	};
	printf("Test Case 57\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x52CE1C6F994233F0ULL,
			0xDF30CF2FA79121F0ULL,
			0xDF832BD50C7557A0ULL,
			0x4C046C8D91D8AFF3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCBF3A7F56A0F2B28ULL,
			0x27F8FB3303E7E679ULL,
			0xE737AA2EA04C8B8FULL,
			0x577A018F0BE529F4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA48F75246F41045EULL,
			0x5AEBEF2C8CABD74FULL,
			0x62747668B5CCEC28ULL,
			0x32CB11F803A46463ULL
		}
	};
	printf("Test Case 58\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x345C15E317F07D90ULL,
			0x1A7F47C25BFFFB91ULL,
			0xBC770E7298A366FAULL,
			0x7EE26A1A22BBCC0EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFEEC8BC93355DD08ULL,
			0xDACDA8F830003B85ULL,
			0xFBF5287D5E0AEBD5ULL,
			0x5A982C98456D8919ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x178F20B1BAADD73DULL,
			0x4AEFEFF54F2D5BC3ULL,
			0x3CDC7BA26106653FULL,
			0x3AE5E42F4FF3ADAAULL
		}
	};
	printf("Test Case 59\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x572D04264D105E50ULL,
			0x9F979B118BDC30B4ULL,
			0x31DC23D636F64E04ULL,
			0x6F804B0BEE441804ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x53BA4B2EFD6F66C8ULL,
			0x05383004C4D62C53ULL,
			0xCF7B704CF61C1B00ULL,
			0x6EB36CA0455D4E49ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x36593669762EE427ULL,
			0xB3A6DC830024DA1CULL,
			0x68E529405883524AULL,
			0x277CAA9766C1EA95ULL
		}
	};
	printf("Test Case 60\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x77FFB2CC15157CE8ULL,
			0xA22A8D88B5B45412ULL,
			0x9AC5A730C91D5768ULL,
			0x466C33B2B6F3FE0BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x956441BBA7E6A0E0ULL,
			0x9CE86F6A5AC4246FULL,
			0xE189AE2739BC7AFDULL,
			0x4EAE3B29424735AFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F8B95EE90B26A81ULL,
			0xBEA1CA2DC9096022ULL,
			0x18AC7D2A8E014988ULL,
			0x3F26A49F3D7DF506ULL
		}
	};
	printf("Test Case 61\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x715ED0C382DCC028ULL,
			0x5D10F86742516E69ULL,
			0xAEDE160D8DDB1FB2ULL,
			0x4DD97BF958CE6C1FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB84A4D30B59F41C0ULL,
			0x8A03FE6DCE92C955ULL,
			0x66185FBDF0DE7A68ULL,
			0x5DFB463C8F4A751CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x798C55ABD916D812ULL,
			0xAC290EE2C1AF6166ULL,
			0x4292D9E928DEF9AFULL,
			0x771973F15AD078F6ULL
		}
	};
	printf("Test Case 62\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x82C2CCF8264F7730ULL,
			0x4AC3735E862F9762ULL,
			0x0A418406D47CFD8CULL,
			0x4EF0C052342486CEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x489C536BBFCF7660ULL,
			0x540E84529CAA3232ULL,
			0x6126D5AFA13B9546ULL,
			0x698D8DC68DE039E0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE5200B9173B061C8ULL,
			0x96A0F710C8D06E47ULL,
			0x42AECBEF64261517ULL,
			0x741DEE36112F6453ULL
		}
	};
	printf("Test Case 63\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7781E1EA2165B868ULL,
			0x7D48FA292043EA5FULL,
			0x177F9597462F807CULL,
			0x5FDB90757285F2CEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC8D9587BACA8B630ULL,
			0xCEDB4D1C4531922EULL,
			0x777422E46A9044BDULL,
			0x7D0039519901A4E2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x25F664A6C00B36D9ULL,
			0xF1707808DA9F1DBBULL,
			0x71562E333CD43398ULL,
			0x22BAE97062499D2FULL
		}
	};
	printf("Test Case 64\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x31D058290133AF38ULL,
			0x931BBD2C487953F4ULL,
			0x29D7F03773FCA353ULL,
			0x69AAEEF940AEB82BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4902EF426ED7E638ULL,
			0x55067ACB19FF85BBULL,
			0x4AF484033C19F4EDULL,
			0x528706B0D25915BBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0767E5B19F503B77ULL,
			0x7298EC46017E8062ULL,
			0x8E0F3732534B1532ULL,
			0x339B71DDB85BB128ULL
		}
	};
	printf("Test Case 65\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x811A54D5D17C38E8ULL,
			0x24C8564E2F298B1AULL,
			0x6EE6FC487C1B014AULL,
			0x740C40C88D6D34B4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC84555FB54A93780ULL,
			0xBDD961CBE616D52AULL,
			0xD55F3EFC8084E186ULL,
			0x714EE291E236B56AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x10F6F57EA272DBB4ULL,
			0x8575B43B7E8526F4ULL,
			0x55F33C62E891FDFBULL,
			0x42D16E01943CDBACULL
		}
	};
	printf("Test Case 66\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5CDC6C7FF691C118ULL,
			0x32CA6A4C83AC6DB1ULL,
			0xAD482E80BD704247ULL,
			0x6065A8B16F1D6EE1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA914B09816C455A0ULL,
			0xCAD196E8DBC38E92ULL,
			0xE4EE17569AD323F4ULL,
			0x769EAC0DC8BBE5C1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xADEF0AA6312ED1F6ULL,
			0x791FBE4C845389BAULL,
			0x5ABABB5E31D9824EULL,
			0x121686FCB9CD2A1EULL
		}
	};
	printf("Test Case 67\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCE883792D8FE9D28ULL,
			0xB5FAB17C9738CEDFULL,
			0x6BAC686412318938ULL,
			0x6DDEBC43A6FF50E3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5AB810400C0CD170ULL,
			0xBF0FD4945DD88695ULL,
			0xA2EF781961E3C0DFULL,
			0x7909557A2AC983A6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x06F181D9093EF4D3ULL,
			0x4873F0301DEBF069ULL,
			0x7E3351AA0422F672ULL,
			0x2D7EB389607BA460ULL
		}
	};
	printf("Test Case 68\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF1CC1AB9A6EE79B8ULL,
			0x26F8C7F644297BE5ULL,
			0x9D3629532DC7DA73ULL,
			0x4D34086F46BB1ABBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA2BC22967F07D680ULL,
			0x512165BC1C9BF487ULL,
			0x75F395F1128ED376ULL,
			0x4D04D57D056E50B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85CB422E1D3B6CB5ULL,
			0x109D1D42618C69D6ULL,
			0x407D8D02FB0EEFEDULL,
			0x61F9DF0C6B662D44ULL
		}
	};
	printf("Test Case 69\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x03AD76D7901E3158ULL,
			0x9E8B3EEE43287C8CULL,
			0x91675B0E14CDE453ULL,
			0x75FAFD5621EAADBBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7100776E8A6EB440ULL,
			0x48AD5B8B85EA4B02ULL,
			0x3611DAE408391EEBULL,
			0x5640581210AE1C13ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8F6991C8AD3D4F44ULL,
			0x3A6B327033A75F76ULL,
			0xD36767403A87701FULL,
			0x2FC477FAB08AFB96ULL
		}
	};
	printf("Test Case 70\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD66F404A8F74DAB0ULL,
			0x1286FCDC7910D6ACULL,
			0xB8817E07DEA94863ULL,
			0x75638D3E11339EFDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0ED864071EB79B18ULL,
			0xAEDAF1A1D6036E00ULL,
			0xF8DD444CA9BC4440ULL,
			0x4FD39BD8596D3CF4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x40C3EA71C3E73652ULL,
			0x265DFAC2A6ADE141ULL,
			0x4D64A618FBF034DAULL,
			0x77AA06734FB4664EULL
		}
	};
	printf("Test Case 71\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD308BDCAD9DC52D8ULL,
			0x1A4A7DF1656485A9ULL,
			0xFED361DE31C660B2ULL,
			0x71768B65F795485AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8F50148EB507C628ULL,
			0x135F51731B13B47EULL,
			0xFE8470C60025C375ULL,
			0x747800C3AEC6C1C4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB022093833ADE6E1ULL,
			0xE16620ACC176AB36ULL,
			0xADFF6645012F08AAULL,
			0x03620E223C0CC828ULL
		}
	};
	printf("Test Case 72\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1CD632ED6A00BD88ULL,
			0x5627AA8D5C5D381AULL,
			0x59BF0290A80619F0ULL,
			0x569A5D5BE3231503ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F627BFD49F56C30ULL,
			0x35A9815AC462882DULL,
			0x51EFAF73816B0366ULL,
			0x4B29DCFF12FB9B46ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9EEC4183F26AEDD9ULL,
			0x31EAC6C09D8D1051ULL,
			0x05284F178F8ED655ULL,
			0x1696A0AC05890AB9ULL
		}
	};
	printf("Test Case 73\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3D56A0649CE2E8A0ULL,
			0xA6D06AB5236FB3DAULL,
			0x4F4395AD218AB10AULL,
			0x4642FA6E72B80EADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD79320B00AD2D230ULL,
			0xC09B7C4F2326FADAULL,
			0xF7A5113F1E7C86D8ULL,
			0x71924007EE904C0FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE84F42BB7B83C772ULL,
			0xFBD990F5019C89CEULL,
			0x7A7DA4C60B8184AEULL,
			0x5EC5939237D90C8BULL
		}
	};
	printf("Test Case 74\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE00FA2AAD6717A20ULL,
			0x7FD1F2B7E01F1A81ULL,
			0x15B8122034B39DDDULL,
			0x6BB442D048DE94B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCDE29EFDCC020508ULL,
			0xD7E57062D070DC8AULL,
			0xE6CD4C36009B15A9ULL,
			0x421DF5909E41B84DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDCC5C94997FA14FBULL,
			0xC3BD9A54C2BA995CULL,
			0x82F4D9D3306432EFULL,
			0x2430E00D9652FF3CULL
		}
	};
	printf("Test Case 75\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDB32550FD3AFE578ULL,
			0x6F58551A5016D0E1ULL,
			0x5032A5540B768BAAULL,
			0x5C8536818AFF9B67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD57931BCBAFC2D48ULL,
			0xC83CE560A46893C8ULL,
			0x67BB8D79900EE023ULL,
			0x4138547C2D8AAA1FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x933C58F3D710ED0BULL,
			0x132C2C232434CB71ULL,
			0x78AE76C731222A63ULL,
			0x37BB3CED53537C06ULL
		}
	};
	printf("Test Case 76\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7825F782C44561E8ULL,
			0x3235A525C665D7FAULL,
			0x7CB77DDF90B04794ULL,
			0x5C1D39CD2D18857BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEFB3C57F73171818ULL,
			0xA03F524638FC4254ULL,
			0xDB561407E2D5E945ULL,
			0x72B9BF631FD5C8E6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE6F19786E1C72680ULL,
			0x9893ABE226D953D1ULL,
			0x9B6414B62726453DULL,
			0x421544AF166B445EULL
		}
	};
	printf("Test Case 77\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x004195A19AAAA460ULL,
			0x6655CEC90CC6DC09ULL,
			0xACD7AC147012D0F5ULL,
			0x5898A8B7534E0312ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x29B03B39739D0D68ULL,
			0x6D30D75B3D1649A5ULL,
			0x4BD4E87CF803FF6CULL,
			0x7B4D9F60D9EF61B2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x94698488CC919EC6ULL,
			0x78DF239FEC5121BBULL,
			0xEB36B7BCD052F0A2ULL,
			0x4DC28540C4E408BCULL
		}
	};
	printf("Test Case 78\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFA6BFEA8A98F0E98ULL,
			0xC1291D932262DA93ULL,
			0x0578F7A3EDBF0813ULL,
			0x43CC93A88D50E006ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9B9A0E37AC0D0230ULL,
			0xEAC5CBE944E29733ULL,
			0x18B5766079756905ULL,
			0x61DCAB2FEC655C8DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x97AF9D7A19CB187FULL,
			0xBC45142EF3928DC3ULL,
			0x9AA5189D1493EC5AULL,
			0x369964C6AA5EE560ULL
		}
	};
	printf("Test Case 79\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5987C3F4E11A8290ULL,
			0xA12B9DFCA4786A2CULL,
			0x049B8E313D580773ULL,
			0x5669E7C93847F097ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8149312010DDEAB8ULL,
			0xBA78E8F7EA493700ULL,
			0x7D62F7AC0944CD91ULL,
			0x4356F55F96215C89ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA2080A46D74BB84CULL,
			0xB6284915D019ED06ULL,
			0xAA453C9C93E9B4F2ULL,
			0x164C50068601F486ULL
		}
	};
	printf("Test Case 80\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x14C2474DD9A49E38ULL,
			0x0EAA7E6AA8EE8C12ULL,
			0x68210E9B57BAA718ULL,
			0x73807A74D02AF303ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E48BA87D2BDFD18ULL,
			0xC3A46C8F629EC86BULL,
			0xCEAFFAF7D5BB9794ULL,
			0x660BC71CB7AF8F34ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA303EA13BDC6C169ULL,
			0x2B0638214D2A5559ULL,
			0x5CF390259F266974ULL,
			0x0BA34F058A26321DULL
		}
	};
	printf("Test Case 81\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF762D642C8705E28ULL,
			0x91DF2E31C8691C0EULL,
			0x14601170DBF9710FULL,
			0x426447F172678691ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2FB93FD3B63DBE58ULL,
			0xA6AC53B04D9249D3ULL,
			0x908057C00245FE0FULL,
			0x7062C85726EE6CFBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8B6D9F9845342485ULL,
			0xFFE5FEBE3D686FCAULL,
			0xA80B3FCC5F496F5EULL,
			0x25863AD230DD15FEULL
		}
	};
	printf("Test Case 82\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0FF063B7B43ED038ULL,
			0x1F6DE09F61A1D209ULL,
			0x689ED7057DAA0C58ULL,
			0x45687E1BF43E21CFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x585BD178E8547E08ULL,
			0x91CB7051E95E572BULL,
			0xFCE4E94EC2034596ULL,
			0x53017C98ED319110ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB06F32E6400F5CCCULL,
			0x598C4C4865BC2459ULL,
			0x2BDF098BCE1034FFULL,
			0x6677183496E46812ULL
		}
	};
	printf("Test Case 83\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC8BD4C84E6BE6FE0ULL,
			0x7B84440496301DFEULL,
			0xAF5E6A4955C8DED6ULL,
			0x515E27F444DB764DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x59C3C36695DEA5F0ULL,
			0x8B4D3887A8F2FF15ULL,
			0x735A1AD675B39C02ULL,
			0x4562CF24A47CC4BAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2D4108F84D58C0A0ULL,
			0x5647A793FB895690ULL,
			0x4C1FDE44915B4F3BULL,
			0x2916F7DA80493C7BULL
		}
	};
	printf("Test Case 84\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8FD2493D44B91FF0ULL,
			0xF17E9148D7ABF793ULL,
			0x2600E163B6CE06DBULL,
			0x6C83CCF3D534EA14ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E7ADB6E57C10818ULL,
			0xA7E68A03EB5CA770ULL,
			0xEEBD1AB744BBA775ULL,
			0x6149B681D303F14DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6F42DA2F5D98D4A3ULL,
			0xA92658B756DB5455ULL,
			0x75A1DACB68284828ULL,
			0x6E660D3C4DC2E2A2ULL
		}
	};
	printf("Test Case 85\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCF798836B5D46648ULL,
			0x7F43BEFC415B1DE1ULL,
			0xF8087AE3388CAE59ULL,
			0x4D2BB2B3986723FAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBED817FAAE3ED408ULL,
			0x9F06D880A043FF56ULL,
			0xC6F47F03E32D591CULL,
			0x5DCAC9A5DD621ECFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x82BF2144D4CF19BEULL,
			0xC1BA7DB535E18FC8ULL,
			0xD16161852BF0D99EULL,
			0x2227A4685C6BE7F4ULL
		}
	};
	printf("Test Case 86\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6136ED3B5E752928ULL,
			0xA020BDE2BF148492ULL,
			0x4F071EF28E5E5C04ULL,
			0x4B640A794F934161ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3C9C19D9E86A45B8ULL,
			0xD2A88E3AF24C3A6DULL,
			0xBC442F20ADF31CD2ULL,
			0x7A8600DF6EFC86C8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xADE97CC92D7F75C6ULL,
			0xE18BC81D8D441CECULL,
			0x86197B511CDD5CF7ULL,
			0x7AD0B07A473A583EULL
		}
	};
	printf("Test Case 87\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x413788D2527B3AC8ULL,
			0xD3E16E1A67B9FC0DULL,
			0x742E5F2492A0C6B4ULL,
			0x6160C8FD10954694ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAC4EC16FA5248900ULL,
			0x2B081CAE9FE3C95BULL,
			0x635EEBC637EAAFAAULL,
			0x71863732B7FF4B6BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x966254AF3F6911D8ULL,
			0x0E25A6DD3DA55B27ULL,
			0x4C1C607FD5D3F31DULL,
			0x2BF696423CF44DF6ULL
		}
	};
	printf("Test Case 88\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1F108B0E024FC098ULL,
			0xFDB9D1F421E03E00ULL,
			0xCB5088A91C72E4E7ULL,
			0x6934F22474E3EF7BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x34F77BA4FE690250ULL,
			0x05C42C7AC3AA76CDULL,
			0xD64DBC8F75AC8484ULL,
			0x4B4B927A9AA66781ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7B2F2898591FD54CULL,
			0xCEE7C713D207B632ULL,
			0x4D88CFD1E49FC9C9ULL,
			0x2DDC78D47E58D03AULL
		}
	};
	printf("Test Case 89\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF1B937C540283268ULL,
			0x6903CA66D3DAA1C4ULL,
			0x144DE978DDEDC227ULL,
			0x664CA3DE5C15DEC3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC26FE71FDDE40728ULL,
			0x295FC8F5069038B0ULL,
			0x501299A22EA17510ULL,
			0x457AD6B504AFE8D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0FAF3F8EE99EAB76ULL,
			0x51EFDB795CB566C6ULL,
			0x9A0F046E92B39C1AULL,
			0x36007130F644C7ABULL
		}
	};
	printf("Test Case 90\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x02E0C0F2DA6FA6C8ULL,
			0x9320D7C2812E93D0ULL,
			0x05C6883A78049054ULL,
			0x50A2B3F2E346A70DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4CB6DE1CBF21B3A8ULL,
			0x1E91ED573B6C1375ULL,
			0xBF638A9909BC22B7ULL,
			0x6146F9204D971A2EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x407FBBBF419C2656ULL,
			0x8C0F6D9D437D0961ULL,
			0x0ADF12F9E7F14D3BULL,
			0x276CEFAAA17A48AFULL
		}
	};
	printf("Test Case 91\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x949A88718961BE58ULL,
			0xDBCEF9B3F8666339ULL,
			0x7037E6A274579C47ULL,
			0x571BDA5E8867CF55ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x81A3ADF8B29D4498ULL,
			0x0756456AC4CA3097ULL,
			0x0524236AC9D14401ULL,
			0x523ED4A1BC1EEDAFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA1296CDCA8CD15A0ULL,
			0xF692584B7365293CULL,
			0xE193F0FE1C93F9FBULL,
			0x72B8655C8D719198ULL
		}
	};
	printf("Test Case 92\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0DADF113542A8FC0ULL,
			0x6A17F964FFD4F57CULL,
			0x1925FA6775EA34EAULL,
			0x5FFFC7E83FC5EA03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x06A6B679FE8A39D0ULL,
			0x7DD86EE15FEBA1E9ULL,
			0xF179367EC832075FULL,
			0x5C724868A4249C72ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFF5B5B1E47F6DA3EULL,
			0xC142896A4A00793BULL,
			0xE723BA9D6F594E33ULL,
			0x180AAD8488D4F727ULL
		}
	};
	printf("Test Case 93\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x14C08B0CB3869990ULL,
			0x2EDA9E9EAF1CD47AULL,
			0x2EC411D01FF5FAD8ULL,
			0x7191DAEB73F8A635ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6283FE9DFA4C7EE0ULL,
			0x2CB7A0B6AF337D1EULL,
			0x14F261051B094A1BULL,
			0x4AA368A7967D9651ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x315C1C30D0B8B139ULL,
			0x6D67FD1C5692BAF9ULL,
			0xE7CF8CBAC9E2AF7FULL,
			0x671580FC378C252BULL
		}
	};
	printf("Test Case 94\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEEE2D3172A3798B8ULL,
			0x55A0D70B2696E1D9ULL,
			0xBFCFB7B58882B613ULL,
			0x4D6332D6120C6BF8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3CEE6EA0CE165080ULL,
			0xFC9BF57F376CA750ULL,
			0x54040315CD5616A2ULL,
			0x432FEA18FFC00F05ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2CAD500E15B4875AULL,
			0x9E59966B9AD4F4EDULL,
			0xA2E152C2180117A1ULL,
			0x490612A4549FD3E9ULL
		}
	};
	printf("Test Case 95\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB105A6D596DD8268ULL,
			0xCC2167F98ADE2F7BULL,
			0xB6F34DC43147A572ULL,
			0x5EF29430F7EC53C7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA8E6556093FF67B8ULL,
			0x702D2D5C800FDB79ULL,
			0x1F08C533FF387830ULL,
			0x56C33AF264200E09ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2D346D27F343C690ULL,
			0x135F7F4616A582F9ULL,
			0xEFBF404CAE9E60ADULL,
			0x1C8B7B3BD570188BULL
		}
	};
	printf("Test Case 96\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEF1B1C0D1A403390ULL,
			0x03989B35248D8D03ULL,
			0x7D02A49F4F49657DULL,
			0x75FE7D8D2B7E8BA9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x978C89A5E8E175F0ULL,
			0x3C735932D0D44FE0ULL,
			0x3AA378F9783499A2ULL,
			0x5D8054D49F42A45DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x79AF52E64B7E4E86ULL,
			0x9082F259027BC42FULL,
			0xF7EF3500535CD272ULL,
			0x4FA6516B86C60976ULL
		}
	};
	printf("Test Case 97\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF0AE2570C28C7D60ULL,
			0x0454BDA61332ECF7ULL,
			0x63056B381533AA8EULL,
			0x4E8707D6CA6C5267ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF244AE8C852F7668ULL,
			0x77E117BDA22DC004ULL,
			0xB2522CEDB09D38FEULL,
			0x6176AF965095443FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x191529E55D17553FULL,
			0x87B8CE8CAD61B398ULL,
			0xB43390AF9E1FB4AFULL,
			0x7BBE7CD0AEDDED59ULL
		}
	};
	printf("Test Case 98\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0C6FCDE0244FC640ULL,
			0x915BFF27DC35A758ULL,
			0xEE856D79DA9A5472ULL,
			0x5EA22C1DB410A456ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF76CB58FED821FC8ULL,
			0x619A8C41544072E8ULL,
			0xF33F80AFA2B4BB6DULL,
			0x4B606F1127583AF0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD8229DBEE1A87D99ULL,
			0x91875DBDFA530775ULL,
			0x4F4E307E05DB6AA5ULL,
			0x2A7DF0873C3CBAB4ULL
		}
	};
	printf("Test Case 99\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x94E3DA18272FDE40ULL,
			0x76DBDA1CF2521783ULL,
			0x9E0F7462FB2243D0ULL,
			0x447474DFD5F248BEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E8A041444C50FD0ULL,
			0xCFAACD831CFF6CCBULL,
			0x6794A47CE51C2CDCULL,
			0x42189E0C98808A5EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD2A93482C3EAF786ULL,
			0x1EAB3D86CAB65393ULL,
			0xFBCF443244F71E37ULL,
			0x689A92298053C546ULL
		}
	};
	printf("Test Case 100\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8C8546C6DC7B3F68ULL,
			0x4E2B754E94A091C7ULL,
			0xDE6D839AA9E244B3ULL,
			0x41DC248E2875D428ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x14504DE1D90368F8ULL,
			0x72EDFE6A8D7C22CAULL,
			0x4B1056F435FB0296ULL,
			0x44E102D48BEBE974ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x30DBF184D390CF78ULL,
			0xF25F9B3490E2B1F3ULL,
			0xF5B73005B2DD60F9ULL,
			0x32245DD47F8C3FE7ULL
		}
	};
	printf("Test Case 101\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8DEE2069B0FB1AB0ULL,
			0x2B42052FC2276A9BULL,
			0x12B665117211AEBAULL,
			0x74EF33A1EA80E18DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0EC32B71D12CEA28ULL,
			0x8BBB8B77A3BD5AC3ULL,
			0x0F664BF27011C554ULL,
			0x496956388B9FD5C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xED6F3124AC44AC0CULL,
			0xFEC50C926F91E19CULL,
			0xC344005B5B0FB4B9ULL,
			0x7F1C1A1E8574E88AULL
		}
	};
	printf("Test Case 102\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC2C822364E998C10ULL,
			0xCA238EC1A9C34639ULL,
			0xCA2FDC969DF90EDCULL,
			0x6346B87F3D2C5B79ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF681A26F8E9BC648ULL,
			0xF1848AD2EEED1033ULL,
			0xF840778C30263673ULL,
			0x700F131EC8B4B308ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3893477FC26D327CULL,
			0xBEF100B8366D8511ULL,
			0xE6C23671C29FD299ULL,
			0x6735BE08EEED66C4ULL
		}
	};
	printf("Test Case 103\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x360A4D49EDA335A0ULL,
			0x081CF7ABC0376D2EULL,
			0x6D303464665279AFULL,
			0x4E1D5D00C4521F6CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x59B2274BB6512240ULL,
			0x0E89D20DB5C178DBULL,
			0x7CE806185FF352CFULL,
			0x68C2D9BC8CEAB373ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x638A690D056A4B94ULL,
			0xDB0833C7EED9D56FULL,
			0xEE298CC3D8F473CFULL,
			0x5F13A396E1275CFEULL
		}
	};
	printf("Test Case 104\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x42593BCA4A6F4DB0ULL,
			0xEF392C21E108FB3DULL,
			0x7E3B27513DFA03B0ULL,
			0x79ABE08900BFC98FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD837D1D2B181E48ULL,
			0x3B30E252D2E69676ULL,
			0x652452140C596192ULL,
			0x6585CDDB18481199ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF4471A52ED1D25A8ULL,
			0xBB1F26C1ACD53500ULL,
			0x8D0EC3576620AFD4ULL,
			0x30679775DF5A66D8ULL
		}
	};
	printf("Test Case 105\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA651200FEC3CC890ULL,
			0x9423614A7BD9882EULL,
			0x3FCDF97F8A36378FULL,
			0x7D533BC2996C50B3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x79922AC3AE1465A0ULL,
			0xE79A1D2BD66F3D1FULL,
			0xAC4D31E7F273122EULL,
			0x711272C512F904BAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8AFD5B9EB9AE9F36ULL,
			0x4271803B9C085CC3ULL,
			0x4DF1EA8BC83DCD02ULL,
			0x153C59FB4B937874ULL
		}
	};
	printf("Test Case 106\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8A8AA3E17D500160ULL,
			0xBD69EEDB97D90ACEULL,
			0x151633B6BBEE7939ULL,
			0x5900DC9DD4A8DBA6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAECC68FCBBC18DE0ULL,
			0xC7A8408311F112ADULL,
			0x11F08B6EBE628696ULL,
			0x444AF25476983FF4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x741A41539D730A75ULL,
			0xAD15EF2D2E6B675CULL,
			0x86E9251C0A6776DEULL,
			0x60A9485944C11FA7ULL
		}
	};
	printf("Test Case 107\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3265598B80447AB0ULL,
			0x46F72C9BD071B7E5ULL,
			0xC0414E474CA6DDA8ULL,
			0x71A94CA393C9675CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDD5F81B96EE0B3B0ULL,
			0x9CD3B42E9B5C262CULL,
			0xC28ECEAB787BEBBFULL,
			0x70A022BD4915607CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF215A3D8BA9228A7ULL,
			0xDADFB43A9B77E34FULL,
			0xF3B7813EADF4D6DAULL,
			0x7CD4F7CAC7510D97ULL
		}
	};
	printf("Test Case 108\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4CA340C7760CC820ULL,
			0x92E16350989DBA9BULL,
			0xF408805FCEE0D150ULL,
			0x7D16247CE8CE9CF0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC07BD5E1C9A1A1D0ULL,
			0x41FDA4C3D62B2D81ULL,
			0xE394D14C177037D0ULL,
			0x4D29B3FCB0CC7C89ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5963EF9095E9CB44ULL,
			0xE02A592AB040113AULL,
			0x45400E23343C474EULL,
			0x6C2B245D345F73DAULL
		}
	};
	printf("Test Case 109\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0068140EB74003A0ULL,
			0xE371F0D281CEA093ULL,
			0xEB6BE6A1D28CD0CAULL,
			0x6E6D85142A168415ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9B6643CFC09D9DC0ULL,
			0xBB4126BE727E8B97ULL,
			0x75A05CD9C8141B4AULL,
			0x6EACFB64962591D2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x710C1165DDE777C1ULL,
			0xDEA04C626DEC3904ULL,
			0x06D5AFF02221B746ULL,
			0x3183C51014A01DB6ULL
		}
	};
	printf("Test Case 110\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7085DADD794942E0ULL,
			0xC5FED82E754A3F1BULL,
			0x2D40FC1B0EFD085BULL,
			0x77716781036B30C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x81716411FA8251D0ULL,
			0x3F36382F430A4479ULL,
			0xB8C8A8F873A16738ULL,
			0x70F7333F55AA70B4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6EBC3A45784B9826ULL,
			0xA1114E203D71DF2CULL,
			0xA7805554441B5815ULL,
			0x32F23686F837D698ULL
		}
	};
	printf("Test Case 111\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA71370BC893E3C40ULL,
			0xCF37911360526F24ULL,
			0x102118D2475DA366ULL,
			0x5355CB7541B2E3F8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8DEF59AF0D7BD238ULL,
			0x3CC79038C92B7347ULL,
			0x6CACA5C0C352B4A7ULL,
			0x795C8C950F0E045FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC67CA30A60145BFEULL,
			0x4928AAFC1FF41B8EULL,
			0x9BCCC91843B28C9DULL,
			0x79FBFEFB70694327ULL
		}
	};
	printf("Test Case 112\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCD5BA8C2146A3730ULL,
			0x0500A35B40281311ULL,
			0x7986D048B4CA3018ULL,
			0x74814587D6D29CA7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C613282CBA14538ULL,
			0xBBFD5132B09E37ECULL,
			0x5AC9E81838D1BFF0ULL,
			0x7FD1E206654FECFDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEF5603BE31E8A3D0ULL,
			0xF49383193B14EB44ULL,
			0xA0996FE0B0AE167DULL,
			0x4207F926206870A9ULL
		}
	};
	printf("Test Case 113\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA213220257BBFB58ULL,
			0x38522351D365D966ULL,
			0x03A32C3007DFCB87ULL,
			0x47258D4C422BE541ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x902FB205AC0C6598ULL,
			0xC565D4F199FC520FULL,
			0x19F750D70682F53DULL,
			0x7A9A90CBC437C96BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E5CDDD35A475540ULL,
			0xD00BB827430787B6ULL,
			0x2603BFE4B23B4458ULL,
			0x29F03A857E9AE27AULL
		}
	};
	printf("Test Case 114\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC5C521099077F1F8ULL,
			0xD358B1BEBA062DB7ULL,
			0x97A3DF2BF8E8423CULL,
			0x7DD388B9A8C00B59ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEEA2A7779B029EF8ULL,
			0xCED9465058DBA261ULL,
			0x1BC90C371104E142ULL,
			0x636227504FC53624ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8CB73F9D8ACC8BC3ULL,
			0x8B580D48B9A2C4A2ULL,
			0xCAFABAAB0B5ADACFULL,
			0x1E38CD803373EA00ULL
		}
	};
	printf("Test Case 115\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9860614E47127BE8ULL,
			0x5484AE96D6D95F40ULL,
			0xB97F8F1E21FCABE2ULL,
			0x7D7932177F730B96ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x22F208C5A86CF068ULL,
			0x419308563B2A71E6ULL,
			0x5F00F225C372FE83ULL,
			0x72221D6A0A061152ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x72D2AC95E7653DE6ULL,
			0x52F83D234E2AC274ULL,
			0x7FE816A20E66E1FDULL,
			0x205BB95BDFF46D5DULL
		}
	};
	printf("Test Case 116\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6CF723A450F5E120ULL,
			0x7F69221CA3A27239ULL,
			0xFF1E145931984728ULL,
			0x72C8D5899B6D8F3AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0DE3BE47E9DED30ULL,
			0x528345DD34276B9EULL,
			0xB617C2F8365C6012ULL,
			0x4E50EB4FBE6EAC1FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x51AC86D66A1D7B28ULL,
			0x14467B915DF86233ULL,
			0x9F81F481B6744036ULL,
			0x2B542AF51108232AULL
		}
	};
	printf("Test Case 117\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD4A52F9D1DA2C7A0ULL,
			0xA9EED6CC77319A4DULL,
			0xF0396209417A1A0EULL,
			0x4EBAFC73028C8747ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x64381C31BF806708ULL,
			0x0BDD4D22ABC25B2AULL,
			0x5BCF5A3C67A4440CULL,
			0x585701E54B3769C5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x03BA6D2218003689ULL,
			0xFA33A7E42FDEAD05ULL,
			0x43989EF6F7A7FEA3ULL,
			0x38B746DC08653C16ULL
		}
	};
	printf("Test Case 118\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBA5D02A825F63548ULL,
			0xD1799FA202411827ULL,
			0x07AFCCC1F564486CULL,
			0x643D6BFCBF36F151ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD943F67FFECAE0A0ULL,
			0xD92E9308CB70CA31ULL,
			0xEB5104BD81F84952ULL,
			0x79FF4CF875DA0259ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9C845273DBF3FE8CULL,
			0x7E5EA3FE1038363EULL,
			0x838364C53C1B5209ULL,
			0x5D8A284035786DEEULL
		}
	};
	printf("Test Case 119\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDB3E6E7E1A7A6338ULL,
			0x085BE37F56060802ULL,
			0x613F0ACB49121F8BULL,
			0x6F8B8628FCC577A7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3334007CA1221BF0ULL,
			0x8F88B4B90B1FE99DULL,
			0x9424BC86AB57564EULL,
			0x787007D44A5BFDA4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x01C356EE75DAF2FFULL,
			0x545662016760EBD9ULL,
			0x77DC2D1E63D7E702ULL,
			0x6B1AD287932E0CBEULL
		}
	};
	printf("Test Case 120\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE4271E17D4609D98ULL,
			0x84CDFF293EB22048ULL,
			0xD74324A137581ED7ULL,
			0x44D9C2DFBE4FEE47ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x685E2E0AA8349F00ULL,
			0xF75AF66AA5533D1CULL,
			0x8AF31C02583A88EBULL,
			0x4A88FFC85F9A89F1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x150526B5500C6B89ULL,
			0xC2E82E1E8168E5CAULL,
			0xDD61B0A0F203D31EULL,
			0x141C7C664DBEFE80ULL
		}
	};
	printf("Test Case 121\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9D279D7E603265F8ULL,
			0xDB8C42AE8F8E39FCULL,
			0xBAF04C43C0860875ULL,
			0x453273A7E2E7C033ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDD13D5E24F3E5D30ULL,
			0x61EB768591A96A60ULL,
			0x27BAEE4C9A88E1ACULL,
			0x547910F2CA1A3BAFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4951593579460BD4ULL,
			0x3C963B72369763AEULL,
			0xDB3961176137A54AULL,
			0x2A5D5484F69B0EB1ULL
		}
	};
	printf("Test Case 122\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x434D0F8582D27318ULL,
			0xCF2A849CED7D6316ULL,
			0xC74CBBC208C9FA7DULL,
			0x54BFF7A10AEBCB3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD10631AFFF115028ULL,
			0xDD394701612165ECULL,
			0x8FEB06A5221B6B1EULL,
			0x5197704C31B37D6AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB928E08A848FB872ULL,
			0x45B4A36D83E365D2ULL,
			0x747D790359C6BC9CULL,
			0x340487B8B109D407ULL
		}
	};
	printf("Test Case 123\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE57FF96C972C2180ULL,
			0x54FEC785957B9AAEULL,
			0x0B204F0A1AF9C467ULL,
			0x4B835339473CF77CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2F2FC2197307D578ULL,
			0xF645E5B8BDDFBAACULL,
			0x798E29FA954A1899ULL,
			0x43EFC546B7CA9479ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE2EE5A55BA54934ULL,
			0x7A04A6B72C71352BULL,
			0x23DB6EBC71718AA9ULL,
			0x03078B8B1D33A3CAULL
		}
	};
	printf("Test Case 124\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0658E14D3AAAD828ULL,
			0xCDEDAF09B0A43498ULL,
			0xAEA95EA67B51937CULL,
			0x6644C118CAC30BE1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71C7DE363147A030ULL,
			0x549E527E31F6B550ULL,
			0x3A91C8EC86398E47ULL,
			0x7E2B7019DEE523C2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBB32474CB7EFBD4CULL,
			0xFBEA6C5E07329B27ULL,
			0x616E8E757ED3A96FULL,
			0x520B613579347CBDULL
		}
	};
	printf("Test Case 125\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4757CC931381CBB0ULL,
			0x23DBFEFAB307CF82ULL,
			0x00B2DE58E5FB2B1FULL,
			0x591D1B612654D501ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x245FAE7ECFAD2680ULL,
			0x1F3278F129349209ULL,
			0x3F062D4270DBF1E5ULL,
			0x6614B6AC4FDCB97DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x34C441B3DB7E5327ULL,
			0x0F4C2F06A40300D5ULL,
			0xEEDF47D08A606CD4ULL,
			0x441649B9C5D0F88EULL
		}
	};
	printf("Test Case 126\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9B96B64E1B88DA88ULL,
			0xDFC71893BD2AFB72ULL,
			0x39B0EE0A11398222ULL,
			0x60858635FA62C209ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEE31D24CFD305678ULL,
			0xA43DAD2C4020C3ECULL,
			0xD78896095E55821CULL,
			0x71752112A1366087ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3A1EE4399200CCAEULL,
			0x86E8A43F611192B9ULL,
			0x1879EA3B62C8DA7DULL,
			0x2C3C3D240B105A1CULL
		}
	};
	printf("Test Case 127\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3E8FB7B38872AB58ULL,
			0x35E5202902D855B1ULL,
			0x1810F79C3E799C95ULL,
			0x4A2888874FD35801ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCEA2716ECCC57AE0ULL,
			0x5AAF2B439E9D97F7ULL,
			0xF249A1C0EFC568DEULL,
			0x7B4E8449143002C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD291340028216094ULL,
			0xE03EE26295739DE4ULL,
			0x080CA98482385363ULL,
			0x6063F6959CC742D8ULL
		}
	};
	printf("Test Case 128\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBCFD5C93F6998C10ULL,
			0xCE264A66BEAAB2F8ULL,
			0xC862F5B8C8BF3D65ULL,
			0x7D06AAA435C36AF5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x590C5FA6188AE270ULL,
			0x21A28D0723E62181ULL,
			0xC9E6674AB410611DULL,
			0x4E450723574F72D4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6D09B56D480AF72CULL,
			0xB53EC07EC30213D0ULL,
			0x5D9BA485398DA333ULL,
			0x67F754C7279FB505ULL
		}
	};
	printf("Test Case 129\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3B4AF61AD45606B0ULL,
			0x2BC1098ACAD73C22ULL,
			0x6B0F3EA940CFD773ULL,
			0x6A3510C92DBFF7C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBFF8FD4BB2902E28ULL,
			0x802D0698424240B5ULL,
			0xEFD177AD84489C9CULL,
			0x758DB350ED8CF249ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x62D9D02F9A1AA45FULL,
			0x968E54FD99555AFEULL,
			0x95703E129B6BE556ULL,
			0x5DB3832902A2B8B3ULL
		}
	};
	printf("Test Case 130\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6C95F59AD2A09F68ULL,
			0xABB0C40A1695712EULL,
			0x746BEB52A1165DADULL,
			0x5F144B1495DF5AD3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD7622C9A41912688ULL,
			0x634FC573C27E4C3EULL,
			0x19ACB3984EFE49F3ULL,
			0x7AAE718EE4D5E15EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC33B371C2E9CB098ULL,
			0x35D7EED60C03F0A0ULL,
			0x5DD47EE8C7E66024ULL,
			0x10460E172BB2124DULL
		}
	};
	printf("Test Case 131\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAD838B8025C32548ULL,
			0xF656914E7B4868E7ULL,
			0x4C2EBD7435C3A83AULL,
			0x6562FBA0CB429B5EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6F3DF96D352D1EE0ULL,
			0x3B87F1A65A08DBD1ULL,
			0xAA019C6D046E07DDULL,
			0x60A112C1E54D71F1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x99553B04497D8D4BULL,
			0x00D99CFE143C5218ULL,
			0x963A733FE9A4B912ULL,
			0x1A4AC6BE70675012ULL
		}
	};
	printf("Test Case 132\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x391113B33D4EB578ULL,
			0x32F0672C4A273C6AULL,
			0xA49902E53BD43B60ULL,
			0x4F1835DB2ACC0C6FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7F0D2812CE02C40ULL,
			0x1B6BFC358F29B7C8ULL,
			0x2A194748374D8EA7ULL,
			0x7921589BEC05E996ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF741596FE3BBD536ULL,
			0x4C9C605A7CBDED75ULL,
			0xB7BB021E3432C5B2ULL,
			0x3B29EB0B01E50E89ULL
		}
	};
	printf("Test Case 133\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD5CD2B441C854590ULL,
			0x819C908E9270229BULL,
			0x1A581CE319C5E6DBULL,
			0x7BED6DEF7FA1204BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x85256258B759B990ULL,
			0x183828B35105885CULL,
			0xB02BE2F5F3F36251ULL,
			0x585CF02320702179ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3C3E70D7D2A86429ULL,
			0x37979DD82A5BF8A5ULL,
			0x748E6D57D7AB796CULL,
			0x2222B9266FA06481ULL
		}
	};
	printf("Test Case 134\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAC52EF4E848FDAF8ULL,
			0x8BCFF8C62096F810ULL,
			0x1C0DF3179057A275ULL,
			0x614010211D92E1A5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6EA153B93F5ABD70ULL,
			0x52A02882CF1907C6ULL,
			0xC4BFE5F6D273541CULL,
			0x6A71A064F6DB76CCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF8A76B7DAFE210A4ULL,
			0x8BA330A641BDC22BULL,
			0x70938BB6C51528D9ULL,
			0x0449E2D9E19BB653ULL
		}
	};
	printf("Test Case 135\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB85964306E13B788ULL,
			0xF0A07C86866E1B68ULL,
			0xB60D2DCD31E0A053ULL,
			0x6A481DBB805A0133ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x839C2D702787A460ULL,
			0xF8730C5217BE0EE0ULL,
			0xA040EE4F1B9072A6ULL,
			0x4A1BECC55917FE2BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E31A3FEFB41FFBBULL,
			0x79E82EE74D4D92EAULL,
			0xE7EEF8A6225532A6ULL,
			0x7A2AD10DECC3564BULL
		}
	};
	printf("Test Case 136\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x85041009EF8543C0ULL,
			0xC411B6C88B3EF656ULL,
			0x7A276194131A53A4ULL,
			0x5F27E0DDBFF636ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7712866CE4F762B0ULL,
			0x19B4FF6E20DB9B6AULL,
			0x6302B46A1140CF8DULL,
			0x4D3FFFFB522FBC19ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x86F908945AB02964ULL,
			0x9020552F315E26A7ULL,
			0x32BB70BDEDBB7FD7ULL,
			0x477C344198D6ACA8ULL
		}
	};
	printf("Test Case 137\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x028E230D89BB7D28ULL,
			0xD8AD8AEF8B01E442ULL,
			0x256380985BC8A0D8ULL,
			0x6D199486B857ED9DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCC0F1CB409D29E70ULL,
			0x881E208184C57F56ULL,
			0x18C824DA426A7CFBULL,
			0x7D542C37CADA2A16ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0D1746EC05A88A79ULL,
			0x9435D34C612510ABULL,
			0x15AA4FCA5F281A12ULL,
			0x709816E3BCDD7209ULL
		}
	};
	printf("Test Case 138\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB4C1D10CF37AC880ULL,
			0x3C1478F7B984C994ULL,
			0xCC362226701EF156ULL,
			0x7C826B4761E546EAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4588C9FB5EA9BC28ULL,
			0x9AB204E4F215C7A9ULL,
			0x95C55455D8C494B8ULL,
			0x498FC7DEEF8D5EFDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x75FD71E61F45EA5BULL,
			0x66BC92E66BE04CF8ULL,
			0x3C1528199D927EC7ULL,
			0x4BD47B76E290ABE6ULL
		}
	};
	printf("Test Case 139\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x63ADB6B2869BE300ULL,
			0xB974A65E966571EEULL,
			0x46546A857F43410BULL,
			0x70CA127F1A2B282EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C65A8CDB8748730ULL,
			0x5A32C056BEDB6A75ULL,
			0x6B8CCA5875D156B5ULL,
			0x789CA18FF9B6EB7EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x57B769420E2D9828ULL,
			0xE7E25102BFF4397EULL,
			0x34371E85A4C04577ULL,
			0x0857AADCD6CBA427ULL
		}
	};
	printf("Test Case 140\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB1C358F4ACBDD6B8ULL,
			0xAC4204C74984BDE5ULL,
			0x6F9F38E36D8EA388ULL,
			0x5F8363B206569168ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBA810FEA8FFCC4C8ULL,
			0xC1F651E6C91E1C1CULL,
			0xFDDF3272935E42AFULL,
			0x52CAFCCCC4570F22ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEDF0889415E4D6CCULL,
			0xAEFF438683F35228ULL,
			0x21FFD830C3DECF6FULL,
			0x0EFD258C65EBD6EDULL
		}
	};
	printf("Test Case 141\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5F1F148F27566000ULL,
			0x6178B0DD122617D3ULL,
			0x4FCFF29E9A8802AEULL,
			0x4A0E86AE235F5581ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFFB928821E3CED20ULL,
			0xE39B050178B5B316ULL,
			0xF7BD486E38FECA9EULL,
			0x6C6433970866FA89ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x16850BE990D73E39ULL,
			0x3E44C53B67BCD9D4ULL,
			0xCA3A4E0A53B9B5A2ULL,
			0x278ADA279FF7CE14ULL
		}
	};
	printf("Test Case 142\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x839372F83B6B5190ULL,
			0x0FD472F7B4DEF172ULL,
			0xAD8B396CF3CC298DULL,
			0x44BF3335FF1AD697ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC37EA3729B7FBD78ULL,
			0x41CABA784BD9660DULL,
			0x79FF8FFD27AEF5FBULL,
			0x691724A988A91B8EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6884457855663C1EULL,
			0x4F18A7C9FD52F3FBULL,
			0xB117F77B3721DC96ULL,
			0x1749DA0676D09505ULL
		}
	};
	printf("Test Case 143\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x97A386E2DB1960F0ULL,
			0x4054F23A8A8CFDFDULL,
			0xF5411BA6FE322A26ULL,
			0x70378381135D26AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2F62CCE37FF5C1E8ULL,
			0x8B85A92B8ADF41ECULL,
			0x60788547297C893CULL,
			0x439CDD7B4FECB4F4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x35BCCAC9962888BAULL,
			0xC872EA67935DE45FULL,
			0xB2C50FE8D2706A15ULL,
			0x1BBE35507D9AAC05ULL
		}
	};
	printf("Test Case 144\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7A4F3C6F9F5DB9D8ULL,
			0xCB5CAA8ECEF8263CULL,
			0xDE99E4349EB3BB1EULL,
			0x71337790376869A2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B1DDEC652C8DA48ULL,
			0x9733B056A5B71CC0ULL,
			0x5D4734F5E0903327ULL,
			0x760906B9217CDF4DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2EF52DB3685657F4ULL,
			0xA8887C9CD07F2FD8ULL,
			0x77C4CFB34D7727DAULL,
			0x05FBEBD5CB97DA5EULL
		}
	};
	printf("Test Case 145\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x775FA4D19A773CE0ULL,
			0x05F24566429385FDULL,
			0x704E7DEA95C253DBULL,
			0x5E1AD46B52011473ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2AA39D086C3B2DE8ULL,
			0x8F0BF51A8BDA8279ULL,
			0x6920B19B9B984D2DULL,
			0x7C7C51F58B9DA8F1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD22C34EC7BD8D0AULL,
			0x6D735FBB33299F62ULL,
			0x33A31371864A5F77ULL,
			0x3E6945898A84D5B4ULL
		}
	};
	printf("Test Case 146\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x50EEC3BAE479CB20ULL,
			0x3C250679522B4F5FULL,
			0xD28F5BF3BB472260ULL,
			0x6CDA3A5FEC2D9864ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x971CB682F9CAD258ULL,
			0x3A1F3BCA049DF53AULL,
			0x62AF75F89A8EEB5FULL,
			0x4CD42013566E23AAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBAACD33A3D006701ULL,
			0x6FDDF3D780BBE0A4ULL,
			0x1126B2C9E6636603ULL,
			0x7A7167AE1FF9CEE2ULL
		}
	};
	printf("Test Case 147\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7CB6DBA68E22B988ULL,
			0x674AA5C2EDF48028ULL,
			0x239DA21D9EC2B019ULL,
			0x7341C52123A8E680ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1DEEDE69F5C00C20ULL,
			0x8374D21EC195D0A4ULL,
			0x2B5DA4B95C1912EBULL,
			0x4D4E86B30FAAB93FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85866C4014460B0DULL,
			0x7311256BA7B4FB9CULL,
			0x13D128F8F89D44E7ULL,
			0x5A9D185063519DCBULL
		}
	};
	printf("Test Case 148\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6F3141812299D320ULL,
			0x8EDC23179340118AULL,
			0xC19E640078C84E7BULL,
			0x45E251003D2BD174ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD60B49E8D93DE268ULL,
			0x51E76E0B94C310DEULL,
			0x9E1E8ECF0AD46144ULL,
			0x66E81D19720D0EF5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x86B1E58E25D69BC7ULL,
			0xBC5FDD2C23A3F1B0ULL,
			0x09455CF589331287ULL,
			0x6181945AA7C91DC0ULL
		}
	};
	printf("Test Case 149\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF895F59504ABAB88ULL,
			0x8F703251C3542F80ULL,
			0x6019CD35ED52B73AULL,
			0x4D652C323A56068BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6320219139DF3C78ULL,
			0xF568B7D25C2F36ABULL,
			0x5E60C377FF7A74ADULL,
			0x7DA00FDEC67FB4D4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0A0AD16167DAD13EULL,
			0xDB85776034762AABULL,
			0xD6B0545D8DB8740FULL,
			0x547C819C641AA03AULL
		}
	};
	printf("Test Case 150\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA5B79734946CEFD0ULL,
			0xFE9EF4576117D9EBULL,
			0xF3B82508E0A65075ULL,
			0x5DAB2CF11F3285BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC0F1DE722439258ULL,
			0x70DE72A31EB0DC10ULL,
			0xABB0020F3584CDE0ULL,
			0x6BED7DD359D4EB93ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDCC83E5CABB9D923ULL,
			0x60ABFC9207F625D4ULL,
			0x3B6B8CCB36764E10ULL,
			0x6DB45D50626373E3ULL
		}
	};
	printf("Test Case 151\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x628005335A0FE290ULL,
			0x4141C7AF6D67C4D5ULL,
			0x39AFF7628520D4D3ULL,
			0x613914E11BB0211CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x157D754A1EA11A80ULL,
			0x474BC774D7193AB9ULL,
			0x626D699552CDC2C5ULL,
			0x43BC6491B69DE09BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFCE56650AF7F2BC5ULL,
			0xD4045C60C6FC8CB1ULL,
			0xAED69C7F44292D8FULL,
			0x2966928D181F4AC2ULL
		}
	};
	printf("Test Case 152\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF6BFBCD72D378F68ULL,
			0xA156C405E5ED75B5ULL,
			0x9E902830CC17E22AULL,
			0x7B36ADA06F2FA379ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF13C71D8699C99C8ULL,
			0x6CD3D6C2A655FE9EULL,
			0x14A3FEADD6E85233ULL,
			0x6F0BB112876C8FBCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x87AE68FE756A09B4ULL,
			0xA13429CFA2554B31ULL,
			0x4F6F7B0512A758C0ULL,
			0x4FA58787D3650CA4ULL
		}
	};
	printf("Test Case 153\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFC1B92003A867A18ULL,
			0x00A951176C9D0C42ULL,
			0x6B7D4D083923D7D0ULL,
			0x591320DA9E417CDEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0B9AD1ECA8C4DD50ULL,
			0x6B669957A78DD869ULL,
			0x33A638F0C4B966B0ULL,
			0x49084269819ACC28ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF046FBCE3FA38664ULL,
			0x26A8EC9D3B0BA9B3ULL,
			0xC80DFFBED04C4078ULL,
			0x0D08BB47D2557887ULL
		}
	};
	printf("Test Case 154\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD99ED37FC71C9880ULL,
			0x6D2DEE530F79F42FULL,
			0x5275901CC2A88E2BULL,
			0x758AFA02F99AEE0AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x35448CFD56A10D68ULL,
			0x20CDD71EBE146ED8ULL,
			0x216B3209794B542AULL,
			0x4CC6030E03AB4050ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE7D58001C211AD1AULL,
			0xA3B2B0A8B8D5BD7BULL,
			0x3C4DC859F616886FULL,
			0x7E2ACB1FC71E816BULL
		}
	};
	printf("Test Case 155\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x842113ECF9729190ULL,
			0xE25CDBE3771A88D6ULL,
			0xDBC94B3A668AAC90ULL,
			0x68820D61818C4C70ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3241E1ACAF45A6B0ULL,
			0xEE4B36CDFAB62ADCULL,
			0x3AFA5A6966988CEEULL,
			0x668B7026BB852BE8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xACA6DA3652EFFA91ULL,
			0xFCD12F0C8F4B508DULL,
			0xFC0ED098B2523388ULL,
			0x2E2F35B45FBDCFA8ULL
		}
	};
	printf("Test Case 156\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD12F8E328AA8E088ULL,
			0x1F9DC1EAD08D29B5ULL,
			0x7BB826EA30A720DDULL,
			0x6F24B1F80CF9DBE0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2F095D5E3D763188ULL,
			0x2D675CB370BF286AULL,
			0x4E0769C400DED097ULL,
			0x695F38542FFA52BCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFA23385D1078B7CAULL,
			0xC00871EEA8ABEE81ULL,
			0x364C570DA631C245ULL,
			0x1DBE8793E74EBF3CULL
		}
	};
	printf("Test Case 157\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEB017B392F02FB20ULL,
			0x442CC46CBFDD3CDDULL,
			0xF802B1E1651851DAULL,
			0x536BD8C2B1D3EB34ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x313DE737B93AAF60ULL,
			0x30A1F34FD9A249D4ULL,
			0x64882B2D81D0B78CULL,
			0x68D24A5DB73116B1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x28B7D852F5FE53FDULL,
			0x37D049DEE1426CACULL,
			0x2C48F6E21DB4277DULL,
			0x4DFC00AE733ABEF0ULL
		}
	};
	printf("Test Case 158\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x64816E1F1F92C128ULL,
			0xE0B6EA2044C28AECULL,
			0x933B1FFB092A2B1FULL,
			0x5275DFF36D467BD9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4E74B34A9FD364C0ULL,
			0x6FC01BEDBD24A2C3ULL,
			0x91F2BD9A04653827ULL,
			0x7140F6A76CE00BD2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x252B26BE26732169ULL,
			0x257E181307CED1C4ULL,
			0xD51895B683FEC9A4ULL,
			0x1969CAC1DFFBFF1CULL
		}
	};
	printf("Test Case 159\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB9F86ABB0B870150ULL,
			0x07E1AC6105CBD6A2ULL,
			0x069FDB539926A48DULL,
			0x74E9E1A453CCA53CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0D0F07B14E8033E0ULL,
			0x7E4578708A313924ULL,
			0xB7008D600164BE2FULL,
			0x6FE99BECF48FE67CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x94A8D753C59DE155ULL,
			0x909F5001E43EDD0AULL,
			0x3BC62336E414E714ULL,
			0x16CCEB8CDAC60433ULL
		}
	};
	printf("Test Case 160\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xED0C0A4269AB0018ULL,
			0x2E4E7D99C321D678ULL,
			0x15FD097400AE2921ULL,
			0x6FB3517E8D87D143ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2913331F13481930ULL,
			0xBA3ED3CFEB61D762ULL,
			0xCDE7E01C1F4599B1ULL,
			0x521CB933E1961C4CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7AE2EEA4422801A4ULL,
			0x1D0C72EE3D9546B1ULL,
			0x1FFA5884A23797DCULL,
			0x4A28F4BF714DA062ULL
		}
	};
	printf("Test Case 161\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA4CBE691CFAEC7D0ULL,
			0x0F2A8D02A990FB0BULL,
			0x2EFE7B48CAF8AD33ULL,
			0x7BF589A6C53B11CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8C06A90A2E404610ULL,
			0xC51EDD8C4C63AA80ULL,
			0xE64C9CD94FB8E364ULL,
			0x682243CD09CF19C2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x56A8087ED948E9F1ULL,
			0xC81A4B363679A548ULL,
			0xB123D1DBFD135025ULL,
			0x57CCB135C81D360CULL
		}
	};
	printf("Test Case 162\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x928FDE44F5BED588ULL,
			0x70640A0334772F58ULL,
			0x2D5371A4CB782D46ULL,
			0x59730CFF60F31DAAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2B748E7B3D9D0998ULL,
			0x3A67D78C339365DFULL,
			0xAF13A2D648413215ULL,
			0x7B1E086815189FC2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB126B9D6EEBBE56CULL,
			0x88FB4889869EC359ULL,
			0x471CAF6F647C670EULL,
			0x622D68E0EB8BCD4BULL
		}
	};
	printf("Test Case 163\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x299364EA1376F5A8ULL,
			0x377F781B4C7C85B4ULL,
			0x4422A63789C6D05AULL,
			0x49FE035E96075F91ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBCDE3E5457C56848ULL,
			0xD04DD7BACB2DF2D5ULL,
			0x943027ADC0258675ULL,
			0x55AB0B7E7408D272ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBA93CC2D73C5F1E3ULL,
			0x8DFA43CF8D323965ULL,
			0x4FA713A004D59B6DULL,
			0x0BE5CA85E15332D4ULL
		}
	};
	printf("Test Case 164\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x523EDEA7123CC308ULL,
			0x0A09C1F483D32EBCULL,
			0x74B9304F10DFB97DULL,
			0x41D5FE55968BE1AFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x125D5D702B5237E0ULL,
			0x893D8B9294977FD7ULL,
			0x49100014A735053CULL,
			0x5F017EDAF4B26AFCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDA50D5960E2721F6ULL,
			0x3D225F3D3A8D94DEULL,
			0x8A63FA0BDE2191ACULL,
			0x769AB0EFED387A91ULL
		}
	};
	printf("Test Case 165\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x39531E3FE85AD318ULL,
			0x8EC905C00C417283ULL,
			0xB4715AD60B665ADCULL,
			0x5AE8D182BC92DE64ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x787F8F5EA46276F0ULL,
			0x139C965C0C911ED2ULL,
			0x0BF1ED763EF71CE8ULL,
			0x6C5DEDA99CCDE190ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC0266B177B48996DULL,
			0x92B7AA697C433688ULL,
			0xACC8BE9A20E12FB2ULL,
			0x4BEFE204BF7B39B4ULL
		}
	};
	printf("Test Case 166\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC2E58043744420B0ULL,
			0xE209DDEED05357C6ULL,
			0xB0AF6742CDFCCE4FULL,
			0x6AB13BCCE77DA4F0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7A21F9C88846A48ULL,
			0x5FA187C1AFCEB3F7ULL,
			0x3507032BB04EFC81ULL,
			0x6D5EF1144D8EA63EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x221AFE8611DDBBB4ULL,
			0xCC35680499111F8EULL,
			0xDA318D4BBE19CDB8ULL,
			0x0D568F9138BF8545ULL
		}
	};
	printf("Test Case 167\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6CA99F88888D2048ULL,
			0x226683D72D629C7AULL,
			0x194507220D1628B6ULL,
			0x49F0536D84D2A2C7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCA7CFF3A89798310ULL,
			0xBE19F84978E29E39ULL,
			0x8910EC5B97ED670AULL,
			0x4082DE1EC44E4A2CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5710B59E3F74EE1ULL,
			0x83CFF4011953F544ULL,
			0x883864F1CC9EB26CULL,
			0x3BD2443E33EB0AA2ULL
		}
	};
	printf("Test Case 168\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6CD9B76ED80B9B98ULL,
			0x362E7BB7AE376C35ULL,
			0x4BAD21EC084DB7BCULL,
			0x51FD4492074254ACULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x73146673ED7A9A00ULL,
			0x7E3E84D00F9A6B0EULL,
			0xF3523FB00A966153ULL,
			0x7ADE70490FA84F99ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C97C6A1F48A8C23ULL,
			0xD24312B45F82D0ABULL,
			0x75F3E31C70B27264ULL,
			0x22CC0F25D03BDCB7ULL
		}
	};
	printf("Test Case 169\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAB1D0D4D396EF618ULL,
			0x841757BD7B4012A6ULL,
			0xDDA20753DFA19336ULL,
			0x634E57BAAFE4D2BBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0B4DB981471193F8ULL,
			0x993B36F580F57E7FULL,
			0xBD36838BA5EDD56BULL,
			0x6E11B88B217CADBFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x405FF005FB8817F8ULL,
			0x4E2D8B779F26ECCEULL,
			0x4CE98FE9937254D8ULL,
			0x62525805E24AFBB6ULL
		}
	};
	printf("Test Case 170\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x19163A998A425050ULL,
			0xB2DEE64A19392223ULL,
			0x1AA709EDDAA30A8DULL,
			0x431A53435D421E9DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x00974D01EB340638ULL,
			0x69E2D1D6656568E4ULL,
			0x5AAA544B25C6608AULL,
			0x55F5F07D80BD3570ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC03EA6D6EE529BF6ULL,
			0xB9858F73087BFD85ULL,
			0x940128E907063C92ULL,
			0x2614D3617A8B19CDULL
		}
	};
	printf("Test Case 171\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9E84D05220FC9AE8ULL,
			0x9C314EB1BB4396BBULL,
			0xFB1AADCD7A92CC94ULL,
			0x7D7392B0EFB4333EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0C027A9BA4EE340ULL,
			0x2257E634EA3527F2ULL,
			0xC694121B28FF5180ULL,
			0x653D234C39BA7F2FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDC5B4AAB83EA4DDAULL,
			0x0C778F44F5C3AD60ULL,
			0x3F8A7009027A0A5FULL,
			0x7910931F1D5C5550ULL
		}
	};
	printf("Test Case 172\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x62E8F730082E7598ULL,
			0x116A3F682095837DULL,
			0x20F4230778FBB412ULL,
			0x7E7F9CC428B29F80ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1C1BD79326E16580ULL,
			0x17A2C4792C3E548EULL,
			0xAF83FEC8ABFC1386ULL,
			0x4E42D770A0857050ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF41DB3C0DF65069CULL,
			0xF04B3992323CD3CBULL,
			0x2FF9F7EFBC040E06ULL,
			0x5414C347E33A90CFULL
		}
	};
	printf("Test Case 173\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2D23B1B45155A240ULL,
			0xF7168638A3F23C71ULL,
			0x88D77D508A0BB2D6ULL,
			0x6C2B8B53C8D064A9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x14DB99BC36CF1F28ULL,
			0x19873A349FF71AC7ULL,
			0xF610BCDBD0646FBAULL,
			0x418C4311008837B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6C6B7474E4BA348EULL,
			0x0654CB1B1660D3BCULL,
			0x0105124C77318586ULL,
			0x7069263C3B79172CULL
		}
	};
	printf("Test Case 174\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1C0B05658219B0F8ULL,
			0x3BB118A638053880ULL,
			0x365A77CB4B85DCBBULL,
			0x5D9CAC8CB376D037ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9072EB73C2E77998ULL,
			0xF420BBE9FC1C78AAULL,
			0x233A04CFB34D9D8FULL,
			0x73A85994CF1D57ECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E294D27CE2C025DULL,
			0x0FE0DB97FD8951ABULL,
			0x3FF4D8731DCD766DULL,
			0x67866B726C72D9DDULL
		}
	};
	printf("Test Case 175\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6339536A1E2C6C10ULL,
			0x2034151892F3B209ULL,
			0x3F17DA80016C4726ULL,
			0x7A691C2F96DC9C05ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x22094167C7DD3F78ULL,
			0x6380A465C85E0A41ULL,
			0xF2225EAD56A898F7ULL,
			0x40347C2028DDAC81ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD7B9357FCEDC2C9EULL,
			0xBC47CB9DAAC9F8EEULL,
			0x7FF97BC42B13AA78ULL,
			0x6BFCD44EAB062A16ULL
		}
	};
	printf("Test Case 176\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x87F578CEA1FFBE20ULL,
			0xA2104C5FC9E98EECULL,
			0xF149284EB78FF522ULL,
			0x7D31D525F8331CE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C6BBAE603E0C8E0ULL,
			0xC0B2C869715E2181ULL,
			0xF731259BA46240D6ULL,
			0x59C72F70853BCE45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3E9918A06E6D83A2ULL,
			0xA998AF8865D57E76ULL,
			0xF46D0B3C90E41B5FULL,
			0x2F75867DF9F16966ULL
		}
	};
	printf("Test Case 177\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x938D424921F0DE28ULL,
			0x3A6F933CCAB0DF49ULL,
			0xD1DE99AE6E235D12ULL,
			0x6B45651A58A17273ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x905664215AD2D1C0ULL,
			0x2BBBB0161C94BAD3ULL,
			0x3EE89BA3941AAF95ULL,
			0x5549991D7F1171BEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1FC6C2D625358D31ULL,
			0x25088A83C60E330BULL,
			0x63F71FC4107A9D15ULL,
			0x63113DB3FA4C1CC3ULL
		}
	};
	printf("Test Case 178\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFEE5284A3A67DAE0ULL,
			0x6C80062E1368F1EFULL,
			0x09DF288CCBE79A36ULL,
			0x56917170CF2B401BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1CDB85DC81135320ULL,
			0xD5691017FF0840AAULL,
			0xF29811C52F1E0DA9ULL,
			0x77EE059A761A34ABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA8DD26ACA7DEA22DULL,
			0xBB82D0836C006884ULL,
			0xB4A39C4B30E37AFFULL,
			0x17573A0C0B2E16C3ULL
		}
	};
	printf("Test Case 179\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD81A8617C3DAB918ULL,
			0xB0784ED26DF16EEBULL,
			0x0A623D1BFE10D901ULL,
			0x42A5EB729834298EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD437ED6B0857EA68ULL,
			0x76001068F650D4A6ULL,
			0xB9487C26CB6FACD1ULL,
			0x61354A6E26C77ADDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x950FD4AC5DAE1D97ULL,
			0x9343CE60CBC2587AULL,
			0x868429C02CD73730ULL,
			0x6F3ED46B39055D32ULL
		}
	};
	printf("Test Case 180\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x49BD5F9EF6177D68ULL,
			0x871329D4FD7CD087ULL,
			0xDC87696060A3487BULL,
			0x775304AA50240EEBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x114D3E7124E48BD0ULL,
			0x38507770F2BC7291ULL,
			0x875EDB0E8217708CULL,
			0x46D6C12DD39AAB9FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60461864A31A1B62ULL,
			0x343532DA60B00D2AULL,
			0x77D6D91F9C787A50ULL,
			0x496C43D800B9FA9BULL
		}
	};
	printf("Test Case 181\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD639F5CF14F5CC98ULL,
			0x17EF227142354B36ULL,
			0xFF50E498E1F29991ULL,
			0x7F541CA298CDED67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x756BCF4E13A7F5C0ULL,
			0x73626CF0AF2D0464ULL,
			0xDC5FCD6B311BBFAAULL,
			0x641D8CA9A0D3CC8AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x57D5ED799F0D3282ULL,
			0x9BEF8D6B5271D613ULL,
			0xCD8EF6A848098D12ULL,
			0x146A5997EE1FBE43ULL
		}
	};
	printf("Test Case 182\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6E15704BF460FF18ULL,
			0x106B2CB826ED1E6BULL,
			0x302764B663FB9EE8ULL,
			0x6BC10CB7B7B797D9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0BB0F73E5467EC28ULL,
			0x3F32C0C178AE0FB2ULL,
			0xD0678839748F026CULL,
			0x65C2C52958F03532ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB203AD0D489E191AULL,
			0x3D3E6F0B334F85EAULL,
			0xF25D30CF7150B992ULL,
			0x1F9780A344936342ULL
		}
	};
	printf("Test Case 183\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC9550A43005C6DC8ULL,
			0xCB428B0CF36011ECULL,
			0xC2E589064A1386CFULL,
			0x5129D0092904DD61ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x23E516BAF19C9088ULL,
			0x5F43A2B4AB0B32C6ULL,
			0xC10250E9D65D38CBULL,
			0x424A335BABD81394ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0BD76F7E41C886C5ULL,
			0x0D4B554A874689EAULL,
			0xFE13F7EBBB8DDAE8ULL,
			0x55A59384ED143DA6ULL
		}
	};
	printf("Test Case 184\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE67C09FD5DB93AA8ULL,
			0x85AFCD68334082DBULL,
			0x6CC9BE15962411E7ULL,
			0x6F4A8C3F7994EF5AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3E8EF53894713E30ULL,
			0x3A471E80A651D92FULL,
			0x99A7331F353B5BD7ULL,
			0x5A6E31991E6D1D0BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD6BB557707D4AAB3ULL,
			0x8AC9E9E64D12470EULL,
			0x5CBE6741116AC109ULL,
			0x0F9C42A80249796DULL
		}
	};
	printf("Test Case 185\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA5D48266D9C64690ULL,
			0xEF38DF06D57C02A6ULL,
			0xF0EAA3C17658A6C8ULL,
			0x43AEA821C3377DDAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x46E72D50FFEE4710ULL,
			0xD131BFF328543733ULL,
			0x62715FCD3B800428ULL,
			0x4252DC160F69318AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC80A4CAF48357619ULL,
			0xA0C710DB462198F5ULL,
			0xE3431D122D9148D4ULL,
			0x0F73F8DFFD3B2BCEULL
		}
	};
	printf("Test Case 186\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD1A6BD4AA487FCC0ULL,
			0xB9D82D0F7F2B86D9ULL,
			0x9FAC6243A59BEF07ULL,
			0x629FFD4CD7416D78ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x69F39B49834B8F80ULL,
			0x7199E03C2B4E1D8FULL,
			0x718B045461CA4468ULL,
			0x65CFDEF343CE57B5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x83A65742E2156B82ULL,
			0x8E32D4316EFE927DULL,
			0x677DBAB7AB82401AULL,
			0x1A72DD6730E262A9ULL
		}
	};
	printf("Test Case 187\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA0A689196995C910ULL,
			0x31544A5558A0CD84ULL,
			0x7E5493E11FE4D36DULL,
			0x44966292D14F3235ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x403FF894D4AD8950ULL,
			0x5CCD1DE667AB25C3ULL,
			0x536D74A5AB48F60CULL,
			0x4FFDC65FA965C914ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8635F7A755BACD42ULL,
			0xD8E53FE7C0ABB269ULL,
			0x6AD82DAB382D5350ULL,
			0x24ED487583D8E3F0ULL
		}
	};
	printf("Test Case 188\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD1142153E828C7A0ULL,
			0xD8C93040C127DD8CULL,
			0x7DE8B894DD817DECULL,
			0x4A18192FA7C63F30ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x61A86772CEAD7100ULL,
			0xDDEB27A0F1D55639ULL,
			0x35636236E1A50583ULL,
			0x540D9541286FA761ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x564905FB85752BD8ULL,
			0x5E4F175156052CD7ULL,
			0x738C8D2272907C3DULL,
			0x1924E7C5A5AEBFEFULL
		}
	};
	printf("Test Case 189\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6AEF02E69B868050ULL,
			0xD95BF5575135B07AULL,
			0xC1D48A56FDA43312ULL,
			0x6FA265646F058C30ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD87091B2BBAF7C80ULL,
			0xC4782B929C994D32ULL,
			0xD234143AEFCCBD8BULL,
			0x6DE23C91B70C7738ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD71AD3978A28FD54ULL,
			0x9A444BC0F147DD29ULL,
			0xD060595E297AF4D5ULL,
			0x43F12E8C8106B141ULL
		}
	};
	printf("Test Case 190\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7D412E43F736E318ULL,
			0x0CA7648D4FD5E1BAULL,
			0xB61725C2775CDF04ULL,
			0x47671AD9289B842BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCF352397EBDE8008ULL,
			0x14B2EA8C913035F7ULL,
			0x96573E2E1FDED01EULL,
			0x728C73FAE7746AEEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB8C3BA8828B0131BULL,
			0x7AB2E24EA35C3857ULL,
			0xB6E835032C09BA64ULL,
			0x041515632C288BC4ULL
		}
	};
	printf("Test Case 191\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x219297BBBB80FE70ULL,
			0x43680E897E2D0D43ULL,
			0x1CA5BAFAE7DC1D55ULL,
			0x7871239B04897D0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE797EFD490B9EB10ULL,
			0x5541CE22292B7B4AULL,
			0xC36665954D1EF6E9ULL,
			0x5BA6E98BC3595797ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x45446E017E71B43DULL,
			0xE1F8E9F878E5EEEAULL,
			0x2A3BBDECB4D46FC9ULL,
			0x62D24FD7E5A72E95ULL
		}
	};
	printf("Test Case 192\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBDC9B642BB6BBD00ULL,
			0x9E26569C9AE46817ULL,
			0xEB677DD643211B6FULL,
			0x573157F440530CAAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x993FAE1F1195C6E8ULL,
			0xF386A2AB266F11F2ULL,
			0x5A8B22877877E1CAULL,
			0x4888E77117F92227ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x687488FE5E87CB59ULL,
			0x8ABBF473D9145261ULL,
			0xE5A6F1DBD0E80807ULL,
			0x4E1E267813AAE720ULL
		}
	};
	printf("Test Case 193\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6A4D5BA431ED08E0ULL,
			0x730F2EBF9200A641ULL,
			0x1A920B4ACD000D53ULL,
			0x4BB44137D51BD662ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBE03E2603F3832A0ULL,
			0xF4BB9152918F26ABULL,
			0xA45B8C0BA5C9D002ULL,
			0x7686CAB4DF734F4FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x00AE5761C83F8701ULL,
			0x638D5F1ACDA911C2ULL,
			0xC29F4422FD480F01ULL,
			0x33C68CB7FF5CA1C1ULL
		}
	};
	printf("Test Case 194\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB8A52DC54A6F72F0ULL,
			0xB63338701AEAF6EFULL,
			0x8657D38C473E46D0ULL,
			0x695DF967EF85AD96ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x32B9253B19389118ULL,
			0xDA6EAE68C9749C5AULL,
			0x3E9EAF28A34FBD2CULL,
			0x60AB5E09A3FD0E81ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x844FF639788521D1ULL,
			0xF7B0982F2BD83681ULL,
			0x8121BC1957F6E849ULL,
			0x02101FBEED8AB579ULL
		}
	};
	printf("Test Case 195\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCFFCCE707D13EA78ULL,
			0xFAF05EEE0C8AF02AULL,
			0x316F053033D72742ULL,
			0x4A709BF408714B15ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xABF60C24E5297F78ULL,
			0x3D27673CA236AADDULL,
			0x311A738F2593928FULL,
			0x7AACE8AD08BEFA0BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE7E072228D429BC9ULL,
			0x2881EC7DF9784822ULL,
			0xDCCD5976AC25D423ULL,
			0x051DB8175D452885ULL
		}
	};
	printf("Test Case 196\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x318E3EBE473D5198ULL,
			0xE8D3F877C03A6C36ULL,
			0xA7E3CAE29A18F1BCULL,
			0x427E58C4CB6C6B27ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D4316CF40511FA0ULL,
			0x7BC34E00D23625ECULL,
			0x1F44CEF09406E410ULL,
			0x7C233B5FC17E788BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEC3FDE013060DFE7ULL,
			0x64E01F81DC4D44BEULL,
			0x3CFD7B57A014029FULL,
			0x3BD6BE3AAA4B4720ULL
		}
	};
	printf("Test Case 197\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x58FF8183F75FEF00ULL,
			0x59E5ED6C284F9693ULL,
			0xF904BA8EE95C2CF0ULL,
			0x5E29B01542DC576BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8F6C61E9FA58CA78ULL,
			0x45058EC47AF571ACULL,
			0x7A1F8F8C73DF6054ULL,
			0x6E1A28839AD51F4AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE2372EA116FCBC57ULL,
			0x8A60BC6B7BE031E2ULL,
			0x1DB7E8350F8FFF8CULL,
			0x604FD58FA1E2FC0AULL
		}
	};
	printf("Test Case 198\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB7D12B7CFBE11788ULL,
			0xF0BBE5081BC2238DULL,
			0x690983159E851D20ULL,
			0x41D4B412BF4EBFB6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA4970574FD8A0650ULL,
			0xE97D0C0A27F55D3FULL,
			0xA3634D040832386DULL,
			0x54F605EAB58CCDBBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2287D3254CEA258ULL,
			0x4D450DA7FF8ACF90ULL,
			0xEF4035AE134776F1ULL,
			0x6ABF18D29D81D1C7ULL
		}
	};
	printf("Test Case 199\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA396F1869B5B1528ULL,
			0x27CD494EA854B815ULL,
			0x02528519175523E1ULL,
			0x53111B0127862E3BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x642B76ADE82A8408ULL,
			0xBCB0816D8D3ECA73ULL,
			0x14C21C5423CA0AA7ULL,
			0x4E98A6855CDB7CE8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x616BDD49B553E37DULL,
			0x21EFC185E4E921A9ULL,
			0x113F0E6341CC2AF7ULL,
			0x6B08605598C81301ULL
		}
	};
	printf("Test Case 200\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x345423C8652874A8ULL,
			0x70C14A7C0A6F6E43ULL,
			0xB7264B54D177D241ULL,
			0x5A24433F1FC6B315ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEE6EC0D13F376DC8ULL,
			0x7B852FD5F78FDD50ULL,
			0x86CA80FA3F560F2FULL,
			0x53CC4D529B97CFB6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x88A99A5F490FBD92ULL,
			0xFCA374CA0A2D3675ULL,
			0x68E3DEEE8718E353ULL,
			0x6E800AC1F11AE436ULL
		}
	};
	printf("Test Case 201\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x37C90523992B0E68ULL,
			0x8BD1FBA705A2E968ULL,
			0xCCCB2BC8EFF15D9EULL,
			0x59B507E3360CB275ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x163F1971EDEB57F8ULL,
			0x67B0C832CDDC2081ULL,
			0x9A218141884214A8ULL,
			0x43F15419C2E0E733ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB9641A16B27B9CDFULL,
			0xEA32E801B2DC3DFDULL,
			0x98C7A11E3F9B1D75ULL,
			0x38F58B71C669C419ULL
		}
	};
	printf("Test Case 202\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7680C42E280BB750ULL,
			0x123830BE4911E39BULL,
			0xE0D9282E41256991ULL,
			0x70961ED80FBC07FEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7DDBB1184A20C068ULL,
			0x36C761BDE86797DDULL,
			0x55992BF087559A6EULL,
			0x4E74F97D48CB6CDCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x228B6E8CDCF705D4ULL,
			0x3C3408AF992328CAULL,
			0x3085F02F023F4A40ULL,
			0x66127CF76F338C6DULL
		}
	};
	printf("Test Case 203\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA0DF27C06EF02F98ULL,
			0x6FD39AA15FD99282ULL,
			0xF3598C18A4FC8B33ULL,
			0x757818E5FFCDD668ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2AA6910069E237E8ULL,
			0xD54C7A9C838D5E58ULL,
			0x7930781E0FC6F301ULL,
			0x6E4E2022F5356179ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7D458E866B042E64ULL,
			0x8EFF71F65A09F9FAULL,
			0x98E14495D7CD0054ULL,
			0x324C6618AEEB59DEULL
		}
	};
	printf("Test Case 204\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x79292352FC1602C8ULL,
			0x978A9B64B5394564ULL,
			0xB3B8188FD3E8C4C6ULL,
			0x7674090F74036A5AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDFEC68B72759B9C0ULL,
			0x65616102C419A6FFULL,
			0x2F53BE4B9FB2A866ULL,
			0x7FDAD136915CC7FCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5EFDD9714E42C838ULL,
			0x0B8FD664A0020410ULL,
			0xCB8CE43FF7311D74ULL,
			0x4943E127A5C3C427ULL
		}
	};
	printf("Test Case 205\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD5DFFD599C3ED4F0ULL,
			0x86DEC159A043DA8CULL,
			0x4476803E3AA56C25ULL,
			0x6BD84059AE475A47ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5867AD2A6994C920ULL,
			0xE300CFFEC90FB6C0ULL,
			0x92F1C5BD6EA34F60ULL,
			0x73506923B30B45DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA871FC3C9B19A0AULL,
			0x3F86C67341E4539BULL,
			0xB17E5E273091B299ULL,
			0x4F6EAA4011D314C3ULL
		}
	};
	printf("Test Case 206\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x94CBB0645CBB4758ULL,
			0x8CDD88438B2CDBCFULL,
			0x123DDFB39BA0CF17ULL,
			0x76F4855DBBCA1816ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E385184FECC8A10ULL,
			0xC272AC6BC22F19E0ULL,
			0xDFCBD9F344881F7AULL,
			0x4EFBE3EB61A5C69CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA9336D6F59FB65AEULL,
			0x9EB9E03255DBF5DDULL,
			0x9AEE9F6DF5731317ULL,
			0x3CC7C7BF0F873FCFULL
		}
	};
	printf("Test Case 207\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x46C2C20C95F17790ULL,
			0x86F98FC86E72B6B0ULL,
			0xFD4299B6F8276A8EULL,
			0x598F06C14711BDDEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4992669A0D125088ULL,
			0xE6764F23356236FDULL,
			0x6F92780249A50487ULL,
			0x452ACDA997208AB7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C49156ACF0BC699ULL,
			0xB7499142F3C2D1F9ULL,
			0xFE39CA429A78EAC4ULL,
			0x3CCE4950067C85C9ULL
		}
	};
	printf("Test Case 208\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x610D7D5829A61E50ULL,
			0xFA5AD409D514A6A5ULL,
			0xF30D627921418974ULL,
			0x607A3B32CCB4EE9BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBE5F94B771341828ULL,
			0x9B50116EBE98E861ULL,
			0xD9FD5A38EECDB0BCULL,
			0x7E2CAF3D32BB8D0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x541386E1644680ABULL,
			0x0CA646EEA5665FD3ULL,
			0xCC66FC8C70AC5D61ULL,
			0x18D9DA61E8C1BDCFULL
		}
	};
	printf("Test Case 209\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x016E450B32FE5438ULL,
			0x381145F7395FA3E1ULL,
			0x9C9CEB792BFC5D6AULL,
			0x418CD4B7D8006413ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71236AB2ED1E6450ULL,
			0xBCCBD3B7FC214705ULL,
			0x5DCDF68AB52619D6ULL,
			0x5B9050DD97E7ACA2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE439FC2FF2E8F40ULL,
			0xCC825A7F8C823DBEULL,
			0x51CF72E27CA467ECULL,
			0x2383D76D106DCF66ULL
		}
	};
	printf("Test Case 210\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE437CA03BD34D3C0ULL,
			0x03318FD694A2B726ULL,
			0x57CCE6A088D976F7ULL,
			0x71DEF9BB04935416ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88EDADBD79CA6488ULL,
			0xC28037BEBBAF0E8BULL,
			0x53B91E1A7DAA7D12ULL,
			0x6CD8EEFAC0D951B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC1B9850588ADA02AULL,
			0xD7A7CF661D9006EDULL,
			0x08273770277D0B49ULL,
			0x03BB944B2EE6AADDULL
		}
	};
	printf("Test Case 211\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDE3D23D9417399E0ULL,
			0xEC29CD343EC53633ULL,
			0x94C6C6C4F62D5B55ULL,
			0x67E8A276749F0E70ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF0A5B3FC8DA80030ULL,
			0xB365476577F95995ULL,
			0xDD1876D0E379D2FFULL,
			0x5C0A6E1BDDF41C2DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0008A9B5A816FE8ULL,
			0x8B67A9394778D82DULL,
			0xA6A4980583C21913ULL,
			0x5DF9FF5767545A8AULL
		}
	};
	printf("Test Case 212\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x08F30F3914A0EC08ULL,
			0x2156FA3D867B8B68ULL,
			0x4B31F4C61AC5EDE4ULL,
			0x696D832C4D60517AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD365B47739BC1768ULL,
			0x8AE03B23360EC85AULL,
			0xD607D4A86444E24CULL,
			0x675BC64D23F40ABAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB9AFF1DFE00DC734ULL,
			0x5DE5C8C5515208B0ULL,
			0x72EF132F9649F6ECULL,
			0x222B4C511B2868A5ULL
		}
	};
	printf("Test Case 213\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x28E007CBD8C51510ULL,
			0x74B83B897DDCBC76ULL,
			0x5BA2440A831C7B5EULL,
			0x73E7F36366A54398ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBCE4BAA767EF8018ULL,
			0x7D3C941B1C34E64FULL,
			0x4B0250BF4AD8D686ULL,
			0x530BBB8D4B32BF2CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAF3D683BA0ACF180ULL,
			0xC9CC9B9686F9A00AULL,
			0x3B3BD364A2931708ULL,
			0x2F15AFEAD49AE727ULL
		}
	};
	printf("Test Case 214\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0641E11AC4A40B90ULL,
			0xB6D89814858C0104ULL,
			0x396E17AFEFF181D4ULL,
			0x4F2DC01A1E657552ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7B3BAA18BB534A18ULL,
			0x494C312C9CCF248BULL,
			0x189E45573CCDD457ULL,
			0x6FEF9708233EE2D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA09EE2C027956C18ULL,
			0x401D8825B4DA5BE4ULL,
			0xC7E37239DA01B6F4ULL,
			0x5BE67924B17440DEULL
		}
	};
	printf("Test Case 215\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x61CD1301CBEB36E8ULL,
			0x716E3C064EBC19F5ULL,
			0xBEF2EE86E7BA0A5CULL,
			0x6A850503649F544FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x29DBB721FEED80E0ULL,
			0x6E3861D8C77DC4A7ULL,
			0x72FF9DA0D0D908FEULL,
			0x60BB91E530EE37DEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x35B875D11A5DE114ULL,
			0x2DA8DE08A7C2C7BBULL,
			0xD3B1317C9B8AFAACULL,
			0x7E04300649CC73B0ULL
		}
	};
	printf("Test Case 216\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x55E555FF3B2A38C0ULL,
			0xF9198CF04EDFD3A2ULL,
			0x4F8376F31132A50EULL,
			0x6B72F8DF1283BD8BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9FD2083C4909F000ULL,
			0x9719001CAEC6987CULL,
			0xBFE021AEA5FDA99DULL,
			0x7592A71A092BDDB3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD610FD5B6B2F005BULL,
			0x3632AB9830504C98ULL,
			0xC0E5F2D86EDF2E6CULL,
			0x3509CCB00A3F39DBULL
		}
	};
	printf("Test Case 217\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x32B4A6BE49387450ULL,
			0x18A6D88EC3BC7EE4ULL,
			0x126A043E107FF489ULL,
			0x7887CFF6CA2BB39CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x01DCCB3E69782770ULL,
			0x5EA9415C34DA34D3ULL,
			0xDA9E77AC6A792378ULL,
			0x7D4C15846DE6B5ABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAB2AA3DF06065284ULL,
			0x416CE6F28B9CA85DULL,
			0x1EE53ADF2EA3338EULL,
			0x0DE89A8DFCA78EA4ULL
		}
	};
	printf("Test Case 218\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x953F737334EF0318ULL,
			0x427A7EF523AA995EULL,
			0xF371370BB05F9C8FULL,
			0x5174F36FADFEA8E0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x604B31E550FCE598ULL,
			0x1772E51D72D65A9FULL,
			0x65EEF8A835589472ULL,
			0x492A4CD72B2BC047ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x65D94A4DD00E560BULL,
			0x44285AAA8FF31D75ULL,
			0x53313A15057CC7CEULL,
			0x7AF96610EF1FEE6AULL
		}
	};
	printf("Test Case 219\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1163B646020C7358ULL,
			0x75FF074B71F9EAD2ULL,
			0xA33D8AC8EBF800BFULL,
			0x7605423ECFDA7AF2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x12675BB28FF8D190ULL,
			0x4EE6AD5FB8009F3FULL,
			0x967AE250E225AF7BULL,
			0x4DAC3DEEE57FB11AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x386EF5D87193EE1DULL,
			0x2C460E0FBFDDCB74ULL,
			0x54049EFE5E39F084ULL,
			0x7B8E34C57D476259ULL
		}
	};
	printf("Test Case 220\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x50CAB6763F275650ULL,
			0xF19F08FEAC0E9411ULL,
			0xF56C19A56F4A8426ULL,
			0x5747CFA3BC368A4CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x40683F2727FEB3F8ULL,
			0xB00F8AEA0E5C5084ULL,
			0xB896FE4906D3E058ULL,
			0x67CB0F3F5F45306CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x649573F6086015F0ULL,
			0x4E1F30529F825DDEULL,
			0x8BA6ADD3952B2569ULL,
			0x66B436406101A0DDULL
		}
	};
	printf("Test Case 221\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x121A020F9F1A2BA8ULL,
			0xFFFEF3CE25C6CD77ULL,
			0xF14A21290426054DULL,
			0x53EF432706ABC5B6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x713B247687E6E230ULL,
			0xBFB00CC9867957A5ULL,
			0xCCDCCBDD1DA235B8ULL,
			0x49E4D72CED9696F3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x652264857068D93FULL,
			0x9053902D9CAA335BULL,
			0x47E196115A5C7BD3ULL,
			0x78AB9F96FA098477ULL
		}
	};
	printf("Test Case 222\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD8C61285D2F7FA40ULL,
			0x85840EC3789B6F47ULL,
			0x4B552A837ABC202EULL,
			0x585DC7C439ED9ADCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEBEE96A2F41AC2B8ULL,
			0x74E03E6E965D34F1ULL,
			0x80D5C633E13E797BULL,
			0x54CD9CEF6B96B891ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x44DDFAA58E66AF49ULL,
			0xE3546975299B995AULL,
			0xFDBD1626F17F37CDULL,
			0x04B156463AC7C29BULL
		}
	};
	printf("Test Case 223\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCEE65EDA09B3F200ULL,
			0xFE41B99DD67987F2ULL,
			0x7930A26BED9A3F04ULL,
			0x5E952EDFDA2AD24AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x172FCA9484EB6480ULL,
			0xABBC6DA6070D0A5EULL,
			0xAED5C487320D70D9ULL,
			0x4409C3448A020F86ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7FE0F1D543264783ULL,
			0xDA48D964D784ED43ULL,
			0xA3810EA329EE5F5FULL,
			0x02275B1FBF512D89ULL
		}
	};
	printf("Test Case 224\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8EF90DF538E10518ULL,
			0xE75BE838A471FFB7ULL,
			0x5A3097D72BA72842ULL,
			0x7FC4139B3C83999EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD2D3943BD818BE28ULL,
			0xCFCA4BD6170E5A98ULL,
			0xD1448D1B1D984BFAULL,
			0x768CC78690A54939ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x92AB5BE38B63A806ULL,
			0x2AB7CC8462B66F9FULL,
			0x63CED163F1205BA9ULL,
			0x0B44BB4A0DB7552FULL
		}
	};
	printf("Test Case 225\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF65ABE39FFC8D6E8ULL,
			0x9EDB3CDA15D406A4ULL,
			0xDE3A6FC07C1740F6ULL,
			0x65A5280830271BD7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x66B1CCB7B10AC948ULL,
			0xCB0D9764DD39B368ULL,
			0xF0D3AA44294F369CULL,
			0x5395195343D20B07ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x28670169FF0DD434ULL,
			0xEA75C35644E3A0F2ULL,
			0x09B10D1D8E13787DULL,
			0x657073B8F7FC14ECULL
		}
	};
	printf("Test Case 226\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7ECF649486B01638ULL,
			0x96EB6EEFD4D12DD6ULL,
			0x3E499917F3D52CDAULL,
			0x4651779AF8C9B531ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD4FED6DD695438B0ULL,
			0x968012E7125BD9D2ULL,
			0x8C923489889C1DCAULL,
			0x582A36FA89706504ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x277224D6CEB07F30ULL,
			0x55CB921CBE0C3FC3ULL,
			0xBDC1FD5DC2DB29C3ULL,
			0x110430DDDCE3DFD5ULL
		}
	};
	printf("Test Case 227\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA29B1346EC7ADA78ULL,
			0x447389F36A166C2FULL,
			0xED87BEC58317B58EULL,
			0x4674B1494BD7E982ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x53A25D476F226840ULL,
			0x6373FA86682200B5ULL,
			0x6EDD7C25FD6C3BF9ULL,
			0x669859F726CBBF08ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDAB508FCC28398BBULL,
			0xF9BCAE3E970461A9ULL,
			0xBFB5E0D62A3C749AULL,
			0x48D81FAE695C6485ULL
		}
	};
	printf("Test Case 228\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAC01CECF8DE94360ULL,
			0x344B4D58797C51EBULL,
			0xCD9CAAFE1EB946EDULL,
			0x631C6CF6EEFDF99BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x331097C73A7329B0ULL,
			0x8B21BEF2A583283FULL,
			0xFCBD7D413C9A2B01ULL,
			0x5990667E8A432B8BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x66B156903AA3A302ULL,
			0x80869F954AA3C4E9ULL,
			0x725DB9B280571F4EULL,
			0x0AA7B164D67D9021ULL
		}
	};
	printf("Test Case 229\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x33C926B65C6F8210ULL,
			0x3BBEED2C52C0FB63ULL,
			0x585143BEEA25A647ULL,
			0x51AB91A6CEE107FCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD26F7A11DD791E60ULL,
			0x81FDBA9E8CCEFD74ULL,
			0x87D4F50204A3F674ULL,
			0x4D6D7353F684DAFFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7845D73CF2C1A896ULL,
			0xB697BF5BE73A2011ULL,
			0x4D1C8852607B9C74ULL,
			0x7EA8193268794138ULL
		}
	};
	printf("Test Case 230\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x80D1EEF454DC5DB0ULL,
			0x0CE6F1E792A52D77ULL,
			0x999955F5CB96CEB5ULL,
			0x5669702F12B425B7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x75BCE9D6852554B0ULL,
			0xC6DD0268AF599744ULL,
			0x5A246F9EEF83FD94ULL,
			0x5BB5F9D2945D785AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE0FC3658BB8A915ULL,
			0x5C6C59DED319CFEDULL,
			0xEA29AE19B0EF7AE0ULL,
			0x1A7F3DECD641BB5EULL
		}
	};
	printf("Test Case 231\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5950AF41FECD6AE8ULL,
			0x4A68ED10600294CAULL,
			0xF5E171AEBA8273B2ULL,
			0x4A0263CFCDC7E476ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF2B64F711CC2CA8ULL,
			0x17568FD43E903CD5ULL,
			0x3FE2A31871DA85EAULL,
			0x55674C320A897F8EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2068F98F16D357D6ULL,
			0x758958E41B16EA0CULL,
			0x964030D85FEE5913ULL,
			0x7ED21D6628854CB8ULL
		}
	};
	printf("Test Case 232\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4978C9EDAEEA1AA8ULL,
			0x1673AB9322399083ULL,
			0x55AFB4B46D8DE42CULL,
			0x5B9AD230D055CB5CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8B989A55560FE1D8ULL,
			0x2C9A66785EE6C006ULL,
			0x105ED2D49C9D2ED5ULL,
			0x480D5C406067A1BBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCB23A7EB3785C2B3ULL,
			0xF17DD40284DD114EULL,
			0x4898F2AD9D390103ULL,
			0x0E9A4B8233629210ULL
		}
	};
	printf("Test Case 233\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x61A3B2EC1D452A58ULL,
			0x36E58E9CCED97F39ULL,
			0xA22695AD891C24D8ULL,
			0x4EF9124C67D29818ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9BFB9B6DDB069960ULL,
			0x62F4A2B647A1AE9AULL,
			0x526DABCF8D4BB48FULL,
			0x4095BDACD4ED14F2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x803B332875859EFCULL,
			0x112B3A6C163683B5ULL,
			0x2E7CCC9B310611E0ULL,
			0x162BD3A201DED32FULL
		}
	};
	printf("Test Case 234\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE5492E5BDD437F40ULL,
			0x79E316D8558B24EFULL,
			0x16FE5BB09E20CB68ULL,
			0x4C45B17A3D73B46AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA939352093F6F650ULL,
			0xEB60891AC9808E1FULL,
			0x08CA784C3CC38B68ULL,
			0x50923CC8CD330532ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB838B960CC12C78AULL,
			0x4344094FC546E3CAULL,
			0xCDE0B1C8FEC0B858ULL,
			0x4B42F67406057B37ULL
		}
	};
	printf("Test Case 235\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBB07FCAE2BF84F18ULL,
			0xD60A128A486B9414ULL,
			0x8430940614829D23ULL,
			0x7BC4436F9C78F2E5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x008B1CE6C41C8048ULL,
			0x67AC7C0FA2092D78ULL,
			0xFED39FA0F8CAEC84ULL,
			0x54CF5C12F0CE7D06ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37087D0FCF63BF64ULL,
			0x6C5DCF0A7DF72AB7ULL,
			0x9552FD56C8AD4D89ULL,
			0x66D55B86C5904B25ULL
		}
	};
	printf("Test Case 236\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x07C0847D28E43338ULL,
			0x60244DDC57B661A9ULL,
			0xFFE0A2EEC291AD10ULL,
			0x62F1F7999A894A9BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD79ECA1347ADFEE8ULL,
			0xA71B3567AE643BC4ULL,
			0x1BB7FE040A6FF0FDULL,
			0x73B34717453B3A0CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC3CCAA48E2E0CB5FULL,
			0xDD7C1837C2453772ULL,
			0x11439DE2123A78FDULL,
			0x6FA4120D0FCA86C3ULL
		}
	};
	printf("Test Case 237\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA0431E75FB8FEE58ULL,
			0xBC430259BDDBEE8BULL,
			0x130906FC82978AF8ULL,
			0x7F2E384529EB773CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x954180AD347181D0ULL,
			0x16F499A6AD9E5A61ULL,
			0x701C749810483AC3ULL,
			0x4EE741A553B6656AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x26773BC3DEADFD9AULL,
			0x7148E1D73D54947CULL,
			0x516BD69B91DF0F96ULL,
			0x0EF5B25776BD7830ULL
		}
	};
	printf("Test Case 238\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCCD52D91DB9A51D8ULL,
			0x4EB48A1A8DE42C1CULL,
			0x1FA5FBDF25758EF5ULL,
			0x51A4621173239776ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x66B843214F7AC748ULL,
			0x05747D49AD29FB5DULL,
			0xD771939EDB39F2ACULL,
			0x61BA89F788E288C8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B1B694FA4B682E5ULL,
			0xB185DDA7C006597FULL,
			0xDB21FD184E2C5E00ULL,
			0x4588D40FBB30A47BULL
		}
	};
	printf("Test Case 239\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5FD374BF038CB8A8ULL,
			0xC781D424F389F1C4ULL,
			0x06ACEDF00D320AADULL,
			0x5407ABABF6A9C137ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72DDB4DCA3797050ULL,
			0x7A142E4C78B57D66ULL,
			0x86A3D22A3C4A45F6ULL,
			0x74337AD0EAD43793ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x15D0E3E12A393E31ULL,
			0x38395D15D74EDD88ULL,
			0xE305E61EA6D1F17AULL,
			0x54A6D63DCD93364EULL
		}
	};
	printf("Test Case 240\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9740FC5632FC4778ULL,
			0xF994263D4BE169A2ULL,
			0xB8BBB8EC999777C6ULL,
			0x7F5C9BF52FC496BBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA516B857E41BAB8ULL,
			0x871739EBC08002B5ULL,
			0x9EB35ED89B5A38F6ULL,
			0x77EECEBBA2C3D9EEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x23BF508C99130CB0ULL,
			0x8F5C1951AA2FF498ULL,
			0x2AB131D9DC7BB3F7ULL,
			0x79D3E7B82CE06617ULL
		}
	};
	printf("Test Case 241\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9555EF961F0C2538ULL,
			0x600086496D6F7217ULL,
			0x359B7E4E30C1BFA5ULL,
			0x762407BC38378960ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E64BF27A5462920ULL,
			0x5C6CD6920EDF1544ULL,
			0xDB606DA957D5ADAFULL,
			0x6879E144DA3253A0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E78862E1E2FA690ULL,
			0xC2B403809A28A24DULL,
			0x39F1D086F75ABB0AULL,
			0x27B2504778A6B902ULL
		}
	};
	printf("Test Case 242\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x61F33B3CE3B0F550ULL,
			0xB9F1AF9E16809D37ULL,
			0x03A62E8955FB1C17ULL,
			0x596316726EA78145ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF2920CEC46B1BA18ULL,
			0xC3CCD6F5AF254CA9ULL,
			0xBB232010CA55F0B2ULL,
			0x6A2A7A7B478BCD7CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x707998A711D2008AULL,
			0x3C33A9AAC5244ACEULL,
			0x0835ADB5C1A47780ULL,
			0x729FFC55F131AE06ULL
		}
	};
	printf("Test Case 243\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x83B146E6B4BBC6A8ULL,
			0x4FF536942681FA38ULL,
			0x1805DF63072FE8EAULL,
			0x76716B31CFF7A606ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8468AC2188D4A2E0ULL,
			0x29FF0E15472C3D41ULL,
			0xFDC1B9F2A9A8F7E6ULL,
			0x670A13CCBA2FA5EFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD195674023783C20ULL,
			0x19BF78911742A53DULL,
			0x8A7295D6F8BE735BULL,
			0x27E37AA97CA42F03ULL
		}
	};
	printf("Test Case 244\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0CAD29261AEFAF40ULL,
			0x5A930E444423D2F5ULL,
			0xDCD6E7FC04F8C6F5ULL,
			0x53D13D1B3FA8ABF9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x82E81AF2A9046670ULL,
			0xE3341F62DEABBB98ULL,
			0xB74B780CF4E567FEULL,
			0x6FFB9209AAA76A04ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x054F11622A508D49ULL,
			0xAC07E557E0A5CD64ULL,
			0xA23911AFA3F7A26AULL,
			0x06BEA0BD338F1D04ULL
		}
	};
	printf("Test Case 245\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB1DD1676605B11B8ULL,
			0x03EB3D3B7EF564A0ULL,
			0xCA81DE959F606746ULL,
			0x40C57655D4874522ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x76F5C5CCF31E7718ULL,
			0xB84ABC89FCE97802ULL,
			0x293830B511D1B076ULL,
			0x6528FD52F85602F0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x18338F59458E8136ULL,
			0x513DAF337D1F7158ULL,
			0x3EEAA61321DB8EEBULL,
			0x68EE5AEE6A871BB7ULL
		}
	};
	printf("Test Case 246\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAC4F967F4649AA10ULL,
			0x69A43729823DB379ULL,
			0x7E5EEAC566EAF03DULL,
			0x7E68CB3FC40FD37BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x33EFD3DC40ACAC10ULL,
			0xEA83AC7A099EF6CFULL,
			0x761E840FDFDD2421ULL,
			0x7B36A4BAF00047DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB665F543E718C035ULL,
			0x5A3F94EB30D34058ULL,
			0x8262C25A55CDE53BULL,
			0x0ACEF3A000844BE7ULL
		}
	};
	printf("Test Case 247\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x48241ECE75D13CD0ULL,
			0xFFCC787778D8C133ULL,
			0xB7D838D091AB39D4ULL,
			0x65C92229F54E8B2FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCFC80CD23317CEC8ULL,
			0x850A1D24D77E7F8BULL,
			0xF23FD0B4473739AFULL,
			0x647B7217453DB780ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x29DB46C26F192F07ULL,
			0xEACF736B85006B0DULL,
			0x47B7EB066144027EULL,
			0x2A1EC28AA6DF0E3AULL
		}
	};
	printf("Test Case 248\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7A256C3C39FD4370ULL,
			0x64106630296B47BAULL,
			0x80E28755E3E154EFULL,
			0x6D945AE93FF77E60ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2D6C21068CBCCD90ULL,
			0x2BDF6E26BCED8F18ULL,
			0x81DC96B0F6DD806CULL,
			0x6B7BF3119E97AFE5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5D5C737F70457EC4ULL,
			0xFE2AF9DF18E01938ULL,
			0x6F6C2A02D2DE3DF7ULL,
			0x15453504EDA59320ULL
		}
	};
	printf("Test Case 249\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDB8BE4807A81AB28ULL,
			0x67563574BB511673ULL,
			0x6946E0011933F3F5ULL,
			0x66C16A821402B716ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x14567B06E3644D50ULL,
			0xEA0A07AD730EC124ULL,
			0xAA12F0A6DFD25295ULL,
			0x49F9995FE1E6D9B1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF4C3339209E253E5ULL,
			0x997DAFA3A8D93AEAULL,
			0xEB27B42372A27F69ULL,
			0x6E42C9457F21204FULL
		}
	};
	printf("Test Case 250\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x35BD9E4F4B26A948ULL,
			0x809621BB094517CEULL,
			0x8688BB6DC3869643ULL,
			0x4FF027C21C41B726ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5DCFA65AF0E56380ULL,
			0x6B554CDF5B01BE0DULL,
			0xB74E1B5F545AC804ULL,
			0x4B9A693E4C4AFFB4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x292874860E62EEA7ULL,
			0x0D95A8C77E311E60ULL,
			0xAB80328E72E1A7BEULL,
			0x3930081D419DC6BAULL
		}
	};
	printf("Test Case 251\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x05BA96E2DE048F78ULL,
			0xD99FCC7D7A7E167FULL,
			0x3361B36640333236ULL,
			0x6D0EDDA7E3C1A1CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71D6DFFEFE367CE0ULL,
			0x0075B51F62E6C698ULL,
			0x1EE1C823517F8F42ULL,
			0x7D14142937B00ADBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEADEF4F19C37258CULL,
			0x1D6A7A437C0DCA8CULL,
			0x3B8BDBA6135F3D4AULL,
			0x019EF2A9E7B3AE3AULL
		}
	};
	printf("Test Case 252\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFDA7DC98C306B730ULL,
			0xBB042B6DE5B67216ULL,
			0xDDBFE04CC2DE3348ULL,
			0x4EA1503F8C185868ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5D17D0A95C96C490ULL,
			0x3924E35C84392180ULL,
			0x2F6AED0243957FF7ULL,
			0x7CD6C5865A3E2D5FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE73BE68EC6F9F510ULL,
			0x605EBC48D3BD3227ULL,
			0x82046434FF2EFA6FULL,
			0x4C0FE95BCF02E2E1ULL
		}
	};
	printf("Test Case 253\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x463E0C7A5A6D9338ULL,
			0x680CE2E22A8CA1F2ULL,
			0x1274BDEF28BCD54BULL,
			0x72497535BCF9A87DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEF69E06027A5580ULL,
			0x088FBE5324AD5D82ULL,
			0xDF447AC78FA7D7CAULL,
			0x602DE845871733F5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE201F10603DE9DDULL,
			0x6B126F0B9DD1AD81ULL,
			0x8DAEFA86D1B29256ULL,
			0x4639C4756943C347ULL
		}
	};
	printf("Test Case 254\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0DC05AE961D040D8ULL,
			0x8ACD7244C0624996ULL,
			0x42736F53DF64F4ECULL,
			0x5EFFA5D894124831ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD70CBFB6207E0110ULL,
			0x88C4DDBC6726E170ULL,
			0x99C726B5262B5549ULL,
			0x4FCBBB1324579DEDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF707641FCB2CD080ULL,
			0x34E2C716A6673E7BULL,
			0xE5A54765325A8FADULL,
			0x5F92F781C07C2781ULL
		}
	};
	printf("Test Case 255\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEACCB71B9CD021E8ULL,
			0xC783F5FF185E0973ULL,
			0xB6DBD72645F83B79ULL,
			0x42100BE1403FCA1FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAAF352A2BA34C318ULL,
			0xDE4ABFAAD4A1216EULL,
			0xD8194501D3226188ULL,
			0x7ADB99C553058B64ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x284A7FD8D7106F49ULL,
			0x6CB04781EFD3921CULL,
			0x945835777148A043ULL,
			0x7934008A00E0C8CCULL
		}
	};
	printf("Test Case 256\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x065D1DFC0AB8BF70ULL,
			0x597A77047F610396ULL,
			0x7E85A02CAFD19687ULL,
			0x4E6FEA01F5C2335AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1105721E1115D6B8ULL,
			0x0E480D428857187CULL,
			0x49C35D7027A5AF2BULL,
			0x72C16CDDFE26E456ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8593B21218E0710AULL,
			0x978E2DEC9824B98AULL,
			0xF0355F1EAD1B901DULL,
			0x3B87E4129C437879ULL
		}
	};
	printf("Test Case 257\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4B69E537687888C0ULL,
			0xB02BCADFDBD5F080ULL,
			0xA7B670EFD77F58BAULL,
			0x6C0BA1F14C3BF3D3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7623471D1ED68D48ULL,
			0x6652D93E047F85FAULL,
			0x05D67B914B61F201ULL,
			0x7637E62EA3487253ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA34441C2B3E92FBDULL,
			0xE35AC8BC8316932EULL,
			0xFF5374D5B0E11D2AULL,
			0x22300243D6A19FB6ULL
		}
	};
	printf("Test Case 258\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3A5B85D8D78348A8ULL,
			0x6CB4E8E3AC90BB42ULL,
			0x92E47A2CE8FB1911ULL,
			0x519C55F02DF12602ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBC3CBD9906CE4EA0ULL,
			0xF4E7C0FB2D823603ULL,
			0x3D842EB754261DF7ULL,
			0x7591AF12BA2C94E3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC51AD919BBFFEBCDULL,
			0xD86090F25C1477D9ULL,
			0x9381E4477049CDEAULL,
			0x51397B6DEAC440E7ULL
		}
	};
	printf("Test Case 259\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x21B2004B2B386288ULL,
			0x68B7CED609B35FE1ULL,
			0x2D682107A170D9C5ULL,
			0x6BE9DF380BDD76C9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2E61C1F48CA17880ULL,
			0x41475CEC72AE7E3EULL,
			0x7FB6857F12A1BC58ULL,
			0x4E2BB436C4070A21ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x80D33667CFC5DF7CULL,
			0xC75EC23FA9EFF9A0ULL,
			0x1764B2911C90CD33ULL,
			0x2263A640E8CB011BULL
		}
	};
	printf("Test Case 260\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5555F3345A22EBD8ULL,
			0xA612329E41FD96A5ULL,
			0xD6B94EB6253E4A12ULL,
			0x5A7F54302B6E4EE3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B5D2775CA097550ULL,
			0xF9901B2DF5A1E6B6ULL,
			0x80E052BA146EF99AULL,
			0x66F2E33320DFAC7CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFB6B227E23099F64ULL,
			0xA6FB6E52E8AF81E8ULL,
			0x4C579424C902DD76ULL,
			0x2BF5F442A34169A1ULL
		}
	};
	printf("Test Case 261\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEAB54C8499E3CEB0ULL,
			0xF3395CEE20AC4898ULL,
			0xFABC5D3285FCBBD8ULL,
			0x5B15C2B56CB06C50ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCDFBB1D4784692D8ULL,
			0xF81DB2D0FEB2D9E3ULL,
			0x5ABD046DA1BB3E16ULL,
			0x72FC5D934DCDBF0EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6D120010D6056483ULL,
			0x18AEDAD1E892D100ULL,
			0x803D1BDC8A22A60FULL,
			0x585FA0B8F30F28F5ULL
		}
	};
	printf("Test Case 262\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC4CF3909E3292CE0ULL,
			0x0928735DBD630FC8ULL,
			0x6EAA9652340E8EE3ULL,
			0x6B857536A9232F63ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x113444BBB50355E0ULL,
			0x4235D152AA51D730ULL,
			0x422C23FD14233C11ULL,
			0x73B46B719D65FCECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x290F278134F69B58ULL,
			0x8F78954C1F25F545ULL,
			0xF37260A32E64FA0DULL,
			0x74C2CB2C0357059CULL
		}
	};
	printf("Test Case 263\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5B522F544E3B1568ULL,
			0xA5140A1B62B378FDULL,
			0x2FC9873AE28BA33BULL,
			0x49F67EBF9E8B0C18ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDCB5900AE8DB4700ULL,
			0x01462F17A6186069ULL,
			0x9401F1E100E440D8ULL,
			0x700F295F8D19D28CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9D46D0A771A72981ULL,
			0x33A336BD9EC5DFC1ULL,
			0xF7035F71D6E16939ULL,
			0x6893FEB386C89673ULL
		}
	};
	printf("Test Case 264\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB2180D2DBAAEB168ULL,
			0xA668762CD8A3A7AAULL,
			0xAA3613E3B9B9DBB9ULL,
			0x4481D1F1F2010070ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x02FB876C497F29D8ULL,
			0xA7670056F02A1A23ULL,
			0x00C8EEDDE43C09F8ULL,
			0x42848C2746DAB4FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1B894DA07F78E13CULL,
			0x30ADB968EBCFF7E0ULL,
			0x27DD54D041C39417ULL,
			0x5A9D9649C1ED99D2ULL
		}
	};
	printf("Test Case 265\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB4B8D25D5D9BFDD0ULL,
			0xC78FEF0A4879B609ULL,
			0x7748B62B99FE0F85ULL,
			0x49DE341850512E58ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x98239841EDCB5D60ULL,
			0x65E30F56CF98DE02ULL,
			0x77DFDA66B8C415DCULL,
			0x73178A2E7ACCB946ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC0050D2FC641DE5FULL,
			0x3A07A898AF7A0D20ULL,
			0x6E4933CF5F3780EDULL,
			0x1F978FAFF6A8F03BULL
		}
	};
	printf("Test Case 266\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x01B4F1A968537F58ULL,
			0xCE730ABDE0836B64ULL,
			0x9C9D3169431DF317ULL,
			0x76938262A8558C51ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB1A02ABEB0C9B9A0ULL,
			0x9430BE2F856A075CULL,
			0x41A7238F343F2B2CULL,
			0x4D7A4B4963372634ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x69C8636A865B8E58ULL,
			0xB5D08A6B77CC0C30ULL,
			0xEEECF8BB0DF10E27ULL,
			0x455F27C89295F7E3ULL
		}
	};
	printf("Test Case 267\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD9B3937DE055E5B8ULL,
			0x5C0AC2A45C5D9D63ULL,
			0xF01C39DCBBA298B5ULL,
			0x504430BA4121CDD3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x68ED2C9CC1D5C2E8ULL,
			0x77ED7075EE745281ULL,
			0x46AF01AE99DDF50AULL,
			0x45780A359F5B9456ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x620EC2B9D6CD6514ULL,
			0x787CE5D80200940EULL,
			0xA7A27219F1FD467DULL,
			0x071AAE6E3B41DF68ULL
		}
	};
	printf("Test Case 268\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6BB7854C3B1CAB90ULL,
			0xC87D0F337742F539ULL,
			0xE96CC0842BEC114EULL,
			0x568B53F0C8D66204ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F7F89EED9F29148ULL,
			0x06AF737DCC7F181DULL,
			0x451227A62D11C586ULL,
			0x6FE703ADAA2AB998ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4EC6024AE4E26DEEULL,
			0x251979D65D10E9F7ULL,
			0x3C3CC6D31FFF039EULL,
			0x280DB4A2C3CD34F3ULL
		}
	};
	printf("Test Case 269\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x91C5C88735012360ULL,
			0x7E4E95536345134AULL,
			0x9FD630167FD02131ULL,
			0x4A55D42782BFFB53ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x07853CC0455DE020ULL,
			0xD638CCA66AD808A6ULL,
			0x3A75E58568F17EF9ULL,
			0x7DCEF9C06518348BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x437549F2CAAF97B6ULL,
			0xCC4EC08C10F9FD1CULL,
			0xC9676CF0B75634A2ULL,
			0x3F9A3E9B11C5ADA9ULL
		}
	};
	printf("Test Case 270\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAE25D67357946D38ULL,
			0x52A08FF2D54909E4ULL,
			0x881A18B6A90C9690ULL,
			0x57094067A3ED502BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x81BDF51ED779ECB0ULL,
			0x16898327D43D92B9ULL,
			0xA233FA0182699025ULL,
			0x7D1FC678F0316DB0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2A91C3B4C48D80A5ULL,
			0x3A0DC324755EE42FULL,
			0xA0862D1C11392678ULL,
			0x533494BA5C3469A7ULL
		}
	};
	printf("Test Case 271\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x86A03DFEEEE93E98ULL,
			0x54123E273554600FULL,
			0xF949070058C734A6ULL,
			0x72484C0D3606C7D2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0EEA3BCE8424D338ULL,
			0x43A19AB835C62F43ULL,
			0x689320D55D1DDF1AULL,
			0x495957A006D936CDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2CF95B46BEA3CF0FULL,
			0xCE9381500CD156EDULL,
			0x4A6F731CC5E0763BULL,
			0x062B80070DD3ADEAULL
		}
	};
	printf("Test Case 272\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF5EA200B771D3538ULL,
			0xA042C4B70B71893EULL,
			0xE75D1C90475BF7C7ULL,
			0x79A90C528EDFE4DFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8FE956D347C526B0ULL,
			0xC938615BCF4709D6ULL,
			0x52162ADF8A4E75FEULL,
			0x59CC9D7D9C823F65ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2466AF96F7A8FF8ULL,
			0xA14C4368A1B21B9BULL,
			0x87C3A4872A385FDBULL,
			0x10C51F7C83B9668CULL
		}
	};
	printf("Test Case 273\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFBF9FAFBC74A9FC8ULL,
			0x37EBD8F939090BB2ULL,
			0xE5E5BF199C4C42DCULL,
			0x7B65B26ABF327C0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6340E7E943DAAB00ULL,
			0xF4B2EBE767BF28B6ULL,
			0x9603337441E2668CULL,
			0x51410E06ED9B9B0FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x602B0DC89B02EBB7ULL,
			0x93B0749F6F50E91FULL,
			0x829E008D7C570A2BULL,
			0x0B74D43249DCCDA4ULL
		}
	};
	printf("Test Case 274\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8B2C5D9B8D0DE2A0ULL,
			0x6142C1DFA583F094ULL,
			0x6CD4E15D267E976FULL,
			0x4EAD88EF77D0DB95ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF051C067553B9660ULL,
			0x2504C926D8C7A3E3ULL,
			0x5179DA013ECB9E65ULL,
			0x79ECB133F9D148B8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7DC4224F620EE9E1ULL,
			0x9E23E02EB8C52B8DULL,
			0x3697E9228676DF95ULL,
			0x7DE680A63968BB8DULL
		}
	};
	printf("Test Case 275\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD32C05E58BBE1FE8ULL,
			0xD612493EBFD1A767ULL,
			0xAEC62681EAA40349ULL,
			0x6327B79E3C4F22FBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C9BC3199FBAB5B8ULL,
			0xC0C81060F00F0AA3ULL,
			0x5620FE079B84BCD4ULL,
			0x6A184A5A7CD2BD46ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7CDDF966012D7C15ULL,
			0x0F7DBF3F0A6C3F55ULL,
			0x753EE07BD089F925ULL,
			0x2F6901A01C9E3D50ULL
		}
	};
	printf("Test Case 276\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE6A679F60678AFF0ULL,
			0x1E12F4FCF7DE8359ULL,
			0x7566E27BABCC5F62ULL,
			0x7D0C46B26A9A1D81ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB2409BE5C74B2C70ULL,
			0xBC25A9D1EE0F0449ULL,
			0x7C0DAA7EFFB610BFULL,
			0x7603E40552862054ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0A810E9A2D561D77ULL,
			0x01E9464BF635C8FDULL,
			0xA68224ECAAD20F5BULL,
			0x0E49FFE3061BC00AULL
		}
	};
	printf("Test Case 277\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDF17164440639930ULL,
			0xAB89649589921D7AULL,
			0xBD1AFE96AF5E31ADULL,
			0x5A46A0AE22C9029EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8DEB5C67C3189120ULL,
			0x501E64928FBF822BULL,
			0xAC49BDEDC3B6B719ULL,
			0x44F764BE2F01676FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFDBD791D00C41679ULL,
			0x25E00BA7634C961BULL,
			0x87C9F7D4C0119AA9ULL,
			0x2B38B1774A415A5CULL
		}
	};
	printf("Test Case 278\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9CF041F4CB559C00ULL,
			0xA345D5A0A3DD902FULL,
			0x17E3A39D5FE521A5ULL,
			0x582FDF04B7A17BC0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B5D33C89656AD08ULL,
			0xF7C8F63CD67BE0A3ULL,
			0x516DA6145DC29F26ULL,
			0x4417163FB304722AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x66D67E7C9DF401B2ULL,
			0xDE698EFA497A23A8ULL,
			0x8254B3DF2D11E7ADULL,
			0x5B18B84B7F5F8913ULL
		}
	};
	printf("Test Case 279\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA50D6A4585090BD0ULL,
			0xC893CA2D1161EA2AULL,
			0x69A862313E184530ULL,
			0x74D772492DAA6888ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D7EE6421AEC5070ULL,
			0x9640FF88390F4F2FULL,
			0x45FEBA0A09B6C2A6ULL,
			0x5524BD5E91B8293EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7EC69D7C07000D88ULL,
			0x01E57AA42AC250F7ULL,
			0x2352B4B2C80E8E2CULL,
			0x2F8864F2D0BBD5DBULL
		}
	};
	printf("Test Case 280\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x18628CC219CB9B28ULL,
			0x333687495B9A8117ULL,
			0x40C0CA123BAB87F8ULL,
			0x4ECDC76887EEDFE8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x267539184ADFFC80ULL,
			0xAFBFD611B4F1B340ULL,
			0x4673B11427106F76ULL,
			0x68472C0CC2011E54ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC31E8B84D8F1B4A7ULL,
			0x8A63A9CB76606285ULL,
			0xAB850A4E4F754B1DULL,
			0x61069DBC05BDFC20ULL
		}
	};
	printf("Test Case 281\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x319192E60D14A908ULL,
			0x1C2C36DA3ED70AEAULL,
			0x553EE0D7076AEDEFULL,
			0x6919D162A9AF6114ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC18445F7628DDF0ULL,
			0x493A878C5AE93219ULL,
			0xFA4354345E5E728DULL,
			0x4331D133B6470198ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC51FFF3C130999BAULL,
			0x29895A031F3B6660ULL,
			0x05919660314E2072ULL,
			0x25ECE675B663C38CULL
		}
	};
	printf("Test Case 282\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x101F59539E5CB198ULL,
			0xC6BA4F44B5B76F46ULL,
			0x39D107C8E150DA97ULL,
			0x6E023187E5E23E48ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x656C9DA153B42630ULL,
			0x822C96DF01EA3E11ULL,
			0x683BAC466CEB6946ULL,
			0x62FF506378044B3EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9698959A122869CDULL,
			0x2EAC4E5C8C18D469ULL,
			0x69815636F3FD078EULL,
			0x31CFD182CACDF1CEULL
		}
	};
	printf("Test Case 283\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x06F7761536340358ULL,
			0x7A1F5FE0340390E8ULL,
			0x9FB4E17A11219010ULL,
			0x786B6E8354A34858ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFDA7BAFF557A7770ULL,
			0xA3AC31A3934FDDA7ULL,
			0x87B08CC562CAEEF0ULL,
			0x548402180FC5B363ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x46E6AF9DF2C63307ULL,
			0xAAC58E104826AD20ULL,
			0x669D4DD693EDA295ULL,
			0x1F733F72E6F7FA75ULL
		}
	};
	printf("Test Case 284\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCAB95512E3B90968ULL,
			0xF99130AAD6010796ULL,
			0xA5892ADEC7A4DE8AULL,
			0x4EBD2EDB304298ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE180D15ADCCF7F78ULL,
			0x7EF850D00754BD23ULL,
			0x24C7FC165122E5F6ULL,
			0x4C700D41B2761719ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDCC150D29607E344ULL,
			0xD22401DBF3DC0FD4ULL,
			0xA7E61DFF41FBE426ULL,
			0x1B93FC89EA3D190AULL
		}
	};
	printf("Test Case 285\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7D887E2DB8C68E98ULL,
			0x008D40AB037AAE25ULL,
			0x0071D28DDAC6A80CULL,
			0x7321A15CA292CE5DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD15AC2D773D05508ULL,
			0x012E15A4B6B7338DULL,
			0x2C7B557AC7660BD2ULL,
			0x7116A4817882C6DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0CDC9B459FAF3390ULL,
			0x108DEAEBA9793722ULL,
			0xC96FE5E688D240ABULL,
			0x7344ED9F1CEB17ADULL
		}
	};
	printf("Test Case 286\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9BC2F699F1E8B758ULL,
			0x1B57D8FD3FF52A92ULL,
			0x80DBA9CC3F384703ULL,
			0x49DDDC5B0E0D7FCDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCB8130873D8C2A88ULL,
			0x566CDCC32DD6097EULL,
			0x7D397990618BAC53ULL,
			0x65D58C5BDBC77891ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAFDEABCFC77BBA51ULL,
			0x868C09EA8E5FDCA3ULL,
			0x2D881462B19CC91AULL,
			0x38CD543527F062B5ULL
		}
	};
	printf("Test Case 287\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF97990D44AA76860ULL,
			0x3B6A6EA53C1BC790ULL,
			0xA2F92E5D3FE7C6BAULL,
			0x7680AD745A42F255ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD1E7AD58AD5F7AB8ULL,
			0x660DD9CD2F7529B6ULL,
			0xFF77D170774D4E21ULL,
			0x708B2D125EA03E5BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF257C0AF186E9B94ULL,
			0xA66F51018B15FC3BULL,
			0xEBAC6E2708629C91ULL,
			0x21240795E6C9A7BEULL
		}
	};
	printf("Test Case 288\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x65B9CC04FD0CF7B0ULL,
			0x63FA894B677F67D2ULL,
			0x6B388BF865670C72ULL,
			0x6A5234EC904E13C6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x29D44871342BA828ULL,
			0xBA27ECBBDF6D443DULL,
			0x1E3AFF22C12F8D5DULL,
			0x4C8E557C30317628ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8F99AF5473CD4811ULL,
			0x88B8726DC8C0BF1BULL,
			0x00271B24F8C53271ULL,
			0x62BE1E3DF8B803DDULL
		}
	};
	printf("Test Case 289\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x02D3F4A032203750ULL,
			0x3B0EA06EC4D90A59ULL,
			0x171E9FE3C594694FULL,
			0x5716107A7A265CDEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C0C1CEB9BEAB5A8ULL,
			0xC3022B2A3D5AF733ULL,
			0x897233F6C2FB462CULL,
			0x575837CEE4C4EEE4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEE4721E0FFCCDDB6ULL,
			0x687E3A244E64B6B4ULL,
			0x49F6D0AA15686291ULL,
			0x44EE279AB2092E3EULL
		}
	};
	printf("Test Case 290\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC29131E704D41968ULL,
			0x1354F3C2E9792CD5ULL,
			0xD62A90456F20FD67ULL,
			0x67E3DFEE55629BCFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x608BF52658796208ULL,
			0xB5DF891FCC1B52D0ULL,
			0xD607A020290512BBULL,
			0x7F797307064AE79AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4D619B356959DB99ULL,
			0x142F4A88F8E7E1F6ULL,
			0x2DDBE01083F1182CULL,
			0x416604D31A120F19ULL
		}
	};
	printf("Test Case 291\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7CAE7E89498D99A0ULL,
			0x51E2C88255ABE309ULL,
			0xBCCBA5F49CF9FDB8ULL,
			0x40D7EF964F05BC84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x97D81BDB6F5EEE28ULL,
			0x6CB28DF2FFB2A532ULL,
			0xD41D67BB829795F7ULL,
			0x75721379C9DACDC3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF999737E3815E932ULL,
			0x6085271312BFCC6DULL,
			0xD5F79E976E8A52F2ULL,
			0x74EDFAA738F827C9ULL
		}
	};
	printf("Test Case 292\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF60FF530A1812F58ULL,
			0xE52FE05A78B77D4EULL,
			0x750CA5837A029307ULL,
			0x5020F0CF9ED430D2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE0AC43367BF66190ULL,
			0xA8FFE903A2B29B49ULL,
			0x1B86132D884CCFDDULL,
			0x636C2DA73059425BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x10EF36762BF1D092ULL,
			0x1E1A94A848D60C6CULL,
			0x5934A87DE1E9B72EULL,
			0x69EE1F19CA6E6E94ULL
		}
	};
	printf("Test Case 293\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x60830D785CD2CC90ULL,
			0xEAC93288EBB6409AULL,
			0xF35A731F9AB81806ULL,
			0x5D79F4E1D1E0D951ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4DF24F1137730F58ULL,
			0x030CF8E2DADC3FA2ULL,
			0x5946ADF080AAB603ULL,
			0x54A5E9C2E7577179ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xABAC6E862F867317ULL,
			0xF5AA062896ADDB3EULL,
			0xDFF722BB39500A8FULL,
			0x085153C09CF6E017ULL
		}
	};
	printf("Test Case 294\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF5916691DA35C4A8ULL,
			0xA975C78288EA6883ULL,
			0x2847F2B068C333DEULL,
			0x550C42E47BFB60EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x347C8996266C1850ULL,
			0x5A07D59BFF340D7CULL,
			0x2DC3E770C6380862ULL,
			0x62171B0F333240D6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x472C40989B972E5AULL,
			0x308AAAD699C1C7FFULL,
			0x9C3BDC5B989D74F4ULL,
			0x478C9E1729EDDDD7ULL
		}
	};
	printf("Test Case 295\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD1F1BDC06AE99C38ULL,
			0xA61E7D801D2EB589ULL,
			0x268511DDC607A6DAULL,
			0x49977B62EA0072C9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x10E7A9D9B20AECA8ULL,
			0x6F4061E01543771EULL,
			0x3DCC1277F31BB71AULL,
			0x6E52A72BED13A5F7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE524801E330A147AULL,
			0x88161ED1497509E1ULL,
			0x2C671C07102EB554ULL,
			0x189CD8E1BCC40254ULL
		}
	};
	printf("Test Case 296\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1ECD21ECDAF09AC0ULL,
			0x0365787599149254ULL,
			0x3787918E88D42F87ULL,
			0x5B2731CA6516FA77ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA7060D8F71BC4790ULL,
			0x9EEE0CA99DA1F337ULL,
			0x1F49AC3FF0204BB1ULL,
			0x6664EEB15EFB051BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2846BC8E9CC8FCECULL,
			0xCE07CDD71C22A5DBULL,
			0xDC51F1334FDDECC3ULL,
			0x6F93550AECE3A694ULL
		}
	};
	printf("Test Case 297\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8CE966AC850E7440ULL,
			0xD49986BBC3C44994ULL,
			0x4672B80DD0D00266ULL,
			0x54C1B6FC91736EBAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1C6BC76D0FCC9340ULL,
			0x7FF3FD8A355CF43AULL,
			0xF2F55A51C427AEBAULL,
			0x7E12794893DAF855ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8D060CA6CCFA93C4ULL,
			0x8CBE7A7C6030597CULL,
			0xE16E6D56EBA92487ULL,
			0x5FC654A17E8D9BD0ULL
		}
	};
	printf("Test Case 298\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9F435723823EA2B0ULL,
			0x07EC9B87BFF1AB22ULL,
			0x50CC6E463238A48DULL,
			0x6B960DE52E3CB1AAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7CEB4722A58F3530ULL,
			0x898F3C29F45132DDULL,
			0xDCD6C73576262052ULL,
			0x6ECBF7FCA1AE89FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9B73C7F25A4B76BAULL,
			0x67C179C02E5CFE85ULL,
			0xB60518A60B8CD556ULL,
			0x580987839A234538ULL
		}
	};
	printf("Test Case 299\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDFDB69EDAF84D9E8ULL,
			0x351DB0BB4FAB5CA6ULL,
			0x004A9F79EFA4E197ULL,
			0x403A2E3C5DDA8993ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD554C518A2C50EA0ULL,
			0x0D3B4184A93E8AACULL,
			0xDA564620C6F9EF07ULL,
			0x66F95246BBE4FA53ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD41AD645B557591ULL,
			0x2CFE58464B2B498CULL,
			0x3BFC92068B6B1098ULL,
			0x7DAE411FF7B82371ULL
		}
	};
	printf("Test Case 300\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF96E3BB655830A58ULL,
			0xEBDD69D45774D6B1ULL,
			0xA6CD100970D2142CULL,
			0x5061538529E56870ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCF384647821E9840ULL,
			0x19B286AB5DBE8C35ULL,
			0xE17EE13C39C3F15AULL,
			0x7AFAADF9BD35B230ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x57A15FA21096F006ULL,
			0x925FB94772588825ULL,
			0xBA1F5796EA19FDA4ULL,
			0x1BF0D4CDD59B336DULL
		}
	};
	printf("Test Case 301\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC0EB85C6A62EC1C8ULL,
			0x860B06236583254CULL,
			0xA89E373A8F4EC5C6ULL,
			0x440754D15EB2FB35ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8780EBF381710BF0ULL,
			0xA8D0EBEFC31B118CULL,
			0x3A28455814C65A7BULL,
			0x7AADB6A7B02D74C4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3888E4235BC0B21CULL,
			0xCA6C168B65947653ULL,
			0x3EB7DEE7EA2CC61CULL,
			0x75A40F4088A439EBULL
		}
	};
	printf("Test Case 302\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB2B97691655228A8ULL,
			0x13F9BA8095AE44A0ULL,
			0xAFA819140ACFA07CULL,
			0x6037EC47534CD027ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA98BEED8B2A844C0ULL,
			0xC54CA465EC4A23A1ULL,
			0xF48F48D2948C9DD2ULL,
			0x7F793D17EE63E7B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0DD835BE20C8F953ULL,
			0xE5B28FF195537496ULL,
			0x009AAF60F14EB224ULL,
			0x71252B4996AB75ADULL
		}
	};
	printf("Test Case 303\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFC5097A9F470E0F0ULL,
			0xCC9BAC513237B779ULL,
			0xE1A336737C59E947ULL,
			0x509FF4741173F404ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x602D202BF0413C00ULL,
			0x39A1AF1B3473E84CULL,
			0x6883F711AC65A085ULL,
			0x5C659D6180047836ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85A92DCD92587A4EULL,
			0x26542DC21B2C50AAULL,
			0xFC696CE86A451D1DULL,
			0x10E201645D36FFFFULL
		}
	};
	printf("Test Case 304\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC80E708B4416FF68ULL,
			0x8D62D704996CB8B5ULL,
			0xCF573495717972BFULL,
			0x7C3F775FA184FE2AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5368344C97B85B20ULL,
			0x4272A6821C49D791ULL,
			0x7A7A96B2548CF3A8ULL,
			0x552ED425F69F6673ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6C50694CB95E1A88ULL,
			0x797809B49534A999ULL,
			0xF7EDB3980333BCFFULL,
			0x5912DA14A1F88D43ULL
		}
	};
	printf("Test Case 305\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEA11C6D0F05378D0ULL,
			0xEC5DF10A47EEEC00ULL,
			0xAB1307F39A350068ULL,
			0x435337251695F6CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD43DD0BC2E8B6720ULL,
			0x9C319BC7F59098EFULL,
			0xC8F116E4D792E63AULL,
			0x4FEA4404809C76BAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0C9E94D16E555323ULL,
			0xBCE417A1A217E449ULL,
			0x65A4D4AFF34AC96AULL,
			0x18EE36C1B85FF708ULL
		}
	};
	printf("Test Case 306\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9656ED8FB1B4B1B8ULL,
			0xCA53DB31A6854BB4ULL,
			0xB156A9B37E7160E8ULL,
			0x529164A2E745930BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x376F5F200D2ECE10ULL,
			0xA5DF2387184B9173ULL,
			0xFF5D1C602AE109B2ULL,
			0x6CD11BD2E375095BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F3C6E02513C7ECCULL,
			0x5A8811977120824AULL,
			0x2FC4237C71205678ULL,
			0x52FE97AAC0AB61E2ULL
		}
	};
	printf("Test Case 307\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC029AEC3526D8EE8ULL,
			0x40D47D89F4B76D01ULL,
			0x3917086FEB10B15BULL,
			0x5B735511E37B7481ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5DD754EE63CF7BA8ULL,
			0x49B06839A8DFF552ULL,
			0xEFA8BB65A6E905C4ULL,
			0x67BC999AB0CE9C98ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43E7D4780F943F81ULL,
			0x61EC62303B084A26ULL,
			0x29BA62E7CA2B7235ULL,
			0x42232918BB9AD359ULL
		}
	};
	printf("Test Case 308\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDF34B700D9227BD0ULL,
			0x6D08310855102025ULL,
			0x1C68394B4AFEBD5CULL,
			0x6A223AC8A6729B52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x50D9CC0D37BF4A88ULL,
			0x7D0162797206CF32ULL,
			0x5AC6B3DE3F721287ULL,
			0x74C065F469B1AD1CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x508877C91EE9A1B2ULL,
			0x1D7BBEA08872797DULL,
			0xC545142A2D7FC099ULL,
			0x2904A81017948A15ULL
		}
	};
	printf("Test Case 309\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x17BCCD1B2C89E648ULL,
			0x5DBF60E5A3D6D58CULL,
			0xD063E3D765AACCC3ULL,
			0x6229B6F08234D769ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x92D4A3103F7BD928ULL,
			0x1D8BCB13AA31433FULL,
			0x4CA3C5C555E3664EULL,
			0x67CE4AD27E4FE0DCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1AA40AD540A7F5B1ULL,
			0x0B8BDD4D21EA5BA0ULL,
			0x8765C03A37F83988ULL,
			0x124FB0950A4E27ACULL
		}
	};
	printf("Test Case 310\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x38EEA033F643A370ULL,
			0xBA3A5E512351BFB8ULL,
			0x1F610A2109A89CBEULL,
			0x72EF1D3FFAA0F979ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF36832894EF38758ULL,
			0xAA89ACFDC533F17EULL,
			0xFFB6E1B58A7C945BULL,
			0x6416DF937EA068F8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD29BBD3070170E5BULL,
			0x6D16FD2B23597134ULL,
			0x2C4D0772ED4A66E8ULL,
			0x517B09D1F2CA9F36ULL
		}
	};
	printf("Test Case 311\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB07D570F05B94EF8ULL,
			0x088878A14452C781ULL,
			0xD90D919838F1353BULL,
			0x5EC78946B23ABE3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9FF2F0D1580C6588ULL,
			0xB9AA6C52FEB43BE0ULL,
			0xA5625F021226EFC5ULL,
			0x70107713DDEE85C2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2C9EB7DE94071F15ULL,
			0x3088F5BF055AAFC9ULL,
			0xD03C3E6C910FDCECULL,
			0x14D7BB66F985B849ULL
		}
	};
	printf("Test Case 312\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC09E314E0C63C088ULL,
			0xB6104AC53C0E1A03ULL,
			0x9FF8519FFC413E2CULL,
			0x7591D04C38CB073DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB275A42A8AC3CFB0ULL,
			0xAE5454F741845B94ULL,
			0x46E7D45CD9778D66ULL,
			0x45154975DA6E2A93ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEBC0E1A8F45FE6CBULL,
			0xA104D5B041D7AC88ULL,
			0x5E4A3D990A24C74FULL,
			0x02F54F1C0068822EULL
		}
	};
	printf("Test Case 313\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1FE980F15D4AF418ULL,
			0xDCDE89FB076910CBULL,
			0x07ABD612FAA9B779ULL,
			0x5627FD20D678E2F6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x405CC6EE040E5E88ULL,
			0xF2C23B71F46A2C9DULL,
			0xF6358F55FFB1AC82ULL,
			0x616950B99754F1B8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE9A71202958234D7ULL,
			0x255F3CAFBD76EE40ULL,
			0x69C7419608D30F75ULL,
			0x17B8C6012EF21FBFULL
		}
	};
	printf("Test Case 314\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBA18AB5B690E86C8ULL,
			0xC900D128AE4B86B9ULL,
			0x29A5A5C38C6DBCC3ULL,
			0x4A788D78D336F4E3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3DAFAB51C5876EC0ULL,
			0x7862F860568B994EULL,
			0x555A972CB5005761ULL,
			0x4A453D936EB25774ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0FCFC3287B114B59ULL,
			0xE77F286E3296D9AFULL,
			0x5E40BAC0D8C55D81ULL,
			0x33F124A145FA3434ULL
		}
	};
	printf("Test Case 315\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1FC2C54E87B2F460ULL,
			0xE80ECD227F189E0EULL,
			0x048FA68578C89FB0ULL,
			0x7954036127042A45ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43FBAF3C93F73650ULL,
			0x1A777E640D66C652ULL,
			0x5121A8D8268C0ACCULL,
			0x6E9EF6089206C193ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB9F7294A25B67DDCULL,
			0x257FD358EF1FDFC6ULL,
			0x1873BFDD59CAC66EULL,
			0x1CD2769F8B1B875BULL
		}
	};
	printf("Test Case 316\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9BEE30E705EC2A60ULL,
			0x5C65C1FA6AA37F83ULL,
			0x5C8A7F9FC929E9A9ULL,
			0x7C853C5C4F2B1B52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x86BD53572CB19DD0ULL,
			0x350B3CE8AB2BE826ULL,
			0xE958B95E0F18C758ULL,
			0x45F6F0DBAE97B75CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD552F8FC47FAC840ULL,
			0x35C258C87AAFE6C8ULL,
			0x4E3742F74E6C31D0ULL,
			0x0ECE0886AB14F258ULL
		}
	};
	printf("Test Case 317\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4EA57078376418E8ULL,
			0x3506EC40F17EC904ULL,
			0x363728FDA7DB0081ULL,
			0x6D6699F0FD6B92F6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x60215D63FF990758ULL,
			0x4E13AF5632D93656ULL,
			0x033B7D193006CFD3ULL,
			0x4B16CAAF2B830BD2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD42C546FB26D7F20ULL,
			0xE7F2D978B755B66AULL,
			0xB59359C4B8204769ULL,
			0x5767950AF5F9C0CFULL
		}
	};
	printf("Test Case 318\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC24E4AC6DB3E6B20ULL,
			0x7F0E1D2E23B97FCCULL,
			0x51752646D18F2D5CULL,
			0x4531148B8A3A1EE8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4189CC33608D6090ULL,
			0xE8C81BC60210B60DULL,
			0xA82EA07E2AD6534AULL,
			0x412C638CEAEE746CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF923F8184E2A8350ULL,
			0xB8131650C65BB86AULL,
			0x7CE7D0BF7F29C688ULL,
			0x30C5790A83B9F925ULL
		}
	};
	printf("Test Case 319\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCBBE1A498C90E6E8ULL,
			0xCE6386EDACD12FE7ULL,
			0x0CE46FAD4D0BDA91ULL,
			0x7349626CEECC0E02ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x66903BA6D77B84C8ULL,
			0x430A85B72559CECFULL,
			0xA997B54ABCC244A8ULL,
			0x77E4333BCBF9F89BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAF42C22BEB11BDCFULL,
			0x7A6252D73FE3BBCDULL,
			0x01C0BE82EC2FEB03ULL,
			0x337A2B99E825013FULL
		}
	};
	printf("Test Case 320\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA956F3B8297A6860ULL,
			0x904EE763BD40D436ULL,
			0x01513191C4DD6027ULL,
			0x52559782FAFD1948ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0EC3E857E12D8C58ULL,
			0xDA0D81D45FCC1FFDULL,
			0x252B68189260F0C2ULL,
			0x5428A485285336D5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x88EB24B23BA0D768ULL,
			0x38031BEF99184D61ULL,
			0x465F1FFA29EB8FEDULL,
			0x5D95D474349965AEULL
		}
	};
	printf("Test Case 321\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x35A9F9ED101F8D78ULL,
			0xADFC108DB9B6553AULL,
			0xAC3C2935F14C5770ULL,
			0x733E622F18AAE06EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5603895C5ABEED10ULL,
			0x2E280BDA968B09EDULL,
			0x4AD3417013E863A2ULL,
			0x4D9D173AC1139A3DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3DF870DC5FD26365ULL,
			0x6BF81E3ED791B3D6ULL,
			0x97C31483E4CFB52FULL,
			0x4E6B116F9A66F345ULL
		}
	};
	printf("Test Case 322\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2C2226D947243098ULL,
			0x955DC20FDCDE6980ULL,
			0xF14B4D2BC217D15AULL,
			0x64AD471E2B29C07FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x111484F91FF6FF00ULL,
			0x5D1D3CDA1E5D7936ULL,
			0x9BEE382EDEDA7353ULL,
			0x407A4C9B4C8CC828ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0D2BF0202B1254EULL,
			0xE28C808B2C1D558AULL,
			0xA775A3BEBF1F311EULL,
			0x6E20203D8D41D55AULL
		}
	};
	printf("Test Case 323\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE99948B5C3B00C60ULL,
			0x3CD66F85CD2D9211ULL,
			0x673BED4E074AF8DBULL,
			0x5B7EDC15461229B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF444DD13EC8CB4E8ULL,
			0x082BB7EC963164FDULL,
			0xA760A19F6A16B2B9ULL,
			0x64B48ABCB31241F9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD503E5F0F2D06C0DULL,
			0xBC457C284FBA5323ULL,
			0xE7B3B4BD44B09F97ULL,
			0x7FB435F124EE9DBFULL
		}
	};
	printf("Test Case 324\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE221A1D5687166A0ULL,
			0x33A022B26CF8F87DULL,
			0xEA00F95BAAAD6E95ULL,
			0x6807C0991FE83A8EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5394F98CB01E7278ULL,
			0x32B0FE76F8B7C78DULL,
			0x178CFC6DA2F25400ULL,
			0x43463AD92B107D48ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x077F37C21BE0F688ULL,
			0x5D55A745BDEC92A9ULL,
			0xDC64761998B78CF8ULL,
			0x2B94F10F59029976ULL
		}
	};
	printf("Test Case 325\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4AE231A2E62D31E0ULL,
			0xFACB1F4A9E2EA6B8ULL,
			0x2D584D06B0091FBFULL,
			0x416297AF25AF5164ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x229C8159FD24BA68ULL,
			0x6670C3CD2B420767ULL,
			0x762F1E96E8A8AC96ULL,
			0x477167D1B6C865BEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E75A7D01C71CCA7ULL,
			0x8137E49B93FD2A4AULL,
			0xF4146D6FD0C986E4ULL,
			0x1DE99B88843C52AEULL
		}
	};
	printf("Test Case 326\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1E745D4E92D5F400ULL,
			0x52FD8314C64ECD88ULL,
			0xB474CB1BDCE273C8ULL,
			0x65A6F005BE704994ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x475F0EF82156B790ULL,
			0x869138A0AB74B26BULL,
			0x98E03ED3A5718EF3ULL,
			0x7880C3767F39AE1DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2695084D385BE5BULL,
			0x867C805F92BF3744ULL,
			0x0D166B52B1B61F9DULL,
			0x1510295878F5B58BULL
		}
	};
	printf("Test Case 327\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEF93B9C617F980A8ULL,
			0xA2A6051139C162ADULL,
			0x9DB81F694B5F19FEULL,
			0x7311295F19821012ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB54B89A393451C58ULL,
			0x17C9B40383EC54C1ULL,
			0xF1C2B83698435DA6ULL,
			0x4AEB2F4579AECE75ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x929044694AF5FFA7ULL,
			0x5898576E49FC671EULL,
			0x1820426A1BA66AE8ULL,
			0x4E857308CE6A2B4AULL
		}
	};
	printf("Test Case 328\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD7DB8B29EC5B62E0ULL,
			0x39F47202CA6C8C43ULL,
			0xE2259E08EF618C93ULL,
			0x768313714F7A2401ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71F6F3D123D66C18ULL,
			0x85B8175CE423A5E1ULL,
			0x9E115748E84DF75DULL,
			0x692D80E8B56A2AD5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x486055413E31C987ULL,
			0x89B8274328E33373ULL,
			0x0F94973275D810ADULL,
			0x1754D50106ABF40FULL
		}
	};
	printf("Test Case 329\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDAD9FFD702EDFA00ULL,
			0x453B641AC5531DC9ULL,
			0xC5C74998477E927BULL,
			0x6E96432971F25282ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x527638CA8EB28A48ULL,
			0x2E92CC998370A731ULL,
			0x4CACA4558E813237ULL,
			0x461526CE3CE4B429ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x928DD96E8EC1D969ULL,
			0x323F32D596EE85CBULL,
			0x7B51C70E7E960CE5ULL,
			0x6CA823E4C9F410B6ULL
		}
	};
	printf("Test Case 330\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDCB754AF33508038ULL,
			0x4027DB8AEF811E3BULL,
			0x3C69DEFC2A045139ULL,
			0x62CA837E8E14B6C5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4F1E29FF5B7D6520ULL,
			0xFB80475DBA2A56CFULL,
			0xCB29267B252E2F2BULL,
			0x57E1EAA3EE1BF4B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x524453C7D6874DCFULL,
			0xC6B27F6ED10B990CULL,
			0x266AA53795FD209CULL,
			0x185CE2AC2E7B8453ULL
		}
	};
	printf("Test Case 331\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x314C6898FB2F23B0ULL,
			0xA927BB9CAB1CCAA9ULL,
			0x392FEC0C3CB54E6DULL,
			0x56DBDE45F6474808ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7001B47CCDF13698ULL,
			0x7B99FD62ED1EDDD6ULL,
			0x1801B2DD11C66F7CULL,
			0x5A74EF39E7D27C32ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE5C4CB3533E26B37ULL,
			0x81239BDC78383CC6ULL,
			0x025CE40924D01EF3ULL,
			0x6FB1697CA50495C8ULL
		}
	};
	printf("Test Case 332\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8F53C81215215EB0ULL,
			0x7AC8F23E6C10B7E5ULL,
			0xAB739AE9B7B08C94ULL,
			0x5D2EB69A166E8770ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD03D7C921FCB0BA0ULL,
			0xD437D405A4531474ULL,
			0x2635A7B985F1F36AULL,
			0x451E33BC6AC40345ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5DFA460B5B8DC750ULL,
			0x13F8B845B7DA5678ULL,
			0xD8CE89AB336EDDA7ULL,
			0x533BF5CB9C834E40ULL
		}
	};
	printf("Test Case 333\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCA26E3BDE1BE7720ULL,
			0x194599D6B15F8F8EULL,
			0xBBA2C36E666D6CD4ULL,
			0x6508D1A6C1C379B0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEABC16E89ADBEE68ULL,
			0x14309507201AE9F6ULL,
			0x00268CDFEC67C199ULL,
			0x7449116419E34A4BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x758FD8BEA76ABDD1ULL,
			0x250CDA7E12630FFEULL,
			0x47981619847B1A31ULL,
			0x754D7C989720ECD8ULL
		}
	};
	printf("Test Case 334\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x54C1452823483C20ULL,
			0x4E3BC7C1295EC8D0ULL,
			0xE656D11D28D76203ULL,
			0x751A343641303E53ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA7880AF2D2262038ULL,
			0xB59A4BAF54C95A8BULL,
			0x654CF1F7E16AA415ULL,
			0x5D69324D8E33E14EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x97327C6C2EF8F946ULL,
			0xD3F9A1F0666200FBULL,
			0x59F0076AB0E87B87ULL,
			0x1C8D7E151195984FULL
		}
	};
	printf("Test Case 335\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x40F6C72C351025B0ULL,
			0xBADE3903660DD926ULL,
			0x3C8D2913A17DF931ULL,
			0x4E49C304125EBF87ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC073B3B92E50A148ULL,
			0x3650F1A6D09E1BD2ULL,
			0xBA05D5A898D2C730ULL,
			0x79E7B01A7AAA65C1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x177A2E99620760BEULL,
			0x85D416FCCC291F8CULL,
			0x6E75BE576BB60E4BULL,
			0x17A18CB997A16239ULL
		}
	};
	printf("Test Case 336\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x650E17A15284A3A0ULL,
			0x1F80F18BBFF3110CULL,
			0x9279BF028CE51858ULL,
			0x693A7385D88A1943ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x35AE66ABDEB2E8F8ULL,
			0xF0B05F66931A9F70ULL,
			0x7617A391E0A4584FULL,
			0x5958D3723B734770ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9DBA5B4A024BF295ULL,
			0xC7DA7AEF63C6C11AULL,
			0x00DEFD811E2175BFULL,
			0x56E5B7A186DDD0CDULL
		}
	};
	printf("Test Case 337\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA95608DAFE070188ULL,
			0xC3E2593BC0C270D5ULL,
			0xF67D766BCE832195ULL,
			0x62667E55AC744DDCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAC34407EE442E548ULL,
			0x51875B03D2B76430ULL,
			0x36459979B86ED191ULL,
			0x5BEF234C034293B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7672F83ABA49A62EULL,
			0x041822A920BA7501ULL,
			0x48EF3D31A0AE350BULL,
			0x07CE549290DB72C2ULL
		}
	};
	printf("Test Case 338\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4A31E009D5DE8638ULL,
			0xB55026ACE1A43604ULL,
			0x8E9C3324B2902D71ULL,
			0x5A365581CB5E2C20ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6405607DD55626C0ULL,
			0x6CA48A058E193346ULL,
			0xC6004B2380B1F6B9ULL,
			0x7DE136A83AC4A071ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD6BCFC0EA1A0A11CULL,
			0x17420E87DAA08017ULL,
			0xB5A0FCF4AAAC2ECEULL,
			0x0FF44DBA09235F52ULL
		}
	};
	printf("Test Case 339\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF843B17875D5CDD0ULL,
			0xCB10C78E00C57D7DULL,
			0x455D63350A0972ABULL,
			0x5E03E0DA3513F268ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB61333E1FBA62178ULL,
			0x05E29F951F5DDAF7ULL,
			0x227D8DFFBB5C6FCCULL,
			0x4CB7A5035806564CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE80216184726E18ULL,
			0x039658A6CF251DE7ULL,
			0xC2056B979CBE447DULL,
			0x1F737C673176442DULL
		}
	};
	printf("Test Case 340\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCAE242A6C9957C10ULL,
			0x15C50C7DA637A95CULL,
			0xEBEA5A7A914CD891ULL,
			0x65F4A6913F56B6A7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1573B73ED3C3F3B8ULL,
			0x20512F5917307D58ULL,
			0x0B7EB793B398155FULL,
			0x7D8154236D60185FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC4C17CB97A061714ULL,
			0x46695D66F373D6E2ULL,
			0x657CAE2AE91B0361ULL,
			0x734AC4898A628C73ULL
		}
	};
	printf("Test Case 341\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x77E21CF995245698ULL,
			0x30A04CE800837E7CULL,
			0xBAFEAD6DBEEE0E61ULL,
			0x624612D7C905AD3AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1BF823F298E56D60ULL,
			0x44F3C347823E8576ULL,
			0x995BBE9D7588143CULL,
			0x5DE486290F00F842ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC2960BE88431F999ULL,
			0x5C4CFE3E6EC3208CULL,
			0xF0C0374C7AD9D3EBULL,
			0x06FBE1FEE9100699ULL
		}
	};
	printf("Test Case 342\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2E04B1C1F0BD9BE0ULL,
			0x1B65FC11E48BC41DULL,
			0x03ED4207E0D8010CULL,
			0x5B7A3A324C1C4ACCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0CCE2EBEE1C831E0ULL,
			0xF6E5029A6060D1AAULL,
			0x080F5060AE3E99D3ULL,
			0x4BE98746C65B4045ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC4733245225BA217ULL,
			0x7AA006BD9F14FC82ULL,
			0x50E4B29CB46480C5ULL,
			0x0CAD80612092413BULL
		}
	};
	printf("Test Case 343\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4FBB9C1D092BCC38ULL,
			0xE4820132F2F2DCB9ULL,
			0x0C8FF3F17FAF0F01ULL,
			0x78897294384808C8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEEC725717193210ULL,
			0x41BA6A4E2A5FE47CULL,
			0xDC37CB8155C31B3BULL,
			0x75D89ED4EF23C6EBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60333230200DD003ULL,
			0xF48FC1565FAA587FULL,
			0x271A73B501486F8AULL,
			0x645BFEBFC45E72FDULL
		}
	};
	printf("Test Case 344\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8E111BBD4FCFF320ULL,
			0x06D214DC069241B7ULL,
			0x2DC29656C037C2F1ULL,
			0x7F25F49D51BBC766ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4E6F8AD82C269CF8ULL,
			0xBF3D9B6904BD9B65ULL,
			0x30B376E3B66CFB2AULL,
			0x70E2A6B6D41062F1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x74A82EBEDD244C87ULL,
			0x13B5AAF2B87D63EEULL,
			0xF148C2AF5A0DB052ULL,
			0x2554910B05D3F09EULL
		}
	};
	printf("Test Case 345\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCEA0E905532EC438ULL,
			0x3354BC0B713FF73FULL,
			0xAD5284ACEA721B67ULL,
			0x76874866C2294BDCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x51838856FAEC98B0ULL,
			0xBF1817AD871161AEULL,
			0x489B9EBC44F9E4E9ULL,
			0x4AB628AE3609A99CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE72A0D8732779375ULL,
			0x94411EA63405A6C0ULL,
			0xCCC904D0204480DEULL,
			0x3A61E4BC6B12501CULL
		}
	};
	printf("Test Case 346\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0FEFEBDAC50E10F8ULL,
			0x096762C8CDFF1ACBULL,
			0xC0BEFAFE04925402ULL,
			0x4F8B0FAFF6B2FF59ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9B89E302985AB338ULL,
			0x0C49FB5D19DF6F2EULL,
			0x46AFFCBEEBA811E6ULL,
			0x4B489BAE7CEBB879ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x84EC7DB657881988ULL,
			0xC27B4A0AC9E1D054ULL,
			0x693ED5E84CFF1E0DULL,
			0x0A9ED45A77981DD3ULL
		}
	};
	printf("Test Case 347\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x20CA09F34AE75C70ULL,
			0x3CADBF23AFE0DAFFULL,
			0xA5A6B7F36C4F305BULL,
			0x54A39B11D66F6A3AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC0B6AD63C94A7648ULL,
			0x635F175285D8C9C7ULL,
			0xF4F155DEE31219A7ULL,
			0x46177D570261782AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xECBBBC88749022CDULL,
			0x28A5D0DBD5D79A86ULL,
			0x493AC4886E2A8383ULL,
			0x5F4BFEF446D633A9ULL
		}
	};
	printf("Test Case 348\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1D264F5565679568ULL,
			0x5643E8F3F908D920ULL,
			0xBF408A07ABFF6B66ULL,
			0x55C6B1CCDF74AC97ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF5909A2949BF16E8ULL,
			0x4C0C595D8A67059EULL,
			0x9485C9AABB8B6387ULL,
			0x6A6B0830965BA379ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFA0A8E754F7182E0ULL,
			0x2870EEF536FF08B7ULL,
			0xED5CA1CEDABF5461ULL,
			0x3A40F262D9AC37AFULL
		}
	};
	printf("Test Case 349\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1D5673530A1FA3E0ULL,
			0xA7F14450EC4DFC1FULL,
			0xAC3CB31E9E3E8144ULL,
			0x7E2189E2CF578BEAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAA47FC54D134D8E8ULL,
			0x5B8312E5A9FC8393ULL,
			0x0BE62B295BEA2743ULL,
			0x51293CC4BB5B12CFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDF487106D2B89873ULL,
			0x96EA3E2E6F70EE08ULL,
			0x622741CCA7F6D7DDULL,
			0x6265BDD537400EF6ULL
		}
	};
	printf("Test Case 350\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x217AD90F5C622B00ULL,
			0xEA2460B0096F138AULL,
			0x855AA3F2A3952340ULL,
			0x7753A55CCC2F3B26ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x379C4EE1F11D0A60ULL,
			0x4DE3766910FA712AULL,
			0x4C3D686C23A95419ULL,
			0x43CDA4F6DCFA414DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2156C3CAF27673B6ULL,
			0x2F9425F102AF9F83ULL,
			0x60563EC2F9273F99ULL,
			0x141D47366E31CB7FULL
		}
	};
	printf("Test Case 351\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFA9797D998056EC8ULL,
			0x0431DACEE7DEA723ULL,
			0x71957DCFFF106371ULL,
			0x7DD850B9C65DDF6DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA485E771953E6CF0ULL,
			0x154A007D8EF63B23ULL,
			0x90398122BB64EDE8ULL,
			0x5D6A36738459BE00ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDC7D850537F41486ULL,
			0xA518FF8116D85BF5ULL,
			0x929169C0DBA20E49ULL,
			0x532820798C81EE91ULL
		}
	};
	printf("Test Case 352\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE3B119C17487F2C8ULL,
			0x47A5054F01D4B0D9ULL,
			0x12D73E8FC6843B6FULL,
			0x7BE9D78BEBE7122DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x583CBBA82325E548ULL,
			0x09A5634B75848E18ULL,
			0x34E41E685BA896A7ULL,
			0x6FF44A7BF0FC8924ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE8D12057DAC9286BULL,
			0x845A6891DCDD60F7ULL,
			0x00F919D7AE91C596ULL,
			0x5CFE54651D82FE8BULL
		}
	};
	printf("Test Case 353\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x85CA7BCC2DAE6440ULL,
			0xB550508C381B1AB5ULL,
			0x201A4404A114BA58ULL,
			0x79630B4FB53C2777ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEF17F329FAC9B598ULL,
			0x2DFD930D0F3DCEF8ULL,
			0xBAAE7C402C0F8C73ULL,
			0x4DB66D7CBD85ACA2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB30FC756DB0AF231ULL,
			0x48095FED559D2A9EULL,
			0x81C2121C9F997255ULL,
			0x2A39BB771D12803EULL
		}
	};
	printf("Test Case 354\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9C02D1C208B17180ULL,
			0x1BA11CAF44C05D33ULL,
			0x1093B29A5F41CFB5ULL,
			0x7E6748E1A48182FDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAB37D53E8783BAA0ULL,
			0x813C5C7C990E9DE8ULL,
			0x8AB23C2562D6B6C6ULL,
			0x55E26B77962BD2AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF3DD21A4753F4181ULL,
			0x38FE5F8B9FBDE9A9ULL,
			0xFF953C48968DDF8EULL,
			0x5D33604EBEB1F391ULL
		}
	};
	printf("Test Case 355\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x259C06020D8E16F8ULL,
			0x8AB9020883B8E7E6ULL,
			0xA9105FBBCEE7737FULL,
			0x4F10E4236A731D0BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x15DA3C23A65D39E8ULL,
			0x14B097EA96697F2BULL,
			0x703BDD42036DEA37ULL,
			0x4629C4DBB595AC19ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC45F303BF4B5DE8DULL,
			0x3A526526ACBEB346ULL,
			0xA8EA7B4F8BF1C53EULL,
			0x4085AF8810C95380ULL
		}
	};
	printf("Test Case 356\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1CC62C19983262D8ULL,
			0xA3D95D9929D66A20ULL,
			0x61415551BB423A89ULL,
			0x7B348227C0AADEBAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD806DEE699AAC850ULL,
			0xFA4DC160E7B98722ULL,
			0xDF210659692E8661ULL,
			0x6BC7A83C33F8D5B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x19374FE3BD30FA46ULL,
			0x3EB04549CB0BD884ULL,
			0x38B9B906979D6592ULL,
			0x6932BC0539A7A275ULL
		}
	};
	printf("Test Case 357\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC37CE5830F4C7AF8ULL,
			0x8DF9C950B4E05A06ULL,
			0x004E23E351172840ULL,
			0x5D3631921AA3170BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6A7509809EFEAB10ULL,
			0x305208E6D412C923ULL,
			0x30DF15634BDA3219ULL,
			0x5AEE227D24B438B2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x166EF3B8FC914589ULL,
			0x75B6D53939FE0825ULL,
			0x550D83B1E547DE3AULL,
			0x314AD6C0814C68DCULL
		}
	};
	printf("Test Case 358\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x17FF93DDA994DB10ULL,
			0xAE729A0F4BE38399ULL,
			0x7A87E741F0A80E19ULL,
			0x48D927F85B806D6AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C68F74C278F4E88ULL,
			0x9FAFBBA52758D57FULL,
			0xB8DEFD736BDD1A4AULL,
			0x50D097A31C9157B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA9B84D342977A38EULL,
			0x16552D219D9F5B8DULL,
			0x167E917A15B075BCULL,
			0x388FD0D2B908B10BULL
		}
	};
	printf("Test Case 359\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7A937AA8454A32A0ULL,
			0x16AAA5F48104D19CULL,
			0x3306211E87458F7AULL,
			0x5F83591D3774B382ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1EC920ED4791E840ULL,
			0x2D02722E936D511AULL,
			0x128DAE713DA1BAE3ULL,
			0x72D170489F11614CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE041DBA2099E70D7ULL,
			0xA5E5F8424E4BB769ULL,
			0x29EA11D21F4060F4ULL,
			0x665A8438F49819D6ULL
		}
	};
	printf("Test Case 360\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3D576E3A66D37F98ULL,
			0xA5BA993366541C18ULL,
			0x1ADC6492195F1093ULL,
			0x46C5889B8A1C1B40ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE83375CFB89AE588ULL,
			0x03B6A87468B00E42ULL,
			0x2D21FBEE835DF988ULL,
			0x5CE95AB6B958F859ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD41B691AE0D975B0ULL,
			0x530C0C5D4999A3C3ULL,
			0x4BFD2B9C34493B27ULL,
			0x62AB4DCD96F8BACFULL
		}
	};
	printf("Test Case 361\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3625BF951EE2FC88ULL,
			0xAF9F34C57A6620AAULL,
			0x35C4AB9B6F583880ULL,
			0x73F62B2D6C75AECFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x92CFEEA52CD25DD0ULL,
			0x9ABC627B5969B890ULL,
			0xF3AB8395AB4F9E0EULL,
			0x726DEC245965B030ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1A36671F9B37CB10ULL,
			0x31A2472703411354ULL,
			0xB753409C025B4224ULL,
			0x2F7E542ADE51D3BBULL
		}
	};
	printf("Test Case 362\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x18E5F51ADB097058ULL,
			0x1FF027C5581883ECULL,
			0x05BC95250A918E2DULL,
			0x42518423707C60C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF31918C3CA6F7C0ULL,
			0x4CA2B36A75274264ULL,
			0xFD5801A35CF5FB95ULL,
			0x7AB27D7ECA8082F5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x64622F8C35366BD5ULL,
			0x5E377CD65A4E0562ULL,
			0x3EB00D80C56D43E5ULL,
			0x25EAC94625B34353ULL
		}
	};
	printf("Test Case 363\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x23554ABF522896A8ULL,
			0x691F462A0C85DD12ULL,
			0xE78CF1957C338E05ULL,
			0x61C3B43958705861ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBB6A581FDEB855E0ULL,
			0xD9183F74A885C4BEULL,
			0x6BCEE6716E9F391DULL,
			0x4E4F5C5C7C61E953ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAE89AF7EB5BAECD6ULL,
			0x9C1CFE3521906E93ULL,
			0xCEC3DB8F1815DF7AULL,
			0x2CE622CB156D0B9EULL
		}
	};
	printf("Test Case 364\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x500A596CE9039248ULL,
			0xE10ED81BC31949EFULL,
			0x183C4C530FDC281EULL,
			0x5437707CD543345DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x791F70A515D80838ULL,
			0x3048FADD168A4454ULL,
			0x067B2A361EEEF66BULL,
			0x511E85181FD33EC7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2BFCD69929062896ULL,
			0xB3AB0836589E51E0ULL,
			0xBBAE3ECFA1A6CAE3ULL,
			0x2F0AE0EA6F9E3149ULL
		}
	};
	printf("Test Case 365\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x08766C32E1DC8E28ULL,
			0xC2D10A29F4092062ULL,
			0x69034B13CC61D5D5ULL,
			0x5AFBB3A304940F0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE366F80EF7837398ULL,
			0x44BEF5295A187935ULL,
			0x0FA4459338FAD19BULL,
			0x4F3D3328FD4748D8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x21219331AD65A91CULL,
			0x192DD9DA9645C308ULL,
			0xB26DDC5EF1197326ULL,
			0x2FB3E45B55887EBFULL
		}
	};
	printf("Test Case 366\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4AEDB5A7735CB4E0ULL,
			0xC17CCE9889FD8486ULL,
			0x8692CF9A9B1F258DULL,
			0x6DC128BC2739B495ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC6EB0F2A27A26950ULL,
			0xEC8CA5EAE5D5A30BULL,
			0xA5C59D3CAD1E16F3ULL,
			0x7BC526FDB3470E66ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9396338529A5A5CFULL,
			0x0D0BCB161858504EULL,
			0x808D6DA5396089F0ULL,
			0x7A51634A065AD307ULL
		}
	};
	printf("Test Case 367\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF2FEF73BBBB2BB60ULL,
			0x1257F5A5430B6C0EULL,
			0xE2A30CC190D73667ULL,
			0x6E4F341817562B2CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEAA984FBB6B86948ULL,
			0x7A87024F5CDF6F08ULL,
			0x5567FEAB9BCBAB41ULL,
			0x50E75575E8549E1FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA5382D41E9A9F9ADULL,
			0x9C2C06F0ADD421F3ULL,
			0xC659DDEB64B59094ULL,
			0x4940468EB320108EULL
		}
	};
	printf("Test Case 368\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x82FDE2A24A295AA8ULL,
			0x180C3BEF60B22563ULL,
			0xBDC6A0C1EC4ADB19ULL,
			0x75DEAB322F42D7A2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x56174B53478681F0ULL,
			0xE02C42EAA5A2AFDCULL,
			0x43C241C6EFFF3C42ULL,
			0x4BB7B98A7B78BC3BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3FD98A8C1629605DULL,
			0x8AEDC214BEFFDCC9ULL,
			0xA6DDF52C3B1585ADULL,
			0x5AAD0AFC87EA1FA6ULL
		}
	};
	printf("Test Case 369\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9A4E9D55A719CB38ULL,
			0xA4785536F3AC21ACULL,
			0x82CBB8EF08562697ULL,
			0x790BBEC9AA14EEA2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x772BCDDCE8919168ULL,
			0xB36055C40869E08EULL,
			0x645B776A47056E4CULL,
			0x6A0CF9A6900B60FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x341A7F810AA4B648ULL,
			0x40FC71FBF0D123ABULL,
			0xBBDB34854CA19248ULL,
			0x6A04F855B5AFDF1DULL
		}
	};
	printf("Test Case 370\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA55524C893201F48ULL,
			0x6B218A5537A706D2ULL,
			0xBEA5985FDA71C597ULL,
			0x75540D2E78AFCD99ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8A169819A8F9C630ULL,
			0x43CE6B606A9EA8DFULL,
			0x8F09600BFD5621C2ULL,
			0x5559C14B52B43492ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF5B391972A267112ULL,
			0xDE06CBD651FF63C8ULL,
			0x4B94F186CA8576C8ULL,
			0x555685355254079EULL
		}
	};
	printf("Test Case 371\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC23E76EA8807A140ULL,
			0xED4E3BC122BF6C92ULL,
			0x23C9C30F5C2AE27EULL,
			0x6100997E8165A642ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x90E8B6F491144FB8ULL,
			0x05A8BEBA02B91EE4ULL,
			0xE9632D5DFAFA4C76ULL,
			0x6BA80D311A597D39ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2E2D5A98733BA02ULL,
			0x1CE734EF371F7D23ULL,
			0x25F6009F9384BB07ULL,
			0x0D80101E1DF4D8DEULL
		}
	};
	printf("Test Case 372\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x74463CD37D821448ULL,
			0x863E1777F1336117ULL,
			0xBD8236AED261F6A2ULL,
			0x4BFADE55035C7E3DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71B41AB2EBFA5018ULL,
			0x9BEDA445830146BDULL,
			0xBDD246371ED3F806ULL,
			0x5AB0C15D889C5D0BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x22A6351CCD035350ULL,
			0xF7E3C8D49BC46A59ULL,
			0x9701DF0EDED1CD0EULL,
			0x1BFE9E8C96095F14ULL
		}
	};
	printf("Test Case 373\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x2EEB76BD8F48BB98ULL,
			0xB730176BB1111D51ULL,
			0x9FF609938D096F5CULL,
			0x60D5BCC77835BE70ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE923FAD101F84058ULL,
			0x26FC0A4D87937158ULL,
			0x91B4F4C4DD48273AULL,
			0x4DEA69DB82D18F5DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x238109C241ECCB6FULL,
			0xDBFF25F6711D7062ULL,
			0x0145690BE423905CULL,
			0x1BEFF73C8CF1ECF2ULL
		}
	};
	printf("Test Case 374\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1738FCFF9059DE20ULL,
			0xC5F82E903F54D121ULL,
			0xDA060C0EC0CABFFDULL,
			0x57835AA4A1809092ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5923949D4C3727B0ULL,
			0xD696F9A82294575BULL,
			0x73DA73E5C5499548ULL,
			0x7A29ED066CC81099ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6ACC97DDE5F6992CULL,
			0x64D0B99BCAD8385AULL,
			0xA480E6310F816888ULL,
			0x164513905EBF1A7BULL
		}
	};
	printf("Test Case 375\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6C64AC18E23EFD08ULL,
			0xEDACB24063415FF7ULL,
			0x17451EDB11B3EB1CULL,
			0x5FD46E4561832120ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD3F884447627EA8ULL,
			0xAFC748E58F75F6E7ULL,
			0x7BEDBCD0F97DFF96ULL,
			0x45B759CA575325A9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7FE0976CF90B26F3ULL,
			0xA4D94FF7CCDA41C3ULL,
			0x512E7307863F3A73ULL,
			0x163FBD5441563C2EULL
		}
	};
	printf("Test Case 376\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x67E90AD461749AE8ULL,
			0xB98A10627ED1D268ULL,
			0x199B462EB8A64C45ULL,
			0x64E3482CC0FE77F4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x28B826F7DED24470ULL,
			0x961BEC12CE09D27AULL,
			0xD36B08A5ADB6C7FEULL,
			0x49F122E7BF8204BDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4B1FAFE777F477E0ULL,
			0xAFA193BE61B4C023ULL,
			0x4B0F15AC5E36CA00ULL,
			0x30AA54826DD29860ULL
		}
	};
	printf("Test Case 377\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x170A43E953DFE5D8ULL,
			0x5E7C744D2DFAF58DULL,
			0xF8DA98032A14EAF3ULL,
			0x4309037A1F9B4639ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFD64930B88253D98ULL,
			0xCBCCA62CB58A5FA1ULL,
			0x7A8C302EA938A980ULL,
			0x5649F0307F00E662ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6A1031337CE2DFE3ULL,
			0x0B26FFAEC748A918ULL,
			0xA1112D5167A67C2BULL,
			0x66374B62C399DA7BULL
		}
	};
	printf("Test Case 378\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4880CEDDE54453B8ULL,
			0x19C27219850BBC91ULL,
			0x0370C33C3572676BULL,
			0x6C6F8FB690581085ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEFF38B5447E6FA18ULL,
			0xC8C13F8D349CD699ULL,
			0xF2BE0A043FA8FE32ULL,
			0x5A90AFB63912BD79ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD4C002C7E23810BULL,
			0x43478931DE5CCF99ULL,
			0xED763242D8499EB0ULL,
			0x1A038C140B3E0C76ULL
		}
	};
	printf("Test Case 379\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1BD8159C991F9510ULL,
			0x114189298A146040ULL,
			0x6DD56F70FE6E2D83ULL,
			0x7CE01851A331C817ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x48E9091EEDB84868ULL,
			0x2EC671AC67031638ULL,
			0x7E99D1D1320D4CF1ULL,
			0x6D9C9150FA791C73ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB5ECDF921BD431AAULL,
			0xD9F14578821202D3ULL,
			0x3A5C6FF1820665D7ULL,
			0x1C57E7FC5F492953ULL
		}
	};
	printf("Test Case 380\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x388AE3C60293F3A8ULL,
			0x2A6427EF3706C868ULL,
			0xF7BE8916D3BF23C5ULL,
			0x5C6E4D6234511849ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCA931583240F1D08ULL,
			0x3E037D2DD045903FULL,
			0x1F0D6D67A3A4A621ULL,
			0x5D589DF7B2006F04ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBFABEA880E4EAF48ULL,
			0x3B8299F67FFEC9F8ULL,
			0xE0B276DF8BE7E382ULL,
			0x23503E9BD831FFC2ULL
		}
	};
	printf("Test Case 381\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9BA36F91828B2C00ULL,
			0x363E04A386787967ULL,
			0x627F87E3F6592B64ULL,
			0x71FD0A4C6F774E92ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16994E88CF4A9570ULL,
			0xAC4D7155BACEBDC0ULL,
			0x7911A58CF0015EE6ULL,
			0x798E3E91F9081D66ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF9CDF6A089224313ULL,
			0x5558E443637AFDE0ULL,
			0xA08FC4B3245DD025ULL,
			0x0573615625A8DBF6ULL
		}
	};
	printf("Test Case 382\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x860045BC1BC5D0B0ULL,
			0x6123227D9646CD1DULL,
			0x496A9BBE547F7F56ULL,
			0x5B53CDEE7EA61825ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5A1FE518148BC060ULL,
			0xF588BA0260262FD5ULL,
			0xB630DC17C8F82E0DULL,
			0x757DBC98F828BE8CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x90AFB02C1F31D60DULL,
			0x4B233B3D91C1240CULL,
			0xE2323CF6B486C7DCULL,
			0x5CC8EDA0394B4247ULL
		}
	};
	printf("Test Case 383\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5857260C7A62CFF8ULL,
			0x56D0453FE0410267ULL,
			0x56992A040880762AULL,
			0x4D63AB970B76F127ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4DAE7F6A2D8120B8ULL,
			0x887A17F8F399B1CCULL,
			0xB8E21872EE620E82ULL,
			0x494486579E53EEC5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB77C07EFA6E2E04EULL,
			0xDD7D7D9CB8EA1829ULL,
			0xACA905A8AA290A29ULL,
			0x0315A22949DFDD7DULL
		}
	};
	printf("Test Case 384\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3E23E3BCDF1D0258ULL,
			0xD04E5CD96171F972ULL,
			0x99C6D771D27DD79FULL,
			0x5D18ADF0843C37AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD296F740646767D8ULL,
			0xEF86049B2038857EULL,
			0xDA1F6640AD4128C5ULL,
			0x6C3398DEB80962FCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAEC52BB3AD92F82AULL,
			0xC4B535F8D069260BULL,
			0xB6FFE4433EC6FAC9ULL,
			0x097ED9DDAC600BBCULL
		}
	};
	printf("Test Case 385\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE776D652E8233CD8ULL,
			0x77C39A4C7EA74F92ULL,
			0x0EBAE4587A684265ULL,
			0x631023FE633FDF27ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB442ED4F48C1698ULL,
			0xAB33B60F3AF1AA66ULL,
			0x5FBF3FC78E605438ULL,
			0x4D1358CFB1653822ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3B30712E6A8C3F1AULL,
			0xA789EF789F60D1C0ULL,
			0x92C917871C897EF3ULL,
			0x2EEA6CAAB2CACFB8ULL
		}
	};
	printf("Test Case 386\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA03E4B4E6D2E2C08ULL,
			0x35725412656723CCULL,
			0xAD09CBB5711D3C5FULL,
			0x65C7B69FBA7E5122ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB9FB0407B33CA008ULL,
			0x53F8698BC361C210ULL,
			0x027DC83E68ED5309ULL,
			0x60D28C77D50D7774ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5639C1D9D11D9D36ULL,
			0xBFBD80BF2A779679ULL,
			0x8462B2F7252B7D21ULL,
			0x0B1A099D5F173969ULL
		}
	};
	printf("Test Case 387\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5D54938FD5DB04E8ULL,
			0x6D77D1FE69A8ED64ULL,
			0xC7171E4F3F7093B4ULL,
			0x6D0A136A69484BD7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE488C3A9EB297A08ULL,
			0x8EFF819802406AF8ULL,
			0x16E1A02DEDC08F82ULL,
			0x7C7EEDEFD91FACBCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC12F686DD97CB977ULL,
			0xB1B55C8C336BA809ULL,
			0x6AB1604817EBFB93ULL,
			0x094C570345817C95ULL
		}
	};
	printf("Test Case 388\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x633F6BA0361A9E50ULL,
			0x4EB1F4AA464F5803ULL,
			0x2975ED5CAC71659CULL,
			0x72D72EDBFA8B8F8BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x609F9E0A51CCE5B8ULL,
			0x2C5CB62140314EDDULL,
			0x0AFB3AFEA4BCE55EULL,
			0x58FE960A4F6C83CAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x18474F324FFDF072ULL,
			0x44550F010C6969F9ULL,
			0x1759FAE924280D31ULL,
			0x55175B988776AF0EULL
		}
	};
	printf("Test Case 389\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF726E82196A1A638ULL,
			0x4652C1E12B71DEDBULL,
			0x5EBBDE64DA404891ULL,
			0x5259BF7157670B17ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF8DEF9B919CE4A8ULL,
			0x124C9336E6E0AE09ULL,
			0x1A9AF0C82D6FA71DULL,
			0x6BF56000A710B515ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2A0E516B1DF0E328ULL,
			0xF066F6E3D993174DULL,
			0x344850F22A64EDD1ULL,
			0x7AF7AA977C5B0066ULL
		}
	};
	printf("Test Case 390\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x67B8174BF3173BF8ULL,
			0xC58302AFC3633EECULL,
			0xE4D186EB0B142906ULL,
			0x5978F4D77DB24DA5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D88D6CB2D6CAFC0ULL,
			0xFC9B07AA418A8E7BULL,
			0x01D6CE920D9A0F51ULL,
			0x49DFD26F7807A7A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8D158674F319C979ULL,
			0xB30C984CCDD1E5EFULL,
			0xCF5A8C8C984F8971ULL,
			0x7A386F4E94E5E014ULL
		}
	};
	printf("Test Case 391\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x757307FB2714F5E8ULL,
			0xA2890B7F6DFE7EBEULL,
			0x1C9449C75579DC0BULL,
			0x42264D142BE715C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAFB0A781607E5618ULL,
			0x842EFAE61655F89AULL,
			0x3FD9DD17F0EBFD87ULL,
			0x44ACCCEA73599313ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB36ADBD742AB22DDULL,
			0x0F1D0DF77451F619ULL,
			0x45908E98E4E609BCULL,
			0x5EEE11B70348BECCULL
		}
	};
	printf("Test Case 392\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x09259E966C05EA58ULL,
			0x863A4D86A8B3CDC9ULL,
			0x5D4323F4C10F6A37ULL,
			0x4572C5008114DB76ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3C1F349DDA44E030ULL,
			0xE6580C1E9DDCBCD6ULL,
			0x34172B953C0160B9ULL,
			0x5E264744A6A67DF0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x31CDD8088351EEE2ULL,
			0xA6C83F3528D95720ULL,
			0x45DF5169C0E89F99ULL,
			0x378D8FC1961D7F8BULL
		}
	};
	printf("Test Case 393\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6004A680C2260388ULL,
			0x43DB73215B435C6AULL,
			0xF5FFE6999DD3E471ULL,
			0x6B214A2F7B87C508ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x999E36121B16FF30ULL,
			0xD50E23397F31D627ULL,
			0xE6D6A1F559BAD764ULL,
			0x6CE0C8C849416AA4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF0D69A590B9A885FULL,
			0x7264ECB940B550B1ULL,
			0x3AE775BA727F9329ULL,
			0x3FD097F983F3A9F8ULL
		}
	};
	printf("Test Case 394\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x22BCBEB854CA5B28ULL,
			0x3CCF236B5FADB12CULL,
			0xF8AB4ABD067F0E52ULL,
			0x419791E6C3BD298CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5D5589D4585D0858ULL,
			0x9D3A72490EABE826ULL,
			0xBB510D87ACBB6D8FULL,
			0x57A5CDCC9F8AEC87ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB94F9CDFF8F5FA88ULL,
			0x8E3AE0A1CA3515EEULL,
			0x79A27747E4854973ULL,
			0x6E2A264116FD694EULL
		}
	};
	printf("Test Case 395\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x25D2CB092F8D88E8ULL,
			0x08DB21D0B4361EA0ULL,
			0xE16A560220DC4E1AULL,
			0x7D2D82F477E1292FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB1F05D3D7564AB78ULL,
			0x5A64E1C7D4E6C664ULL,
			0x6CB39F66770CAB25ULL,
			0x6A5F0EAD3BD05B39ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE99ED853740CDD11ULL,
			0x0FE1A4C43578CB96ULL,
			0x3550B84212C30FC2ULL,
			0x5652055CE1ABF81BULL
		}
	};
	printf("Test Case 396\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5169ED71FBA58DC0ULL,
			0xA816006A5273D4EAULL,
			0x2AF2991B80668253ULL,
			0x6B71CCF788159062ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8B01392194370D30ULL,
			0x97CC64D091DC22B4ULL,
			0x86D05B1759894F45ULL,
			0x5297FF95C00F001AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E26FACA066BB3CEULL,
			0x891CCB9EB5C2C4A6ULL,
			0x67BF890BAE959D18ULL,
			0x2FB30A13E6421C1CULL
		}
	};
	printf("Test Case 397\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC59A87BA74F446D0ULL,
			0xCBF631A7EE22F54AULL,
			0xBCD4D1C25E759082ULL,
			0x78746FF32B907BACULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF9874D66DDA65098ULL,
			0x88DC6257EDFD0249ULL,
			0xC19D082E39402531ULL,
			0x5D4CAA19179046DBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2BB99A23FAE9EC40ULL,
			0x77B997565FFBF7BDULL,
			0x9A6ABDD65E6143C5ULL,
			0x2B3CB6BED38235C0ULL
		}
	};
	printf("Test Case 398\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x59B65C0FCB9D9CD8ULL,
			0x752CB6611F96BA16ULL,
			0x8097C97BF74A72F0ULL,
			0x77EC6C139342656CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x65F4A5F37D1D3A28ULL,
			0x17F44D64C11E035EULL,
			0xA399479F05616B34ULL,
			0x799602D204CA6AC5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9279360D777308F8ULL,
			0x092D5DB55CA66583ULL,
			0x6E36834C9ECF7938ULL,
			0x4FF4BAE7450746DEULL
		}
	};
	printf("Test Case 399\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x592A6ECDC6E682F0ULL,
			0xB22EDF22C830B7D1ULL,
			0xD294611A8EC966F4ULL,
			0x745B91C77F879D8AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x615364EB981555F8ULL,
			0x1975F7D8C0A2B1DFULL,
			0x94525CB9AC3F3E88ULL,
			0x5DDA3D378171C1E2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE3D120A6215953E8ULL,
			0x6F53343BA6AB7F0EULL,
			0x350F95DFF0ABFC0DULL,
			0x3273B5E5E309774BULL
		}
	};
	printf("Test Case 400\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5FC42E8592FC0B38ULL,
			0x94091FE0561D6433ULL,
			0x5804200476CD4BFAULL,
			0x661711228828F045ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x49C8E79FA84431A8ULL,
			0x26D7EA5AD3C250BAULL,
			0x2A8A4A57DFF3CBB0ULL,
			0x6779F6C7A049C915ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x990027F438756F61ULL,
			0x58ADC2FCB7EA8FB0ULL,
			0xF131C1BCC319E0DDULL,
			0x234B1D27365EE68AULL
		}
	};
	printf("Test Case 401\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC2B28FA7107D3938ULL,
			0xA5983100F20C4D09ULL,
			0xD960DE159B850627ULL,
			0x6EE297B6943DC58EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1B14E855707FFEA0ULL,
			0x2C78698DB15CD013ULL,
			0x9568D80F6E6C5CDAULL,
			0x4273D0D935BE7161ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x191E02423338CADAULL,
			0x161695A7D9E5A4BCULL,
			0x2CCBE8421210D27BULL,
			0x0D869D89EC5D9E9AULL
		}
	};
	printf("Test Case 402\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAB8AB38E66B65220ULL,
			0xBFD0C013FE992E7FULL,
			0x8E94087C2A45C0B1ULL,
			0x7606DF91F63D737FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE5BB49AC388B9178ULL,
			0x5B77AF550141E3C5ULL,
			0x4B770090D0F8BE24ULL,
			0x7E3B2F2813A76CDBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x02D48E87A516E149ULL,
			0xA3B2DF08792BEECCULL,
			0xA4051C9AEEEEE7A9ULL,
			0x6C98D9F09C34F3E1ULL
		}
	};
	printf("Test Case 403\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8B24F374A4BCF608ULL,
			0xA0558B6ACCF44F87ULL,
			0x4BC451937E27DA84ULL,
			0x76DEB0EA3890D9CDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x267909E23C7F9BB0ULL,
			0x84A5FB67106094C8ULL,
			0x7DCD583C42B95986ULL,
			0x59CC83AFCC31E804ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x01840078079F58E1ULL,
			0x7C869A99D40C7A05ULL,
			0xD9471511455289C1ULL,
			0x6EDFD084870421F1ULL
		}
	};
	printf("Test Case 404\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x76C632D03DA41970ULL,
			0x4C6D2C3A1C1E7BE1ULL,
			0x3F14C217DC566C00ULL,
			0x6DB8717F7C2D6C8AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C0A0E2FF291A7E8ULL,
			0xD3BC42DC19D2EABFULL,
			0xBB968C2C5971DCF8ULL,
			0x562D25EED4860D61ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF16EF8BA85106981ULL,
			0x55233364644647A8ULL,
			0x7083DE7E468CB2DAULL,
			0x3D7E5E03D7419B68ULL
		}
	};
	printf("Test Case 405\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0A21AA0E22A68908ULL,
			0xF8034906A9A2871EULL,
			0xDBB29F34A3690746ULL,
			0x48FDD1494ADB0556ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x280782D85FBE93F8ULL,
			0x1E68667F70C2A960ULL,
			0xE0455649CAF8B45DULL,
			0x4262C542E535C98AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2E3BF2448CB7935EULL,
			0xAABFA2D4735C59BAULL,
			0xD1C37DA9935CCA71ULL,
			0x5C856B360DCA158BULL
		}
	};
	printf("Test Case 406\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x195379DEE97BA9B8ULL,
			0x8C9BEC1E3C3270A0ULL,
			0xADD44B7B89F11C36ULL,
			0x5174823202B64704ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71AE46B7C1A69680ULL,
			0xF06BF52FC976CCC1ULL,
			0xD106088C5F11DB93ULL,
			0x5B347A07C1665B0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x14FBC2BB55CEDBD6ULL,
			0xB19D5CEF3B602850ULL,
			0x7EC5425825C95B46ULL,
			0x78EA30D2370A1112ULL
		}
	};
	printf("Test Case 407\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x56CD7869C78F3AF8ULL,
			0x91861294740438E8ULL,
			0x7E96FB5D9F9E7F83ULL,
			0x439016CA4DF8D4C6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC92A251DEE361C10ULL,
			0x3E8CAB0845984F72ULL,
			0x34958EBFAC1454DAULL,
			0x7F3E4AB95A3B93E7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x412E1BCC7D88FB8FULL,
			0x1ECBD0918DD0C577ULL,
			0x40B23D66E1A90910ULL,
			0x67715864AF04F82AULL
		}
	};
	printf("Test Case 408\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6136DF8365CD3A48ULL,
			0xBF36F4357D3E95EBULL,
			0x26CE0929D2BC5F6DULL,
			0x7B7A2F6BA5482530ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7F0A29A64EB66D0ULL,
			0x5E84625F4930EE4EULL,
			0xE69724594F3BA69AULL,
			0x6D8B850BE7CB7E4AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5B5B892E1D615D2ULL,
			0xB5B000F904776C5EULL,
			0xD90675D78B1B8C1DULL,
			0x58401A9A4B2CAF06ULL
		}
	};
	printf("Test Case 409\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x847E82EE62F3CD48ULL,
			0xBE0BAE02D7BF4033ULL,
			0x64466366EE15368CULL,
			0x753FB26F9DB75CB9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF74B0ABF13E7E020ULL,
			0xFCD767CAF670EA4DULL,
			0xB15040A0FB072CB4ULL,
			0x69AC15F935B204DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A77B23F5CCA73A5ULL,
			0x194B237A8F48DABCULL,
			0xFB20F9072AD5FDCBULL,
			0x2584348F2B49DACEULL
		}
	};
	printf("Test Case 410\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x762EEC23305486F0ULL,
			0x37CC1CAF5E195C23ULL,
			0x8BC1BF6BA7920A51ULL,
			0x4C8BC02D110A0CBEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF45163D0CB2F7F0ULL,
			0x770819003A0A14C6ULL,
			0xA10181B4745E9744ULL,
			0x7BA1F24A2B9E7CE4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC2CFEF0A1B4674E8ULL,
			0x0C63FD10420B05FAULL,
			0x5E3D7BF8C0B576BAULL,
			0x5EF457CCD52B7983ULL
		}
	};
	printf("Test Case 411\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE92DDE2D03CD1A70ULL,
			0x01025BC2E4DBCD4FULL,
			0x5FC22802BB200231ULL,
			0x63F93B036657279BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x15BC5D4E1E5E4608ULL,
			0xB9EEC8C546EA5B5BULL,
			0x49A9D77F4A878CCEULL,
			0x5E46EAA937E037A8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEFABC34531767B44ULL,
			0xA01FBDFC157F2B77ULL,
			0xB8F6D3EF51963833ULL,
			0x5B8B377CAC0BF6DEULL
		}
	};
	printf("Test Case 412\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x73123DBEBE411C80ULL,
			0xEEC5C6833C8C63BEULL,
			0xA8EDF817F26B0260ULL,
			0x7D43A62E7D86D56EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8B6876ED8A54B9D0ULL,
			0xBB65F4B8B2CE01B8ULL,
			0xD1D3B2D5CCFDB598ULL,
			0x5D6D5A93B6F2F216ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2405A8150190AD0CULL,
			0xF160A5C5586493BCULL,
			0x6642FF7190C1BDB4ULL,
			0x7CB9E2942C672947ULL
		}
	};
	printf("Test Case 413\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5D6BAB117DE1E860ULL,
			0x8907AA7D674B9140ULL,
			0xF83E0BB6CA860A7CULL,
			0x67A8BC1859C9F661ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB1DE8B52C343DDA0ULL,
			0x8267746CCEC3FF8CULL,
			0xCB2392C0EEEC63F4ULL,
			0x549AD35722BF7808ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEBD2D737315E0750ULL,
			0x47D9F17261A8D677ULL,
			0xF5FCC5E817AB6A05ULL,
			0x4446780982519DDAULL
		}
	};
	printf("Test Case 414\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x779AF234111DAB60ULL,
			0xEF9AA6779C3609DFULL,
			0x9D8CEF62E67F0715ULL,
			0x5685B2BE5310CE83ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF7EADDCE30A13050ULL,
			0x14B1E43F855BCC87ULL,
			0xCD21A68D6C525D55ULL,
			0x59DFF8EB435C14ABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F8E05CBE951D576ULL,
			0xC6F0455E6E042A53ULL,
			0x7DB50B09C52953B7ULL,
			0x5374B9B6E53C6EC9ULL
		}
	};
	printf("Test Case 415\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xED157013986F7300ULL,
			0x338D98629E53629BULL,
			0x25702D175A8703CAULL,
			0x5DD419388E4AB3BEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x50B2EBDC9034BA50ULL,
			0x8FE9232165EE12ADULL,
			0x837D02F3E132F577ULL,
			0x567707135FB05465ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9086BD6A0869047DULL,
			0xE5E76CF637EBE56AULL,
			0x428B955D95609977ULL,
			0x57990E0FC639A7D4ULL
		}
	};
	printf("Test Case 416\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCC807CC6B4CEE8E8ULL,
			0x79A36E5E69D49E35ULL,
			0x8D9CC10CF864DC2EULL,
			0x7F7F08DDAA07B9ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7C97BEBEF4D4BE60ULL,
			0x651FA14D087CDED8ULL,
			0x482C9D08A3E54102ULL,
			0x5334145FDD95E785ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x33062B960EC5DB3EULL,
			0x36B0DD93EF60B119ULL,
			0x21F6C8CA9F0AE6D9ULL,
			0x4F0BEDD5C0C60195ULL
		}
	};
	printf("Test Case 417\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x82F8704FCF28FEE8ULL,
			0xFAC99105FCB6F80DULL,
			0xE3BB77C2436D5879ULL,
			0x621C9B800AC94259ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5706BF0EDDDB4008ULL,
			0xD2D22B10C6DE63EEULL,
			0x0B8F7072D1A57ADEULL,
			0x6F6F8C0F9C3EF3C5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDCF42012027C631EULL,
			0x14AC873257090B95ULL,
			0x1D2A349FFFA60BDCULL,
			0x00448B11C7C111D6ULL
		}
	};
	printf("Test Case 418\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE414EA5D5C3DEC68ULL,
			0x543EFBA9589AE241ULL,
			0x84A4EB25D8861FF7ULL,
			0x4E51C03EE8BBE431ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1290DB28C35745B0ULL,
			0x0C58501365E0322BULL,
			0x59C9070EEF6DD25AULL,
			0x6396F24946C6FF7DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x56E1FCF2ADC35342ULL,
			0xAF813E3282BD2D80ULL,
			0xAADFE560700287A6ULL,
			0x6B6FEE6E2FA9EA68ULL
		}
	};
	printf("Test Case 419\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEAC392A21DC56780ULL,
			0x424A0351B33C4872ULL,
			0x2E8D215DE34C4910ULL,
			0x61219F0CDA2A049BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C437D4251E21728ULL,
			0xD9F68B57E17F344AULL,
			0x3D6A0EED405F233FULL,
			0x72B684CEE6CE29FAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5F1C4DC3CAAE3CA4ULL,
			0x47494EAA03BD98A2ULL,
			0x724CB6B3A1BBA8F9ULL,
			0x6D37A809382B4F51ULL
		}
	};
	printf("Test Case 420\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCBA6A05AAFBCB3E0ULL,
			0x18F769D3571B9C77ULL,
			0x043BF9E997A16844ULL,
			0x7B47B83BB28954F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFB619908B9E8D498ULL,
			0x8DF8F8F204DD8BE3ULL,
			0x3C21F2BFC647C0ACULL,
			0x7281556EBE4C6D3EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEE06346E91026016ULL,
			0x1D146CD83C3116B9ULL,
			0x92141AC8EC40F3D3ULL,
			0x2930BD82A8D9D638ULL
		}
	};
	printf("Test Case 421\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6D8635B695C457F8ULL,
			0x432463833D013DBBULL,
			0x14DE95991A416D85ULL,
			0x5AF0ACB7EF564E06ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1227B490D16EFBF0ULL,
			0x8544ED6DB194805BULL,
			0xF8A0304744DF7164ULL,
			0x72D03B529BB7B04EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x87049E7D7AEB0570ULL,
			0x27575A5067C32CCEULL,
			0x5002FFCF3A8F68D1ULL,
			0x25BDB8910B5B8F6EULL
		}
	};
	printf("Test Case 422\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x67525CB38689B3C8ULL,
			0x8D9701430D51CFDDULL,
			0xCBF24C4453C225BDULL,
			0x747A5B7F9BD5AC94ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x163B3E59ECB88B70ULL,
			0xE9A7640E5479885AULL,
			0xF7736B31B6F9B554ULL,
			0x61ACAE1222118E55ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA210EFC5C32DF66AULL,
			0x9AD4C35AD78E0239ULL,
			0xC70B371224B19958ULL,
			0x2E7E856A9130BB8AULL
		}
	};
	printf("Test Case 423\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6121C8ADABEB7158ULL,
			0xB19CA1E5AF0BD65DULL,
			0x12AE31A6A82E57A1ULL,
			0x773F2F0B2C0A33B8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA869CCBDEDE47D08ULL,
			0xE0C3CE99F8C6752FULL,
			0xF0FCF4397434599BULL,
			0x5CEB4878A5DA306EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5F9557D72CFF3F6ULL,
			0x7C4AAAEDD9DF863BULL,
			0xC6C0FCB588D52274ULL,
			0x626D9FBBDB22E304ULL
		}
	};
	printf("Test Case 424\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x640E7483C69779C0ULL,
			0x67261A0121FC4BE4ULL,
			0x492E16E91AE7C142ULL,
			0x64FA37F00D231FFCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF107ADCB7D4FF90ULL,
			0xCA4383D5EB5CA5EEULL,
			0x20C91E203E80CAA7ULL,
			0x51FDFE632F759772ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x67A1D2F652BA4340ULL,
			0x083926D44CD1451DULL,
			0x1304D719DC4F1838ULL,
			0x7387C395FA17B2AEULL
		}
	};
	printf("Test Case 425\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFB87B0C7005EAC78ULL,
			0xBF0E8B0611707FE2ULL,
			0xCCFCF0C318A335C2ULL,
			0x50D1FD0999217F20ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD20C6CF8943D91C8ULL,
			0x07E13D445719D867ULL,
			0x216BB18DD148227EULL,
			0x40E8DED92CA0FB33ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA7BCF8F51478246EULL,
			0x1B94583D0343E372ULL,
			0x967BC8F22D63C227ULL,
			0x10D5B7B27A4FF6B3ULL
		}
	};
	printf("Test Case 426\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFB62B1FB8B4EF6B8ULL,
			0x5CCCC3245ABE2DA0ULL,
			0x77ED7E4D89A57455ULL,
			0x44FDF016A6172627ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4904206F75A3D9D0ULL,
			0xEE15FEAA5B87EC7BULL,
			0xC5BF0675A4B829B5ULL,
			0x48B43C9228A357EFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE1B83131789F1694ULL,
			0xDF6B7F74A3EFD014ULL,
			0xD2413AFDEDEF6BF0ULL,
			0x5986274BB2889FE5ULL
		}
	};
	printf("Test Case 427\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x3C501B8DE0299840ULL,
			0x9073EB9E0D472CA4ULL,
			0x488D3DC281FB590DULL,
			0x56C263AC1C3CAD7CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C529710A78CFF78ULL,
			0x87D4B5BB21D27A1BULL,
			0x177DFFCEA3F5D398ULL,
			0x450FCC98C98603F2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0A0088ACEEF1BCAAULL,
			0x126CD3ABE7690853ULL,
			0x271BB49C6599A89BULL,
			0x19813DA7A9E323AAULL
		}
	};
	printf("Test Case 428\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE94B2F67A2C8D0F0ULL,
			0xC001117FABA1EAB8ULL,
			0x5FCF82D5B989C81AULL,
			0x4972EE7A10B37050ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88F31BD7791FC768ULL,
			0xEFBF0826ADB57968ULL,
			0xC57FA1C92893E425ULL,
			0x75BD6ECF82C2B064ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAFEB5F83415E1766ULL,
			0x134F82E6DD1F4ED1ULL,
			0xD38FE73CF2456C14ULL,
			0x7843984E96FDBE3AULL
		}
	};
	printf("Test Case 429\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x483CED50ECB9BF10ULL,
			0xA8B7073E01FFFD24ULL,
			0x802B99524DF1F6C6ULL,
			0x483DD8B4F9D232C9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD392EBD6A6923E0ULL,
			0x704C45BC10C98844ULL,
			0xE9EAA3783C9FF7D9ULL,
			0x5349BC0F8FC8D6F6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB5D757CF0F48B98AULL,
			0xBC92ADBA7657142CULL,
			0xC8C9297B13E40FECULL,
			0x3A1C5A129456384FULL
		}
	};
	printf("Test Case 430\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x17EDAB06D1CED1D8ULL,
			0xEE9C9C00FA4769B2ULL,
			0x1625025F8E9DE07EULL,
			0x4B3A4FB8261E2A3CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x762889A5B76FB4B0ULL,
			0x5F83E338DC432331ULL,
			0x94DBEB2FFECE36CAULL,
			0x7CCD85B8C764017FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBBC23230E426752EULL,
			0xA8F0AC78E91389BFULL,
			0x011C51C524FF6B1BULL,
			0x47880B8ECB471061ULL
		}
	};
	printf("Test Case 431\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x85463EAB9D259700ULL,
			0x89BD355ADA2B4B4AULL,
			0x1D07155335A8A018ULL,
			0x6D4299E7CDD72A3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD6182C3976EB8728ULL,
			0xA2605DC352EEAF8DULL,
			0x9649A6E11EEF7B37ULL,
			0x6224321B77654DDFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x54158BFF42796078ULL,
			0xFFC3C46D7516A19BULL,
			0x9BA0359AC8D141E9ULL,
			0x27E494C1C459129BULL
		}
	};
	printf("Test Case 432\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x95EA3DE28B1DDB28ULL,
			0xA0D7C4BC59A6081DULL,
			0x061F74DF14D49BF9ULL,
			0x41648E238E7A184BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x01BAC6BDBB4A4D90ULL,
			0xC1A807910BDF6450ULL,
			0x8223644F7235CD11ULL,
			0x60309E94FC060654ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6367DF6F41E102AAULL,
			0xC99BC5C03E1670BEULL,
			0xE9236449AB31BD77ULL,
			0x2A0FC5892BF773E0ULL
		}
	};
	printf("Test Case 433\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEC1E8D0D66144770ULL,
			0x15FF2C541630D4BFULL,
			0xDEDF2DA823990EEEULL,
			0x65E72D08C171B278ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE14597FF42760200ULL,
			0xECC10571D5CF8FB6ULL,
			0x09250A7D31AA3829ULL,
			0x7432834DCCE4504BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x32AF77A7DA3CAD71ULL,
			0xEEBB917F27064428ULL,
			0x1E477F706237B0D8ULL,
			0x6CCF10A9532EDC34ULL
		}
	};
	printf("Test Case 434\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE688594988309068ULL,
			0x9F13CDD83023F38EULL,
			0xF4477231B3F31EA1ULL,
			0x6C9D36BC8E3A101CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB54AA5997AC62370ULL,
			0x41F2ECE222F94C0CULL,
			0x73BBB579B5EDECD9ULL,
			0x7C7722ABCF078B15ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x13CB7ACD44B06F7CULL,
			0xC81FB56AC3C9FA61ULL,
			0xFC6C562102E43C09ULL,
			0x24D669792D3D5E91ULL
		}
	};
	printf("Test Case 435\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8EF64129E0F5B168ULL,
			0x32BEAA040F7826A9ULL,
			0xE2C2E7FB3701A6B2ULL,
			0x66335793977BD14AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x55D794966B52D440ULL,
			0x64B6E11CC0E1DC3FULL,
			0x36FCE14CA9C08A0DULL,
			0x767B3A047F613049ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE540711F9C5A2D31ULL,
			0x266FE4869B6486DEULL,
			0xFDC4DC18679118AEULL,
			0x67F51A3C2CBAC42BULL
		}
	};
	printf("Test Case 436\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC380AD6A38E03948ULL,
			0x5DB7165FD1C30F93ULL,
			0xA3EF3995F754206CULL,
			0x55FFD7EA2E87A1F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC9FFF75CCF29F490ULL,
			0x86EE77CAF626AC6AULL,
			0x64938F6600FCD4D5ULL,
			0x609A26DA7BD140C2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x866F696051804409ULL,
			0x13FDD93C50A737D5ULL,
			0x5976745F6E7F7BE1ULL,
			0x46B9C322971B092AULL
		}
	};
	printf("Test Case 437\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7EBAAE40F411A610ULL,
			0x1A0452797F3C1DA7ULL,
			0x207BC602661EBACCULL,
			0x5312AC3608D773B5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x586BDC00C7657850ULL,
			0x92F01DEFA0131CB1ULL,
			0x98E133620C0D54A3ULL,
			0x4245FCB69A0E8132ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD6EB60E281ABC31AULL,
			0xF9FF8F1881A560A9ULL,
			0xB7461080A315A47BULL,
			0x6EF3153458428566ULL
		}
	};
	printf("Test Case 438\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA407325B768FAEF8ULL,
			0xC51897E5822AB21EULL,
			0xB222C7980E9399B3ULL,
			0x4E5C750D9DF97669ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72E5781C1DF35698ULL,
			0x3BB77FC92187BF32ULL,
			0xBE65D6958723BC47ULL,
			0x76E8D17A82248462ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEF6B71D915C0179BULL,
			0x27CED58B77F2AC95ULL,
			0x23858271D5DF3F46ULL,
			0x050240E4B0F76BCAULL
		}
	};
	printf("Test Case 439\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB1E290909C90B400ULL,
			0x17ADF985F7F2C241ULL,
			0x256EAC4FDD5C4E18ULL,
			0x77542B0F87427DD5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x44B560D707885B10ULL,
			0x1CE1E094B2FCD530ULL,
			0x93C481C737B1F5C8ULL,
			0x62BFC0F616B14824ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x05685564B3FF5686ULL,
			0x95327ED75DC7C660ULL,
			0xB998EB5BC391A80FULL,
			0x41107E6A177F0C88ULL
		}
	};
	printf("Test Case 440\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x847DB2A208337618ULL,
			0x70DBBBC52DC57CA5ULL,
			0x000E8861D7AA20BAULL,
			0x58A136002F4E2240ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E23B872C76A0608ULL,
			0x4C29192811E9C151ULL,
			0xDAB0C13880263070ULL,
			0x5554C11CDDAACF5BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7E3B41F5F6634C42ULL,
			0x56663581B8C4A8E3ULL,
			0x41F0A07D20BB6030ULL,
			0x5978BE636147B156ULL
		}
	};
	printf("Test Case 441\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDE8A6D2C1ECEA230ULL,
			0x08771C8876B33F97ULL,
			0x843CDAFE3F25B97AULL,
			0x563F8B889A3D7C10ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9B49A29DA57AE120ULL,
			0xCDD2F5BEE231ABA4ULL,
			0x850DE6453794FDCBULL,
			0x4C61469D445A2297ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8537655070FA9F5EULL,
			0x27F42FE630C1D0F5ULL,
			0xF414B6F2C2DFDFE5ULL,
			0x3B9CF477BEA50608ULL
		}
	};
	printf("Test Case 442\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xFF2284892D887F90ULL,
			0x686D23FBB47C911DULL,
			0x43B2EE3C722009A4ULL,
			0x79E335F01F8C4C24ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54B68FFF1A4B28E8ULL,
			0x8CBE5FAF88A74A77ULL,
			0x0AC0AF215325BF30ULL,
			0x489D44A4F75791FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x84836F13E7128845ULL,
			0x77125E0DEF970169ULL,
			0xA9A3C119ACD8C9CEULL,
			0x6C357D5A9A8DBC8EULL
		}
	};
	printf("Test Case 443\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE1C4D6033C3ECF88ULL,
			0x77D040F51126BE18ULL,
			0x00E598804878700CULL,
			0x46BAAB0335AEF7F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE456224F23B06608ULL,
			0x9A9737F3B7005E58ULL,
			0x20D75E41B140B3B3ULL,
			0x7D7547460D27BD36ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9E37A114CF773C9BULL,
			0x2B912BF2555E0C2CULL,
			0xFBBC8EE8B67980BBULL,
			0x313E2B0C9AC2C0A2ULL
		}
	};
	printf("Test Case 444\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4850DC28B11DACD8ULL,
			0x05D7046F9CDB1698ULL,
			0xECC6A5CDF42585B4ULL,
			0x45BF26998B66BFAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1CDADC589DE337F8ULL,
			0x4F7346C9644B7EFDULL,
			0xDA7BA2ECB5E93407ULL,
			0x407400992C5D38FBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37E87DBC6F87E7ABULL,
			0x42899C2DA485FF98ULL,
			0x8D76D3D4FCDF68CCULL,
			0x2A69FF4AD60B7439ULL
		}
	};
	printf("Test Case 445\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0CD8DB08E99F1808ULL,
			0x688BDD3019AEEB45ULL,
			0xCEF50AF8EDA43EA8ULL,
			0x78276C196791E46EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF430BA1C4580B1A0ULL,
			0x4E4197604A905EC4ULL,
			0x49A442FF874F0170ULL,
			0x67BA69D7E94BB0BFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5742F7428C975A67ULL,
			0x2636B69B3534838AULL,
			0xB26B209DDE14B028ULL,
			0x49913CFA31841717ULL
		}
	};
	printf("Test Case 446\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x890E524DC8E38C48ULL,
			0x925214BE5C7CAD1DULL,
			0x18A20014E9DE8536ULL,
			0x58A5758BD0A0A011ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1D752A0DC6F620B0ULL,
			0x09627ED6635F2186ULL,
			0x64E83C2DAD5D2675ULL,
			0x764CC8D0413969D8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF3462F8EE674C3F2ULL,
			0x8FBB4DDB47420027ULL,
			0x868BBFA579E7A6F0ULL,
			0x26E723DC9F766C8FULL
		}
	};
	printf("Test Case 447\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xCCE0F232050A6488ULL,
			0x9263E8261C641505ULL,
			0x2FBD73F55D9C8BC3ULL,
			0x7BAF95DAD1BB176DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x61468EEE00FD7E68ULL,
			0x4FA961D6343049DEULL,
			0x5B925C067AA973F2ULL,
			0x4F7486FD8D3058D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD2936C9744552969ULL,
			0x5CD3270AA75B941BULL,
			0x8C32695803091CFCULL,
			0x1291C64AD05D87EAULL
		}
	};
	printf("Test Case 448\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD3F82B8F1B701928ULL,
			0x0E76CFF50D7A2BACULL,
			0x98DA57AA833BD4A1ULL,
			0x7CB77487B43D56E5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54026198A09D6470ULL,
			0xCDBF4D369FD6FE79ULL,
			0x33A3DB9EB2303ADEULL,
			0x4C68562761712CAAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x22B726BC98DB5B3FULL,
			0xCF831538E094270EULL,
			0x1FE5AF3FDA51B7DFULL,
			0x14686C74A1D8DCFEULL
		}
	};
	printf("Test Case 449\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBD43610B3E3D5E58ULL,
			0x43821C17292B5C02ULL,
			0x9F528B7CE03D1A18ULL,
			0x40D893B163E0B0B8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB9B7C7D83865DAE8ULL,
			0x832B38F2514CB4F4ULL,
			0x16516134DD054A50ULL,
			0x59D57D7988D835D0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF1004C0F1B306F15ULL,
			0x127E087A106D874BULL,
			0x8AF3AFABDC054D8AULL,
			0x012AAAE970AABABCULL
		}
	};
	printf("Test Case 450\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD5B7211DA9801108ULL,
			0x85FB9B03E0AF603EULL,
			0xB6200F1802D27994ULL,
			0x64405A4972E71011ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEF378D3E92CDD978ULL,
			0xA54FAF3DC8222C1CULL,
			0x7105D1D58AC4A8B9ULL,
			0x513DDC1BD7AD52E7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x11FECC377EA801E0ULL,
			0xC85DB395F0D77E65ULL,
			0xCADAB51B0447E779ULL,
			0x14F07B7466D9A265ULL
		}
	};
	printf("Test Case 451\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE885D8DB9C725AE0ULL,
			0x6CC423E71488254AULL,
			0xC9CAE42B40CBB955ULL,
			0x49F4578BD2E20019ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF94C262714DDB2F0ULL,
			0x5EA98A2836464742ULL,
			0xDC13B3CBB557CF41ULL,
			0x5F57110A69052999ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x67C863D272E7891DULL,
			0xF0FFA29DF008346AULL,
			0xE3C0C196401792D6ULL,
			0x3C39862F42329334ULL
		}
	};
	printf("Test Case 452\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x93AD7EEF9E1A4478ULL,
			0xDC9EF8840846C3E3ULL,
			0xAA9A4420F1A96285ULL,
			0x42FA18EA9B3CB714ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCADC6E819272C740ULL,
			0x529DCCBE95CC72CAULL,
			0x864F79D701B07DF3ULL,
			0x6C2FC3493A4CB18CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC6EF5116A9F32B62ULL,
			0x1F6FE70FBE2A30ACULL,
			0xFD0D09CBBF5B0FCAULL,
			0x424BB3034E92FA7DULL
		}
	};
	printf("Test Case 453\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x60723486F41A5FC0ULL,
			0x006A6A85759D466BULL,
			0x05128EC1E00E38A3ULL,
			0x5A6603CC10D8159FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC72F7704ECC200B8ULL,
			0x4B0DCF00F85F1407ULL,
			0xA01F7D5936D289D9ULL,
			0x6A06D8337720BDBAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB91F0550C5032B1AULL,
			0x24126720785BAD91ULL,
			0x5055A37F21D5CF67ULL,
			0x547A22B19808E9A0ULL
		}
	};
	printf("Test Case 454\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB0A88FE1350B5658ULL,
			0x57984C876A9C8362ULL,
			0x04A6C09D56FF0162ULL,
			0x739B94D56AC16ED1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x605A546EF7635188ULL,
			0x5AD06C743E38EF2AULL,
			0x6321899179EC71C2ULL,
			0x69ACAE77ADEA09FCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x17F5340318E75D1BULL,
			0x63C77F104DBBBADEULL,
			0xFC22A2A6B75828FAULL,
			0x08281A2C82CA297BULL
		}
	};
	printf("Test Case 455\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x41173B18B7150A68ULL,
			0xE253BE90E652F71EULL,
			0xEFFB39C2C5160351ULL,
			0x776826312FD121B2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E6F204BCC44D720ULL,
			0x49FFA8824854609DULL,
			0x1C97071B249EF662ULL,
			0x455743BB7942EFFBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3A914D3C4BE98EB4ULL,
			0x738EE785D50FAE69ULL,
			0xE76AE0925B5EEE85ULL,
			0x4A9BD488F87BCE6BULL
		}
	};
	printf("Test Case 456\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xAEFF62DF02F297C0ULL,
			0x7DAD16886127563CULL,
			0x37E1CB2C3FBD5B12ULL,
			0x56356C6BB518D3D1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA2122D66189C18A0ULL,
			0xE7D348F979FD9FDCULL,
			0x1909A4F285342487ULL,
			0x53A55B14FE219D36ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC060896E7D6F61B9ULL,
			0x6306776CF75ABDEDULL,
			0x1C465A65F5D83902ULL,
			0x030CF6CC11E2E543ULL
		}
	};
	printf("Test Case 457\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6EF427EC94A32CE0ULL,
			0xDDF893EA97CD5036ULL,
			0x190BD12A478CA4F3ULL,
			0x5E731F6254B46849ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0F53A4D3A28E0360ULL,
			0x807B96D9F87EAD79ULL,
			0x1D57F7E33B33AE6EULL,
			0x610BEDA5EDD32B09ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x26666263BF9FE2C2ULL,
			0xD8D85656DF9DC738ULL,
			0x72B035114BA7FCC9ULL,
			0x655E4271B84EBEA4ULL
		}
	};
	printf("Test Case 458\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x04128BDFD941BEF8ULL,
			0x1EC49282A59B6428ULL,
			0xBC39C22D30B50A16ULL,
			0x4D1F5368758E3A78ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xED1D044E9B1CE4B8ULL,
			0x9F10CA4980B7402FULL,
			0x611C1821CD4596A3ULL,
			0x6CBD7595C4402FBBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8D58FA1DE2D2147DULL,
			0x44F17DFDA9F22D24ULL,
			0x9B1DBE203CA08E2EULL,
			0x6BACA1A7EFD746D2ULL
		}
	};
	printf("Test Case 459\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7F2A924B24B3E250ULL,
			0xAF68D00D4E15E939ULL,
			0xB2FB37478620B94FULL,
			0x61B69404EB48CA9CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD795B0D0A011780ULL,
			0x6A06D9017BBCDDA6ULL,
			0xBEB6BED0C0C4A655ULL,
			0x51569C515E6C1FEEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47472D35635C6281ULL,
			0xC597AF8AC4116A91ULL,
			0x5D8C62EBB4518FA5ULL,
			0x32FD117B00AD8E9BULL
		}
	};
	printf("Test Case 460\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x10EF6AA3B8B32AA0ULL,
			0x354B313A4E38AB4CULL,
			0x0EDC08B25200B1E2ULL,
			0x4381E5C5493AF8C5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x21498E5379FCDDC8ULL,
			0x9CD2FD89818E805DULL,
			0x0B247881B8E5A375ULL,
			0x50D8FB5AAB87AD46ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x42093D52B1715360ULL,
			0x91879CC6C63AE2D9ULL,
			0x3DABC8F9E0198D07ULL,
			0x0C69C53B9DF08ECBULL
		}
	};
	printf("Test Case 461\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x04F1575C95A4CDD8ULL,
			0x1308032C2759B38AULL,
			0x8E9D6476DACE87F0ULL,
			0x440622E690A6DEC9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8F41C900B168FAC8ULL,
			0x3DCF8568AE2CFEEEULL,
			0x2A43F7386DBE6863ULL,
			0x5CC016BC2ADDAF87ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5CF14865A8F94AECULL,
			0xFEFB6FAF5C2211C5ULL,
			0x85C4431360582086ULL,
			0x12FA24943391E26EULL
		}
	};
	printf("Test Case 462\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x75796470D77A6CC8ULL,
			0x06FF3127A5D1B6B1ULL,
			0x233624B824764133ULL,
			0x62568F090530D2CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9976F6CF25DFD9F8ULL,
			0x1FBB5C12F423E662ULL,
			0x5AAB90F1E226AC56ULL,
			0x48E21606DB959BFAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x314C3CDC1D6E1D73ULL,
			0x0A36F448CE7B3329ULL,
			0xDE0DC4E3C939B679ULL,
			0x63275F72BD9DBA1AULL
		}
	};
	printf("Test Case 463\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x4A630685FDC3D880ULL,
			0x038F06F3A22DA032ULL,
			0xDF677CC267F02EC6ULL,
			0x75BAFAAD9D8F6561ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE9A3A92557FF3C30ULL,
			0xA242D4467EC68199ULL,
			0x20EBCE150037739CULL,
			0x42A471FA9A28771AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEBD644CE30B54315ULL,
			0x4DB054E9CF45F50CULL,
			0xB241E35247005F78ULL,
			0x7207A0397C2ED51BULL
		}
	};
	printf("Test Case 464\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC16CC5F872E29B00ULL,
			0xAB81669701E7C29DULL,
			0xF3BB425E8DB276DFULL,
			0x4401A929E013E389ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3520817B3914B330ULL,
			0x8B4F3334D4C32E8AULL,
			0xFA0AFD808F6CCCBBULL,
			0x7AAE5F0EF3803396ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x431865A8460AB148ULL,
			0x1F6494691E5DC282ULL,
			0x4EB58337D19A0BF8ULL,
			0x00A8E12A6DF41725ULL
		}
	};
	printf("Test Case 465\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x042A986132AF68B8ULL,
			0x10E98C84AE84AEF4ULL,
			0x0057E0D5D4EE43C2ULL,
			0x6667100EBD4CDC27ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4FCD21F793E6E4F8ULL,
			0x277DA07F72D872FFULL,
			0x7CF8B067917853C2ULL,
			0x680ECE2B32DB5723ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7A5A0DD1003B3FB3ULL,
			0x79E50E0EECF90D7DULL,
			0x2DA2433732B6DA17ULL,
			0x293FDD578BD20EA1ULL
		}
	};
	printf("Test Case 466\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1F6EB1A4AB4DD298ULL,
			0x0B7CCFFC792AB1E9ULL,
			0x465724E670164BE9ULL,
			0x699979805C4A125BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC45697BDDBB13D68ULL,
			0x8284E73942216B05ULL,
			0xE8681613C151E64AULL,
			0x650737CBD3C289EAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2FC31F35DEA2EE6BULL,
			0x3879E901D205C0B6ULL,
			0x3BE8DCBF831E554EULL,
			0x2F9C8A1E14C3E9D3ULL
		}
	};
	printf("Test Case 467\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD785ACF8671EA880ULL,
			0x0D24A7575D58373CULL,
			0xF4759D6AA2C51822ULL,
			0x45E401B502970EB5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8FAF06482ECA8BD8ULL,
			0x8CCD8A6374D7212CULL,
			0x4ECF48BFB21085AEULL,
			0x6DE8986A3FC41808ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7BE2BF21B791A6C3ULL,
			0x95ABA9B58E8ECC13ULL,
			0x9C0D37D58532ABA9ULL,
			0x563E27B906AA03CEULL
		}
	};
	printf("Test Case 468\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xDA68BC0BD6C501C0ULL,
			0x01E94D540775EDA6ULL,
			0xED93860EFF0DE294ULL,
			0x7B1D2DD9E7791014ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x83D88225C9B67050ULL,
			0x0D276AA1DB52676BULL,
			0xC80193350D65278DULL,
			0x5E729A9561478305ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3831CCD02450E778ULL,
			0x24934B1FEFB57300ULL,
			0xBC655A8F583FC876ULL,
			0x47C61F4173F79D46ULL
		}
	};
	printf("Test Case 469\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0A68A094BC9DDCC0ULL,
			0x97D45ED60A304347ULL,
			0x288A53A56CC43A2AULL,
			0x65C8E6B7BCCEEB42ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8EA7D50B4A31D030ULL,
			0xC20F8D19C499F602ULL,
			0xD140AB3F096C2CF0ULL,
			0x61CC008C82AFE42AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2ABB90F3CFD0CD30ULL,
			0x0A0A20A5D4D2C86DULL,
			0xA6F4A231BA80A4ADULL,
			0x18C61284166F49FDULL
		}
	};
	printf("Test Case 470\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x0FD56ABF196D1F98ULL,
			0x2CE8D41F4D9D635EULL,
			0x923950418B914622ULL,
			0x4F5DDE38101F69E4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D11BB19C6441800ULL,
			0x4F558B9E3B311D96ULL,
			0x91D00FB74F156FC6ULL,
			0x44D1C2BFD6BE2DE0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC4DC9688F91B2BC4ULL,
			0xC6B782640A85464AULL,
			0xA6DFAD09C806905FULL,
			0x5E28F1E0450A6EFDULL
		}
	};
	printf("Test Case 471\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x12584C40D38A3130ULL,
			0x201D0814EA249607ULL,
			0x100CCFAB06633D29ULL,
			0x4126DC62D4B28FA3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x21DC807FB6CAFC88ULL,
			0x4CAB994D8EC741C8ULL,
			0x07B8EDD7D284DE36ULL,
			0x5E16CD1F3B4647A8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x88B675BDE8D56B54ULL,
			0xB75BAE348770A3E1ULL,
			0x40BC85BBF829E747ULL,
			0x05455C497E385BCCULL
		}
	};
	printf("Test Case 472\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8926EB8B891EF828ULL,
			0x7E86EBF25346E8D1ULL,
			0x25D7353485226FB4ULL,
			0x640DB8FC8FED2FAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF4F3B149408C738ULL,
			0xDFFE30458341969AULL,
			0x12A187CC4A752513ULL,
			0x5E2E8994102581D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD5FB9F77FA4763FFULL,
			0xD183C71A477054CFULL,
			0xFF8F889B4C4A81E3ULL,
			0x4F8625CFC6AE63D2ULL
		}
	};
	printf("Test Case 473\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7A40223A7E6DE080ULL,
			0xC657D2193CF1F94FULL,
			0x23F9E3DB48C38828ULL,
			0x492F05CD6137CE07ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8D3D24EC0E93D410ULL,
			0xEFE85DA42812D283ULL,
			0x1B4454D07C5536D9ULL,
			0x70D5A174A33C310AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8DB2B7FD62CD3110ULL,
			0xECEE58E2DA98FCAAULL,
			0x58C407FF93339E8CULL,
			0x12B75727B2206CF0ULL
		}
	};
	printf("Test Case 474\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x81AF20B77872CB70ULL,
			0x0537309E4FDC08BBULL,
			0x0016A1EC75C7C2C5ULL,
			0x5863AEF5D32462FBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3B24676319C83630ULL,
			0x1621945A952165ABULL,
			0x520C1A425CB34851ULL,
			0x4FCDD96A25785962ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3E36246B6DCCD33AULL,
			0x584F168DB9AD76F3ULL,
			0x4C62333C1A2DB3D2ULL,
			0x10478C293395EC6FULL
		}
	};
	printf("Test Case 475\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC7D87C520EF2FB50ULL,
			0xA71D97F7BBDB5BC6ULL,
			0x59338F05B1064871ULL,
			0x42ECEEBC4F02B53DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7C26B4484165CC10ULL,
			0xBAF5632B2CA77561ULL,
			0x5F244AC0776ED0C8ULL,
			0x760FBF655EF7DEA3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5750EDDD6E4FAD30ULL,
			0xBB79BBD77032E50FULL,
			0x8B93A46DFE8F9241ULL,
			0x240A07B98639E1D2ULL
		}
	};
	printf("Test Case 476\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x74C3DE984530DB50ULL,
			0x13938DDAA8ACFED9ULL,
			0x24570C364965A09AULL,
			0x5CE0D4AC940C84DAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x35A08A4F82ACE540ULL,
			0xFBAE3191A66C2892ULL,
			0x50120DCCF0DF3FC8ULL,
			0x4D919C5661468141ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA48392E67F5D7030ULL,
			0x0CB19E7AE5314F69ULL,
			0x4FEF1D419212736DULL,
			0x5162341B7EA842C6ULL
		}
	};
	printf("Test Case 477\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x51D79047049A2DD8ULL,
			0xEE5DC2CAE71DA1D8ULL,
			0x421E378E4BAE6D4BULL,
			0x7462D1EC1B41CC84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCC2296534E202338ULL,
			0x8DE1E5F4DAF74BD4ULL,
			0xE11E4CE21705A122ULL,
			0x61260DDADD5B9D87ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x39C2F9C5882A31A7ULL,
			0xC8009537D2BEAD57ULL,
			0xE7CA074D462C9E34ULL,
			0x6FD765A3BD6C7154ULL
		}
	};
	printf("Test Case 478\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1CE1760491521F48ULL,
			0x6F0FB5771C74E7D3ULL,
			0x9FA736760B096B3BULL,
			0x6BB910938B010384ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA8CEF0C0897BA538ULL,
			0x83027847E6543540ULL,
			0x85AA4B8C9978EECAULL,
			0x5BE3F08150492C83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8D57424C7C8F78ADULL,
			0x0104428251208095ULL,
			0x9EE7838F5188B4F4ULL,
			0x78E613428978F763ULL
		}
	};
	printf("Test Case 479\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6CAA83AF620D34A8ULL,
			0x7B3D46F3DE6D3E8CULL,
			0xCE516E153FCCD235ULL,
			0x67DE183E0483DE52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFE26286C69CEFEE8ULL,
			0x3DAF10DBE25F9E09ULL,
			0xD6EE1A703ED3D5A4ULL,
			0x7A9642D8FB7FB845ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE58964D9428478C5ULL,
			0xEE305B59A761A323ULL,
			0x140A9F3706DB770AULL,
			0x207C14D05F8E5536ULL
		}
	};
	printf("Test Case 480\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xD534189C80AA18F0ULL,
			0x1DE1D7D0A00CA138ULL,
			0x12E97DBB35B510C6ULL,
			0x6AE07BF652B18EB2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x756CC01865762A68ULL,
			0xFB7F6BB42B11A700ULL,
			0xA623972D6E2C3A71ULL,
			0x7827D1B791516541ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x856DAFF522C85198ULL,
			0x8C6AC832A23CBEC5ULL,
			0xEB26E4D8F7A3D680ULL,
			0x62EFB46365D33DCBULL
		}
	};
	printf("Test Case 481\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x59E5D71EA97268E8ULL,
			0xA25CF3B6BFBAA899ULL,
			0xBE09A7CDFCA4E875ULL,
			0x71B23E546A988EF5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x99D6DD2EB8A29EE0ULL,
			0x0341F17B85DC7B85ULL,
			0x70D322E0F702A2D8ULL,
			0x4338E55472AE5B57ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC8B4CA0B0D822B91ULL,
			0x3064E9B716103ACAULL,
			0x2D01C8681DF9B66AULL,
			0x10D075E68C95BE6BULL
		}
	};
	printf("Test Case 482\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1D4E27C47869D500ULL,
			0xCB71F9C4887FE4F0ULL,
			0xC0E1DDDE88032D29ULL,
			0x464A8EF69D32CF1CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBC6643D4232C2780ULL,
			0x7B2B45C20D3F5740ULL,
			0xE48BA1A2C8824A9BULL,
			0x5D96B81957170304ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B2A97F9C0BC5753ULL,
			0x4398CD82094657C8ULL,
			0xABB66958910D3763ULL,
			0x5004B863AE34999FULL
		}
	};
	printf("Test Case 483\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA72AEE374BB436F0ULL,
			0x46F826266F8E58CFULL,
			0xE360C822A00B6F45ULL,
			0x781C97A30C72C56DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAC6F6888DD35AAF0ULL,
			0x5144C20A04192254ULL,
			0x05A21EE891A613FEULL,
			0x5243D3AF8FEAB251ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD832E444565D32BULL,
			0x13B024377EE8ECDFULL,
			0xF3F90A33DED71DB9ULL,
			0x4BDB17E05B316B4CULL
		}
	};
	printf("Test Case 484\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xC93156D7F72E9670ULL,
			0xBAE8A038AF4701CDULL,
			0x12EB75FC9A09AF8DULL,
			0x4612CCF2D25A9EEAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x61B0907A0CEC7D48ULL,
			0x53A813648539205FULL,
			0x3B7AD8837846F3AAULL,
			0x5A21B3EAD529CDBEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA93F895F7A7CB9CCULL,
			0x6E6B112BCC8A530EULL,
			0x2D1C11B8ACAA9F94ULL,
			0x46BA443BB83AB96FULL
		}
	};
	printf("Test Case 485\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x817ED5434E2C4A20ULL,
			0x6BFC02A728D35597ULL,
			0x6FCC37999C3B46BBULL,
			0x5967464B4CF13B2EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4F22E480632EA060ULL,
			0xAFE2E5590CBAA1D7ULL,
			0x9B0E7C57438127E8ULL,
			0x7AF290EA6FC97A13ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4DA1E9D8822A98CEULL,
			0x8973341564EEB254ULL,
			0xCD33DA797A9C7178ULL,
			0x57A29DE8D8DAE9A8ULL
		}
	};
	printf("Test Case 486\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x433C89E13ED46170ULL,
			0xE3E48FB85A39B5E4ULL,
			0xF5340576C01EFBFEULL,
			0x6244478668F69E0EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0346F00AC0E90338ULL,
			0x6C4158E5CAB1101EULL,
			0xEA5B04A2888C5D55ULL,
			0x42AC5DC11CB3EB11ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9B171F1853314D1FULL,
			0xF83E656DCCED8F33ULL,
			0x2217D1726FCC3BEAULL,
			0x5A208875D9CF9F4CULL
		}
	};
	printf("Test Case 487\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xBAC7CC8CC9457AE0ULL,
			0x481C6C672681782BULL,
			0x1EA551EC3976F548ULL,
			0x57AF872A3A2C679CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x569445936C8109E0ULL,
			0x2CB96DAF2751CF35ULL,
			0x6A66D2835918323EULL,
			0x71A0E5EC0880A047ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9900B21D9DE8594DULL,
			0x584127A2C25AB73CULL,
			0xB077C75B8A58FEE5ULL,
			0x5F53B42964D4DFDBULL
		}
	};
	printf("Test Case 488\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xB47372F5E50BA800ULL,
			0xD346C45577211EE6ULL,
			0x9C0585DB92DE00E2ULL,
			0x7E0EF5B823434824ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBCE73C4133A6CD08ULL,
			0xA86BBB430CBDB909ULL,
			0xCE54D62021A827ACULL,
			0x51BC81E942163443ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3FD6F906E8958FE6ULL,
			0xD934474A935DF104ULL,
			0x768C8097714757F1ULL,
			0x7F4EB0CF83F44936ULL
		}
	};
	printf("Test Case 489\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xEECDEEF558B97A40ULL,
			0x1B18BD057E72DE3FULL,
			0x10197394A527C912ULL,
			0x7E47830CD62F8EC1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x827ABA4F366CC820ULL,
			0xD4B2E958057FDD69ULL,
			0x5D36ADDD746F995DULL,
			0x58702D6149FBB513ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x94DF4EFC5D33B6B6ULL,
			0x9F96812A5F5D2DC2ULL,
			0x2437E2439C81CBBFULL,
			0x7501D89C6D5DD1F6ULL
		}
	};
	printf("Test Case 490\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x1A1C7D26C5DC6EE8ULL,
			0x3841833DDAD4409AULL,
			0x51CC6CD9CCDE5ADEULL,
			0x6DC15DCF98630A4FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7EE00C4E9D43B560ULL,
			0x0090C1DB30FC5F51ULL,
			0x59129B85A242AF6BULL,
			0x57BFC4AD89ECA773ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB51DF0BD13123B85ULL,
			0x7A3F87766BA937ECULL,
			0xAFD69816A8472DAAULL,
			0x3D54B7309038AC51ULL
		}
	};
	printf("Test Case 491\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x5CC2B81DABE43D00ULL,
			0x5F0EA6511056EDA2ULL,
			0x73D3DDBD1460AB44ULL,
			0x6AF8F28BDC8B1A4BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE666A14BA5C02160ULL,
			0xDF2E18A7C3299515ULL,
			0xD5A8C086C5BAE3E5ULL,
			0x6A993255FE4D1E6BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA0B49AC9439A516ULL,
			0x628244DF6A72A34BULL,
			0x07F7BF3DF7409665ULL,
			0x4C5BBDE652153783ULL
		}
	};
	printf("Test Case 492\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x6A5BBD84220BB430ULL,
			0x1B7C0FDE45BB7861ULL,
			0xB18AB82C2595622DULL,
			0x7A5ACC51D9AD58BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x90F49391CC79BAF8ULL,
			0x9A05E90F3148E515ULL,
			0xEA7FD416A49742D2ULL,
			0x6D9374727662DF4BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5EB8895B0FF483EEULL,
			0x6B84057536972C41ULL,
			0xFBEF6A3D6C0BCD55ULL,
			0x379088FC6951921FULL
		}
	};
	printf("Test Case 493\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xA00926A40DE251F0ULL,
			0x7F83DB0D9389CFDEULL,
			0x9DF050D4645A17C5ULL,
			0x6AB0A98F3A6A9E5AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3A0DBA1336323020ULL,
			0xF00DA24ECF1981EDULL,
			0x686F99607B245BCCULL,
			0x7B3F9008A96812C3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x78C2C06BEFD5B9B5ULL,
			0xADE0FE1AB7E656FFULL,
			0x2FCD714D07FC10EEULL,
			0x21CDDDB3FF036D5BULL
		}
	};
	printf("Test Case 494\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x12B83ECBB5BAFA30ULL,
			0x4785362C3CE192DDULL,
			0xAEBCE2BEABA4388EULL,
			0x4D5584FF3294CD2CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF9248887EC73518ULL,
			0xA43DABD21FC3A2C2ULL,
			0x2F8783C76F963EE3ULL,
			0x6236C960DBB4D055ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37A4E3AC20AD73DDULL,
			0xFC34A293B0CE4AB9ULL,
			0xA1A7D41D02C74F66ULL,
			0x44DD48C14C0AEF18ULL
		}
	};
	printf("Test Case 495\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x8C651C76982FB590ULL,
			0x4155862233B6126AULL,
			0x727B81214A640955ULL,
			0x63680CAF80D1745BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3ECCDE15EC5D3100ULL,
			0xFEE19F20DA7CFD7EULL,
			0x7F26A10135F39B99ULL,
			0x5112B733D3B88299ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x146528CB08BCE2B0ULL,
			0x2B0A47D07D749CDAULL,
			0x5135E3228D58B082ULL,
			0x41B126FD6754F6D0ULL
		}
	};
	printf("Test Case 496\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xF9742F307EADFB18ULL,
			0x377BF67CA1FF1534ULL,
			0x737B8ED604512721ULL,
			0x69CBD95783387730ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C151D9C02AC8790ULL,
			0xAF370EB22F84F7D8ULL,
			0x60F3EDA741B56355ULL,
			0x6DACC190944ABDF5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF3C2387EBB9F0FABULL,
			0x8235D6E70BED48BAULL,
			0x88DC868BC1EE1F4AULL,
			0x34D4BC99D928275CULL
		}
	};
	printf("Test Case 497\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0xE9B2023DC845D750ULL,
			0xFD0537C337BB74E9ULL,
			0x9E6310B676EE0313ULL,
			0x4608331A53B52499ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE76FE7A45DD31048ULL,
			0x540059D0A3E9399DULL,
			0x15943FD89A14410EULL,
			0x6E12E2FBA8165C8DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD4A09E1BC4AD4CDULL,
			0x6BDBF720D06B2D4CULL,
			0xF088BB79DD7F2193ULL,
			0x7C5C33771E5C4184ULL
		}
	};
	printf("Test Case 498\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x9D3E735F3F6907E8ULL,
			0xFD1C70FC72801963ULL,
			0x6F06C06D4D97C4FAULL,
			0x72234D517AEFDACEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE87AFEB8B04BF688ULL,
			0xE6B847744466858BULL,
			0x1BD267A510CEA734ULL,
			0x6D7772767F96A1AAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x511D19B9A895AF0DULL,
			0xFEAA6E653DB46E1DULL,
			0x939DE7F1B5C56E28ULL,
			0x5FB4D110C91F3B76ULL
		}
	};
	printf("Test Case 499\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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
			0x7EB167C2E75258D8ULL,
			0x697C38F44F8DAE83ULL,
			0x8CC043FC35175714ULL,
			0x423D9B033E9EBA00ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC19B832F585F338ULL,
			0x7B2E9F8A848B846EULL,
			0x643AB1A391654E44ULL,
			0x4DDC750760B7A952ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5771D6C322E0D9CULL,
			0x84A62E21458FE91AULL,
			0xA3BC0B62AD84B075ULL,
			0x340D2E50BBD2E305ULL
		}
	};
	printf("Test Case 500\n");
	printf("n:\n");
	curve25519_key_printf(&n, COMPLETE);
	printf("base:\n");
	curve25519_key_printf(&base, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&nbase, COMPLETE);
	curve25519_pub_key_init(&n, &base, &r);
	res = curve25519_key_cmp(&nbase, &r);
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