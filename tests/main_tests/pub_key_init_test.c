#include "../tests.h"

int32_t curve25519_pub_key_init_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t n = {
		.key64 = {
			0x2AEA863313458CD0ULL,
			0x22F3407A8FC3F8FDULL,
			0xF9B9FC9693A88971ULL,
			0x7C0F33F675AC01BDULL
		}
	};
	curve25519_key_t base = {
		.key64 = {
			0xFCC8CC1C3CD44430ULL,
			0x8D04A1B876D4EA64ULL,
			0x7C17DB24905C42F0ULL,
			0x5F3F37D81BC65388ULL
		}
	};
	curve25519_key_t nbase = {
		.key64 = {
			0xF315B28A5E64E7CFULL,
			0xE9E5895997DF00BAULL,
			0x3E335FB609E38FE5ULL,
			0x6776EB02A4470F40ULL
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
			0x5DCE6E799944CA48ULL,
			0x113AA6E31AEF51E8ULL,
			0xBCA1AD07B3D810F3ULL,
			0x4EE2DB0B909FF63EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCE2FC51F6ABB7360ULL,
			0xAC8D695B749120CEULL,
			0x4C94DC1E677CFEDBULL,
			0x63A4587184CC8036ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC023CB3F9D5ACDDFULL,
			0xB68C320D91F1A526ULL,
			0x49BE6ABB62097322ULL,
			0x212FC93B41E4915CULL
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
			0x6DC20C6654D412E8ULL,
			0x7F276F30914A1517ULL,
			0xCE3E21610A1D5BD3ULL,
			0x4F5DA80A97B58F0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBF5279953A5D1880ULL,
			0x9A260C62E8A9D95AULL,
			0xEE07FA807CAC5A18ULL,
			0x48E8923D34790658ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB0EE7B03133F32D9ULL,
			0x3DA18339C40E38EFULL,
			0xF5D028D531576EA0ULL,
			0x7E11C2E1D50E0C88ULL
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
			0xC130203312DBE3C0ULL,
			0xF61852BCC6CC3640ULL,
			0x074223A95C0DDAE0ULL,
			0x465C28EB92641439ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x30B1E739862394C0ULL,
			0x38F722684F780FD6ULL,
			0xF4F470009C9AFDC1ULL,
			0x697481CAB42D2B7BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE01E209CEAE942AAULL,
			0xDA97A27B85DE037BULL,
			0x05EED35034D87CACULL,
			0x77CCFABB5CDBBDF4ULL
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
			0x169028CD8ED68E28ULL,
			0xDD78F31D6B00B463ULL,
			0x86CB7B5771A94B96ULL,
			0x5BC1FD058B509CCFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB670187A1CCCFAB8ULL,
			0x62A2C9D900091D09ULL,
			0x65E5826F0BF08B0CULL,
			0x799F4C90EB0254D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8B8EF54EEB70D7C3ULL,
			0x774436596BAD9BF7ULL,
			0x4F57EAE3485CBCEBULL,
			0x26921917C4F1D5DBULL
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
			0x450CBCB6AACBCD90ULL,
			0x29382A60B766CC70ULL,
			0x0CCF6D1A3C7A17FBULL,
			0x6696B1C496AB66F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x42373DE21400ED28ULL,
			0x3C9D5144664C8A79ULL,
			0xF95C296F567FD0FBULL,
			0x740B882B64D480B2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF0A9144F81679441ULL,
			0xF0711353DF99970BULL,
			0xC739ACBA9E2EF110ULL,
			0x09D65F1AE949199EULL
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
			0x620BB1C299BDF3A8ULL,
			0x1849527F17D8578FULL,
			0x400EB3476A24C209ULL,
			0x624E6509B2E7947AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x17010FDAF75CF150ULL,
			0x1F1242F6C0474AF8ULL,
			0xDC8370DD45F2B4E5ULL,
			0x668F0BA994024528ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x72D8BF403A098619ULL,
			0x6BDD0D6BC1C6FDA6ULL,
			0x93CA4935A8B9A8EAULL,
			0x7F68E07D673D34FDULL
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
			0x8EEA874169B47018ULL,
			0x1F06FFFCF75BA9F1ULL,
			0x5F76A7899BAAF160ULL,
			0x5AB44AF3CC40AC5CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x30089EA616814B30ULL,
			0x6114E1A49DC0607CULL,
			0x4A69A644E159B654ULL,
			0x6076AAEB481BBFFAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA8D43165288D3123ULL,
			0x227CD32716D1630DULL,
			0x44B09A959BF9FC49ULL,
			0x7F6EC1737BAE4AB8ULL
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
			0x063CF528F9D39C78ULL,
			0xF9724691C31B7A93ULL,
			0xE7083F1886712540ULL,
			0x50EAAFD911910F8BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3482290C75A91530ULL,
			0xE5B53BC63E3B30C6ULL,
			0xBBE30695C5F68C70ULL,
			0x52218C27BA5EF368ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x729A2E5BF2216EDFULL,
			0x54866CB1BC263F39ULL,
			0x2FC6FDCF59B9B722ULL,
			0x1EF06272C2BACE3EULL
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
			0xEE57B465BA71DE70ULL,
			0x4ADCA9F697B8FECAULL,
			0x7F09B8FB4D09E722ULL,
			0x4E2906DFC7167EC0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE3F988B26664100ULL,
			0xD5CC6A87A12C5C34ULL,
			0xFF0B23ED3294C855ULL,
			0x59D51DC83A658A6DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x69FEB07F0C65D0D2ULL,
			0x8280FF34B85F2125ULL,
			0x32B97CEF8E1E393CULL,
			0x5FE1BA57C56CBB42ULL
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
			0xAD366F8AF59DFBE8ULL,
			0x08AEFD31B55CB1A8ULL,
			0xFD2C003DF1CCCD97ULL,
			0x413496F24CDFE17DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3560F30B19331188ULL,
			0x628E60A91AF0D626ULL,
			0x078DDE316C1E15B2ULL,
			0x6D2048CB5409D820ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6E699681CBB9CB4FULL,
			0x260E5A574F645FABULL,
			0x5810299BF97FE511ULL,
			0x63BE70DFA4292625ULL
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
			0xD3590FA03E4B2748ULL,
			0x18ABCD1E791AD235ULL,
			0xE164CE5A88F41805ULL,
			0x5A6CED66BF76ECD1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1C84841546ABB5E0ULL,
			0x647593507AF3595FULL,
			0xA049A6BCDA3D0403ULL,
			0x4976AA3603A75EC6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBCFD5F36DAC5B2B1ULL,
			0x4D69EF7B86B42E99ULL,
			0xDC23D11F5B53082DULL,
			0x0327CC47038F2EC9ULL
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
			0x9243B45AC6C06D58ULL,
			0x168FF1BD87D6B1ECULL,
			0x09E5E3E022974D58ULL,
			0x4069453DA62E8B45ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54EC7F9662CAA3A0ULL,
			0x6DAEB5540AFC37F3ULL,
			0x87A95D7DF3DA110DULL,
			0x726FE84847C9BE4BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA31A4872967612F8ULL,
			0x8617EBA7D22B6749ULL,
			0x5E52DE587A5CF1CEULL,
			0x1D075D291605DAF7ULL
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
			0x52CD461B5B1049D8ULL,
			0x0CC99DDA2C00E48AULL,
			0x48BDB5F588091C8FULL,
			0x7A3B4C5C5A7EDDFBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCB6BE53A2B75E9C0ULL,
			0x53C508CE66D8DC13ULL,
			0xEEEF52F8E209A73DULL,
			0x563494EDF0433657ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6BA2D9916B35D91AULL,
			0x88CC4ED204C83C67ULL,
			0x92ED5A86C77D9B9CULL,
			0x23AD16DA678F6F28ULL
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
			0x2FDCA6926C7C3BB0ULL,
			0xD2047FEA08892206ULL,
			0xBC35DA3A5D8902A5ULL,
			0x6425EDD096ED5856ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9908C18083F2A3F8ULL,
			0xB3DB24FEDE3F3DDFULL,
			0xBF50CEE8B001AE1FULL,
			0x594021771D1009D3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7AF5AC2F8DF4359DULL,
			0xA143F8B2D4A71D34ULL,
			0xA0386130D1A94A2CULL,
			0x15E826E3E0C042DCULL
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
			0x16957EF87F041FC8ULL,
			0xE117174D4BFF7FDAULL,
			0xE78DC2EF5C9EE428ULL,
			0x63C553AC38CFD2AAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x64C6AB75F52CD828ULL,
			0xC2CB0E6113D8E6C9ULL,
			0xEC43BA6A68D46E5BULL,
			0x463F9CF3DB5FE3FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x19A9EE9479A28747ULL,
			0x6C24EC51095F0257ULL,
			0x7F79E041AE691D00ULL,
			0x507F391EFCC5DCF4ULL
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
			0x9F7762AC42274C38ULL,
			0x77B0C4398D41B2B0ULL,
			0x7472B1492E6FB1CAULL,
			0x763043FF95C24A8AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x27D687228B90A3D8ULL,
			0xCCA846B8791E6113ULL,
			0x8646C7B86B7FE44EULL,
			0x4BF336B519827D0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E79F6A5EDACBF43ULL,
			0x4C8E38A950351CEAULL,
			0xA31BA35E014271C7ULL,
			0x13963EDFFE27CBA4ULL
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
			0x36A5A7D4D5755890ULL,
			0x68B3D45019450182ULL,
			0xC0CACD442FEAE462ULL,
			0x4B533FF94F6DFE25ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8847E92DCFC23228ULL,
			0x4D698F44D531D6DAULL,
			0xBCDEC8F79897579BULL,
			0x68EA9DFD4F6DAEFAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x34020C083518AF9BULL,
			0xEC0B7074D6FB42E3ULL,
			0xBC68226FDC406ABFULL,
			0x5F7033A9C104257BULL
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
			0xD5086AF465843228ULL,
			0xBF6FE40AB205C04CULL,
			0xE2C8033D58536AC7ULL,
			0x54B20B6A3C202D53ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE0AFCF24C07A6A00ULL,
			0xF1E0D65D06831C4DULL,
			0x5B1591A14FB9755EULL,
			0x5738A57000D6A8C1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x729739297944BAD0ULL,
			0x000C14964E35F18DULL,
			0x3FA2FCC924B449BDULL,
			0x2B7E8614D7A4F929ULL
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
			0x4596A590631A02C8ULL,
			0x0718FA2093405917ULL,
			0x18226E9EF30744DBULL,
			0x6AD7A2978B1DC449ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDF78D7165BAA1448ULL,
			0x75B4CF89EBE50913ULL,
			0xBA9F608990D928F5ULL,
			0x48F9BF7DF4278DE4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2588C734D9C191B8ULL,
			0x7B60D45D5F4BF528ULL,
			0x2DD7029C48CECE17ULL,
			0x5CC5D8A1A8D16890ULL
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
			0x44A2E31999C1B348ULL,
			0x8F442CBDFE4FA2F6ULL,
			0x37A4F7D307788E04ULL,
			0x6FC381C9F4646B53ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x94DB6674378CDC60ULL,
			0xA3B1770085141B33ULL,
			0xEDF9CF56022E1E52ULL,
			0x4543B6F8D535A78BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD830519588F21D9FULL,
			0xA6353C8083CE3ED1ULL,
			0xDEFF7BFEE6405360ULL,
			0x212BFD1A26D8090AULL
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
			0x00C1E5A5689F0540ULL,
			0x40153400E35939B8ULL,
			0x0442330028752B05ULL,
			0x45B72246F95A04C0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD56B70288765D758ULL,
			0x2CE2CC56DBFEFD60ULL,
			0xC75A31A60FB50972ULL,
			0x67EAF26030909624ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x75A35199589D3A33ULL,
			0x982870538E5A6E36ULL,
			0xB69142FC75FD8CEDULL,
			0x525BCB0CCF4D2A6FULL
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
			0x68902D36B5AF51B8ULL,
			0x5A4EBA50D251D014ULL,
			0x55658AA89A6059A3ULL,
			0x6FFB60172C59F157ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB96A2068385DBBB0ULL,
			0xF6580DA457B4BDC5ULL,
			0x31C99B015606E62EULL,
			0x497D2A19DC431622ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA7E3DCAEE3C37FEFULL,
			0x5C6C2B7258248B64ULL,
			0x317E6E0B4DB22A99ULL,
			0x142E238089EE882CULL
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
			0x733899F289EDB710ULL,
			0xF7095766A4EC8049ULL,
			0x113BD788DE7AD1DEULL,
			0x4FD56AC81748C872ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCF745D741E728308ULL,
			0x85B5A9C131B85FA9ULL,
			0x78661AF08B490EC1ULL,
			0x746ADFF2E813F4E1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA57EDA4773299E20ULL,
			0xCE76913B637A09C5ULL,
			0xAD81AFE2D7233DF2ULL,
			0x394F043221A1EE0BULL
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
			0x7E8E53110A954DC0ULL,
			0x14D6598DAD65D997ULL,
			0x778EF43C3AECC69DULL,
			0x593E87CB9759FE83ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAB3329777F8B81E0ULL,
			0x799FD8947A31D210ULL,
			0xB6DA1BF5ABF03454ULL,
			0x6BA3BADA0CBA3A4EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2ABFD60D4027DAC2ULL,
			0x9A266854DA4BB850ULL,
			0x6E7BBED27DA37CE3ULL,
			0x1666D4141EDE9CC9ULL
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
			0xE96B3FCAEA340F90ULL,
			0xCF0BB9D88671A0F1ULL,
			0xC5E5186E7C0DA052ULL,
			0x6B13FC0D9AD34E00ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8DB1A40395994A28ULL,
			0xB3502891AFEF4BA4ULL,
			0x22AA29E7EB8471FAULL,
			0x57A57CDA7E2C7CCBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE796811299D13B90ULL,
			0x6B03FA54DEDA3087ULL,
			0x59AA4D8EEB10C2C7ULL,
			0x439656E788459457ULL
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
			0x8271D33C131EA7B8ULL,
			0x44A9123516227F15ULL,
			0x4FA84BFF7B3565F7ULL,
			0x5501593A75B81A04ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D73746280B9F5F0ULL,
			0x7590D96618D5DA28ULL,
			0xCF4350B1011F2CD1ULL,
			0x59E4CB230D821660ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F717604BF80FF5FULL,
			0x668282066AAD9AA1ULL,
			0x4BE658CBD764F3A8ULL,
			0x45B480811B02CC12ULL
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
			0xE9CC0370657AF720ULL,
			0x5B105B3519F99E6CULL,
			0x33367D6E42BADC86ULL,
			0x7C6DD54420E6394FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x150BFBF2F4BA3F10ULL,
			0x2C93F6C24D2C1572ULL,
			0x02B5B64164737F50ULL,
			0x527B4EBC74A455DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9EB97F33505A0658ULL,
			0x6F961C1466D5661FULL,
			0xBA2B85909FF8DBC9ULL,
			0x211A84FD4BB9054EULL
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
			0xC344EFBE3EDE7470ULL,
			0x6327E9C0048FF055ULL,
			0x4EECD808C7DDECE7ULL,
			0x6E2FC5679B94FC47ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x361CAA16128E9028ULL,
			0x93C6BB7080086292ULL,
			0x5AC8D1C5679EFEACULL,
			0x61B65CD1C5DFCB1FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAECAAE01663C42A3ULL,
			0xE6A306C790E5ED9BULL,
			0x348648FCD890F4D4ULL,
			0x69FF155251A14983ULL
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
			0x516BD2162D26BC18ULL,
			0x99E249F90EE9D9F3ULL,
			0x1EF2BA27B18164E6ULL,
			0x72B30DA680D95587ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x97E89B79C53365C0ULL,
			0xFDB55B6792585F87ULL,
			0x711370832D70F1EEULL,
			0x47EFD9E304A32D2EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4DA288D638A4FC21ULL,
			0x39E513FCB755A082ULL,
			0x90EDC3619AC26D2EULL,
			0x4D3C5C593A5F15F1ULL
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
			0x6727CBC8A7A78DC0ULL,
			0xECFA8679956D22A7ULL,
			0xC3A7F6820387C7BEULL,
			0x7B4DCEC0FA10E7A2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B3AB27649864DA8ULL,
			0x7542B6AB6A8E3C99ULL,
			0x2FC67A6106FA6A89ULL,
			0x4386754FDF9F4ECDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x65A5DE6DEE64B9CFULL,
			0x8F3A8AB045A915AFULL,
			0xCAAC49B59AC4CF28ULL,
			0x44F92984E983361AULL
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
			0x2D1BC75688C84AB8ULL,
			0xC7B6F9602BD7B94CULL,
			0xAC05C0C1DF3470FCULL,
			0x43760D0AF9EA7180ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3550CAEF69E7BFC8ULL,
			0x75490563AB81DC44ULL,
			0x72008FE4D1AC69F1ULL,
			0x59A5400BF6E471B1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x160258C8BA75751AULL,
			0x15BCB92116E6E9DCULL,
			0x0E06218F1CF5FDC2ULL,
			0x44434E8D0541A3FFULL
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
			0x331FD6F3DFD6FC10ULL,
			0x0A33ED674C5750C7ULL,
			0xA6509C924F900D82ULL,
			0x75603769058AE237ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x22F7E4BB1BC59D80ULL,
			0x6083CE67C31D3C15ULL,
			0xCDD4E41503776B79ULL,
			0x5E527FCC8FA24FB8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x50AE136EAF05F63CULL,
			0x76DCB83D0F273D18ULL,
			0x52924857FCEB71CEULL,
			0x2EDDE55585507F9CULL
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
			0xFDE8C8EC763633C8ULL,
			0xF5FB0A4724F52B3DULL,
			0x6DBCB451DF3FE158ULL,
			0x48AAC67BC33E49BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9114016054615E60ULL,
			0x11E61E6378784801ULL,
			0xB81099640251B112ULL,
			0x65A3FF718004F120ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC386601C15DA95B6ULL,
			0xBFCBCC2CB7CA9D36ULL,
			0x8B03EB8DABFAA510ULL,
			0x087DE4D732F68EFCULL
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
			0x54E129F02AF62FB8ULL,
			0x77B6ABDF97B518B1ULL,
			0x5E71D6C7B6BE6D4BULL,
			0x7768D9A3A4582B52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5BBD899E720C3318ULL,
			0x93274AF83C8B83F8ULL,
			0xE8549FCD31273E0BULL,
			0x7025FF86125E36DDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x763E88B468806A5CULL,
			0xBD1AD9AEAD3ECD49ULL,
			0x51ACEBA6DF5CE606ULL,
			0x44AEA18AA576AB15ULL
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
			0xBC5E96CEF2981BC0ULL,
			0xE759B41E8FE5092FULL,
			0xBBC433D8318E4DA1ULL,
			0x40574967E3732227ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x70E66156D80802D0ULL,
			0xD177C55ABBA4901CULL,
			0x5FAECDF25C338067ULL,
			0x69B7DF1FB89B99C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43D5E4254B534758ULL,
			0x85364F1C2F5CFFF7ULL,
			0xE85E62FCD2D77F04ULL,
			0x71A972F9F36791FBULL
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
			0x47AFD756198997A8ULL,
			0x90D7B63ECA00959AULL,
			0xFC361A2A52728924ULL,
			0x6A49A50110185A93ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x987294C21B61D590ULL,
			0xB93282EA6ADF2B01ULL,
			0xF4A6A4574C896699ULL,
			0x4AB4893344DEE6FCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x363D86AB54E80EACULL,
			0x8028E92523ACCD70ULL,
			0xC91EE1ACEA25E067ULL,
			0x698DB13C7B454812ULL
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
			0xAA109BF020926F90ULL,
			0x9935693161FC23BBULL,
			0x5BC60E9942358A8FULL,
			0x7BADB98BD360EC0AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA7FB42D5E2ED4808ULL,
			0x2A158B0FC201515CULL,
			0x3DB4497B5910EBAFULL,
			0x5C95EF520E5E6B45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAEAF7B75BC1B8130ULL,
			0xBECB068AC0E79B41ULL,
			0xC209DDF82F29E441ULL,
			0x7E758E5E92B4413AULL
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
			0x2860A49710B1AF88ULL,
			0xCDFD19868E329B60ULL,
			0x99A973AFCFA0F7CDULL,
			0x75DE780CB8C86448ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA0D93B45939AFB0ULL,
			0x30EEAB7C54FBA022ULL,
			0x410B3071D5C3F0F8ULL,
			0x5CCF8D19632652CEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x17FBE0A646570CCAULL,
			0xD1EA2EB85ACAE4DFULL,
			0x1ACB482DC6643AFCULL,
			0x71F3C5B67A8A9E90ULL
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
			0x6D8E7DD00A6D2B58ULL,
			0x495AD3F49146811DULL,
			0xAC92FED6174FF120ULL,
			0x77B0992E89AE483EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1A86D23B5FBD9828ULL,
			0x3B3B15BF0D12560BULL,
			0x0CAE5A4AE19AB3FDULL,
			0x6A317A043C44D9B6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x26BE51339AD47F80ULL,
			0xA0609E3A56683CB0ULL,
			0x5008C3BFF1546B67ULL,
			0x1DA3F5F5AA6B0269ULL
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
			0xB82217EF899FCB78ULL,
			0x775FFE8C74D0929FULL,
			0xDC32567132E852AEULL,
			0x402E68D9D9D53144ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB96C82DC379E86B0ULL,
			0x341E9C2331592EF1ULL,
			0xE8A44BFACCF3B8CCULL,
			0x6CBBDDA471E5E383ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3D94B1BDCC8BB426ULL,
			0x0F85468FEEE5E218ULL,
			0x781BEFB4A4D3ABC8ULL,
			0x5DF7872ABDF2D09BULL
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
			0x90BE2E5101D04218ULL,
			0x41E9A2BA5F97CE6AULL,
			0x563DB353B05AC2C1ULL,
			0x417416CC9C3023BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2929CD1FD2123938ULL,
			0x4D07FBB54F034377ULL,
			0xB0B20610B7119A7DULL,
			0x51EA9528C2579267ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE80B6BD5473AC84ULL,
			0xB9D1EE4A68A36426ULL,
			0xA7B89C0404DF670DULL,
			0x6F2A51D33E5D3DACULL
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
			0x99D69E3C4C55D608ULL,
			0x0873673B8A972E51ULL,
			0xEAEED09446B9EE5AULL,
			0x7429363B6140A861ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x13DE662FC34412E8ULL,
			0xBDDEAE4F91968041ULL,
			0x299495052D20073FULL,
			0x40E3ACB3C0307159ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3D44A99DD61EE948ULL,
			0x55B65D9552AFE588ULL,
			0x17556A069CCD835CULL,
			0x3EF7847A70367ACEULL
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
			0x2E238070974EDBB8ULL,
			0x95EE1B30FB48EF06ULL,
			0x8B893E7CA2FD7E05ULL,
			0x793AC446BA43F8EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAB0FB718DC4BDF28ULL,
			0xF527B54B1952467EULL,
			0xE6BA8F2B7B24EB6BULL,
			0x48F60B4258C253E6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x66F27F643035160EULL,
			0x92FDB7D2BF7D4087ULL,
			0x8D479475650238E9ULL,
			0x207F58728CA09BADULL
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
			0xAB614BFC0FC7FD50ULL,
			0x755B15FA22599B32ULL,
			0x8664587431993029ULL,
			0x741050B1EBD86791ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9964CB64AE820288ULL,
			0xE6161F7A1D2CEC5EULL,
			0xE9FA601AA2432D4BULL,
			0x61E5387D0AA1958DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x041CDEF763AF565FULL,
			0x4A365A4CC568CBC2ULL,
			0x572C7C8187BA4D0EULL,
			0x77C5E0CE8576FDE7ULL
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
			0x7C33E09D4B758850ULL,
			0x8A67474A39CC3BBFULL,
			0x1B7036CF0174F0EFULL,
			0x4D9B5585A14029A5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0B1256B90E526700ULL,
			0x7389D0BC5B6E3121ULL,
			0xE77BCE935137D172ULL,
			0x74AD2853408BDCBFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE22088D004C29652ULL,
			0x0F6DEEAA48CA1496ULL,
			0xCA04DA38904D004BULL,
			0x28CB62F417733F4CULL
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
			0x7B1B8E65AAA87C70ULL,
			0x3CE63F329BC07716ULL,
			0xE87088C9C907EED7ULL,
			0x7BCD637B39D09AF6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD7BBA5AEEB993C48ULL,
			0xE9A2555A403A23BFULL,
			0x3B77DB55B5CE7024ULL,
			0x40CD1E8BCA6A13C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xED618DF42576F4FAULL,
			0xF714308ADF089F04ULL,
			0x42C09F0E02FF911AULL,
			0x7C4CB774EA2BC945ULL
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
			0xC223A3C73F52F2C8ULL,
			0x1A44B6F5EAC3A345ULL,
			0x5908BCB2D1D7BAE0ULL,
			0x7B739F6EE8B7D2A7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x92CE66E0C36EEE80ULL,
			0x0BB18A90BCE964C9ULL,
			0x09CC71158A96FFFDULL,
			0x7B5379901B9E3616ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7573403101B70C35ULL,
			0x0A2ECEB028CA643AULL,
			0xE70AC6997778D09CULL,
			0x6DEEEAB18736763AULL
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
			0x7B945C28F3D97020ULL,
			0x1CFEB31E9DDB4B18ULL,
			0xC520C6983B02958AULL,
			0x78EB4C05286C97E1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3EFA3BD0591556A0ULL,
			0x1FCF13A65CBDAED3ULL,
			0x1268D7F233DAF3FEULL,
			0x588488D3BA8B359EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8245058D52442C7FULL,
			0x9FFE7794B5C45FCBULL,
			0xF754150404C5BFB3ULL,
			0x30A39EB318636129ULL
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
			0xD3971446ACBB26C0ULL,
			0xA2B0D02C10527F4FULL,
			0x04547732513686F8ULL,
			0x4A6FDF1F4EB120ECULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x98B60EB0B930CCA8ULL,
			0x82B3753F0C40BCB3ULL,
			0x2154D560C26FCC06ULL,
			0x631407148FEFEA57ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAAB069D5F54427C8ULL,
			0x5E9D558F468AEBB9ULL,
			0x7DE79B18CB087AB2ULL,
			0x705ABED91F878FF6ULL
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
			0x71D0859E70FEE8C0ULL,
			0x20BE4FCCBCD816BFULL,
			0xEDE47D4413416644ULL,
			0x4E1119A9A6B92307ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x70A51B10D049DDC0ULL,
			0x6A8FAC7586245933ULL,
			0x22BE73872B3DFC46ULL,
			0x5AA33E45E67BDAECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1269B5E6E792C579ULL,
			0xE5C61EFD86F049D9ULL,
			0x9AC3D86ACE28ACF4ULL,
			0x08FF3BAEA4AFEFC8ULL
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
			0x56A9678EDF9AE1E8ULL,
			0xCE971FDA9424729AULL,
			0x1CAD2DA21FA2F675ULL,
			0x6CE83F4BD55AD105ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x14D121EA735F5618ULL,
			0x18F785844695C06FULL,
			0x06C09DAF58CD8E86ULL,
			0x662BF439A87FE226ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE571F25108723844ULL,
			0x48D42D2B2F79812BULL,
			0xF3FBFC1C3561A82DULL,
			0x2AEF64CFF4BD459EULL
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
			0x4F605E5C68013B48ULL,
			0x69FF519F9AE23BDFULL,
			0x8AD3D625DA29C24CULL,
			0x436447FF20108D07ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA3DBDBEE5E909448ULL,
			0x2E551D83DC8EFA98ULL,
			0x376CAD0CE8F0C033ULL,
			0x5B4707ABCAA9C5C5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5153761FB397973ULL,
			0x32B4048F20C04593ULL,
			0xF556725194F7298CULL,
			0x42E85E47659F4C1BULL
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
			0x58221F75C717E638ULL,
			0x1EE0818A230A3EA2ULL,
			0xAA8756BB4904CA0EULL,
			0x46F1C6B760D2A449ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x27F7E38EEA1BB3C8ULL,
			0xE5E8E0311958A08BULL,
			0x61F16E9EBF7DE0A6ULL,
			0x56333DAB6AED1BC3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD7A23B351BE46907ULL,
			0x02930EF54A31182AULL,
			0xD38CB27A3F7065E8ULL,
			0x441DFC8E181F545EULL
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
			0x90EDA4F982CF3078ULL,
			0xE73710E39C825622ULL,
			0xAB6F0F3A511763E7ULL,
			0x7FB589291886C2C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD15ACEE4A1B5E20ULL,
			0xBB53F15945D099DDULL,
			0x682B3FB2C6520EDFULL,
			0x4BB54D165EFD93D3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9E6B92F918EAA542ULL,
			0x1DCF8A24EE31A5E8ULL,
			0x730EC09D779ECD5DULL,
			0x6E3D9B5335BB2B10ULL
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
			0x3DCE2F1589683550ULL,
			0x8BA5D8E08ADEA841ULL,
			0x1F840286AFB780F8ULL,
			0x58735EF0B7EAEC24ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC1E47E936B7D8AA0ULL,
			0x46B3B83965FF9DDCULL,
			0xC8C03D8C02BB60AEULL,
			0x574715657B108598ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3F83F85DCED44AC2ULL,
			0x8926B320471DA805ULL,
			0x732BBABA732661BFULL,
			0x35A59BB33750A2ADULL
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
			0x5C6417A3E592C028ULL,
			0x36AE684797DC0717ULL,
			0xB8784913AA2C4BE8ULL,
			0x5211DA086C15676BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x369D799BC3DEDD20ULL,
			0x391B70FFDA866ED7ULL,
			0xC1800869D86050DDULL,
			0x51EB09DE747B0930ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE254A87072D99C84ULL,
			0xA021AB9022CA16BCULL,
			0x5B136A40B5825AD0ULL,
			0x5A3E04956118E51DULL
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
			0x406A035908231DD0ULL,
			0x60B36F29B6842061ULL,
			0xD4B5A7D4D7BAC5E3ULL,
			0x4F55F0638F65E9BCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6176C9B7983C9BF0ULL,
			0xF25E40690946FC6CULL,
			0x1E728182B85BFD29ULL,
			0x4CA8153D92902F4AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x98560DC8680E868DULL,
			0xFB23979BE50AFDD4ULL,
			0xEF36F89BF16CA455ULL,
			0x555FF07FB3C3CB7AULL
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
			0xB662779739823418ULL,
			0x462737F354A5B340ULL,
			0x37BE8A1105F7498AULL,
			0x65AC2112DFFDB2CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C59118348E0AC78ULL,
			0x586F6DF23B903361ULL,
			0x8FFCF84A8D314402ULL,
			0x7402E2E4716C2D77ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB7F2BD37EA2740F4ULL,
			0x95023A866E389266ULL,
			0x68530E7D73544B3EULL,
			0x6C838838665F059FULL
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
			0x068C1B06061AD0C0ULL,
			0x440D39E8A213561CULL,
			0x2EE9E712541B3DDEULL,
			0x54D43D3E0CCF41B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x34D6FBD469894530ULL,
			0xD71D88549F09D3A6ULL,
			0x9CD5BB2170132C70ULL,
			0x55C6B3581F793A36ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x605E663E6EFE47E5ULL,
			0x66ABE123AA87A443ULL,
			0x40B903A9B5A1646DULL,
			0x13FB9DDE9C66B342ULL
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
			0xF4C39760587A6A60ULL,
			0x36BA42F0953AEA92ULL,
			0x4D93D84FDA35986DULL,
			0x5C04562EE2EFC309ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5C28694B68F47098ULL,
			0x66DD76A9660DD906ULL,
			0xD8AB5C3A259D0910ULL,
			0x5414CB7C01FC9CABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0D3E54D37315FC7ULL,
			0x8BC9E0B54AAEB7ADULL,
			0x11CC54828E66135FULL,
			0x36DD779A1108B1C2ULL
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
			0x0E9E0124A1E5B850ULL,
			0x21B62C4849D9F180ULL,
			0x1430F77C4ED597C3ULL,
			0x675F4493CD371C93ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x525DD0A45388A508ULL,
			0x69922F6A221536EEULL,
			0x76499ED9AF3A6D1BULL,
			0x65998A8F5A4FD41BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCAEDD53351ED1DBFULL,
			0x1DEA2C99C3B41022ULL,
			0x2B50CEC438DA35EBULL,
			0x5482DEE172F0025EULL
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
			0x0B8811DF5B1D07F0ULL,
			0x9ABFD87F17FF29CFULL,
			0xCBB5D4B8D87858EFULL,
			0x78A232F3F5203F50ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43092FD449ED8EE8ULL,
			0x049C9311E54DADFBULL,
			0xB61628DF92EE2DE7ULL,
			0x53F05FC6F635ED7BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB34AF2DDB85BBD77ULL,
			0x69AD07627BAC4945ULL,
			0xE2F54E64B138564EULL,
			0x47BA148943C03BFBULL
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
			0x14C4F3834B3E69A8ULL,
			0x2C02E6C4F06FA3A5ULL,
			0xFC5470DE43BEF522ULL,
			0x63BB4349E47E0ECCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3CB1899AE3478E90ULL,
			0xC87AA2CBF6F5C7A5ULL,
			0xDC526B9CAE75A034ULL,
			0x7FE08936951D7703ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x886CE02A5B9AC523ULL,
			0x65EEF65E26734018ULL,
			0x73C3D46A1E16DA75ULL,
			0x1FF8A2E90311B775ULL
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
			0xDB4DD9F597015478ULL,
			0x3777A55389174220ULL,
			0xBB8068911A703FF5ULL,
			0x6978E2E07D9E464CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA11694187305E5C0ULL,
			0x39A046A1BD002E60ULL,
			0x5109B09B336479D4ULL,
			0x73D6F3F705D98F85ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2D575DE833B7236BULL,
			0x09230FDE6ADB3714ULL,
			0x6CA6C156E23E8214ULL,
			0x53755ACEF56F03F2ULL
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
			0x440BD3214DFD61C8ULL,
			0x223B9CC8D9AAA2EDULL,
			0x2DE76210453AD670ULL,
			0x5B802F3AC2514F05ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3C0C203497E23D78ULL,
			0x8FB5E2044DD0C188ULL,
			0x3228D3A3507258A0ULL,
			0x640FE0B687D0EFC8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7F96B336222E7F32ULL,
			0x72FE33A28F445E62ULL,
			0xE6087D3F6AAD6B1FULL,
			0x5693C31B787C7A10ULL
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
			0xF7B29C6F79ADE250ULL,
			0x82F382BE0305C017ULL,
			0x2B6A21A471786FC4ULL,
			0x655521A040F9896BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x59DB72E5BAE96A90ULL,
			0x6EC25E7D138C2412ULL,
			0xACC910B5127E9D3AULL,
			0x4F84DAE3D0E99D83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB9520EFD3DF711AFULL,
			0x8E80FFE89097D382ULL,
			0xE4F40C81B9131F32ULL,
			0x2763DC3062282A25ULL
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
			0x5DF1CBC8D14F50C0ULL,
			0x0893E878FAAC7876ULL,
			0x522CCC8DCECFD684ULL,
			0x6A322BC0C6B2C632ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x008A1ED422444208ULL,
			0x377794A9B147BFDAULL,
			0x3EF1C706745E9397ULL,
			0x4D2C0C8B97A10779ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCA1AA407CD71166EULL,
			0x4F231E3E0F5261E4ULL,
			0x7ADE59ECD197BF4EULL,
			0x66FCA3A23D711BDAULL
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
			0xC29790B664BD9658ULL,
			0x56AC3DE7D765FCFAULL,
			0xA009BD59F7567409ULL,
			0x7074C9505B02FFD1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x65E8C9DBEE0E97D0ULL,
			0xB5214A19AC235564ULL,
			0xDA71486581D74D85ULL,
			0x574E0E71E7D3954EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47D9D6B1727A07BDULL,
			0xDA90A125C4FC8283ULL,
			0x7AB8D4370BB2849CULL,
			0x4B2CDC3C335719A2ULL
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
			0x457D3D0179C88C60ULL,
			0xD19C9BA88EF0EA80ULL,
			0xD4F108D493C51964ULL,
			0x4123BB019398C0CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC088FECA7782AB50ULL,
			0xFDEC4C9DE0306DCDULL,
			0xDB8CDC4D69C7B73AULL,
			0x425E64AF5EFF96E8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0741EE69EA34879FULL,
			0xE170FE87E613B8F5ULL,
			0x3CBF5C3C47B406D7ULL,
			0x00FFB7C327C47E60ULL
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
			0x29BEA87B8680C248ULL,
			0x6AB364805B6862BCULL,
			0xF50A206E00BA5C39ULL,
			0x5A9F88689FCA2BF8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2E61A87E799E2EC8ULL,
			0xE0A2EE16ECD09885ULL,
			0xFE178EE8ADEFDD66ULL,
			0x4AEA947A7F2C2B52ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x65520ECA0A0F46D6ULL,
			0xF3FE68DB5DFE7F59ULL,
			0x462A4AD567F36456ULL,
			0x50F21752CF4005ADULL
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
			0x4771ECD9634DE668ULL,
			0x0813BF1EB3D09EAAULL,
			0x7850D694AE758513ULL,
			0x56094A9E988B2C60ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0F142307113F8FC0ULL,
			0xC07904150216852BULL,
			0x6AA7245176EC9F55ULL,
			0x4F0EE76E2262D3D5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x74FC2BD244C69011ULL,
			0xEEC939F71A6C1A79ULL,
			0x8A1B1DA8A3F68989ULL,
			0x556043D9E4182235ULL
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
			0x03D8481759481978ULL,
			0xC46FBDD616CA5CC0ULL,
			0x703196AD0EFB22D7ULL,
			0x4879A4F18CAE4694ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF5EA748CDD594BB0ULL,
			0x3AF45C23F57DEE43ULL,
			0x9AA99EE90EF6CFC4ULL,
			0x4746FCB73CF87768ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x61F83DFF09F0BACCULL,
			0x71851213BACAE08AULL,
			0x281FAC03EAB84A13ULL,
			0x67B3F0C1D85E1C5CULL
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
			0x969D9190B8A871D0ULL,
			0x18AD7F8CBD85B461ULL,
			0x3DC56969B6380950ULL,
			0x54FFF7F386A25A1DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF1C40ECC64F2D7B8ULL,
			0x5CC402F7CDE86275ULL,
			0x27F79BB55617A35EULL,
			0x6E491B6540F2755EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1C8EDC674C3FB9E3ULL,
			0xB1CCB1570695574BULL,
			0x3C3028F0B5024FDBULL,
			0x51679CF40837ACCFULL
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
			0x9076F6008441DCE8ULL,
			0x6FDFA7E1E4B57570ULL,
			0x3C7C03081E022367ULL,
			0x44A5D1DDF52D0C3BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF3F75AFCEFAC7850ULL,
			0x68BAFE3119A5755EULL,
			0x4A97CDAFA921A4ECULL,
			0x793897ED60076A5AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x29BBD6A371EA5ECAULL,
			0x53E0BECF09DD0F7DULL,
			0xB41AAE418FF6872BULL,
			0x568D31404C5B6306ULL
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
			0xE5392C66BF315068ULL,
			0x9BF16B11FD1F3E83ULL,
			0x3A810DF6BA14AFCBULL,
			0x58397DB92C399209ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2771371B8A9B97F0ULL,
			0x817375B3844357E6ULL,
			0xF61C13354A6AAD0DULL,
			0x412733FA6F104270ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD2AF77B291C240DCULL,
			0xB09D9F0EE4636264ULL,
			0xCB36CA6F1603F367ULL,
			0x7688174EA48A92D6ULL
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
			0x569C0A52F12E9608ULL,
			0xD46F8C8633103239ULL,
			0xF10C1AB7EB44A964ULL,
			0x605B70BFEF1215B1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x673C7CE55E688BA8ULL,
			0x11F2AE373D339420ULL,
			0x557FE40A6B60D580ULL,
			0x607A24D0C9757227ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x66BBAD36A859F5E4ULL,
			0x3BFEE96A4945181CULL,
			0xCEFAAF5DF1942F73ULL,
			0x067AD309C0A3B359ULL
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
			0x1264E4561ABB2590ULL,
			0x563B298F036586B8ULL,
			0xBE01D8FF0551C764ULL,
			0x4227971DD54FEF19ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF86262AA1434E300ULL,
			0x94DB8124B80F2EB9ULL,
			0x724BD2C912CB1BFAULL,
			0x4B82B1F4A2E8AA45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7D9A389B7FA84B61ULL,
			0xBDEA59047C75BE1AULL,
			0x09097877E4E2E3CFULL,
			0x525925AD84ADA66CULL
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
			0x88C9C668CD77C3D8ULL,
			0x28F705EE0F605891ULL,
			0x752DE492AD5F9853ULL,
			0x7084B0AB5CE7D0B0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x42FA7CD31DAD49D0ULL,
			0x9600FC89EBD0413FULL,
			0x64333048974EB07FULL,
			0x549B8C5E4FD25734ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBBD0449B8F38963BULL,
			0xAE24A6EC7F6D0AAFULL,
			0xAB0EF3D3DDCA827BULL,
			0x49FE1E0A7A014A6FULL
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
			0x7065E5229D1B89B0ULL,
			0x3CC2DF39B8076C4AULL,
			0x8CAC0453C33C4689ULL,
			0x62086AE3EF6F0D58ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDDA1F8E5D258AF78ULL,
			0x96420C480ECBB595ULL,
			0x0444F8240C7E4D41ULL,
			0x71D6EF91FB1CF64FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6D255D7A294BD718ULL,
			0xF0861CBC71DE941AULL,
			0x6CF1FAE962B09203ULL,
			0x25D1C0B1323EB083ULL
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
			0x378728A7ACFE3898ULL,
			0x7EF66880C4B0CC0AULL,
			0x1523FB9D2A59D31DULL,
			0x72D6051C41043DFBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x90D2CB40C73A3B60ULL,
			0xB323019817FC76A4ULL,
			0xF4FD93CBE528EFD1ULL,
			0x449EDD4C56D2DD36ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1F12A9D90F9735E7ULL,
			0x9453A55B3457FD3CULL,
			0x7A4B29C1F8CCC242ULL,
			0x5CC5549B0B0C9E89ULL
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
			0x9EAF8D567F258248ULL,
			0x5117F792688B2971ULL,
			0x8D22D1BA42167D99ULL,
			0x7F77F3BBE1153DD6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5F1F8F4088A9F248ULL,
			0x4B3C7AB97FA09264ULL,
			0x55166407D514D0F7ULL,
			0x5B57663F1D904F60ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x09AEE1332AC7AC99ULL,
			0xCCBC7364D9A1A893ULL,
			0x2ECE0E25952D073AULL,
			0x4C373D3BE45954EFULL
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
			0xD73A5B810DC7B800ULL,
			0xBCFB851205C892A1ULL,
			0x8036F5D222B51363ULL,
			0x4E0A1ACC2E6ACA15ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC132E03E876A22A8ULL,
			0xBEBB1C16DA9C145CULL,
			0x3D0F882721364227ULL,
			0x7EFFB90FB07AA49DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x679277FA5D5D7B9CULL,
			0x0B123CFD6B090DB5ULL,
			0x858775DE99BB3646ULL,
			0x0C95E7BD19983E93ULL
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
			0xFE982ADA2E2E0958ULL,
			0x96675C17FDE48AD5ULL,
			0x0083D8AFD19C145AULL,
			0x5042C65BB6C017C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7F48E1939C5EC778ULL,
			0xE019718B5A2F4E3FULL,
			0x86B0E12C6165BC14ULL,
			0x4458A407B43DF956ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEFBCB34FC3FD685DULL,
			0x3A8F897304983904ULL,
			0xA948030AB6FED363ULL,
			0x2C089BD1EBD0EE4BULL
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
			0x5C04CD638F316308ULL,
			0x4A2C93F02BA3CD4EULL,
			0x4A8429505AF41A6BULL,
			0x4063CEB96A476CE8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC8A0D8CFF4356488ULL,
			0xEA90F73F2955F09DULL,
			0xB3F3B72292FB17B9ULL,
			0x5965F890D454E643ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x907F13787C9C9D0DULL,
			0x8C4779A3E8BAAB80ULL,
			0x9A5369A0D300D854ULL,
			0x083E568D746E6FF8ULL
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
			0x528F9CAF67BDC0C8ULL,
			0x5A5194C6989EA7ACULL,
			0xCF72B824CE903DB7ULL,
			0x787EA1E626969262ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x389E5AE8972E32B8ULL,
			0x137AC174363F944BULL,
			0x53438E0A3B32255BULL,
			0x701340C7D262B9D0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFE921B0FA88CAA69ULL,
			0x2A8609871AD1A58DULL,
			0x23CB0538CB0988D5ULL,
			0x2CB609DFA1894AEFULL
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
			0x1EA54858BC89BD30ULL,
			0xD5ED8E04CDF49E1AULL,
			0x9972CF354E586A92ULL,
			0x65A5DEEDEB73E2B6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x782A57A362C7D8E0ULL,
			0x8D9805C230B8411AULL,
			0xCE6FD27C67828BCBULL,
			0x438754E39BF1331BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5D37B4765513340ULL,
			0x3785D93B0357F52EULL,
			0xB69C1508BBECBDC7ULL,
			0x75C0E2E3D993AFE6ULL
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
			0x70B2C8F71EAD6038ULL,
			0xAE9BCD5FFBE02D4BULL,
			0x5FE3C46022181B86ULL,
			0x5BB069BD2C50406FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC0AC19C843CFBB90ULL,
			0xD188F2C6A3A56D02ULL,
			0x2B17D0417EDB9804ULL,
			0x6E48C20D44CFB1D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F2330136335C64DULL,
			0x7E3D410B2E97C01DULL,
			0x1EF9244A660CA0BCULL,
			0x45514F388584711DULL
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
			0x4039861534C62628ULL,
			0xE730C790F1B8D55EULL,
			0xF8E580243383E7F2ULL,
			0x6F093304616D10F5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x04121BA807214338ULL,
			0xD83348CF51D52FC4ULL,
			0xF68AE44E6356F71EULL,
			0x48E8E57A8D466FF9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x31654BB38826DAEFULL,
			0x1F69621782B6A197ULL,
			0x6C7115DF4D8F65B0ULL,
			0x00EBFC60CCBEEA28ULL
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
			0x5B68661CD75EE558ULL,
			0x97A3F0833D005185ULL,
			0xA446046F3BBBED5EULL,
			0x5EFB04FB4F035BD1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE8F34416927E43C8ULL,
			0x37AF0F32B73E6842ULL,
			0xD880CE755D550562ULL,
			0x5784ED39E9878810ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEF22A4C9871E1FC3ULL,
			0x052B30C1C4BEAC79ULL,
			0x3972443A1A0DE8CFULL,
			0x088DA7016AF9F6E4ULL
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
			0x30CAB7119D37A658ULL,
			0x0EB0CB4594DFE82BULL,
			0xC4F3A39BFA2A29BAULL,
			0x5295E57511D342E9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC33DE154E92F9CA8ULL,
			0x37543201A8354CD2ULL,
			0x13E787E2D2DD31DCULL,
			0x4B6376F7AAE89B70ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E55DA1EEFC910A6ULL,
			0xCED4841436441B3AULL,
			0x609E0E4EDFACF11EULL,
			0x01A0A96692DC77AEULL
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
			0x91517FA885437990ULL,
			0xD2B94B699AC6C5DEULL,
			0xF36A01BD170A32DFULL,
			0x5C10BF3B124A2D87ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD37AC919B5416E78ULL,
			0xCFE3EAA5214A4E2DULL,
			0x6D19D5FCCE4D1552ULL,
			0x5A191D903C44CB7BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6D2C752ED94B01FEULL,
			0x0A8C9FD4F781EE98ULL,
			0x273ED427BBBB3BBBULL,
			0x6DE8E0970E9E348BULL
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
			0x411D06E4D1766A80ULL,
			0x2754A933B6E4ED93ULL,
			0x94922496CB762EF0ULL,
			0x66EFD5CCA3C69714ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCABC8C073FE59C78ULL,
			0x3CD0C6FEE7C781CFULL,
			0x3F652ACC9B4A02C5ULL,
			0x4809B011B450F6AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE3C3AE6FA10549CAULL,
			0xCF705B9F12A8A8EAULL,
			0x7A77265BA2951FCDULL,
			0x2ED1C3AB830C73B5ULL
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
			0x0CD4B3C3DC360520ULL,
			0x3906EF258E3B9F32ULL,
			0x30E4893C6D3E52ECULL,
			0x5039E2543D1D0727ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFD425A8E12B1D978ULL,
			0xCE6C497E2E3BA8AAULL,
			0x6156CA2D8F287462ULL,
			0x5F59B1E0040FBD82ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x30E1301CCF54FC34ULL,
			0x25409DE1E02B2674ULL,
			0xF37640B4378627C7ULL,
			0x7EB0D53074DC4D1BULL
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
			0x8B7B1D9D6C3E36A0ULL,
			0x23F742755E37D149ULL,
			0x7C0D0E70F175A792ULL,
			0x6B71D0733B47F4E2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD265E63C6DCAC2B0ULL,
			0x8F554B6AE991236EULL,
			0x52BA9B18AC6C82EFULL,
			0x486D915A6D00892DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4536420C939E0496ULL,
			0x7F43CC155BC71334ULL,
			0x3EF7461F41732F97ULL,
			0x074B01B295DAEABEULL
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
			0x7786B8AB15378E60ULL,
			0x09B171188D24BF87ULL,
			0x1CE4DFD124581A57ULL,
			0x77A9E0C625E335E8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4105C85413759B08ULL,
			0x32109B55F2B8B874ULL,
			0xFF58569ABE3377C2ULL,
			0x49F41DA29BB13141ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF66D16268B23E8A2ULL,
			0x96799AED74117466ULL,
			0x2F86AF472086949DULL,
			0x50A565DE0A49ABF6ULL
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
			0xA5424EFF401A9E08ULL,
			0xF9CAD735EFE457E9ULL,
			0x5F1EF02A5AD4FC01ULL,
			0x780ACD98D947ADB2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC7D3D53B2591B6E0ULL,
			0x84077F5F31012AE9ULL,
			0x6FC1D8BEAD07EFA9ULL,
			0x59C7A295597F4165ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3A19556AF95CAC11ULL,
			0x6578FC9388B62AD1ULL,
			0x0AC39E7BA52866A3ULL,
			0x3E12175D4D1F30E4ULL
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
			0x12494845F6CAB728ULL,
			0x051F76707CA776B6ULL,
			0x9E2B6B2F12112E2CULL,
			0x723A9A9F93CBB732ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x83AE2905EB806D88ULL,
			0x7B7016EEF86FBDF2ULL,
			0x30396FAE02DE0D40ULL,
			0x405906B929E1F410ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC1CFDEC250E1BB96ULL,
			0x86EF6544631B5B47ULL,
			0x1C9D57A3C83B9A2EULL,
			0x3218FA048F4AEEE6ULL
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
			0x22C637AB8EED59E8ULL,
			0xB9404CC03C968A73ULL,
			0x7D9B01ACC3A33822ULL,
			0x5D39AFFE3AA002ECULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xED51F0185DED2D30ULL,
			0x04A69DA227AAC22DULL,
			0x81ECEFF29C2EDC68ULL,
			0x68D5E0EB2A87DF76ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8CF7983A33912F1DULL,
			0x6F7F9205DAFE23FCULL,
			0xBA89F63ED6D88A09ULL,
			0x345F890870DF8499ULL
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
			0x9498F3560AB0B8A8ULL,
			0x0E86B9EAAEB5EC6DULL,
			0x900CD03AC8A6E824ULL,
			0x6C3B90E431239BABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAA6F259F1AB4B4D8ULL,
			0x7997C81189BD93F4ULL,
			0xB31D20ADE856EDBCULL,
			0x47033403F150E42CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xED255BE95DD229BAULL,
			0x02D4B7E1265A6A71ULL,
			0x369CAB3A526EAADBULL,
			0x1E00AABEFD318269ULL
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
			0x2D9008151698EF60ULL,
			0xAEBF09167AAB42D2ULL,
			0x6D0B9B89F83830BDULL,
			0x606CB1AEB98AE975ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x205CDAD70BFBD970ULL,
			0x025D68B61FCDE740ULL,
			0x4897108168FC70E4ULL,
			0x463AE03B9B7C8712ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0F3FC9085F229FEBULL,
			0x41191047707DC55DULL,
			0xC839380C11C6A249ULL,
			0x3E7B07C23DB6CEEBULL
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
			0x254F50B9779213F8ULL,
			0x4C93667FAF4DF6AAULL,
			0x9B3127302120B7D4ULL,
			0x46C09EC402B2FD2DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFC7F8394FA301460ULL,
			0x9329BEA59A764A2AULL,
			0x79356B68781B3234ULL,
			0x45439C5A291E991EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x13E0F927EB9B1E08ULL,
			0x7F3C66618E32226FULL,
			0x5AD4077B5EA6EA3FULL,
			0x566A0860C9D25148ULL
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
			0x3AC4F10CD1462148ULL,
			0xF8CA357BBA16E25BULL,
			0xF7B7CD4F1C9BDCD9ULL,
			0x475B25E3039A060DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5349D6C15E4A1B90ULL,
			0x3B6FE1D8E027768DULL,
			0x3A89A3B273052D81ULL,
			0x4D5BE3F44A6E6CECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4BE197F533D09D75ULL,
			0xA6A2003196662D91ULL,
			0xDA8A5E5819C35C0BULL,
			0x0B5AE603C6BB839EULL
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
			0xF4425EF03DF8A818ULL,
			0x051A5DA3D72EA158ULL,
			0x4BA43F65FA1C4F41ULL,
			0x63F5C8BE10177493ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x79BE302B1AD34E10ULL,
			0xE0156697788C4A96ULL,
			0x4961665D51061C72ULL,
			0x599AA5F276141D6FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2897C78F50A4E89EULL,
			0x4E88F1666114B66AULL,
			0x84C67F31AF3FCA5FULL,
			0x3553F408E8687789ULL
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
			0xE466986BBCDEEC68ULL,
			0xAB5846E871A4E3F2ULL,
			0xCF08DD213FB2D7CAULL,
			0x687A9F3D30BC9C08ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x75C66E9750EA2ED0ULL,
			0x5A24B9A196A6874EULL,
			0x81AF4AE0C81F56CFULL,
			0x73B154B3E4D8DE20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE1DBF70784592797ULL,
			0xA4F8909A5453E5E9ULL,
			0x0FBF7EFA935B840AULL,
			0x3C0F6BD4B7268221ULL
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
			0x1E763AE2C54E1148ULL,
			0x050CBE4EB593F7A1ULL,
			0xB639F0ED72B1FB44ULL,
			0x5DDB49C7ABCAD591ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCE5D078FE2CEC828ULL,
			0xF0D2A25597291130ULL,
			0xFDBC5E0CCC6D745EULL,
			0x40F989C96EA50D3EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C1CA68C0567638FULL,
			0x67FF40577427718DULL,
			0x965CC3A85CF3102DULL,
			0x0F6B30FC0BEA38E6ULL
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
			0x608C7E88952D90F8ULL,
			0xC61E3F1B2769F302ULL,
			0xB1BBEDD4FCE99530ULL,
			0x6E49F99ED49D35EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2E50478974AE6238ULL,
			0xA6DCC5EA167BDF94ULL,
			0x951AFCF09C365EBFULL,
			0x56980765E5B16940ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x63B045CBA11E866BULL,
			0x0176391EAC4A7ED0ULL,
			0xE3F746E5DB6D78A5ULL,
			0x57E6ED3105863367ULL
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
			0x964A2E7279CB3CC0ULL,
			0x4F3470A53B649DE4ULL,
			0x5A87F622E60208C7ULL,
			0x72857622C7F7F07AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1A635E2A925EECF8ULL,
			0xFCA7C5AE2F0682BDULL,
			0x8309949BE78B7EBAULL,
			0x63144F2FAE4DBE58ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x76AFE6C23C33EC30ULL,
			0xA016044829B7D4EDULL,
			0xEBDE55B68009214EULL,
			0x6A6B97BF7BF118CEULL
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
			0x5F7436C6ECE4AC98ULL,
			0x527FD5AE441B875FULL,
			0x6AB54A90140B28F5ULL,
			0x6F58DCCEC12622CFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x91DE6E3753F00348ULL,
			0x924E06F57B0E7C5FULL,
			0x0A9DCABD4773D4E1ULL,
			0x4415D71272174477ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6C514D5787D32C74ULL,
			0xA702CA198C524BBEULL,
			0xFAEE41723D0ECFA8ULL,
			0x4B1122EC1ED9F062ULL
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
			0x263499215D7CAAC0ULL,
			0x874A2EE9E5A3BA5FULL,
			0x1D4720A3A19113FAULL,
			0x491DFEA8B8C43102ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD3511CE95115100ULL,
			0x308C28592FD0D326ULL,
			0x4153290BCCDB628BULL,
			0x56BD0E0F355CEC86ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC1914A43F0B19A4AULL,
			0xCDDE80A8DBE374C9ULL,
			0x9AD6CE0D8CA65F13ULL,
			0x03A974D331A1926BULL
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
			0xB58995B7D515A8D0ULL,
			0xF4AF653A4A23F4F5ULL,
			0xB650DB3DED86D574ULL,
			0x5691CC6FCCFAFCFFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8F774DB417CA0758ULL,
			0x6319DA5F563C896BULL,
			0x394D1D45FF5690E4ULL,
			0x4054C35484824A7AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x836DDE8FEACC0867ULL,
			0x9665BDCB14651D52ULL,
			0xB085EBE01BA60111ULL,
			0x068F69BD3901E316ULL
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
			0xD8B87796B144B5E0ULL,
			0xC6CCCA89B4CF793CULL,
			0xDA43AC78BB0E664CULL,
			0x7ECE0DBB190D182AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0549CEE4154EAEE0ULL,
			0x65F6CE2DB7C91116ULL,
			0x3578C8A7977C41C5ULL,
			0x431051A35270130AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x902DD50BE0A7FBACULL,
			0x6C750FDCA54B0388ULL,
			0x9CF6904E375A9F38ULL,
			0x588A97124DF7AE41ULL
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
			0xD0270E8EEDE13478ULL,
			0xC745793B0E0B5EFEULL,
			0x8E892C7BEF95684FULL,
			0x6D5C0B8374E77FDDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x596B0268DA4886B0ULL,
			0x0AE261FFBB215645ULL,
			0xAC96F9B6979FE49EULL,
			0x770193F51CE7458EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDEF9A76322B33B1DULL,
			0xBA3D552E609BA548ULL,
			0x1C1689820A1DFE0FULL,
			0x3617247B7055C4C1ULL
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
			0x7B553E676ABF75A8ULL,
			0x45AF452053413BF5ULL,
			0xC6D4BC59F7A6446BULL,
			0x6C8DDCD0934C22C3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x612E3E5F4026F050ULL,
			0x7A321E259F8A7982ULL,
			0x2D7936116E698FEDULL,
			0x5511D25969F02D79ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF039748D59B1C68CULL,
			0x8F2DC153971C1657ULL,
			0x278362653756CF6EULL,
			0x127DFEA5B6074ECFULL
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
			0x47B00E4523779910ULL,
			0xB17BFF72EA7799FAULL,
			0x46BA35A7BC328EEDULL,
			0x7302096B5F4C7EA0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8B7A625A98283EA8ULL,
			0xA7B775A79C00C09DULL,
			0x326C9606AD998642ULL,
			0x5156D6761D81A258ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBDAACEC0629CD55DULL,
			0xFE5D4B3B4248FFFEULL,
			0x8ED54FCC767B82B3ULL,
			0x6D7E4968FF1043CEULL
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
			0xBBB790CE08DF2640ULL,
			0x7BE7665850716F89ULL,
			0x73FF4E44B04C9DC5ULL,
			0x6F373973E4E786A7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC558AF1070DA77D8ULL,
			0xCC223F011B02C660ULL,
			0x7FA72A7A6C84986CULL,
			0x6D883C77A0EB50E1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDAC0670B359CC5BFULL,
			0x7AEB54D9E0CB33FBULL,
			0x5AE1FFF4D9BF13E3ULL,
			0x674A5D91FF8A0ACEULL
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
			0x6FD825ED5FCE3948ULL,
			0xC25D10FAB1B8A524ULL,
			0x5D455363C37CC7E6ULL,
			0x50EBF27DAC70EEF8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x94626B8DADECF700ULL,
			0x062BC89CDEE43468ULL,
			0x4AAD739979044699ULL,
			0x7BA906883FBA8995ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC89302409F6399BAULL,
			0x7B33E2998AFA96D8ULL,
			0xAE020A6B867C3A33ULL,
			0x4F7B65A8EA448927ULL
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
			0x75B50AF59C214140ULL,
			0xD21A6A5CFDC63168ULL,
			0x243E8CF8C211B55FULL,
			0x733E867EF28EB56BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x312C703A91E06C60ULL,
			0xE83E137C82D0D6BDULL,
			0x24EF2D2DD3B633DDULL,
			0x7DF49235CF258B80ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE78F517D3803247ULL,
			0x269597842BF99212ULL,
			0x358F6956479460F8ULL,
			0x54BF76F644DFBEBBULL
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
			0x4B1A5625C8A6B4F8ULL,
			0x2986D25EDC9C2F39ULL,
			0x48263BE42F1DEE45ULL,
			0x40BF7EF18C99F58CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDDEDEAAFE2933450ULL,
			0x7FE1329005CCCEBBULL,
			0x9F1F5A801E9B2B57ULL,
			0x556E7E04091D53F3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEAB3121EF9393C51ULL,
			0x149DA1604FBB49DCULL,
			0x1E1AE36A39B353D4ULL,
			0x0C91481F53176A63ULL
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
			0xE743728FC7084398ULL,
			0xA0A22DE29EB8031FULL,
			0xE0EF78ED1D1C6A1CULL,
			0x4263D7181369161CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE6DC677421A09668ULL,
			0x6EB0C49536DC0D9DULL,
			0x57FBEDB316A76AE3ULL,
			0x56FE457AC291B67FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB80CCF73E331DC16ULL,
			0x5133D3AFCF356749ULL,
			0x0EF0DF85269AEA9CULL,
			0x6AA9303386124169ULL
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
			0x16AD15BAD6C71AC8ULL,
			0x762F51348510DF8CULL,
			0xCBAC4C75D1EC53C0ULL,
			0x5FEA294545B680D3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x23FC88AD2B1C42E0ULL,
			0xF8F8EE3F214F8DA8ULL,
			0x287B9FA44916C4CAULL,
			0x5728D4276F306E6BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD54109FF0A2F81AULL,
			0x9B96A3270F22B2E9ULL,
			0x588555B6CA68824AULL,
			0x609FA59F6EE1A509ULL
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
			0x623756E40679F6F8ULL,
			0xB72B3F63036EAEB9ULL,
			0x014FCA23BDE402DCULL,
			0x7D42CB1F713832D4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2D69BF363C8ED3C0ULL,
			0xC16CE98FBA040D68ULL,
			0x4D5E3468C97EB7FCULL,
			0x62A125D8EB8EEC6AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x65F0914A40461220ULL,
			0xFA36F81827E3F0C2ULL,
			0x01E1E7BEBE1DBB6EULL,
			0x71F30FE9CB17D1F9ULL
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
			0x201A0401484C7518ULL,
			0x5DF9256AFA320E5FULL,
			0xF7F3E8A6A47A555FULL,
			0x5ADA93D7A4021B92ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8BB5C31697D2CC60ULL,
			0xCE6C5ACD779BD4C4ULL,
			0xD240D1A8A9E0506EULL,
			0x6B46709E078486A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE959718784C13BAULL,
			0x369CC0A68526810DULL,
			0xA2823136A9A239AFULL,
			0x74DE73E3E4B4160AULL
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
			0x0807B451DEF038C8ULL,
			0x0B99E5620BA77697ULL,
			0x16FCD69E8E28E29FULL,
			0x403650D0C17943E6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x914CB8568642EE40ULL,
			0xD4945986906FFA04ULL,
			0x687271A5EDA6218EULL,
			0x68D791C149061ED0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2CB074E31205A58DULL,
			0x2D23E512682A576AULL,
			0xD0652A71E7E2AA8DULL,
			0x7A73C3A58B5F49E5ULL
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
			0x065144ABC70797C0ULL,
			0x06E6791113A89B13ULL,
			0x0BED4FB2F961DB1BULL,
			0x7C0E159AB759F52BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF4C513A1071ECF0ULL,
			0xF61180C11BF9E86BULL,
			0x8DB728F26C6C193DULL,
			0x5198EE4C936E0920ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F45E470F3AF1296ULL,
			0xEB0E6F9D9327AA00ULL,
			0x94D0D8B48C42EA6FULL,
			0x1B74AF27177EC269ULL
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
			0x0B9E8EC622A9F870ULL,
			0x8D894D5D32F79A73ULL,
			0xA083A46463AE24D1ULL,
			0x64EEAE70F521E92FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE3BA29BA7D696810ULL,
			0x871E46839521EB55ULL,
			0x4D086A6C93333CE7ULL,
			0x73EBF67A0036F0B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1418940A8A66CDB8ULL,
			0xBF0D13885AF2D6B9ULL,
			0xF44E97524626D74BULL,
			0x724DAFDED75AD604ULL
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
			0x009447F949BC98E8ULL,
			0x47FF96206AE965F5ULL,
			0xC7D77CF83181E6E8ULL,
			0x5A076746882B2DBFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1C939D2D23287800ULL,
			0x123D87387CE61A01ULL,
			0xB214F6E4BFCA1A68ULL,
			0x68F5B5F533739832ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE45A1A959592B2BEULL,
			0xEE76DB942F9EA0C5ULL,
			0xE35463E5762285FBULL,
			0x5A3DE19206DC531EULL
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
			0xF95F9AEA97B5FE48ULL,
			0x0A3DB6793A2253C5ULL,
			0xA7E011C5E8BB3D59ULL,
			0x64BD96DC744F495BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE71ECBB3D026B558ULL,
			0x963348FAD5352227ULL,
			0x420E80EA05B0A892ULL,
			0x69C6CEBCA4A007C1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x59F8C4AADD8B1CACULL,
			0x185839B32692C9A8ULL,
			0xC8D8961FD2B3B274ULL,
			0x09758DB37D407A06ULL
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
			0xBD75B66EE2B0A920ULL,
			0xF0505D9E4747BC26ULL,
			0x9C4E4936CC9ACC6BULL,
			0x5F8D99DB8BD94349ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x15BFA991C615BD80ULL,
			0xC07D5C361C6DCB06ULL,
			0x5745CCEA3E8314E8ULL,
			0x5AF294B82EA5F4A6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF3CFAA6E4D4BAB01ULL,
			0x7F3E1B5DCECC4374ULL,
			0x9207A06290EF52CCULL,
			0x38DC6FF12A270D12ULL
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
			0x7B202254925CC128ULL,
			0x0747A7303C334FDAULL,
			0x45A7A944236F62A3ULL,
			0x4ABFE0249BBECD17ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0797CA0D31E04300ULL,
			0xFA90BE56E18453C2ULL,
			0xDA5FF14AD6CAA668ULL,
			0x78C35A7DBED54436ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB4FF39AA88CDD417ULL,
			0x529C238A79A24B3AULL,
			0xEB79B3B836F738CCULL,
			0x154726A246C2870DULL
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
			0xC76F42333A127DF0ULL,
			0x8930CB7B6EC8EB20ULL,
			0x33B49973240C3A4EULL,
			0x6AF409378D124135ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0735AE56B0CABF10ULL,
			0xEAC6359CE9458935ULL,
			0x57CD0D814D60B248ULL,
			0x733FB1D70E6123CFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCCC20F3142B98583ULL,
			0x164129CF50DA2273ULL,
			0xCBBEECDFA7668D15ULL,
			0x0E1B600C41A38C7BULL
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
			0xFA485E124AB33C70ULL,
			0xE6A106B6684FDCA7ULL,
			0x57F37C970E68BFA2ULL,
			0x6F34D5174DECB395ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC3B160D1A88C490ULL,
			0x0C03C5566C8E0B7FULL,
			0xD581B8D4C38C175EULL,
			0x76CEC8C5560FED1BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC12D366FB21E2F55ULL,
			0x75446CDE139AD9D7ULL,
			0x5900E76AEA46CC95ULL,
			0x663C26D9105687D6ULL
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
			0xA1881F2C9FF83788ULL,
			0xE09F464CE8E0BB09ULL,
			0x96B246301E937A2EULL,
			0x5B7975AA6E4234BEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBE6967F3CA242B10ULL,
			0x169A87F3E3FC4C11ULL,
			0xD7116D510A4BFC84ULL,
			0x4C6470C961EF4353ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD00660525106AC36ULL,
			0x307E824199008873ULL,
			0x6498083C7B2DA17DULL,
			0x005C3D420B5ED160ULL
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
			0x6E27CFDF49E058A8ULL,
			0x708C4AFCCD2F4A1AULL,
			0x35AA55363147142CULL,
			0x785A355E278541D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x725CE29D838A2460ULL,
			0x66B35E40BE594CB3ULL,
			0x323298687CBC7D87ULL,
			0x6098887A05D284E3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B3E55BB76BD7000ULL,
			0xC97D289BC3A187BCULL,
			0x0D85A4B8BA731BBAULL,
			0x70A138937AD751FFULL
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
			0x0D616C5F7FE204E0ULL,
			0xB8B4426C791D1DEDULL,
			0x2C6CC00E26F88C38ULL,
			0x5E980FB53F17A188ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0070C2F7309ED10ULL,
			0x2E6E7F0D5A8F08C8ULL,
			0xFD4C8F877F40682CULL,
			0x67A6523FDFEDF9B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x74713A2BFF0A3B36ULL,
			0xBDCC6A372B7F5609ULL,
			0x9A3E6D6E51EEA9EFULL,
			0x7CFC5A4E1C9414DCULL
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
			0x453B625A554D9278ULL,
			0xBF79D64CE996F933ULL,
			0xE30BC759B9A18654ULL,
			0x6B7E163EEF0B29F4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x55AA46130E772010ULL,
			0xD2025E8C0C89E355ULL,
			0xFB8427C4234C0097ULL,
			0x714E466C81D56BB8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA195BDF4C6855542ULL,
			0x0E829FAEB02CB4D6ULL,
			0xFCCA9A3FE2BB8ADFULL,
			0x2B1B50699C796FC8ULL
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
			0xFE750CD6B852B130ULL,
			0x622CCDF0D9C8DEEBULL,
			0xAB6358B36938CD37ULL,
			0x7A45E09D35D5DA56ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9421D860B80C1288ULL,
			0xFD58BBAA4337D21EULL,
			0xC17C98C9565CC1DCULL,
			0x6DF2E95F2E5ADE58ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C4AE6B20DEE03E9ULL,
			0xA43AE331B5C75A27ULL,
			0xAD14A0BA883E0808ULL,
			0x45D99495B6565714ULL
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
			0xB99E931A97AC1818ULL,
			0x0366C9D76477DDA0ULL,
			0x9D0933955E8083E1ULL,
			0x547044B903CDA9EEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE52E0AB9B50B5278ULL,
			0x6943AC9361FCA15BULL,
			0xA33706AEB88AF095ULL,
			0x43BD099141F83B9DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3329CE9A28316E7AULL,
			0x208EDC68718D4A1AULL,
			0x34D2A00A02047450ULL,
			0x30193EC76D7AF877ULL
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
			0xF099DE7C07618B70ULL,
			0x6B9C1277D357B395ULL,
			0x92970E2B34720A94ULL,
			0x6C950C8CF40390FDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x64AD4F72340998A0ULL,
			0x51ACD2A39A80E56EULL,
			0x278959B144F65FA2ULL,
			0x6767D87E82BC93B2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2C7920EDB45F815ULL,
			0xF3D23A15B59DFDCCULL,
			0x80751456D57956B7ULL,
			0x6BBB1538891CC26EULL
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
			0xA7CF77C75BCCCA68ULL,
			0x45D352FF7DF77CE0ULL,
			0x85CA54CB9F734129ULL,
			0x50AC8E64E10BF541ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2931E7CF3CD42208ULL,
			0x292D0D755283A960ULL,
			0x6F14811F05168B92ULL,
			0x6E58658BB51447D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAB39507BD70A3926ULL,
			0x075A4EAC911805FCULL,
			0x0C730E280C54B47BULL,
			0x041434CC5C7F689FULL
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
			0xAC6999E76F88B6C8ULL,
			0xF1CA7251E1278719ULL,
			0xB58FBF6A384CB019ULL,
			0x7AC5741F24C862E4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2A4F3A84A9ABCAA0ULL,
			0xB0C6A2375A52E10CULL,
			0x07811EDF7029FF76ULL,
			0x691A2B34114CF2EDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x297B3097165AF912ULL,
			0x50BCBE2C2B40B142ULL,
			0xB97AA22478128DFAULL,
			0x73B4C36879704925ULL
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
			0x8D88582984DCF500ULL,
			0x78118BEED4217E81ULL,
			0x6AF48BFBFCF1919BULL,
			0x64AD6F369C510E0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF95DECC1EB1B5B8ULL,
			0x4AEF31571CEF41FEULL,
			0xF9A304C1E40A0238ULL,
			0x6864758D8D48E748ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x131A26AF0F7B4330ULL,
			0xEBB89ECFFEA9C218ULL,
			0xD6E2A16EDD2457FFULL,
			0x4756063057276C60ULL
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
			0x07F2F55D8B3BA100ULL,
			0x7E2617848765D388ULL,
			0xD7A4BEB480CC3740ULL,
			0x67309797BCB3A102ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF45A498B70F67720ULL,
			0x6D50080C7B9D433AULL,
			0x72B61FD01AE4A83EULL,
			0x6B3D046A2425255BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9BA1070FB5F1D17AULL,
			0x96509B6E5BC4E3A9ULL,
			0x2026717EDC92BCDFULL,
			0x2CF67BF690BC6082ULL
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
			0x395C7C26C4D35688ULL,
			0x71F453DA3CA0AA80ULL,
			0xC0500D5156232713ULL,
			0x602068326682E1F5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8E8F99EF7F19E220ULL,
			0x2CABF65CB96757D5ULL,
			0x8B85377358AE92DFULL,
			0x7AE465C05733EC83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE6C61E317CE5E9A8ULL,
			0xEFE03673C6F8FCB5ULL,
			0x99264CD5D1144724ULL,
			0x41365941165690C6ULL
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
			0x71DD4BE8A4A8BE98ULL,
			0xC3403A874853B28FULL,
			0x276E9ECA285ED980ULL,
			0x7618AD46F29551D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8ABDCFB9455AF068ULL,
			0x0B74BD4AE7FBF19DULL,
			0x23CC3D706DF5A5ADULL,
			0x487026EC5E501ADFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA2BD12CB98A22DB6ULL,
			0x24AA9A752F41A8E4ULL,
			0x8C154C886EE28F50ULL,
			0x4327B6E9CA77213EULL
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
			0x0C04AFE3C67FD648ULL,
			0x5BE574A0F2095E0BULL,
			0x0E4F90787E1987D5ULL,
			0x6A8DA62F92B4923EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0725969CD21A7A58ULL,
			0x4D78733602569749ULL,
			0x4E6D7604E5F8B17EULL,
			0x4A97FF879F9A5D37ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x471F25636B5EABBEULL,
			0x67C4A75E8A731B96ULL,
			0x02410A12BB868FC8ULL,
			0x6D06D233F137F4D8ULL
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
			0x1228790FD1DA5E58ULL,
			0xBD668C916C527A23ULL,
			0x65218E4ED0524DF2ULL,
			0x7D6BCD874DB55B1BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB0D10C45A21959B0ULL,
			0x26F7E19D3733E277ULL,
			0xB26345475C147206ULL,
			0x48BE1C5FBF8924AFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x02B0EBAD17C0ECF4ULL,
			0x1878A07F678F9BC3ULL,
			0x82E5FBD9B833CAAFULL,
			0x0400226B43E186A0ULL
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
			0x232B8C725C0C16E0ULL,
			0xD2F549B316D07459ULL,
			0xFE707DE9E2E0B6A5ULL,
			0x56B09AA3339E6888ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7816EBAACABDDFE0ULL,
			0x5E0098F9E7DEDEFCULL,
			0xBBFF9D3B14B887E0ULL,
			0x576121BDDD0F8FC9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6BC26663C82C8CACULL,
			0x101594939D6CD966ULL,
			0x66D402628AB8837EULL,
			0x1D72AFA6B3142086ULL
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
			0x254011374097F098ULL,
			0x584565C04A497F76ULL,
			0xF0AE02E81673CB57ULL,
			0x412C3F55C30A7068ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC511C7F818633770ULL,
			0x7876C8AB852E4C16ULL,
			0x170F802FA342A64BULL,
			0x57A70B47D0525609ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF79821ECEDD1F567ULL,
			0x3AA19C9D80867ED1ULL,
			0xE441EE565E78AA88ULL,
			0x16A03C1950F278F5ULL
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
			0x804B78BA0DC954D0ULL,
			0x6403B6FDBFDD841BULL,
			0x5FC0078B3923AD38ULL,
			0x792D02ED1C77B986ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x813664A68E0210B8ULL,
			0x7979337DD642CF1FULL,
			0xF17BB7CEF98AEB56ULL,
			0x5D07C5D2550F6B29ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x10ED6FE098978705ULL,
			0xAD7E8F72F65A717AULL,
			0xCAD75EFA50BD7D7BULL,
			0x4B1BA7F97ACF1F52ULL
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
			0xC0F0C15461E73910ULL,
			0xB244EF4712A9A84DULL,
			0xBF39F30643885668ULL,
			0x5BF558E77FDD8CE0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC51DCAE5A9F95E00ULL,
			0x38313D295D4FC64AULL,
			0x10B170EB9CB11CBBULL,
			0x6D8228756B21B5C6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD8AAC1845CFC351FULL,
			0x15A7D3F5F9469F48ULL,
			0xF33A50032CE9A47EULL,
			0x2526758E33541627ULL
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
			0x6284BD344D807BD8ULL,
			0x28A0D911042B9F65ULL,
			0xD2DAB0D588C708A7ULL,
			0x5B2C9F609DED4BA8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x697DCFC653985EE0ULL,
			0x6C4140BC6A1F01C8ULL,
			0x12E07661CECAC216ULL,
			0x53D0F6CA38295973ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9C5FCA4895714F75ULL,
			0x175A269266D807E7ULL,
			0x49CE12B1AE747319ULL,
			0x042DFC02CE79FE59ULL
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
			0xE71F9CE40200F2D0ULL,
			0x3BC657A4B52E696EULL,
			0xA041FC5E60624B86ULL,
			0x6274EE3BAA764D9EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDEA14E76DD788218ULL,
			0xED1870D1080F218BULL,
			0x0B95F0CFD6947198ULL,
			0x73051839F7A5A60BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x419C3C5754708D9AULL,
			0x5118D87B65F47E2FULL,
			0x28AFAFE067D20904ULL,
			0x72930E836C1B8B14ULL
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
			0x555A3D7C6411C080ULL,
			0x6CD69A96AC3DD9C5ULL,
			0x13EE3B6387002E1BULL,
			0x4C4195AEC3B499CEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7EA16D9AB6BB1FB0ULL,
			0x92D51675549D6018ULL,
			0xCAC560EA6F57D060ULL,
			0x6CA0C98F48F94613ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBCF155EC07C28008ULL,
			0xDEE1B29B49B6C991ULL,
			0x2CC7B3E44BD67CA3ULL,
			0x162D04BE58DB0440ULL
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
			0xC59D2DE189F12D90ULL,
			0xDD9024904711174DULL,
			0xFD7144D735409B2DULL,
			0x477804B2F5088BB7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54CC8500D2776E98ULL,
			0xC8794F7EDE5A15E7ULL,
			0x807B4B3E91156A70ULL,
			0x7C084A38B1EAC26AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0E3536C1442A7060ULL,
			0x9C56D1AAFDC5FD44ULL,
			0x2A07BACADB556F20ULL,
			0x6892652E20731DE4ULL
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
			0xB0C3BE493BFC97A0ULL,
			0x1F625700C76D5593ULL,
			0x9B4FBD5FBBF2B62CULL,
			0x498368AE78B62B48ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA9AF50B118B3E978ULL,
			0x1280AC3A4B7CE0B9ULL,
			0xF9C0A580CBE44C44ULL,
			0x7781BAB127B122E9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x070E70199B812223ULL,
			0xDE69A45685BBFBB9ULL,
			0x3B41E2922ADD9E33ULL,
			0x4F6E386981D8E1D9ULL
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
			0x4DDF464F8952ACA0ULL,
			0x7CC9D0C709D20382ULL,
			0xAC78565E01433405ULL,
			0x6D1551B447FAEC64ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD27E2A9DF59DFE40ULL,
			0xFE36E06A0AB92596ULL,
			0xD807F5EFC51ABCB2ULL,
			0x4AB6FB306DBDC629ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCC61253DAA41888DULL,
			0x77EAE27C743FA32EULL,
			0x847215F550784D0AULL,
			0x4B0EEF86CF0CA990ULL
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
			0xDCAF2D2B3A4FF400ULL,
			0x7E6BE1D10A410B53ULL,
			0xE7DB39A05D08B5EFULL,
			0x5E2ADF161595830FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x408FF4B82C7A5CA0ULL,
			0xC761B12EFEA45724ULL,
			0x3E20A8CA7661C772ULL,
			0x594826CFBB419B75ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x086646D53C4B64E0ULL,
			0x198072B663A9910BULL,
			0xC2D3813E090CFDC7ULL,
			0x0B17E0D5EE07921DULL
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
			0x95882479F57CFE08ULL,
			0x3C55E4AE8B984098ULL,
			0x05D3C9671BB9729FULL,
			0x5A61BD8D4D4E446BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x649FD39FC2FFA738ULL,
			0xF60B0CF7D756BDC8ULL,
			0x6D708652ACBB5D62ULL,
			0x4D1F41A7EF641492ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x551FE5445DE51279ULL,
			0x7AC20AB5F4D2912AULL,
			0x1E9777259D14F86EULL,
			0x25309C66E0AF808FULL
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
			0x217E1CD954851910ULL,
			0x0E4D1692C576B96BULL,
			0xDCDF20E040814867ULL,
			0x772EAF738940D59FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB9FEAC905FFC2328ULL,
			0xCE2071DC79FE9A36ULL,
			0xBC52860F4E693D51ULL,
			0x761A380ABFDA5C4BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0F6A4FDF24BB63ADULL,
			0xDF7622FB2D337420ULL,
			0xDB0FBFEB72549BAAULL,
			0x5F6A0A3E8892E4CFULL
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
			0x27A03AAEB5B032A8ULL,
			0x00455DC7AD6E110AULL,
			0x917265520BB66A9AULL,
			0x7A8582AA9C5C2137ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD6011359E582FBB8ULL,
			0x4E1EC4FC526C5C5CULL,
			0x8B657194297C9938ULL,
			0x68220DB73B8997BFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBF80ED1183247783ULL,
			0x920011CA02BABCF5ULL,
			0x11EFE252B52AEDD0ULL,
			0x2E18165B44AF101BULL
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
			0x5BF3AFC490F93C28ULL,
			0x66B4CA6C7F55225CULL,
			0x4A32F9199C71D9B8ULL,
			0x765BC19BD631DD73ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x379676789C87FBF0ULL,
			0x4360F23DF9F80E54ULL,
			0xEEDD703DE6EFC554ULL,
			0x63952CA17ED83116ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC6D0C60FF53B96D3ULL,
			0xF7BD9A4919D2BFDFULL,
			0x81D416D146D68CF8ULL,
			0x2D205F399044C510ULL
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
			0xA6929639C3FC8770ULL,
			0x95113B27D4EC0780ULL,
			0x754116B6DB59AD74ULL,
			0x6225725278381D69ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4DE27AF3A19DE050ULL,
			0xD59FCEA9AF37D646ULL,
			0xEC1BA227D761F1A2ULL,
			0x77980F5DFA250F56ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5266B6234FEDAC28ULL,
			0x00947B1958CE7ACCULL,
			0x84D38EC90E3CC64EULL,
			0x53B077DB27811AC7ULL
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
			0x0382DC4075535C78ULL,
			0xDDBAD28E5A5E1778ULL,
			0xC62FC7FB28BA1793ULL,
			0x72C4F0339BC6AD93ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x32F91067E85AD7B8ULL,
			0xD73D8C1ADF7FBB0FULL,
			0xCCE116D8221F87ABULL,
			0x4A07457C7675463AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3CF2075D7485327BULL,
			0x112CCFDBF40FB838ULL,
			0x98130015BA95571FULL,
			0x3C9709FC7066DC84ULL
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
			0xCA76F00701B7D678ULL,
			0x49AC01D7CED50C3DULL,
			0x0C4097FC6153DE89ULL,
			0x64D34534CC47C0BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC12991FEF4421C0ULL,
			0xD22A9D04EB7A5A0DULL,
			0x366C0C8654B0846AULL,
			0x5E57ABEEADB2620BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xABDED229759AD0F8ULL,
			0x136A0DDA78A9CF81ULL,
			0x2E556540E9992CF7ULL,
			0x7294243DB39A138EULL
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
			0x3C38089770913E20ULL,
			0x51AC79801B1BEFF4ULL,
			0xF36D9A51CAE105CAULL,
			0x47B8DAEA5C28EA10ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x35C336959FAD1A50ULL,
			0x3B388FC859C3BE11ULL,
			0x4FFDBCFD1FBE9A98ULL,
			0x5F4EFBD860587989ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD4B7EB714592BADFULL,
			0x182608D9D00B8785ULL,
			0x325CFCFBCC27742AULL,
			0x04154052BB62503AULL
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
			0xEE5BFA96B3445EF8ULL,
			0x49C5A0C46F1EF10DULL,
			0xC18E93BFB6972686ULL,
			0x5E9B51C3A7158882ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB4BECBCF5E0DDF98ULL,
			0x030BD36ACA951463ULL,
			0xCCFF25ACCDF21159ULL,
			0x6AB194E689BDEC3FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x62999EA1767357E5ULL,
			0xB628BAFF20D96AD8ULL,
			0x8690D324543D7AF7ULL,
			0x456C8FA91927624BULL
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
			0x4897C45400D9A1F0ULL,
			0x9A2906535E06408CULL,
			0x7024242E95CC4763ULL,
			0x6B5DF257D0EDFF6EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD5BB57F12A04CC80ULL,
			0x1FB569799069EC00ULL,
			0xA51283BCE022A16CULL,
			0x4F6271385DD084AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEC9393E6C1369CFFULL,
			0x4A5D6BEE1787A423ULL,
			0xC0900FDB04A5671EULL,
			0x60329F52C4958E0BULL
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
			0xDBBF3C37704B7348ULL,
			0x62DD74E4FC623AAAULL,
			0x71BAD9C08788D0F1ULL,
			0x400E6E4E8B961A5EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x882A701E1CB6B6F8ULL,
			0x4B6439AE68D5240FULL,
			0x630AF574A1BC891AULL,
			0x5BD53A80DA2E4B28ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE769E1E26D22925AULL,
			0xD6015D1E1D27AF44ULL,
			0x501B8A099479CC17ULL,
			0x0BB9B11AAF2CBE49ULL
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
			0xDD471596504EBB50ULL,
			0x63B4D7E3874A0CF9ULL,
			0x108AF20F0CE93347ULL,
			0x531B0A6A6BA222EFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3E4747F1840BE938ULL,
			0x3BC134C6CB894FAEULL,
			0xD319DDF0122E8FEBULL,
			0x5695005BB3F4854DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F0A6EC2E0C05C8FULL,
			0xCBF0B2117D25F41FULL,
			0x54ED36C40B14227BULL,
			0x67C87A74C6F34ED4ULL
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
			0x6A347769ECBB6AB0ULL,
			0x9BD874522FD9FE65ULL,
			0xEDF13DF82D759EA6ULL,
			0x4121A2F5375EA3A0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB6D01400355C6F10ULL,
			0x3398D3E814CCE3AFULL,
			0xB2B3A1602DD2D452ULL,
			0x51BA4067151DFFFCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBF0E84BB4B560AF0ULL,
			0x78C8A3821CC596F3ULL,
			0x9910EEA7A3E11D81ULL,
			0x6ED6A32F8BF181E8ULL
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
			0x5687A2FC00B47650ULL,
			0x8CB736713EE32A8DULL,
			0x4BEADD1F9D82D51CULL,
			0x4DA8269696826BF8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBDC602C42CA0F0D8ULL,
			0xABA4AF152B28DA69ULL,
			0x0A45E421A8B30063ULL,
			0x4A649255484E5ABFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3CD6E1D48B496306ULL,
			0x464DE499DC2C987DULL,
			0x3BC619F7A8569495ULL,
			0x274F1C1B6FCE2C57ULL
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
			0x7B5AC6EC0AB01EF0ULL,
			0xD97C7827C1B1F84AULL,
			0x013D1AD8A860627DULL,
			0x707BB31A6876376AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF4BCC22356690688ULL,
			0x4EEFA4B409E2401CULL,
			0x532B8F471209417AULL,
			0x43A9FEE55FD7EF28ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B54EEA22D69D852ULL,
			0x348177B0059E22CFULL,
			0x6EB547366A44B56DULL,
			0x77B9EC0C718AE99DULL
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
			0x8F869B1B88954898ULL,
			0x1E9039810520F8C3ULL,
			0x848B7631C46949FCULL,
			0x43BF32EA7CFA16C7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x42D5917C9DE61490ULL,
			0x0714D6FF8ACC0F9BULL,
			0x1FF1F24B4A31D9DCULL,
			0x717F96B338924F39ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B3CB03EB8D6BEF8ULL,
			0xBB287466A67398C4ULL,
			0x99C70C34E197BE01ULL,
			0x7D95EC7454CA8DDCULL
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
			0x58B83608176AD3C8ULL,
			0x81ACAA4295C27B2CULL,
			0x98EF726B30771337ULL,
			0x68D3D0F87F3FD07FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6B8AA06A4623DBD8ULL,
			0x31DF8E8F6ABFCF42ULL,
			0xAE021BB3ED31C847ULL,
			0x6534DB1D46E6C366ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x544DE159D28EFE9EULL,
			0x4235B1CC3ED3C877ULL,
			0x0D7E3D679A6C496BULL,
			0x6719CAC87C6D80A6ULL
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
			0xDFBCF398EC51ACC0ULL,
			0x84BBA9255FB39F91ULL,
			0xA8C2A213454A10EDULL,
			0x7CA3F7650AF2C456ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA35CF09F3C190FA0ULL,
			0x5A52133BBCFEEC68ULL,
			0x81ED6C6CB37B6474ULL,
			0x41A7AA91FCEC1791ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBECD9FFCDCBE7295ULL,
			0x26D2706550AB1B25ULL,
			0x95DE48B5C0D36EEEULL,
			0x5BD3F91E991F9BE3ULL
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
			0xD53D550FF6529958ULL,
			0x961B4D7966C8E11CULL,
			0xC97B810A7E97E4B1ULL,
			0x6C460794108CAE6EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x25CF8BBB38F6B9B8ULL,
			0x2BB1BA5022550335ULL,
			0x2120BDFF7EE51306ULL,
			0x490A5837987F2436ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C1075C2A9E9A845ULL,
			0x1E83A959C713B3E5ULL,
			0x49D83C223C5B612FULL,
			0x153D5218D07C8442ULL
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
			0xFAE2F6F27FB755F0ULL,
			0x9D09624F6927E9BCULL,
			0x9E776B9089F241F2ULL,
			0x422161158BEE1457ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0A05237FA7D362E0ULL,
			0xE0EA7FD6F2109927ULL,
			0x3D7EAD3193255622ULL,
			0x7056B7C2CFD9ABA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4D2E1C195F83A03FULL,
			0x216D121B8D3A7194ULL,
			0x30CB4B25B3063FC2ULL,
			0x6423B5122E4B0AF2ULL
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
			0x0C68ED87818C5018ULL,
			0x3708761A6E3144A2ULL,
			0xE6EA660A9C2EC406ULL,
			0x7FFC5287DC041AE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCEDB7C371B78F588ULL,
			0x2BEC06765A84D6CBULL,
			0x02F590B3335B2D2AULL,
			0x7E4E3B89029BB95BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6F51F7E120101F39ULL,
			0x29291F4118C61AE4ULL,
			0xA6EE7BE2081C6A92ULL,
			0x44EE06819DF761EEULL
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
			0xE3985E96DF05DAB0ULL,
			0xBC3BD469D7B2334DULL,
			0xF70B0022BF77DA61ULL,
			0x721EDA07BBFB4B2AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0048D0A4C8D848A0ULL,
			0xD664013E855004D9ULL,
			0xB9CF76C9BE85479CULL,
			0x5116DAB5206B4051ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x81B2C523EFFE39D7ULL,
			0x485E1F0E9600DEC5ULL,
			0x7D5CD8CBF13AC443ULL,
			0x3D9FBF8AC9B99EFBULL
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
			0x802F931B0C7EE698ULL,
			0x812798B26DB1F6FAULL,
			0xC84120D7A8409D70ULL,
			0x61CFD46FBD319A96ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA477E03051DA8CA0ULL,
			0xF59B9F570465B4EDULL,
			0xC309607154016CE0ULL,
			0x49C69ABCD274CFB4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD012EF164597D83BULL,
			0x0F3A821E6D078C89ULL,
			0x49BD3BA284FD981FULL,
			0x46C3EFC2556278DAULL
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
			0x9F8A6B1240621BC0ULL,
			0x69B239AB850DE677ULL,
			0xA6147A85E86D9125ULL,
			0x771D6D746FA1B047ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x92380EE7A647D848ULL,
			0x2BA31A440AD5B3F9ULL,
			0x1735D6B76559B796ULL,
			0x62BE82306B166534ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x174F7090A413BC06ULL,
			0x4D9D70AAA9146D16ULL,
			0x64AE9A0B6E0583C9ULL,
			0x72522612AFF8F8A1ULL
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
			0xD6D34037C4681A90ULL,
			0xCA3AAE15D1982A8EULL,
			0x44B7CFE20A39380EULL,
			0x6B7DC01E3BB67CFEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1BA100D81A968850ULL,
			0x20CDD25DD7AEE9DCULL,
			0xF5CE24516D97DCC0ULL,
			0x7A4B166AB0B24BAFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF73F57F3CA6781A9ULL,
			0x01A077BFE0A0A91CULL,
			0x21B9337382EE146DULL,
			0x67A83EC98B6EABA3ULL
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
			0xA18E0E118385B2D8ULL,
			0x78E98E04267E99A9ULL,
			0x14FF1FB2F821E546ULL,
			0x76A64F2A083B60DFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16E7BBD81A2F9D40ULL,
			0xFC550CB99F595EB3ULL,
			0x5D38EA490CC425CCULL,
			0x516EB4C412FD1142ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x56B662A7BBB7AB1FULL,
			0x5F2985D53B1EBA4BULL,
			0x8F509603F6ABE729ULL,
			0x16999763ACEAE13BULL
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
			0xBA4163EC041C8170ULL,
			0xCBEF816E3B2613E6ULL,
			0x21E2E82167CB175AULL,
			0x42511EE809E820BBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0D1FB7E73F7AC100ULL,
			0xD4669E34FA874F00ULL,
			0xB57AE44A5EEF44BCULL,
			0x49417EF51613C385ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2A76230A166FABCULL,
			0x1277AE69C77C55A7ULL,
			0xE431AFFA97441ED2ULL,
			0x509EE046A16B4F63ULL
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
			0xF178250959EE9EE8ULL,
			0x8AF872934B69C0E0ULL,
			0x4F164BA00C13A67BULL,
			0x744287DAFC33B70BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE6AA3F1C2BCE1858ULL,
			0x011BCFF1A17D9442ULL,
			0xD1D3C155CCDE7654ULL,
			0x741C0D7A6A10FF15ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2F2078384D48BA4ULL,
			0xBB07411CF2752A90ULL,
			0x566E51DEDD1AD593ULL,
			0x53D9F73D04BA2079ULL
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
			0x08433ACC78F47198ULL,
			0x1708F2E9077401F8ULL,
			0xA188CA283B8C27B6ULL,
			0x63B90A65D926C897ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA870FEE994290780ULL,
			0xCEC74BDADE3047EFULL,
			0x3E9B69F7879E5656ULL,
			0x4D597187663F9C21ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2194748A1812780CULL,
			0x10F6DE71DC682A39ULL,
			0x88CE2E4896FA7BBCULL,
			0x5896D7853C6A6E9FULL
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
			0x3611CC60DE183D10ULL,
			0x19CF4966A29CF26AULL,
			0x658E985D4DBBA88DULL,
			0x4AC83CE16E495951ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6A2B3B0506390708ULL,
			0x701447D777FE6FA3ULL,
			0xA1EAF994CE7C9616ULL,
			0x7DD56C5D3D4554DEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x173FE552FF8883F1ULL,
			0x7ED4C2F2C3688172ULL,
			0x802BD1C4E1A9AABDULL,
			0x286BC59FC275045BULL
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
			0xF86DF52514580D88ULL,
			0xCE6A8433204D8217ULL,
			0x3B6C058A6C1DEA4DULL,
			0x6A1C732BAB0A764DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54198A2B45128C48ULL,
			0x77D56E6EEAC4C3A6ULL,
			0xB17B536EB622B844ULL,
			0x5D3AAC8A53427FACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x720FFFB572433146ULL,
			0xB85D0647533ABC4EULL,
			0x87A1B004BFEFC709ULL,
			0x011C53222B569580ULL
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
			0x79F8E97363B258D8ULL,
			0x8629A4CAB2273EA7ULL,
			0x6DD22E6D7C2040F7ULL,
			0x5E5F1E55F57229F5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEB99E3DC2715058ULL,
			0x8BAFFE33FAC6F7F9ULL,
			0x6F45B64CF0379D69ULL,
			0x79186E76989AB7F5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD7F4CF24DBBBA309ULL,
			0xB920FC5D541FAF63ULL,
			0xFD572E8CAACDEFB0ULL,
			0x663F382036857953ULL
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
			0xE127D44F04155EC0ULL,
			0xD81783001B6024EBULL,
			0x0AF2CF3F699A1342ULL,
			0x5B8A4574F809F843ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAE7E34D78A2B1AD8ULL,
			0xC8D3892F46BB34C2ULL,
			0x29D3035862916BDEULL,
			0x7EE810845C3E35FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x42AD0F9E9F85740BULL,
			0x2471297E96E68384ULL,
			0x44CC38C10CFA536CULL,
			0x0FF613E93EBB7E62ULL
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
			0x14940F6328FEB080ULL,
			0x2E26DB5262B37680ULL,
			0xC43C66CD06BE3A5EULL,
			0x5E297181964E89AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB6829A4BE2D45C0ULL,
			0xA62E65A9A68353ECULL,
			0xB1349477D26D7E6DULL,
			0x7079264CA52DA221ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F96C9BFBA7E5553ULL,
			0x6EAF50D8A2906068ULL,
			0xF1DDE3F58A5029BDULL,
			0x4DE01A8378722B56ULL
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
			0x13F5D59A3DA868A0ULL,
			0x4D606C8FA4D596CAULL,
			0x4F97EBC718F434BCULL,
			0x463320FACA220DD6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7E8EB4DABAFE4F50ULL,
			0xD8B8C4D87B35D5BDULL,
			0xFC01974B26ACE2AFULL,
			0x40D70B9014DD932CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6D8BC137343670B1ULL,
			0x85BA2C1398EDD161ULL,
			0xED6B9B1AE2AC2A51ULL,
			0x65D55FA2460EB9CFULL
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
			0x36DEEFE526B743D0ULL,
			0x722631800BEB263AULL,
			0xB4CEA8DC92E4B3F4ULL,
			0x4F005DA46CB03D9AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA9A2F72F9D02EE8ULL,
			0xF83E3514E97F3263ULL,
			0x82E3740CDD566708ULL,
			0x6C27C7F7ADDF6379ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD590246C4268ACC0ULL,
			0x42A763427A328BCAULL,
			0xACD969A3127994BFULL,
			0x587E33A1D6EBF5A8ULL
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
			0xC1594C8674BFF1C8ULL,
			0xC323C73F49FEA46BULL,
			0x9DCD7CA3314F8D17ULL,
			0x4F6852E47DFA2D33ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x85833BA64F2FBFB8ULL,
			0x27E172EF648F031DULL,
			0x17A39C17165687E2ULL,
			0x6764350A7D828677ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE6E3AA3D246CFB2ULL,
			0x4CA15BAA13E4A39EULL,
			0xD923C7322B26C428ULL,
			0x47AFCACBF6CAD528ULL
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
			0xFDF1FD2118002718ULL,
			0xDF8CC7927DA55DCCULL,
			0x4DB869D3C87D9D17ULL,
			0x7F338EDAC2A4CE46ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x34CA6E24799D3EE8ULL,
			0x6005990C0D8F605CULL,
			0x7A336D1518CCD0CCULL,
			0x498D2EED22CD5FDCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAE96525C8F75081CULL,
			0xFDA8290318809FDCULL,
			0x002D6E5B33216BBFULL,
			0x44F0F8454D8161EEULL
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
			0xF466E8E650579E70ULL,
			0x544312DCE2E07269ULL,
			0xBAD3AD271848BAFDULL,
			0x77CFEF0BA793D258ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC1C9DFC13053C4D0ULL,
			0x40526E19244F1093ULL,
			0x4E16BD23C8B25864ULL,
			0x562B9F6B7D8D1667ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x524E9369B9B90BA1ULL,
			0x6BC522CCAD44F2B9ULL,
			0x2C2F11C7BF9203A5ULL,
			0x0AA25370F18994E6ULL
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
			0x65EA08D673F067D8ULL,
			0xCE3CA9C2C34A6600ULL,
			0x47515C159D6B5DCDULL,
			0x69D072D4EEF7FC04ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x886DC258C23C6220ULL,
			0x743BC8A04D41D27AULL,
			0x49E663E203F2037AULL,
			0x4C85A0EDFFAF5F34ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD0E1C3899BE1E65BULL,
			0xBD5F7788B039D214ULL,
			0xE558D436F3B4F345ULL,
			0x53CE22DDA1EFA3F6ULL
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
			0x303B01AB6555E4B0ULL,
			0x6EBB384D6CBDE7A7ULL,
			0x46D33E34670A4610ULL,
			0x67DD6D7602239B2BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE91EE757FB549FD8ULL,
			0x70FD9CFFEE6A4120ULL,
			0xC343E7070B0FECF2ULL,
			0x693668B1C68E0C4FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEC9E322DD4D2C002ULL,
			0x99E09202648BF39CULL,
			0x140A0739A32D4923ULL,
			0x6F674A9CD89C540DULL
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
			0xCFD8A278CD073300ULL,
			0x8F6B73270FEA7518ULL,
			0xFD9F3B1EC2B7F3A7ULL,
			0x5C5C7F02EF7237CDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCB450DB862D59F20ULL,
			0x0A2602452845D567ULL,
			0x433A396D39470708ULL,
			0x79ABA6DB5FFB46DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x14D3F1A389071233ULL,
			0xA7DEE0986720CC53ULL,
			0x28C012578B197921ULL,
			0x3341F32B6E0FEF67ULL
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
			0x9F70CE548939D500ULL,
			0xE8C7B0292282625EULL,
			0x7D2E0F75F8EF193CULL,
			0x6E147C748709D5FAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1EA31922F8F88EA0ULL,
			0xAB0E60F64675279CULL,
			0x74847124FA8CD04FULL,
			0x4A52E2778CC3B53FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE4DAACC93EDBD94EULL,
			0xE55556AE68107919ULL,
			0xADE1CB7E71EA0A3FULL,
			0x7781D4CE481A30AAULL
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
			0xF47F2726CDF21C10ULL,
			0x6C3924C2A7E85F62ULL,
			0xE22F1D9E30F4C696ULL,
			0x78858FF4980BDBB7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6CC08EB439493E70ULL,
			0x8EE966BF6DEBEB71ULL,
			0x446F883F265B0AB4ULL,
			0x40AF350AD5BA12B5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x76985769CFB29AFDULL,
			0xB48C245F3DD88CFCULL,
			0x86128F22F3DB7C5FULL,
			0x2B599DAEBEDD849BULL
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
			0x87E2D1F51AE57898ULL,
			0x4B04008D1B03B5DAULL,
			0x03E3F3022E369627ULL,
			0x5284831B90979FE9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x58EE53D08DBFCFD8ULL,
			0x3EE48665D85DC903ULL,
			0x568DD67E9F9AD8E6ULL,
			0x7EDA1DA6A2DE6DDFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x81E7CE62936C94F1ULL,
			0x947EE4BF871900DCULL,
			0x767C0F5584AB4D37ULL,
			0x613AD7FDC77F8FC9ULL
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
			0xA8F7F12DE7F818C8ULL,
			0xB960FB430DE8CB34ULL,
			0xFE7C89BB55B294CCULL,
			0x66995C52471348E8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBECE7508367C21F0ULL,
			0x6C959CD91DD33C4BULL,
			0x94F60DDCA3666110ULL,
			0x5D7C0289B59C9CBAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7D88013132EDAC05ULL,
			0x93B6E3A45C081274ULL,
			0x047895D473DE9C99ULL,
			0x53CD4919B5FAACA9ULL
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
			0x375ED706A3EAF300ULL,
			0x3D45015562EEA9C9ULL,
			0x1AA543A720AD0558ULL,
			0x525F099F0FE03DB1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x22740F653A130C38ULL,
			0xDDE63409076108CCULL,
			0x9C918D5F3AA3FA87ULL,
			0x6804430DD9B033DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6E40B637F3276CABULL,
			0xF7F51C255B81F4A6ULL,
			0x6E55DB5B56F9C79CULL,
			0x77D2DBE65BFE5325ULL
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
			0x96036F7B4AED2A68ULL,
			0xD17474014AE86B14ULL,
			0xC5940214A0790600ULL,
			0x473D095F8C4B1F03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x443CC62E38660480ULL,
			0x333AEE4AB63C1FE1ULL,
			0x8EFBECA8F19AE6B3ULL,
			0x7E64E534ED27FC97ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x636989A45DD81078ULL,
			0x772D2E5D7A7E52B1ULL,
			0x023316CC54A51E88ULL,
			0x76C8C53E0A983ECBULL
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
			0x351E0ECB08C2F948ULL,
			0xDE9140BECED6FA71ULL,
			0x6FB517448EE47361ULL,
			0x649691E6C2B6D815ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD60F8B5D7F7C9450ULL,
			0x1D2F066111445ACFULL,
			0xD4F154B72EDC7090ULL,
			0x5154B297B9703ED0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF65DDA6E4C3D0BE8ULL,
			0xEE761905FDC0E256ULL,
			0x9F4C45B366E6A02FULL,
			0x5914AF7A94C5E94EULL
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
			0x111112DC65596F90ULL,
			0x67C949CEA76E7B98ULL,
			0xE70484629005B345ULL,
			0x6B4139811785AED1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7C15468902C477B8ULL,
			0xA74A10FFE7D879E1ULL,
			0xB4F40715C606BC85ULL,
			0x61463FAC83964EC8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCBD3A1E0AC9A3A2DULL,
			0xDFD3107B99EE1B74ULL,
			0x74D718DC99872C43ULL,
			0x5AF66DC282597183ULL
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
			0x07FD1EE49A30D890ULL,
			0x8551A72DCEC71F7DULL,
			0x8D93EE00B10CBFA7ULL,
			0x73166360BBD31A5FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4DEFD317F0D83BE8ULL,
			0xCAADFD7381A0EF36ULL,
			0x646D5D495B82BDCBULL,
			0x62A78B74586F4958ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE089F22955E4EFAULL,
			0xC2ED9653A8CEB417ULL,
			0xE7EBA385DCBEC71CULL,
			0x76F27F423BF47EE6ULL
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
			0xD625448B766E8848ULL,
			0xEF929DDEC82424D6ULL,
			0x325CF679516CF32DULL,
			0x5CBC7A73C24592DFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB2EFDCC3B8E92FA8ULL,
			0x381456A36AB5EA6FULL,
			0x4F9F8B4B9FFC8CA0ULL,
			0x6932C14CF7D77A68ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A9D4AFBD5E5DBA0ULL,
			0xAE7D3865BF793F3EULL,
			0x5BB789AEBD36A13AULL,
			0x2D9948CD1862EF3BULL
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
			0xA1BA119D63707A50ULL,
			0x0C785A17C143EDC1ULL,
			0x8D06D03C7B307406ULL,
			0x5D1A5D379D374955ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x99ED0FE24E74F9B8ULL,
			0x8917BDACA85C89B5ULL,
			0xC3196C11F9982A8EULL,
			0x53DADAF82DCCD5ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x271D733D4CE80689ULL,
			0x921ECAA43B53459AULL,
			0x543E9DFC6F73B7FDULL,
			0x2D5074CB48E36F8DULL
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
			0x96A41D6AE991BA20ULL,
			0x85DE1D2D40B554B6ULL,
			0x5CDC7AFEFF236382ULL,
			0x5F262E9600B406C9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0DF23E1DA45E7338ULL,
			0x3446708F4282A48FULL,
			0x5E778AF4A1980F66ULL,
			0x5EBA422B4E3B4B37ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x52820642687C830BULL,
			0xA4734A0CEEC7D18CULL,
			0xB9745C756A5E403FULL,
			0x0983F032820DDE92ULL
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
			0xEC454E3AC91ADF58ULL,
			0x41E1DF787039520FULL,
			0xE8D1B114D9F19E5AULL,
			0x458CD668736DF3D4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA8436AC300F43ED8ULL,
			0xEB0A99CB7F41FAFCULL,
			0xC4544391B43138ABULL,
			0x4C99D1B87130BCADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43E220E43F1FDC56ULL,
			0x5D955042A53EFDB8ULL,
			0xC5397EDB1A37AE60ULL,
			0x224919B893AA4B21ULL
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
			0x05AA865A55BABF98ULL,
			0x65710BE403F6EF58ULL,
			0xA0E6457468A2F1EBULL,
			0x50C94027C805AB34ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC227BBEF909CB348ULL,
			0x5BD6E49043B6B00DULL,
			0x3A2E36303D6D7A94ULL,
			0x4A99D68EDCEB4498ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0998A643376CA579ULL,
			0x094679AA04F76E94ULL,
			0xDD46CFA1C65CE547ULL,
			0x7E268EA3431AECD0ULL
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
			0xDE2531C6EDFCFD18ULL,
			0xBBB90BEFEFFC1ED4ULL,
			0x1DC9F52F950A57A9ULL,
			0x5EA886501F06F9B1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4AD627B20DB39158ULL,
			0x2600CF6EED91677BULL,
			0xD47B585BED943EA7ULL,
			0x78BFC7B1B932C9B6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2FE885304F1D7AABULL,
			0xFE887E41C7CAD36AULL,
			0x6ED335D23C6FF760ULL,
			0x7839CE4D466F7B92ULL
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
			0xC4812764381F3CF0ULL,
			0x7599ABEC97E18366ULL,
			0x44D014084435A5C7ULL,
			0x7D72A3F044FDC091ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBA85567DAC792178ULL,
			0xD8A38BC3C9773843ULL,
			0x70919BBDB0007F91ULL,
			0x4DDAA70EEFFF952DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB1AC981261B538F8ULL,
			0x0200B28C4B42880AULL,
			0x52263DCAD28C3638ULL,
			0x588BB4CF899D3552ULL
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
			0x8A5570DA055A1508ULL,
			0x4FD2B537BD1C271AULL,
			0xDD85DBEBB1F66954ULL,
			0x46BFB311432AAF33ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x556A28D27C2DA4F0ULL,
			0x6CC480209629C16AULL,
			0x9282030409E614DAULL,
			0x5D23010C8E607804ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF19E5F9EC8569150ULL,
			0xC6D039892CBCD744ULL,
			0xF0FDB17B38AA3B93ULL,
			0x1CFC8018D1EF2642ULL
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
			0x650681287E7C9168ULL,
			0x608A42D88B2BE437ULL,
			0xA0F188A6C6ABE35BULL,
			0x61FB5695C65D1E78ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2E9FFB98353D3FE8ULL,
			0x9E763D9700789FDBULL,
			0x71A4A8C2BAB75968ULL,
			0x62981B8551BD50ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2BBF8AB1AC1F7477ULL,
			0x584B822E711D5444ULL,
			0xCFC447C683851EE2ULL,
			0x382594C37ADB15F2ULL
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
			0xCA50AE2B1AF03818ULL,
			0x7ED382114EB8839CULL,
			0x30451B37DDE575F7ULL,
			0x4DE1689587AB6107ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC2B79CD661DA3BC0ULL,
			0x15579AB09B2C79AEULL,
			0x21F11A51268F2245ULL,
			0x5AE39FB3F3BC5BE5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDBC49EA7B5FF26EAULL,
			0xEB3CE58A87B65AD3ULL,
			0xB3F0248D9F3C16D6ULL,
			0x5C2621EEA72AE501ULL
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
			0xE22D2A90DE335C00ULL,
			0xE26BFF3BBD8145E9ULL,
			0x988EB7121E7BB42CULL,
			0x650C7A4639CBED37ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4F9ED378AEF90230ULL,
			0x8049C75A3B1F84EEULL,
			0xB7122B85A92ACCCBULL,
			0x4E6F0DC51B553BBBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x54BC69037013498AULL,
			0x0D7F037387108F1EULL,
			0x841754ABBC2ACD94ULL,
			0x4C3E535D6FB21947ULL
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
			0x70A1A7BEDF311B08ULL,
			0xA25DD6EA69D45D0DULL,
			0xD367BA539F88CDFFULL,
			0x69313DFEA4BA2681ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x31A7BBAEDE003B00ULL,
			0xCE1553F5DF9DBD79ULL,
			0xF32996C930843CB9ULL,
			0x55A74FCA5636B4DBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFD0D0EE8E0170D02ULL,
			0xA2086BAC6495C14FULL,
			0xB2F9004996467F89ULL,
			0x41BCF2FE2D4B0F6EULL
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
			0x2B580215BAD7E2B0ULL,
			0xDDF5D0DD71A8A2E8ULL,
			0x84A362278E84A19CULL,
			0x4C748200D3B97BD7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x91BEEAA1F181F3F0ULL,
			0xB93B98C3126F2E86ULL,
			0x766E0C36C8DF30D2ULL,
			0x45DAA5E3BF78268EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB6A6C7A2E4DB9D04ULL,
			0x0B2903264791B264ULL,
			0xF6667C575B7B7AA5ULL,
			0x76F81C6E26901C66ULL
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
			0x62695742EFF44340ULL,
			0xAE0AAF7AB3DEF2C1ULL,
			0x8384C621196E3B71ULL,
			0x6E8272B07D180020ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6A44915712ACA870ULL,
			0xA78C36F284E1AB56ULL,
			0x835DF87645079A99ULL,
			0x4104FEA831DC2067ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x840826FFFA6640F2ULL,
			0x8E8AD950313BEF10ULL,
			0x543BD3136C39A22AULL,
			0x6F1E668D96387003ULL
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
			0xD11332E0CF524A20ULL,
			0x9CAEA49529E5BBA5ULL,
			0x0A2ECCA8D1A4B149ULL,
			0x6EA96EFA0468E94DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x412E5D581A742680ULL,
			0x5868119C6C316D02ULL,
			0x379921612960461BULL,
			0x5C265399627BE568ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4C4F7A72E39BC705ULL,
			0xAC0FBB767D94D2B3ULL,
			0xB3B63FAC04897FBCULL,
			0x439ECD76ADE81FDFULL
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
			0x1F9153D97AABB3D8ULL,
			0x452BF602EB99C913ULL,
			0x09F7C33D754F38FEULL,
			0x7F92E6B170E2920EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB855E78BD5206E00ULL,
			0x1421F725F1A9896CULL,
			0xB893D825ABC4FE66ULL,
			0x5CD6A982EA940480ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7CB6627B609C2B7BULL,
			0x22A0F772494387EBULL,
			0x506555C6E62466D9ULL,
			0x56D69BFF8F2385E7ULL
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
			0x9524C96E6DB41718ULL,
			0x0D5C2C4FB39B6951ULL,
			0xA364803460F70619ULL,
			0x7118D5327C62A257ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x85624D25E601DB08ULL,
			0x71AF298BD1619154ULL,
			0x17CAD78795F9BEBCULL,
			0x5FDA796FD05F52B7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9FBD715322678781ULL,
			0xF063EDC09DAA7A54ULL,
			0xEFE8E2487AE40392ULL,
			0x5B93798ADBD85E6DULL
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
			0x0BE6E43ECAFF2E50ULL,
			0x3A7688EE7F81855BULL,
			0xBAA9723F3E2CE07AULL,
			0x47B46984143A251BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x06564E91A28BF330ULL,
			0xF92BA86BE9A9034AULL,
			0xC2EEF6F4C0F844A1ULL,
			0x7FCE1B4B45A984F2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2E442185824ABD2DULL,
			0x750CA042B7EC094DULL,
			0x1827EF05E3CC19A4ULL,
			0x0FCCBB844FB39A9CULL
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
			0x7B48F0E4A6B71478ULL,
			0xF9ECCF2ECD822419ULL,
			0x8BCA96586EAD7088ULL,
			0x5BB3CE9F7E2B7C84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA6904620B649D320ULL,
			0x1EDA6A30AF78EB7FULL,
			0x688B8F5FDA456202ULL,
			0x6741985393923D45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x80FA72D88A4FD254ULL,
			0x9A631A979A27C5A2ULL,
			0x6F9B85AB1A0E2494ULL,
			0x56B4D00C967E21E0ULL
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
			0xB1595D5E679D7DA0ULL,
			0xDD979B97D4F64AA6ULL,
			0xC744FA16A184373DULL,
			0x5E8149584D169E67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4567109017C61B30ULL,
			0x4D06E53590AF12A6ULL,
			0xB2471D876C48AAC8ULL,
			0x5C6D6818B7D05405ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE281BF3E32BB805ULL,
			0xF7AD425D69A869CCULL,
			0x0693A7B68B31F86AULL,
			0x2D465EED074D606BULL
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
			0xFE0F35DE9CC36C20ULL,
			0xC1F1F6CA5357162BULL,
			0x4B6C1F1AF70A3FABULL,
			0x517760A537918434ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x128D26AA08340078ULL,
			0x04060C45D1A1E6CBULL,
			0x3BA554A887B76D76ULL,
			0x7C7515A60F87A38CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE082F3F4889FC7FAULL,
			0xBD73ED5601B988B1ULL,
			0xCE5E063E1D7F923EULL,
			0x53A0A51E2CE95E3AULL
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
			0x0C75903447DB5C90ULL,
			0xA52393A8B8849E3CULL,
			0x4775E831281014E2ULL,
			0x73407EB4E730A3F4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E3041E18708AAD0ULL,
			0x9A60CBAD01AAD458ULL,
			0xDB367786A4B4080FULL,
			0x53B7BA9732EC057DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3DDD89B3AC51D9EEULL,
			0x071893BE20D2A417ULL,
			0x23483D822FB03AC1ULL,
			0x5F516A215FC042D0ULL
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
			0x66489A8EC9F48D00ULL,
			0xEEFBA8A7B494C3E0ULL,
			0x7F0C3D67A1FFB996ULL,
			0x4C447F451F5F128BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x953CCEC19A1C4630ULL,
			0x2457E45A6F3C762CULL,
			0xB77595A4CE83F1C6ULL,
			0x4DEBF5DA6055B3D3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5551648F2B56B399ULL,
			0x5B9E9E5A3150C93BULL,
			0x2C07AFD663FAF88BULL,
			0x248CAE656446F642ULL
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
			0x46552AA85C3798E0ULL,
			0x0CAE166D008FD44EULL,
			0x9CB44D2AF4B9AB12ULL,
			0x533D6E979E1B3F41ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFAFD26590585E850ULL,
			0x7E3053AA9E26ACAFULL,
			0x6514A70C5C799A8EULL,
			0x68BF90AAB23DC47FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7325000FC29BA106ULL,
			0x01F4BE4FD1BC7D18ULL,
			0x975D658DCBF41CD7ULL,
			0x3D9242384E5713F4ULL
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
			0xE32BDEE54FAF48F0ULL,
			0x1188659F3DDE0292ULL,
			0xBE255C9E5E687C31ULL,
			0x6955904BA6829DCDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x690B4B1B4D5BD718ULL,
			0xF610CDE57A76AB79ULL,
			0x61C6AF2BB6185F55ULL,
			0x5E8610D0265F3606ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCA11288247F70F55ULL,
			0x37071B33C6426260ULL,
			0x024E0270AF658BF5ULL,
			0x2D26BE910DB04316ULL
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
			0x1503F08A6CAD1468ULL,
			0x4F2881E9BCD524FFULL,
			0x373005982448D5ABULL,
			0x716D73D5DB294CF4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x530B6C8851F5F1F8ULL,
			0x2C3E8131BAAD767AULL,
			0x0DD1727F987FBD16ULL,
			0x7671B3A9AB4A0B45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFC96922E0AE88BC3ULL,
			0x08A89B2BF346092DULL,
			0x46C717C97629906EULL,
			0x3D99D91E30E8FF68ULL
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
			0x7A4FE97713DAF068ULL,
			0x6F7D47DDA039FBBDULL,
			0x9386489383B71857ULL,
			0x432DD7E997772313ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEC8100C952725A8ULL,
			0xBFAE1C998CD778D6ULL,
			0x68E7909535436E5FULL,
			0x62B8BB18D172DA0EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD08B6F15A1A92973ULL,
			0x94312D40581A0287ULL,
			0xC307B70F80ACA233ULL,
			0x70F3C0251EF677B6ULL
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
			0x394309F784BAA738ULL,
			0x522BB2825FC4AAF6ULL,
			0x965D701B3E2E5C44ULL,
			0x52E8A176328A5586ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAAD621BA4527EA00ULL,
			0xBEED83BEB5B6A844ULL,
			0xC873712D117F7437ULL,
			0x480B32263A8B9CE0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C2C5AF679AB7D3EULL,
			0xA5CD189A9AE7AE3FULL,
			0xCE70D9F54354B39FULL,
			0x1BB7A3EC268F28E6ULL
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
			0x5CA70B6E02DB24A8ULL,
			0xECFD88189F832F5FULL,
			0xBE3ABDBD6310DFFBULL,
			0x4160FE0E84E34443ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5D90AC0330F39288ULL,
			0xE1F9664ECE4A666BULL,
			0x2851DE482B4B20D4ULL,
			0x5C15A7526729D911ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF641B354529D5243ULL,
			0xD06FFCD265B913E8ULL,
			0x25BBDD76A052EB30ULL,
			0x1C40712F5C0A1F43ULL
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
			0x4408CFA3A0129270ULL,
			0x2ADF96062DA2EE9EULL,
			0x650762A73C82776DULL,
			0x45229CB178C1C277ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC5716E683B9BA550ULL,
			0xE46F980FF19714ADULL,
			0xBF0AECDAC99C0118ULL,
			0x6C0A0275603FDBE3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA124437D61244D2ULL,
			0x9962D71F0B176553ULL,
			0xF1368F66BEB60C34ULL,
			0x5FEA0063318B4A6BULL
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
			0xD6C103CAE56CE2F0ULL,
			0x30761A6EEEDE4AA6ULL,
			0x5F0DD9F62DB4EE0CULL,
			0x58FA2A5FE3E9C5C0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF33A49DF32D95690ULL,
			0x0A6F791AF7760F50ULL,
			0x3452C1FF18E6470CULL,
			0x536A3B50389B36EAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF93457F68D81F6DEULL,
			0x25BE05ACCD47D8A0ULL,
			0xFB405E76EB8105AEULL,
			0x5BABE10BC7F19DA7ULL
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
			0xC3D970A6BF088C38ULL,
			0xB647CF9D8F74BF7CULL,
			0x260CCFBA2E2CF8AAULL,
			0x6A5D1EE4AD8F7F50ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE48B34745FD5CAA8ULL,
			0xDE0ABEB02A255A9AULL,
			0xDCCCD27F4E02D606ULL,
			0x6FC98F218AEF4099ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7DD8556D59F3E4FDULL,
			0xE57F00129511DEE0ULL,
			0xD71FECBD4622EBDEULL,
			0x482AFCF50D175ED0ULL
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
			0xB25A6F9ABA545938ULL,
			0x5FD04EA2C47F141FULL,
			0x138D8C53EF565836ULL,
			0x49A2A9D2FD6008BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3ADC785C4574B2B8ULL,
			0xCCE86754809C5056ULL,
			0x7A4D544A80BFBC75ULL,
			0x4E7C6D0231393C0DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x26C0A1594B524A70ULL,
			0xE888C74FD72EB972ULL,
			0xC2482DBC77BB1974ULL,
			0x1BE43776587F4AEAULL
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
			0x92844A1272D70498ULL,
			0xBEB020791CCC9731ULL,
			0xDE9C357D7911FFDAULL,
			0x7CD78F1AF8AA0383ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1FEFCD3603B2FC38ULL,
			0x192B0C6A8A6D0C10ULL,
			0x17A95407147156F5ULL,
			0x72BE7C9A3374B5A0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFF65796638D22503ULL,
			0x4C9F7A1F545CA9B6ULL,
			0x473B23024DE22EE6ULL,
			0x5D6CF7D49EEC4C10ULL
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
			0xD2E7DD2B64470B30ULL,
			0x752952B3C414D575ULL,
			0x4126426766CEE38DULL,
			0x76931F5B691E7496ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4F828290937AA020ULL,
			0x02F170889A012BEAULL,
			0x5CA10329D20582B2ULL,
			0x78F591693DF29D08ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC263B16EEE5C292BULL,
			0xC5ECD22DD10BE49AULL,
			0xED1A7EA90B779F7FULL,
			0x45794B6558B5D322ULL
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
			0x6B0AE486D74920D0ULL,
			0xF4E4A3F52AED2B99ULL,
			0x256A83AF4120344DULL,
			0x68E8A0E9B086BD71ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C5BA2AC82867A88ULL,
			0xE94E931E9B055F90ULL,
			0x74A33F129A3B9204ULL,
			0x5E6752B6E785A74FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2C63BCC3DAB754C1ULL,
			0x45093E5853E5D3BAULL,
			0x475027ED3C73BF26ULL,
			0x0D530E61ABD29501ULL
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
			0xAD111FB6319615B8ULL,
			0xF20864E11985D643ULL,
			0x484A50A56F86E8C8ULL,
			0x67257940E46DFEB4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBFD44AEBAAE4D008ULL,
			0x91A467CE6B89E6E5ULL,
			0x5A05506F1AB7E9C3ULL,
			0x67411A708D6F9CEEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x50C9E267A4681042ULL,
			0x0869F4AC0E71E1ADULL,
			0x95B6E3C9E18B6192ULL,
			0x5266286AFE6F6A13ULL
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
			0x539F24CDFC6D06F8ULL,
			0x278CF110589BB726ULL,
			0xFA36433CF0A8006CULL,
			0x72DD5CCAF904E597ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x06A0FD4B78BDB698ULL,
			0x25DFC1AB1C482D6AULL,
			0x625BFBD5585EFDC4ULL,
			0x5800B9996C3F2D64ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0CE219D8B21705ABULL,
			0x4725505930C890D0ULL,
			0x44F03E0A5199BEFFULL,
			0x714C3BD13628C471ULL
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
			0x3925CEDE2E179450ULL,
			0x301C72ADF41AA43FULL,
			0x0FB06F4A4DEC21FEULL,
			0x7620B0ECC07002E9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB74CE8140AF94178ULL,
			0xDD1491DBC76DE6B9ULL,
			0xA8D9EBFCC7E45E18ULL,
			0x69AF0584B775F1A7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCDE728DF2488B3FCULL,
			0xC6C62DFAC70B9ADBULL,
			0xC6480ECA7AE76D0FULL,
			0x086731197F287473ULL
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
			0x52F19DE22BDDB4F0ULL,
			0xAE1DA8EE2181A07AULL,
			0x712623112A58366BULL,
			0x6A1F66448ADD5FC9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x28D65B7AFFAA4FE0ULL,
			0x0228E66CED39BD1AULL,
			0x3DD3163E244F66ADULL,
			0x77BC105F3F3E32EDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x56DB063985D3EDA6ULL,
			0x147778D271567AD6ULL,
			0x45B51A78DE257EF9ULL,
			0x5729151C4C994858ULL
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
			0x41449808FBAA0340ULL,
			0xA43FE5E3A0040F9EULL,
			0x389A6E49168B6FE1ULL,
			0x4417E3CAE2D0D332ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF9F0D28D79E3E338ULL,
			0xB72B7980D64EAD19ULL,
			0x6995E4B051EF45FCULL,
			0x75A00574A99873BCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE59B6D77DC78825AULL,
			0xED06F6A76C9B835DULL,
			0x62328FCE9FD293A0ULL,
			0x682346C5446349F5ULL
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
			0xD233AE0D6F64EBE8ULL,
			0x8F38332269F96B04ULL,
			0x2EBB95CD14739971ULL,
			0x6A2D09B64D348711ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5A2EFF271183A6E8ULL,
			0x32E27846BA55437AULL,
			0x77FB2E437E4A3B2BULL,
			0x6C2A0C3B4F797F40ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x096274D2B76A563CULL,
			0xA16FD44A39C302EDULL,
			0x0FE7878C78483470ULL,
			0x2F0FB562CA585EF1ULL
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
			0x89E3F776D7AB7F08ULL,
			0x9F893B86AD7AFDD8ULL,
			0x5BDCEE786E43BFE5ULL,
			0x7D132D1D5C71DD57ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC8B6012F5872BC8ULL,
			0xA5307025A25F562BULL,
			0xCFD4C1B8F80E93EAULL,
			0x77CA72A5977D7694ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7F1124CDE4847BF1ULL,
			0x4D8860A7C6A7708DULL,
			0xF95717AC147593A4ULL,
			0x4FC471EA53731CC7ULL
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
			0x89D0FFCEF9B8BD80ULL,
			0x706556B4B652B2A7ULL,
			0x6B6A7E07B54BE8B9ULL,
			0x73099120345FAE53ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD4891C2EFD743F18ULL,
			0xDDF7DDE8F5A2D012ULL,
			0xAAF2BFE6A0F4F49AULL,
			0x4BDD1EFD475C957EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x749C7EEB186A339BULL,
			0x4C5D4914A244D5EBULL,
			0xAAEA91B3DD3796AEULL,
			0x158F3D56AD2B6F93ULL
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
			0xA3E960F0ACF8C170ULL,
			0x01EBCE057A3C4E86ULL,
			0x6B05569FB63F2215ULL,
			0x77F2289F75D248F6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8452A079794BDCD8ULL,
			0x44477ECC88E18ADAULL,
			0x363BDC918C8EF072ULL,
			0x410B79172007647BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC2BD4C86F52FACD2ULL,
			0x30CC88F35BA15AE4ULL,
			0x68DA02F2330CCCEBULL,
			0x1C7A2482E2482AFEULL
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
			0xB8EE96FE33042840ULL,
			0xCFCA38C6DAFA054FULL,
			0x75CABD6F35FBE2D1ULL,
			0x5278941E57E40144ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB8C7CA6C39DC4560ULL,
			0xE8B847B8729AF916ULL,
			0x452A1F922AEE2356ULL,
			0x6F31F069B116332AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6F3C3C0E9F4E7ED8ULL,
			0xE0B4511B719C93A4ULL,
			0xBA8468E0BF8F640BULL,
			0x4C8E64877E2EFF6BULL
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
			0xA5B03F2BF18D8008ULL,
			0x7A5F456CC37B0BDFULL,
			0xD3CFF025BD97DB2CULL,
			0x4E80B06AD2CEDF4EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x883A9B7B801C36C8ULL,
			0x3FAFDFD1F058CDE8ULL,
			0x5F97BDDF6B003E66ULL,
			0x445A3DA43547FA9EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x75B6725EF9C84314ULL,
			0xBAAC79DA5C9CED7EULL,
			0x866EB2D9ADB1F4B8ULL,
			0x6281B1FB03D4422AULL
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
			0x30AA322962C60680ULL,
			0xFA3DB82CB7B3F190ULL,
			0xA6722C5CD18C11D1ULL,
			0x5C96AC137FF39BE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6272062CCF58A8F0ULL,
			0x6B4F75F4986C2297ULL,
			0x168DA18012A40A0DULL,
			0x5C02EE756F2D31C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9AA5FC10B36F211AULL,
			0x2F07CDDA218FFC41ULL,
			0xC51CDD40D88F9EE8ULL,
			0x4D68F9222358310AULL
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
			0xAD1CAA97C574E6F8ULL,
			0xD5C6148E26F4F632ULL,
			0x90F6E43A28EB25EBULL,
			0x45E7746BDBCBF11DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2B0A20ED0A714E10ULL,
			0xA18FE8B174B8EA6FULL,
			0xEA7B0E2D4F54BD6AULL,
			0x7751FC0552C65946ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x318CAA839EA4DE86ULL,
			0x6914C5E4C05BF3BDULL,
			0x5F17EFAAA38CCDD3ULL,
			0x16FFF624D97EE3ECULL
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
			0x1210FF9BD2445160ULL,
			0x324EBAEE1EF3EE94ULL,
			0xB936698DE6365DE6ULL,
			0x47F1F5B0E6FA48C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA1CDBCBAE0144D08ULL,
			0x1609B258E860B88BULL,
			0x85856AF97A779CB5ULL,
			0x4A7221E42E685E9DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x22B8D7DB54005CF9ULL,
			0x46C635F894A141A5ULL,
			0x73605224621C4E5EULL,
			0x559D38188685E7FFULL
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
			0x3A04F9AECA7B2248ULL,
			0xA9AFD1BC42C71F25ULL,
			0x0F7398E5A7D2D976ULL,
			0x7DBCFAE3A65B4C89ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4BB9008A6066EFA0ULL,
			0x9EC6C4DAC6BACEB5ULL,
			0x4ADE6E8203EC84BEULL,
			0x5E141237BC186B1EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47103D01C05D25A1ULL,
			0xBAFE9FC0C50D6753ULL,
			0x79F6594F89188BEFULL,
			0x4CC6982AA90DEF5AULL
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
			0xB859C3D946A68338ULL,
			0x91D6F846F4DC3E89ULL,
			0x2CAC7D437507FDCBULL,
			0x6B357A36599142D7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7E982598E53EF08ULL,
			0xDF7863578366B141ULL,
			0xC2EC03AB0413EF0CULL,
			0x4E9BB933D255E27DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8823E616B17D7368ULL,
			0xCD29612E78A883A0ULL,
			0xDE8326228D611572ULL,
			0x7905B670BEB930EFULL
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
			0x9ED2362D76F8DD38ULL,
			0x171A70DAEFE05F76ULL,
			0x3015A6BA822DDB8EULL,
			0x46F2BDA792D399F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE03E7585996D8A90ULL,
			0x222615BF090A6A65ULL,
			0xD1632EA739FB4549ULL,
			0x7F7D9C4ACD37BFA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF673DB97A63745EEULL,
			0x8B1CB676639BE7CEULL,
			0x598BA1B9B6810415ULL,
			0x2B6507FF3CCAB72BULL
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
			0xA793505ADAC20708ULL,
			0x313A1563339E0627ULL,
			0x560B99D428220251ULL,
			0x4A4354618FAED9DFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x77CA08A32948A840ULL,
			0x4D9E75A80B430DC6ULL,
			0xF3625BAA5DFFCD9DULL,
			0x5A8EB337BEA3163EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1B649C2C7D1BCCAAULL,
			0x8A9099AE7202F451ULL,
			0xDD44BA224E35F993ULL,
			0x4E619C0A10A82B7BULL
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
			0xABCA7E0BE02BD3F0ULL,
			0x3F2CFE9A1E690D54ULL,
			0x67D4B5420DB43DAFULL,
			0x71841DBF2327DF8BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16DE94E647D6A0E0ULL,
			0xCEE55530CC4164B2ULL,
			0xD0FBF53D5A009285ULL,
			0x736E3B9A76CE6644ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x615172D90B0E3888ULL,
			0x56989488B9C3CD05ULL,
			0x8DDE067F8B3B7A85ULL,
			0x37CE0764A6DF23CCULL
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
			0x36C535B9B379CE68ULL,
			0x9B592BABEF3F9E49ULL,
			0x3F044C8914223E03ULL,
			0x46D039EB31AAD47EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAEF68757C17B1158ULL,
			0x9CA6EAB8F108BCDFULL,
			0xC21D5A2F7D9B1943ULL,
			0x66651E25D94C574CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA7A4B8A22AC18B06ULL,
			0xA2C16E7C11BC7A4AULL,
			0x004770C629B79BFCULL,
			0x10F1725997C4CE2AULL
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
			0x0AF4B861405B2968ULL,
			0xC46A00B21617A81AULL,
			0xC6C2736B49064D86ULL,
			0x5B67979811A799CBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE57BB6D5516730D8ULL,
			0x12C90CEFA3E88F6CULL,
			0xC6C3C21E8F253B3CULL,
			0x68B69BB78EDBE9E6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0F90D4FB38FE5FC1ULL,
			0x5311E286C33DCF66ULL,
			0x98919B384ED1FA7CULL,
			0x1587662AC965A9A5ULL
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
			0x9207F3A391A0A810ULL,
			0x69F240F3E9C46D5AULL,
			0x735626C766064E52ULL,
			0x568281D45531F485ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD6B45DEDA8D4F5E8ULL,
			0x1C9971886CE1AEC2ULL,
			0x3FFBD7726BAED2A3ULL,
			0x78DE38A4119046B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0C0A09884A24224ULL,
			0x12E58EA9EBFF6CF4ULL,
			0x2062A5A9B41B30D3ULL,
			0x7F469CC560DC851CULL
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
			0xB9C02FBB25C38E10ULL,
			0xBE08961AADA28EAFULL,
			0xA03326ACD34A451EULL,
			0x5B546B059B28A0ACULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD77362487FA17990ULL,
			0xB0DF88420F24F657ULL,
			0xE8F80262BFF28D9EULL,
			0x41869ACF53DD0BE8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x137D34097E4DDDBAULL,
			0x318503278B4AFF70ULL,
			0x195176184B0A4FBFULL,
			0x6895D00E8F9BCB7FULL
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
			0xC412DEB8CDC80D60ULL,
			0xC99D0CC8E54C237DULL,
			0x3854878D47B0B477ULL,
			0x5F6834881ADA7D43ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9794023A97E2DB50ULL,
			0x4B4F5BA461CF21D1ULL,
			0x5509104F1C5BE9FAULL,
			0x417C06332C8DE445ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A8C21BCD77A3AC4ULL,
			0x6DBA88A1F0E08ABEULL,
			0x2FD8F4ABEA4C874DULL,
			0x1CD7ECAFB215F0CFULL
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
			0x1754E59EEB3B6598ULL,
			0x3E6196A2BDA7DC46ULL,
			0xAF1C8E58EDADEA28ULL,
			0x6D028D892C540CFFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5C1873609FEF5078ULL,
			0x03B950995DA7191FULL,
			0x047F07D11C01F0A1ULL,
			0x658A1A2FAAC54242ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x081561D448A462EFULL,
			0xD579AF80D44A4FEEULL,
			0x115648CBF5DF1AF3ULL,
			0x1F885297C6D49C6AULL
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
			0x9897B2E5146FD9C8ULL,
			0xAA3D0A2079FA2EC0ULL,
			0x5F2D5B83C30D65EDULL,
			0x712377D09B32750CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBE766935DF52B3B8ULL,
			0xF8BD9094AF35EE43ULL,
			0xF22F37115B3ABE72ULL,
			0x4F005742033589E1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2E2D3846B63B34CULL,
			0xC4A59281C16E0F0FULL,
			0x9793C8FD86C5CA27ULL,
			0x23F6C1B7B12DB51FULL
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
			0xC3347E2DD0E9DDF8ULL,
			0x3661F766222860FEULL,
			0x12F65D458B35C641ULL,
			0x656B4706741B57B5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x09726D551EFBB7D0ULL,
			0xC2854128DF0B8361ULL,
			0x4BC4703EE985B416ULL,
			0x5169010210D4650BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x467F56DEEA58A2C0ULL,
			0x59E539503007B759ULL,
			0xCA5E828014B555C1ULL,
			0x0F586DA02B30E961ULL
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
			0x92E16F7FAC8D2D28ULL,
			0xD66AD4663FF39B4DULL,
			0x523336637BCE78C1ULL,
			0x4EFB7367E4E33812ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C6866F8CBD7E768ULL,
			0xE603C5CE40CF5942ULL,
			0x1BE7304DE769D2D8ULL,
			0x606631BFB0681E2BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x44F72D52434E0A88ULL,
			0x2CD91F3F558FA4B7ULL,
			0x35FABDE4D604C523ULL,
			0x18E8940B17355B72ULL
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
			0xA6D6FB9063078D68ULL,
			0x37863F88A8BC4426ULL,
			0xFE8CBADFF15F9E3BULL,
			0x6ACA89F4ECDE19F8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6B8C3DFFA15001F8ULL,
			0x18089469C28D803FULL,
			0x99B9E5E3E89F610BULL,
			0x6B44D018D0853354ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC8C44D0FED3EDCF4ULL,
			0xEEC20AE6E3BBB1A0ULL,
			0xF21A226F0B061727ULL,
			0x762C047D4DB23065ULL
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
			0x4CAC9FECF872DC10ULL,
			0x0E7CD66E6AF83A34ULL,
			0xE4C9A11B22F5921CULL,
			0x51FB768565658BFCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x913BAF1EC7AECC70ULL,
			0xE1EE1D7C5EA1D8A3ULL,
			0x71050D146414E32DULL,
			0x714C7AEE07257313ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x761F3C0BBC473249ULL,
			0xD10655F0F3C8ACDDULL,
			0x05704AF11F62C000ULL,
			0x2C4AB21C047E8EB7ULL
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
			0x5C6626D6885F1BC8ULL,
			0x63257C4322E01F74ULL,
			0xB4D04C2183548CB9ULL,
			0x6AC46870D0BE6361ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x31B3F7E35DCFAA08ULL,
			0x86996DC1328A7791ULL,
			0x8E7B3AA9703C851FULL,
			0x77D68014911777FCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2C4CAD9E5E9B8BEFULL,
			0xAE3C167684888FDFULL,
			0x809E5930EB3990E6ULL,
			0x5E6C51D0801D1730ULL
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
			0x06EA302E3DEB0908ULL,
			0xD7C6B5B555D0B47EULL,
			0xCE91C3E239C17F6DULL,
			0x610B1048C0ADA05CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA85715C7D914E118ULL,
			0x403989D1BB5D0CB3ULL,
			0xA94DF791F05CAA5FULL,
			0x7458025F15FB9E41ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8BCA4272088AFDA4ULL,
			0x64AAB179B0495130ULL,
			0x448CCC5760C3DBD7ULL,
			0x3168A4EC1C6D7C96ULL
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
			0xC9584F664D0A8DA0ULL,
			0x96A3698F2DF41843ULL,
			0xA6DD8B3FD4A06A61ULL,
			0x40A6000432ADD7EAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8D6F59282019FAF8ULL,
			0x0E26992F38E21215ULL,
			0xA938643614438DE3ULL,
			0x5A7A8AF0B48064CEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0C37238D00205578ULL,
			0x1779DD84C3E08C4FULL,
			0x8948FEB0513F8CBBULL,
			0x67F78A653268936DULL
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
			0x5CB115215A8AD460ULL,
			0x870BF1D42F123C63ULL,
			0xEE7BD476AC2675DFULL,
			0x4D24DAE517E5550AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDF5F3E2308BAC798ULL,
			0x7AC4546899B099DDULL,
			0x3E0D1D4CCE4678F3ULL,
			0x755994FF7E606788ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBBB81991509D8041ULL,
			0x5BCF580D0F8CA98BULL,
			0x6BB8738A74378ACDULL,
			0x5ECBAFD12618F700ULL
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
			0xD3ECD1AA3A75CC60ULL,
			0xE4851B63F6B17FF1ULL,
			0x42D7125559DA5C5EULL,
			0x7F17A7D907F25C40ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x05EBD2E6CDCA2428ULL,
			0xD9CEED870C1BA778ULL,
			0xD60E316EA7AF5BF2ULL,
			0x6B2835E0F4964D6FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDC3761997CE68873ULL,
			0x041C9C8F9A3DF45DULL,
			0x0B3F8D29D070EA8AULL,
			0x03FF450ADC1A145AULL
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
			0x92DD6437192594B8ULL,
			0x2216384361EE363FULL,
			0x8D6146F7B0EDF66EULL,
			0x4708336E7516399EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x48A720869CA41620ULL,
			0x6F3442F5FB625665ULL,
			0xA69F3F805DE0F999ULL,
			0x5C838790303C6D45ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8908571D55763B99ULL,
			0xB5BF26D53650E02AULL,
			0x8A76FDBAA3FC4112ULL,
			0x430493A76C8E483DULL
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
			0xF290095DA43EED18ULL,
			0xC86E4005E55BEB92ULL,
			0x6B75144C98EFC81AULL,
			0x49530BBC5778A000ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA6EA1C3C0ECD2388ULL,
			0x3B6F4D295164ACBAULL,
			0x0BA104C31DA0729EULL,
			0x66C5074E519A218AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE5C40EDFBE9AB4DULL,
			0x989BFC996A5AF945ULL,
			0x5066B6749DBD7A75ULL,
			0x53B040F976AC0415ULL
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
			0x6AC728A6FCB5C568ULL,
			0x58F70006E5FB5D3EULL,
			0xC8839ECDE3C352A4ULL,
			0x59C25F163D05C3EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0D7EAFAE8DDCCAD0ULL,
			0x4E6918EA1CD82E0FULL,
			0xFD12244CBB2E5505ULL,
			0x62EF28D66EB63C2AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5C10F64D7E602BCULL,
			0xFCA12ABC3B2C89A8ULL,
			0x92362988167CBFCBULL,
			0x50236A2DF829CE91ULL
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
			0x539F98F5A15CCCE0ULL,
			0x2DAEDCDCAE9AAFD4ULL,
			0x5A305622072DE745ULL,
			0x7B2FF46541C1D57FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x87AD2C7E1BA5C968ULL,
			0x86C50ADBF356DB0FULL,
			0xC942CFE066C5AF20ULL,
			0x737890A7489645F2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBACC78AC7A8685F3ULL,
			0x9EF51D34FC34A20CULL,
			0x58C8F3A791B2A127ULL,
			0x5D64EFDEABAEB81AULL
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
			0x5541CA0035B67010ULL,
			0xC760EF017A32B2ACULL,
			0x8F51B3385385D3D7ULL,
			0x7CDD066F121A3D17ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE317C90DB3AF0730ULL,
			0x3C70C4442B039FF3ULL,
			0x591F0D5A49550D40ULL,
			0x6353FECC163F9723ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x351C4F75545A4508ULL,
			0xC51A0DF219076EAFULL,
			0x02A606B535E949C6ULL,
			0x0F4C48D581463854ULL
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
			0x49216DEDB947E728ULL,
			0xEA28E01F359EC52EULL,
			0x2727EBDF13F8E999ULL,
			0x7EC564CEEAB3878FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC412A99302CAB3F0ULL,
			0x69148D5EC6F13947ULL,
			0xFE40425CB3023EE3ULL,
			0x4B8FFDD8F43EF619ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE653A51AB629CE0BULL,
			0x4566A5993968054BULL,
			0x29AA8B4A125DD776ULL,
			0x40DBF4D321048BBDULL
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
			0x3292CFD842244B68ULL,
			0x5D4034B2252373C5ULL,
			0xAB390AF96F8AE260ULL,
			0x4C45933E089A5C80ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x834F337556805958ULL,
			0xECA8B03B2F26EEE2ULL,
			0xBEDD906D631713CCULL,
			0x6EFCFB4A82CB9AD6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC53D02892663D70DULL,
			0xCAF30F30D3D0A452ULL,
			0x74A6269463BEF200ULL,
			0x3641E9523FF68DB5ULL
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
			0x440C088BC2FEF000ULL,
			0x7E9DD24AB0C6B431ULL,
			0x09D37C49B8BBE86BULL,
			0x678795A23C91F06BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0BC9C77886D9888ULL,
			0x40A068C5CEB8BDD4ULL,
			0x7A972CAB0F0C9E3CULL,
			0x462C41DB842FF792ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDFA7DDC91A20785FULL,
			0x7A79139BD170AB75ULL,
			0x0853A70D231D663BULL,
			0x66F6F5663E2FAFCDULL
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
			0xCAE01B72BCECAAE8ULL,
			0x2AB6610A44EB5429ULL,
			0x5D22F0FA00A75F03ULL,
			0x6AF82FDEA535A1EBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1F0FD2592DA9D3E0ULL,
			0x565923A09B8233BBULL,
			0xEDBEE3362349C8D1ULL,
			0x74342A071E08D410ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD049D76B3E246849ULL,
			0x568EE06C5D72726EULL,
			0xEA9CE96274A52D94ULL,
			0x080E8F512F05C066ULL
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
			0xB38062A5538B3F90ULL,
			0x32E22BEF54A2A1CBULL,
			0x819ED22960889045ULL,
			0x47788E9CB1F26D30ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x275D083490CDEC30ULL,
			0xEAA510B889E8E337ULL,
			0x4227C8D8A0BBAFFDULL,
			0x4B7D401DF2FE7C98ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x274DF4F3227330C2ULL,
			0x9E19D1FE0B757209ULL,
			0x3BF6BB8A00563716ULL,
			0x6FB75962CFBF1888ULL
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
			0xF146D24D92F6F6C8ULL,
			0x9913E0E9C790F41EULL,
			0xAEFAF53D6EA17FB8ULL,
			0x7E4016834CEED833ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1FB615B5145E3130ULL,
			0x6F6A028FEB98B31CULL,
			0x3C55E7FCE0D4694FULL,
			0x537A19758AC8E545ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x498B13EB051967B9ULL,
			0xC95AE44D37C7382DULL,
			0x0D3DFD9B5E963A56ULL,
			0x429FEA96CDCDE214ULL
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
			0x6ACFECAE6B4E8600ULL,
			0xAD63B7DA9FB210E4ULL,
			0xC01753D68C44192BULL,
			0x5872A744835E431DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6F672B814E0626A8ULL,
			0xA3CF5F0861719416ULL,
			0xBB5383C760F1F368ULL,
			0x5FF769157870CBBCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x32A34316DA224C6EULL,
			0xD0DBC76A34A58360ULL,
			0x9A27569B7BC03888ULL,
			0x673D7B6BC331BCA6ULL
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
			0x22177878C509A2A8ULL,
			0x33FC487426120191ULL,
			0xDDE41A6F8F8AFF6CULL,
			0x7D42271B6FDB9871ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x75D5E79B10DBAC80ULL,
			0xC2E1A72B98D661B7ULL,
			0xDCA06B3E860F2FD0ULL,
			0x593D1F3EFA973846ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x42CBEB770EB9C2A7ULL,
			0x0102A767C8BF475CULL,
			0x530CC70CEDB4EC7DULL,
			0x699A4BA4B3E888C6ULL
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
			0x6B938D581B8198D8ULL,
			0xC691E3DD1ED8D2C6ULL,
			0x3523F8CC40816ECBULL,
			0x569D59BB40C00EBAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDDFFDBDD9C4B4968ULL,
			0xB9E12E2290C5FFABULL,
			0x93AC42A2EDB9CEBDULL,
			0x625EEE1DB7756DE3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1F8F968D601B5349ULL,
			0x4E703C7E2DD592A4ULL,
			0x8890102AE3AADC13ULL,
			0x790F3684EC03733AULL
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
			0x9386A2B298512FE0ULL,
			0xF3D3F8A8713CFAEEULL,
			0x15FEB656564A4B1BULL,
			0x5F26EB005141AD35ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0C1C41AD19BA0F10ULL,
			0x037AB1D906C1F44BULL,
			0xF68E2B94534DA354ULL,
			0x621B8D4BD1C5C100ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0D4A58342AA279AULL,
			0x6A056447BB943646ULL,
			0x3206ECA3889D61A5ULL,
			0x7A179EF7EDF7E12BULL
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
			0x3A1A52D50FE297B0ULL,
			0xE714F5F6F6067100ULL,
			0x63160F4722F33BE9ULL,
			0x4A550AD39CB5496EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43530699BEF14F00ULL,
			0xCCB33A16896DD034ULL,
			0xB9E16C45CC7B95B9ULL,
			0x55128E43270F599CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x770F7FA0FD060E0CULL,
			0x636C1ABFE72C8D7FULL,
			0x1C65AC8C78560A34ULL,
			0x1B483A85F3F16E26ULL
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
			0x2F3D45EC8124DFC0ULL,
			0xAEED6B6F5EAAC7FCULL,
			0x54F9A57F79E90FC1ULL,
			0x58C8AD51B16E9721ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4E4E85614EE89860ULL,
			0x37FED0A2BD9F0F00ULL,
			0x06A68D376AE65608ULL,
			0x510D9518F8EA1829ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x69558C07B5ABEAE6ULL,
			0xF87C0FA2F120F2D4ULL,
			0xE0E555B1D465654FULL,
			0x5CE7CE8EC41C9AB6ULL
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
			0x63D71A4ED195A140ULL,
			0x6313177C5BA79F29ULL,
			0x9424C041C47736A2ULL,
			0x68CE5FD2D5C3A211ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4726984A4EB45C68ULL,
			0x4AC7A8FD4B4ADE50ULL,
			0x2B05F62D09CD5B03ULL,
			0x5A3B2C877DC3B488ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD65D27BF6A7F5394ULL,
			0xD4EB0338E598E703ULL,
			0xF94E37E7C7C6E10DULL,
			0x156A5E288185AE45ULL
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
			0x8454FCF75EE427F8ULL,
			0xE89925AF921BB143ULL,
			0x3D5DDD8C31E422F7ULL,
			0x4670D4D118CA310BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4AC70AA33988E7F0ULL,
			0x60BFDA9593FCFB07ULL,
			0x699639D29A8F6B13ULL,
			0x46F9FFDB77D3B311ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3EBCCB2ADED30CB3ULL,
			0x4742144EED767034ULL,
			0xBDAB5A68E5663DE2ULL,
			0x19E285C9957535AEULL
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
			0x66DAB54A199FB658ULL,
			0xDCC50941A5F3E6A0ULL,
			0x13E3D5F8C385DD3EULL,
			0x47E5B0A6CC4EE5DCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC360AD4D5C123A8ULL,
			0xFC2AADC40D0A7F91ULL,
			0x562F888D1B69C37AULL,
			0x5A034CDF6CE9DE94ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x792ECE402D8999C7ULL,
			0x17087667BBFE67A3ULL,
			0x2677D335B99D061EULL,
			0x2E0DB78EA3CE24E5ULL
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
			0xF111FEE4D53E1EB0ULL,
			0xE1D689B48A40BB7AULL,
			0x1420C965EC9F0FD6ULL,
			0x741CC6F2A8A6F219ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7B77D781EDD0EBA8ULL,
			0x32C5D75F77CAF130ULL,
			0xCA89121255B17EA7ULL,
			0x4AFC03CCFAB5E87AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xABB3B964E8C8094FULL,
			0xA8E7F6DA1281ECFCULL,
			0xA2A8EEE19146D1E9ULL,
			0x2695D86533DCB329ULL
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
			0xE2BC2007AB655F18ULL,
			0xED6C80AEAAF8BA08ULL,
			0x9FAD055B001D2BCBULL,
			0x6D427ACB443BAD97ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x167B7CBEAF1EDD18ULL,
			0xE663C891584D454CULL,
			0x7096A970C592D142ULL,
			0x6DD0752FEED3C0DCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCEF976DD3855F522ULL,
			0x99AE57E891AE727AULL,
			0x58D46546ACB281A6ULL,
			0x73580FADE36F00F6ULL
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
			0x7F657EDE5B9AE370ULL,
			0x87B04EC64F5B36D9ULL,
			0x1DB4E9840313CDE6ULL,
			0x7996357AB9472834ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBD3D9E8F8D024E30ULL,
			0x4E7B8858844059A4ULL,
			0x50DF44292B99F229ULL,
			0x55A01C6A6DD64596ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDB94084ED4F434EFULL,
			0x856DB2A2729C456AULL,
			0xB502DB0C75EBD6EDULL,
			0x3EC64A0107694B41ULL
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
			0x43829A0D43A313F0ULL,
			0x19D96A63C9E1E462ULL,
			0xD6B0EB9AD2BB830FULL,
			0x444C5BA62823A4D6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB98F33E795481A00ULL,
			0x93553EE6BE355DCBULL,
			0xEE3A4FB188CB1B6DULL,
			0x48BFAD5FFA574421ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6A64AE4F6B1EAAF0ULL,
			0x7B67EA2E4275753EULL,
			0x5D79680C7DD1ECADULL,
			0x68663A1C8466C929ULL
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
			0x63DEDEBA43582940ULL,
			0x327AC040B52D3EFCULL,
			0x3769DC63950D8407ULL,
			0x4F9486623FDB96F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0A5F93E574766AD0ULL,
			0xD66DE3440A5B4E24ULL,
			0xECA4CBD54DB53902ULL,
			0x741E73ACFC12D589ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x86A8E5A9D614B916ULL,
			0x7A90637361AC5E15ULL,
			0xBE1C74119873A881ULL,
			0x1E0F269EC06EC0C8ULL
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
			0x6CCFFEF00347A750ULL,
			0x03D05C3EEBCAA78AULL,
			0x7A73C2C4E0E543B6ULL,
			0x6CC951C9BC9E539CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x738D3D9D0BC098A8ULL,
			0x41D5E5B8212D6425ULL,
			0x93148AB8CE8DBA11ULL,
			0x764A437315F0E29DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEBD557B7ECA260CBULL,
			0x80C6114AC9AD6803ULL,
			0x7606664521B9A1F8ULL,
			0x60CCDFBF3081CF13ULL
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
			0x8DE5275709A356B0ULL,
			0x2149009F5BE03F69ULL,
			0x8A81D5409FC30454ULL,
			0x7EEF2CB6EC498A3AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71E73CD8EC9B7C60ULL,
			0x492A2972A19D4942ULL,
			0x939B20E7296EF996ULL,
			0x5EC33185447BCE0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7F3CCA9B58969632ULL,
			0x90BC7B1863A98962ULL,
			0xD985E6B062C7F3DCULL,
			0x12C6C4DEE013D39FULL
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
			0xF90D4B99D1B268E0ULL,
			0x4EAD8509DEBB91A2ULL,
			0x074ADD0BA1C7529BULL,
			0x488454C82814F74AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD0F63EE43D81D6D8ULL,
			0xA5EF02D7A680E7DBULL,
			0xF28E078EAD21FA97ULL,
			0x49E996EED9F417D6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD835A90DDD2DA147ULL,
			0x469973BE28A82502ULL,
			0x8DDB690B0D62A1C2ULL,
			0x2D5EEA2738004063ULL
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
			0xBC72038790E0B638ULL,
			0x9FA1E1DEE6FAA57BULL,
			0x9C570DBB9343D690ULL,
			0x6080F2442243D41EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4FCC72A657E92F70ULL,
			0xA3C2326A34C7ABF1ULL,
			0x7F776E682BA0A7DDULL,
			0x6311BCC467EADF7FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xACF6BD3C881B86C5ULL,
			0x0F4AA401D12BBAA8ULL,
			0xE6C8B8D388C637F9ULL,
			0x6E14605700FB4F10ULL
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
			0xAE20F0970A0F7210ULL,
			0xA55B0314A663C5DFULL,
			0xBBDA4411B3AFCEE4ULL,
			0x56A04FED8CF5E84CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6412AE6C63A2C178ULL,
			0x9706572E811A14E2ULL,
			0x86DB3F67964D7A2CULL,
			0x53C27EFC5A5D4B83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB8A90E4104F41854ULL,
			0xDB0F05DB1D8077BFULL,
			0x43D5915A0BBF2A63ULL,
			0x581120E667CF3650ULL
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
			0x0F37ED8596F23F40ULL,
			0x9CE356FE3A8D7AFEULL,
			0x99730696D0E7B044ULL,
			0x429CEA9152957B2DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6B6F82716B42FBE0ULL,
			0x908CE3EAD49FA57FULL,
			0xCF9AFB3AC3AF9BFCULL,
			0x61C3BF437A53E647ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xED2A87CC7A34CB70ULL,
			0x182A09324658D5F7ULL,
			0xF8734D78E14A20DFULL,
			0x2895CE9DC75E68E1ULL
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
			0x539CE49305AF5480ULL,
			0xF6AE7B9D8971C81FULL,
			0x0D9BE89A2BEC0403ULL,
			0x6F310F474BF3E5D3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC0C608346EF979E0ULL,
			0xBE94514C2313D1DFULL,
			0x4216627013B4E6A7ULL,
			0x5C5C7A44030773F5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA81F6E2336C8DCBDULL,
			0x830BD0CA2D9FBDC3ULL,
			0x91ECD19128424AB9ULL,
			0x309C70C7D17D0578ULL
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
			0xC73DCFCE67E8DD98ULL,
			0x8245B1F06D182528ULL,
			0xCB072E5B7BDE3572ULL,
			0x6E0B2B81F5FF4378ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x480133B95BB09418ULL,
			0x2A1C851BBF06AB7CULL,
			0x74E02B0BA5718090ULL,
			0x4D8C1465629B6978ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1D704EC6FC5C6B1DULL,
			0x1631AF108200A358ULL,
			0x95F3A35D47B83A6AULL,
			0x5A48F0B5E69262C0ULL
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
			0x06E5324577DB0850ULL,
			0xF43C938092EFE108ULL,
			0x28EFFDEB6D5E8C70ULL,
			0x7779C488CB9C8B47ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x104CAE0DA3DBADC8ULL,
			0xB847F556334D645CULL,
			0x0ADBE4A9586ADD51ULL,
			0x49147B99114D685FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC3CB420781A050E9ULL,
			0x892ABD119DD766B0ULL,
			0x2E9011B4F9A5E5C2ULL,
			0x2B4C00A58FC4FBF2ULL
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
			0xD5CAC71B9BB7C0B0ULL,
			0xBAEFF17C414C491EULL,
			0xA7CF8B25525C28AEULL,
			0x609270F9700A66ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3730790B76CAE998ULL,
			0xCA179E56C627775EULL,
			0x69680E491B4C1F55ULL,
			0x5820EDB4D98EFE67ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF63AB4941F1EE514ULL,
			0x9885692AB0D4D737ULL,
			0x2D01465E628F6B33ULL,
			0x2B025235387C72EFULL
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
			0x4E2A0BBBD52A1940ULL,
			0x10640A9395928D50ULL,
			0x74A4DD02D3671459ULL,
			0x4B3A0A08643F1A51ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72843522052C0040ULL,
			0x7CE2945095351880ULL,
			0xF3C813B3C337A3F9ULL,
			0x4AF0E4F1BA219B83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47388DA743223E0AULL,
			0x035F32E3C04A6081ULL,
			0x469FEF639AAFA8E7ULL,
			0x5D6DD48191A74CFEULL
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
			0xB23B02DC51FD8200ULL,
			0xCAFB7241F8AA3E00ULL,
			0x7B487DB0463F8A03ULL,
			0x4C9DB91D9DD94706ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2F1137E07BBDBD48ULL,
			0x7C4B394A80F2A96FULL,
			0x9BA8368DDC93B8F2ULL,
			0x76DF4F0BBD1B81F8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0B8E4F392FB37A0AULL,
			0x0AEAAE4C2FBDEB7DULL,
			0x9B5AA6CAC8EC429FULL,
			0x24CEA17A3A955F06ULL
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
			0xA9D3DD18AED868C8ULL,
			0x65128C451F16D50DULL,
			0x938ADEE7753844ECULL,
			0x60DD60ACDD5E83E4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x882A3EDE8EA13AB8ULL,
			0x5F6F106569875E38ULL,
			0xD29802E92A95E23AULL,
			0x6ABA6EC250A036C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x153C3100ABFEA907ULL,
			0x00FB84E1AC8A0EB4ULL,
			0x0ECB4054BEA31CA9ULL,
			0x3781F9A7F7105F50ULL
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
			0xCEC1001D20507950ULL,
			0x62854A3785902B6DULL,
			0xB9906E0357CB11AAULL,
			0x62CAEBDBBA5E7A0AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C947F5B48A746D0ULL,
			0x0AA07292B4E8DF39ULL,
			0x3F6FAF325EE42980ULL,
			0x406FE960DE045F2CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF0A2202C4D93191DULL,
			0x689AE76FB776DB4AULL,
			0xD04857CBF75CD712ULL,
			0x7922DF98EAC1745DULL
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
			0x26B2E0AB71C30F08ULL,
			0x0C59ED66BE2C1668ULL,
			0xCB0491CBDF4853C7ULL,
			0x79C7D75F8BBD8175ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7A68D3C4FF04BF98ULL,
			0x444C193E63FA6373ULL,
			0x8EF3DEE086842742ULL,
			0x79B86E3B30912970ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x08BA7D4F102435B4ULL,
			0x94BF4AB8125FA726ULL,
			0x1BEEF6C1A6380B54ULL,
			0x6C9691ED3D1B7BA1ULL
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
			0x072118C01B642C90ULL,
			0x83B9F633F6A03CDAULL,
			0xDDA4E401D6B2D1B1ULL,
			0x67DCB31A11123423ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB28339BF8D49F930ULL,
			0xE4E00ECA1EA171F4ULL,
			0xC469E58EAC19FEB7ULL,
			0x739914B7A9443410ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBC17FBDC7BBD06E0ULL,
			0xDF182FA2F3DF32FBULL,
			0x1DD126D5B9463B55ULL,
			0x238A7655070CE44CULL
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
			0x7E629049D5EA2600ULL,
			0x5A67B922D4499A98ULL,
			0x0D3214E6C0C56BD3ULL,
			0x7CDB503D3373901AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x948A5D31E69439C0ULL,
			0xB04B8020A9B3C7B9ULL,
			0xB20C00AE24BB3707ULL,
			0x677FDB3EF3964F3CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC0D32B8FA39B8028ULL,
			0xC3E3EA5924466CC1ULL,
			0xC29CAFCDE6BC8673ULL,
			0x52527B5946AF671BULL
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
			0x59916457486FB530ULL,
			0x740D8BBD7AA38BADULL,
			0xCD4FB92DF55FBCCBULL,
			0x532E443852E2C05DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA132A783B21D8AB8ULL,
			0x46F7AE26358C8D2DULL,
			0x17544F0E089AADC5ULL,
			0x4E8BF89FA8751C8DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37CB30A28D627620ULL,
			0x730C28AC5A306963ULL,
			0xEADEA8F3A0E18E9FULL,
			0x568C2F35CFA0A1EAULL
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
			0xE04C11F8AA995D50ULL,
			0x2CE7CD9A0716C8F9ULL,
			0x48F6B8C1D421A908ULL,
			0x78FB1E9E96DD19E0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x56E07F1DA0E66A38ULL,
			0xB85239CB0DBAE774ULL,
			0xE923426CA20C7704ULL,
			0x46A60AC670704FE0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB15E7280A650ECE2ULL,
			0xEFD2959B9CD33FEBULL,
			0x888ABD9DEC6464EAULL,
			0x5DE67C23708152ADULL
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
			0xEE084CE094C7B140ULL,
			0x5EDC154C46CE9F38ULL,
			0x7511D78F7BB945CDULL,
			0x7B07B2733A0D317DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x488FF08A998F64E0ULL,
			0x6C50B50F5D8893D2ULL,
			0x977EDC7F6BB9C7C7ULL,
			0x6840688EDEE6D758ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x79FA74E7A5FEB7EFULL,
			0x6BDF8C68F036A241ULL,
			0x9C09CA44B853561AULL,
			0x08981332FA093677ULL
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
			0xB8A95606989EFB60ULL,
			0x978973E2540058E6ULL,
			0xB099A8E9B2DCE38EULL,
			0x558365EFAC81BA08ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA4253F3558BBF58ULL,
			0x5B1D9B8392B15165ULL,
			0xE9209AA510AF0544ULL,
			0x6189F749A9163609ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x41D4EF04752CF04DULL,
			0x21368B77F88ECE8FULL,
			0x8378C358E2F6732CULL,
			0x584A7E49711CF3D7ULL
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
			0xABCCC8DE520AEB30ULL,
			0x97F2BAC4FC0FEEA4ULL,
			0x77B270B2FDD98FCEULL,
			0x4852BD0FA493F08DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x12A21E0F62C91CC0ULL,
			0xDF56A1C7D58DE060ULL,
			0x203D030D7D0CDF81ULL,
			0x7A86D44B0B132F89ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6E6AFA700A26A926ULL,
			0xEA373E7E3448D1DFULL,
			0xE34E13F2EA7238B0ULL,
			0x093FA4AE86BF65C7ULL
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
			0x6F62DDECCC108BB0ULL,
			0xC92C1AE99230B85DULL,
			0x61DF96DF1823CFDCULL,
			0x7FC6D62E57F9218EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x73EE2D99823AA338ULL,
			0x1BB2D77FDCD990D0ULL,
			0x33D2566305B1DEC1ULL,
			0x5F95498A922AE5D0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC7984F37E0D1989FULL,
			0x826B41FC1304554BULL,
			0x279000B737471213ULL,
			0x6CFE7EF9DBDC43B8ULL
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
			0x2C25BC51A1072748ULL,
			0x29564C456D091347ULL,
			0x6EB0900EE3279E61ULL,
			0x7C6A06C669089CE6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x73AB41D32D8A1800ULL,
			0x32EE3C2FCD55894EULL,
			0x6FB6305461512DF2ULL,
			0x75E54EC0AD0E3772ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6836ABDA2E997802ULL,
			0x48DB371F587B381BULL,
			0xE5021017F0F96AB3ULL,
			0x1C955B9C3827FBE9ULL
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
			0x1678F2032BCD43C0ULL,
			0x9858FDF6C09FD95CULL,
			0x3F90898616A3A26AULL,
			0x670FBB71AA810445ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x95792CA039093F90ULL,
			0x9F3522219279C958ULL,
			0x7D78BE3A18945285ULL,
			0x496FA3AEC8109254ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9FB7F9B939DC25D1ULL,
			0x2968E2FAFCCF6716ULL,
			0xC3BD6BF3193C6905ULL,
			0x36B532A0F897A931ULL
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
			0xBA28AE88D69F92C0ULL,
			0x3DDD2C077EBC9430ULL,
			0x0BB5805B14398628ULL,
			0x7880D3A6A1AD9340ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA27BD1315D3F1F0ULL,
			0xACD2199A8C8E22B8ULL,
			0x618DE45FF6C460CDULL,
			0x5D983210FDD56AA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x446F9496A7DC26D4ULL,
			0x28A199FC1A5AF54BULL,
			0x71AB9F09E53050D8ULL,
			0x568553952B3F6129ULL
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
			0x133A2B7EED0419E0ULL,
			0xDB247BE5D7F85E74ULL,
			0x5ED083A328788396ULL,
			0x6BA66188F1744D7EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x56E39CEDA8F8CB50ULL,
			0x9039F5977255B7C7ULL,
			0x288558BF9F6271FCULL,
			0x5E0A1B3B050BEDC2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x455DC76C1FD3EC8BULL,
			0x11A6A7035B1F17F7ULL,
			0xC92F650DC9C92964ULL,
			0x72FB462559D963FEULL
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
			0xE062521041C9ACE0ULL,
			0x1731D8C92A53F73AULL,
			0x5BC9D8822B161EC6ULL,
			0x5E3094209915110CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2D0B740D0CAC5330ULL,
			0xB60A1CE568D89B29ULL,
			0x6078C77E4751DBE8ULL,
			0x580BFB01DB54293DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3B09965ECE139D7CULL,
			0xE4524EC7BCAB6EE9ULL,
			0x2E8F50A5BD207091ULL,
			0x4BA5D34A903F0DBBULL
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
			0x12FCA4617B38C980ULL,
			0xF5692DEC695F1F7FULL,
			0xBDDDB29D89633391ULL,
			0x6B92EB8D54D19D20ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBAAF15CDF0095EA0ULL,
			0x3597AC5CB78C53C8ULL,
			0xB35D0B197EEF797BULL,
			0x44B3506B15354AC7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC3FE6CEF935E8DE1ULL,
			0x3F91FAF187C930FDULL,
			0x6909BDE3F3C35709ULL,
			0x54324904A5F3F7AAULL
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
			0x2A280C545401BFF0ULL,
			0x6739925EF5367340ULL,
			0xA1FE4F76DC4432E0ULL,
			0x4368B0B7A1073C37ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x860046726A3C0D68ULL,
			0x67FB235C676BFBB0ULL,
			0x20207538F8AC8371ULL,
			0x7F40BFFBB8E58523ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x26637D2399A4CCC3ULL,
			0xB66F0AF5BBACF220ULL,
			0xF4A095B781FDB600ULL,
			0x4730323DDC4576C9ULL
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
			0x131422B519D4D6F0ULL,
			0x57449F212310D280ULL,
			0xA8EA0FE4F4F3C1AEULL,
			0x7F7E579A79A7ADCEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC90077305D64F460ULL,
			0xBE53D4CB1C59D486ULL,
			0x44C50295AB6A39FDULL,
			0x66605824599251DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x08ACF86BA0804A16ULL,
			0xFA9CFF42E8783540ULL,
			0xB7794D5B3BBCE13CULL,
			0x3205FC7BE8C9BB31ULL
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
			0xA45BE3C605B1F0B8ULL,
			0xA8C39E23D9F0B758ULL,
			0x9EF48B4EF1619622ULL,
			0x7FADF8612B7BE673ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC2261AB7FD82488ULL,
			0x61D33C748F16BF53ULL,
			0x92661DB1B32C3F66ULL,
			0x72C3A0C41E33C7BDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B2CED73216FC3F9ULL,
			0x30ECEE424F8F0882ULL,
			0x62AB59B76DA4AA3BULL,
			0x071CAAC2BEFE21A0ULL
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
			0xF928B1F5E25FB530ULL,
			0x53C4D1F682B65495ULL,
			0x7DA4E6C9581D7F7BULL,
			0x63DF66CD79451E8FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8E12DAA93DCBB3B0ULL,
			0x9B7A129BDE2BE24AULL,
			0x7DDD0D6F79A5F996ULL,
			0x4262851E671C49F8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBEA198F6699186F1ULL,
			0xE06377F7FDF5B8F0ULL,
			0xEF234B7D39DB7211ULL,
			0x2A3EFD0106BB0790ULL
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
			0x50F36D09167F8760ULL,
			0x433BCB787E743C6BULL,
			0x645F654D1AA07E45ULL,
			0x553EBD564DA5B6E2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBD8E016BDB2BE9C8ULL,
			0x7FE184905AE16AC0ULL,
			0x4C6DBC9B8D3973D3ULL,
			0x6D4B1979A44B54C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E7732D6C503040FULL,
			0xAC6A6EACEF06F61CULL,
			0x997893B1F529C578ULL,
			0x571C025061A0258BULL
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
			0xEE55E1BB075CB000ULL,
			0x0C44A77ED7694C4AULL,
			0x49A2D8E4E2F57C7DULL,
			0x6A840828454FCDE9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x10B5C028ACEB7D30ULL,
			0x431154C1097DAE1EULL,
			0xF1F5FA1DF1076CCBULL,
			0x4F5E63278BD08CC5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x91980CCDC9E599E2ULL,
			0x436175217C761191ULL,
			0x39FA6D2A4AC050BFULL,
			0x7C405821EC78F3CBULL
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
			0x7C617FACAD5C0E60ULL,
			0x9BC0854DCC16E669ULL,
			0x0218563086089E42ULL,
			0x7448E717CA6FB5F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA297C8FEF462BC48ULL,
			0x9DCA821EAEBCABF6ULL,
			0xA812D75366542705ULL,
			0x5F3CE5AFECF23ACEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5926ACBADDC47EFEULL,
			0xD4F48C6B1E76D7BDULL,
			0x8F5BD8D5F1366A44ULL,
			0x161A1240456C9AD9ULL
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
			0xB74DCB7F35E33AF0ULL,
			0x721934D9FD999164ULL,
			0xF9896D924F82BCABULL,
			0x44EE367E8F871FADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0A0969F244CCC688ULL,
			0xCADFCC2494F948BCULL,
			0x0B95065D0A6F900CULL,
			0x57640597688978E0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBDB0A2EFC26594C6ULL,
			0x01F4F502DD5DBB2DULL,
			0x3A7C7A38E0571424ULL,
			0x08E587C2D69A4A65ULL
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
			0x511229813F679B68ULL,
			0x1358BF495F4BB7AAULL,
			0x5C923A55CB119244ULL,
			0x44CA18906A230A7AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2FD4267363E22C98ULL,
			0x99AFF11F444EEB49ULL,
			0x81AA0FE89F023102ULL,
			0x4CFF5D6A5F59056CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE06FB86054FB019ULL,
			0x7B883514FEA47D15ULL,
			0x49A6C9FE843B2059ULL,
			0x105A7ADD951A38D3ULL
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
			0xC121AF36FEB8EC50ULL,
			0x199B9401CA25142CULL,
			0xD904F67BF0554A1DULL,
			0x72EE0249E145AF3DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB417A368B0008DD0ULL,
			0x41F8FB9E76E862CEULL,
			0x0E3E796A1B0A5C94ULL,
			0x420FDF655B9E830DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x94E0A90A59216669ULL,
			0xD49A1590A98DCB5EULL,
			0x6443E1D8965728A5ULL,
			0x655D43F94368DB1CULL
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
			0xC47080A1DB4D3F08ULL,
			0x404D9E7A0BB5C231ULL,
			0xBEAE6B3EEFA99998ULL,
			0x7AA567D1E2248A4BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC7B926547C816E08ULL,
			0x68C152C299F75B0FULL,
			0x2ACF9CF43565A20AULL,
			0x605A8163D09903F8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD8B48EF74493EA88ULL,
			0x6AED68AE7FC5B4B3ULL,
			0x9026577B1A192C51ULL,
			0x75A2590322AACC13ULL
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
			0xB124D30EF9EAC268ULL,
			0xF548417DBC236633ULL,
			0xABCA764A44EE0B78ULL,
			0x6BEBA6AB91362803ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x24DC2C1190C8FA40ULL,
			0xDB139491912C4A28ULL,
			0x4131CDD0A7245BAAULL,
			0x45244995EB5988D7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8EF4886AA1584CCBULL,
			0x0A4AD62D465FE12BULL,
			0x050AFFC6FE898A8CULL,
			0x316026C30E99D065ULL
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
			0x2CA181F192B42058ULL,
			0x0A0856AD8264773FULL,
			0xCAFD6B5D33B547E2ULL,
			0x43B591AFA36F2086ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x69FF7A1BFB91DCD8ULL,
			0xFB3E075B5218B8E3ULL,
			0x8437B2C1BD305B4CULL,
			0x5CB277DCBA09A29FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xECD2A92231DFCF07ULL,
			0x8FBBAFDC369CA983ULL,
			0xCA958A03DC129856ULL,
			0x61711AC9686E848EULL
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
			0x5836B055D22F7F88ULL,
			0xB019FEC5A70F6D30ULL,
			0x11CA3A9957BCB6A5ULL,
			0x50C84F23E766741CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x37EB421404AD6F08ULL,
			0x3E6D760FBA2452EAULL,
			0x7ABD0952CA53AD66ULL,
			0x5DCB26D18026056CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB537D0F79689A75EULL,
			0x0814929E68348EE4ULL,
			0x51A540638DB56868ULL,
			0x42D8E790B9A92854ULL
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
			0x4D7F09F8B4EEB928ULL,
			0xB3BD7B969E79CC18ULL,
			0x562DBF4CA4F99C36ULL,
			0x735B9AA19547F93DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x654A22933F71C1E0ULL,
			0x53DBF50EEC31CD5FULL,
			0x3FE6FC319B1C5025ULL,
			0x7191EC472A80D547ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x86E82D0E3A746614ULL,
			0x93F2B2EF2FFF2E66ULL,
			0xC88D021975FB242EULL,
			0x32DCCCAEAF30E327ULL
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
			0xD4616ECF5A06FC30ULL,
			0x5E011B4B3621521BULL,
			0x1751FB16A7FAE600ULL,
			0x5E2CFE5AE4AD68C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6F3243CAEF44F4B8ULL,
			0xF7EDEBAFD4E3231DULL,
			0xE6181B7BE3C84E5CULL,
			0x4BF27195FFBB39ACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x98D59043439B03BCULL,
			0xAE48EB2F31A7D142ULL,
			0xD65AA186B0540180ULL,
			0x3D24CDB66F673B31ULL
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
			0x56FC27C9A050FB10ULL,
			0x2EB659A509224A9CULL,
			0x85E30D0C4E4E1228ULL,
			0x61CC3B212453FDE6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDBC031508FCF1178ULL,
			0xA840323E4F1C2F05ULL,
			0xCA7CDE2C01829AF0ULL,
			0x72F05BC2E4A275DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60616679D9CDD232ULL,
			0x83329F146F80E2F6ULL,
			0x78FC803E6312C122ULL,
			0x1985DE4222F8FFA6ULL
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
			0xD5BA2EF5EEC17670ULL,
			0x51DDC8E3230BDD06ULL,
			0xAC71C2D9B4ADB985ULL,
			0x40FEB214C99D3423ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16747C55B680C0D8ULL,
			0x5F305469EC3D5385ULL,
			0xA831CA91FA4893BFULL,
			0x74DAAE6589627EB1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9649F052BCBAEB37ULL,
			0xCADF91F073561A75ULL,
			0xA3E815CB33E84FB0ULL,
			0x4957C63F08D60AB6ULL
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
			0x6BB93C3BA9EC6058ULL,
			0xD7D89A809ECE7D04ULL,
			0x85288E7C060D2096ULL,
			0x5601D3C0F2EEAF55ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEE90173BA8E861B8ULL,
			0x95D336AED9072087ULL,
			0x8100541C0203836BULL,
			0x78C4F16D4BD59A23ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x13DB71C24949DEC9ULL,
			0x44913D4FD57E81C8ULL,
			0xE94BBD5647F63FC6ULL,
			0x1879AC32C11E5A09ULL
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
			0x6A8562751FFA3850ULL,
			0x2C7BAC8115F7FCE6ULL,
			0xB70AAEB738D70B62ULL,
			0x5E2D412CB36C1B43ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF03B5F98C78998D8ULL,
			0x3F27096B114BF259ULL,
			0xF84BA58F0C07D160ULL,
			0x4D7B0DFEC3BC48C4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9401136B94B006B1ULL,
			0xA6BD230F75DA354FULL,
			0xB881864196476623ULL,
			0x4F2B78DDD9F8CE97ULL
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
			0x86A0EE023FE5E088ULL,
			0xDDD3569F0186F5BEULL,
			0x2326330CE030400AULL,
			0x7C87146A1378924FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAFC4DD42A1DF2F40ULL,
			0x192C5C2BD875E882ULL,
			0x826E7803E7E1E309ULL,
			0x4DEEB21448EB7886ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6E5ADEDA43912418ULL,
			0xD3FD6FBA5A16EC26ULL,
			0xE6DC61F6534E43E5ULL,
			0x32EF18FE1CF431D9ULL
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
			0xBCC289FC6C2C44D8ULL,
			0x68CC7AB7AEE512E0ULL,
			0x86AC03C67B87EC50ULL,
			0x730C6D29EF90C464ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCCBE51ECB0BDC4E0ULL,
			0xE8D12739D53AAA94ULL,
			0x60A1253EFE697289ULL,
			0x6DD2C521E51178F7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5636FB405638F01CULL,
			0xC168213B4070F458ULL,
			0x52E7AA570BC97141ULL,
			0x6ABA7B0F9781C5A1ULL
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
			0x16B03C5A045519E8ULL,
			0xBDD1321F30F314C9ULL,
			0x695C68EDA03EFC3DULL,
			0x6CD9DFDCCBD8BBD3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3175127AB2E1CC8ULL,
			0x917F6EE96EB06B55ULL,
			0xE2C5F864B9E89847ULL,
			0x6E525502B17086EEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x70B77EDBABF4B067ULL,
			0xF0BBCEB9992AB458ULL,
			0xE8AAEA58DFFF33EAULL,
			0x53919D4BAF05317AULL
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
			0x684475F8A97F6190ULL,
			0x81844BAD319C38F6ULL,
			0xDDBAC2ADAC30F472ULL,
			0x54AFB2A007CF544EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE033AD2F96281A48ULL,
			0x1D18449C45B750CDULL,
			0x8B346DA99CB121FDULL,
			0x6F024994FB40B392ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x63D18B8217F1767BULL,
			0xD61F4216857D8338ULL,
			0x2185DB44825DEDC1ULL,
			0x3A61BBC38C027A66ULL
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
			0x533D41A953E01608ULL,
			0x162353CEA926C81DULL,
			0x614626479778AD07ULL,
			0x5B99B1C1F70F3D6AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD2AB31444E14058ULL,
			0x018BF5773F360596ULL,
			0xF078121339728A27ULL,
			0x41F08D2D972C576FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCF68E339E8107F5EULL,
			0x6CD43FDD320FF705ULL,
			0x974B80966CE0F303ULL,
			0x257FBE5C94C6DB9EULL
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
			0xBEB2F1D164D77130ULL,
			0x3DA7FFEC2F6B70C8ULL,
			0x16A2020A7C13AA56ULL,
			0x7FC18187BFC248D6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEAD7AF8D462044E8ULL,
			0xA381E9931CE97A66ULL,
			0xCB1CDA354C543D32ULL,
			0x796989EEEEA7C600ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x46AA3150719108BEULL,
			0xA19440B8F690453FULL,
			0x82109819E08D27B7ULL,
			0x0859BB4C8749861DULL
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
			0x0D5FAEDD0362C4D8ULL,
			0xF9893419668E4ABEULL,
			0xB146469CFB8BC930ULL,
			0x62EE0769D740A1D9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x19DF1CE629FB6F90ULL,
			0x773FCF83261AEF9FULL,
			0x3C7711BA11BE8DC0ULL,
			0x5050C1774FBF3203ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x32ED1465ED0D0AE0ULL,
			0x3C82C900895CC6E7ULL,
			0xD2B8B625B2A3D060ULL,
			0x569664BFD4240B52ULL
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
			0xAD8AC4D0E0746F90ULL,
			0x5067DE9025323449ULL,
			0xC0A0521FB52EFCF2ULL,
			0x665A23CB0BFF656AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F99635D31E44AB8ULL,
			0x2B7A74786EC420DDULL,
			0x8FB815B5D22AE312ULL,
			0x53A07FE62215B417ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFB6690EDE24A7614ULL,
			0xCA6031D04C8D6DC4ULL,
			0xA00E8BD20F4514C2ULL,
			0x3E280B3B3ADA5D16ULL
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
			0x40006E7DAAFE0650ULL,
			0xA76E464BE174E427ULL,
			0x4312555ED164ED21ULL,
			0x5659D7EA9C837FF4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1BAB226786689840ULL,
			0x90AD657F7980678CULL,
			0x74938B557487A468ULL,
			0x4CFF021D7001851AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB525493AC5A8F5EFULL,
			0x2306EEABE857AC72ULL,
			0x882F92E56AADE52EULL,
			0x62F66B4C35FA5E8AULL
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
			0x98420A621AB7A660ULL,
			0xCFD1BC235B2B6F63ULL,
			0x8549537147662F0CULL,
			0x61194A15C596524BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD0D5FA145205DE70ULL,
			0xC0707E802F9F3812ULL,
			0x941E2C8F87A4EE56ULL,
			0x5CA2E713CBD87325ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E99E1207E0373C7ULL,
			0xB430908BFDDC1D8FULL,
			0xB2B6153954DDBB9EULL,
			0x4B76DFA3AED37F1AULL
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
			0xAFF0113316438C28ULL,
			0x711CC80A5787FBA0ULL,
			0x616C9D1D0F81BA39ULL,
			0x756F22E4B1974D1BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1419358E00E02C80ULL,
			0x1B085BD6E8BE9D95ULL,
			0x91A4920A003A827EULL,
			0x4C8500C0B3BBB8E3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x61784910799FD822ULL,
			0xF5B0ABB9FEA2EB71ULL,
			0xCD7D0D0DC7EE36E9ULL,
			0x6FDE887485AB5D82ULL
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
			0x2B7CB4CF0BF97BC0ULL,
			0x0451F8BF0FCD5D75ULL,
			0x54400FF4F4F6E8FDULL,
			0x78A59780CF864C58ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE7443C86DF13E48ULL,
			0x67887D261E76B64FULL,
			0xB03B70E1964EA64BULL,
			0x726B85884AB949B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1F3188F14FA37AC0ULL,
			0xB7618554AEEE4F70ULL,
			0x0B7EEAB72D1C80F2ULL,
			0x555C378C50E06A4FULL
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
			0xE721444EC5AD7B68ULL,
			0xDB7C72E0E1A00AE3ULL,
			0x3F786540F8E12524ULL,
			0x4CF3E6B8F0D5CC73ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5A848319AC5DCD90ULL,
			0x8FAB4C112B822350ULL,
			0xD1D8C9DD84D6659BULL,
			0x595A8D90CD0E21CAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC9B105D71C1B0792ULL,
			0x2FE8D3F351486356ULL,
			0xC189FF5BB1EDA620ULL,
			0x3AE9D88FF5388FAEULL
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
			0xF15FBFE962A2FEC0ULL,
			0xE9E7ECAD5E04F981ULL,
			0xD393F4582D76AAE9ULL,
			0x648063A1BBF86D71ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x720C440A9F829E58ULL,
			0xEA3BD764003D9B6AULL,
			0x31C3A09989459A9CULL,
			0x4D6784C1A8D426F6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE98733E161AC2120ULL,
			0xE5DF155E5454CD78ULL,
			0xB78D625894972620ULL,
			0x5A0C041801F456A3ULL
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
			0x7E8730C6DD8012C8ULL,
			0xC5EDEB6727CDC9F6ULL,
			0xD90C339101F514C8ULL,
			0x50771B42F32729B4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF45393C285A5ED8ULL,
			0x21A2B077754848D7ULL,
			0x6E8351631C4A1381ULL,
			0x4D7341FF285BA12EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2A18D0E61D413FDEULL,
			0x098B326807AD1380ULL,
			0x1BE9A52F6E95935FULL,
			0x2888F6DC13167BE1ULL
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
			0x7B3F96BFF03F7B88ULL,
			0x51A2A1D40D3C3B69ULL,
			0xE19922E5D77EC098ULL,
			0x5F5558AD5453FAE4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16F78CA00FCB3618ULL,
			0x1337D45C1F3FEA8DULL,
			0x78B1893260CB4626ULL,
			0x46CE90B9B21FD6A5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBAC10C2E3F487D59ULL,
			0x71CE8B183F18CA2AULL,
			0xFEC3366C3128FF84ULL,
			0x4665C615BB812D21ULL
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
			0xF38B2DECF38E5B10ULL,
			0x5CAEFDB52AD7B4FDULL,
			0xC5C3F20F504DF971ULL,
			0x7B171254D34F8A56ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x10108CA27E29E0B8ULL,
			0x71D8C59C00CA5E38ULL,
			0x3FA90515D0C348D0ULL,
			0x778B6F13828FB2B6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD3D023A2826EBECULL,
			0xD5938DDB90B7BC0FULL,
			0xD8482CC5C3F4DF39ULL,
			0x2D2CF5239F9F0947ULL
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
			0x7CEFBBF2C1B14728ULL,
			0xDA51BD196A4718A9ULL,
			0xEDF67B0FF9E1EE78ULL,
			0x5512D478738FB645ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7CAB2A748E19BC28ULL,
			0x18FE04BFCB019CA3ULL,
			0xA15C465AA1A50F15ULL,
			0x435396AB120755E4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD956DBD7C3CC06C0ULL,
			0x585195A75F419C12ULL,
			0x2FCCB1908BF4CBD0ULL,
			0x39442AB9DFC99AACULL
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
			0x80384B4EFBE4E960ULL,
			0xD31A8C10C75BC42FULL,
			0x02877CD438119A68ULL,
			0x5C8E983062777BFBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB2D22DB376652858ULL,
			0xC03A4F61D2F2B4B2ULL,
			0x1271DDA863CBAD93ULL,
			0x4542790766E60E27ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4FB01C82C3700A90ULL,
			0x5CAEB3B0BA6DE06FULL,
			0x64E880451CC51F44ULL,
			0x6ED6E23F1A9BC201ULL
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
			0x54C3CA591A6A6350ULL,
			0xE176DCDC2F7DC327ULL,
			0xDD7AB8F4A98BCE1CULL,
			0x7E705F4C49F89C65ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF46BC51C67F14680ULL,
			0x294BB168754956EDULL,
			0x65ED66E70B27A24AULL,
			0x432CB16DE37A4D96ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9DB3334E9AB3D8B1ULL,
			0x4C4B2D2B4D5D2970ULL,
			0xABFC970B9FC3C8FFULL,
			0x0BDB7016646EB633ULL
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
			0x47601157B786C400ULL,
			0x5DB2C9618391459BULL,
			0x64FDCBFBB8E143F8ULL,
			0x76CE06F755D0A9A4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCCE29599746CA4B0ULL,
			0xAE88E9130A25CED9ULL,
			0x56D971F31ED49B52ULL,
			0x47413C4EBC44DF4AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60F216BE976CA0E8ULL,
			0x068C90C7B1BE2520ULL,
			0x9D478622873D5858ULL,
			0x5F1DBFD7D3B2D916ULL
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
			0x5DDC2A52690B9BA0ULL,
			0xE0568BA958CFC263ULL,
			0x17916E349945DD89ULL,
			0x6286253C5DE2F1A2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0C0585ED12F28338ULL,
			0xB6906B36FCA2433BULL,
			0x6907942A8CEAB828ULL,
			0x72845077294C8DAAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7CE1791E900097CCULL,
			0x1DF2C00A3F28A12EULL,
			0x2614F353A316A3D8ULL,
			0x1C2AFC9B78B005A5ULL
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
			0xC833355147B40C10ULL,
			0x813E68565DBBE73EULL,
			0xD43F55CD61E917B3ULL,
			0x67A8CC0D0C95E41DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA2B7AE7A711F8B98ULL,
			0x8593A83000A11F9CULL,
			0x2EA18BAA3BF48B9CULL,
			0x6CFF2233D54EE0D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xADA1C9E06E7C3F51ULL,
			0xCFFCAA8B31522238ULL,
			0xF1298A3275619861ULL,
			0x09A83151B47D1445ULL
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
			0x10ADA4A642D3BC78ULL,
			0x619146565EF66FCAULL,
			0x29748BE254B3C1E2ULL,
			0x4B1ED3D5C0F56E0FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF963B1D491DF5990ULL,
			0x23FAF825EAFCC86AULL,
			0x2E15A3ECF29D8652ULL,
			0x7F011685D1BAEADAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD2923D77180DA1CULL,
			0x96F53E54690C889BULL,
			0x0D8D586B465F4242ULL,
			0x409F39507694E326ULL
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
			0x1BA515E5A96F6378ULL,
			0x679F9EC113991635ULL,
			0x65493D8472F08E71ULL,
			0x6085F5540395AC84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x770E95790EA4BF58ULL,
			0x90730B1B6F8F7FEEULL,
			0x55F93DB0A912BA42ULL,
			0x68859E79D81AFFC0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4912ABFEB8D70956ULL,
			0x899E94FA93032FDFULL,
			0xBBBFFE562DAF07C3ULL,
			0x2B04B996D375C6E3ULL
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
			0x0FE45056EC082908ULL,
			0x74198BCBC0583828ULL,
			0x983131E8C3991F6AULL,
			0x59EE32C53EA052E7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3A64B452DC040AD8ULL,
			0x435F8C095468DA55ULL,
			0x4A117361DF2FDBFBULL,
			0x431064C4E4F81C69ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCDEAEEEBDAFA033FULL,
			0x84FD0241506036A4ULL,
			0x22DD1110938024F1ULL,
			0x66D1241314CA0227ULL
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
			0xFCBA70FEFA169390ULL,
			0x53F37B1DA1172DFBULL,
			0xAE6AC1D0FBCA1BD3ULL,
			0x4C1CFB96A52CF804ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB0789462CCDE88D0ULL,
			0xD5489DFA0F199CA7ULL,
			0x357F9C05E290714FULL,
			0x5482CA07280FC22AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDB86A97F0A3BA816ULL,
			0x9802BBD8E4DE65A2ULL,
			0x8D4E1FD26037CFA7ULL,
			0x20743EADEB73C263ULL
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
			0x22F1DF19E77339B8ULL,
			0x99F25D9BA083935BULL,
			0xB79C459BF6E10C2CULL,
			0x7CE88554366E4B86ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x601E3FD7E9AA29C8ULL,
			0x8116CCDB284F669AULL,
			0x3BB30CF00B901D1BULL,
			0x6D88DB712F546C01ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x032A5A25CB840C27ULL,
			0x8E61A5DE5A3F64CCULL,
			0xCB36F423D6370CE5ULL,
			0x1DCEC82FC943D79CULL
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
			0x477A927DAD1A37E8ULL,
			0xE99D2F2EE8DF86CCULL,
			0xECD4AA2142809430ULL,
			0x70867BFBC5A8E683ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEF398F9DBBEDC920ULL,
			0xA78A239EE4238CFBULL,
			0x57CAFFDE37DF15D8ULL,
			0x6561D07DF7FEE0A9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F962C5D8CAB78DFULL,
			0x52014F2F23B002E5ULL,
			0x3E2098CBBD40DD50ULL,
			0x7374BEBF586631FAULL
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
			0x7F08C045A08536C8ULL,
			0x848AC71679C6F08EULL,
			0xB492FA6390F1065DULL,
			0x775AD066FCC1A8F8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x31D3F0A475174CE0ULL,
			0xB048681BD0DD7CF0ULL,
			0x0194E05FAB795911ULL,
			0x7A6D578AC168D547ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x827FA700142F1599ULL,
			0x4E91818D6E72B76FULL,
			0x0903192E23F869B9ULL,
			0x7A16BE7C34E4A2ABULL
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
			0x772C0CFB7E7E8580ULL,
			0x5BAEF443A077D616ULL,
			0x3EB45E9D718E7FFAULL,
			0x46B51B49CA1CFB0AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x287647C59D4CB948ULL,
			0xC3094279798EC2BEULL,
			0xA0E275F19A020FD0ULL,
			0x647E810DE308428FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8EFA12C1FE845EC5ULL,
			0xCE0AE48F41020885ULL,
			0xC5898D50703997FAULL,
			0x0CF187E5390EB3A1ULL
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
			0x8BD774AE976473B0ULL,
			0xF48FF720CFFCA397ULL,
			0xB322F8E1A5F523BFULL,
			0x7C5C5383D6354D3AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1C1796A7A8AD8D58ULL,
			0x825222CA635A6195ULL,
			0x9904B2FF4470D7EBULL,
			0x4C1DFCF4E8D0477BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6AA949C4344B38D0ULL,
			0xF1DE234085F9C197ULL,
			0x1870D4A58A4F307AULL,
			0x09244B4B74A3470BULL
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
			0xCC876EAEEBD8A880ULL,
			0x388217FB18A45C5DULL,
			0x767F1CA5DD5A52ECULL,
			0x49825D24A1F04F9BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD32754B46074D0E0ULL,
			0xD71B6C3FAE27BC4BULL,
			0x9DFFFB6B862E79BAULL,
			0x6CCEE1CB18F865E2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF90213B192CA5E56ULL,
			0x203E87708287559DULL,
			0x2754633428630F95ULL,
			0x299E9ADC49692327ULL
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
			0xE5A8530A2F0D36C0ULL,
			0xC538A186FDFC3E32ULL,
			0x3505BDB1AE617C5FULL,
			0x4C00139B9C16B0ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA4E1D9759F2E7ED0ULL,
			0x4F7F651EAEA94FE4ULL,
			0xD311BD04EA1B4CCEULL,
			0x7AFFC86BDB6721BDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E2A032457AC070EULL,
			0x5F67C220B59C17AFULL,
			0x7B09FAFA2F27EC0FULL,
			0x1A4D61898AB964CEULL
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
			0x7B9BB870622BF4E0ULL,
			0x1E3B55BE4C491B0FULL,
			0x0D1A9A8A0D9C77E2ULL,
			0x54A15F30DE817361ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x50B8EDE3BF837EF8ULL,
			0x5BFCDE9EDF6B3D12ULL,
			0x82CCD5A6A03A6F36ULL,
			0x5A7863F5EBC0AAB6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF19C90C3BEFD185EULL,
			0xAF156480C3620A4DULL,
			0x15F67B8CEFF2E3DBULL,
			0x29C8E477147925B2ULL
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
			0x361D47837C0AB9E0ULL,
			0x575ACEE0DBB33A59ULL,
			0xDFB01EFD98A88B74ULL,
			0x760499B580D0E9F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF7E22ACB65728538ULL,
			0x2E8866FA1D558218ULL,
			0xB7F7D8539CB1FD02ULL,
			0x53B901BABEBE1D4DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEAE7E6F40C7ECD16ULL,
			0x5C6F8C6523B176E6ULL,
			0xBD675F8CAA5C188FULL,
			0x42FB4C9365548A00ULL
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
			0x62E00D464F2FCE88ULL,
			0x925AE8DFB56EE5FFULL,
			0x04C1019459A49C18ULL,
			0x5DBD2612E0287299ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBBCE46A3D3EA24F0ULL,
			0x1C2E49C075E3EC79ULL,
			0x2B6671F06A8FB82BULL,
			0x7DC98AD238C76DFBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x92FB1BEC50BE41BCULL,
			0x8A0D6F4C4D030738ULL,
			0xB49EECA1B69D3DF0ULL,
			0x07334A6FA4A1DF13ULL
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
			0x280F8A99D0345580ULL,
			0x61FE9751D42BC775ULL,
			0x200731C64B9487ECULL,
			0x6880909F671769AAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4BA9F32ECB1FD618ULL,
			0x95FF769474CF027BULL,
			0xCC9D16193A04190BULL,
			0x6E32880E8B96F36DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF413057388DED319ULL,
			0xA874D3A3119687E1ULL,
			0xD0747E52AF2922F2ULL,
			0x0C686F7A508D2DAFULL
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
			0x01E35109410C75D0ULL,
			0x66B70E209BA5314CULL,
			0x4728E071F9CDC5BDULL,
			0x4F6ABE2835B2977AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE2E7DEE4715022A8ULL,
			0xD9506012896F7677ULL,
			0x0FB7990DEC89DE5FULL,
			0x45D85F858B45D8DAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE1D585FFD29D7DDULL,
			0x3F0B0ACF5DAF8A13ULL,
			0xCE8C01F813EA3A3BULL,
			0x72DE49E2AA1FCD92ULL
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
			0xBACA45224D54E310ULL,
			0x315D179EF1AA2A08ULL,
			0xC25A9A2E80E3C33FULL,
			0x4B69906FD5AA5FDAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB289FFEBC2EC3430ULL,
			0x63C3931C8750EC7DULL,
			0xA17919AAB20C39C2ULL,
			0x5AAB3E0101D25B92ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5158F6DD38B4493EULL,
			0xF7AA309442159726ULL,
			0xE458F746FEF26B1BULL,
			0x0C774FE76FB23E0CULL
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
			0x3AD43EB0457F16C0ULL,
			0xA82C40BDAFA79025ULL,
			0xE7BA744E48C5FB33ULL,
			0x53686F6CB2709A52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFB6B6F1F76FDF3E8ULL,
			0x980C1AD229891DC7ULL,
			0xA1DB4F1B1ED4F86CULL,
			0x7F266C173BB328C5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F0920DFCA318A37ULL,
			0x21BD09AABA8E9E0DULL,
			0xC76C2804BB573371ULL,
			0x38B5C0757AD85ABBULL
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
			0x55EAF48CCF9188F8ULL,
			0xD1ABF0600690759EULL,
			0x181B6D8B9018E97BULL,
			0x5EFAA5F24634C432ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCB2138EC6575E440ULL,
			0x5686C92E65E9FA85ULL,
			0xC848330D7879DE1DULL,
			0x552CFF61CFDCB5A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4929EE7C880004EDULL,
			0xE186B4E74A73CCFBULL,
			0xB7C760A0F57EB556ULL,
			0x0BC8E0005F6CAF10ULL
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
			0x1BE23C271F2B4D40ULL,
			0x07B8A77BCE9610D7ULL,
			0x47329EC460D2CF86ULL,
			0x4414B854037CB801ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6399CE0425BF6DC8ULL,
			0x149965EDF60D47E9ULL,
			0x427F54C95E88B279ULL,
			0x580DA58018D068D4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9E1D93221DDC6FDDULL,
			0xE06C78C2520851C0ULL,
			0x3DEBC3F82669D562ULL,
			0x604B4686A36303B4ULL
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
			0x57C54DA38E0D21C8ULL,
			0x4E4E2FDD8DFC866DULL,
			0x70AF67AF9391E2A9ULL,
			0x51AFB136184A4B2DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3596E872B656740ULL,
			0xF1096978C4203F50ULL,
			0x33F5438FC54F1D40ULL,
			0x70E35A2D69459EC7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB7C719C0F183F945ULL,
			0x6139F9856024207CULL,
			0xE75D36C1D1C51D65ULL,
			0x24F3349A8D95C01BULL
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
			0xAB1E0F02433F0338ULL,
			0x1D4F939736B4AB07ULL,
			0xF2A0E16F70F8796EULL,
			0x6DC86C10203C026AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCC55B332652A4E20ULL,
			0x8516BC4C5366691CULL,
			0x22D7216B728DD57BULL,
			0x414D34A8F2683E36ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x615E10D39EAD57B1ULL,
			0x4D6E910B26B34F00ULL,
			0x3A67650062DA3E70ULL,
			0x1827F600D8472CEBULL
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
			0x02313E3851B098F0ULL,
			0x46C3954724D8BB21ULL,
			0xBAA815467BA4D282ULL,
			0x50A0CBCD8BBDF9ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5E00A0B91F38C350ULL,
			0x2BE0564DE7C27B7FULL,
			0xD965AAF9C1BFEDA1ULL,
			0x5B64D3C85EF2D800ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A282D8F81546FD5ULL,
			0x5DBDCAD91AF10F76ULL,
			0xA80549E20C05CF56ULL,
			0x76978B396EAB9E83ULL
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
			0xE17852870EC926D0ULL,
			0x049147CD84580732ULL,
			0xC8F1BA998AAAC982ULL,
			0x738939256D715489ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x193E25F6894628D0ULL,
			0x4AA29CACC1C54FFEULL,
			0x8C8FB2E6FFDDEFD4ULL,
			0x7ADDDC6820B5C9B0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDD4EECE54D49FC17ULL,
			0xF64A799AED84E0FBULL,
			0x55C990C20E641E15ULL,
			0x468AEF8A25225B5DULL
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
			0x9A37FA393D7E1740ULL,
			0x0C7F0B59002DE171ULL,
			0x9921E5974B401C28ULL,
			0x7A94AAC6057EC7CDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCCE2F2C5311DA918ULL,
			0xC2B826B8A3D323CEULL,
			0x352A792B0E52DEF7ULL,
			0x469EB3307DBADCE4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3A9295F6910D349BULL,
			0xF8182039000987D5ULL,
			0xCEBF7886AB54B42AULL,
			0x4DE14EF077B90094ULL
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
			0x0AEF37543CB36ED8ULL,
			0x005E9EDCF0F43B44ULL,
			0x388122AE5C353ADEULL,
			0x602D350CBB005A8AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x95E8349D80F61218ULL,
			0x3664C48FD82BCBC8ULL,
			0xE902EBFEC57F78BAULL,
			0x7E00A76589AD5F4DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x29E9E124072AB19DULL,
			0xBD16CC1BF1490F16ULL,
			0x20FF121D5DF9FBE6ULL,
			0x5CBE2C950E3ACE4BULL
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
			0x97341B3CE9B03B50ULL,
			0xE39B7F0A3FE4B9D3ULL,
			0x89F19E402B60109FULL,
			0x5D8DC2788CE02994ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF877EDD500B0E030ULL,
			0xC1465D6A0901B590ULL,
			0xE7945805C60FB21EULL,
			0x64C2A488343BDBD6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE1BB251E5E0283E6ULL,
			0xB681AB9E3751F5CAULL,
			0xDC2A5348251C0389ULL,
			0x0893838C1F08D167ULL
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
			0xE2328ADEDDA8FCF8ULL,
			0x529FB7229FD402B9ULL,
			0xFA2AFB5DEE9981F4ULL,
			0x7944ED49B1BDF95AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1117C4C2977DE628ULL,
			0xCF33ECA570FD3A21ULL,
			0xEF1914D231214833ULL,
			0x728C47958D69D546ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x17E1C685A3D25783ULL,
			0x90108FB1A217C8DFULL,
			0x848572BA732BB14BULL,
			0x524CD8D8E99CF3A8ULL
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
			0x9BF5C18CA39D8CF0ULL,
			0x56FC9D7DA47CEA34ULL,
			0xC8761DA578ED329AULL,
			0x41B6478E9A3DE98AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x00022A35A357B448ULL,
			0x87F33314BDD15B59ULL,
			0xEFC649A36A09D879ULL,
			0x4E006F26BDB9E514ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3E78F6F8701386E0ULL,
			0x49ADEDE47C7196A3ULL,
			0x095ABC7A2EB6054CULL,
			0x7970367E37EA7794ULL
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
			0x11E2CCF1934EAE18ULL,
			0xEC79263AC5473DFCULL,
			0x18782692814D2006ULL,
			0x40E4593038F062E6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x237D87C77F8F5DC8ULL,
			0x8B058A4BC56D93F8ULL,
			0x5061FBA44126506EULL,
			0x4174048351D64AB1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3653808D6B74FA8FULL,
			0x3A241AD4411B5080ULL,
			0xFB9783F5974BD02BULL,
			0x714C4CAB91FDE78EULL
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
			0x72AB33F4B021A0C8ULL,
			0x4244A0C7C92B6A78ULL,
			0x39599D04B851FAB2ULL,
			0x5DE7AB0CAB62490EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDDE18214F9215D90ULL,
			0xE9EE4E41690CC053ULL,
			0x0536E1BA159F5D2CULL,
			0x5375F9E1FE4C99E5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB41C1164C2FAC936ULL,
			0xD3F97E4099E0B692ULL,
			0x5CC5A7D388B2A48DULL,
			0x54567B335A39C904ULL
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
			0xA4B84B1459DE4ED0ULL,
			0xEA5CB4D07645B127ULL,
			0x6EF53A6235EAD343ULL,
			0x713F08A5626B8019ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x33815A56D85D2A40ULL,
			0x4B962F54567E33E2ULL,
			0x843A8FC8D9F869F5ULL,
			0x7D4A43B617F36575ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x555EC91E4D939E34ULL,
			0xB1AA24B34D660CBDULL,
			0x413034D929A09E25ULL,
			0x05F3F05E316D22E8ULL
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
			0xA62A8A2D47F29D70ULL,
			0x5AF7613859D53DDBULL,
			0xD53358DC7474DE63ULL,
			0x6EBEDAA06C034933ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDEC3058D7ED15CF0ULL,
			0xE463A50F216912B1ULL,
			0x60694164CEB902E0ULL,
			0x640F38ECA5914D12ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD35C56AEC7B16C25ULL,
			0xFA5F39D8E6AF7BC5ULL,
			0xF40BACE3B7522165ULL,
			0x393A6C8F61896CD8ULL
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
			0xE9749752A0AFA670ULL,
			0x7C0163AFCF522674ULL,
			0xBB0958B6C8C37E3EULL,
			0x5E2C3884CEEA9E19ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE73224E29711150ULL,
			0x798D74BC78960570ULL,
			0xF78E17F9B3046311ULL,
			0x77C29D2A475FF8ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x966430C7515D3430ULL,
			0xEA31204832F4734DULL,
			0x615325BF401632E1ULL,
			0x363E2CFEA663A0AAULL
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
			0xF2D2B43F541605A8ULL,
			0x3B1CD99D2E90B607ULL,
			0x02D682BE13F24AC5ULL,
			0x5572ED513FBC0F19ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7A8F55D7EF46D4F0ULL,
			0x240CD8C7E9A77B53ULL,
			0xBF316CA49B4D664CULL,
			0x6CC2F31C4E9FB136ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1B23135EA7F26ADAULL,
			0xD8C9D1C1318E0A85ULL,
			0xC8E121EE4FD15223ULL,
			0x285AB10107D9AC53ULL
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
			0xE44FAD4898BDA368ULL,
			0x24FDCDFF0A5D023DULL,
			0xF5E7179DAE2FEB0DULL,
			0x5C708C852D14A440ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB16C768E2C3E218ULL,
			0x90EA3C48F69F5ECBULL,
			0xBEA9DA0618476966ULL,
			0x4A5B0DA82B011262ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5EE8B6EBB56482A7ULL,
			0x9B1B319AADE4D7ACULL,
			0x16488EB433A13550ULL,
			0x06A97BF32F4CFE32ULL
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
			0xC1088C6798109238ULL,
			0x186BF8BF1266A7D5ULL,
			0x9423EEAF84B4332CULL,
			0x4F90BC45C5669A22ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x209102E0DB678AA0ULL,
			0x157D76231ABBFB4EULL,
			0x2DDB242D3205FE5EULL,
			0x54CFF47573B8A1C8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x990A1BB8BCA3CCA7ULL,
			0xBB7D6CACC5123EC6ULL,
			0x20A7326DE7F958FBULL,
			0x56F6A215CE1AEB34ULL
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
			0x12D3B101D0644EC8ULL,
			0x9A79899B7365080DULL,
			0xCEF00DAC98969C7FULL,
			0x620B1A93A9C3EC13ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFDC90C8F942C2988ULL,
			0xDDB6A731D4A9A50BULL,
			0x5ABF6791639D9091ULL,
			0x613C8FABCB90E4FBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E0B89DBBEB0B868ULL,
			0x6A5A08FCBA6DDFEDULL,
			0xEBF2A4FE38C7D567ULL,
			0x7F5B55D4BCAE7EC5ULL
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
			0x9FB57B08B1EFB470ULL,
			0x273EFA8D411ADF3AULL,
			0x8A46363156436F60ULL,
			0x6A04D972C0985037ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2918E2845736C360ULL,
			0xD1B9C7F6A74541A1ULL,
			0x887FE1574CC50A48ULL,
			0x4196D3B65AC863DBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFCB7687093AC72C6ULL,
			0x40AEE51AE9A09415ULL,
			0xE14209145AACAF3BULL,
			0x315A1C1A020230B7ULL
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
			0xC22B04EF6C8E03B8ULL,
			0x5DB0D3B1EF4E37E2ULL,
			0x28FBE8337FE16F1BULL,
			0x4A726C04238434C4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x311EAE5CFFA9BDC0ULL,
			0x27AA7AE5D9FD85FAULL,
			0x5A93D40F15D4ADB9ULL,
			0x4966EEA5A9B5350CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2B29BA5A3F139F50ULL,
			0xF8CA1095656DA6AFULL,
			0xA44C96CA57146ABCULL,
			0x3C11238E1D7AC09EULL
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
			0x935D17675C045278ULL,
			0x27FDC0B579CE25CDULL,
			0x0067A716DB02B150ULL,
			0x57E5F26469531CC1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDB362BB797876A30ULL,
			0x50D87E9B61328F07ULL,
			0xC3CEDA3FE8145BE7ULL,
			0x578294C353419C68ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x502C6645043B3243ULL,
			0xF2C843CDB13B2AF0ULL,
			0x0ED20898D8D58436ULL,
			0x4F480D5DD83BDBE3ULL
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
			0x22CBF4AF9D036E80ULL,
			0xFD0C1C77FEE5BEF6ULL,
			0x155E69B6BA0417DEULL,
			0x7D3F9279443159F0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x41A7CB0914108C98ULL,
			0xADE3C300CD482FA5ULL,
			0x51D9E9EA032B9973ULL,
			0x581F2DDC2438F822ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8B848B5A994C3D0BULL,
			0x08B9FC6A12D8C371ULL,
			0x18B32FE145C2DC3FULL,
			0x053F795682FC6F72ULL
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
			0x85C564D395C8EAB0ULL,
			0xEE25515E9D5518A0ULL,
			0x3CF349C81A532FBFULL,
			0x636A8B699111FC67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7F07BC46E89B1370ULL,
			0xC8B5EFAAFF63D4CAULL,
			0xA2EAD5C0FFE21E97ULL,
			0x5D49E418AA175050ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x279F7787AD3A9A32ULL,
			0xDF4257C18CF5DAB6ULL,
			0x5FFC16A30A0931BDULL,
			0x27BEC1FE0EC51EB3ULL
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
			0xC4D28F9491B8D1A8ULL,
			0x09A67301703EB24AULL,
			0x6BEEC4B08BABBFCEULL,
			0x6FAA271318532E79ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3D6057E9066BA48ULL,
			0x95B05AD19388E59DULL,
			0xA21C780D1F43B235ULL,
			0x69AEDA66FBB23A1FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x02C37BD00173AF46ULL,
			0xDBF9A64E7AC68B9EULL,
			0xD0D36C99A71CBC3EULL,
			0x4DED4D0B3AC6FBA5ULL
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
			0x1E952497220FBDA0ULL,
			0x727931D1343B0516ULL,
			0x737DCF1F16FF19B6ULL,
			0x71EFD5AAE2237160ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x803BDC91E0CDA578ULL,
			0x69F9E9E00EA70CECULL,
			0xEF33DF33E5109C8FULL,
			0x62ED2DA12601C5D7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x81ECE23276C02181ULL,
			0x0F3FF6BE1B6413A6ULL,
			0x074B78BA8A3C7E47ULL,
			0x651B3D238F1C46FFULL
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
			0x6B22038C3A3D5E98ULL,
			0x131496CB284C16C3ULL,
			0x7AE2F8C6B1A854CDULL,
			0x61B3111155DC7951ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC8A0931936A438E8ULL,
			0x2CA2C77CC7E4853FULL,
			0x26E63C16C6079BDEULL,
			0x50A1762F6012A1BEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE29A73D8D29D220ULL,
			0x8E44281F18FC11C8ULL,
			0xC1AF71D1145B80BEULL,
			0x41AA1427089F098DULL
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
			0xBC9A54E08E520310ULL,
			0xDC0A32E23E2A8000ULL,
			0xEA1D3169CB7243ADULL,
			0x5FF1BDC8B50025B4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x28AAD37EC3E330E8ULL,
			0x22E67E801D6A412AULL,
			0x12618C2D7C78F7D4ULL,
			0x773398F687936D1EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x03BBC10399C8C6F3ULL,
			0x5FC269537BC08FB9ULL,
			0xE88194B9179AF141ULL,
			0x4EDBBC014EBFEBB5ULL
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
			0x335B5C07EF887B48ULL,
			0x0B4B5FAC89B74594ULL,
			0xE10E6CBB8FB8CFB7ULL,
			0x60CD0C5D0CC37C0BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C8460A2C62CF8A8ULL,
			0xD942A31D95D33279ULL,
			0xD725ACE9312D1997ULL,
			0x52FF2CA97DE79B35ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFE76EF71135F0119ULL,
			0xE5D121DD52C8766EULL,
			0x4327F0767BDB4C9DULL,
			0x7DDD2AD9D2802517ULL
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
			0x7E64783E7B9BA758ULL,
			0xC848B1C5699E9E2EULL,
			0xACC528BECF294ED7ULL,
			0x5F84885188ECD194ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF7A8AE8A898205B0ULL,
			0x0C19EA89490163B5ULL,
			0x88D4500BC478FF00ULL,
			0x565714AB5B9B01ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0D42287E3307D737ULL,
			0x3427BC708B78CB70ULL,
			0x8159C3B5B4827B67ULL,
			0x1E35241D06439D21ULL
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
			0xB91256D25F3E5B00ULL,
			0xD6899F18295F36E9ULL,
			0xC1ABA90AA9E9173DULL,
			0x65262C47F773EF4AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3EF87F6F37D36C70ULL,
			0x897FB407C16882EBULL,
			0x5D386C490751CD66ULL,
			0x76EBBCCF9B45AE5BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x27A32D22D8880A9DULL,
			0xC857645DD27356B7ULL,
			0xC2C07A257FC99B71ULL,
			0x54FE58C568D48846ULL
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
			0xD6A2A71583B28610ULL,
			0x02DAA698BE195EC8ULL,
			0xE0F7B296C9FD67DEULL,
			0x69959BBC1F352F79ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x254C6E90202CB838ULL,
			0x93BE71CB0ED198EDULL,
			0x2981D9BC770BD6F4ULL,
			0x5D728B073905DDB0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x638E6A7FEA204EEAULL,
			0x6EA006C457213FF9ULL,
			0x5A70186600456DE6ULL,
			0x3FD400DBA3D5A054ULL
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
			0x30324F83E3249E28ULL,
			0xB59F5BCE1192094AULL,
			0xA329F7478AA5AFC5ULL,
			0x4B7AC3D6890AF6BDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF95B992DB78597A8ULL,
			0x970162E56E95E0CEULL,
			0x7DC5B6B3FF34C109ULL,
			0x6DA7EFEE13939372ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1C4C4EAC886A20D9ULL,
			0x2A9BFA3A2EED068AULL,
			0x0400EB59204E5D28ULL,
			0x5B37F2CC77CCE62DULL
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
			0x69F88D562BE602C8ULL,
			0x9AF9E0B90563C0F5ULL,
			0x58BBC67F84AA2808ULL,
			0x60CE88B38FE4D64BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC1C5C83FB69A0C98ULL,
			0xAE2271CE492DCB08ULL,
			0x6F3ACA451D6EC089ULL,
			0x7C1A91C81D331123ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE9D27AEEA5F4A645ULL,
			0xDB262F5D50D7CD2FULL,
			0xFF9A00B76926291AULL,
			0x7CDC75CE081DD89FULL
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
			0x163D8B822B13AEA8ULL,
			0xAB3BC3AAD326FF7EULL,
			0x0730172C699D11FBULL,
			0x711174A91DC7A546ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x879BEDCC23789220ULL,
			0x0F2BD493634C6825ULL,
			0xB47972AE18C08BE4ULL,
			0x42278DFC238CDC41ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC44A1C2F649784DDULL,
			0x5F8337050930D9BCULL,
			0xDD0F85A499680443ULL,
			0x467D768BB819D7F4ULL
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
			0xCCC4A017DC494E18ULL,
			0x090C096C6155D090ULL,
			0x03430454CD0F8C73ULL,
			0x46E9C46D13B5A218ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA4A16D4A1E0DF468ULL,
			0x19D7A3F6F9A9DB60ULL,
			0x1B88CB3E62F7B1FDULL,
			0x6C2E0DCBB4AF1D22ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x296FBDA9F359B458ULL,
			0x333996A53483F2F3ULL,
			0x5D2DE9B7DF620A71ULL,
			0x385CC243BF503EB8ULL
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
			0x43320BD54A42F3C0ULL,
			0x7214EF1A8E3FAC86ULL,
			0x789D25F1E2D46BB0ULL,
			0x6C2B15A61B95133BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54284027C6164A38ULL,
			0x6838F456FE074FC4ULL,
			0xF6669873E33ACA56ULL,
			0x50556915271A750BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1814DE5F3F10B04BULL,
			0xA085B311D94E066EULL,
			0x6C1887325973F8B0ULL,
			0x6AE609D928DE24A5ULL
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
			0x11EBD93073F44C68ULL,
			0x00D9D5D0C448F64AULL,
			0x098FDD936E0EBDC2ULL,
			0x6543E5D21BD07548ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x694BAAB908DF6660ULL,
			0xEFF00EF9D15F3DE7ULL,
			0x9103CA6F3012A428ULL,
			0x7B2A081156BD8251ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD93A8CC477DFB6B0ULL,
			0x473224E5BD7B56C4ULL,
			0x1D221B28BBA6BB38ULL,
			0x4FBEA91C5ADFA679ULL
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
			0xDD46D3BAE4089B48ULL,
			0x1699BDE89121B156ULL,
			0x9A84868E49A9BF5DULL,
			0x5507A5B371A6D813ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAFD18403610DEE88ULL,
			0x8A26852146356B86ULL,
			0x2AE27641ED4EA084ULL,
			0x4801A1CCDC3064C4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDF28E4A55EB3C730ULL,
			0xCE69008F4090D5A7ULL,
			0xFA3382606F27206FULL,
			0x3E588BC7101F5843ULL
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
			0xFBB2C79EC53F7530ULL,
			0x8B325DD7813FBADDULL,
			0xCB533BC6326D92F9ULL,
			0x48E48110238F2517ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF4D3B46232C24050ULL,
			0x994317B49BCE6384ULL,
			0x4EB851CFBA9A539FULL,
			0x77EB197CBA0CD67FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD686660C8AC2BFB6ULL,
			0xD781C416DD06119CULL,
			0x35779341ACB6A67EULL,
			0x4757EE35E99596E5ULL
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
			0x9B64056B7D76B278ULL,
			0x53C5382F3A69C066ULL,
			0x8C70DA4F20B0D58DULL,
			0x6E25415B467A1ED5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x06D9CDE9291B9830ULL,
			0x0D7F138E65ABF3A9ULL,
			0xD671DC0396BCB5F6ULL,
			0x5EA0BFA700B6D327ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7406E439D47DEDC3ULL,
			0x8785664FB5B3D9EAULL,
			0x00994935A886D2FBULL,
			0x4AC2E0D3594B6EA0ULL
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
			0x728A49C25CCCD240ULL,
			0x9099DF7F7DF2E239ULL,
			0x9C16657318E67FC3ULL,
			0x7D516044BDEFF365ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCC56172E1DA03BE8ULL,
			0x4EAE2C561A717EE0ULL,
			0xD30F0325E2F37412ULL,
			0x5280B76979DEC681ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0451BEF43EB53E5FULL,
			0x3D4034DB88B5C8B6ULL,
			0x226F720323F89F88ULL,
			0x4D13B3FB17941E80ULL
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
			0x71F768F0514C24C8ULL,
			0xE335DE7F6423357DULL,
			0x129EA8C3D1332CD0ULL,
			0x6C70CF392C467B45ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2469DFED27F239C8ULL,
			0xB3EC4B9B15DE4E09ULL,
			0x891AC2B0E3E65E14ULL,
			0x5C59688A72533D21ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1B5EF171A89E501CULL,
			0xAE555A1EF705B104ULL,
			0x178CF0844AA4FE8EULL,
			0x5F77CE947277905DULL
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
			0xB8B69A3EE18BA528ULL,
			0x752021AB18538614ULL,
			0xC5F565964A87164DULL,
			0x4A6E136AA12B24E8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE367B200B58F8B28ULL,
			0xB2DAAF06FE1A5DCDULL,
			0xDB2ACB215EF984CBULL,
			0x52417133B6CC47F9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x67029AC1F0BD72F7ULL,
			0x1AEE5E6924FAB89CULL,
			0x9C0EB2E0192A3AECULL,
			0x78DB16C5F49A0278ULL
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
			0x9CD071825E95F440ULL,
			0x6FAE52FCABABB804ULL,
			0x8E060705D66147CCULL,
			0x53343558EFE6D4B7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x47B3720297316AF0ULL,
			0xD0F343ED906B2D5AULL,
			0xE4F405C853EC4ACEULL,
			0x5CCD86C6BA371CD7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x53B2926BCB726405ULL,
			0x78ABFBCC29CFEA1FULL,
			0x7D6D4E26E9FC6FA5ULL,
			0x4C3176210EC28694ULL
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
			0xF14024C778425AF8ULL,
			0x014803625223566AULL,
			0x3069A32F3514A439ULL,
			0x4A03D0148B21F227ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDF8E948F0139C620ULL,
			0x5FCB685441E770E2ULL,
			0x43F4CD7892B49A09ULL,
			0x64ADDF5A44E58408ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F0084D0DE560EEFULL,
			0x01BA18BA12379881ULL,
			0xE6E866755392CDFEULL,
			0x0692C11DD1E6BF79ULL
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
			0xAD726D1CE5FE1B08ULL,
			0xF21E7CDAE926D64DULL,
			0x0055C5789CA94332ULL,
			0x517462D45A37E610ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFFF6627ED85EAE88ULL,
			0xA555A240959EA935ULL,
			0xFE71B9DBD2A510E1ULL,
			0x7A343CC60B9B0A3CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x04902E2E4B0984D9ULL,
			0x2454C59B1DB6F340ULL,
			0x5D33623A8A38CCD1ULL,
			0x794B205EABC89787ULL
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
			0xC23F2788E4CD2198ULL,
			0xC80713099ECED730ULL,
			0xEBED27A4A93E1A15ULL,
			0x4D378AB1C6A2FE3BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA85B395BD4B61920ULL,
			0xFD55B84153AF4755ULL,
			0xA233C23CD72C0E94ULL,
			0x5B0953888ACA3732ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0E58B0DF71FD641EULL,
			0x7E5383BCEB0EF994ULL,
			0xE67E97D385894B8BULL,
			0x04AD16F8C6638F28ULL
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
			0xA6EBC7BB3DE602B0ULL,
			0xA603F97E06EE99ABULL,
			0x42C8A717C556019BULL,
			0x41CDDEACD1C8236DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0C6B0A55F5CB9CF0ULL,
			0xEB42509371FAFCEFULL,
			0xF431DF2D796B2CAEULL,
			0x419581229CFF91DDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2D521EF1B8E21F31ULL,
			0x000B782B146D3350ULL,
			0x2864D8DBA43E7C7BULL,
			0x2A0039C87E0C943BULL
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
			0x9A738BC1886D5880ULL,
			0xC2B0D8C4BFA05FCAULL,
			0xB0EE8D5C865ADCCCULL,
			0x44A47E6A4B2152F5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEA7C14EB52B25008ULL,
			0xEDD11D7046C0383AULL,
			0x6D20108C352AE527ULL,
			0x676D35BB7EF0B6E0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x32203D5ED390EF25ULL,
			0x9B221ED701CD6A3EULL,
			0x097B7E839AFA3CBBULL,
			0x68E98C0FDE908CAEULL
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
			0x0EBA91D5CFB8C330ULL,
			0x40C0B3F3FAD2DC8EULL,
			0xB74B3DDA0F54A3F0ULL,
			0x797983AC94D51B41ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x29ED11F87EAF1B48ULL,
			0x222DDB6C4D58DA20ULL,
			0xBF84EF38E8BD8466ULL,
			0x4AB328F833851041ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x50A61E2A28E5550BULL,
			0x3C154DD79A97C7EDULL,
			0x774BBA139D65959CULL,
			0x3A147DB02DFB7809ULL
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
			0xF1B5F0ABA7381D08ULL,
			0x1DC8C0A19F7B6C2AULL,
			0x7DE463717CB624C3ULL,
			0x7F0C0E610E7CF83EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1669C8149A25B2A8ULL,
			0xF7E8E871C3164969ULL,
			0x537BBEF8368751D9ULL,
			0x64306FBAD38EA656ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9285AFBFACF50233ULL,
			0x32837961B282919AULL,
			0x38656A7FC3FE35F2ULL,
			0x7B6E77523F9CBFDFULL
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
			0x995B2F86613846F8ULL,
			0x5D0C925F2A5F3D5BULL,
			0x747B3EE0709D31F7ULL,
			0x7F93F5D81B17DF32ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4EF5A60B901C8E70ULL,
			0x3ABC573C7FCB3199ULL,
			0xBD2EFD9ED1DBD33DULL,
			0x776ABFA2C48B53DDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCFF491B6A29175A5ULL,
			0xEDF1E53F26AB293EULL,
			0x27E52DFF91BC9680ULL,
			0x329A3A93240CA916ULL
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
			0x47925F1CDD471D50ULL,
			0x9BBA5C8C86FD1A63ULL,
			0x501442C5455BAD51ULL,
			0x69B8D479FD05211EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2EE84D319564B228ULL,
			0x76B1D4D19DC198EFULL,
			0xF04332AE6173585CULL,
			0x60807CFB68A47A3EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5F75890349B4EF5AULL,
			0xFF382D5822BBECCBULL,
			0x08AB21BF0A5A16DEULL,
			0x082B32E3D56C0926ULL
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
			0x9C5FBE743C7CED28ULL,
			0x1000F75ADB6DBACBULL,
			0x2DFBAA914DA8D61CULL,
			0x7FEF563A9E46FE11ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2A8EEA9ACEACB878ULL,
			0xBDE61608A14979FCULL,
			0x47CA7519BCC6E204ULL,
			0x6858DF163C005656ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x510C827CC079FCF4ULL,
			0x73903F9BB117A3F8ULL,
			0x650C20845B894180ULL,
			0x11D139C6C01D91A7ULL
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
			0xD245DBD6AD2EDF10ULL,
			0x4B0D56E9F948C620ULL,
			0x73CF16212A2FE88FULL,
			0x60B4F5C7C0D4B916ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x45DD6C4EBB677CB8ULL,
			0x231205F714E39F38ULL,
			0xFC1FE5AEACCDA0ADULL,
			0x5192C983760C42E0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBA162D41A579B47DULL,
			0xF9C7C7E452A03013ULL,
			0xE0A62E0F7768B865ULL,
			0x14546EEC4232D706ULL
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
			0x7E14E38A3EB47570ULL,
			0xB739AF79EE1DAEACULL,
			0x050DADB8C405F98FULL,
			0x675BC25D5F8D23F1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x10CE192BBA391880ULL,
			0x717AEB67BA0D98BFULL,
			0x6E2870D0F424FBAAULL,
			0x77C77370F3596ED8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x780655EEAA75D267ULL,
			0xBC4C5932A587C27CULL,
			0x0937E13127A6ED2FULL,
			0x7B3320071E77D450ULL
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
			0x946A26BD3E6890F8ULL,
			0xE942A7A6C2640C17ULL,
			0x60DB737E3B4596E1ULL,
			0x76A05DA696F7CDD1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE7CD42C8BE4F6308ULL,
			0xF7BB41693112365FULL,
			0xB5D7B6D1C20A3D01ULL,
			0x64C28A4C5B554BA5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB600045BC9D5D0B1ULL,
			0x9DE792D4F7FBCEC2ULL,
			0x2275F095E7A162CDULL,
			0x2D2A587B42E555E8ULL
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
			0x80E56F484E7DF8F8ULL,
			0x4754AFDC2614E48EULL,
			0x7C7F094009C07612ULL,
			0x5F2BBE6A09F6295EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0BCE58AC950AF8F0ULL,
			0x0E2AAA711F38731EULL,
			0x4BF4DE34E73A5988ULL,
			0x4DE064C664715AA3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE66D05994FCD85AEULL,
			0x7FC483C658B83199ULL,
			0xF331031C3E058393ULL,
			0x18E5C7595E8F66DFULL
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
			0x89989043513E54A0ULL,
			0x094F619ABFBBF4E4ULL,
			0xEEA301C10DD69DBFULL,
			0x5A2151534F813F03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x223760F216E08980ULL,
			0xF26A81A83DF3CE63ULL,
			0x46A8EC7E97240D07ULL,
			0x475F28165BD4D134ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x04A9B9101ED4B2FDULL,
			0xD79C21EA15325887ULL,
			0x3D39773A83CC8436ULL,
			0x3D935872297B10ECULL
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
			0xAB9DE86640D74D10ULL,
			0x65A28316185201C5ULL,
			0xD69810B365D214E7ULL,
			0x6E55F6B38304ECC0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x854DA032BB253638ULL,
			0x951769D6464FAB2EULL,
			0x738ED0D68A154EC0ULL,
			0x419386A233C89E20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB7C18E8C5EF8F38EULL,
			0xFCB417161682F48EULL,
			0xEB5DE2F0565D5E14ULL,
			0x34A9023534865B0CULL
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
			0x39E090D5E07F9398ULL,
			0xB6B31FAF092C5571ULL,
			0xE4FFF09A13A27955ULL,
			0x68EBD716997D9C3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8643E7779642AF38ULL,
			0xC7ABA55EDA36AD25ULL,
			0x1B5925F3D0C1F2A0ULL,
			0x45AD7CFC5F76274AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8724B573733D156DULL,
			0xA5695BB2348C328BULL,
			0xAF0914B8DF4AFA74ULL,
			0x4A769043E17E5A49ULL
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
			0x60390C81F3A6DA00ULL,
			0x2BBD027DDF170A43ULL,
			0x53D9DABF21C53EE9ULL,
			0x7F6B9556C4FB6A59ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x11841E1798F02E90ULL,
			0x169245C85CB3C1C0ULL,
			0x93DD06EAA9727AC6ULL,
			0x7B22FFB0F576D5F7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB3D72BEF486E085CULL,
			0x2B68FE643D84F437ULL,
			0xDFC564DCEE00A80EULL,
			0x3EE3160C57043429ULL
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
			0x75FBC8E6CD840008ULL,
			0x6383F626B344CAB0ULL,
			0x6674EA2735D85C66ULL,
			0x4A18B7B0E61824E1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF1E5D809C6CF8690ULL,
			0xBA5B62F5ADCCB4A0ULL,
			0x8F33F44D0523BD9FULL,
			0x75F8BFF970A2F6EAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7B394C4A7E001EF4ULL,
			0x7629EF009ECD9DF3ULL,
			0x127D1788C63F843DULL,
			0x050939C281FE725CULL
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
			0x2A49651EE9DA3F38ULL,
			0x1DB8C6DA68AA3FA7ULL,
			0x9C6A490D6E4244E0ULL,
			0x78489A67B4C3EED8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE76CFBCC92C3B1C0ULL,
			0xAD1A5D0FCB57340CULL,
			0xE3B8B49EBA0CC77FULL,
			0x54ACF59683D7DD67ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBEFC1B3F81C00BAEULL,
			0x3C28E2E5C26A1161ULL,
			0xB7B40DBBBB240576ULL,
			0x322EF2754CBA406CULL
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
			0xF6018B39AAA41D20ULL,
			0x5A21F2DFEB33BB2BULL,
			0x98268DD67EA0AE8FULL,
			0x58AE7E7BA4BE6638ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54FC657628CF75B0ULL,
			0x47F0B5F70475EEDEULL,
			0x655C3BCF7DD90721ULL,
			0x59FDB37945AEAB9BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x09B1C139590C225DULL,
			0xDCB96608DF6C3232ULL,
			0x8D685661C4DD1662ULL,
			0x5DB71FA3687347A3ULL
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
			0x420938698C3EBE48ULL,
			0x393966995A0FDF5BULL,
			0x66EB01E933A9EF8DULL,
			0x52B7DD3A42CEC664ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE670F456772D8A0ULL,
			0xFE7188BB9F4AAA37ULL,
			0x52702D2EC4F0BB0EULL,
			0x618AFF231608802FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x284E2A2B54D67014ULL,
			0xEED53B1DB1DD6A63ULL,
			0x738C3584E3DFA392ULL,
			0x13CA09EDF41E868AULL
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
			0xD6C96633264C6900ULL,
			0x8EC73BADF355BB85ULL,
			0xE52A6AD93A85F1F1ULL,
			0x70F4DE360FFA8222ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x80303F6333AAE890ULL,
			0x9B7717C85FA2DEEDULL,
			0x5DFEC38DF4B77B97ULL,
			0x47167808ECA68515ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x41AB87E134A8CB06ULL,
			0x6CDD80D0DFDC363AULL,
			0x6B9A613503814F37ULL,
			0x28ACA849DB6E739BULL
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
			0x6BF77C993A3C6330ULL,
			0x3C25441827AC7E3DULL,
			0xB417D04FC0BA8FAEULL,
			0x6434E71940D75E62ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x12E11EEFE853CFB0ULL,
			0x0A71499810D5F68FULL,
			0x0DD6A2E2DF725BD4ULL,
			0x57DC5A9C87D29F66ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA2EF4F8B1B1EA5E7ULL,
			0x8D834FD6B6E600C0ULL,
			0xF5280C3D5B12D1B7ULL,
			0x0977CFAD7F135BE5ULL
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
			0x16041C8448FFEB00ULL,
			0xA0C180F5B8D336BEULL,
			0x828F083FABB64259ULL,
			0x7CFBCAD2F4E8D2F4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C42E651C6826D78ULL,
			0x82632E41B27067D6ULL,
			0xB82221707AFE3362ULL,
			0x70112AAEC59749ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFF2DE42E1AD92DD2ULL,
			0x2AD1A1CF4700B93DULL,
			0x73CDE708EEF9BD9AULL,
			0x08F98DC77107A5EDULL
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
			0x0255715974E71920ULL,
			0x944D16BCD341F7DEULL,
			0x2DA807E8E63F812BULL,
			0x531582B9CD3CCB41ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5C2FF16571B951C8ULL,
			0x8E8675319FDF19D5ULL,
			0xB39D8C1A417B7FC0ULL,
			0x78F3A33734756DC1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1F0BD227A09D2257ULL,
			0x573A499BF6C0A1DFULL,
			0x0920283EAADA9846ULL,
			0x5803810BEC63BB6BULL
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
			0x7157950289920028ULL,
			0x0AB7576301EDD8A8ULL,
			0xB007D7A0E82D3204ULL,
			0x7ED22EB38DB25A58ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB1658CA17BEDB120ULL,
			0x120D2DC68DA9FE97ULL,
			0x41FB06017A147303ULL,
			0x5308740B6595E7DBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC807E1D6CAD579F0ULL,
			0xBF158F55DD950859ULL,
			0x3D41DE3565009986ULL,
			0x645C9F67B63D9146ULL
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
			0x3F21517A9C364A98ULL,
			0x6EA54CE6A4362FB0ULL,
			0xB3043554B6294605ULL,
			0x6A3580F5DD25213BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72F403C30B40D870ULL,
			0x1C5CED2CB2B87282ULL,
			0xEDE4C8F16E89A15FULL,
			0x6A74CDC524FA62C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCFF50E1379AB346DULL,
			0xC4193987919252CCULL,
			0x28F470358CDC3449ULL,
			0x40E2E6075F0D7D6AULL
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
			0xC9E215EDCF7A6930ULL,
			0xF2225F4F91C6A345ULL,
			0x0F93EB44A48E1EF4ULL,
			0x53938B4EC5BF8B03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5909D6770CD79438ULL,
			0xEC1B14C5703C3C4AULL,
			0x5F7F88BD73FCBD5AULL,
			0x5B5FFC615A039DFFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE6CD325003E1B7E7ULL,
			0xD429EED607FA9636ULL,
			0x4250284BA0DF0006ULL,
			0x0192AE8548793273ULL
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
			0x3CA10092B060F1C0ULL,
			0x2904AD012883E0A2ULL,
			0x9F2F2B7DCE42B69CULL,
			0x43FE4ED72BE21770ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1B96DA67C9877640ULL,
			0xC0958C86079CEEC1ULL,
			0xDF6A406FE297F85DULL,
			0x60E28B2CBC191C11ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x86EC41652520F847ULL,
			0x47E18895BF85949FULL,
			0xB8CD0475C3E462C8ULL,
			0x39E827470E9E8C29ULL
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
			0x7F5E0B086CA96240ULL,
			0x08EB641DEBCBEE48ULL,
			0xA31AF610478750D4ULL,
			0x40E06E3570C85087ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB5C5698BA3049860ULL,
			0x886D61CBB3785E2EULL,
			0x07C7644B4E8BC4B5ULL,
			0x62FA970215BA9A70ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3C8A8CDF7F5452F7ULL,
			0x7DAD22911B5A5C91ULL,
			0xA9F311A917DB575DULL,
			0x14E2F3C56881D95AULL
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
			0xD221785490557010ULL,
			0x3C0F552AC0A3887AULL,
			0x3B67C3C5B58B7032ULL,
			0x63483C981E804347ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD0E868CD3A5D6AC0ULL,
			0x2642585F9F887263ULL,
			0x47D04ADAB684C038ULL,
			0x6AF6641C81EBEF10ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0ACF56C9E477AB57ULL,
			0xB291D9AED007FC00ULL,
			0x0839C7D7235945CEULL,
			0x77E0EB9C63EAB5E7ULL
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
			0xF9AACE7586D252F8ULL,
			0x0035C1CAB1C0D340ULL,
			0xDC692F255416FC1BULL,
			0x4178144D50806FF5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x140BB3C973A77ED0ULL,
			0x4C26555F3D9069C2ULL,
			0x9F980090FA2BB93DULL,
			0x6C3C0F3BF39B5334ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE81C0497FE3BC2ADULL,
			0x8C01AB9C3A918D12ULL,
			0x563E8D2F463F946DULL,
			0x1AE80D05D14D4712ULL
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
			0xA02A711BD7AA9100ULL,
			0x5C9F8074B442FAD1ULL,
			0x90FD158982BA20F9ULL,
			0x42619F0D6F16F99DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x78D43C98E3244EF8ULL,
			0xEE7C5B25F91C0223ULL,
			0x76FA41AC6ABF0158ULL,
			0x4BE2EF6AA8163D50ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x938EEBFEA039C384ULL,
			0x41CF349A51BC56C3ULL,
			0x725055C5F9880BE1ULL,
			0x63BA7624832E362FULL
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
			0x92BA0131314CD788ULL,
			0x6CDE18D8DC448AACULL,
			0x7837FF8849B7ED1EULL,
			0x6F61BEE6532A175BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x60E75D4C5525A4B8ULL,
			0x53C71EEAAC61D3B7ULL,
			0xE8474F68DC850C2BULL,
			0x6BD19120274A7BBEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x115E9DE8461E28BBULL,
			0xAC7F79FC0105573EULL,
			0x3C780F325836ADBCULL,
			0x07A6EBFCC3E10E02ULL
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
			0x11620C4546877058ULL,
			0xA5C14CEB68DEE06DULL,
			0xF35132AA4DB4CC43ULL,
			0x5F6B7E515F4D5845ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x48957C1BC7668D50ULL,
			0xB697EE45A6B5A738ULL,
			0x723722F24BA1FEE6ULL,
			0x5EEB7BFDDE112097ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x519C4F87B9E134ADULL,
			0x659F49C18705D298ULL,
			0xD86022FCEBA0F78AULL,
			0x7976D061EFB67E56ULL
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
			0x05825C4BC43233A8ULL,
			0xC03245C70EA6D2C5ULL,
			0x5E85EFB6F93E6C5BULL,
			0x414613B67D056FE3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8F495D66167B1168ULL,
			0x5652E789E6FEC181ULL,
			0x52EA1EAC5FBE9449ULL,
			0x47F0477F71651779ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9E667EC589B213EBULL,
			0x981B60AD7865A4F6ULL,
			0xB3B0DE71561FDB3DULL,
			0x63D5C3BE01DABE2BULL
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
			0x0A9DD6A6C81160C8ULL,
			0x9EAA504F36508ACCULL,
			0x168FCF0A4B9A8450ULL,
			0x42164A5EB356A387ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7672273178EE4A80ULL,
			0x6F9760CC56F9138CULL,
			0x19D39D5C5CBD3857ULL,
			0x7A881633127402B7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x20580A78AEB35A06ULL,
			0xD41002DB45D450DBULL,
			0x28E4997FD0B437F7ULL,
			0x1729A3E560B9A6BCULL
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
			0x84020AA8FBE9A638ULL,
			0xB3951CB4AFF62978ULL,
			0x187625280E069B87ULL,
			0x691B84BFA4BBB08EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4D33A986A0A86268ULL,
			0xD6CD8B906B2D9764ULL,
			0xB70231B84AE3FEB5ULL,
			0x5D33C2FBFCD57F50ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4DEEF61364590BA4ULL,
			0xF51C02857E2568ABULL,
			0x2467B1F065D58C4AULL,
			0x00C3CD70F9593A2FULL
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
			0xBB9194231D9A9008ULL,
			0x7EFB91311ED12383ULL,
			0xBDC8EC0ABA4C397BULL,
			0x71DB55F347BE37F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA6118BB69D2FA768ULL,
			0x3161BFA9C67C2BB7ULL,
			0xDAEE2A7E4353AFFAULL,
			0x47808EEC8DC5C389ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD6BB718CEF31B600ULL,
			0x0919D4C264DA73F1ULL,
			0x4F4D1C01AF9D47A5ULL,
			0x20E377F8279B403EULL
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
			0xAC204BF49F300480ULL,
			0x071C78F36F00446BULL,
			0x7FEDABCECB2D584DULL,
			0x4FDBE661E566BF73ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBCB778D6C63DA260ULL,
			0x01A4D3E514498283ULL,
			0x310BDBA3880C88AAULL,
			0x720792C5D2A23AC8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCF83EF8933FAEA18ULL,
			0x52DCA33574031343ULL,
			0x2DE83AA1776CDDD5ULL,
			0x692C085EBA6A03DDULL
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
			0xD67100435899FF70ULL,
			0x8B2984CE5202F649ULL,
			0x6AB0654A123E107FULL,
			0x6695993254EF40C4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF520EBD738E2B0D0ULL,
			0xCD92F129EA66F1FCULL,
			0x4980733B198A8495ULL,
			0x6F0D250679DE7B16ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x44CD7C8046377327ULL,
			0xA281285D433A6608ULL,
			0xD76FFF8879075C31ULL,
			0x36D83EA137AB5E82ULL
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
			0xFC3737AC622C5AD0ULL,
			0x719934001DAAF97EULL,
			0xD2D3C57869B3B761ULL,
			0x6359F999153BA67CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB2FA67FA423C30D0ULL,
			0xFF4FED9CDBA3D271ULL,
			0xEC757953B0115156ULL,
			0x55BCE59DA708F09DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x948272046B320A20ULL,
			0xE11508CB1D515EF9ULL,
			0xE90E152C246F82A3ULL,
			0x73C927DE79ECB431ULL
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
			0x851413063B46CA08ULL,
			0x312C411D17A2AF01ULL,
			0x72DEE160CF1C8EC4ULL,
			0x54D7956382926F4DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAF1725277AA962C8ULL,
			0x0012583233D697BCULL,
			0x49CD444836B9067CULL,
			0x4DF2A1AA9A9DEB83ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x11F3F6270150D418ULL,
			0x3DEB4A1A28266DF2ULL,
			0x221BE2B950E0E05FULL,
			0x00ED847DAE1825AAULL
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
			0xBD7A3B2E9E729248ULL,
			0xAFC313432A0A8191ULL,
			0x86A206B963643777ULL,
			0x7BA15CD29FA119DAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x005AD3E1F763CB50ULL,
			0x2F326F031AABEAB9ULL,
			0x06F82866992C3208ULL,
			0x432509AA6A91F77DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85078714D2948F0DULL,
			0x226B9036737DBDBCULL,
			0xFF7AFE5506939EA7ULL,
			0x175C8A13666C23C0ULL
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
			0x51D9F8F3916AD4C0ULL,
			0x5BD2DF09228C2576ULL,
			0x1D262B6AB422A54DULL,
			0x4EDAB28F2D5750CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8904B6521F51B200ULL,
			0x07C880C2208B7477ULL,
			0x86DD6D6BB0017861ULL,
			0x5F2F412B8BE0A632ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFBE8A3DA74FE877DULL,
			0x422DF0B70F0B1E81ULL,
			0x72E67AC8EE39D698ULL,
			0x3E89977CE0754E9FULL
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
			0xB2C4310EBF635920ULL,
			0x5754D17F0A03E88CULL,
			0x2DC45E3F019FE163ULL,
			0x4D4C99DCAF10D86CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x153CEAF77BE93528ULL,
			0x785380C6DB7569DEULL,
			0x0533CD6E5C5754BCULL,
			0x6A7BF67101429017ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF423A74443523205ULL,
			0x8F5F1C14DA1696A9ULL,
			0x36C706BC95915CC8ULL,
			0x47B0937197327E93ULL
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
			0x2A0A8AD539B9CDA8ULL,
			0x3BD7593A9145FDB1ULL,
			0x157EEE63B9AC5612ULL,
			0x58271C6F5425AAD0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF6565F8FB6517528ULL,
			0x4D8F5C28F0E73645ULL,
			0x42231E458420DBB6ULL,
			0x4829EF39A52FFE69ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43FCF9BC8E62EB19ULL,
			0xF96E1AD672E0BE52ULL,
			0xF9B0B45E478CBCC2ULL,
			0x633A682EA719AA07ULL
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
			0xAB8987C1B1782B00ULL,
			0xD2824691EA8FC4DFULL,
			0x2B9079FE247D48B1ULL,
			0x60C5BF73C86DEDC4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C64E07C22EE33B8ULL,
			0xF625033DCFF6AC07ULL,
			0x27DAB475DB054111ULL,
			0x53D2D6CAC2D72BEDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x72B8189F9290F133ULL,
			0x2D1F47D9A826B4A7ULL,
			0x3CA528DCDB56750CULL,
			0x392BF70515704B78ULL
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
			0x1BE92BD5606D88C8ULL,
			0x5AA3E898BBFCF144ULL,
			0xE5C63805475E3978ULL,
			0x615916BD929AF7BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1FF45239E3FEDB78ULL,
			0x6B15A0C9754A2019ULL,
			0x6D6EFF747B627557ULL,
			0x550A4A83116FDCB0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF399BBB5399585ADULL,
			0xDCFB11051843992EULL,
			0xB5497F947F888D6BULL,
			0x796981E5EB96D09EULL
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
			0x8D7CEA62AC3597B0ULL,
			0xDFC3A8FB056F90D0ULL,
			0x751418BE51A99853ULL,
			0x6578F5C0D36B7A5CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x33027C14621954D0ULL,
			0xAE23DD1EC9E5B06EULL,
			0xD67F6A8BAB9ACA79ULL,
			0x429CB21E512AF111ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE1348CB52D663DDULL,
			0x9C6BB88CC5699CA6ULL,
			0x99B98FF2CBF969E9ULL,
			0x2CE10893A646D706ULL
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
			0xDDBA6567D1E95AC0ULL,
			0x28B35B6DDD523256ULL,
			0xC4F96407DE6E7BD3ULL,
			0x71D2A2857CBFE0CEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB5698AFE7CCE7AB0ULL,
			0xF1851F7A1BB51855ULL,
			0x3BA51B35C2AF66FFULL,
			0x7EF8DC77FEE54DFFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB078433BE5681E8DULL,
			0x9BE845A34CB0B311ULL,
			0xB3A034F435B0BF94ULL,
			0x6A0C478D2467E06DULL
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
			0xCA3D98590DF58D40ULL,
			0xAE1009323FCA5516ULL,
			0xAAF90AFE1D4AF23BULL,
			0x407854F7AFE17383ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x91951A83E40F2E98ULL,
			0xD8AA017525DDD066ULL,
			0xE734678873EAA5FAULL,
			0x4742041D5A65DD69ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8771D10F15812093ULL,
			0xDE38B40D2DCF8324ULL,
			0x72FCBADAF26BF923ULL,
			0x3A46D033AF3A455FULL
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
			0xDFE5618A7B4113F0ULL,
			0xA79A0C94B44CF5DAULL,
			0xB2BD3090C061D747ULL,
			0x69C2AA34E78C3A96ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3836B95F5F72D380ULL,
			0x7E090B58726CDB58ULL,
			0x116C946D51258C5AULL,
			0x722142A6CD32D478ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5255784FB9C0AA49ULL,
			0x5C8FCCDA1AD53053ULL,
			0xDF0A10F648211F26ULL,
			0x23E8E92FBCB07654ULL
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
			0x3EE0ABE791E281C0ULL,
			0xEB3E626549B26188ULL,
			0xB22355476CA5062AULL,
			0x41C8F66120AD37CBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x535B22C2E9F0EDF0ULL,
			0x9EF2123DD0D847F5ULL,
			0x3C67E0679A88464FULL,
			0x4F5A133C7E29EF3DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAEAC81B4CEEE74BCULL,
			0x5013C28758243AF9ULL,
			0x7B4C64E7191FD054ULL,
			0x18565C2254F1625EULL
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
			0x9F63BC03290289E0ULL,
			0x25DA10BECA21380FULL,
			0x7A35BB7776A84C30ULL,
			0x58B39CC3280C761DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6E4DF3E33FD96B58ULL,
			0x6804009055DB962AULL,
			0xDC6D3C57D358B006ULL,
			0x73DFD7F2BCE153A9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x066CB93525AE623CULL,
			0xAE5B3C2097B72DE6ULL,
			0xB664DC4AEEAB5632ULL,
			0x08C1806ECDF44161ULL
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
			0xA8B25AE2ADFD9FD8ULL,
			0xC36F2E456D300889ULL,
			0x7BFAEE25A34E7D9CULL,
			0x711C8B50CE026F44ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8ED71C0E6F210D60ULL,
			0x843FD3B53A84492AULL,
			0xF7282E3639B51047ULL,
			0x677C93A03574FED3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x75454543BF24FFFFULL,
			0xAAEAB9DD871F450FULL,
			0x144E1BFD9F46F303ULL,
			0x6EE47A2315D85044ULL
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
			0xCFB114523C864F38ULL,
			0x63BA17C5AF78CBD5ULL,
			0xE22ABA283936FF2DULL,
			0x596C00522BA97105ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDB6223A6C969ED08ULL,
			0x55DE47D5CC4D12B2ULL,
			0x2C0057CBCB49C792ULL,
			0x40EA6900B8DE0DE0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0BF2C45D8A03D195ULL,
			0x4430B71FFE3F4420ULL,
			0xAEF2BB7B67F686A4ULL,
			0x0A5CD1703FAD76FAULL
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
			0x7F774375C8021DA0ULL,
			0xD1E27647B2DE2881ULL,
			0x573FE2DF81E6148DULL,
			0x6819FECC7F0544BCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE6789E169EF10870ULL,
			0x1DE8C4B9BADA3E0FULL,
			0x34DB65DCD33A92A5ULL,
			0x516754084B940AB9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC00263F87D5C5E3EULL,
			0xF5FB9112FCF755C1ULL,
			0xDA3DC5A97375C5B3ULL,
			0x2EB888819293952AULL
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